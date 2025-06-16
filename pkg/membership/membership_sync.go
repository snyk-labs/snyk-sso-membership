package membership

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk-labs/snyk-sso-membership/pkg/sso"
)

type provisionedUserAttributes struct {
	id                           *string
	name                         *string
	groupMembershipID            *string
	groupMemberships             *UserGroupMemberships
	orgMemberships               *UserOrgMemberships
	provisionedID                *string
	provisionedEmail             *string
	provisionedGroupMembershipID *string
}

// Builds a map of the previous domain email of User to its corresponding current provisioned ssoDomain User entity containing its Memberships
func (m *Client) mapProvisionedUsersAttributes(groupID, domain, ssoDomain string, users sso.Users, logger *zerolog.Logger) (int32, *map[string]provisionedUserAttributes) {
	provisionedUserAttributesMap := make(map[string]provisionedUserAttributes)

	for _, u := range *users.Data {
		if strings.HasSuffix(*u.Attributes.Email, domain) {
			userID := *u.ID
			groupMemberships, err := m.getUserGroupMemberships(groupID, userID)
			if err != nil || groupMemberships == nil || len(*groupMemberships.Data) == 0 {
				logger.Info().Msg(fmt.Sprintf("No existent Group membership found for user: %s", *u.Attributes.Email))
				logger.Warn().Msg(err.Error())
			}
			orgMemberships, err := m.getUserOrgMembershipsOfGroup(groupID, userID)
			if err != nil {
				logger.Info().Msg(fmt.Sprintf("No existent Org membership found for user: %s", *u.Attributes.Email))
				logger.Warn().Msg(err.Error())
			}
			provisionedUserAttributesMap[*u.Attributes.Email] = provisionedUserAttributes{
				id:                u.ID,
				name:              u.Attributes.Name,
				groupMembershipID: (*groupMemberships.Data)[0].ID,
				groupMemberships:  groupMemberships,
				orgMemberships:    orgMemberships,
			}
		}
	}

	var count int32
	// populate provisioned User ID and Email on the ssoDomain
	for prevEmail, uAttributes := range provisionedUserAttributesMap {
		emailName := strings.Split(prevEmail, "@")
		provisionedEmail := emailName[0] + "@" + ssoDomain
		for _, u := range *users.Data {
			if provisionedEmail == *u.Attributes.Email {
				logger.Info().Msg(fmt.Sprintf("User: %s -> %s", prevEmail, provisionedEmail))
				// get the GroupMembership of provisioned User to update
				pGroupMemberships, err := m.getUserGroupMemberships(groupID, *u.ID)
				if err == nil && pGroupMemberships != nil && len(*pGroupMemberships.Data) > 0 {
					uAttributes.provisionedGroupMembershipID = (*pGroupMemberships.Data)[0].ID
				} else if err != nil {
					logger.Info().Msg(fmt.Sprintf("No existent Group membership found for user: %s", provisionedEmail))
					logger.Warn().Msg(err.Error())
				}
				uAttributes.provisionedEmail = &provisionedEmail
				uAttributes.provisionedID = u.ID
				provisionedUserAttributesMap[prevEmail] = uAttributes
				count++
				break
			}
		}
	}

	return count, &provisionedUserAttributesMap
}

// A provisioned User is provisioned with a default Group membership based on the Login strategy at SSO settings
// this function will update this provisioned membership to be similar to the pre-migration User
func (m *Client) updateUserGroupMembership(uAttributes *provisionedUserAttributes, logger *zerolog.Logger) {
	if uAttributes.groupMemberships.Data != nil && uAttributes.provisionedGroupMembershipID != nil {
		gm := (*uAttributes.groupMemberships.Data)[0]
		groupID := gm.Relationship.Group.Data.ID
		groupName := *gm.Relationship.Group.Data.Attributes.Name

		err := m.updateRoleAtUserGroupMembership(*groupID, *uAttributes.provisionedGroupMembershipID, gm)
		if err != nil {
			errorMessage := err.Error()
			// make it idempotent by ignoring status code 409 Conflict - Membership already exists for the specified user error
			if !strings.HasSuffix(errorMessage, "409") {
				logger.Info().Msg(fmt.Sprintf("Failed to update GroupMembership of User: %s, Group: %s", *uAttributes.provisionedEmail, groupName))
				logger.Error().Msg(errorMessage)
			}
		} else {
			logger.Info().Msg(fmt.Sprintf("Updated GroupMembership of User: %s, Group: %s", *uAttributes.provisionedEmail, groupName))
		}
	}
}

// Deletes the current provisioned ssoDomain User org memberships
func (m *Client) deleteUserOrgMembership(groupID, userID, userEmail string, logger *zerolog.Logger) error {
	// get User org memberships
	userOrgMemberships, err := m.getUserOrgMembershipsOfGroup(groupID, userID)
	if err != nil {
		logger.Info().Msg(fmt.Sprintf("Failed to get org memberships of User: %s", userEmail))
		logger.Error().Msg(err.Error())
		return err
	}

	// delete these memberships
	for _, om := range *userOrgMemberships.Data {
		orgID := om.Relationship.Org.Data.ID
		orgName := *om.Relationship.Org.Data.Attributes.Name
		err := m.deleteOrgMembership(*orgID, *om.ID)
		if err != nil {
			logger.Info().Msg(fmt.Sprintf("Failed to delete OrgMembership of User: %s, Org: %s", userEmail, orgName))
			logger.Error().Msg(err.Error())
		}
	}
	return nil
}

// Synchronizes provisioned user Org memberships with corresponding Org Role of the pre-migrated user across all Orgs
func (m *Client) syncUserOrgMemberships(groupID string, uAttributes *provisionedUserAttributes, logger *zerolog.Logger) {
	// synchronizes by first scrubbing all provisioned user org memberships if existent
	err := m.deleteUserOrgMembership(groupID, *uAttributes.provisionedID, *uAttributes.provisionedEmail, logger)
	if err != nil {
		logger.Warn().Msg(fmt.Sprintf("Failed to delete OrgMembership of User: %s", *uAttributes.provisionedEmail))
	}

	for _, om := range *uAttributes.orgMemberships.Data {
		userType := sso.TypeUser
		pUserAttributes := &TypeIdentifierAttributes{
			ID:   uAttributes.provisionedID,
			Type: &userType,
		}
		pUser := &struct {
			Data *TypeIdentifierAttributes `json:"data"`
		}{
			Data: pUserAttributes,
		}

		orgMbrRelationship := MemberRelationship{
			Org:  om.Relationship.Org,
			Role: om.Relationship.Role,
			User: pUser,
		}
		orgID := om.Relationship.Org.Data.ID
		orgName := *om.Relationship.Org.Data.Attributes.Name
		// recreate them again so they will match org memberships of the pre-migrated User
		_, err = m.createUserOrgMembership(*orgID, orgMbrRelationship)
		if err != nil {
			errorMessage := err.Error()
			// make it idempotent by ignoring Error status code 409 Conflict - Membership already exists for the specified user
			if !strings.HasSuffix(errorMessage, "409") {
				logger.Error().Msg(fmt.Sprintf("Failed to create OrgMembership of User: %s, Org: %s", *uAttributes.provisionedEmail, orgName))
				logger.Error().Msg(errorMessage)
			}
		} else {
			logger.Info().Msg(fmt.Sprintf("Created OrgMembership of User: %s, Org: %s", *uAttributes.provisionedEmail, orgName))
		}
	}
}

func (m *Client) syncUserGroupMembership(uAttributes *provisionedUserAttributes, logger *zerolog.Logger) {
	// update provisioned user group membership
	if uAttributes.provisionedGroupMembershipID != nil {
		m.updateUserGroupMembership(uAttributes, logger)
	} else {
		// otherwise recreate it again
		userType := sso.TypeUser
		pUserAttributes := &TypeIdentifierAttributes{
			ID:   uAttributes.provisionedID,
			Type: &userType,
		}
		pUser := &struct {
			Data *TypeIdentifierAttributes `json:"data"`
		}{
			Data: pUserAttributes,
		}

		// extract the prev User groupmembership
		gm := (*uAttributes.groupMemberships.Data)[0]
		groupMbrRelationship := MemberRelationship{
			Group: gm.Relationship.Group,
			Role:  gm.Relationship.Role,
			User:  pUser,
		}
		groupID := gm.Relationship.Group.Data.ID
		groupName := *gm.Relationship.Group.Data.Attributes.Name
		_, err := m.createUserGroupMembership(*groupID, groupMbrRelationship)
		if err != nil {
			logger.Error().Msg(fmt.Sprintf("Failed to create GroupMembership of User: %s, Group: %s", *uAttributes.provisionedEmail, groupName))
		} else {
			logger.Info().Msg(fmt.Sprintf("Created GroupMembership of User: %s, Group: %s", *uAttributes.provisionedEmail, groupName))
		}
	}
}

func (m *Client) SyncMemberships(groupID, domain, ssoDomain string, users sso.Users, logger *zerolog.Logger) {
	userCount, provisionedUserAttributesMap := m.mapProvisionedUsersAttributes(groupID, domain, ssoDomain, users, logger)
	logger.Info().Msg(fmt.Sprintf("Found %d Users to synchronize", userCount))
	var index int32

	for _, uAttributes := range *provisionedUserAttributesMap {
		if uAttributes.provisionedID != nil {
			index++
			logger.Info().Msg(fmt.Sprintf("Start synchronization of memberships %d/%d User: %s", index, userCount, *uAttributes.provisionedEmail))
			m.syncUserGroupMembership(&uAttributes, logger)
			m.syncUserOrgMemberships(groupID, &uAttributes, logger)
		}
	}

	logger.Info().Msg("End synchronization of memberships")
}
