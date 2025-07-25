package membership

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk-labs/snyk-sso-membership/pkg/sso"
)

type provisionedUserAttributes struct {
	id                           *string
	userName                     *string
	groupMembershipID            *string
	groupMemberships             *UserGroupMemberships
	orgMemberships               *UserOrgMemberships
	provisionedID                *string
	provisionedUserName          *string
	provisionedEmail             *string
	provisionedGroupMembershipID *string
}

// matchToUserProperty checks user properties against the local part or provisioned email based on matchToLocalPart flag.
// It returns true if the user matches either the local part at the username property or the provisoned email at email property.
func matchToUserProperty(u sso.User, localPart, provisionedEmail string, matchToLocalPart bool) bool {
	if matchToLocalPart && u.Attributes.UserName != nil {
		return localPart == *u.Attributes.UserName
	} else if !matchToLocalPart && u.Attributes.Email != nil {
		return provisionedEmail == *u.Attributes.Email
	}

	return false
}

// Builds a map of the previous domain email of User to its corresponding current provisioned ssoDomain User entity containing its Memberships
func (m *Client) mapProvisionedUsersAttributes(groupID, domain, ssoDomain string, users sso.Users, matchByUserName, matchToLocalPart bool, logger *zerolog.Logger) (int32, *map[string]provisionedUserAttributes) {
	provisionedUserAttributesMap := make(map[string]provisionedUserAttributes)

	for _, u := range *users.Data {
		if (!matchByUserName && strings.HasSuffix(*u.Attributes.Email, domain)) || (matchByUserName && strings.HasSuffix(*u.Attributes.UserName, domain)) {
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
			var prevKeyIdentifier string
			if matchByUserName {
				prevKeyIdentifier = *u.Attributes.UserName
			} else {
				prevKeyIdentifier = *u.Attributes.Email
			}

			provisionedUserAttributesMap[prevKeyIdentifier] = provisionedUserAttributes{
				id:                u.ID,
				userName:          u.Attributes.UserName,
				groupMembershipID: (*groupMemberships.Data)[0].ID,
				groupMemberships:  groupMemberships,
				orgMemberships:    orgMemberships,
			}
		}
	}

	var count int32
	// populate provisioned User ID, UserName and Email on the ssoDomain
	for prevKeyID, uAttributes := range provisionedUserAttributesMap {
		emailParts := strings.Split(prevKeyID, "@")
		localPart := emailParts[0]
		provisionedEmail := localPart + "@" + ssoDomain

		for _, u := range *users.Data {
			if matchToUserProperty(u, localPart, provisionedEmail, matchToLocalPart) {
				if matchToLocalPart && u.Attributes.UserName != nil {
					logger.Info().Msg(fmt.Sprintf("Matched %s -> User: username: %s", prevKeyID, *u.Attributes.UserName))
				} else {
					logger.Info().Msg(fmt.Sprintf("Matched %s -> User: email:  %s", prevKeyID, provisionedEmail))
				}

				// get the GroupMembership of provisioned User to update
				pGroupMemberships, err := m.getUserGroupMemberships(groupID, *u.ID)
				if err == nil && pGroupMemberships != nil && len(*pGroupMemberships.Data) > 0 {
					uAttributes.provisionedGroupMembershipID = (*pGroupMemberships.Data)[0].ID
				} else if err != nil {
					logger.Info().Msg(fmt.Sprintf("No existent Group membership found for User: username: %s", *u.Attributes.UserName))
					logger.Warn().Msg(err.Error())
				}
				uAttributes.provisionedEmail = &provisionedEmail
				uAttributes.provisionedUserName = u.Attributes.UserName
				uAttributes.provisionedID = u.ID
				provisionedUserAttributesMap[prevKeyID] = uAttributes
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
				logger.Info().Msg(fmt.Sprintf("Failed to update GroupMembership of User: username: %s, Group: %s", *uAttributes.provisionedUserName, groupName))
				logger.Error().Msg(errorMessage)
			}
		} else {
			logger.Info().Msg(fmt.Sprintf("Updated GroupMembership of User: username: %s, Group: %s", *uAttributes.provisionedUserName, groupName))
		}
	}
}

// Deletes the current provisioned ssoDomain User org memberships
func (m *Client) deleteUserOrgMembership(groupID, userID, userIdentifier string, logger *zerolog.Logger) error {
	// get User org memberships
	userOrgMemberships, err := m.getUserOrgMembershipsOfGroup(groupID, userID)
	if err != nil {
		logger.Info().Msg(fmt.Sprintf("Failed to get org memberships of User: username: %s", userIdentifier))
		logger.Error().Msg(err.Error())
		return err
	}

	// delete these memberships
	for _, om := range *userOrgMemberships.Data {
		orgID := om.Relationship.Org.Data.ID
		orgName := *om.Relationship.Org.Data.Attributes.Name
		err := m.deleteOrgMembership(*orgID, *om.ID)
		if err != nil {
			logger.Info().Msg(fmt.Sprintf("Failed to delete OrgMembership of User: username: %s, Org: %s", userIdentifier, orgName))
			logger.Error().Msg(err.Error())
		}
	}
	return nil
}

// Synchronizes provisioned user Org memberships with corresponding Org Role of the pre-migrated user across all Orgs
func (m *Client) syncUserOrgMemberships(groupID string, uAttributes *provisionedUserAttributes, logger *zerolog.Logger) {
	// synchronizes by first scrubbing all provisioned user org memberships if existent
	err := m.deleteUserOrgMembership(groupID, *uAttributes.provisionedID, *uAttributes.provisionedUserName, logger)
	if err != nil {
		logger.Warn().Msg(fmt.Sprintf("Failed to delete OrgMembership of User: username: %s", *uAttributes.provisionedUserName))
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
				logger.Error().Msg(fmt.Sprintf("Failed to create OrgMembership of User: username: %s, Org: %s", *uAttributes.provisionedUserName, orgName))
				logger.Error().Msg(errorMessage)
			}
		} else {
			logger.Info().Msg(fmt.Sprintf("Created OrgMembership of User: username: %s, Org: %s", *uAttributes.provisionedUserName, orgName))
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
			logger.Error().Msg(fmt.Sprintf("Failed to create GroupMembership of User: username: %s, Group: %s", *uAttributes.provisionedUserName, groupName))
		} else {
			logger.Info().Msg(fmt.Sprintf("Created GroupMembership of User: username: %s, Group: %s", *uAttributes.provisionedUserName, groupName))
		}
	}
}

// Synchronizes memberships of provisioned users with the corresponding SSO users
// This will update the provisioned user Group and Org memberships to match the pre-migrated user memberships
// It will also create the provisioned user Group and Org memberships if they do not exist
func (m *Client) SyncMemberships(groupID, domain, ssoDomain string, users sso.Users, matchByUserName, matchToLocalPart bool, logger *zerolog.Logger) {
	userCount, provisionedUserAttributesMap := m.mapProvisionedUsersAttributes(groupID, domain, ssoDomain, users, matchByUserName, matchToLocalPart, logger)
	logger.Info().Msg(fmt.Sprintf("Found %d Users to synchronize", userCount))
	var index int32

	for _, uAttributes := range *provisionedUserAttributesMap {
		if uAttributes.provisionedID != nil {
			index++
			logger.Info().Msg(fmt.Sprintf("Start synchronization of memberships %d/%d User: username: %s", index, userCount, *uAttributes.provisionedUserName))
			m.syncUserGroupMembership(&uAttributes, logger)
			m.syncUserOrgMemberships(groupID, &uAttributes, logger)
		}
	}

	logger.Info().Msg("End synchronization of memberships")
}
