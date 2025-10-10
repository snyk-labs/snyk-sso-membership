package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk-labs/snyk-sso-membership/pkg/client"
	"github.com/snyk-labs/snyk-sso-membership/pkg/config"
	"github.com/snyk-labs/snyk-sso-membership/pkg/membership"
	"github.com/snyk-labs/snyk-sso-membership/pkg/sso"
	"github.com/spf13/cobra"
)

// UserWithMemberships represents a user with their full membership data
type UserWithMemberships struct {
    ID               string           `json:"id"`
    Username         string           `json:"username"`
    Email            string           `json:"email"`
    Name             string           `json:"name"`
    Active           bool             `json:"active"`
    GroupMemberships []MembershipInfo `json:"group_memberships"`
    OrgMemberships   []MembershipInfo `json:"org_memberships"`
}

// MembershipInfo represents membership details for group or org
type MembershipInfo struct {
    MembershipID string `json:"membership_id"`
    ID           string `json:"id"`
    Name         string `json:"name"`
    RoleID       string `json:"role_id"`
    RoleName     string `json:"role_name"`
    // For API provisioning - these fields make it easier to iterate and call provision endpoint
    OrgID string `json:"org_id,omitempty"` // Organization ID for provision API calls
    Role  string `json:"role,omitempty"`   // Role name for provision API (ADMIN, MEMBER, COLLABORATOR)
}

// UsersWithMembershipsResponse represents the full JSON response structure
type UsersWithMembershipsResponse struct {
    Users []UserWithMemberships `json:"users"`
}

func GenerateMembershipsJSON(logger *zerolog.Logger) *cobra.Command {
	generateCmd := cobra.Command{
		Use:                   "generate-memberships-json [groupID]",
		Short:                 "Generate JSON export of users with their full membership data",
		DisableFlagParsing:    false,
		DisableFlagsInUseLine: false,
		Args: func(_ *cobra.Command, args []string) error {
			return validateGenerateMembershipsArgs(logger, args)
		},
		RunE: func(_ *cobra.Command, args []string) error {
			c := client.New(config.New(), logger)
			sc := sso.New(c)
			mc := membership.New(c)
			return runGenerateMembershipsJSON(args, logger, sc, mc)
		},
	}

	return &generateCmd
}

// validateGenerateMembershipsArgs validates that either groupID or --groups is provided
func validateGenerateMembershipsArgs(logger *zerolog.Logger, args []string) error {
	hasPositionalGroup := len(args) == 1
	hasGroupsFlag := groups != ""

	if !hasPositionalGroup && !hasGroupsFlag {
		msg := "either groupID argument or --groups flag must be provided"
		logger.Error().Msg(msg)
		return fmt.Errorf(msg)
	}

	if hasPositionalGroup && hasGroupsFlag {
		msg := "cannot use both groupID argument and --groups flag together"
		logger.Error().Msg(msg)
		return fmt.Errorf(msg)
	}

	if len(args) > 1 {
		msg := fmt.Sprintf("expected 0 or 1 groupID argument, got %d", len(args))
		logger.Error().Msg(msg)
		return fmt.Errorf(msg)
	}

	// Validate groupID if provided
	if hasPositionalGroup {
		if _, err := uuid.Parse(args[0]); err != nil {
			msg := fmt.Sprintf("groupID must be a valid UUID: %s", args[0])
			logger.Error().Msg(msg)
			return fmt.Errorf(msg)
		}
	}

	// Validate groups flag if provided
	if hasGroupsFlag {
		groupIDs := strings.Split(groups, ",")
		for _, gid := range groupIDs {
			gid = strings.TrimSpace(gid)
			if _, err := uuid.Parse(gid); err != nil {
				msg := fmt.Sprintf("all group IDs must be valid UUIDs, invalid: %s", gid)
				logger.Error().Msg(msg)
				return fmt.Errorf(msg)
			}
		}
	}

	return nil
}

func runGenerateMembershipsJSON(args []string, logger *zerolog.Logger, sc userFetcher, mc *membership.Client) error {
	var groupIDs []string

	// Determine which group(s) to process
	if len(args) == 1 {
		groupIDs = []string{args[0]}
	} else if groups != "" {
		groupIDs = strings.Split(groups, ",")
		for i := range groupIDs {
			groupIDs[i] = strings.TrimSpace(groupIDs[i])
		}
	}

	logger.Info().Msgf("Processing %d group(s)", len(groupIDs))

	// Map to consolidate users by email (or username)
	userMap := make(map[string]*UserWithMemberships)

	// Process each group
	for _, groupID := range groupIDs {
		logger.Info().Msgf("Fetching users from group: %s", groupID)

		// Get filtered users for this group
		ssoUsers, err := getAndFilterUsers(groupID, logger, sc)
		if err != nil {
			logger.Warn().Err(err).Msgf("Failed to get users from group %s, skipping", groupID)
			continue
		}

		logger.Info().Msgf("Found %d users in group %s", len(ssoUsers.Data), groupID)

		// Process each user in this group
		for _, user := range ssoUsers.Data {
			if user.Attributes == nil || user.ID == nil {
				continue
			}

			// Determine user key for deduplication
			var userKey string
			if matchByUserName && user.Attributes.UserName != nil {
				userKey = *user.Attributes.UserName
			} else if user.Attributes.Email != nil {
				userKey = *user.Attributes.Email
			} else {
				continue
			}

			// Get or create user entry in map
			if _, exists := userMap[userKey]; !exists {
				userMap[userKey] = &UserWithMemberships{
					ID:               safeString(user.ID),
					Username:         safeString(user.Attributes.UserName),
					Email:            safeString(user.Attributes.Email),
					Name:             safeString(user.Attributes.Name),
					Active:           safeBool(user.Attributes.Active),
					GroupMemberships: []MembershipInfo{},
					OrgMemberships:   []MembershipInfo{},
				}
			}

			// Get and merge group memberships
			groupMemberships, err := mc.GetUserGroupMemberships(groupID, *user.ID)
			if err == nil && groupMemberships != nil {
				for _, gm := range groupMemberships.Data {
					membershipInfo := MembershipInfo{
						MembershipID: safeString(gm.ID),
						ID:           safeString(gm.Relationship.Group.Data.ID),
						Name:         safeString(gm.Relationship.Group.Data.Attributes.Name),
						RoleID:       safeString(gm.Relationship.Role.Data.ID),
						RoleName:     safeString(gm.Relationship.Role.Data.Attributes.Name),
					}
					// Check for duplicate membership before adding
					if !membershipExists(userMap[userKey].GroupMemberships, membershipInfo.MembershipID) {
						userMap[userKey].GroupMemberships = append(userMap[userKey].GroupMemberships, membershipInfo)
					}
				}
			} else if err != nil {
				logger.Warn().Err(err).Msgf("Failed to get group memberships for user %s in group %s", userKey, groupID)
			}

			// Get and merge org memberships
			orgMemberships, err := mc.GetUserOrgMembershipsOfGroup(groupID, *user.ID)
			if err == nil && orgMemberships != nil {
				for _, om := range orgMemberships.Data {
					roleName := safeString(om.Relationship.Role.Data.Attributes.Name)
					provisionRole := mapRoleNameToProvisionAPI(roleName)

					membershipInfo := MembershipInfo{
						MembershipID: safeString(om.ID),
						ID:           safeString(om.Relationship.Org.Data.ID),
						Name:         safeString(om.Relationship.Org.Data.Attributes.Name),
						RoleID:       safeString(om.Relationship.Role.Data.ID),
						RoleName:     roleName,
						OrgID:        safeString(om.Relationship.Org.Data.ID),
						Role:         provisionRole,
					}
					// Check for duplicate membership before adding
					if !membershipExists(userMap[userKey].OrgMemberships, membershipInfo.MembershipID) {
						userMap[userKey].OrgMemberships = append(userMap[userKey].OrgMemberships, membershipInfo)
					}
				}
			} else if err != nil {
				logger.Warn().Err(err).Msgf("Failed to get org memberships for user %s in group %s", userKey, groupID)
			}
		}
	}

	// Convert map to slice
	var usersWithMemberships []UserWithMemberships
	for _, user := range userMap {
		usersWithMemberships = append(usersWithMemberships, *user)
	}

	if len(usersWithMemberships) == 0 {
		logger.Error().Msg("No users found matching the specified criteria")
		return nil
	}

	// Create response and output JSON
	response := UsersWithMembershipsResponse{Users: usersWithMemberships}
	jsonData, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		logger.Error().Err(err).Msg("Failed to marshal JSON")
		return err
	}
	if _, err = os.Stdout.Write(jsonData); err != nil {
		logger.Error().Err(err).Msg("Failed to write JSON output")
		return err
	}
	logger.Info().Msgf("Successfully generated membership data for %d users across %d group(s)", len(usersWithMemberships), len(groupIDs))
	return nil
}

// membershipExists checks if a membership ID already exists in the slice
func membershipExists(memberships []MembershipInfo, membershipID string) bool {
	for _, m := range memberships {
		if m.MembershipID == membershipID {
			return true
		}
	}
	return false
}

// Helper functions to safely handle pointer values
func safeString(ptr *string) string {
    if ptr == nil {
        return ""
    }
    return *ptr
}

func safeBool(ptr *bool) bool {
    if ptr == nil {
        return false
    }
    return *ptr
}

// mapRoleNameToProvisionAPI maps Snyk role names to the provision API role format
func mapRoleNameToProvisionAPI(roleName string) string {
    switch roleName {
    case "Org Admin", "Group Admin":
        return "ADMIN"
    case "Org Member", "Group Member", "Member":
        return "MEMBER"
    case "Org Collaborator", "Group Collaborator", "Collaborator":
        return "COLLABORATOR"
    default:
        return "MEMBER"
    }
}


