package commands

import (
    "encoding/json"
    "os"

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
            return validateGetDeleteArgs(logger, args)
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

func runGenerateMembershipsJSON(args []string, logger *zerolog.Logger, sc userFetcher, mc *membership.Client) error {
    groupID := args[0]

    // Get filtered users using the same logic as get-users
    ssoUsers, err := getAndFilterUsers(groupID, logger, sc)
    if err != nil {
        return err
    }

    if len(ssoUsers.Data) == 0 {
        logger.Error().Msg("No users found matching the specified criteria")
        return nil
    }

    logger.Info().Msgf("Generating membership data for %d users", len(ssoUsers.Data))

    // Build the response with membership data
    var usersWithMemberships []UserWithMemberships

    for _, user := range ssoUsers.Data {
        userWithMemberships := UserWithMemberships{
            ID:               safeString(user.ID),
            Username:         safeString(user.Attributes.UserName),
            Email:            safeString(user.Attributes.Email),
            Name:             safeString(user.Attributes.Name),
            Active:           safeBool(user.Attributes.Active),
            GroupMemberships: []MembershipInfo{},
            OrgMemberships:   []MembershipInfo{},
        }

        // Get group memberships
        if user.ID != nil {
            groupMemberships, err := mc.GetUserGroupMemberships(groupID, *user.ID)
            if err == nil {
                for _, gm := range groupMemberships.Data {
                    membershipInfo := MembershipInfo{
                        MembershipID: safeString(gm.ID),
                        ID:           safeString(gm.Relationship.Group.Data.ID),
                        Name:         safeString(gm.Relationship.Group.Data.Attributes.Name),
                        RoleID:       safeString(gm.Relationship.Role.Data.ID),
                        RoleName:     safeString(gm.Relationship.Role.Data.Attributes.Name),
                    }
                    userWithMemberships.GroupMemberships = append(userWithMemberships.GroupMemberships, membershipInfo)
                }
            } else {
                logger.Warn().Err(err).Msgf("Failed to get group memberships for user %s", safeString(user.Attributes.Email))
            }

            // Get org memberships
            orgMemberships, err := mc.GetUserOrgMembershipsOfGroup(groupID, *user.ID)
            if err == nil {
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
                    userWithMemberships.OrgMemberships = append(userWithMemberships.OrgMemberships, membershipInfo)
                }
            } else {
                logger.Warn().Err(err).Msgf("Failed to get org memberships for user %s", safeString(user.Attributes.Email))
            }
        }

        usersWithMemberships = append(usersWithMemberships, userWithMemberships)
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
    logger.Info().Msgf("Successfully generated membership data for %d users", len(usersWithMemberships))
    return nil
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


