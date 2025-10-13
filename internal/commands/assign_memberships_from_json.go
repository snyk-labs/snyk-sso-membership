package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/rs/zerolog"
	"github.com/snyk-labs/snyk-sso-membership/pkg/client"
	"github.com/snyk-labs/snyk-sso-membership/pkg/config"
	"github.com/snyk-labs/snyk-sso-membership/pkg/membership"
	"github.com/snyk-labs/snyk-sso-membership/pkg/sso"
	"github.com/spf13/cobra"
)

// assignUsersWithMemberships matches the JSON structure from generate-memberships-json
type assignUsersWithMemberships struct {
	Users []struct {
		ID               string `json:"id"` // user ID
		Email            string `json:"email"`
		Username         string `json:"username"`
		GroupMemberships []struct {
			ID       string `json:"id"`   // group id
			Name     string `json:"name"` // group name
			RoleID   string `json:"role_id"`
			RoleName string `json:"role_name"`
		} `json:"group_memberships"`
		OrgMemberships []struct {
			ID       string `json:"id"`   // org id (also in org_id)
			Name     string `json:"name"` // org name
			OrgID    string `json:"org_id"`
			RoleID   string `json:"role_id"`
			RoleName string `json:"role_name"`
		} `json:"org_memberships"`
	} `json:"users"`
}

func AssignMembershipsFromJSON(logger *zerolog.Logger) *cobra.Command {
	var inputPath string

	cmd := cobra.Command{
		Use:   "assign-memberships-from-json [groupID]",
		Short: "Assign group and org memberships to users in a group based on a JSON export",
		Args: func(_ *cobra.Command, args []string) error {
			if err := validateGetDeleteArgs(logger, args); err != nil {
				return err
			}
			if inputPath == "" {
				return fmt.Errorf("--input is required")
			}
			if _, err := os.Stat(inputPath); os.IsNotExist(err) {
				return fmt.Errorf("input file does not exist: %s", inputPath)
			}
			return nil
		},
		RunE: func(_ *cobra.Command, args []string) error {
			groupID := args[0]
			c := client.New(config.New(), logger)
			sc := sso.New(c)
			mc := membership.New(c)
			return runAssignMembershipsFromJSON(groupID, inputPath, logger, sc, mc)
		},
	}

	cmd.Flags().StringVar(&inputPath, "input", "", "Path to users_with_memberships.json (required)")
	cmd.Flags().BoolVar(&matchByUserName, "matchByUserName", false, "Match by UserName Identifier (default: false)")
	_ = cmd.MarkFlagFilename("input", "json")

	return &cmd
}

func runAssignMembershipsFromJSON(groupID, path string, logger *zerolog.Logger, sc *sso.Client, mc *membership.Client) error {
	// Read JSON
	f, err := os.Open(path)
	if err != nil {
		logger.Error().Err(err).Msgf("failed to open input file: %s", path)
		return err
	}
	defer f.Close()

	bytes, err := io.ReadAll(f)
	if err != nil {
		logger.Error().Err(err).Msg("failed to read input file")
		return err
	}

	// Strip BOM if present (handles UTF-8, UTF-16 BOMs)
	bytes = stripBOM(bytes)

	var payload assignUsersWithMemberships
	if err := json.Unmarshal(bytes, &payload); err != nil {
		logger.Error().Err(err).Msg("failed to parse JSON input")
		return err
	}

	// Get all SSO users from the NEW IdP group
	ssoUsers, err := sc.GetUsers(groupID, logger)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get SSO users from group")
		return err
	}

	logger.Info().Msgf("Found %d users in group %s", len(ssoUsers.Data), groupID)
	logger.Info().Msgf("Found %d users in JSON file", len(payload.Users))

	// Match users from NEW IdP group to JSON users by email/username
	for _, ssoUser := range ssoUsers.Data {
		if ssoUser.Attributes == nil || ssoUser.ID == nil {
			continue
		}

		var userIdentifier string
		if matchByUserName && ssoUser.Attributes.UserName != nil {
			userIdentifier = *ssoUser.Attributes.UserName
		} else if ssoUser.Attributes.Email != nil {
			userIdentifier = *ssoUser.Attributes.Email
		} else {
			continue
		}

		// Find matching user in JSON by email/username
		var matchedUser *struct {
			ID               string `json:"id"`
			Email            string `json:"email"`
			Username         string `json:"username"`
			GroupMemberships []struct {
				ID       string `json:"id"`
				Name     string `json:"name"`
				RoleID   string `json:"role_id"`
				RoleName string `json:"role_name"`
			} `json:"group_memberships"`
			OrgMemberships []struct {
				ID       string `json:"id"`
				Name     string `json:"name"`
				OrgID    string `json:"org_id"`
				RoleID   string `json:"role_id"`
				RoleName string `json:"role_name"`
			} `json:"org_memberships"`
		}

		for i := range payload.Users {
			jsonUser := &payload.Users[i]
			var jsonIdentifier string
			if matchByUserName {
				jsonIdentifier = jsonUser.Username
			} else {
				jsonIdentifier = jsonUser.Email
			}

			if userIdentifier == jsonIdentifier {
				matchedUser = jsonUser
				break
			}
		}

		if matchedUser == nil {
			logger.Debug().Msgf("No matching JSON entry for user: %s", userIdentifier)
			continue
		}

		logger.Info().Msgf("Matched user: %s, applying memberships", userIdentifier)

		// Apply group memberships using NEW user ID from ssoUser
		for _, gm := range matchedUser.GroupMemberships {
			if gm.ID == "" || gm.RoleID == "" {
				continue
			}

			groupIDStr := gm.ID
			groupNameStr := gm.Name
			roleIDStr := gm.RoleID
			roleNameStr := gm.RoleName
			userIDStr := *ssoUser.ID // Use NEW user ID from group
			userType := sso.TypeUser

			mbrRelationship := membership.MemberRelationship{
				Group: &struct {
					Data *membership.TypeIdentifierAttributes `json:"data"`
				}{
					Data: &membership.TypeIdentifierAttributes{
						ID:   &groupIDStr,
						Type: ptrString("group"),
						Attributes: &membership.AttributesName{
							Name: &groupNameStr,
						},
					},
				},
				Role: &struct {
					Data *membership.TypeIdentifierAttributes `json:"data"`
				}{
					Data: &membership.TypeIdentifierAttributes{
						ID:   &roleIDStr,
						Type: ptrString("group_role"),
						Attributes: &membership.AttributesName{
							Name: &roleNameStr,
						},
					},
				},
				User: &struct {
					Data *membership.TypeIdentifierAttributes `json:"data"`
				}{
					Data: &membership.TypeIdentifierAttributes{
						ID:   &userIDStr,
						Type: &userType,
					},
				},
			}

			_, err := mc.CreateUserGroupMembership(groupIDStr, mbrRelationship)
			if err != nil {
				logger.Error().Err(err).Msgf("Failed to create group membership for user %s in group %s", userIdentifier, groupNameStr)
			} else {
				logger.Info().Msgf("Created/updated group membership for user %s in group %s with role %s", userIdentifier, groupNameStr, roleNameStr)
			}
		}

		// Apply org memberships using NEW user ID from ssoUser
		for _, om := range matchedUser.OrgMemberships {
			orgIDStr := om.OrgID
			if orgIDStr == "" {
				orgIDStr = om.ID
			}
			if orgIDStr == "" || om.RoleID == "" {
				continue
			}

			orgNameStr := om.Name
			roleIDStr := om.RoleID
			roleNameStr := om.RoleName
			userIDStr := *ssoUser.ID // Use NEW user ID from group
			userType := sso.TypeUser

			mbrRelationship := membership.MemberRelationship{
				Org: &struct {
					Data *membership.TypeIdentifierAttributes `json:"data"`
				}{
					Data: &membership.TypeIdentifierAttributes{
						ID:   &orgIDStr,
						Type: ptrString("org"),
						Attributes: &membership.AttributesName{
							Name: &orgNameStr,
						},
					},
				},
				Role: &struct {
					Data *membership.TypeIdentifierAttributes `json:"data"`
				}{
					Data: &membership.TypeIdentifierAttributes{
						ID:   &roleIDStr,
						Type: ptrString("org_role"),
						Attributes: &membership.AttributesName{
							Name: &roleNameStr,
						},
					},
				},
				User: &struct {
					Data *membership.TypeIdentifierAttributes `json:"data"`
				}{
					Data: &membership.TypeIdentifierAttributes{
						ID:   &userIDStr,
						Type: &userType,
					},
				},
			}

			_, err := mc.CreateUserOrgMembership(orgIDStr, mbrRelationship)
			if err != nil {
				logger.Error().Err(err).Msgf("Failed to create org membership for user %s in org %s", userIdentifier, orgNameStr)
			} else {
				logger.Info().Msgf("Created/updated org membership for user %s in org %s with role %s", userIdentifier, orgNameStr, roleNameStr)
			}
		}
	}

	logger.Info().Msg("Completed assigning memberships from JSON")
	return nil
}

func ptrString(s string) *string {
	return &s
}
