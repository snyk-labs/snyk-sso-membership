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
    "github.com/spf13/cobra"
)

// Minimal structs to parse the generated JSON
type deleteUsersWithMemberships struct {
    Users []struct {
        ID               string `json:"id"`
        Username         string `json:"username"`
        Email            string `json:"email"`
        GroupMemberships []struct {
            MembershipID string `json:"membership_id"`
            ID           string `json:"id"`   // group id
            Name         string `json:"name"` // group name
        } `json:"group_memberships"`
        OrgMemberships []struct {
            MembershipID string `json:"membership_id"`
            ID           string `json:"id"`   // org id
            OrgID        string `json:"org_id"`
            Name         string `json:"name"` // org name
        } `json:"org_memberships"`
    } `json:"users"`
}

func DeleteMembershipsFromJSON(logger *zerolog.Logger) *cobra.Command {
	var inputPath string

	cmd := cobra.Command{
		Use:                   "delete-memberships-from-json",
		Short:                 "Delete group and org memberships for users defined in a JSON export",
		DisableFlagParsing:    false,
		DisableFlagsInUseLine: false,
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 0 {
				return fmt.Errorf("unexpected arguments, use --input flag instead")
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
			return runDeleteMembershipsFromJSON(inputPath, logger)
		},
	}

	cmd.Flags().StringVar(&inputPath, "input", "", "Path to users_with_memberships.json (required)")
	_ = cmd.MarkFlagFilename("input", "json")

	return &cmd
}

func runDeleteMembershipsFromJSON(path string, logger *zerolog.Logger) error {
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

    var payload deleteUsersWithMemberships
    if err := json.Unmarshal(bytes, &payload); err != nil {
        logger.Error().Err(err).Msg("failed to parse JSON input")
        return err
    }

    c := client.New(config.New(), logger)
    mc := membership.New(c)

    logger.Info().Msgf("Processing %d users from JSON file", len(payload.Users))

    for _, u := range payload.Users {
        userIdentifier := u.Email
        if userIdentifier == "" {
            userIdentifier = u.Username
        }

        // Delete org memberships first
        for _, om := range u.OrgMemberships {
            orgID := om.OrgID
            if orgID == "" {
                orgID = om.ID
            }
            if om.MembershipID != "" && orgID != "" {
                if err := mc.DeleteOrgMembership(orgID, om.MembershipID); err != nil {
                    logger.Error().Err(err).Msgf("failed to delete org membership for user %s in org %s", userIdentifier, om.Name)
                } else {
                    logger.Info().Msgf("Deleted org membership in org %s for user %s", om.Name, userIdentifier)
                }
            }
        }

        // Delete group memberships using group ID from JSON
        for _, gm := range u.GroupMemberships {
            if gm.MembershipID != "" && gm.ID != "" {
                if err := mc.DeleteGroupMembership(gm.ID, gm.MembershipID); err != nil {
                    logger.Error().Err(err).Msgf("failed to delete group membership for user %s in group %s", userIdentifier, gm.Name)
                } else {
                    logger.Info().Msgf("Deleted group membership in group %s for user %s", gm.Name, userIdentifier)
                }
            }
        }
    }

    logger.Info().Msg("Completed deleting memberships from JSON")
    return nil
}


