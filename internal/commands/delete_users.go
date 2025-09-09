package commands

import (
	"github.com/rs/zerolog"
	"github.com/snyk-labs/snyk-sso-membership/pkg/client"
	"github.com/snyk-labs/snyk-sso-membership/pkg/config"
	"github.com/snyk-labs/snyk-sso-membership/pkg/sso"
	"github.com/spf13/cobra"
)

// ssoDeleter defines the interface for SSO user operations needed by delete-users.
type ssoDeleter interface {
	userFetcher
	DeleteUsers(groupID string, users sso.Users, logger *zerolog.Logger) error
}

func DeleteUsers(logger *zerolog.Logger) *cobra.Command {
	deleteCmd := cobra.Command{
		Use:                   "delete-users [groupID]",
		Short:                 "Delete users from a SSO matching specified email or domain address or identifier",
		DisableFlagParsing:    false,
		DisableFlagsInUseLine: false,
		Args: func(_ *cobra.Command, args []string) error {
			return validateGetDeleteArgs(logger, args)
		},
		RunE: func(_ *cobra.Command, args []string) error {
			c := client.New(config.New())
			sc := sso.New(c)
			return runDeleteUsers(args, logger, sc)
		},
	}

	return &deleteCmd
}

func runDeleteUsers(args []string, logger *zerolog.Logger, sc ssoDeleter) error {
	groupID := args[0]

	ssoUsers, err := getAndFilterUsers(groupID, logger, sc)
	if err != nil {
		return err
	}

	// delete matching users
	if len(ssoUsers.Data) > 0 {
		logger.Info().Msgf("Deleting %d users", len(ssoUsers.Data))
		_ = sc.DeleteUsers(groupID, *ssoUsers, logger)
	} else {
		logger.Info().Msg("No users found matching the specified criteria, no Users to delete")
	}
	return nil
}
