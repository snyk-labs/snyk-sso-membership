package commands

import (
	"fmt"

	"golang.org/x/net/idna"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk-labs/snyk-sso-membership/pkg/client"
	"github.com/snyk-labs/snyk-sso-membership/pkg/config"
	"github.com/snyk-labs/snyk-sso-membership/pkg/membership"
	"github.com/snyk-labs/snyk-sso-membership/pkg/sso"
	"github.com/spf13/cobra"
)

func SyncMemberships(logger *zerolog.Logger) *cobra.Command {
	syncCmd := cobra.Command{
		Use:   "sync [groupID]",
		Short: "Synchronizes SSO user assigned Group and Org Memberships",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("expected groupID, arguments specified: %d", len(args))
			}

			groupID := args[0]
			// get the 2 required flags
			domain := cmd.Flags().Lookup("domain").Value.String()
			ssoDomain := cmd.Flags().Lookup("ssoDomain").Value.String()

			_, err := uuid.Parse(groupID)
			if err != nil {
				return fmt.Errorf("groupID must be a valid UUID: %s", args[0])
			}
			_, err = idna.ToASCII(domain)
			if err != nil {
				return fmt.Errorf("domain must be a valid domain name: %s", domain)
			}
			_, err = idna.ToASCII(ssoDomain)
			if err != nil {
				return fmt.Errorf("ssoDomain must be a valid domain name: %s", ssoDomain)
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			// get all sso users
			groupID := args[0]
			c := client.New(config.New())
			sc := sso.New(c)
			ssoUsers, err := sc.GetUsers(groupID, logger)
			if err != nil {
				logger.Fatal().Err(err).Msg("Failed to get SSO users")
			}
			// get the 2 required flags
			domain := cmd.Flags().Lookup("domain").Value.String()
			ssoDomain := cmd.Flags().Lookup("ssoDomain").Value.String()

			if len(*ssoUsers.Data) > 0 {
				mc := membership.New(c)
				// synchronize Group and Org memberships of matching users of domain to ssoDomain
				mc.SyncMemberships(groupID, domain, ssoDomain, *ssoUsers, logger)
			}
		},
	}
	return &syncCmd
}
