package commands

import (
	"fmt"
	"net/mail"

	"golang.org/x/net/idna"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk-labs/snyk-sso-membership/pkg/client"
	"github.com/snyk-labs/snyk-sso-membership/pkg/config"
	"github.com/snyk-labs/snyk-sso-membership/pkg/sso"
	"github.com/spf13/cobra"
)

func DeleteUsers(logger *zerolog.Logger) *cobra.Command {
	deleteCmd := cobra.Command{
		Use:                   "delete-users [groupID]",
		Short:                 "Delete users from a SSO matching specified email or domain address",
		DisableFlagParsing:    false,
		DisableFlagsInUseLine: false,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("expected groupID argument, got %d", len(args))
			}
			groupID := args[0]
			// get the flags
			domain := cmd.Flags().Lookup("domain").Value.String()
			email := cmd.Flags().Lookup("email").Value.String()

			_, err := uuid.Parse(groupID)
			if err != nil {
				return fmt.Errorf("groupID must be a valid UUID: %s", args[0])
			}

			if domain != "" {
				_, err := idna.ToASCII(domain)
				if err != nil {
					return fmt.Errorf("domain must be a valid domain name: %s", domain)
				}
			}

			if email != "" {
				validEmail := isValidEmailRFC5322(email)
				if !validEmail {
					return fmt.Errorf("email must be a valid email address: %s", email)
				}
			}

			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			groupID := args[0]
			// get the flags
			domain := cmd.Flags().Lookup("domain").Value.String()
			email := cmd.Flags().Lookup("email").Value.String()
			c := client.New(config.New())
			sc := sso.New(c)
			_ = sc.DeleteUsers(groupID, domain, email, logger)
		},
	}

	return &deleteCmd
}

// Checks an email is a valid address based on RFC5322 standards
func isValidEmailRFC5322(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}
