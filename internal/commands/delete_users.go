package commands

import (
	"fmt"
	"net/mail"
	"os"
	"regexp"

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
				logger.Error().Msgf("expected groupID argument, got %d", len(args))
				return fmt.Errorf("expected groupID argument, got %d", len(args))
			}
			groupID := args[0]
			// get the flags
			domain := cmd.Flags().Lookup("domain").Value.String()
			email := cmd.Flags().Lookup("email").Value.String()
			// optional csv file path will be used if specified, otherwise it will be empty
			csvFilePath := cmd.Flags().Lookup("csvFilePath").Value.String()

			_, err := uuid.Parse(groupID)
			if err != nil {
				logger.Error().Msgf("groupID must be a valid UUID: %s", args[0])
				return fmt.Errorf("groupID must be a valid UUID: %s", args[0])
			}

			var domainRegexp = regexp.MustCompile(`^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`)
			if domain != "" && !domainRegexp.MatchString(domain) {
				logger.Error().Msgf("domain must be a valid domain name: %s", domain)
				return fmt.Errorf("domain must be a valid domain name: %s", domain)
			}

			if email != "" {
				validEmail := isValidEmailRFC5322(email)
				if !validEmail {
					logger.Error().Msgf("email must be a valid email address: %s", email)
					return fmt.Errorf("email must be a valid email address: %s", email)
				}
			}

			if csvFilePath != "" {
				if _, err := os.Stat(csvFilePath); os.IsNotExist(err) {
					logger.Error().Msgf("csvFile does not exist: %s", csvFilePath)
					return fmt.Errorf("csvFile does not exist: %s", csvFilePath)
				}
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			groupID := args[0]
			// get the mutually exclusive flags i.e. one of 3 flags must be specified
			domain := cmd.Flags().Lookup("domain").Value.String()
			email := cmd.Flags().Lookup("email").Value.String()
			csvFilePath := cmd.Flags().Lookup("csvFilePath").Value.String()

			c := client.New(config.New())
			sc := sso.New(c)
			// get all sso users
			ssoUsers, err := sc.GetUsers(groupID, logger)
			if err != nil {
				logger.Fatal().Err(err).Msg("Failed to get SSO users")
			}

			if domain != "" {
				filteredUserData, _ := sc.FilterUsersByDomain(domain, *ssoUsers, logger)
				ssoUsers.Data = &filteredUserData
			} else if email != "" {
				userEmails := []string{email}
				filteredUserData := filterUsers(userEmails, *ssoUsers, false, logger)
				ssoUsers.Data = &filteredUserData
			} else if csvFilePath != "" {
				csvEmails, err := readCsvFile(csvFilePath, logger)
				if err != nil {
					logger.Error().Err(err).Msg("Failed to read CSV file")
					return err
				}
				if len(csvEmails) == 0 {
					logger.Error().Msg("CSV file is empty")
					return fmt.Errorf("CSV file is empty")
				}
				// filter for a specific SSO User from the provided email in CSV line
				filteredUserData := filterUsers(csvEmails, *ssoUsers, false, logger)
				ssoUsers.Data = &filteredUserData
			}

			// delete matching users
			if len(*ssoUsers.Data) > 0 {
				logger.Info().Msgf("Deleting %d users", len(*ssoUsers.Data))
				_ = sc.DeleteUsers(groupID, *ssoUsers, logger)
			} else {
				logger.Info().Msg("No users found matching the specified criteria, no Users to delete")
			}
			return nil
		},
	}

	return &deleteCmd
}

// Checks an email is a valid address based on RFC5322 standards
func isValidEmailRFC5322(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}
