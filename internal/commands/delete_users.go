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

// ssoDeleter defines the interface for SSO user operations needed by delete-users.
type ssoDeleter interface {
	GetUsers(groupID string, logger *zerolog.Logger) (*sso.Users, error)
	DeleteUsers(groupID string, users sso.Users, logger *zerolog.Logger) error
	FilterUsersByDomain(domain string, users sso.Users, matchByUserName bool, logger *zerolog.Logger) ([]sso.User, error)
}

func DeleteUsers(logger *zerolog.Logger) *cobra.Command {
	deleteCmd := cobra.Command{
		Use:                   "delete-users [groupID]",
		Short:                 "Delete users from a SSO matching specified email or domain address",
		DisableFlagParsing:    false,
		DisableFlagsInUseLine: false,
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 1 {
				logger.Error().Msgf("expected groupID argument, got %d", len(args))
				return fmt.Errorf("expected groupID argument, got %d", len(args))
			}

			groupID := args[0]
			// Validate groupID and the flags
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

	// get all sso users
	ssoUsers, err := sc.GetUsers(groupID, logger)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get SSO users")
		return err
	}

	if domain != "" {
		filteredUserData, _ := sc.FilterUsersByDomain(domain, *ssoUsers, matchByUserName, logger)
		ssoUsers.Data = &filteredUserData
	} else if email != "" {
		userEmails := []string{email}
		filteredUserData := filterUsers(userEmails, *ssoUsers, false, matchByUserName, matchToLocalPart, logger)
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
		filteredUserData := filterUsers(csvEmails, *ssoUsers, false, matchByUserName, matchToLocalPart, logger)
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
}

// Checks an email is a valid address based on RFC5322 standards
func isValidEmailRFC5322(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}
