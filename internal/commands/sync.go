package commands

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

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
			// optional csv file path will be used if specified, otherwise it will be empty
			csvFilePathFlag := cmd.Flags().Lookup("csvFilePath")
			if csvFilePathFlag != nil {
				csvFilePath = csvFilePathFlag.Value.String()
			}

			_, err := uuid.Parse(groupID)
			if err != nil {
				logger.Error().Msgf("groupID must be a valid UUID: %s", args[0])
				return fmt.Errorf("groupID must be a valid UUID: %s", args[0])
			}

			var domainRegexp = regexp.MustCompile(`^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`)
			if !domainRegexp.MatchString(domain) {
				logger.Error().Msgf("domain must be a valid domain name: %s", domain)
				return fmt.Errorf("domain must be a valid domain name: %s", domain)
			}
			if !domainRegexp.MatchString(ssoDomain) {
				logger.Error().Msgf("ssoDomain must be a valid domain name: %s", ssoDomain)
				return fmt.Errorf("ssoDomain must be a valid domain name: %s", ssoDomain)
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
			// get the 2 required flags
			domain := cmd.Flags().Lookup("domain").Value.String()
			ssoDomain := cmd.Flags().Lookup("ssoDomain").Value.String()
			// optional csvFilePath flag will be used if specified, otherwise it will be empty
			csvFilePath := cmd.Flags().Lookup("csvFilePath").Value.String()

			// instantiate a new client and sso service
			c := client.New(config.New())
			sc := sso.New(c)
			// get all sso users
			ssoUsers, err := sc.GetUsers(groupID, logger)
			if err != nil {
				logger.Fatal().Err(err).Msg("Failed to get SSO users")
			}

			if csvFilePath != "" {
				csvEmails, err := readCsvFile(csvFilePath, logger)

				if err != nil {
					logger.Error().Err(err).Msg("Failed to read CSV file")
					return err
				}
				if len(csvEmails) == 0 {
					logger.Error().Msg("CSV file is empty")
					return fmt.Errorf("CSV file is empty")
				}
				// filter SSO individuals with provided CSV emails and include their corresponding provisioned email in the SSO domain
				filteredUserData := filterUsers(csvEmails, *ssoUsers, true, logger)
				ssoUsers.Data = &filteredUserData
			}

			if len(*ssoUsers.Data) > 0 {
				mc := membership.New(c)
				// synchronize Group and Org memberships of matching users of domain to ssoDomain
				mc.SyncMemberships(groupID, domain, ssoDomain, *ssoUsers, logger)
			} else {
				logger.Info().Msgf("No corresponding SSO users found on groupID: %s, no Users to synchronize", groupID)
			}
			return nil
		},
	}
	return &syncCmd
}

// readCsvFile reads a CSV file and returns a slice of emails found in the first column.
func readCsvFile(filePath string, logger *zerolog.Logger) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		logger.Error().Err(err).Msgf("Failed to open CSV file: %s", filePath)
		return nil, err
	}
	defer file.Close()
	// Read the CSV file and extract emails
	reader := csv.NewReader(file)
	var csvEmails []string

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			logger.Error().Err(err).Msg("Failed to read record in CSV file")
		}
		if len(record) > 0 && record[0] != "" {
			csvEmails = append(csvEmails, record[0])
		}
	}

	return csvEmails, nil
}

// filterUsers filters the SSO users with provided CSV emails.
// Depending on the includeSSODomain flag, this may include the corresponding User on provisioned emails in the SSO domain.
func filterUsers(emails []string, users sso.Users, includeSSODomain bool, logger *zerolog.Logger) []sso.User {
	var filteredUsers []sso.User
	for _, email := range emails {
		foundCount := 0
		var emailUserName []string
		if isValidEmailRFC5322(email) {
			emailUserName = strings.Split(email, "@")
		} else {
			logger.Error().Msgf("Invalid email address format: %s", email)
		}
		// ssoDomain may not be set so provisionedEmail may be an invalid email
		var provisionedEmail string
		if includeSSODomain && ssoDomain != "" && len(emailUserName) > 0 && len(emailUserName[0]) > 0 {
			provisionedEmail = emailUserName[0] + "@" + ssoDomain
		}

		for _, user := range *users.Data {
			if user.Attributes != nil && user.Attributes.Email != nil &&
				(*user.Attributes.Email == email || *user.Attributes.Email == provisionedEmail) {
				filteredUsers = append(filteredUsers, user)
				foundCount++
				// search through SSO users until we find both the original email and the provisioned email
				if (includeSSODomain && foundCount == 2) || !includeSSODomain {
					break
				}
			}
		}
		if includeSSODomain && foundCount < 2 {
			logger.Warn().Msgf("Email %s not found in SSO with a corresponding %s", email, provisionedEmail)
		}
	}
	return filteredUsers
}
