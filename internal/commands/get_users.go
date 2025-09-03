package commands

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk-labs/snyk-sso-membership/pkg/client"
	"github.com/snyk-labs/snyk-sso-membership/pkg/config"
	"github.com/snyk-labs/snyk-sso-membership/pkg/sso"
	"github.com/spf13/cobra"
)

func GetUsers(logger *zerolog.Logger) *cobra.Command {
	getCmd := cobra.Command{
		Use:                   "get-users [groupID]",
		Short:                 "Get users from a SSO matching specified criteria and output as CSV",
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
			return runGetUsers(args, logger, sc)
		},
	}

	return &getCmd
}

func runGetUsers(args []string, logger *zerolog.Logger, sc userFetcher) error {
	groupID := args[0]

	ssoUsers, err := getAndFilterUsers(groupID, logger, sc)
	if err != nil {
		return err
	}

	// return matching users
	if len(*ssoUsers.Data) > 0 {
		header := []string{"username", "email", "name", "active"}
		if err := writeQuotedRecord(os.Stdout, header); err != nil {
			logger.Error().Err(err).Msg("failed to write csv header")
			return err
		}

		for _, user := range *ssoUsers.Data {
			var username, email, name, active string
			if user.Attributes != nil {
				if user.Attributes.UserName != nil {
					username = *user.Attributes.UserName
				}
				if user.Attributes.Email != nil {
					email = *user.Attributes.Email
				}
				if user.Attributes.Name != nil {
					name = *user.Attributes.Name
				}
				if user.Attributes.Active != nil {
					active = strconv.FormatBool(*user.Attributes.Active)
				}
			}
			record := []string{username, email, name, active}
			if err := writeQuotedRecord(os.Stdout, record); err != nil {
				logger.Error().Err(err).Msg("failed to write csv record")
				return err
			}
		}
	} else {
		logger.Error().Msg("No users found matching the specified criteria")
	}
	return nil
}

func writeQuotedRecord(writer io.Writer, record []string) error {
	var b strings.Builder
	for i, field := range record {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"`)
		b.WriteString(strings.ReplaceAll(field, `"`, `""`))
		b.WriteString(`"`)
	}
	b.WriteString("\n")
	_, err := writer.Write([]byte(b.String()))
	return err
}
