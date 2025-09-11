package commands

import (
	"io"
	"os"
	"strconv"
	"strings"

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
			return validateGetDeleteArgs(logger, args)
		},
		RunE: func(_ *cobra.Command, args []string) error {
			c := client.New(config.New(), logger)
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
	if len(ssoUsers.Data) > 0 {
		header := []string{"username", "email", "name", "active"}
		if err := writeQuotedRecord(os.Stdout, header); err != nil {
			logger.Error().Err(err).Msg("failed to write csv header")
			return err
		}

		for _, user := range ssoUsers.Data {
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
