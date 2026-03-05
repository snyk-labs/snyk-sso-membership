package commands

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/mail"
	"os"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk-labs/snyk-sso-membership/pkg/sso"
)

// userFetcher defines a common interface for getting and filtering SSO users.
type userFetcher interface {
	GetUsers(groupID string, logger *zerolog.Logger) (*sso.Users, error)
	FilterUsersByDomains(domains []string, users sso.Users, matchByUserName bool, logger *zerolog.Logger) ([]sso.User, error)
	FilterUsersByProfileIDs(identifiers []string, users sso.Users, matchByUserName bool, logger *zerolog.Logger) ([]sso.User, error)
}

// splitDomains parses --domain (single value or comma-separated) into a list of non-empty trimmed domains.
func splitDomains(domain string) []string {
	var out []string
	for _, d := range strings.Split(domain, ",") {
		d = strings.TrimSpace(d)
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

// getAndFilterUsers fetches all users and then filters them based on the command-line flags.
func getAndFilterUsers(groupID string, logger *zerolog.Logger, sc userFetcher) (*sso.Users, error) {
	// get all sso users
	ssoUsers, err := sc.GetUsers(groupID, logger)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get SSO users")
		return nil, err
	}

	if domain != "" {
		// --domain can be comma-separated (e.g. robsworld.com,Robsworld.com); include users matching any.
		domains := splitDomains(domain)
		if len(domains) > 0 {
			filteredUserData, _ := sc.FilterUsersByDomains(domains, *ssoUsers, matchByUserName, logger)
			ssoUsers.Data = filteredUserData
		}
	} else if email != "" {
		userEmails := []string{email}
		filteredUserData, _ := sc.FilterUsersByProfileIDs(userEmails, *ssoUsers, matchByUserName, logger)
		ssoUsers.Data = filteredUserData
	} else if csvFilePath != "" {
		csvEmails, err := readCsvFile(csvFilePath, logger)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to read CSV file")
			return nil, err
		}
		if len(csvEmails) == 0 {
			err := fmt.Errorf("CSV file is empty")
			logger.Error().Err(err).Send()
			return nil, err
		}
		filteredUserData, _ := sc.FilterUsersByProfileIDs(csvEmails, *ssoUsers, matchByUserName, logger)
		ssoUsers.Data = filteredUserData
	}

	return ssoUsers, nil
}

// readCsvFile reads a CSV file and returns a slice of strings from the first column.
func readCsvFile(filePath string, logger *zerolog.Logger) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		logger.Error().Err(err).Msgf("Failed to open CSV file: %s", filePath)
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	var records []string

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			logger.Error().Err(err).Msg("Failed to read record in CSV file")
		}
		if len(record) > 0 && record[0] != "" {
			records = append(records, record[0])
		}
	}

	return records, nil
}

// isValidEmailRFC5322 checks an email is a valid address based on RFC5322 standards.
func isValidEmailRFC5322(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func validateGetDeleteArgs(logger *zerolog.Logger, args []string) error {
	if len(args) != 1 {
		msg := fmt.Sprintf("expected groupID argument, got %d", len(args))
		logger.Error().Msg(msg)
		return fmt.Errorf("%s", msg)
	}

	groupID := args[0]
	// Validate groupID and the flags
	if _, err := uuid.Parse(groupID); err != nil {
		msg := fmt.Sprintf("groupID must be a valid UUID: %s", args[0])
		logger.Error().Msg(msg)
		return fmt.Errorf("%s", msg)
	}

	var domainRegexp = regexp.MustCompile(`^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`)
	if domain != "" && !domainRegexp.MatchString(domain) {
		msg := fmt.Sprintf("domain must be a valid domain name: %s", domain)
		logger.Error().Msg(msg)
		return fmt.Errorf("%s", msg)
	}

	if email != "" {
		if !isValidEmailRFC5322(email) {
			msg := fmt.Sprintf("email must be a valid email address: %s", email)
			logger.Error().Msg(msg)
			return fmt.Errorf("%s", msg)
		}
	}

	if csvFilePath != "" {
		if _, err := os.Stat(csvFilePath); os.IsNotExist(err) {
			msg := fmt.Sprintf("csvFile does not exist: %s", csvFilePath)
			logger.Error().Msg(msg)
			return fmt.Errorf("%s", msg)
		}
	}

	return nil
}

// stripBOM removes UTF-8, UTF-16 LE/BE BOMs from the beginning of data
func stripBOM(data []byte) []byte {
	// UTF-8 BOM
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}
	// UTF-16 LE BOM
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		return data[2:]
	}
	// UTF-16 BE BOM
	if len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF {
		return data[2:]
	}
	return data
}
