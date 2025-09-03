package commands

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/mail"
	"os"

	"github.com/rs/zerolog"
	"github.com/snyk-labs/snyk-sso-membership/pkg/sso"
)

// userFetcher defines a common interface for getting and filtering SSO users.
type userFetcher interface {
	GetUsers(groupID string, logger *zerolog.Logger) (*sso.Users, error)
	FilterUsersByDomain(domain string, users sso.Users, matchByUserName bool, logger *zerolog.Logger) ([]sso.User, error)
	FilterUsersByProfileIDs(identifiers []string, users sso.Users, matchByUserName bool, logger *zerolog.Logger) ([]sso.User, error)
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
		// Errors from filter functions are intentionally ignored to allow processing to continue.
		// If no users are found, an empty list is returned, which is handled by the calling function.
		filteredUserData, _ := sc.FilterUsersByDomain(domain, *ssoUsers, matchByUserName, logger)
		ssoUsers.Data = &filteredUserData
	} else if email != "" {
		userEmails := []string{email}
		filteredUserData, _ := sc.FilterUsersByProfileIDs(userEmails, *ssoUsers, matchByUserName, logger)
		ssoUsers.Data = &filteredUserData
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
		// filter for a specific SSO User from the provided email in CSV line
		filteredUserData, _ := sc.FilterUsersByProfileIDs(csvEmails, *ssoUsers, matchByUserName, logger)
		ssoUsers.Data = &filteredUserData
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
