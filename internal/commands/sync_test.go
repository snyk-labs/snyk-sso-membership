package commands

import (
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk-labs/snyk-sso-membership/pkg/sso"
	"github.com/stretchr/testify/assert"
)

func TestSyncMemberships_Args_GroupID(t *testing.T) {
	logger := zerolog.New(zerolog.NewConsoleWriter())
	t.Run("invalid number of arguments", func(t *testing.T) {
		cmd := SyncMemberships(&logger)
		var domainFlag, ssoDomainFlag string
		cmd.Flags().StringVar(&domainFlag, "domain", "", "domain flag")
		cmd.Flags().StringVar(&ssoDomainFlag, "ssoDomain", "", "ssoDomain flag")
		cmd.SetArgs([]string{})
		cmd.Flags().Set("domain", "example.com")
		cmd.Flags().Set("ssoDomain", "sso.example.com")
		cmd.ParseFlags(nil)
		err := cmd.Args(cmd, []string{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected groupID")
	})

	t.Run("invalid groupID", func(t *testing.T) {
		cmd := SyncMemberships(&logger)
		var domainFlag, ssoDomainFlag string
		cmd.Flags().StringVar(&domainFlag, "domain", "", "domain flag")
		cmd.Flags().StringVar(&ssoDomainFlag, "ssoDomain", "", "ssoDomain flag")
		cmd.SetArgs([]string{})
		cmd.Flags().Set("domain", "example.com")
		cmd.Flags().Set("ssoDomain", "sso.example.com")
		cmd.ParseFlags(nil)
		err := cmd.Args(cmd, []string{"invalid-uuid"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "groupID must be a valid UUID")
	})
}

func TestSyncMemberships_Args_DomainValidation(t *testing.T) {
	logger := zerolog.New(zerolog.NewConsoleWriter())
	validUUID := uuid.New().String()

	t.Run("invalid domain", func(t *testing.T) {
		cmd := SyncMemberships(&logger)
		var domainFlag, ssoDomainFlag string
		cmd.Flags().StringVar(&domainFlag, "domain", "", "domain flag")
		cmd.Flags().StringVar(&ssoDomainFlag, "ssoDomain", "", "ssoDomain flag")
		cmd.SetArgs([]string{validUUID})
		cmd.Flags().Set("domain", "invalid_domain_@@")
		cmd.Flags().Set("ssoDomain", "example.com")
		cmd.ParseFlags(nil)
		err := cmd.Args(cmd, []string{validUUID})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "domain must be a valid domain name")
	})

	t.Run("valid domain, invalid ssoDomain", func(t *testing.T) {
		cmd := SyncMemberships(&logger)
		var domainFlag, ssoDomainFlag string
		cmd.Flags().StringVar(&domainFlag, "domain", "", "domain flag")
		cmd.Flags().StringVar(&ssoDomainFlag, "ssoDomain", "", "ssoDomain flag")
		cmd.SetArgs([]string{validUUID})
		cmd.Flags().Set("domain", "example.com")
		cmd.Flags().Set("ssoDomain", "invalid_sso_domain_@@")
		cmd.ParseFlags(nil)
		err := cmd.Args(cmd, []string{validUUID})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ssoDomain must be a valid domain name")
	})

	t.Run("valid domain and ssoDomain", func(t *testing.T) {
		cmd := SyncMemberships(&logger)
		var domainFlag, ssoDomainFlag string
		cmd.Flags().StringVar(&domainFlag, "domain", "", "domain flag")
		cmd.Flags().StringVar(&ssoDomainFlag, "ssoDomain", "", "ssoDomain flag")
		cmd.SetArgs([]string{validUUID})
		cmd.Flags().Set("domain", "example.com")
		cmd.Flags().Set("ssoDomain", "sso.example.com")
		cmd.ParseFlags(nil)
		err := cmd.Args(cmd, []string{validUUID})
		assert.NoError(t, err)
	})
}

func TestSyncMemberships_Args_CsvFilePathValidation(t *testing.T) {
	logger := zerolog.New(zerolog.NewConsoleWriter())
	validUUID := uuid.New().String()

	t.Run("missing csv file", func(t *testing.T) {
		cmd := SyncMemberships(&logger)
		var domainFlag, ssoDomainFlag, csvFilePathFlag string
		cmd.Flags().StringVar(&domainFlag, "domain", "", "domain flag")
		cmd.Flags().StringVar(&ssoDomainFlag, "ssoDomain", "", "ssoDomain flag")
		cmd.Flags().StringVar(&csvFilePathFlag, "csvFilePath", "", "csv file path flag")
		cmd.SetArgs([]string{validUUID})
		cmd.Flags().Set("domain", "example.com")
		cmd.Flags().Set("ssoDomain", "sso.example.com")
		cmd.Flags().Set("csvFilePath", "/path/to/nonexistent.csv")
		cmd.ParseFlags(nil)
		err := cmd.Args(cmd, []string{validUUID})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "csvFile does not exist")
	})

	t.Run("invalid csv file format", func(t *testing.T) {
		// Create a temporary invalid CSV file
		tmpFile, err := os.CreateTemp("", "invalid*.csv")
		assert.NoError(t, err)
		defer os.Remove(tmpFile.Name())
		_, err = tmpFile.WriteString("not,a,valid,csv\n\"unterminated")
		assert.NoError(t, err)
		tmpFile.Close()

		cmd := SyncMemberships(&logger)
		var domainFlag, ssoDomainFlag, csvFilePathFlag string
		cmd.Flags().StringVar(&domainFlag, "domain", "", "domain flag")
		cmd.Flags().StringVar(&ssoDomainFlag, "ssoDomain", "", "ssoDomain flag")
		cmd.Flags().StringVar(&csvFilePathFlag, "csvFilePath", "", "csv file path flag")
		cmd.SetArgs([]string{validUUID})
		cmd.Flags().Set("domain", "example.com")
		cmd.Flags().Set("ssoDomain", "sso.example.com")
		cmd.Flags().Set("csvFilePath", tmpFile.Name())
		cmd.ParseFlags(nil)
		// Args does not parse CSV, so expect no error here
		err = cmd.Args(cmd, []string{validUUID})
		assert.NoError(t, err)
	})
	t.Run("existing csv file", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "test*.csv")
		assert.NoError(t, err)
		defer os.Remove(tmpFile.Name())
		_, err = tmpFile.WriteString("user1@example.com\nuser2@example.com\n")
		assert.NoError(t, err)
		tmpFile.Close()

		cmd := SyncMemberships(&logger)
		var domainFlag, ssoDomainFlag, csvFilePathFlag string
		cmd.Flags().StringVar(&domainFlag, "domain", "", "domain flag")
		cmd.Flags().StringVar(&ssoDomainFlag, "ssoDomain", "", "ssoDomain flag")
		cmd.Flags().StringVar(&csvFilePathFlag, "csvFilePath", "", "csv file path flag")
		cmd.SetArgs([]string{validUUID})
		cmd.Flags().Set("domain", "example.com")
		cmd.Flags().Set("ssoDomain", "sso.example.com")
		cmd.Flags().Set("csvFilePath", tmpFile.Name())
		cmd.ParseFlags(nil)
		err = cmd.Args(cmd, []string{validUUID})
		assert.NoError(t, err)
	})
}

func TestFilterUsers(t *testing.T) {
	logger := zerolog.Nop()

	// Helper to create sso.User
	makeUser := func(id, email string) sso.User {
		return sso.User{ID: &id, Attributes: &struct {
			Name     *string `json:"name"`
			Email    *string `json:"email"`
			UserName *string `json:"username"`
			Active   *bool   `json:"active"`
		}{Email: &email}}
	}

	ssoUsers := sso.Users{
		Data: &[]sso.User{
			makeUser("id1", "user1@example.com"),
			makeUser("id2", "user2@example.com"),
			makeUser("id3", "user1@sso.example.com"), // Corresponds to user1@example.com if ssoDomain is "sso.example.com"
			makeUser("id4", "user4@another.com"),
			makeUser("id5", "user5@sso.example.com"), // No corresponding non-sso domain email in this list
		},
	}

	// Backup and restore original ssoDomain
	originalSsoDomain := ssoDomain
	defer func() { ssoDomain = originalSsoDomain }()

	t.Run("includeSSODomain false - exact match", func(t *testing.T) {
		ssoDomain = "" // Should not be used
		emailsToFilter := []string{"user1@example.com", "user4@another.com"}
		filtered := filterUsers(emailsToFilter, ssoUsers, false, &logger)
		assert.Len(t, filtered, 2)
		assert.Equal(t, "user1@example.com", *filtered[0].Attributes.Email)
		assert.Equal(t, "user4@another.com", *filtered[1].Attributes.Email)
	})

	t.Run("includeSSODomain true - match original and sso domain email", func(t *testing.T) {
		ssoDomain = "sso.example.com"
		emailsToFilter := []string{"user1@example.com"}
		filtered := filterUsers(emailsToFilter, ssoUsers, true, &logger)
		assert.Len(t, filtered, 2)
		// Order might vary, so check for presence
		foundOriginal := false
		foundSso := false
		for _, u := range filtered {
			if *u.Attributes.Email == "user1@example.com" {
				foundOriginal = true
			}
			if *u.Attributes.Email == "user1@sso.example.com" {
				foundSso = true
			}
		}
		assert.True(t, foundOriginal, "Original email user1@example.com not found")
		assert.True(t, foundSso, "SSO domain email user1@sso.example.com not found")
	})

	t.Run("includeSSODomain true - only original email found", func(t *testing.T) {
		ssoDomain = "sso.example.com"
		emailsToFilter := []string{"user2@example.com"} // No user2@sso.example.com in ssoUsers
		filtered := filterUsers(emailsToFilter, ssoUsers, true, &logger)
		assert.Len(t, filtered, 1)
		assert.Equal(t, "user2@example.com", *filtered[0].Attributes.Email)
	})

	t.Run("includeSSODomain true - only sso domain email found (no original in filter list)", func(t *testing.T) {
		ssoDomain = "sso.example.com"
		// We filter by "user5@example.com", expecting to find "user5@sso.example.com"
		emailsToFilter := []string{"user5@example.com"}
		filtered := filterUsers(emailsToFilter, ssoUsers, true, &logger)
		assert.Len(t, filtered, 1)
		assert.Equal(t, "user5@sso.example.com", *filtered[0].Attributes.Email)
	})

	t.Run("includeSSODomain true - ssoDomain not set", func(t *testing.T) {
		ssoDomain = ""
		emailsToFilter := []string{"user1@example.com"}
		filtered := filterUsers(emailsToFilter, ssoUsers, true, &logger)
		assert.Len(t, filtered, 1)
		assert.Equal(t, "user1@example.com", *filtered[0].Attributes.Email)
	})

	t.Run("no matching users", func(t *testing.T) {
		ssoDomain = "sso.example.com"
		emailsToFilter := []string{"nonexistent@example.com"}
		filtered := filterUsers(emailsToFilter, ssoUsers, false, &logger)
		assert.Len(t, filtered, 0)
	})

	t.Run("empty email list", func(t *testing.T) {
		ssoDomain = "sso.example.com"
		var emailsToFilter []string
		filtered := filterUsers(emailsToFilter, ssoUsers, false, &logger)
		assert.Len(t, filtered, 0)
	})

	t.Run("empty sso user list", func(t *testing.T) {
		ssoDomain = "sso.example.com"
		emptySsoUsers := sso.Users{Data: &[]sso.User{}}
		emailsToFilter := []string{"user1@example.com"}
		filtered := filterUsers(emailsToFilter, emptySsoUsers, false, &logger)
		assert.Len(t, filtered, 0)
	})

	t.Run("user with nil attributes or email", func(t *testing.T) {
		ssoDomain = "sso.example.com"
		usersWithNil := sso.Users{Data: &[]sso.User{{ID: stringPtr("nil-attr")}, makeUser("id1", "user1@example.com")}}
		emailsToFilter := []string{"user1@example.com"}
		filtered := filterUsers(emailsToFilter, usersWithNil, false, &logger)
		assert.Len(t, filtered, 1)
		assert.Equal(t, "user1@example.com", *filtered[0].Attributes.Email)
	})
}

// Helper function to create a string pointer
func stringPtr(s string) *string {
	return &s
}
