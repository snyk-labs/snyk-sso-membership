package commands

import (
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk-labs/snyk-sso-membership/pkg/sso"
	"github.com/stretchr/testify/assert"
)

// Helper function to create a string pointer
func stringPtr(s string) *string {
	return &s
}

func TestSyncMemberships_Args(t *testing.T) {
	logger := zerolog.New(zerolog.NewConsoleWriter())
	cmd := SyncMemberships(&logger)
	validUUID := uuid.New().String()

	// Backup and restore package-level flag variables
	oldDomain, oldSsoDomain, oldCsvFilePath := domain, ssoDomain, csvFilePath
	defer func() {
		domain, ssoDomain, csvFilePath = oldDomain, oldSsoDomain, oldCsvFilePath
	}()

	resetFlags := func() {
		domain, ssoDomain, csvFilePath = "", "", ""
	}

	t.Run("invalid number of arguments", func(t *testing.T) {
		resetFlags()
		domain = "example.com"
		ssoDomain = "sso.example.com"
		err := cmd.Args(cmd, []string{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected groupID")
	})

	t.Run("invalid groupID", func(t *testing.T) {
		resetFlags()
		domain = "example.com"
		ssoDomain = "sso.example.com"
		err := cmd.Args(cmd, []string{"invalid-uuid"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "groupID must be a valid UUID")
	})

	t.Run("invalid domain", func(t *testing.T) {
		resetFlags()
		domain = "invalid_domain_@@"
		ssoDomain = "example.com"
		err := cmd.Args(cmd, []string{validUUID})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "domain must be a valid domain name")
	})

	t.Run("valid domain, invalid ssoDomain", func(t *testing.T) {
		resetFlags()
		domain = "example.com"
		ssoDomain = "invalid_sso_domain_@@"
		err := cmd.Args(cmd, []string{validUUID})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ssoDomain must be a valid domain name")
	})

	t.Run("valid domain and ssoDomain", func(t *testing.T) {
		resetFlags()
		domain = "example.com"
		ssoDomain = "sso.example.com"
		err := cmd.Args(cmd, []string{validUUID})
		assert.NoError(t, err)
	})

	t.Run("missing csv file", func(t *testing.T) {
		resetFlags()
		domain = "example.com"
		ssoDomain = "sso.example.com"
		csvFilePath = "/path/to/nonexistent.csv"
		err := cmd.Args(cmd, []string{validUUID})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "csvFile does not exist")
	})

	t.Run("existing csv file", func(t *testing.T) {
		resetFlags()
		domain = "example.com"
		ssoDomain = "sso.example.com"

		tmpFile, err := os.CreateTemp("", "test*.csv")
		assert.NoError(t, err)
		defer os.Remove(tmpFile.Name())
		_, err = tmpFile.WriteString("user1@example.com\nuser2@example.com\n")
		assert.NoError(t, err)
		tmpFile.Close()

		csvFilePath = tmpFile.Name()
		err = cmd.Args(cmd, []string{validUUID})
		assert.NoError(t, err)
	})
}

func TestFilterUsers(t *testing.T) {
	logger := zerolog.Nop()

	ssoUsers := sso.Users{
		Data: []sso.User{
			makeUser("id1", "user1@example.com", "user1@example2.com"),
			makeUser("id2", "user2@example.com", "user2@example2.com"),
			makeUser("id3", "user1@sso.example.com", "user1-sso"), // Corresponds to user1@example.com if ssoDomain is "sso.example.com"
			makeUser("id4", "user4@another.com", "user4@another2.com"),
			makeUser("id5", "user5@sso.example.com", "user5-sso"), // No corresponding non-sso domain email in this list
			// for username matching test
			makeUser("id6", "real.email@example.com", "csv.user"),
			makeUser("id7", "real.email@sso.example.com", "csv.user.sso"),
			makeUser("id8", "another.email@sso.example.com", "csv.user"),
			makeUser("id9", "user-to-match@by.username", "user-to-match@by.username"),
		},
	}

	// Backup and restore original ssoDomain
	originalSsoDomain := ssoDomain
	defer func() { ssoDomain = originalSsoDomain }()

	t.Run("includeSSODomain false - exact match", func(t *testing.T) {
		ssoDomain = "" // Should not be used
		emailsToFilter := []string{"user1@example.com", "user4@another.com"}
		filtered := filterUsers(emailsToFilter, ssoUsers, false, false, false, &logger)
		assert.Len(t, filtered, 2)
		assert.Equal(t, "user1@example.com", *filtered[0].Attributes.Email)
		assert.Equal(t, "user4@another.com", *filtered[1].Attributes.Email)
	})

	t.Run("includeSSODomain true - match original and sso domain email", func(t *testing.T) {
		ssoDomain = "sso.example.com"
		emailsToFilter := []string{"user1@example.com"}
		filtered := filterUsers(emailsToFilter, ssoUsers, true, false, false, &logger)
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
		filtered := filterUsers(emailsToFilter, ssoUsers, true, false, false, &logger)
		assert.Len(t, filtered, 1)
		assert.Equal(t, "user2@example.com", *filtered[0].Attributes.Email)
	})

	t.Run("includeSSODomain true - only sso domain email found (no original in filter list)", func(t *testing.T) {
		ssoDomain = "sso.example.com"
		// We filter by "user5@example.com", expecting to find "user5@sso.example.com"
		emailsToFilter := []string{"user5@example.com"}
		filtered := filterUsers(emailsToFilter, ssoUsers, true, false, false, &logger)
		assert.Len(t, filtered, 1)
		assert.Equal(t, "user5@sso.example.com", *filtered[0].Attributes.Email)
	})

	t.Run("includeSSODomain true - ssoDomain not set", func(t *testing.T) {
		ssoDomain = ""
		emailsToFilter := []string{"user1@example.com"}
		filtered := filterUsers(emailsToFilter, ssoUsers, true, false, false, &logger)
		assert.Len(t, filtered, 1)
		assert.Equal(t, "user1@example.com", *filtered[0].Attributes.Email)
	})

	t.Run("no matching users", func(t *testing.T) {
		ssoDomain = "sso.example.com"
		emailsToFilter := []string{"nonexistent@example.com"}
		filtered := filterUsers(emailsToFilter, ssoUsers, false, false, false, &logger)
		assert.Len(t, filtered, 0)
	})

	t.Run("empty email list", func(t *testing.T) {
		ssoDomain = "sso.example.com"
		var emailsToFilter []string
		filtered := filterUsers(emailsToFilter, ssoUsers, false, false, false, &logger)
		assert.Len(t, filtered, 0)
	})

	t.Run("empty sso user list", func(t *testing.T) {
		ssoDomain = "sso.example.com"
		emptySsoUsers := sso.Users{Data: []sso.User{}}
		emailsToFilter := []string{"user1@example.com"}
		filtered := filterUsers(emailsToFilter, emptySsoUsers, false, false, false, &logger)
		assert.Len(t, filtered, 0)
	})

	t.Run("user with nil attributes or email", func(t *testing.T) {
		ssoDomain = "sso.example.com"
		usersWithNil := sso.Users{Data: []sso.User{{ID: stringPtr("nil-attr")}, makeUser("id1", "user1@example.com", "user1@example2.com")}}
		emailsToFilter := []string{"user1@example.com"}
		filtered := filterUsers(emailsToFilter, usersWithNil, false, false, false, &logger)
		assert.Len(t, filtered, 1)
		assert.Equal(t, "user1@example.com", *filtered[0].Attributes.Email)
	})

	t.Run("matchByUserName true, matchToLocalPart false - match by full username string", func(t *testing.T) {
		ssoDomain = "sso.example.com"
		// The full string from the CSV is used for matching against the UserName attribute.
		emailsToFilter := []string{"user-to-match@by.username"}
		filtered := filterUsers(emailsToFilter, ssoUsers, true, true, false, &logger)

		// It should find user id9, which has a UserName of "user-to-match@by.username"
		assert.Len(t, filtered, 1)
		assert.Equal(t, "id9", *filtered[0].ID)
	})

	t.Run("matchByUserName and matchToLocalPart true - match by local part username", func(t *testing.T) {
		ssoDomain = "sso.example.com"
		// The email in the list has local part "csv.user", which should match users by username
		emailsToFilter := []string{"csv.user@some-domain.com"}
		// With matchToLocalPart=true, the logic also checks for username matching the local part of the email.
		// The logic is: `matchUserByUserName(user, email) || (includeSSODomain && matchToLocalPart && matchUserByUserName(user, localPart))`
		// This will match users where UserName is "csv.user".
		filtered := filterUsers(emailsToFilter, ssoUsers, true, true, true, &logger)

		// It should find user id6 (by username) and id8 (by username)
		// The inner loop of filterUsers breaks after finding 2 users for a given email.
		assert.Len(t, filtered, 2)

		foundId6 := false
		foundId8 := false
		for _, u := range filtered {
			if *u.ID == "id6" {
				foundId6 = true
			}
			if *u.ID == "id8" {
				foundId8 = true
			}
		}
		assert.True(t, foundId6, "User with id6 (username: csv.user) not found")
		assert.True(t, foundId8, "User with id8 (username: csv.user) not found")
	})
}

// Helper to create sso.User
func makeUser(id, email string, username ...string) sso.User {
	user := sso.User{
		ID: &id,
		Attributes: &struct {
			Name     *string `json:"name"`
			Email    *string `json:"email"`
			UserName *string `json:"username"`
			Active   *bool   `json:"active"`
		}{
			Email: &email,
		},
	}
	if len(username) > 0 {
		user.Attributes.UserName = &username[0]
	}
	return user
}

func TestMatchDomainUser(t *testing.T) {
	stringp := func(s string) *string { return &s }

	testCases := []struct {
		name            string
		user            sso.User
		email           string
		matchByUserName bool
		want            bool
	}{
		{
			name: "match by username when matchByUserName is true",
			user: sso.User{
				Attributes: &struct {
					Name     *string `json:"name"`
					Email    *string `json:"email"`
					UserName *string `json:"username"`
					Active   *bool   `json:"active"`
				}{
					Email:    stringp("different@example.com"),
					UserName: stringp("test@example.com"),
				},
			},
			email:           "test@example.com",
			matchByUserName: true,
			want:            true,
		},
		{
			name: "match by email when matchByUserName is false",
			user: sso.User{
				Attributes: &struct {
					Name     *string `json:"name"`
					Email    *string `json:"email"`
					UserName *string `json:"username"`
					Active   *bool   `json:"active"`
				}{
					Email:    stringp("test@example.com"),
					UserName: stringp("test@example.com"), // valid email format required
				},
			},
			email:           "test@example.com",
			matchByUserName: false,
			want:            true,
		},
		{
			name: "fail match by email when username is not valid email format",
			user: sso.User{
				Attributes: &struct {
					Name     *string `json:"name"`
					Email    *string `json:"email"`
					UserName *string `json:"username"`
					Active   *bool   `json:"active"`
				}{
					Email:    stringp("test@example.com"),
					UserName: stringp("invalid-username"), // not valid email format
				},
			},
			email:           "test@example.com",
			matchByUserName: false,
			want:            false,
		},
		{
			name: "fail when attributes are nil",
			user: sso.User{
				Attributes: nil,
			},
			email:           "test@example.com",
			matchByUserName: false,
			want:            false,
		},
		{
			name: "fail when email is nil",
			user: sso.User{
				Attributes: &struct {
					Name     *string `json:"name"`
					Email    *string `json:"email"`
					UserName *string `json:"username"`
					Active   *bool   `json:"active"`
				}{
					UserName: stringp("test@example.com"),
				},
			},
			email:           "test@example.com",
			matchByUserName: false,
			want:            false,
		},
		{
			name: "fail when username is nil",
			user: sso.User{
				Attributes: &struct {
					Name     *string `json:"name"`
					Email    *string `json:"email"`
					UserName *string `json:"username"`
					Active   *bool   `json:"active"`
				}{
					Email: stringp("test@example.com"),
				},
			},
			email:           "test@example.com",
			matchByUserName: false,
			want:            false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := matchDomainUser(tc.user, tc.email, tc.matchByUserName)
			assert.Equal(t, tc.want, got, "matchDomainUser() = %v, want %v", got, tc.want)
		})
	}
}
