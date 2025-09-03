package commands

import (
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk-labs/snyk-sso-membership/pkg/sso"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockSsoDeleter is a mock for the ssoDeleter interface
type MockSsoDeleter struct {
	mock.Mock
}

func (m *MockSsoDeleter) GetUsers(groupID string, logger *zerolog.Logger) (*sso.Users, error) {
	args := m.Called(groupID, logger)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*sso.Users), args.Error(1)
}

func (m *MockSsoDeleter) DeleteUsers(groupID string, users sso.Users, logger *zerolog.Logger) error {
	args := m.Called(groupID, users, logger)
	return args.Error(0)
}

func (m *MockSsoDeleter) FilterUsersByDomain(domain string, users sso.Users, matchByUserName bool, logger *zerolog.Logger) ([]sso.User, error) {
	args := m.Called(domain, users, matchByUserName, logger)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]sso.User), args.Error(1)
}

// makeUserForDeleteTest is a helper to create sso.User for tests
func makeUserForDeleteTest(id, email string, username ...string) sso.User {
	attrs := &struct {
		Name     *string `json:"name"`
		Email    *string `json:"email"`
		UserName *string `json:"username"`
		Active   *bool   `json:"active"`
	}{Email: &email}
	if len(username) > 0 {
		attrs.UserName = &username[0]
	}
	return sso.User{ID: &id, Attributes: attrs}
}

func TestDeleteUsersCommand_Args(t *testing.T) {
	logger := zerolog.New(zerolog.NewConsoleWriter())
	cmd := DeleteUsers(&logger)

	// Backup and restore package-level flag variables
	oldDomain, oldEmail, oldCsvFilePath := domain, email, csvFilePath
	defer func() {
		domain, email, csvFilePath = oldDomain, oldEmail, oldCsvFilePath
	}()

	resetFlags := func() {
		domain, email, csvFilePath = "", "", ""
	}

	t.Run("invalid number of arguments", func(t *testing.T) {
		resetFlags()
		domain = "example.com"
		err := cmd.Args(cmd, []string{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected groupID")
	})

	t.Run("invalid groupID", func(t *testing.T) {
		resetFlags()
		domain = "example.com"
		err := cmd.Args(cmd, []string{"invalid-uuid"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "groupID must be a valid UUID")
	})
}

func TestRunDeleteUsers(t *testing.T) {
	logger := zerolog.Nop()
	validUUID := uuid.New().String()

	allSsoUsers := &sso.Users{
		Data: &[]sso.User{
			makeUserForDeleteTest("id1", "user1@example.com", "user1@example2.com"),
			makeUserForDeleteTest("id2", "user2@example.com", "user2@example2.com"),
			makeUserForDeleteTest("id3", "user3@another.com", "user3@another2.com"),
			makeUserForDeleteTest("id4", "user4@example.com", "user4@example.com"),
		},
	}

	// Backup and restore package-level flag variables
	oldDomain, oldEmail, oldCsvFilePath, oldMatchByUserName := domain, email, csvFilePath, matchByUserName
	defer func() {
		domain, email, csvFilePath, matchByUserName = oldDomain, oldEmail, oldCsvFilePath, oldMatchByUserName
	}()

	resetFlags := func() {
		domain, email, csvFilePath, matchByUserName = "", "", "", false
	}

	t.Run("delete users from csv by email", func(t *testing.T) {
		resetFlags()
		mockSso := new(MockSsoDeleter)

		// Create temp csv file
		tmpFile, err := os.CreateTemp("", "test-*.csv")
		assert.NoError(t, err)
		defer os.Remove(tmpFile.Name())
		_, err = tmpFile.WriteString("user1@example.com\nuser2@example.com\n")
		assert.NoError(t, err)
		tmpFile.Close()

		csvFilePath = tmpFile.Name()

		mockSso.On("GetUsers", validUUID, &logger).Return(allSsoUsers, nil).Once()

		// Expect DeleteUsers to be called with the filtered users
		expectedUsersToDelete := sso.Users{
			Data: &[]sso.User{
				makeUserForDeleteTest("id1", "user1@example.com", "user1@example2.com"),
				makeUserForDeleteTest("id2", "user2@example.com", "user2@example2.com"),
			},
		}
		mockSso.On("DeleteUsers", validUUID, mock.Anything, &logger).Run(func(args mock.Arguments) {
			usersArg := args.Get(1).(sso.Users)
			assert.ElementsMatch(t, *expectedUsersToDelete.Data, *usersArg.Data)
		}).Return(nil).Once()

		err = runDeleteUsers([]string{validUUID}, &logger, mockSso)
		assert.NoError(t, err)
		mockSso.AssertExpectations(t)
	})

	t.Run("delete users from csv with matchByUserName", func(t *testing.T) {
		resetFlags()
		mockSso := new(MockSsoDeleter)

		// Create temp csv file with username to be matched
		tmpFile, err := os.CreateTemp("", "test-*.csv")
		assert.NoError(t, err)
		defer os.Remove(tmpFile.Name())
		// The current implementation of filterUsers matches the full line from the CSV against the UserName.
		// The user to match has UserName "user4@example.com".
		_, err = tmpFile.WriteString("user4@example.com\n")
		assert.NoError(t, err)
		tmpFile.Close()

		// Use a valid UUID
		groupID := validUUID
		// Set package-level variables
		csvFilePath = tmpFile.Name()
		matchByUserName = true
		domain = "example.com" // Needed for FilterUsersByDomain
		mockSso.On("GetUsers", groupID, &logger).Return(allSsoUsers, nil).Once()

		mockSso.On("FilterUsersByDomain", "example.com", *allSsoUsers, true, &logger).Return([]sso.User{
			makeUserForDeleteTest("id4", "user4@example.com", "user4@example.com"),
		}, nil).Once()

		expectedUsersToDelete := sso.Users{
			Data: &[]sso.User{
				makeUserForDeleteTest("id4", "user4@example.com", "user4@example.com"),
			},
		}

		mockSso.On("DeleteUsers", groupID, mock.Anything, &logger).Run(func(args mock.Arguments) {
			usersArg := args.Get(1).(sso.Users)
			assert.ElementsMatch(t, *expectedUsersToDelete.Data, *usersArg.Data)
		}).Return(nil).Once()

		err = runDeleteUsers([]string{groupID}, &logger, mockSso)
		assert.NoError(t, err)
		mockSso.AssertExpectations(t)
	})

	t.Run("empty csv file", func(t *testing.T) {
		resetFlags()
		mockSso := new(MockSsoDeleter)

		// Create temp empty csv file
		tmpFile, err := os.CreateTemp("", "empty-*.csv")
		assert.NoError(t, err)
		defer os.Remove(tmpFile.Name())
		tmpFile.Close()

		csvFilePath = tmpFile.Name()

		mockSso.On("GetUsers", validUUID, &logger).Return(allSsoUsers, nil).Once()

		err = runDeleteUsers([]string{validUUID}, &logger, mockSso)
		assert.Error(t, err)
		assert.EqualError(t, err, "CSV file is empty")
		mockSso.AssertExpectations(t)
		mockSso.AssertNotCalled(t, "DeleteUsers", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("csv file with no matching users", func(t *testing.T) {
		resetFlags()
		mockSso := new(MockSsoDeleter)
		// Create temp csv file
		tmpFile, err := os.CreateTemp("", "test-*.csv")
		assert.NoError(t, err)
		defer os.Remove(tmpFile.Name())
		_, err = tmpFile.WriteString("nonexistent@example.com\n")
		assert.NoError(t, err)
		tmpFile.Close()

		csvFilePath = tmpFile.Name()

		mockSso.On("GetUsers", validUUID, &logger).Return(allSsoUsers, nil).Once()

		err = runDeleteUsers([]string{validUUID}, &logger, mockSso)
		assert.NoError(t, err)
		mockSso.AssertExpectations(t)
		mockSso.AssertNotCalled(t, "DeleteUsers", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("GetUsers returns error", func(t *testing.T) {
		resetFlags()
		mockSso := new(MockSsoDeleter)
		domain = "example.com" // Need to set one of the flags to trigger logic

		mockSso.On("GetUsers", validUUID, &logger).Return(nil, errors.New("API error")).Once()

		err := runDeleteUsers([]string{validUUID}, &logger, mockSso)
		assert.Error(t, err)
		assert.EqualError(t, err, "API error")
		mockSso.AssertExpectations(t)
	})

	t.Run("delete users by domain", func(t *testing.T) {
		resetFlags()
		mockSso := new(MockSsoDeleter)
		domain = "example.com"

		mockSso.On("GetUsers", validUUID, &logger).Return(allSsoUsers, nil).Once()

		filteredUsers := []sso.User{
			makeUserForDeleteTest("id1", "user1@example.com", "user1@example2.com"),
			makeUserForDeleteTest("id2", "user2@example.com", "user2@example2.com"),
			makeUserForDeleteTest("id4", "user4@example.com", "user4@example.com"),
		}
		mockSso.On("FilterUsersByDomain", domain, *allSsoUsers, false, &logger).Return(filteredUsers, nil).Once()

		expectedUsersToDelete := sso.Users{Data: &filteredUsers}
		mockSso.On("DeleteUsers", validUUID, mock.Anything, &logger).Run(func(args mock.Arguments) {
			usersArg := args.Get(1).(sso.Users)
			assert.ElementsMatch(t, *expectedUsersToDelete.Data, *usersArg.Data)
		}).Return(nil).Once()

		err := runDeleteUsers([]string{validUUID}, &logger, mockSso)
		assert.NoError(t, err)
		mockSso.AssertExpectations(t)
	})

	t.Run("delete users by email", func(t *testing.T) {
		resetFlags()
		mockSso := new(MockSsoDeleter)
		email = "user1@example.com"

		mockSso.On("GetUsers", validUUID, &logger).Return(allSsoUsers, nil).Once()

		expectedUsersToDelete := sso.Users{
			Data: &[]sso.User{
				makeUserForDeleteTest("id1", "user1@example.com", "user1@example2.com"),
			},
		}
		mockSso.On("DeleteUsers", validUUID, mock.Anything, &logger).Run(func(args mock.Arguments) {
			usersArg := args.Get(1).(sso.Users)
			assert.ElementsMatch(t, *expectedUsersToDelete.Data, *usersArg.Data)
		}).Return(nil).Once()

		err := runDeleteUsers([]string{validUUID}, &logger, mockSso)
		assert.NoError(t, err)
		mockSso.AssertExpectations(t)
	})

	t.Run("no users found to delete", func(t *testing.T) {
		resetFlags()
		mockSso := new(MockSsoDeleter)
		email = "nonexistent@example.com"

		mockSso.On("GetUsers", validUUID, &logger).Return(allSsoUsers, nil).Once()

		err := runDeleteUsers([]string{validUUID}, &logger, mockSso)
		assert.NoError(t, err)
		mockSso.AssertExpectations(t)
		mockSso.AssertNotCalled(t, "DeleteUsers", mock.Anything, mock.Anything, mock.Anything)
	})
}
