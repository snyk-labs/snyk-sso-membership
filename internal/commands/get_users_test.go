package commands

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk-labs/snyk-sso-membership/pkg/sso"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock implementation of ssoGetter interface
type mockSSOGetter struct {
	mock.Mock
}

func (m *mockSSOGetter) GetUsers(groupID string, logger *zerolog.Logger) (*sso.Users, error) {
	args := m.Called(groupID, logger)
	return args.Get(0).(*sso.Users), args.Error(1)
}

func (m *mockSSOGetter) FilterUsersByDomain(domain string, users sso.Users, matchByUserName bool, logger *zerolog.Logger) ([]sso.User, error) {
	args := m.Called(domain, users, matchByUserName, logger)
	return args.Get(0).([]sso.User), args.Error(1)
}

func (m *mockSSOGetter) FilterUsersByProfileIDs(identifiers []string, users sso.Users, matchByUserName bool, logger *zerolog.Logger) ([]sso.User, error) {
	args := m.Called(identifiers, users, matchByUserName, logger)
	return args.Get(0).([]sso.User), args.Error(1)
}

func TestRunGetUsers(t *testing.T) {
	// Helper functions
	boolPtr := func(b bool) *bool { return &b }
	stringPtr := func(s string) *string { return &s }

	// Create temp csv file with last testcase mock username to be matched
	tmpFile, err := os.CreateTemp("", "users.csv")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	_, err = tmpFile.WriteString("csv@example.com,\n")
	assert.NoError(t, err)
	tmpFile.Close()

	tests := []struct {
		name            string
		args            []string
		setupMock       func(*mockSSOGetter)
		domain          string
		email           string
		csvFilePath     string
		matchByUserName bool
		expectedOutput  string
		expectError     bool
		expectedErrMsg  string
	}{
		{
			name:   "successful get users with domain filter",
			args:   []string{"group-id"},
			domain: "example.com",
			setupMock: func(m *mockSSOGetter) {
				users := &sso.Users{Data: []sso.User{}}
				filteredUsers := []sso.User{
					{
						Attributes: &struct {
							Name     *string `json:"name"`
							Email    *string `json:"email"`
							UserName *string `json:"username"`
							Active   *bool   `json:"active"`
						}{
							Email:    stringPtr("test@example.com"),
							UserName: stringPtr("testuser"),
							Active:   boolPtr(true),
						},
					},
				}
				m.On("GetUsers", "group-id", mock.Anything).Return(users, nil)
				m.On("FilterUsersByDomain", "example.com", *users, false, mock.Anything).Return(filteredUsers, nil)
			},
			expectedOutput: "\"username\",\"email\",\"name\",\"active\"\n\"testuser\",\"test@example.com\",\"\",\"true\"\n",
			expectError:    false,
		},
		{
			name:  "successful get users with email filter",
			args:  []string{"group-id"},
			email: "test@example.com",
			setupMock: func(m *mockSSOGetter) {
				users := &sso.Users{Data: []sso.User{}}
				filteredUsers := []sso.User{
					{
						Attributes: &struct {
							Name     *string `json:"name"`
							Email    *string `json:"email"`
							UserName *string `json:"username"`
							Active   *bool   `json:"active"`
						}{
							Email:    stringPtr("test@example.com"),
							UserName: stringPtr("testuser"),
							Active:   boolPtr(true),
						},
					},
				}
				m.On("GetUsers", "group-id", mock.Anything).Return(users, nil)
				m.On("FilterUsersByProfileIDs", []string{"test@example.com"}, *users, false, mock.Anything).Return(filteredUsers, nil)
			},
			expectedOutput: "\"username\",\"email\",\"name\",\"active\"\n\"testuser\",\"test@example.com\",\"\",\"true\"\n",
			expectError:    false,
		},
		{
			name:   "filter users error is ignored",
			args:   []string{"group-id"},
			domain: "example.com",
			setupMock: func(m *mockSSOGetter) {
				users := &sso.Users{Data: []sso.User{}}
				m.On("GetUsers", "group-id", mock.Anything).Return(users, nil)
				m.On("FilterUsersByDomain", "example.com", *users, false, mock.Anything).Return([]sso.User{}, errors.New("filter error"))
			},
			expectedOutput: "",
			expectError:    false,
		},
		{
			name:        "get users with csv filter",
			args:        []string{"group-id"},
			csvFilePath: tmpFile.Name(),
			setupMock: func(m *mockSSOGetter) {
				users := &sso.Users{Data: []sso.User{}}
				filteredUsers := []sso.User{
					{
						Attributes: &struct {
							Name     *string `json:"name"`
							Email    *string `json:"email"`
							UserName *string `json:"username"`
							Active   *bool   `json:"active"`
						}{
							Email:    stringPtr("csv@example.com"),
							UserName: stringPtr("csvuser"),
							Active:   boolPtr(true),
						},
					},
				}
				m.On("GetUsers", "group-id", mock.Anything).Return(users, nil)
				m.On("FilterUsersByProfileIDs", []string{"csv@example.com"}, *users, false, mock.Anything).Return(filteredUsers, nil)
			},
			expectedOutput: "\"username\",\"email\",\"name\",\"active\"\n\"csvuser\",\"csv@example.com\",\"\",\"true\"\n",
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Backup and restore package-level variables
			oldDomain, oldEmail, oldCsvFilePath := domain, email, csvFilePath
			oldMatchByUserName := matchByUserName
			defer func() {
				domain = oldDomain
				email = oldEmail
				csvFilePath = oldCsvFilePath
				matchByUserName = oldMatchByUserName
			}()

			// Set test values
			domain = tt.domain
			email = tt.email
			csvFilePath = tt.csvFilePath
			matchByUserName = tt.matchByUserName

			// Create mock and set expectations
			mock := new(mockSSOGetter)
			tt.setupMock(mock)

			// Create logger for testing
			logger := zerolog.New(zerolog.NewConsoleWriter())

			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Run test
			err := runGetUsers(tt.args, &logger, mock)

			// Restore stdout
			w.Close()
			os.Stdout = oldStdout

			// Read captured output
			var buf bytes.Buffer
			io.Copy(&buf, r)

			// Assert results
			if tt.expectError {
				assert.Error(t, err)
				if tt.expectedErrMsg != "" {
					assert.Contains(t, err.Error(), tt.expectedErrMsg)
				}
			} else {
				assert.NoError(t, err)
				if tt.expectedOutput != "" {
					assert.Equal(t, tt.expectedOutput, buf.String())
				}
			}
			// Verify all mock expectations were met
			mock.AssertExpectations(t)
		})
	}
}

func TestWriteQuotedRecord(t *testing.T) {
	tests := []struct {
		name     string
		record   []string
		expected string
	}{
		{
			name:     "empty record",
			record:   []string{},
			expected: "\n",
		},
		{
			name:     "single field",
			record:   []string{"test"},
			expected: "\"test\"\n",
		},
		{
			name:     "multiple fields",
			record:   []string{"username", "email", "name"},
			expected: "\"username\",\"email\",\"name\"\n",
		},
		{
			name:     "field with quotes",
			record:   []string{"user\"name"},
			expected: "\"user\"\"name\"\n",
		},
		{
			name:     "empty fields",
			record:   []string{"", "email", ""},
			expected: "\"\",\"email\",\"\"\n",
		},
		{
			name:     "fields with special characters",
			record:   []string{"user,name", "test@email.com", "John \"Quote\" Doe"},
			expected: "\"user,name\",\"test@email.com\",\"John \"\"Quote\"\" Doe\"\n",
		},
		{
			name:     "fields with newlines",
			record:   []string{"line1\nline2", "email"},
			expected: "\"line1\nline2\",\"email\"\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := writeQuotedRecord(&buf, tt.record)

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, buf.String())
		})
	}
}

func TestWriteQuotedRecord_WriteError(t *testing.T) {
	t.Run("writer error", func(t *testing.T) {
		// Create a writer that always fails
		writer := &errorWriter{}
		err := writeQuotedRecord(writer, []string{"test"})

		assert.Error(t, err)
		assert.Equal(t, "write error", err.Error())
	})
}

// errorWriter implements io.Writer and always returns an error
type errorWriter struct{}

func (w *errorWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("write error")
}
