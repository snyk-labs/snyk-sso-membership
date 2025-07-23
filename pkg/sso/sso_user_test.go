package sso

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk-labs/snyk-sso-membership/test/mocks"
	"github.com/stretchr/testify/assert"
)

func stringPtr(s string) *string {
	return &s
}

func boolPtr(b bool) *bool {
	return &b
}

func TestGetSSOUsers(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	sso := New(mockClient)

	groupID := "test-group-id"
	connectionID := "test-connection-id"
	expectedPath := fmt.Sprintf("/rest/groups/%s/sso_connections/%s/users", groupID, connectionID)
	expectedResponse := Users{
		Data: &[]User{
			{
				ID:   stringPtr("test-user-id"),
				Type: stringPtr("user"),
				Attributes: &struct {
					Name     *string `json:"name"`
					Email    *string `json:"email"`
					UserName *string `json:"username"`
					Active   *bool   `json:"active"`
				}{
					Name:     stringPtr("test-user-name"),
					Email:    stringPtr("test@example.com"),
					UserName: stringPtr("test-user-username"),
					Active:   boolPtr(true),
				},
			},
		},
	}
	expectedResponseBody, _ := json.Marshal(expectedResponse)

	mockClient.On("Get", expectedPath).Return(expectedResponseBody, nil)

	users, err := sso.getSSOUsers(groupID, connectionID)
	assert.NoError(t, err)
	assert.NotNil(t, users)
	assert.Equal(t, *expectedResponse.Data, *users.Data)

	mockClient.AssertExpectations(t)
}

func TestGetSSOUsers_Error(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	sso := New(mockClient)

	groupID := "test-group-id"
	connectionID := "test-connection-id"
	expectedPath := fmt.Sprintf("/rest/groups/%s/sso_connections/%s/users", groupID, connectionID)

	mockClient.On("Get", expectedPath).Return([]byte{}, errors.New("get error"))

	users, err := sso.getSSOUsers(groupID, connectionID)
	assert.Error(t, err)
	assert.EqualError(t, err, "get error")
	assert.Nil(t, users)

	mockClient.AssertExpectations(t)
}

func TestGetSSOUsers_UnmarshalError(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	sso := New(mockClient)

	groupID := "test-group-id"
	connectionID := "test-connection-id"
	expectedPath := fmt.Sprintf("/rest/groups/%s/sso_connections/%s/users", groupID, connectionID)

	mockClient.On("Get", expectedPath).Return([]byte("invalid json"), nil)

	users, err := sso.getSSOUsers(groupID, connectionID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid character")
	assert.Nil(t, users)

	mockClient.AssertExpectations(t)
}

func TestDeleteSSOUser(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	sso := New(mockClient)

	groupID := "test-group-id"
	connectionID := "test-connection-id"
	userID := "test-user-id"
	expectedPath := fmt.Sprintf("/rest/groups/%s/sso_connections/%s/users/%s", groupID, connectionID, userID)

	mockClient.On("Delete", expectedPath).Return([]byte{}, nil)

	err := sso.deleteSSOUser(groupID, connectionID, userID)
	assert.NoError(t, err)

	mockClient.AssertExpectations(t)
}

func TestDeleteSSOUser_Error(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	sso := New(mockClient)

	groupID := "test-group-id"
	connectionID := "test-connection-id"
	userID := "test-user-id"
	expectedPath := fmt.Sprintf("/rest/groups/%s/sso_connections/%s/users/%s", groupID, connectionID, userID)

	mockClient.On("Delete", expectedPath).Return([]byte{}, errors.New("delete error"))

	err := sso.deleteSSOUser(groupID, connectionID, userID)
	assert.Error(t, err)
	assert.EqualError(t, err, "delete error")

	mockClient.AssertExpectations(t)
}

func TestIsMatchUserProfileOnDomain(t *testing.T) {
	user := &User{
		Attributes: &struct {
			Name     *string `json:"name"`
			Email    *string `json:"email"`
			UserName *string `json:"username"`
			Active   *bool   `json:"active"`
		}{
			Email: stringPtr("test@example.com"),
		},
	}

	assert.True(t, isUserProfileOfDomain(user, "example.com", false))
	assert.False(t, isUserProfileOfDomain(user, "different.com", false))
	assert.False(t, isUserProfileOfDomain(user, "", false))
}

func TestGetUsers_GetConnectionError(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	sso := New(mockClient)

	groupID := "test-group-id"
	expectedPath := fmt.Sprintf("/rest/groups/%s/sso_connections", groupID)

	mockClient.On("Get", expectedPath).Return([]byte{}, errors.New("unable to get SSO connection on group: test-group-id"))

	_, err := sso.GetUsers(groupID, nil)
	assert.Error(t, err)
	assert.EqualError(t, err, "unable to get SSO connection on group: test-group-id")
}

func TestDeleteUsers_GetConnectionError(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	sso := New(mockClient)
	groupID := "test-group-id"
	expectedUsersResponse := Users{
		Data: &[]User{
			{
				ID: stringPtr("user-id-1"),
				Attributes: &struct {
					Name     *string `json:"name"`
					Email    *string `json:"email"`
					UserName *string `json:"username"`
					Active   *bool   `json:"active"`
				}{
					Email: stringPtr("test1@different.com"),
				},
			},
		},
	}
	logger := zerolog.Nop()

	expectedPath := fmt.Sprintf("/rest/groups/%s/sso_connections", groupID)
	mockClient.On("Get", expectedPath).Return([]byte{}, errors.New("unable to get SSO connection on group: test-group-id"))

	err := sso.DeleteUsers(groupID, expectedUsersResponse, &logger)
	assert.Error(t, err)
	assert.EqualError(t, err, "unable to get SSO connection on group: test-group-id")
}

func TestGetUsers_EmptyConnection(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	sso := New(mockClient)

	groupID := "test-group-id"
	expectedPath := fmt.Sprintf("/rest/groups/%s/sso_connections", groupID)
	expectedResponse := Connection{
		Data: []struct {
			ID         *string `json:"id"`
			Type       *string `json:"type"`
			Attributes *struct {
				Name *string `json:"name"`
			} `json:"attributes"`
		}{},
	}
	expectedResponseBody, _ := json.Marshal(expectedResponse)
	mockClient.On("Get", expectedPath).Return(expectedResponseBody, nil)

	_, err := sso.GetUsers(groupID, nil)
	assert.Error(t, err)
	assert.EqualError(t, err, "unable to get SSO connection on group: test-group-id")
}

func TestFilterUsersByDomain(t *testing.T) {
	ssoClient := New(nil) // Client is not used by FilterUsersByDomain directly
	logger := zerolog.Nop()

	users := Users{
		Data: &[]User{
			{ID: stringPtr("1"), Attributes: &struct {
				Name     *string `json:"name"`
				Email    *string `json:"email"`
				UserName *string `json:"username"`
				Active   *bool   `json:"active"`
			}{Email: stringPtr("user1@example.com"), UserName: stringPtr("user1@example.com")}},
			{ID: stringPtr("2"), Attributes: &struct {
				Name     *string `json:"name"`
				Email    *string `json:"email"`
				UserName *string `json:"username"`
				Active   *bool   `json:"active"`
			}{Email: stringPtr("user2@example.com"), UserName: stringPtr("user2@example.com")}},
			{ID: stringPtr("3"), Attributes: &struct {
				Name     *string `json:"name"`
				Email    *string `json:"email"`
				UserName *string `json:"username"`
				Active   *bool   `json:"active"`
			}{Email: stringPtr("user3@another.com"), UserName: stringPtr("user3@another.com")}},
		},
	}

	t.Run("users match domain", func(t *testing.T) {
		filtered, err := ssoClient.FilterUsersByDomain("example.com", users, false, &logger)
		assert.NoError(t, err)
		assert.Len(t, filtered, 2)
		assert.Equal(t, "user1@example.com", *filtered[0].Attributes.Email)
		assert.Equal(t, "user2@example.com", *filtered[1].Attributes.Email)
	})

	t.Run("users match by username", func(t *testing.T) {
		filtered, err := ssoClient.FilterUsersByDomain("another.com", users, true, &logger)
		assert.NoError(t, err)
		assert.Len(t, filtered, 1)
		assert.Equal(t, "user3@another.com", *filtered[0].Attributes.UserName)
	})

	t.Run("no users match domain", func(t *testing.T) {
		filtered, err := ssoClient.FilterUsersByDomain("nonexistent.com", users, false, &logger)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no users found matching domain: nonexistent.com")
		assert.Nil(t, filtered)
	})

	t.Run("no users match username", func(t *testing.T) {
		filtered, err := ssoClient.FilterUsersByDomain("nouser", users, true, &logger)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no users found matching domain: nouser")
		assert.Nil(t, filtered)
	})

	t.Run("empty domain string", func(t *testing.T) {
		filtered, err := ssoClient.FilterUsersByDomain("", users, false, &logger)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no users found matching domain: ")
		assert.Nil(t, filtered)
	})

	t.Run("empty user list", func(t *testing.T) {
		emptyUsers := Users{Data: &[]User{}}
		filtered, err := ssoClient.FilterUsersByDomain("example.com", emptyUsers, false, &logger)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no users found matching domain: example.com")
		assert.Nil(t, filtered)
	})

	t.Run("user with nil attributes", func(t *testing.T) {
		usersWithNilAttributes := Users{
			Data: &[]User{
				{ID: stringPtr("1"), Attributes: nil},
				{ID: stringPtr("2"), Attributes: &struct {
					Name     *string `json:"name"`
					Email    *string `json:"email"`
					UserName *string `json:"username"`
					Active   *bool   `json:"active"`
				}{Email: stringPtr("user2@example.com"), UserName: stringPtr("user2@example.com")}},
			},
		}
		filtered, err := ssoClient.FilterUsersByDomain("example.com", usersWithNilAttributes, true, &logger)
		assert.NoError(t, err)
		assert.Len(t, filtered, 1)
		assert.Equal(t, "user2@example.com", *filtered[0].Attributes.UserName)
	})
}
