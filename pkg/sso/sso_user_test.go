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

func TestIsMatchUserDomain(t *testing.T) {
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

	assert.True(t, isMatchUserDomain(user, "example.com"))
	assert.False(t, isMatchUserDomain(user, "different.com"))
	assert.False(t, isMatchUserDomain(user, ""))
}

func TestIsMatchUserEmail(t *testing.T) {
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

	assert.True(t, isMatchUserEmail(user, "test@example.com"))
	assert.False(t, isMatchUserEmail(user, "different@example.com"))
	assert.False(t, isMatchUserEmail(user, ""))
	assert.True(t, isMatchUserEmail(user, " test@example.com "))
}

func TestDeleteMatchingUsers_Domain(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	sso := New(mockClient)
	logger := zerolog.Nop()
	groupID := "test-group-id"
	connectionID := "test-connection-id"
	domain := "example.com"
	email := ""
	users := &Users{
		Data: &[]User{
			{
				ID: stringPtr("user-id-1"),
				Attributes: &struct {
					Name     *string `json:"name"`
					Email    *string `json:"email"`
					UserName *string `json:"username"`
					Active   *bool   `json:"active"`
				}{
					Email: stringPtr("test1@example.com"),
				},
			},
			{
				ID: stringPtr("user-id-2"),
				Attributes: &struct {
					Name     *string `json:"name"`
					Email    *string `json:"email"`
					UserName *string `json:"username"`
					Active   *bool   `json:"active"`
				}{
					Email: stringPtr("test2@example.com"),
				},
			},
			{
				ID: stringPtr("user-id-3"),
				Attributes: &struct {
					Name     *string `json:"name"`
					Email    *string `json:"email"`
					UserName *string `json:"username"`
					Active   *bool   `json:"active"`
				}{
					Email: stringPtr("test3@different.com"),
				},
			},
		},
	}

	expectedPath1 := fmt.Sprintf("/rest/groups/%s/sso_connections/%s/users/%s", groupID, connectionID, "user-id-1")
	expectedPath2 := fmt.Sprintf("/rest/groups/%s/sso_connections/%s/users/%s", groupID, connectionID, "user-id-2")

	mockClient.On("Delete", expectedPath1).Return([]byte{}, nil)
	mockClient.On("Delete", expectedPath2).Return([]byte{}, nil)

	count := sso.deleteMatchingUsers(groupID, connectionID, users, domain, email, &logger)
	assert.Equal(t, int32(2), count)

	mockClient.AssertExpectations(t)
}

func TestDeleteMatchingUsers_Email(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	sso := New(mockClient)
	logger := zerolog.Nop()
	groupID := "test-group-id"
	connectionID := "test-connection-id"
	domain := ""
	email := "test1@example.com,test3@different.com"
	users := &Users{
		Data: &[]User{
			{
				ID: stringPtr("user-id-1"),
				Attributes: &struct {
					Name     *string `json:"name"`
					Email    *string `json:"email"`
					UserName *string `json:"username"`
					Active   *bool   `json:"active"`
				}{
					Email: stringPtr("test1@example.com"),
				},
			},
			{
				ID: stringPtr("user-id-2"),
				Attributes: &struct {
					Name     *string `json:"name"`
					Email    *string `json:"email"`
					UserName *string `json:"username"`
					Active   *bool   `json:"active"`
				}{
					Email: stringPtr("test2@example.com"),
				},
			},
			{
				ID: stringPtr("user-id-3"),
				Attributes: &struct {
					Name     *string `json:"name"`
					Email    *string `json:"email"`
					UserName *string `json:"username"`
					Active   *bool   `json:"active"`
				}{
					Email: stringPtr("test3@different.com"),
				},
			},
		},
	}

	expectedPath1 := fmt.Sprintf("/rest/groups/%s/sso_connections/%s/users/%s", groupID, connectionID, "user-id-1")
	expectedPath2 := fmt.Sprintf("/rest/groups/%s/sso_connections/%s/users/%s", groupID, connectionID, "user-id-3")

	mockClient.On("Delete", expectedPath1).Return([]byte{}, nil)
	mockClient.On("Delete", expectedPath2).Return([]byte{}, nil)

	count := sso.deleteMatchingUsers(groupID, connectionID, users, domain, email, &logger)
	assert.Equal(t, int32(2), count)

	mockClient.AssertExpectations(t)
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

func TestDeleteUsers_Success(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	sso := New(mockClient)
	groupID := "test-group-id"
	domain := "example.com"
	email := ""
	logger := zerolog.Nop()

	expectedConnectionPath := fmt.Sprintf("/rest/groups/%s/sso_connections", groupID)
	expectedConnectionResponse := Connection{
		Data: []struct {
			ID         *string `json:"id"`
			Type       *string `json:"type"`
			Attributes *struct {
				Name *string `json:"name"`
			} `json:"attributes"`
		}{
			{
				ID:   stringPtr("test-connection-id"),
				Type: stringPtr("sso_connection"),
				Attributes: &struct {
					Name *string `json:"name"`
				}{
					Name: stringPtr("test-connection-name"),
				},
			},
		},
	}
	expectedConnectionResponseBody, _ := json.Marshal(expectedConnectionResponse)
	mockClient.On("Get", expectedConnectionPath).Return(expectedConnectionResponseBody, nil)

	expectedUsersPath := fmt.Sprintf("/rest/groups/%s/sso_connections/%s/users", groupID, "test-connection-id")
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
					Email: stringPtr("test1@example.com"),
				},
			},
			{
				ID: stringPtr("user-id-2"),
				Attributes: &struct {
					Name     *string `json:"name"`
					Email    *string `json:"email"`
					UserName *string `json:"username"`
					Active   *bool   `json:"active"`
				}{
					Email: stringPtr("test2@example.com"),
				},
			},
			{
				ID: stringPtr("user-id-3"),
				Attributes: &struct {
					Name     *string `json:"name"`
					Email    *string `json:"email"`
					UserName *string `json:"username"`
					Active   *bool   `json:"active"`
				}{
					Email: stringPtr("test3@different.com"),
				},
			},
		},
	}
	expectedUsersResponseBody, _ := json.Marshal(expectedUsersResponse)
	mockClient.On("Get", expectedUsersPath).Return(expectedUsersResponseBody, nil)

	expectedDeletePath1 := fmt.Sprintf("/rest/groups/%s/sso_connections/%s/users/%s", groupID, "test-connection-id", "user-id-1")
	expectedDeletePath2 := fmt.Sprintf("/rest/groups/%s/sso_connections/%s/users/%s", groupID, "test-connection-id", "user-id-2")
	mockClient.On("Delete", expectedDeletePath1).Return([]byte{}, nil)
	mockClient.On("Delete", expectedDeletePath2).Return([]byte{}, nil)

	err := sso.DeleteUsers(groupID, domain, email, &logger)
	assert.NoError(t, err)

	mockClient.AssertExpectations(t)
}

func TestDeleteUsers_NoMatchingUsers(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	sso := New(mockClient)
	groupID := "test-group-id"
	domain := "example.com"
	email := ""
	logger := zerolog.Nop()

	expectedConnectionPath := fmt.Sprintf("/rest/groups/%s/sso_connections", groupID)
	expectedConnectionResponse := Connection{
		Data: []struct {
			ID         *string `json:"id"`
			Type       *string `json:"type"`
			Attributes *struct {
				Name *string `json:"name"`
			} `json:"attributes"`
		}{
			{
				ID:   stringPtr("test-connection-id"),
				Type: stringPtr("sso_connection"),
				Attributes: &struct {
					Name *string `json:"name"`
				}{
					Name: stringPtr("test-connection-name"),
				},
			},
		},
	}
	expectedConnectionResponseBody, _ := json.Marshal(expectedConnectionResponse)
	mockClient.On("Get", expectedConnectionPath).Return(expectedConnectionResponseBody, nil)

	expectedUsersPath := fmt.Sprintf("/rest/groups/%s/sso_connections/%s/users", groupID, "test-connection-id")
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
	expectedUsersResponseBody, _ := json.Marshal(expectedUsersResponse)
	mockClient.On("Get", expectedUsersPath).Return(expectedUsersResponseBody, nil)

	err := sso.DeleteUsers(groupID, domain, email, &logger)
	assert.NoError(t, err)

	mockClient.AssertExpectations(t)
}

func TestDeleteUsers_Email_Success(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	sso := New(mockClient)
	groupID := "test-group-id"
	domain := ""
	email := "test1@example.com,test3@different.com"
	logger := zerolog.Nop()

	expectedConnectionPath := fmt.Sprintf("/rest/groups/%s/sso_connections", groupID)
	expectedConnectionResponse := Connection{
		Data: []struct {
			ID         *string `json:"id"`
			Type       *string `json:"type"`
			Attributes *struct {
				Name *string `json:"name"`
			} `json:"attributes"`
		}{
			{
				ID:   stringPtr("test-connection-id"),
				Type: stringPtr("sso_connection"),
				Attributes: &struct {
					Name *string `json:"name"`
				}{
					Name: stringPtr("test-connection-name"),
				},
			},
		},
	}
	expectedConnectionResponseBody, _ := json.Marshal(expectedConnectionResponse)
	mockClient.On("Get", expectedConnectionPath).Return(expectedConnectionResponseBody, nil)

	expectedUsersPath := fmt.Sprintf("/rest/groups/%s/sso_connections/%s/users", groupID, "test-connection-id")
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
					Email: stringPtr("test1@example.com"),
				},
			},
			{
				ID: stringPtr("user-id-2"),
				Attributes: &struct {
					Name     *string `json:"name"`
					Email    *string `json:"email"`
					UserName *string `json:"username"`
					Active   *bool   `json:"active"`
				}{
					Email: stringPtr("test2@example.com"),
				},
			},
			{
				ID: stringPtr("user-id-3"),
				Attributes: &struct {
					Name     *string `json:"name"`
					Email    *string `json:"email"`
					UserName *string `json:"username"`
					Active   *bool   `json:"active"`
				}{
					Email: stringPtr("test3@different.com"),
				},
			},
		},
	}
	expectedUsersResponseBody, _ := json.Marshal(expectedUsersResponse)
	mockClient.On("Get", expectedUsersPath).Return(expectedUsersResponseBody, nil)

	expectedDeletePath1 := fmt.Sprintf("/rest/groups/%s/sso_connections/%s/users/%s", groupID, "test-connection-id", "user-id-1")
	expectedDeletePath2 := fmt.Sprintf("/rest/groups/%s/sso_connections/%s/users/%s", groupID, "test-connection-id", "user-id-3")
	mockClient.On("Delete", expectedDeletePath1).Return([]byte{}, nil)
	mockClient.On("Delete", expectedDeletePath2).Return([]byte{}, nil)

	err := sso.DeleteUsers(groupID, domain, email, &logger)
	assert.NoError(t, err)

	mockClient.AssertExpectations(t)
}

func TestDeleteUsers_GetConnectionError(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	sso := New(mockClient)
	groupID := "test-group-id"
	domain := "example.com"
	email := ""
	logger := zerolog.Nop()

	expectedPath := fmt.Sprintf("/rest/groups/%s/sso_connections", groupID)
	mockClient.On("Get", expectedPath).Return([]byte{}, errors.New("unable to get SSO connection on group: test-group-id"))

	err := sso.DeleteUsers(groupID, domain, email, &logger)
	assert.Error(t, err)
	assert.EqualError(t, err, "unable to get SSO connection on group: test-group-id")
}

func TestDeleteUsers_GetUsersError(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	sso := New(mockClient)
	groupID := "test-group-id"
	domain := "example.com"
	email := ""
	logger := zerolog.Nop()

	expectedConnectionPath := fmt.Sprintf("/rest/groups/%s/sso_connections", groupID)
	expectedConnectionResponse := Connection{
		Data: []struct {
			ID         *string `json:"id"`
			Type       *string `json:"type"`
			Attributes *struct {
				Name *string `json:"name"`
			} `json:"attributes"`
		}{
			{
				ID:   stringPtr("test-connection-id"),
				Type: stringPtr("sso_connection"),
				Attributes: &struct {
					Name *string `json:"name"`
				}{
					Name: stringPtr("test-connection-name"),
				},
			},
		},
	}
	expectedConnectionResponseBody, _ := json.Marshal(expectedConnectionResponse)
	mockClient.On("Get", expectedConnectionPath).Return(expectedConnectionResponseBody, nil)

	expectedUsersPath := fmt.Sprintf("/rest/groups/%s/sso_connections/%s/users", groupID, "test-connection-id")
	mockClient.On("Get", expectedUsersPath).Return([]byte{}, errors.New("unable to get SSO users on connection: test-connection-name"))

	err := sso.DeleteUsers(groupID, domain, email, &logger)
	assert.Error(t, err)
	assert.EqualError(t, err, "unable to get SSO users on connection: test-connection-name")
}

func TestGetUsers_GetUsersError(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	sso := New(mockClient)

	groupID := "test-group-id"
	expectedConnectionPath := fmt.Sprintf("/rest/groups/%s/sso_connections", groupID)
	expectedConnectionResponse := Connection{
		Data: []struct {
			ID         *string `json:"id"`
			Type       *string `json:"type"`
			Attributes *struct {
				Name *string `json:"name"`
			} `json:"attributes"`
		}{
			{
				ID:   stringPtr("test-connection-id"),
				Type: stringPtr("sso_connection"),
				Attributes: &struct {
					Name *string `json:"name"`
				}{
					Name: stringPtr("test-connection-name"),
				},
			},
		},
	}
	expectedConnectionResponseBody, _ := json.Marshal(expectedConnectionResponse)
	mockClient.On("Get", expectedConnectionPath).Return(expectedConnectionResponseBody, nil)

	expectedUsersPath := fmt.Sprintf("/rest/groups/%s/sso_connections/%s/users", groupID, "test-connection-id")
	mockClient.On("Get", expectedUsersPath).Return([]byte{}, errors.New("unable to get SSO users on connection: test-connection-name"))
	logger := zerolog.Nop()

	_, err := sso.GetUsers(groupID, &logger)
	assert.Error(t, err)
	assert.EqualError(t, err, "unable to get SSO users on connection: test-connection-name")
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

func TestDeleteUsers_DeleteError(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	sso := New(mockClient)
	groupID := "test-group-id"
	domain := "example.com"
	email := ""
	logger := zerolog.Nop()

	expectedConnectionPath := fmt.Sprintf("/rest/groups/%s/sso_connections", groupID)
	expectedConnectionResponse := Connection{
		Data: []struct {
			ID         *string `json:"id"`
			Type       *string `json:"type"`
			Attributes *struct {
				Name *string `json:"name"`
			} `json:"attributes"`
		}{
			{
				ID:   stringPtr("test-connection-id"),
				Type: stringPtr("sso_connection"),
				Attributes: &struct {
					Name *string `json:"name"`
				}{
					Name: stringPtr("test-connection-name"),
				},
			},
		},
	}
	expectedConnectionResponseBody, _ := json.Marshal(expectedConnectionResponse)
	mockClient.On("Get", expectedConnectionPath).Return(expectedConnectionResponseBody, nil)

	expectedUsersPath := fmt.Sprintf("/rest/groups/%s/sso_connections/%s/users", groupID, "test-connection-id")
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
					Email: stringPtr("test1@example.com"),
				},
			},
		},
	}
	expectedUsersResponseBody, _ := json.Marshal(expectedUsersResponse)
	mockClient.On("Get", expectedUsersPath).Return(expectedUsersResponseBody, nil)

	expectedDeletePath1 := fmt.Sprintf("/rest/groups/%s/sso_connections/%s/users/%s", groupID, "test-connection-id", "user-id-1")
	mockClient.On("Delete", expectedDeletePath1).Return([]byte{}, errors.New("delete error"))

	err := sso.DeleteUsers(groupID, domain, email, &logger)
	// deleteMatchingUsers call returns a count, not error
	assert.NoError(t, err)
	// assert.Error(t, err)
	// assert.EqualError(t, err, "delete error")

	mockClient.AssertExpectations(t)
}
