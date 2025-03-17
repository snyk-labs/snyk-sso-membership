package sso

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/snyk-labs/snyk-sso-membership/test/mocks"
	"github.com/stretchr/testify/assert"
)

func TestGetSSOConnection(t *testing.T) {
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
	expectedResponseBody, _ := json.Marshal(expectedResponse)

	mockClient.On("Get", expectedPath).Return(expectedResponseBody, nil)

	connection, err := sso.getSSOConnection(groupID)
	assert.NoError(t, err)
	assert.NotNil(t, connection)
	assert.Equal(t, *expectedResponse.Data[0].ID, *connection.Data[0].ID)
	assert.Equal(t, *expectedResponse.Data[0].Type, *connection.Data[0].Type)
	assert.Equal(t, *expectedResponse.Data[0].Attributes.Name, *connection.Data[0].Attributes.Name)

	mockClient.AssertExpectations(t)
}

func TestGetSSOConnection_Error(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	sso := New(mockClient)

	groupID := "test-group-id"
	expectedPath := fmt.Sprintf("/rest/groups/%s/sso_connections", groupID)

	mockClient.On("Get", expectedPath).Return([]byte{}, errors.New("get error"))

	connection, err := sso.getSSOConnection(groupID)
	assert.Error(t, err)
	assert.EqualError(t, err, "get error")
	assert.Nil(t, connection)

	mockClient.AssertExpectations(t)
}

func TestGetSSOConnection_UnmarshalError(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	sso := New(mockClient)

	groupID := "test-group-id"
	expectedPath := fmt.Sprintf("/rest/groups/%s/sso_connections", groupID)

	mockClient.On("Get", expectedPath).Return([]byte("invalid json"), nil)

	connection, err := sso.getSSOConnection(groupID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid character")
	assert.Nil(t, connection)

	mockClient.AssertExpectations(t)
}
