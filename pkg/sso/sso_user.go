package sso

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk-labs/snyk-sso-membership/pkg/client"
)

type Client struct {
	client client.SnykClient
}

func New(c client.SnykClient) *Client {
	return &Client{
		client: c,
	}
}

type Connection struct {
	Data []struct {
		ID         *string `json:"id"`
		Type       *string `json:"type"`
		Attributes *struct {
			Name *string `json:"name"`
		} `json:"attributes"`
	} `json:"data"`
}

type User struct {
	ID         *string `json:"id"`
	Type       *string `json:"type"`
	Attributes *struct {
		Name     *string `json:"name"`
		Email    *string `json:"email"`
		UserName *string `json:"username"`
		Active   *bool   `json:"active"`
	} `json:"attributes"`
}

type Users struct {
	Data *[]User `json:"data"`
}

const TypeUser = "user"

func (sso *Client) getSSOConnection(groupID string) (*Connection, error) {
	requestPath := fmt.Sprintf("/rest/groups/%s/sso_connections", groupID)
	respBody, err := sso.client.Get(requestPath)
	if err != nil {
		return nil, err
	}

	var ssoConnection Connection
	encodingError := json.Unmarshal(respBody, &ssoConnection)
	if encodingError != nil {
		return nil, encodingError
	}
	return &ssoConnection, nil
}

func (sso *Client) getSSOUsers(groupID, ssoConnectionID string) (*Users, error) {
	requestPath := fmt.Sprintf("/rest/groups/%s/sso_connections/%s/users", groupID, ssoConnectionID)
	respBody, err := sso.client.Get(requestPath)
	if err != nil {
		return nil, err
	}

	var ssoUsers Users
	encodingError := json.Unmarshal(respBody, &ssoUsers)
	if encodingError != nil {
		return nil, encodingError
	}
	return &ssoUsers, nil
}

// Checks whether domain matches User email domain
func isMatchUserDomain(user *User, domain string) bool {
	isMatched := false
	var userEmail *string
	if user.Attributes != nil && user.Attributes.Email != nil {
		userEmail = user.Attributes.Email
	}

	if domain != "" && userEmail != nil && strings.HasSuffix(*userEmail, "@"+domain) {
		isMatched = true
	}

	return isMatched
}

// Deletes a SSO user.
// This sends a "Your Snyk account was deleted" email to the deleted user email
// if PAT is used, it also sends same email to the user behind the PAT
func (sso *Client) deleteSSOUser(groupID, ssoConnectionID, userID string) error {
	requestPath := fmt.Sprintf("/rest/groups/%s/sso_connections/%s/users/%s", groupID, ssoConnectionID, userID)
	_, err := sso.client.Delete(requestPath)
	if err != nil {
		return err
	}

	return nil
}

// GetUsers retrieves SSO users for a given groupID.
// It fetches the SSO connection first and then retrieves users associated with that connection.
func (sso *Client) GetUsers(groupID string, logger *zerolog.Logger) (*Users, error) {
	ssoConnection, err := sso.getSSOConnection(groupID)
	if err != nil || ssoConnection == nil || len(ssoConnection.Data) == 0 {
		return nil, fmt.Errorf("unable to get SSO connection on group: %s", groupID)
	}
	logger.Info().Msg(fmt.Sprintf("SSO Connection Name: %s", *(ssoConnection.Data)[0].Attributes.Name))

	// customer self-service can only create a SSO setting for a single connection
	ssoUsers, err := sso.getSSOUsers(groupID, *(ssoConnection.Data)[0].ID)
	if err != nil {
		return nil, fmt.Errorf("unable to get SSO users on connection: %s", *(ssoConnection.Data)[0].Attributes.Name)
	}
	logger.Info().Msg(fmt.Sprintf("SSO Connection Users: %d", len(*ssoUsers.Data)))
	return ssoUsers, nil
}

// Delete SSO users based on the provided groupID and Users.
func (sso *Client) DeleteUsers(groupID string, users Users, logger *zerolog.Logger) error {
	ssoConnection, err := sso.getSSOConnection(groupID)
	if err != nil || ssoConnection == nil || len(ssoConnection.Data) == 0 {
		logger.Error().Err(err).Msg(fmt.Sprintf("unable to get SSO connection on group: %s", groupID))
		return fmt.Errorf("unable to get SSO connection on group: %s", groupID)
	}
	logger.Info().Msg(fmt.Sprintf("SSO Connection Name: %s", *(ssoConnection.Data)[0].Attributes.Name))

	ssoConnectionID := *(ssoConnection.Data)[0].ID

	for _, user := range *users.Data {
		err := sso.deleteSSOUser(groupID, ssoConnectionID, *user.ID)
		if err != nil {
			logger.Error().Err(err).Msg(fmt.Sprintf("Failed to delete user: %s", *user.Attributes.Email))
		} else {
			logger.Info().Msg(fmt.Sprintf("Deleted user: %s", *user.Attributes.Email))
		}
	}
	return nil
}

// FilterUsersByDomain filters the SSO users based on the provided domain.
func (sso *Client) FilterUsersByDomain(domain string, users Users, logger *zerolog.Logger) ([]User, error) {
	var filteredUsers []User
	for _, user := range *users.Data {
		if isMatchUserDomain(&user, domain) {
			filteredUsers = append(filteredUsers, user)
		}
	}

	if len(filteredUsers) == 0 {
		logger.Warn().Msg(fmt.Sprintf("No users found matching domain: %s", domain))
		return nil, fmt.Errorf("no users found matching domain: %s", domain)
	}

	logger.Info().Msg(fmt.Sprintf("Filtered %d users matching domain: %s", len(filteredUsers), domain))
	return filteredUsers, nil
}
