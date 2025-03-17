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
	userEmail := user.Attributes.Email
	if domain != "" && strings.HasSuffix(*userEmail, "@"+domain) {
		isMatched = true
	}

	return isMatched
}

// checks whether an email matches directly to a Snyk user SSO-mapped email
func isMatchUserEmail(user *User, email string) bool {
	isMatched := false
	userEmail := user.Attributes.Email
	trimEmail := strings.TrimSpace(email)
	if email != "" && *userEmail == trimEmail {
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

func (sso *Client) deleteMatchingUsers(groupID, ssoConnectionID string, users *Users, domain, email string, logger *zerolog.Logger) int32 {
	var count int32
	if domain != "" {
		for _, u := range *users.Data {
			if isMatchUserDomain(&u, domain) {
				err := sso.deleteSSOUser(groupID, ssoConnectionID, *(u.ID))
				if err != nil {
					logger.Error().Err(err).Msg(fmt.Sprintf("Unable to delete user: %s", *u.Attributes.Email))
				} else {
					logger.Info().Msg(fmt.Sprintf("Deleted user: %s", *u.Attributes.Email))
				}
				count++
			}
		}
	} else if email != "" {
		userEmails := strings.Split(email, ",")
		for _, e := range userEmails {
			for _, u := range *users.Data {
				if isMatchUserEmail(&u, e) {
					err := sso.deleteSSOUser(groupID, ssoConnectionID, *(u.ID))
					if err != nil {
						logger.Error().Err(err).Msg(fmt.Sprintf("Unable to delete user: %s", *u.Attributes.Email))
					} else {
						logger.Info().Msg(fmt.Sprintf("Deleted user: %s", *u.Attributes.Email))
					}
					count++
					break
				}
			}
		}
	}
	return count
}

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

func (sso *Client) DeleteUsers(groupID, domain, email string, logger *zerolog.Logger) error {
	ssoConnection, err := sso.getSSOConnection(groupID)
	if err != nil || ssoConnection == nil || len(ssoConnection.Data) == 0 {
		logger.Error().Err(err).Msg(fmt.Sprintf("unable to get SSO connection on group: %s", groupID))
		return fmt.Errorf("unable to get SSO connection on group: %s", groupID)
	}
	logger.Info().Msg(fmt.Sprintf("SSO Connection Name: %s", *(ssoConnection.Data)[0].Attributes.Name))

	ssoConnectionID := *(ssoConnection.Data)[0].ID
	ssoUsers, err := sso.getSSOUsers(groupID, ssoConnectionID)
	if err != nil {
		logger.Error().Err(err).Msg(fmt.Sprintf("unable to get SSO users on connection: %s", *(ssoConnection.Data)[0].Attributes.Name))
		return fmt.Errorf("unable to get SSO users on connection: %s", *(ssoConnection.Data)[0].Attributes.Name)
	}
	// delete matching users
	count := sso.deleteMatchingUsers(groupID, ssoConnectionID, ssoUsers, domain, email, logger)
	logger.Info().Msg(fmt.Sprintf("Deleted %d users", count))
	return nil
}
