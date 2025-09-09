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
	Data []User `json:"data"`
}

type UsersResponse struct {
	Data  []User `json:"data"`
	Links *struct {
		Prev *string `json:"prev"`
		Next *string `json:"next"`
	} `json:"links"`
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

func (sso *Client) getSSOUsers(groupID, ssoConnectionID string, logger *zerolog.Logger) (*Users, error) {
	requestPath := fmt.Sprintf("/rest/groups/%s/sso_connections/%s/users?limit=100", groupID, ssoConnectionID)
	respBody, err := sso.client.Get(requestPath)
	if err != nil {
		return nil, err
	}

	var usersResp UsersResponse
	encodingError := json.Unmarshal(respBody, &usersResp)
	if encodingError != nil {
		return nil, encodingError
	}

	// Initialize with the first page of users.
	// A slice is a reference type, so this is efficient.
	allUsers := usersResp.Data
	logger.Debug().Msg(fmt.Sprintf("Firing request for users: %s", requestPath))

	// iterate all next links
	for {
		nextLink := ""
		// Check if there's a next link
		if usersResp.Links != nil && usersResp.Links.Next != nil {
			nextLink = *usersResp.Links.Next
		}

		if nextLink == "" {
			break
		}

		// Fetch the next page of users
		restNextLink := "/rest" + nextLink
		logger.Debug().Msg(fmt.Sprintf("Fetching users next page: %s", restNextLink))
		nextRespBody, err := sso.client.Get(restNextLink)
		if err != nil {
			return nil, err
		}

		// Unmarshal into a fresh response object for the new page
		var nextPageResp UsersResponse
		encodingError := json.Unmarshal(nextRespBody, &nextPageResp)
		if encodingError != nil {
			return nil, encodingError
		}
		usersResp = nextPageResp // Update usersResp for the next loop iteration's link check

		// Append the next users to the existing list
		if len(usersResp.Data) > 0 {
			logger.Debug().Msg(fmt.Sprintf("Fetched %d users", len(usersResp.Data)))
			allUsers = append(allUsers, usersResp.Data...)
		}
	}
	logger.Debug().Msg(fmt.Sprintf("Fetched total %d users", len(allUsers)))
	return &Users{Data: allUsers}, nil
}

// Checks whether User profile matches the provided domain.
// It checks if the User's email or username (depending on the matchByUserName flag) ends with the provided domain.
func isUserProfileOfDomain(user *User, domain string, matchByUserName bool) bool {
	isMatched := false
	var userProfileID *string

	if user.Attributes != nil {
		if matchByUserName && user.Attributes.UserName != nil {
			userProfileID = user.Attributes.UserName
		} else if user.Attributes.Email != nil {
			userProfileID = user.Attributes.Email
		}
	}

	if domain != "" && userProfileID != nil && strings.HasSuffix(*userProfileID, "@"+domain) {
		isMatched = true
	}

	return isMatched
}

func isUserProfileMatchingIdentifier(user *User, identifier string, matchByUserName bool) bool {
	isMatched := false
	var userProfileID *string

	if user.Attributes != nil {
		if matchByUserName && user.Attributes.UserName != nil {
			userProfileID = user.Attributes.UserName
		} else if user.Attributes.Email != nil {
			userProfileID = user.Attributes.Email
		}
	}

	if identifier != "" && userProfileID != nil && *userProfileID == identifier {
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
	ssoUsers, err := sso.getSSOUsers(groupID, *(ssoConnection.Data)[0].ID, logger)
	if err != nil {
		return nil, fmt.Errorf("unable to get SSO users on connection: %s", *(ssoConnection.Data)[0].Attributes.Name)
	}
	logger.Info().Msg(fmt.Sprintf("SSO Connection Users: %d", len(ssoUsers.Data)))
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

	for _, user := range users.Data {
		err := sso.deleteSSOUser(groupID, ssoConnectionID, *user.ID)
		if err != nil {
			logger.Error().Err(err).Msg(fmt.Sprintf("Failed to delete User: username: %s, email: %s", *user.Attributes.UserName, *user.Attributes.Email))
		} else {
			logger.Info().Msg(fmt.Sprintf("Deleted User: username: %s, email: %s", *user.Attributes.UserName, *user.Attributes.Email))
		}
	}
	return nil
}

// FilterUsersByDomain filters the SSO users based on the provided domain.
func (sso *Client) FilterUsersByDomain(domain string, users Users, matchByUserName bool, logger *zerolog.Logger) ([]User, error) {
	var filteredUsers []User
	for _, user := range users.Data {
		if isUserProfileOfDomain(&user, domain, matchByUserName) {
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

func (sso *Client) FilterUsersByProfileIDs(identifiers []string, users Users, matchByUserName bool, logger *zerolog.Logger) ([]User, error) {
	var filteredUsers []User

	for i := range identifiers {
		for _, user := range users.Data {
			if isUserProfileMatchingIdentifier(&user, identifiers[i], matchByUserName) {
				filteredUsers = append(filteredUsers, user)
				break
			}
		}
	}

	if len(filteredUsers) == 0 {
		logger.Warn().Msg(fmt.Sprintf("No users found matching identifier: %v", identifiers))
		return nil, fmt.Errorf("no users found matching identifiers: %v", identifiers)
	}

	logger.Info().Msg(fmt.Sprintf("Filtered %d users matching identifiers: %v", len(filteredUsers), identifiers))
	return filteredUsers, nil
}
