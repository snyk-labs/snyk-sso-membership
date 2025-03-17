package users

import (
	"encoding/json"

	"github.com/snyk-labs/snyk-sso-membership/pkg/client"
)

type User struct {
	client client.SnykClient
}

func New(c client.SnykClient) *User {
	return &User{
		client: c,
	}
}

type UserIdentifier struct {
	Data struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Attributes struct {
			Name              string `json:"name"`
			DefaultOrgContext string `json:"default_org_context,omitempty"`
			Username          string `json:"username,omitempty"`
			Email             string `json:"email"`
			AvatarURL         string `json:"avatar_url"`
		} `json:"attributes"`
	} `json:"data"`
}

func (u *User) getUserDetails() (*UserIdentifier, error) {
	respBody, err := u.client.Get("/rest/self")
	if err != nil {
		return nil, err
	}

	var self UserIdentifier
	encodingError := json.Unmarshal(respBody, &self)
	if encodingError != nil {
		return nil, encodingError
	}

	return &self, nil
}
