package membership

import (
	"bytes"
	"encoding/json"
	"fmt"

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

type TypeIdentifier struct {
	ID   *string `json:"id"`
	Type *string `json:"type"`
}

type AttributesName struct {
	Name *string `json:"name"`
}

type TypeIdentifierAttributes struct {
	ID         *string         `json:"id"`
	Type       *string         `json:"type"`
	Attributes *AttributesName `json:"attributes,omitempty"`
}

type MemberRelationship struct {
	Group *struct {
		Data *TypeIdentifierAttributes `json:"data"`
	} `json:"group,omitempty"`
	Org *struct {
		Data *TypeIdentifierAttributes `json:"data"`
	} `json:"org,omitempty"`
	User *struct {
		Data *TypeIdentifierAttributes `json:"data"`
	} `json:"user"`
	Role *struct {
		Data *TypeIdentifierAttributes `json:"data"`
	} `json:"role"`
}

type Membership struct {
	ID           *string             `json:"id"`
	Type         *string             `json:"type"`
	Relationship *MemberRelationship `json:"relationships"`
}

type UserGroupMemberships struct {
	Data []Membership `json:"data"`
}

// UserMembershipResponse is a generic struct for paginated membership API responses.
type UserMembershipResponse struct {
	Data  []Membership `json:"data"`
	Links *struct {
		Prev *string `json:"prev"`
		Next *string `json:"next"`
	} `json:"links"`
}
type UserOrgMemberships struct {
	Data []Membership `json:"data"`
}

type RequestBody struct {
	Data *struct {
		Relationships *struct {
			Group *struct {
				Data *TypeIdentifier `json:"data"`
			} `json:"group,omitempty"`
			Org *struct {
				Data *TypeIdentifier `json:"data"`
			} `json:"org,omitempty"`
			Role *struct {
				Data *TypeIdentifier `json:"data"`
			} `json:"role"`
			User *struct {
				Data *TypeIdentifier `json:"data"`
			} `json:"user"`
		} `json:"relationships"`
		Type string `json:"type"`
	} `json:"data"`
}

type RoleRequestBody struct {
	Data *struct {
		ID            string `json:"id"`
		Relationships *struct {
			Role *struct {
				Data *TypeIdentifier `json:"data"`
			} `json:"role"`
		} `json:"relationships"`
		Type string `json:"type"`
	} `json:"data"`
}

type Response struct {
	Data *Membership `json:"data"`
}

const (
	GroupMembershipType = "group_membership"
	OrgMembershipType   = "org_membership"
)

// getPaginatedMemberships handles fetching all pages for a membership-style endpoint.
func (m *Client) getPaginatedMemberships(requestPath string) ([]Membership, error) {
	respBody, err := m.client.Get(requestPath)
	if err != nil {
		return nil, err
	}

	var resp UserMembershipResponse
	encodingError := json.Unmarshal(respBody, &resp)
	if encodingError != nil {
		return nil, encodingError
	}

	allMemberships := resp.Data

	for {
		nextLink := ""
		if resp.Links != nil && resp.Links.Next != nil {
			nextLink = *resp.Links.Next
		}

		if nextLink == "" {
			break
		}

		restNextLink := "/rest" + nextLink
		nextRespBody, err := m.client.Get(restNextLink)
		if err != nil {
			return nil, err
		}

		var nextPageResp UserMembershipResponse
		encodingError := json.Unmarshal(nextRespBody, &nextPageResp)
		if encodingError != nil {
			return nil, encodingError
		}
		resp = nextPageResp

		if len(resp.Data) > 0 {
			allMemberships = append(allMemberships, resp.Data...)
		}
	}

	return allMemberships, nil
}

func (m *Client) getUserGroupMemberships(groupID, userID string) (*UserGroupMemberships, error) {
	requestPath := fmt.Sprintf("/rest/groups/%s/memberships?limit=100&user_id=%s", groupID, userID)
	allMemberships, err := m.getPaginatedMemberships(requestPath)
	if err != nil {
		return nil, err
	}
	return &UserGroupMemberships{Data: allMemberships}, nil
}

func (m *Client) getUserOrgMembershipsOfGroup(groupID, userID string) (*UserOrgMemberships, error) {
	requestPath := fmt.Sprintf("/rest/groups/%s/org_memberships?limit=100&user_id=%s", groupID, userID)
	allMemberships, err := m.getPaginatedMemberships(requestPath)
	if err != nil {
		return nil, err
	}
	return &UserOrgMemberships{Data: allMemberships}, nil
}

// func (m *Client) getUserOrgMembershipsOfOrg(orgID, userID string) (*UserOrgMemberships, error) {
// 	requestPath := fmt.Sprintf("/rest/orgs/%s/memberships?limit=100&user_id=%s", orgID, userID)
// 	respBody, err := m.client.Get(requestPath)
// 	if err != nil {
// 		return nil, err
// 	}
// 	var orgMemberships UserOrgMemberships
// 	encodingError := json.Unmarshal(respBody, &orgMemberships)
// 	if encodingError != nil {
// 		return nil, encodingError
// 	}
// 	return &orgMemberships, nil
// }

func toTypeIdentifier(typeIDAttributes *TypeIdentifierAttributes) *TypeIdentifier {
	return &TypeIdentifier{
		ID:   typeIDAttributes.ID,
		Type: typeIDAttributes.Type,
	}
}

func (m *Client) createMembershipRequestBody(mbrshipType string, mbrRelationship MemberRelationship) *RequestBody {
	// construct request body
	reqBody := RequestBody{
		Data: &struct {
			Relationships *struct {
				Group *struct {
					Data *TypeIdentifier `json:"data"`
				} `json:"group,omitempty"`
				Org *struct {
					Data *TypeIdentifier `json:"data"`
				} `json:"org,omitempty"`
				Role *struct {
					Data *TypeIdentifier `json:"data"`
				} `json:"role"`
				User *struct {
					Data *TypeIdentifier `json:"data"`
				} `json:"user"`
			} `json:"relationships"`
			Type string `json:"type"`
		}{
			Relationships: &struct {
				Group *struct {
					Data *TypeIdentifier `json:"data"`
				} `json:"group,omitempty"`
				Org *struct {
					Data *TypeIdentifier `json:"data"`
				} `json:"org,omitempty"`
				Role *struct {
					Data *TypeIdentifier `json:"data"`
				} `json:"role"`
				User *struct {
					Data *TypeIdentifier `json:"data"`
				} `json:"user"`
			}{},
			Type: mbrshipType,
		},
	}

	if mbrRelationship.Group != nil {
		reqBody.Data.Relationships.Group = &struct {
			Data *TypeIdentifier `json:"data"`
		}{
			Data: toTypeIdentifier(mbrRelationship.Group.Data),
		}
	}
	if mbrRelationship.Org != nil {
		reqBody.Data.Relationships.Org = &struct {
			Data *TypeIdentifier `json:"data"`
		}{
			Data: toTypeIdentifier(mbrRelationship.Org.Data),
		}
	}
	if mbrRelationship.User != nil {
		reqBody.Data.Relationships.User = &struct {
			Data *TypeIdentifier `json:"data"`
		}{
			Data: toTypeIdentifier(mbrRelationship.User.Data),
		}
	}
	reqBody.Data.Relationships.Role = &struct {
		Data *TypeIdentifier `json:"data"`
	}{
		Data: toTypeIdentifier(mbrRelationship.Role.Data),
	}

	return &reqBody
}

func (m *Client) updateRoleAtUserGroupMembership(groupID, membershipID string, mbr Membership) error {
	roleRelationship := MemberRelationship{
		Role: mbr.Relationship.Role,
	}

	reqBody := RoleRequestBody{
		Data: &struct {
			ID            string `json:"id"`
			Relationships *struct {
				Role *struct {
					Data *TypeIdentifier `json:"data"`
				} `json:"role"`
			} `json:"relationships"`
			Type string `json:"type"`
		}{
			ID: membershipID,
			Relationships: &struct {
				Role *struct {
					Data *TypeIdentifier `json:"data"`
				} `json:"role"`
			}{},
			Type: GroupMembershipType,
		},
	}

	reqBody.Data.Relationships.Role = &struct {
		Data *TypeIdentifier `json:"data"`
	}{
		Data: toTypeIdentifier(roleRelationship.Role.Data),
	}

	encodedBody, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	requestPath := fmt.Sprintf("/rest/groups/%s/memberships/%s", groupID, membershipID)
	_, err = m.client.Patch(requestPath, bytes.NewBuffer(encodedBody))
	if err != nil {
		return err
	}

	return nil
}

func (m *Client) createUserOrgMembership(orgID string, mbrRelationship MemberRelationship) (*Response, error) {
	reqBody := m.createMembershipRequestBody(OrgMembershipType, mbrRelationship)
	encodedBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	requestPath := fmt.Sprintf("/rest/orgs/%s/memberships", orgID)
	respBody, err := m.client.Post(requestPath, bytes.NewBuffer(encodedBody))
	if err != nil {
		return nil, err
	}

	var orgMembership Response
	encodingError := json.Unmarshal(respBody, &orgMembership)
	if encodingError != nil {
		return nil, encodingError
	}
	return &orgMembership, nil
}

func (m *Client) createUserGroupMembership(groupID string, mbrRelationship MemberRelationship) (*Response, error) {
	reqBody := m.createMembershipRequestBody(GroupMembershipType, mbrRelationship)
	encodedBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	requestPath := fmt.Sprintf("/rest/groups/%s/memberships", groupID)
	respBody, err := m.client.Post(requestPath, bytes.NewBuffer(encodedBody))
	if err != nil {
		return nil, err
	}

	var groupMembership Response
	encodingError := json.Unmarshal(respBody, &groupMembership)
	if encodingError != nil {
		return nil, encodingError
	}
	return &groupMembership, nil
}

func (m *Client) deleteOrgMembership(orgID, membershipID string) error {
	requestPath := fmt.Sprintf("/rest/orgs/%s/memberships/%s", orgID, membershipID)
	_, err := m.client.Delete(requestPath)
	if err != nil {
		return err
	}

	return nil
}
