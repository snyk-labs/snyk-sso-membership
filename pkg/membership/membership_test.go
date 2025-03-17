package membership

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/snyk-labs/snyk-sso-membership/test/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func stringPtr(s string) *string {
	return &s
}

func TestGetUserGroupMemberships(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	m := New(mockClient)

	groupID := "test-group-id"
	userID := "test-user-id"

	expectedPath := fmt.Sprintf("/rest/groups/%s/memberships?limit=100&user_id=%s", groupID, userID)
	expectedMemberships := UserGroupMemberships{
		Data: &[]Membership{
			{ID: stringPtr("membership-id-1"), Type: stringPtr("group_membership")},
		},
	}
	expectedResponse, _ := json.Marshal(expectedMemberships)

	mockClient.On("Get", expectedPath).Return(expectedResponse, nil)

	memberships, err := m.getUserGroupMemberships(groupID, userID)
	assert.NoError(t, err)
	assert.Equal(t, expectedMemberships, *memberships)

	mockClient.AssertExpectations(t)
}

func TestGetUserGroupMemberships_Error(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	m := New(mockClient)

	groupID := "test-group-id"
	userID := "test-user-id"

	expectedPath := fmt.Sprintf("/rest/groups/%s/memberships?limit=100&user_id=%s", groupID, userID)
	mockClient.On("Get", expectedPath).Return([]byte{}, errors.New("get error"))

	_, err := m.getUserGroupMemberships(groupID, userID)
	assert.Error(t, err)
	assert.EqualError(t, err, "get error")

	mockClient.AssertExpectations(t)
}

func TestGetUserGroupMemberships_UnmarshalError(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	m := New(mockClient)

	groupID := "test-group-id"
	userID := "test-user-id"

	expectedPath := fmt.Sprintf("/rest/groups/%s/memberships?limit=100&user_id=%s", groupID, userID)
	mockClient.On("Get", expectedPath).Return([]byte("invalid json"), nil)

	_, err := m.getUserGroupMemberships(groupID, userID)
	assert.Error(t, err)

	mockClient.AssertExpectations(t)
}

func TestGetUserOrgMembershipsOfGroup(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	m := New(mockClient)

	groupID := "test-group-id"
	userID := "test-user-id"

	expectedPath := fmt.Sprintf("/rest/groups/%s/org_memberships?limit=100&user_id=%s", groupID, userID)
	expectedMemberships := UserOrgMemberships{
		Data: &[]Membership{
			{ID: stringPtr("membership-id-1"), Type: stringPtr("org_membership")},
		},
	}
	expectedResponse, _ := json.Marshal(expectedMemberships)

	mockClient.On("Get", expectedPath).Return(expectedResponse, nil)

	memberships, err := m.getUserOrgMembershipsOfGroup(groupID, userID)
	assert.NoError(t, err)
	assert.Equal(t, expectedMemberships, *memberships)

	mockClient.AssertExpectations(t)
}

func TestGetUserOrgMemberships_Error(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	m := New(mockClient)

	groupID := "test-group-id"
	userID := "test-user-id"
	// ssoUser := &sso.User{ID: &userID}

	expectedPath := fmt.Sprintf("/rest/groups/%s/org_memberships?limit=100&user_id=%s", groupID, userID)
	mockClient.On("Get", expectedPath).Return([]byte{}, errors.New("get error"))

	_, err := m.getUserOrgMembershipsOfGroup(groupID, userID)
	assert.Error(t, err)
	assert.EqualError(t, err, "get error")

	mockClient.AssertExpectations(t)
}

func TestGetUserOrgMemberships_UnmarshalError(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	m := New(mockClient)

	groupID := "test-group-id"
	userID := "test-user-id"
	// ssoUser := &sso.User{ID: &userID}

	expectedPath := fmt.Sprintf("/rest/groups/%s/org_memberships?limit=100&user_id=%s", groupID, userID)
	mockClient.On("Get", expectedPath).Return([]byte("invalid json"), nil)

	_, err := m.getUserOrgMembershipsOfGroup(groupID, userID)
	assert.Error(t, err)

	mockClient.AssertExpectations(t)
}

func TestCreateUserGroupMembership(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	m := New(mockClient)

	groupID := "test-group-id"
	userID := "test-user-id"
	roleID := "test-role-id"
	groupName := "test-group-name"
	roleName := "test-role-name"
	userName := "test-user-name"

	mbrRelationship := MemberRelationship{
		Group: &struct {
			Data *TypeIdentifierAttributes `json:"data"`
		}{
			Data: &TypeIdentifierAttributes{ID: &groupID, Type: stringPtr("group"), Attributes: &AttributesName{Name: &groupName}},
		},
		Role: &struct {
			Data *TypeIdentifierAttributes `json:"data"`
		}{
			Data: &TypeIdentifierAttributes{ID: &roleID, Type: stringPtr("role"), Attributes: &AttributesName{Name: &roleName}},
		},
		User: &struct {
			Data *TypeIdentifierAttributes `json:"data"`
		}{
			Data: &TypeIdentifierAttributes{ID: &userID, Type: stringPtr("user"), Attributes: &AttributesName{Name: &userName}},
		},
	}

	expectedPath := fmt.Sprintf("/rest/groups/%s/memberships", groupID)
	expectedResponse := Response{
		Data: &Membership{
			ID:   stringPtr("created-membership-id"),
			Type: stringPtr(GroupMembershipType),
			Relationship: &MemberRelationship{
				Group: mbrRelationship.Group,
				Role:  mbrRelationship.Role,
				User:  mbrRelationship.User,
			},
		},
	}
	expectedResponseBody, _ := json.Marshal(expectedResponse)

	reqBody := m.createMembershipRequestBody(GroupMembershipType, mbrRelationship)
	expectedReqBody, _ := json.Marshal(reqBody)

	mockClient.On("Post", expectedPath, mock.MatchedBy(func(buf *bytes.Buffer) bool {
		return bytes.Equal(buf.Bytes(), expectedReqBody)
	})).Return(expectedResponseBody, nil)

	response, err := m.createUserGroupMembership(groupID, mbrRelationship)
	assert.NoError(t, err)
	assert.Equal(t, expectedResponse, *response)

	mockClient.AssertExpectations(t)
}

func TestCreateUserGroupMembership_Error(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	m := New(mockClient)

	groupID := "test-group-id"
	userID := "test-user-id"
	roleID := "test-role-id"
	groupName := "test-group-name"
	roleName := "test-role-name"
	userName := "test-user-name"

	mbrRelationship := MemberRelationship{
		Group: &struct {
			Data *TypeIdentifierAttributes `json:"data"`
		}{
			Data: &TypeIdentifierAttributes{ID: &groupID, Type: stringPtr("group"), Attributes: &AttributesName{Name: &groupName}},
		},
		Role: &struct {
			Data *TypeIdentifierAttributes `json:"data"`
		}{
			Data: &TypeIdentifierAttributes{ID: &roleID, Type: stringPtr("role"), Attributes: &AttributesName{Name: &roleName}},
		},
		User: &struct {
			Data *TypeIdentifierAttributes `json:"data"`
		}{
			Data: &TypeIdentifierAttributes{ID: &userID, Type: stringPtr("user"), Attributes: &AttributesName{Name: &userName}},
		},
	}

	expectedPath := fmt.Sprintf("/rest/groups/%s/memberships", groupID)
	reqBody := m.createMembershipRequestBody(GroupMembershipType, mbrRelationship)
	expectedReqBody, _ := json.Marshal(reqBody)

	mockClient.On("Post", expectedPath, mock.MatchedBy(func(buf *bytes.Buffer) bool {
		return bytes.Equal(buf.Bytes(), expectedReqBody)
	})).Return([]byte{}, errors.New("post error"))

	_, err := m.createUserGroupMembership(groupID, mbrRelationship)
	assert.Error(t, err)
	assert.EqualError(t, err, "post error")

	mockClient.AssertExpectations(t)
}

func TestCreateUserGroupMembership_UnmarshalError(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	m := New(mockClient)

	groupID := "test-group-id"
	userID := "test-user-id"
	roleID := "test-role-id"
	groupName := "test-group-name"
	roleName := "test-role-name"
	userName := "test-user-name"

	mbrRelationship := MemberRelationship{
		Group: &struct {
			Data *TypeIdentifierAttributes `json:"data"`
		}{
			Data: &TypeIdentifierAttributes{ID: &groupID, Type: stringPtr("group"), Attributes: &AttributesName{Name: &groupName}},
		},
		Role: &struct {
			Data *TypeIdentifierAttributes `json:"data"`
		}{
			Data: &TypeIdentifierAttributes{ID: &roleID, Type: stringPtr("role"), Attributes: &AttributesName{Name: &roleName}},
		},
		User: &struct {
			Data *TypeIdentifierAttributes `json:"data"`
		}{
			Data: &TypeIdentifierAttributes{ID: &userID, Type: stringPtr("user"), Attributes: &AttributesName{Name: &userName}},
		},
	}

	expectedPath := fmt.Sprintf("/rest/groups/%s/memberships", groupID)
	reqBody := m.createMembershipRequestBody(GroupMembershipType, mbrRelationship)
	expectedReqBody, _ := json.Marshal(reqBody)

	mockClient.On("Post", expectedPath, mock.MatchedBy(func(buf *bytes.Buffer) bool {
		return bytes.Equal(buf.Bytes(), expectedReqBody)
	})).Return([]byte("invalid json"), nil)

	_, err := m.createUserGroupMembership(groupID, mbrRelationship)
	assert.Error(t, err)

	mockClient.AssertExpectations(t)
}

func TestCreateUserOrgMembership(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	m := New(mockClient)

	orgID := "test-org-id"
	userID := "test-user-id"
	roleID := "test-role-id"
	orgName := "test-org-name"
	roleName := "test-role-name"
	userName := "test-user-name"

	mbrRelationship := MemberRelationship{
		Org: &struct {
			Data *TypeIdentifierAttributes `json:"data"`
		}{
			Data: &TypeIdentifierAttributes{ID: &orgID, Type: stringPtr("org"), Attributes: &AttributesName{Name: &orgName}},
		},
		Role: &struct {
			Data *TypeIdentifierAttributes `json:"data"`
		}{
			Data: &TypeIdentifierAttributes{ID: &roleID, Type: stringPtr("role"), Attributes: &AttributesName{Name: &roleName}},
		},
		User: &struct {
			Data *TypeIdentifierAttributes `json:"data"`
		}{
			Data: &TypeIdentifierAttributes{ID: &userID, Type: stringPtr("user"), Attributes: &AttributesName{Name: &userName}},
		},
	}

	expectedPath := fmt.Sprintf("/rest/orgs/%s/memberships", orgID)
	expectedResponse := Response{
		Data: &Membership{
			ID:   stringPtr("created-membership-id"),
			Type: stringPtr(OrgMembershipType),
			Relationship: &MemberRelationship{
				Org:  mbrRelationship.Org,
				Role: mbrRelationship.Role,
				User: mbrRelationship.User,
			},
		},
	}
	expectedResponseBody, _ := json.Marshal(expectedResponse)

	reqBody := m.createMembershipRequestBody(OrgMembershipType, mbrRelationship)
	expectedReqBody, _ := json.Marshal(reqBody)

	mockClient.On("Post", expectedPath, mock.MatchedBy(func(buf *bytes.Buffer) bool {
		return bytes.Equal(buf.Bytes(), expectedReqBody)
	})).Return(expectedResponseBody, nil)

	response, err := m.createUserOrgMembership(orgID, mbrRelationship)
	assert.NoError(t, err)
	assert.Equal(t, expectedResponse, *response)

	mockClient.AssertExpectations(t)
}

func TestCreateUserOrgMembership_Error(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	m := New(mockClient)

	orgID := "test-org-id"
	userID := "test-user-id"
	roleID := "test-role-id"
	orgName := "test-org-name"
	roleName := "test-role-name"
	userName := "test-user-name"

	mbrRelationship := MemberRelationship{
		Org: &struct {
			Data *TypeIdentifierAttributes `json:"data"`
		}{
			Data: &TypeIdentifierAttributes{ID: &orgID, Type: stringPtr("org"), Attributes: &AttributesName{Name: &orgName}},
		},
		Role: &struct {
			Data *TypeIdentifierAttributes `json:"data"`
		}{
			Data: &TypeIdentifierAttributes{ID: &roleID, Type: stringPtr("role"), Attributes: &AttributesName{Name: &roleName}},
		},
		User: &struct {
			Data *TypeIdentifierAttributes `json:"data"`
		}{
			Data: &TypeIdentifierAttributes{ID: &userID, Type: stringPtr("user"), Attributes: &AttributesName{Name: &userName}},
		},
	}

	expectedPath := fmt.Sprintf("/rest/orgs/%s/memberships", orgID)
	reqBody := m.createMembershipRequestBody(OrgMembershipType, mbrRelationship)
	expectedReqBody, _ := json.Marshal(reqBody)

	mockClient.On("Post", expectedPath, mock.MatchedBy(func(buf *bytes.Buffer) bool {
		return bytes.Equal(buf.Bytes(), expectedReqBody)
	})).Return([]byte{}, errors.New("post error"))

	_, err := m.createUserOrgMembership(orgID, mbrRelationship)
	assert.Error(t, err)
	assert.EqualError(t, err, "post error")

	mockClient.AssertExpectations(t)
}

func TestCreateUserOrgMembership_UnmarshalError(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	m := New(mockClient)

	orgID := "test-org-id"
	userID := "test-user-id"
	roleID := "test-role-id"
	orgName := "test-org-name"
	roleName := "test-role-name"
	userName := "test-user-name"

	mbrRelationship := MemberRelationship{
		Org: &struct {
			Data *TypeIdentifierAttributes `json:"data"`
		}{
			Data: &TypeIdentifierAttributes{ID: &orgID, Type: stringPtr("org"), Attributes: &AttributesName{Name: &orgName}},
		},
		Role: &struct {
			Data *TypeIdentifierAttributes `json:"data"`
		}{
			Data: &TypeIdentifierAttributes{ID: &roleID, Type: stringPtr("role"), Attributes: &AttributesName{Name: &roleName}},
		},
		User: &struct {
			Data *TypeIdentifierAttributes `json:"data"`
		}{
			Data: &TypeIdentifierAttributes{ID: &userID, Type: stringPtr("user"), Attributes: &AttributesName{Name: &userName}},
		},
	}

	expectedPath := fmt.Sprintf("/rest/orgs/%s/memberships", orgID)
	reqBody := m.createMembershipRequestBody(OrgMembershipType, mbrRelationship)
	expectedReqBody, _ := json.Marshal(reqBody)

	mockClient.On("Post", expectedPath, mock.MatchedBy(func(buf *bytes.Buffer) bool {
		return bytes.Equal(buf.Bytes(), expectedReqBody)
	})).Return([]byte("invalid json"), nil)

	_, err := m.createUserOrgMembership(orgID, mbrRelationship)
	assert.Error(t, err)

	mockClient.AssertExpectations(t)
}

func TestDeleteUserOrgMembership(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	m := New(mockClient)

	orgID := "test-org-id"
	membershipID := "test-membership-id"

	expectedPath := fmt.Sprintf("/rest/orgs/%s/memberships/%s", orgID, membershipID)

	mockClient.On("Delete", expectedPath).Return([]byte{}, nil)

	err := m.deleteOrgMembership(orgID, membershipID)
	assert.NoError(t, err)

	mockClient.AssertExpectations(t)
}

func TestDeleteUserOrgMembership_Error(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	m := New(mockClient)

	orgID := "test-org-id"
	membershipID := "test-membership-id"

	expectedPath := fmt.Sprintf("/rest/orgs/%s/memberships/%s", orgID, membershipID)

	mockClient.On("Delete", expectedPath).Return([]byte{}, errors.New("delete error"))

	err := m.deleteOrgMembership(orgID, membershipID)
	assert.Error(t, err)
	assert.EqualError(t, err, "delete error")

	mockClient.AssertExpectations(t)
}
