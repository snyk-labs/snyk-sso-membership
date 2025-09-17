package membership

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk-labs/snyk-sso-membership/pkg/sso"
	"github.com/snyk-labs/snyk-sso-membership/test/mocks"
	"github.com/stretchr/testify/assert"
)

func TestMatchSourceDomainUser(t *testing.T) {
	tests := []struct {
		name             string
		user             sso.User
		domain           string
		ssoDomain        string
		matchByUserName  bool
		matchToLocalPart bool
		expected         bool
	}{
		{
			name: "Scenario 1.1: matchByUserName=true, matchToLocalPart=true, username matches domain, email is valid",
			user: sso.User{Attributes: &struct {
				Name     *string `json:"name"`
				Email    *string `json:"email"`
				UserName *string `json:"username"`
				Active   *bool   `json:"active"`
			}{UserName: stringPtr("user@example.com"), Email: stringPtr("user@example.com")}},
			domain:           "example.com",
			ssoDomain:        "sso.com",
			matchByUserName:  true,
			matchToLocalPart: true,
			expected:         true,
		},
		{
			name: "Scenario 1.2: matchByUserName=true, matchToLocalPart=true, username does not match domain",
			user: sso.User{Attributes: &struct {
				Name     *string `json:"name"`
				Email    *string `json:"email"`
				UserName *string `json:"username"`
				Active   *bool   `json:"active"`
			}{UserName: stringPtr("user@other.com"), Email: stringPtr("user@example.com")}},
			domain:           "example.com",
			ssoDomain:        "sso.com",
			matchByUserName:  true,
			matchToLocalPart: true,
			expected:         false,
		},
		{
			name: "Scenario 1.3: matchByUserName=true, matchToLocalPart=true, email is invalid",
			user: sso.User{Attributes: &struct {
				Name     *string `json:"name"`
				Email    *string `json:"email"`
				UserName *string `json:"username"`
				Active   *bool   `json:"active"`
			}{UserName: stringPtr("user@example.com"), Email: stringPtr("invalid-email")}},
			domain:           "example.com",
			ssoDomain:        "sso.com",
			matchByUserName:  true,
			matchToLocalPart: true,
			expected:         false,
		},
		{
			name: "Scenario 2.1: matchByUserName=true, matchToLocalPart=false, username matches domain, email not ssoDomain",
			user: sso.User{Attributes: &struct {
				Name     *string `json:"name"`
				Email    *string `json:"email"`
				UserName *string `json:"username"`
				Active   *bool   `json:"active"`
			}{UserName: stringPtr("user@example.com"), Email: stringPtr("user@other.com")}},
			domain:           "example.com",
			ssoDomain:        "sso.com",
			matchByUserName:  true,
			matchToLocalPart: false,
			expected:         true,
		},
		{
			name: "Scenario 2.2: matchByUserName=true, matchToLocalPart=false, username does not match domain",
			user: sso.User{Attributes: &struct {
				Name     *string `json:"name"`
				Email    *string `json:"email"`
				UserName *string `json:"username"`
				Active   *bool   `json:"active"`
			}{UserName: stringPtr("user@other.com"), Email: stringPtr("user@sso.com")}},
			domain:           "example.com",
			ssoDomain:        "sso.com",
			matchByUserName:  true,
			matchToLocalPart: false,
			expected:         false,
		},
		{
			name: "Scenario 2.3: matchByUserName=true, matchToLocalPart=false, email matches ssoDomain",
			user: sso.User{Attributes: &struct {
				Name     *string `json:"name"`
				Email    *string `json:"email"`
				UserName *string `json:"username"`
				Active   *bool   `json:"active"`
			}{UserName: stringPtr("user@example.com"), Email: stringPtr("user@sso.com")}},
			domain:           "example.com",
			ssoDomain:        "sso.com",
			matchByUserName:  true,
			matchToLocalPart: false,
			expected:         false,
		},
		{
			name: "Scenario 3.1: matchByUserName=false, matchToLocalPart=true, email matches domain, username is valid email",
			user: sso.User{Attributes: &struct {
				Name     *string `json:"name"`
				Email    *string `json:"email"`
				UserName *string `json:"username"`
				Active   *bool   `json:"active"`
			}{UserName: stringPtr("username@valid.com"), Email: stringPtr("user@example.com")}},
			domain:           "example.com",
			ssoDomain:        "sso.com",
			matchByUserName:  false,
			matchToLocalPart: true,
			expected:         true,
		},
		{
			name: "Scenario 3.2: matchByUserName=false, matchToLocalPart=true, email does not match domain",
			user: sso.User{Attributes: &struct {
				Name     *string `json:"name"`
				Email    *string `json:"email"`
				UserName *string `json:"username"`
				Active   *bool   `json:"active"`
			}{UserName: stringPtr("username@valid.com"), Email: stringPtr("user@other.com")}},
			domain:           "example.com",
			ssoDomain:        "sso.com",
			matchByUserName:  false,
			matchToLocalPart: true,
			expected:         false,
		},
		{
			name: "Scenario 3.3: matchByUserName=false, matchToLocalPart=true, username is invalid email",
			user: sso.User{Attributes: &struct {
				Name     *string `json:"name"`
				Email    *string `json:"email"`
				UserName *string `json:"username"`
				Active   *bool   `json:"active"`
			}{UserName: stringPtr("invalid-username"), Email: stringPtr("user@example.com")}},
			domain:           "example.com",
			ssoDomain:        "sso.com",
			matchByUserName:  false,
			matchToLocalPart: true,
			expected:         false,
		},
		{
			name: "Scenario 4.1: matchByUserName=false, matchToLocalPart=false, email matches domain",
			user: sso.User{Attributes: &struct {
				Name     *string `json:"name"`
				Email    *string `json:"email"`
				UserName *string `json:"username"`
				Active   *bool   `json:"active"`
			}{UserName: stringPtr("username"), Email: stringPtr("user@example.com")}},
			domain:           "example.com",
			ssoDomain:        "sso.com",
			matchByUserName:  false,
			matchToLocalPart: false,
			expected:         true,
		},
		{
			name: "Scenario 4.2: matchByUserName=false, matchToLocalPart=false, email does not match domain",
			user: sso.User{Attributes: &struct {
				Name     *string `json:"name"`
				Email    *string `json:"email"`
				UserName *string `json:"username"`
				Active   *bool   `json:"active"`
			}{UserName: stringPtr("username"), Email: stringPtr("user@other.com")}},
			domain:           "example.com",
			ssoDomain:        "sso.com",
			matchByUserName:  false,
			matchToLocalPart: false,
			expected:         false,
		},
		{
			name:             "Edge Case: User attributes are nil",
			user:             sso.User{Attributes: nil},
			domain:           "example.com",
			ssoDomain:        "sso.com",
			matchByUserName:  false,
			matchToLocalPart: false,
			expected:         false,
		},
		{
			name: "Edge Case: User email is nil",
			user: sso.User{Attributes: &struct {
				Name     *string `json:"name"`
				Email    *string `json:"email"`
				UserName *string `json:"username"`
				Active   *bool   `json:"active"`
			}{UserName: stringPtr("username"), Email: nil}},
			domain:           "example.com",
			ssoDomain:        "sso.com",
			matchByUserName:  false,
			matchToLocalPart: false,
			expected:         false,
		},
		{
			name: "Edge Case: User username is nil",
			user: sso.User{Attributes: &struct {
				Name     *string `json:"name"`
				Email    *string `json:"email"`
				UserName *string `json:"username"`
				Active   *bool   `json:"active"`
			}{UserName: nil, Email: stringPtr("user@example.com")}},
			domain:           "example.com",
			ssoDomain:        "sso.com",
			matchByUserName:  false,
			matchToLocalPart: false,
			expected:         false,
		},
		{
			name: "Edge Case: Domain is empty",
			user: sso.User{Attributes: &struct {
				Name     *string `json:"name"`
				Email    *string `json:"email"`
				UserName *string `json:"username"`
				Active   *bool   `json:"active"`
			}{UserName: stringPtr("user@example.com"), Email: stringPtr("user@example.com")}},
			domain:           "",
			ssoDomain:        "sso.com",
			matchByUserName:  false,
			matchToLocalPart: false,
			expected:         false,
		},
		{
			name: "Edge Case: ssoDomain is empty (matchByUserName=true, matchToLocalPart=false)",
			user: sso.User{Attributes: &struct {
				Name     *string `json:"name"`
				Email    *string `json:"email"`
				UserName *string `json:"username"`
				Active   *bool   `json:"active"`
			}{UserName: stringPtr("user@example.com"), Email: stringPtr("user@other.com")}},
			domain:           "example.com",
			ssoDomain:        "",
			matchByUserName:  true,
			matchToLocalPart: false,
			expected:         true,
		},
		{
			name: "Edge Case: ssoDomain is empty (matchByUserName=false, matchToLocalPart=false)",
			user: sso.User{Attributes: &struct {
				Name     *string `json:"name"`
				Email    *string `json:"email"`
				UserName *string `json:"username"`
				Active   *bool   `json:"active"`
			}{UserName: stringPtr("username"), Email: stringPtr("user@example.com")}},
			domain:           "example.com",
			ssoDomain:        "",
			matchByUserName:  false,
			matchToLocalPart: false,
			expected:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchSourceDomainUser(tt.user, tt.domain, tt.ssoDomain, tt.matchByUserName, tt.matchToLocalPart)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMapProvisionedUsersAttributes_NoGroupMembership(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	m := New(mockClient)
	logger := zerolog.Nop()

	groupID := "test-group-id"
	domain := "example.com"
	ssoDomain := "sso.com"
	userID := "user-id-1"

	users := sso.Users{
		Data: []sso.User{
			{
				ID: stringPtr(userID),
				Attributes: &struct {
					Name     *string `json:"name"`
					Email    *string `json:"email"`
					UserName *string `json:"username"`
					Active   *bool   `json:"active"`
				}{
					Email:    stringPtr("user@example.com"),
					UserName: stringPtr("user@example.com"),
				},
			},
		},
	}

	// This user will be identified as a source user.
	// Now, mock the API calls.

	// Mock for getUserGroupMemberships to return an error.
	groupMembershipPath := fmt.Sprintf("/rest/groups/%s/memberships?limit=100&user_id=%s", groupID, userID)
	mockClient.On("Get", groupMembershipPath).Return([]byte{}, errors.New("group membership error")).Once()

	// Mock for getUserOrgMembershipsOfGroup to return empty, to avoid another panic.
	orgMembershipPath := fmt.Sprintf("/rest/groups/%s/org_memberships?limit=100&user_id=%s", groupID, userID)
	apiResponse := UserMembershipResponse{
		Data: []Membership{},
	}
	responseBody, _ := json.Marshal(apiResponse)
	mockClient.On("Get", orgMembershipPath).Return(responseBody, nil).Once()

	// The function is NOT expected to panic when getUserGroupMemberships returns an error.
	var count int32
	var userMap *map[string]provisionedUserAttributes
	assert.NotPanics(t, func() {
		count, userMap = m.mapProvisionedUsersAttributes(groupID, domain, ssoDomain, users, false, false, &logger)
	}, "The code panicked unexpectedly")

	// The function should handle the error gracefully.
	// The user should be in the map, but with nil group memberships.
	// The count of provisioned users found will be 0 because there's no matching destination user in the input `users`.
	assert.Equal(t, int32(0), count)
	assert.NotNil(t, userMap)
	assert.Len(t, *userMap, 1)
	attrs, ok := (*userMap)["user@example.com"]
	assert.True(t, ok)
	assert.Nil(t, attrs.groupMemberships)
	assert.Nil(t, attrs.provisionedID)

	mockClient.AssertExpectations(t)
}

func TestSyncUserOrgMemberships_NilOrgMemberships(t *testing.T) {
	// setup
	mockClient := new(mocks.MockSnykClient)
	m := New(mockClient)
	logger := zerolog.Nop()

	groupID := "test-group-id"
	provisionedUserID := "provisioned-user-id"
	provisionedUserName := "provisioned-user"

	uAttributes := &provisionedUserAttributes{
		provisionedID:       stringPtr(provisionedUserID),
		provisionedUserName: stringPtr(provisionedUserName),
		orgMemberships:      nil, // This is the condition we are testing
	}

	// Mock the calls within deleteUserOrgMembership
	// 1. Mock getUserOrgMembershipsOfGroup to simulate the user having existing memberships to delete.
	orgMembershipPath := fmt.Sprintf("/rest/groups/%s/org_memberships?limit=100&user_id=%s", groupID, provisionedUserID)
	existingMembershipID := "existing-membership-id"
	existingOrgID := "existing-org-id"
	existingOrgName := "existing-org-name"
	apiResponse := UserMembershipResponse{
		Data: []Membership{
			{
				ID: stringPtr(existingMembershipID),
				Relationship: &MemberRelationship{
					Org: &struct {
						Data *TypeIdentifierAttributes `json:"data"`
					}{
						Data: &TypeIdentifierAttributes{
							ID:   stringPtr(existingOrgID),
							Type: stringPtr("org"),
							Attributes: &AttributesName{
								Name: stringPtr(existingOrgName),
							},
						},
					},
				},
			},
		},
	}
	responseBody, _ := json.Marshal(apiResponse)
	mockClient.On("Get", orgMembershipPath).Return(responseBody, nil).Once()

	// 2. Mock deleteOrgMembership for the existing membership.
	deletePath := fmt.Sprintf("/rest/orgs/%s/memberships/%s", existingOrgID, existingMembershipID)
	mockClient.On("Delete", deletePath).Return([]byte{}, nil).Once()

	// The function under test
	m.syncUserOrgMemberships(groupID, uAttributes, &logger)

	// Assertions
	// Check that the mocks for deletion were called.
	mockClient.AssertExpectations(t)

	// We also implicitly assert that `createUserOrgMembership` (which calls `client.Post`) is not called,
	// because there is no mock set up for `Post`. If it were called, the test would fail.
}

func TestSyncUserOrgMemberships_EmptyOrgMemberships(t *testing.T) {
	// setup
	mockClient := new(mocks.MockSnykClient)
	m := New(mockClient)
	logger := zerolog.Nop()

	groupID := "test-group-id"
	provisionedUserID := "provisioned-user-id"
	provisionedUserName := "provisioned-user"

	uAttributes := &provisionedUserAttributes{
		provisionedID:       stringPtr(provisionedUserID),
		provisionedUserName: stringPtr(provisionedUserName),
		orgMemberships:      &UserOrgMemberships{Data: []Membership{}}, // This is the condition we are testing
	}

	// Mock the calls within deleteUserOrgMembership
	// 1. Mock getUserOrgMembershipsOfGroup to simulate the user having existing memberships to delete.
	orgMembershipPath := fmt.Sprintf("/rest/groups/%s/org_memberships?limit=100&user_id=%s", groupID, provisionedUserID)
	existingMembershipID := "existing-membership-id"
	existingOrgID := "existing-org-id"
	existingOrgName := "existing-org-name"
	apiResponse := UserMembershipResponse{
		Data: []Membership{
			{
				ID: stringPtr(existingMembershipID),
				Relationship: &MemberRelationship{
					Org: &struct {
						Data *TypeIdentifierAttributes `json:"data"`
					}{
						Data: &TypeIdentifierAttributes{
							ID:   stringPtr(existingOrgID),
							Type: stringPtr("org"),
							Attributes: &AttributesName{
								Name: stringPtr(existingOrgName),
							},
						},
					},
				},
			},
		},
	}
	responseBody, _ := json.Marshal(apiResponse)
	mockClient.On("Get", orgMembershipPath).Return(responseBody, nil).Once()

	// 2. Mock deleteOrgMembership for the existing membership.
	deletePath := fmt.Sprintf("/rest/orgs/%s/memberships/%s", existingOrgID, existingMembershipID)
	mockClient.On("Delete", deletePath).Return([]byte{}, nil).Once()

	// The function under test
	m.syncUserOrgMemberships(groupID, uAttributes, &logger)

	// Assertions
	// Check that the mocks for deletion were called.
	mockClient.AssertExpectations(t)
}

func TestMapProvisionedUsersAttributes_EmptyGroupMembership(t *testing.T) {
	mockClient := new(mocks.MockSnykClient)
	m := New(mockClient)
	logger := zerolog.Nop()

	groupID := "test-group-id"
	domain := "example.com"
	ssoDomain := "sso.com"
	userID := "user-id-1"

	users := sso.Users{
		Data: []sso.User{
			{
				ID: stringPtr(userID),
				Attributes: &struct {
					Name     *string `json:"name"`
					Email    *string `json:"email"`
					UserName *string `json:"username"`
					Active   *bool   `json:"active"`
				}{
					Email:    stringPtr("user@example.com"),
					UserName: stringPtr("user@example.com"),
				},
			},
		},
	}

	// This user will be identified as a source user.
	// Now, mock the API calls.

	// Mock for getUserGroupMemberships to return empty data.
	groupMembershipPath := fmt.Sprintf("/rest/groups/%s/memberships?limit=100&user_id=%s", groupID, userID)
	groupApiResponse := UserMembershipResponse{
		Data: []Membership{},
	}
	groupResponseBody, _ := json.Marshal(groupApiResponse)
	mockClient.On("Get", groupMembershipPath).Return(groupResponseBody, nil).Once()

	// Mock for getUserOrgMembershipsOfGroup to return empty.
	orgMembershipPath := fmt.Sprintf("/rest/groups/%s/org_memberships?limit=100&user_id=%s", groupID, userID)
	orgApiResponse := UserMembershipResponse{
		Data: []Membership{},
	}
	orgResponseBody, _ := json.Marshal(orgApiResponse)
	mockClient.On("Get", orgMembershipPath).Return(orgResponseBody, nil).Once()

	// The function is NOT expected to panic when memberships are empty,
	// as it should handle this case gracefully.
	var count int32
	var userMap *map[string]provisionedUserAttributes
	assert.NotPanics(t, func() {
		count, userMap = m.mapProvisionedUsersAttributes(groupID, domain, ssoDomain, users, false, false, &logger)
	}, "The code panicked unexpectedly")

	assert.Equal(t, int32(0), count)
	assert.NotNil(t, userMap)
	assert.Len(t, *userMap, 1)
	attrs, ok := (*userMap)["user@example.com"]
	assert.True(t, ok)
	assert.Nil(t, attrs.provisionedID)

	mockClient.AssertExpectations(t)
}
