package membership

import (
	"testing"

	"github.com/snyk-labs/snyk-sso-membership/pkg/sso"
	"github.com/stretchr/testify/assert"
)

// Helper functions for pointers
func boolPtr(b bool) *bool {
	return &b
}

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
