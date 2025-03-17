package users

import (
	"log"
	"os"

	"github.com/snyk-labs/snyk-sso-membership/pkg/client"
	"github.com/snyk-labs/snyk-sso-membership/pkg/config"
)

func GetSnykOrgID() *string {
	snykOrgID := os.Getenv("SNYK_ORG_ID")
	if snykOrgID == "" {
		client := client.New(config.New())
		u := New(client)
		uid, err := u.getUserDetails()

		if err != nil {
			log.Fatalf("Need to set SNYK_ORG_ID environment variable: %s", err.Error())
		}

		snykOrgID = uid.Data.Attributes.DefaultOrgContext
	}
	return &snykOrgID
}
