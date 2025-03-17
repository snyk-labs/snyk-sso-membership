package config

import (
	"fmt"
	"log"
	"os"
	"strconv"
)

type Config struct {
	BaseURI             string
	AuthorizationHeader string
	Version             string
	SkipVerifyTLS       bool
}

func New() *Config {
	skipVerifyTLS, _ := strconv.ParseBool(requiredEnv("SKIP_VERIFY_TLS", "false"))
	return &Config{
		BaseURI:             requiredEnv("SNYK_API", "https://api.snyk.io"),
		AuthorizationHeader: fmt.Sprintf("Token %s", requiredEnv("SNYK_TOKEN")),
		Version:             requiredEnv("SNYK_API_VERSION", "2024-10-15"),
		SkipVerifyTLS:       skipVerifyTLS,
	}
}

func requiredEnv(env string, defaultValue ...string) string {
	val := os.Getenv(env)
	if val != "" {
		return val
	}
	if defaultValue != nil {
		return defaultValue[0]
	}
	log.Fatalf("You need to set the %s environment variable", env)
	return ""
}
