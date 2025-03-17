package main

import (
	"os"

	"github.com/snyk-labs/snyk-sso-membership/internal/commands"
)

func main() {
	if err := commands.DefaultCommand().Execute(); err != nil {
		os.Exit(1)
	}
}
