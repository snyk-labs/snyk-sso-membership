package commands

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cliVersion string
	domain     string
	ssoDomain  string
	email      string
)

func DefaultCommand() *cobra.Command {
	output := zerolog.ConsoleWriter{Out: os.Stderr}
	logger := zerolog.New(output).With().Timestamp().Logger()

	cmd := cobra.Command{
		Use:                   "snyk-sso-membership",
		Short:                 "Modify SSO users membership at Group and Org",
		SilenceUsage:          true,
		DisableFlagsInUseLine: false,
		Version:               cliVersion,
		Run: func(cmd *cobra.Command, _ []string) {
			if err := cmd.Help(); err != nil {
				logger.Fatal().Err(err).Msg("Failed to run snyk-sso-membership command")
			}
		},
		PersistentPreRun: func(_ *cobra.Command, _ []string) {
			if viper.GetBool("debug") {
				zerolog.SetGlobalLevel(zerolog.DebugLevel)
			} else {
				zerolog.SetGlobalLevel(zerolog.InfoLevel)
			}
		},
	}
	cmd.CompletionOptions.HiddenDefaultCmd = true

	cmd.PersistentFlags().Bool("debug", false, "")
	viper.BindPFlag("debug", cmd.PersistentFlags().Lookup("debug")) //nolint:errcheck

	syncCmd := SyncMemberships(&logger)
	syncCmd.Flags().StringVar(&domain, "domain", "", "Domain")
	syncCmd.Flags().StringVar(&ssoDomain, "ssoDomain", "", "Sync Domain")
	_ = syncCmd.MarkFlagRequired("domain")
	_ = syncCmd.MarkFlagRequired("ssoDomain")
	cmd.AddCommand(syncCmd)
	deleteUsersCmd := DeleteUsers(&logger)
	deleteUsersCmd.Flags().StringVar(&domain, "domain", "", "Domain")
	deleteUsersCmd.Flags().StringVar(&email, "email", "", "Email")
	deleteUsersCmd.MarkFlagsMutuallyExclusive("domain", "email")
	deleteUsersCmd.MarkFlagsOneRequired("domain", "email")
	cmd.AddCommand(deleteUsersCmd)

	// set ldflags input version flag
	cmd.SetVersionTemplate(cliVersion)
	return &cmd
}
