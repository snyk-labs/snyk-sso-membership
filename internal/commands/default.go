package commands

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cliVersion      string
	domain          string
	ssoDomain       string
	email           string
	csvFilePath     string
	matchByUserName bool
)

func DefaultCommand() *cobra.Command {
	currentTime := time.Now()
	layout := currentTime.Format("20060102150405")
	// Set the log file name with the current timestamp
	fileName := "snyk-sso-membership_run_" + layout + ".log"
	logFile, ferr := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
	if ferr != nil {
		panic(ferr)
	}
	// Create a multi-level writer to write logs to both stdout and a file
	consoleWriter := zerolog.ConsoleWriter{Out: os.Stdout}
	multiWriter := zerolog.MultiLevelWriter(consoleWriter, logFile)
	logger := zerolog.New(multiWriter).With().Timestamp().Logger()

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
	syncCmd.Flags().StringVar(&csvFilePath, "csvFilePath", "", "Path to CSV file containing email addresses (optional)")
	syncCmd.Flags().BoolVar(&matchByUserName, "matchByUserName", false, "Match by UserName Identifier (default: false)")
	_ = syncCmd.MarkFlagRequired("domain")
	_ = syncCmd.MarkFlagRequired("ssoDomain")
	_ = syncCmd.MarkFlagFilename("csvFilePath", "csv")
	cmd.AddCommand(syncCmd)
	deleteUsersCmd := DeleteUsers(&logger)
	deleteUsersCmd.Flags().StringVar(&domain, "domain", "", "Domain")
	deleteUsersCmd.Flags().StringVar(&email, "email", "", "Email")
	deleteUsersCmd.Flags().StringVar(&csvFilePath, "csvFilePath", "", "Path to CSV file containing email addresses (optional)")
	deleteUsersCmd.Flags().BoolVar(&matchByUserName, "matchByUserName", false, "Match by UserName Identifier (default: false)")
	deleteUsersCmd.MarkFlagsMutuallyExclusive("domain", "email", "csvFilePath")
	deleteUsersCmd.MarkFlagsOneRequired("domain", "email", "csvFilePath")
	_ = deleteUsersCmd.MarkFlagFilename("csvFilePath", "csv")
	cmd.AddCommand(deleteUsersCmd)

	// set ldflags input version flag
	cmd.SetVersionTemplate(cliVersion)
	return &cmd
}
