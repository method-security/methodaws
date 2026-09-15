package cmd

import (
	// Generated
	cloudfrontfern "github.com/Method-Security/methodaws/generated/go/cloudfront"
	// Internal
	"github.com/Method-Security/methodaws/internal/cloudfront/enumerate"
	"github.com/Method-Security/methodaws/utils"
	"github.com/spf13/cobra"
)

// InitCloudFrontCommand initializes the `methodaws cloudfront` subcommand that deals with enumerating CloudFront distributions and their
// related resources.
func (a *MethodAws) InitCloudFrontCommand() {
	// CloudFront Command
	// Subcommands:
	// - enumerate
	cloudFrontCmd := &cobra.Command{
		Use:   "cloudfront",
		Short: "Audit and command CloudFront distributions",
		Long:  `Audit and command CloudFront distributions`,
	}

	// Enumerate Command
	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate CloudFront distributions",
		Long:  `Enumerate CloudFront distributions`,
		Run: func(cmd *cobra.Command, args []string) {
			// Account ID
			accountID, err := utils.GetAccountID(cmd.Context(), *a.AwsConfig)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config
			config := getCloudFrontEnumerateConfig(accountID)

			// Report
			report := enumerate.GatherCloudFrontInfo(cmd.Context(), *a.AwsConfig, config)
			a.setReport(report, report.Errors)
		},
	}

	// Add subcommands
	cloudFrontCmd.AddCommand(enumerateCmd)

	// Add CloudFront Command to Root Command
	a.RootCmd.AddCommand(cloudFrontCmd)
}

// getCloudFrontEnumerateConfig returns the configuration for the CloudFront enumerate command.
func getCloudFrontEnumerateConfig(accountID string) cloudfrontfern.CloudFrontEnumerateConfig {
	return cloudfrontfern.CloudFrontEnumerateConfig{
		AccountId: accountID,
	}
}
