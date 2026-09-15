package cmd

import (
	// Generated
	vpcfern "github.com/Method-Security/methodaws/generated/go/vpc"
	// Internal
	"github.com/Method-Security/methodaws/internal/vpc"
	"github.com/Method-Security/methodaws/utils"

	// External
	"github.com/spf13/cobra"
)

// InitVPCCommand initializes the `methodaws vpc` subcommand that deals with enumerating VPCs and related resources in
// the AWS account.
func (a *MethodAws) InitVPCCommand() {
	// vpc command
	// Subcommands:
	// - enumerate
	vpcCmd := &cobra.Command{
		Use:   "vpc",
		Short: "Audit and manage VPC services",
		Long:  `Audit and manage VPC services`,
	}

	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate all VPCs",
		Long:  `Enumerate all VPCs in your AWS account.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Account ID
			accountID, err := utils.GetAccountID(cmd.Context(), *a.AwsConfig)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config
			config := getVPCEnumerateConfig(a.RootFlags.Regions, accountID)

			// Genate Report
			report := vpc.EnumerateVPC(cmd.Context(), *a.AwsConfig, config)
			a.setReport(report, report.Errors)
		},
	}

	vpcCmd.AddCommand(enumerateCmd)
	a.RootCmd.AddCommand(vpcCmd)
}

// getVPCEnumerateConfig returns the configuration for the VPC enumerate command.
func getVPCEnumerateConfig(regions []string, accountID string) vpcfern.VpcEnumerateConfig {
	return vpcfern.VpcEnumerateConfig{
		AccountId: accountID,
		Regions:   regions,
	}
}
