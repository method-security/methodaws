package cmd

import (
	// Generated
	ec2 "github.com/Method-Security/methodaws/generated/go/ec2"
	"github.com/Method-Security/methodaws/utils"

	// Internal
	"github.com/Method-Security/methodaws/internal/ec2/enumerate"
	"github.com/spf13/cobra"
)

// InitEc2Command initializes the `methodaws ec2` subcommand that deals with enumerating EC2 instances and their
// related resources.
func (a *MethodAws) InitEc2Command() {
	// ec2 command
	// Subcommands:
	// - enumerate
	ec2Cmd := &cobra.Command{
		Use:   "ec2",
		Short: "Audit and command EC2 instances",
		Long:  `Audit and command EC2 instances`,
	}

	// Enumerate command
	enumerateCmd := regionalCommand(&cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate EC2 instances",
		Long:  `Enumerate EC2 instances`,
		Run: func(cmd *cobra.Command, args []string) {
			// Account ID
			accountID, err := utils.GetAccountID(cmd.Context(), *a.AwsConfig)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config
			config := getEc2EnumerateConfig(a.RootFlags.Regions, accountID)

			// Genate Report
			report := enumerate.InternalEnumerateEc2(cmd.Context(), *a.AwsConfig, config)
			a.setReport(report)
		},
	})

	// Add subcommands
	ec2Cmd.AddCommand(enumerateCmd)
	a.RootCmd.AddCommand(ec2Cmd)
}

// getEc2EnumerateConfig returns the configuration for the EC2 enumerate command.
func getEc2EnumerateConfig(regions []string, accountID string) ec2.Ec2EnumerateConfig {
	return ec2.Ec2EnumerateConfig{
		AccountId: accountID,
		Regions:   regions,
	}
}
