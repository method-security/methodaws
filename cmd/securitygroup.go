package cmd

import (
	// Generated
	fernsecuritygroup "github.com/Method-Security/methodaws/generated/go/securitygroup"
	"github.com/Method-Security/methodaws/utils"

	// Internal
	"github.com/Method-Security/methodaws/internal/securitygroup"
	// External
	"github.com/spf13/cobra"
)

// InitSecurityGroupCommand initializes the `methodaws securitygroup` subcommand that deals with enumerating security
// groups and their related resources.
func (a *MethodAws) InitSecurityGroupCommand() {
	// Root Security Group Command
	// Subcommands
	// - enumerate
	securityGroupCmd := &cobra.Command{
		Use:     "security-group",
		Short:   "Audit and command security groups",
		Long:    `Audit and command security groups`,
		Aliases: []string{"sg"},
	}

	// Enumerate Command
	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate security groups",
		Long:  `Enumerate security groups`,
		Run: func(cmd *cobra.Command, args []string) {
			// Account ID
			accountID, err := utils.GetAccountID(cmd.Context(), *a.AwsConfig)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get Config
			config := getSecurityGroupEnumerateConfig(accountID, a.RootFlags.Regions)

			// Get Report
			report := securitygroup.EnumerateSecurityGroups(cmd.Context(), *a.AwsConfig, config)
			a.setReport(report, report.Errors)
		},
	}

	securityGroupCmd.AddCommand(enumerateCmd)
	a.RootCmd.AddCommand(securityGroupCmd)
}

func getSecurityGroupEnumerateConfig(accountID string, regions []string) fernsecuritygroup.SecurityGroupsEnumerateConfig {
	return fernsecuritygroup.SecurityGroupsEnumerateConfig{
		AccountId: accountID,
		Regions:   regions,
	}
}
