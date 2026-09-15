package cmd

import (
	// Generated
	rdsfern "github.com/Method-Security/methodaws/generated/go/rds"
	// Internal
	"github.com/Method-Security/methodaws/internal/rds"
	"github.com/Method-Security/methodaws/utils"

	// External
	"github.com/spf13/cobra"
)

// InitRdsCommand initializes the `methodaws rds` subcommand that deals with enumerating RDS instances in the AWS account.
func (a *MethodAws) InitRdsCommand() {
	rdsCmd := &cobra.Command{
		Use:   "rds",
		Short: "Audit and manage RDS instances",
		Long:  `Audit and manage RDS instances`,
	}

	enumerateCmd := regionalCommand(&cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate RDS instances",
		Long:  `Enumerate RDS instances in your AWS account.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Account ID
			accountID, err := utils.GetAccountID(cmd.Context(), *a.AwsConfig)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config
			config := getRdsEnumerateConfig(a.RootFlags.Regions, accountID)

			// Report
			report := rds.EnumerateRDS(cmd.Context(), *a.AwsConfig, config)
			a.setReport(report)
		},
	})

	rdsCmd.AddCommand(enumerateCmd)
	a.RootCmd.AddCommand(rdsCmd)
}

func getRdsEnumerateConfig(regions []string, accountID string) rdsfern.RdsEnumerateConfig {
	return rdsfern.RdsEnumerateConfig{
		Regions:   regions,
		AccountId: accountID,
	}
}
