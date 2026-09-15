package cmd

import (
	// Generated
	route53fern "github.com/Method-Security/methodaws/generated/go/route53"
	"github.com/Method-Security/methodaws/utils"

	// Internal
	"github.com/Method-Security/methodaws/internal/route53"
	"github.com/spf13/cobra"
)

// InitRoute53Command initializes the `methodaws route53` subcommand that deals with enumerating Route53 resources.
func (a *MethodAws) InitRoute53Command() {
	//route53Cmd
	//Subcommands:
	// - enumerate
	route53Cmd := &cobra.Command{
		Use:   "route53",
		Short: "Enumerate Route53 resources",
		Long:  `Enumerate Route53 resources`,
	}

	// enumerateCmd
	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate Route53 records",
		Long:  `Enumerate Route53 records`,
		Run: func(cmd *cobra.Command, args []string) {
			// Account ID
			accountID, err := utils.GetAccountID(cmd.Context(), *a.AwsConfig)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config
			config := getRoute53EnumerateConfig(accountID)

			// Get Report
			report := route53.EnumerateRoute53(cmd.Context(), *a.AwsConfig, config)
			a.setReport(report)
		},
	}

	// Add Commands
	route53Cmd.AddCommand(enumerateCmd)

	a.RootCmd.AddCommand(route53Cmd)
}

func getRoute53EnumerateConfig(accountID string) route53fern.Route53EnumerateConfig {
	return route53fern.Route53EnumerateConfig{
		AccountId: accountID,
	}
}
