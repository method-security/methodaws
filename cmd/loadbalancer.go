package cmd

import (
	"errors"
	"strings"

	loadbalancerfern "github.com/Method-Security/methodaws/generated/go/loadbalancer"
	loadbalancer "github.com/Method-Security/methodaws/internal/loadbalancer/enumerate"
	"github.com/Method-Security/methodaws/utils"
	"github.com/spf13/cobra"
)

func (a *MethodAws) InitLoadBalancerCommand() {

	// Load Balancer Command
	// Subcommands
	//  - enumerate
	loadBalancerCmd := &cobra.Command{
		Use:   "load-balancer",
		Short: "Audit and manage load balancers",
		Long:  `Audit and manage load balancers`,
	}

	// Enumerate Command
	enumerate := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate load balancers",
		Long:  `Enumerate load balancers in your AWS account.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Account ID
			accountID, err := utils.GetAccountID(cmd.Context(), *a.AwsConfig)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Flags
			// LB Versions
			var versions []loadbalancerfern.LoadBalancerVersion
			loadBalancerVersions, err := cmd.Flags().GetStringSlice("versions")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if len(loadBalancerVersions) > 0 {
				for _, v := range loadBalancerVersions {
					version, err := loadbalancerfern.NewLoadBalancerVersionFromString(strings.ToUpper(v))
					if err != nil {
						a.OutputSignal.AddError(err)
						return
					}
					versions = append(versions, version)
				}
			}
			if len(versions) == 0 {
				a.OutputSignal.AddError(errors.New("no load balancer versions provided"))
				return
			}

			// Config
			config := getLoadBalancerEnumerateConfig(a.RootFlags.Regions, accountID, versions)

			// Report
			report := loadbalancer.EnumerateLoadBalancers(cmd.Context(), *a.AwsConfig, config)
			a.setReport(report, report.Errors)
		},
	}

	enumerate.Flags().StringSlice("versions", []string{"V1", "V2"}, "Load balancer versions to enumerate. Valid options are ['V1', 'V2']. Default value is ['V1', 'V2']")

	loadBalancerCmd.AddCommand(enumerate)
	a.RootCmd.AddCommand(loadBalancerCmd)
}

// getLoadBalancerEnumerateConfig returns a LoadBalancerEnumerateConfig struct with the provided regions, account ID, and versions
func getLoadBalancerEnumerateConfig(regions []string, accountID string, versions []loadbalancerfern.LoadBalancerVersion) loadbalancerfern.LoadBalancerEnumerateConfig {
	return loadbalancerfern.LoadBalancerEnumerateConfig{
		Regions:   regions,
		AccountId: accountID,
		Versions:  versions,
	}
}
