package cmd

import (
	apigatewayfern "github.com/Method-Security/methodaws/generated/go/apigateway"
	apigateway "github.com/Method-Security/methodaws/internal/apigateway/enumerate"
	"github.com/Method-Security/methodaws/utils"
	"github.com/spf13/cobra"
)

func (a *MethodAws) InitAPIGatewayCommand() {
	apiGatewayCmd := &cobra.Command{
		Use:     "api-gateway",
		Short:   "Audit and manage api gateways",
		Long:    `Audit and manage api gateways`,
		Aliases: []string{"agw"},
	}

	enumerateCmd := regionalCommand(&cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate api gateways",
		Long:  `Enumerate api gateways in your AWS account.`,
		Run: func(cmd *cobra.Command, args []string) {
			accountID, err := utils.GetAccountID(cmd.Context(), *a.AwsConfig)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get Config - default to both versions if not specified
			config := getAPIGatewayEnumerateConfig(a.RootFlags.Regions, accountID)

			// Get Report
			report := apigateway.EnumerateAPIGateway(cmd.Context(), *a.AwsConfig, config)
			a.setReport(report)
		},
	})

	apiGatewayCmd.AddCommand(enumerateCmd)
	a.RootCmd.AddCommand(apiGatewayCmd)
}

// getAPIGatewayEnumerateConfig returns an ApiGatewayEnumerateConfig with the given regions and account ID
func getAPIGatewayEnumerateConfig(regions []string, accountID string) apigatewayfern.ApiGatewayEnumerateConfig {
	// Default to both V1 and V2 if not specified
	versions := []apigatewayfern.ApiGatewayVersion{
		apigatewayfern.ApiGatewayVersionV1,
		apigatewayfern.ApiGatewayVersionV2,
	}

	return apigatewayfern.ApiGatewayEnumerateConfig{
		Regions:   regions,
		AccountId: accountID,
		Versions:  versions,
	}
}
