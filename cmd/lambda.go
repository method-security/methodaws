package cmd

import (
	lambdafern "github.com/Method-Security/methodaws/generated/go/lambda"
	"github.com/Method-Security/methodaws/internal/lambda"
	"github.com/Method-Security/methodaws/utils"
	"github.com/spf13/cobra"
)

func (a *MethodAws) InitLambdaCommand() {
	lambdaCmd := &cobra.Command{
		Use:   "lambda",
		Short: "Audit Lambda functions",
		Long:  `Audit Lambda functions`,
	}

	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate Lambda functions",
		Long:  `Enumerate Lambda functions`,
		Run: func(cmd *cobra.Command, args []string) {
			accountID, err := utils.GetAccountID(cmd.Context(), *a.AwsConfig)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get Config
			config := getLambdaEnumerateConfig(a.RootFlags.Regions, accountID)

			// Get Report
			report := lambda.EnumerateLambda(cmd.Context(), *a.AwsConfig, config)
			a.setReport(report, report.Errors)
		},
	}

	lambdaCmd.AddCommand(enumerateCmd)
	a.RootCmd.AddCommand(lambdaCmd)
}

// getLambdaEnumerateConfig returns a LambdaEnumerateConfig with the given regions and account ID
func getLambdaEnumerateConfig(regions []string, accountID string) lambdafern.LambdaEnumerateConfig {
	return lambdafern.LambdaEnumerateConfig{
		Regions:   regions,
		AccountId: accountID,
	}
}
