package cmd

import (
	lambdafern "github.com/Method-Security/methodaws/generated/go/lambda"
	lambdaInternal "github.com/Method-Security/methodaws/internal/lambda/enumerate"
	"github.com/Method-Security/methodaws/utils"
	"github.com/spf13/cobra"
)

func (a *MethodAws) InitLambdaCommand() {
	lambdaCmd := &cobra.Command{
		Use:   "lambda",
		Short: "Audit Lambda functions",
		Long:  `Audit Lambda functions`,
	}

	enumerateCmd := regionalCommand(&cobra.Command{
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
			report := lambdaInternal.EnumerateLambda(cmd.Context(), *a.AwsConfig, config)
			a.setReport(report)
		},
	})

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
