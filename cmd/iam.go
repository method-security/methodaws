package cmd

import (
	iam "github.com/Method-Security/methodaws/generated/go/iam"
	iamInternal "github.com/Method-Security/methodaws/internal/iam/enumerate"
	"github.com/Method-Security/methodaws/utils"
	"github.com/spf13/cobra"
)

// InitIamCommand initializes the `methodaws iam` subcommand that deals with enumerating IAM roles, attached policies,
// inline policies and assume role policies within the AWS account.
func (a *MethodAws) InitIamCommand() {
	iamCmd := &cobra.Command{
		Use:   "iam",
		Short: "Audit and command IAM resources",
		Long:  `Audit and command IAM resources`,
	}

	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate IAM resources",
		Long:  `Enumerate IAM resources`,
		Run: func(cmd *cobra.Command, args []string) {
			accountID, err := utils.GetAccountID(cmd.Context(), *a.AwsConfig)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			excludeAWSManagedRoles, err := cmd.Flags().GetBool("exclude-aws-managed-roles")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get Config
			config := getIamEnumerateConfig(accountID, excludeAWSManagedRoles)

			// Get Report
			report := iamInternal.EnumerateIam(cmd.Context(), *a.AwsConfig, config)
			a.setReport(report, report.Errors)
		},
	}

	enumerateCmd.Flags().Bool("exclude-aws-managed-roles", false, "Exclude AWS managed roles")

	iamCmd.AddCommand(enumerateCmd)
	a.RootCmd.AddCommand(iamCmd)
}

// getIamEnumerateConfig returns an IamEnumerateConfig with the given regions and account ID
func getIamEnumerateConfig(accountID string, excludeAWSManagedRoles bool) iam.IamEnumerateConfig {
	return iam.IamEnumerateConfig{
		AccountId:              accountID,
		ExcludeAwsManagedRoles: excludeAWSManagedRoles,
	}
}
