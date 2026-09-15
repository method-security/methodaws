package cmd

import (
	eksfern "github.com/Method-Security/methodaws/generated/go/eks"
	eks "github.com/Method-Security/methodaws/internal/eks/enumerate"
	"github.com/Method-Security/methodaws/utils"
	"github.com/spf13/cobra"
)

// InitEksCommand initializes the `methodaws eks` subcommand that deals with enumerating EKS instances and their
// related resources.
func (a *MethodAws) InitEksCommand() {
	eksCmd := &cobra.Command{
		Use:   "eks",
		Short: "Enumerate EKS instances",
		Long:  `Enumerate EKS instances`,
	}

	enumerateCmd := regionalCommand(&cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate EKS instances",
		Long:  `Enumerate EKS instances`,
		Run: func(cmd *cobra.Command, args []string) {
			accountID, err := utils.GetAccountID(cmd.Context(), *a.AwsConfig)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get Config
			config := getEksEnumerateConfig(a.RootFlags.Regions, accountID)

			// Get Report
			report := eks.EnumerateEks(cmd.Context(), *a.AwsConfig, config)
			a.setReport(report)
		},
	})

	credsCmd := &cobra.Command{
		Use:   "creds",
		Short: "Generate a K8s Credential for an EKS instance",
		Long:  `Generate a K8s Credential for an EKS instance`,
		Run: func(cmd *cobra.Command, args []string) {
			clusterName, err := cmd.Flags().GetString("name")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report, err := eks.CredsEks(cmd.Context(), *a.AwsConfig, clusterName)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.setReport(report)
		},
	}

	credsCmd.Flags().String("name", "", "Name of the EKS cluster")

	_ = credsCmd.MarkFlagRequired("name")

	eksCmd.AddCommand(enumerateCmd)
	eksCmd.AddCommand(credsCmd)
	a.RootCmd.AddCommand(eksCmd)
}

// getEksEnumerateConfig returns an EksEnumerateConfig with the given regions and account ID
func getEksEnumerateConfig(regions []string, accountID string) eksfern.EksEnumerateConfig {
	return eksfern.EksEnumerateConfig{
		Regions:   regions,
		AccountId: accountID,
	}
}
