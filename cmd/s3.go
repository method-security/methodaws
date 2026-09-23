package cmd

import (
	// Standard
	"fmt"
	"strings"

	// Internal
	s3enumerate "github.com/Method-Security/methodaws/internal/s3/enumerate"
	s3external "github.com/Method-Security/methodaws/internal/s3/external"
	s3list "github.com/Method-Security/methodaws/internal/s3/list"
	"github.com/Method-Security/methodaws/utils"
	"github.com/spf13/cobra"

	// Generated
	s3fern "github.com/Method-Security/methodaws/generated/go/s3"
)

// InitS3Command initializes the `methodaws s3` subcommand that deals with enumerating S3 buckets and their related resources.

func (a *MethodAws) InitS3Command() {

	// S3 Command
	// Subcommands:
	// - enumerate: Enumerate all S3 buckets in your AWS account.
	// - list: List all objects in a single S3 bucket.
	// - external: Enumerate public-facing S3 buckets from an external perspective.
	s3Cmd := &cobra.Command{
		Use:   "s3",
		Short: "Audit and manage S3 services.",
		Long:  `Audit and manage S3 services.`,
	}

	// Enumerate Command
	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate all S3 buckets",
		Long:  `Enumerate all S3 buckets in your AWS account.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Account ID
			accountID, err := utils.GetAccountID(cmd.Context(), *a.AwsConfig)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get Config
			config := a.getS3EnumerateConfig(accountID, a.RootFlags.Regions)

			// Get Report
			report := s3enumerate.EnumerateS3(cmd.Context(), *a.AwsConfig, config)
			a.setReport(report)
		},
	}
	s3Cmd.AddCommand(enumerateCmd)

	// External Command
	externalCmd := &cobra.Command{
		Use:   "external",
		Short: "Enumerate public-facing S3 buckets from an external perspective.",
		Long:  `Enumerate public-facing S3 buckets from an external perspective.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Override parent's PersistentPreRunE to use authed=false since external command uses anonymous credentials
			outputFormat, _ := cmd.Root().PersistentFlags().GetString("output")
			outputFile, _ := cmd.Root().PersistentFlags().GetString("output-file")
			return a.setupCommonConfig(cmd, outputFormat, outputFile, false)
		},
		Run: func(cmd *cobra.Command, args []string) {
			bucketURL, err := cmd.Flags().GetString("url")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			targetSeed, err := cmd.Flags().GetString("target-seed")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			// A whitespace-only seed normalizes to zero candidates, so treat it
			// as unset rather than silently completing with no probes.
			targetSeed = strings.TrimSpace(targetSeed)

			maxCandidates, err := cmd.Flags().GetInt("max-candidates")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			if bucketURL == "" && targetSeed == "" {
				a.OutputSignal.AddError(fmt.Errorf("either --url or --target-seed must be provided"))
				return
			}
			if bucketURL != "" && targetSeed != "" {
				a.OutputSignal.AddError(fmt.Errorf("provide either --url or --target-seed, not both"))
				return
			}

			// Get Config
			config := getExternalS3BucketConfig(a.RootFlags.Regions, bucketURL, targetSeed, maxCandidates)

			// Get Report
			report := s3external.EnumerateS3(cmd.Context(), config)
			a.setReport(report)
		},
	}

	// Flags
	externalCmd.Flags().String("url", "", "URL of a single S3 bucket to enumerate")
	externalCmd.Flags().String("target-seed", "", "Org/domain seed used to generate and probe candidate bucket names")
	externalCmd.Flags().Int("max-candidates", 50, "Max candidate bucket names to probe when --target-seed is set (cap 500)")

	// Add Command to S3 Command
	s3Cmd.AddCommand(externalCmd)

	// List Command
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all objects in a single S3 bucket",
		Long:  `List all objects in a single S3 bucket.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Config  Flags
			bucketName, err := cmd.Flags().GetString("name")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Account ID
			accountID, err := utils.GetAccountID(cmd.Context(), *a.AwsConfig)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get Config
			config := a.getS3ListConfig(accountID, bucketName)
			cfg, err := configForSingleRegion(*a.AwsConfig, a.RootFlags.Regions)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Return report
			report := s3list.ListS3Bucket(cmd.Context(), cfg, config)
			a.setReport(report)
		},
	}

	// Flags
	listCmd.Flags().String("name", "", "Name of the S3 bucket")

	_ = listCmd.MarkFlagRequired("name")

	// Add Command to S3 Command
	s3Cmd.AddCommand(listCmd)

	// Add S3 Command to Root Command
	a.RootCmd.AddCommand(s3Cmd)
}

// getS3EnumerateConfig returns a s3fern.S3EnumerateConfig with the given regions
func (a *MethodAws) getS3EnumerateConfig(accountID string, regions []string) s3fern.S3EnumerateConfig {
	return s3fern.S3EnumerateConfig{
		AccountId: accountID,
		Regions:   regions,
	}
}

// getExternalS3BucketConfig returns a s3fern.S3ExternalConfig for either a single
// bucket URL or seed-based candidate discovery.
func getExternalS3BucketConfig(regions []string, bucketURL string, targetSeed string, maxCandidates int) s3fern.S3ExternalConfig {
	config := s3fern.S3ExternalConfig{
		Regions: regions,
	}
	if bucketURL != "" {
		config.Url = &bucketURL
	}
	if targetSeed != "" {
		config.TargetSeed = &targetSeed
		config.MaxCandidates = &maxCandidates
	}
	return config
}

// getS3ListConfig returns a s3fern.ListS3BucketConfig with the given regions, and bucket name
func (a *MethodAws) getS3ListConfig(accountID string, bucketName string) s3fern.ListS3BucketConfig {
	return s3fern.ListS3BucketConfig{
		AccountId:  accountID,
		BucketName: bucketName,
	}
}
