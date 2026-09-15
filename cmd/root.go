// Package cmd implements the CobraCLI commands for the methodaws CLI. Subcommands for the CLI should all live within
// this package. Logic should be delegated to internal packages and functions to keep the CLI commands clean and
// focused on CLI I/O.
package cmd

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Method-Security/methodaws/internal/config"
	"github.com/Method-Security/methodaws/utils"
	"github.com/Method-Security/pkg/signal"
	"github.com/Method-Security/pkg/writer"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/palantir/pkg/datetime"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"

	// Import wlog-zap for its side effects, initializing the zap logger
	_ "github.com/palantir/witchcraft-go-logging/wlog-zap"
	"github.com/spf13/cobra"
)

// MethodAws is the main struct that holds the root command and all subcommands that are used throughout execution
// of the CLI. It is also responsible for holding the AWS configuration, Output configuration, and Output signal
// for use by subcommands. The output signal is used to write the output of the command to the desired output format
// after the execution of the invoked commands Run function.
type MethodAws struct {
	Version       string
	RootFlags     config.RootFlags
	OutputConfig  writer.OutputConfig
	OutputSignal  signal.Signal
	AwsConfig     *aws.Config
	RootCmd       *cobra.Command
	outputWritten bool
}

const discoverRegionsAnnotation = "methodaws/discover-regions"

func regionalCommand(command *cobra.Command) *cobra.Command {
	if command.Annotations == nil {
		command.Annotations = make(map[string]string)
	}
	command.Annotations[discoverRegionsAnnotation] = "true"
	return command
}

func commandRequiresRegionDiscovery(command *cobra.Command) bool {
	return command.Annotations[discoverRegionsAnnotation] == "true"
}

// NewMethodAws returns a new MethodAws struct with the provided version string. The MethodAws struct is used to
// initialize the root command and all subcommands that are used throughout execution of the CLI.
// We pass the version command in here from the main.go file, where we set the version string during the build process.
func NewMethodAws(version string) *MethodAws {
	startedAt := datetime.DateTime(time.Now())
	methodAws := MethodAws{
		Version: version,
		RootFlags: config.RootFlags{
			Quiet:      false,
			Verbose:    false,
			Regions:    []string{},
			HTTPProxy:  "",
			SOCKSProxy: "",
		},
		OutputConfig: writer.NewOutputConfig(nil, writer.NewFormat(writer.SIGNAL)),
		OutputSignal: signal.NewSignal(nil, &startedAt, nil, 0, nil),
		AwsConfig:    nil,
	}
	return &methodAws
}

// Helper function to set up common configurations
func (a *MethodAws) setupCommonConfig(cmd *cobra.Command, outputFormat string, outputFile string, authed bool) error {
	var err error

	// Set up output configuration FIRST - before anything that might fail
	// This ensures we get properly formatted error output even if AWS auth fails
	format, err := validateOutputFormat(outputFormat)
	if err != nil {
		return err
	}
	var outputFilePointer *string
	if outputFile != "" {
		outputFilePointer = &outputFile
	} else {
		outputFilePointer = nil
	}
	a.OutputConfig = writer.NewOutputConfig(outputFilePointer, format)

	ctx := svc1log.WithLogger(cmd.Context(), config.InitializeLogging(cmd, &a.RootFlags))
	ctx = config.SetProxyConfig(ctx, config.ProxyConfig{
		HTTPProxy:  a.RootFlags.HTTPProxy,
		SOCKSProxy: a.RootFlags.SOCKSProxy,
	})
	cmd.SetContext(ctx)
	if authed {
		loadOptions, err := config.AWSLoadOptionsFromContext(cmd.Context())
		if err != nil {
			return err
		}
		awsConfig, err := awsconfig.LoadDefaultConfig(cmd.Context(), loadOptions...)
		if err != nil {
			return err
		}
		a.AwsConfig = &awsConfig
		if commandRequiresRegionDiscovery(cmd) {
			a.RootFlags.Regions, err = utils.GetAWSRegions(cmd.Context(), *a.AwsConfig, a.RootFlags.Regions)
			if err != nil {
				return fmt.Errorf("unable to discover enabled AWS regions: %w", err)
			}
		}
	}

	return nil
}

// InitRootCommand initializes the root command for the methodaws CLI. This command is used to set the global flags
// that are used by all subcommands, such as the region, output format, and output file. It also initializes the
// version command that prints the version of the CLI.
// Critically, this sets the PersistentPreRunE and PersistentPostRunE functions that are inherited by most subcommands.
// The PersistentPreRunE function is used to validate the region flag and set the AWS configuration. The PersistentPostRunE
// function is used to write the output of the command to the desired output format after the execution of the invoked
// command's Run function.
func (a *MethodAws) InitRootCommand() {
	var outputFormat string
	var outputFile string
	a.RootCmd = &cobra.Command{
		Use:           "methodaws",
		Short:         "Audit AWS resources",
		Long:          "Audit AWS resources",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			// Use the variables directly - Cobra automatically updates them when flags are parsed
			return a.setupCommonConfig(cmd, outputFormat, outputFile, true)
		},
		PersistentPostRunE: func(cmd *cobra.Command, _ []string) error {
			return a.writeOutput()
		},
	}

	a.RootCmd.PersistentFlags().BoolVarP(&a.RootFlags.Quiet, "quiet", "q", false, "Suppress output")
	a.RootCmd.PersistentFlags().BoolVarP(&a.RootFlags.Verbose, "verbose", "v", false, "Verbose output")
	a.RootCmd.PersistentFlags().StringArrayVarP(&a.RootFlags.Regions, "regions", "r", []string{}, "AWS Regions to search for resources. You can specify multiple regions by providing the flag multiple times. If blank, will search all regions.")
	a.RootCmd.PersistentFlags().StringVarP(&outputFile, "output-file", "f", "", "Path to output file. If blank, will output to STDOUT")
	a.RootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "signal", "Output format (signal, json, yaml). Default value is signal")
	a.RootCmd.PersistentFlags().StringVar(&a.RootFlags.HTTPProxy, "http-proxy", "", "HTTP/HTTPS proxy URL (e.g., http://proxy.example.com:8080)")
	a.RootCmd.PersistentFlags().StringVar(&a.RootFlags.SOCKSProxy, "socks-proxy", "", "SOCKS proxy URL (e.g., socks5://proxy.example.com:1080)")

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version number of methodaws",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println(a.Version)
		},
		PersistentPostRunE: func(cmd *cobra.Command, _ []string) error {
			return nil
		},
	}

	a.RootCmd.AddCommand(versionCmd)
}

// Execute runs the configured command, ensures failures are serialized, and returns the process exit code.
func (a *MethodAws) Execute() int {
	err := a.RootCmd.Execute()
	if err != nil {
		a.OutputSignal.AddError(err)
		if !a.outputWritten {
			_ = a.writeOutput()
		}
		return 1
	}
	if a.OutputSignal.Status != 0 {
		return a.OutputSignal.Status
	}
	return 0
}

func (a *MethodAws) writeOutput() error {
	completedAt := datetime.DateTime(time.Now())
	a.OutputSignal.CompletedAt = &completedAt
	a.outputWritten = true
	return writer.Write(
		a.OutputSignal.Content,
		a.OutputConfig,
		&a.OutputSignal.StartedAt,
		a.OutputSignal.CompletedAt,
		a.OutputSignal.Status,
		a.OutputSignal.ErrorMessage,
	)
}

func (a *MethodAws) setReport(report any) {
	a.OutputSignal.Content = report
}

// A utility function to validate that the provided output format is one of the supported formats: json, yaml, signal.
func validateOutputFormat(output string) (writer.Format, error) {
	var format writer.FormatValue
	switch strings.ToLower(output) {
	case "json":
		format = writer.JSON
	case "yaml":
		return writer.Format{}, errors.New("yaml output format is not supported for methodaws")
	case "signal":
		format = writer.SIGNAL
	default:
		return writer.Format{}, errors.New("invalid output format. Valid formats are: json, yaml, signal")
	}
	return writer.NewFormat(format), nil
}
