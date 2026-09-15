package cmd

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/Method-Security/pkg/writer"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigForSingleRegion(t *testing.T) {
	t.Parallel()
	base := aws.Config{Region: "us-west-2"}
	cfg, err := configForSingleRegion(base, []string{"us-east-1", "us-east-1"})
	require.NoError(t, err)
	assert.Equal(t, "us-east-1", cfg.Region)
	assert.Equal(t, "us-west-2", base.Region)
	_, err = configForSingleRegion(base, []string{"us-east-1", "us-west-2"})
	require.Error(t, err)
	cfg, err = configForSingleRegion(base, nil)
	require.NoError(t, err)
	assert.Equal(t, base.Region, cfg.Region)
}

func TestSetReportRetainsRegionCoverageError(t *testing.T) {
	t.Parallel()
	app := NewMethodAws("test")
	app.OutputSignal.AddError(errors.New("region coverage incomplete"))
	app.setReport("partial inventory")
	assert.Equal(t, "partial inventory", app.OutputSignal.Content)
	assert.Equal(t, 1, app.OutputSignal.Status)
	require.NotNil(t, app.OutputSignal.ErrorMessage)
	assert.Contains(t, *app.OutputSignal.ErrorMessage, "region coverage incomplete")
}

func TestSetReportPreservesPartialContentWithoutFailingSignal(t *testing.T) {
	t.Parallel()

	app := NewMethodAws("test")
	report := struct {
		Value  string
		Errors []string
	}{Value: "partial", Errors: []string{"enrichment denied"}}
	app.setReport(report)

	assert.Equal(t, report, app.OutputSignal.Content)
	assert.Equal(t, 0, app.OutputSignal.Status)
	assert.Nil(t, app.OutputSignal.ErrorMessage)
}

func TestRegionalCommandRequiresRegionDiscovery(t *testing.T) {
	t.Parallel()

	regional := regionalCommand(&cobra.Command{Use: "regional"})
	global := &cobra.Command{Use: "global"}

	assert.True(t, commandRequiresRegionDiscovery(regional))
	assert.False(t, commandRequiresRegionDiscovery(global))
}

func TestExecuteWritesStartupFailure(t *testing.T) {
	t.Parallel()

	outputPath := t.TempDir() + "/signal.json"
	app := NewMethodAws("test")
	app.OutputConfig = writer.NewOutputConfig(&outputPath, writer.NewFormat(writer.JSON))
	app.RootCmd = &cobra.Command{
		Use:           "test",
		SilenceErrors: true,
		SilenceUsage:  true,
		PreRunE: func(*cobra.Command, []string) error {
			return errors.New("startup failed")
		},
		Run: func(*cobra.Command, []string) {},
	}

	assert.Equal(t, 1, app.Execute())

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	var output struct {
		Status       int     `json:"status"`
		ErrorMessage *string `json:"error_message"`
	}
	require.NoError(t, json.Unmarshal(data, &output))
	assert.Equal(t, 1, output.Status)
	require.NotNil(t, output.ErrorMessage)
	assert.Equal(t, "startup failed", *output.ErrorMessage)
}
