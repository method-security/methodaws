package cmd

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/Method-Security/pkg/writer"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetReportPreservesContentAndSetsFailureStatus(t *testing.T) {
	t.Parallel()

	app := NewMethodAws("test")
	report := struct{ Value string }{Value: "partial"}
	app.setReport(report, []string{"first failure", "second failure"})

	assert.Equal(t, report, app.OutputSignal.Content)
	assert.Equal(t, 1, app.OutputSignal.Status)
	require.NotNil(t, app.OutputSignal.ErrorMessage)
	assert.Equal(t, "first failure; second failure", *app.OutputSignal.ErrorMessage)
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
