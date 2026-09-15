package lambda

import (
	"testing"

	lambdafern "github.com/Method-Security/methodaws/generated/go/lambda"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateCloudWatchLogReferencesUsesEffectiveLogGroupAndSourceIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		loggingConfig *lambdafern.LambdaLoggingConfig
		expectedName  string
	}{
		{
			name: "missing logging configuration",
		},
		{
			name: "configured default log group",
			loggingConfig: &lambdafern.LambdaLoggingConfig{
				LogGroup: "/aws/lambda/example",
			},
			expectedName: "/aws/lambda/example",
		},
		{
			name: "custom log group",
			loggingConfig: &lambdafern.LambdaLoggingConfig{
				LogGroup: "/method/lambda/example",
			},
			expectedName: "/method/lambda/example",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			references, err := createCloudWatchLogReferences(
				test.loggingConfig,
				"arn:aws:lambda:us-east-1:123456789012:function:example",
				"us-east-1",
			)

			require.NoError(t, err)
			if test.expectedName == "" {
				assert.Empty(t, references)
				return
			}
			require.Len(t, references, 1)
			assert.Equal(t, test.expectedName, references[0].LogGroupName)
			assert.Equal(
				t,
				"arn:aws:logs:us-east-1:123456789012:log-group:"+test.expectedName,
				references[0].Arn,
			)
		})
	}
}
