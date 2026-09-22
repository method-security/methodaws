package apigateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	v1types "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	v2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStageIdentityUsesParentARN(t *testing.T) {
	for _, apiARN := range []string{
		"arn:aws:apigateway:us-east-1::/restapis/abc123",
		"arn:aws-us-gov:apigateway:us-gov-west-1::/restapis/abc123",
		"arn:aws-cn:apigateway:cn-north-1::/apis/abc123",
	} {
		identity, err := stageIdentification(apiARN, "prod")
		require.NoError(t, err)
		assert.Equal(t, apiARN+"/stages/prod", identity.Arn)
	}
	identity, err := stageIdentification("arn:aws:apigateway:us-east-1::/apis/abc123", "$default")
	require.NoError(t, err)
	assert.Equal(t, "arn:aws:apigateway:us-east-1::/apis/abc123/stages/$default", identity.Arn)
	for _, name := range []string{"", " ", "prod/other", "$default"} {
		identity, err := stageIdentification("arn:aws:apigateway:us-east-1::/restapis/abc123", name)
		require.Error(t, err)
		assert.Nil(t, identity)
	}
}

func TestRESTStageSettingsKeepTheirOwner(t *testing.T) {
	const apiARN = "arn:aws:apigateway:us-east-1::/restapis/abc123"
	const webACL = "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod/id"
	stages, errs := restAPIStages(apiARN, []v1types.Stage{
		{StageName: aws.String("prod"), DeploymentId: aws.String("deployment-prod"), WebAclArn: aws.String(webACL),
			Variables: map[string]string{"backend": "prod"}, ClientCertificateId: aws.String("cert-prod"),
			AccessLogSettings: &v1types.AccessLogSettings{DestinationArn: aws.String("arn:aws:logs:us-east-1:123456789012:log-group:prod")}},
		{StageName: aws.String("dev"), DeploymentId: aws.String("deployment-dev"),
			AccessLogSettings: &v1types.AccessLogSettings{DestinationArn: aws.String("arn:aws:logs:us-east-1:123456789012:log-group:dev")}},
		{},
	})
	require.Len(t, errs, 1)
	require.Len(t, stages, 2)
	assert.Equal(t, "dev", stages[0].Identification.Name)
	assert.Nil(t, stages[0].Resources)
	assert.Equal(t, "arn:aws:logs:us-east-1:123456789012:log-group:dev", stages[0].Configuration.AccessLogSettings.DestinationArn)
	assert.Equal(t, apiARN+"/stages/prod", stages[1].Identification.Arn)
	assert.Equal(t, webACL, stages[1].Resources.WebAcl.Arn)
	assert.Equal(t, "deployment-prod", *stages[1].Configuration.DeploymentId)
	assert.Equal(t, "cert-prod", *stages[1].Configuration.ClientCertificateId)
	assert.Equal(t, "prod", stages[1].Configuration.Variables["backend"])
	assert.Equal(t, "arn:aws:logs:us-east-1:123456789012:log-group:prod", stages[1].Configuration.AccessLogSettings.DestinationArn)

	payload, err := json.Marshal(stages[1])
	require.NoError(t, err)
	var signal map[string]any
	require.NoError(t, json.Unmarshal(payload, &signal))
	assert.Equal(t, apiARN+"/stages/prod", signal["identification"].(map[string]any)["arn"])
	assert.NotContains(t, signal["resources"], "routes")
}

func TestHTTPStagesPreserveDefaultAndIndependentConfiguration(t *testing.T) {
	stages, errs := httpAPIStages("arn:aws:apigateway:us-east-1::/apis/abc123", []v2types.Stage{
		{StageName: aws.String("$default"), AutoDeploy: aws.Bool(false), StageVariables: map[string]string{"backend": "default"}},
		{StageName: aws.String("prod"), AutoDeploy: aws.Bool(true),
			AccessLogSettings: &v2types.AccessLogSettings{DestinationArn: aws.String("arn:aws:logs:us-east-1:123456789012:log-group:prod")}},
	})
	require.Empty(t, errs)
	require.Len(t, stages, 2)
	assert.False(t, *stages[0].Configuration.AutoDeploy)
	assert.Nil(t, stages[0].Configuration.AccessLogSettings)
	assert.Equal(t, "default", stages[0].Configuration.Variables["backend"])
	assert.True(t, *stages[1].Configuration.AutoDeploy)
	assert.NotNil(t, stages[1].Configuration.AccessLogSettings)
}

func TestInvalidStageEnrichmentDoesNotDropStage(t *testing.T) {
	stages, errs := restAPIStages("arn:aws:apigateway:us-east-1::/restapis/abc123", []v1types.Stage{{
		StageName: aws.String("prod"), WebAclArn: aws.String("not-an-arn"),
		AccessLogSettings: &v1types.AccessLogSettings{},
	}})
	require.Len(t, errs, 2)
	require.Len(t, stages, 1)
	assert.Nil(t, stages[0].Resources)
	assert.Nil(t, stages[0].Configuration.AccessLogSettings)
}

func TestHTTPDefaultRouteIsExplicit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"routeKey":"$default"},{"routeKey":"ANY /items"},{"routeKey":"GET /items"}]}`))
	}))
	defer server.Close()
	client := apigatewayv2.NewFromConfig(aws.Config{
		Region: "us-east-1", Credentials: aws.AnonymousCredentials{}, BaseEndpoint: aws.String(server.URL),
	})
	routes, errs := getHTTPAPIRoutes(context.Background(), client, "abc123", "us-east-1")
	require.Empty(t, errs)
	require.Len(t, routes, 3)
	assert.True(t, *routes[0].Configuration.IsDefaultRoute)
	assert.Equal(t, "$default", routes[0].Identification.Path)
	assert.False(t, *routes[1].Configuration.IsDefaultRoute)
	assert.Equal(t, "ANY", routes[1].Identification.Method)
	assert.False(t, *routes[2].Configuration.IsDefaultRoute)
}
