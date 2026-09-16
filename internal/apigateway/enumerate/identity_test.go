package apigateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	v1types "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	v2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIIdentificationARNs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	for _, tc := range []struct {
		region    string
		partition string
	}{
		{"us-east-1", "aws"},
		{"us-gov-west-1", "aws-us-gov"},
		{"cn-north-1", "aws-cn"},
	} {
		t.Run(tc.region, func(t *testing.T) {
			cfg := aws.Config{Region: tc.region, Credentials: aws.AnonymousCredentials{}, BaseEndpoint: aws.String(server.URL)}
			rest, errs := convertV1RestAPIToFern(context.Background(), apigateway.NewFromConfig(cfg),
				v1types.RestApi{Id: aws.String("example123")}, nil, tc.region)
			require.Empty(t, errs)
			require.NotNil(t, rest)
			assert.Equal(t, "arn:"+tc.partition+":apigateway:"+tc.region+"::/restapis/example123", rest.Identification.Arn)
			assert.Equal(t, "example123", rest.Identification.Id)
			assert.Nil(t, rest.Identification.Url)

			httpAPI, errs := convertV2HttpAPIToFern(context.Background(), apigatewayv2.NewFromConfig(cfg),
				v2types.Api{ApiId: aws.String("example123")}, tc.region)
			require.Empty(t, errs)
			require.NotNil(t, httpAPI)
			assert.Equal(t, "arn:"+tc.partition+":apigateway:"+tc.region+"::/apis/example123", httpAPI.Identification.Arn)
			assert.Equal(t, "example123", httpAPI.Identification.Id)
			assert.Nil(t, httpAPI.Identification.Url)
		})
	}
}

func TestAPIIdentificationRejectsMissingIdentity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		id     string
		region string
	}{
		{"missing ID", "", "us-east-1"},
		{"missing region", "example123", ""},
		{"invalid region", "example123", "not-a-region"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Identity failures must return before any enrichment requests.
			rest, errs := convertV1RestAPIToFern(context.Background(), nil,
				v1types.RestApi{Id: aws.String(tc.id)}, nil, tc.region)
			assert.Nil(t, rest)
			require.NotEmpty(t, errs)

			httpAPI, errs := convertV2HttpAPIToFern(context.Background(), nil,
				v2types.Api{ApiId: aws.String(tc.id)}, tc.region)
			assert.Nil(t, httpAPI)
			require.NotEmpty(t, errs)
		})
	}
}
