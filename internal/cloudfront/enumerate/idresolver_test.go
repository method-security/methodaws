package enumerate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIGatewayOriginUsesResolvedAPIFamily(t *testing.T) {
	for _, tc := range []struct {
		name, region, suffix, partition, resource string
		restStatus                                int
	}{
		{"REST", "us-east-1", "amazonaws.com", "aws", "/restapis/", http.StatusOK},
		{"v2", "us-east-1", "amazonaws.com", "aws", "/apis/", http.StatusNotFound},
		{"REST denied v2 allowed", "us-east-1", "amazonaws.com", "aws", "/apis/", http.StatusForbidden},
		{"China", "cn-north-1", "amazonaws.com.cn", "aws-cn", "/restapis/", http.StatusOK},
		{"GovCloud", "us-gov-west-1", "amazonaws.com", "aws-us-gov", "/apis/", http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/restapis/example123":
					w.WriteHeader(tc.restStatus)
					assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{"id": "example123"}))
				case "/v2/apis/example123":
					assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{"apiId": "example123"}))
				default:
					t.Errorf("unexpected lookup: %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			cfg := aws.Config{Region: "us-east-1", Credentials: aws.AnonymousCredentials{}, BaseEndpoint: aws.String(server.URL)}
			domain := "example123.execute-api." + tc.region + "." + tc.suffix
			origin, err := processOrigin(context.Background(), cfg, types.Origin{
				Id: aws.String("native-origin-label"), DomainName: aws.String(domain),
			}, "123456789012")
			require.NoError(t, err)
			require.NotNil(t, origin.Backend)
			require.NotNil(t, origin.Backend.ApiGateway)
			assert.Equal(t, "native-origin-label", origin.Identification.Id)
			assert.Equal(t, "arn:"+tc.partition+":apigateway:"+tc.region+"::"+tc.resource+"example123", origin.Backend.ApiGateway.Arn)
			assert.Equal(t, "example123", origin.Backend.ApiGateway.Id)
			assert.Equal(t, tc.region, origin.Backend.ApiGateway.Region)
			if tc.restStatus == http.StatusOK {
				assert.Equal(t, 1, requests)
			} else {
				assert.Equal(t, 2, requests)
			}
		})
	}
}

func TestUnresolvedAPIOriginDoesNotInventBackendAndCollectionContinues(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusOK} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{"id": "different-api", "apiId": "different-api"}))
			}))
			defer server.Close()
			cfg := aws.Config{Credentials: aws.AnonymousCredentials{}, BaseEndpoint: aws.String(server.URL)}
			origins, errs := processOrigins(context.Background(), cfg, []types.Origin{
				{Id: aws.String("api-origin"), DomainName: aws.String("example123.execute-api.us-east-1.amazonaws.com")},
				{Id: aws.String("bucket-origin"), DomainName: aws.String("example-bucket.s3.amazonaws.com")},
				{Id: aws.String("custom-origin"), DomainName: aws.String("backend.example.com")},
			}, "123456789012")
			require.Len(t, errs, 1)
			assert.Contains(t, errs[0], `Origin "api-origin"`)
			require.Len(t, origins, 3)
			assert.Nil(t, origins[0].Backend)
			assert.Equal(t, "example123.execute-api.us-east-1.amazonaws.com", aws.ToString(origins[0].Identification.DomainName))
			require.NotNil(t, origins[1].Backend.S3)
			assert.Equal(t, "example-bucket", origins[1].Backend.S3.BucketName)
			assert.Nil(t, origins[2].Backend)
		})
	}
}
