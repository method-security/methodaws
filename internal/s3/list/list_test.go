package list

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	s3fern "github.com/Method-Security/methodaws/generated/go/s3"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type listingHTTPClient struct {
	headStatus int
	region     string
	listHost   string
}

func (c *listingHTTPClient) Do(request *http.Request) (*http.Response, error) {
	header := http.Header{}
	status := http.StatusOK
	body := `<ListBucketResult><Contents><Key>example</Key><Size>1</Size></Contents></ListBucketResult>`
	if request.Method == http.MethodHead {
		status = c.headStatus
		header.Set("X-Amz-Bucket-Region", c.region)
		body = ""
	} else {
		c.listHost = request.URL.Host
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
}

func TestListingUsesDiscoveredRegionAndSurvivesDiscoveryFailure(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusMovedPermanently, http.StatusForbidden} {
		client := &listingHTTPClient{headStatus: status, region: "us-west-2"}
		report := ListS3Bucket(context.Background(), aws.Config{
			Region: "us-east-1", Credentials: aws.AnonymousCredentials{}, HTTPClient: client, RetryMaxAttempts: 1,
		}, s3fern.ListS3BucketConfig{BucketName: "example-bucket"})
		require.Empty(t, report.Errors)
		assert.Contains(t, client.listHost, "us-west-2")
		require.NotNil(t, report.Result.Resources)
		assert.Len(t, report.Result.Resources.Objects, 1)
	}
	client := &listingHTTPClient{headStatus: http.StatusForbidden}
	report := ListS3Bucket(context.Background(), aws.Config{
		Region: "us-east-1", Credentials: aws.AnonymousCredentials{}, HTTPClient: client, RetryMaxAttempts: 1,
	}, s3fern.ListS3BucketConfig{BucketName: "example-bucket"})
	require.Len(t, report.Errors, 1)
	require.NotNil(t, report.Result.Resources)
	assert.Len(t, report.Result.Resources.Objects, 1)
}
