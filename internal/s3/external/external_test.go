package s3

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubHeadBucketClient struct {
	output *awss3.HeadBucketOutput
	err    error
}

func (s *stubHeadBucketClient) HeadBucket(
	context.Context,
	*awss3.HeadBucketInput,
	...func(*awss3.Options),
) (*awss3.HeadBucketOutput, error) {
	return s.output, s.err
}

func TestLocateBucketUsesRegionFromSuccessfulResponse(t *testing.T) {
	t.Parallel()

	exists, region, err := locateBucketWithClient(context.Background(), &stubHeadBucketClient{
		output: &awss3.HeadBucketOutput{BucketRegion: aws.String("eu-west-1")},
	}, "us-east-1", "example-bucket")

	require.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, "eu-west-1", region)
}

func TestLocateBucketUsesRegionFromAccessDeniedResponse(t *testing.T) {
	t.Parallel()

	header := make(http.Header)
	header.Set("X-Amz-Bucket-Region", "ap-southeast-2")
	exists, region, err := locateBucketWithClient(context.Background(), &stubHeadBucketClient{
		err: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusForbidden, Header: header}},
			Err:      errors.New("access denied"),
		},
	}, "us-east-1", "example-bucket")

	require.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, "ap-southeast-2", region)
}

func TestLocateBucketUsesProbeRegionForAccessDeniedWithoutRegionHeader(t *testing.T) {
	t.Parallel()

	exists, region, err := locateBucketWithClient(context.Background(), &stubHeadBucketClient{
		err: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusForbidden, Header: make(http.Header)}},
			Err:      errors.New("access denied"),
		},
	}, "us-gov-west-1", "example-bucket")

	require.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, "us-gov-west-1", region)
}

func TestLocateBucketTreatsNotFoundAsAbsent(t *testing.T) {
	t.Parallel()

	exists, region, err := locateBucketWithClient(context.Background(), &stubHeadBucketClient{
		err: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header)}},
			Err:      errors.New("not found"),
		},
	}, "us-east-1", "example-bucket")

	require.NoError(t, err)
	assert.False(t, exists)
	assert.Empty(t, region)
}
