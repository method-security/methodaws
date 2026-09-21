package enumerate

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	s3fern "github.com/Method-Security/methodaws/generated/go/s3"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubListBucketsClient struct {
	outputs []*s3.ListBucketsOutput
	errors  []error
	inputs  []*s3.ListBucketsInput
}

func (s *stubListBucketsClient) ListBuckets(
	_ context.Context,
	input *s3.ListBucketsInput,
	_ ...func(*s3.Options),
) (*s3.ListBucketsOutput, error) {
	inputCopy := *input
	s.inputs = append(s.inputs, &inputCopy)
	if len(s.errors) > 0 {
		err := s.errors[0]
		s.errors = s.errors[1:]
		if err != nil {
			return nil, err
		}
	}
	output := s.outputs[0]
	s.outputs = s.outputs[1:]
	return output, nil
}

func TestListBucketsPreservesCompletedPagesWhenPaginationFails(t *testing.T) {
	t.Parallel()

	client := &stubListBucketsClient{
		outputs: []*s3.ListBucketsOutput{{
			Buckets:           []types.Bucket{{Name: aws.String("preserved")}},
			ContinuationToken: aws.String("next-page"),
		}},
		errors: []error{nil, errors.New("page two denied")},
	}

	output, err := listBuckets(context.Background(), client)

	require.EqualError(t, err, "page two denied")
	require.NotNil(t, output)
	require.Len(t, output.Buckets, 1)
	assert.Equal(t, "preserved", aws.ToString(output.Buckets[0].Name))
}

func TestKmsKeyReferenceRequiresKeyARN(t *testing.T) {
	t.Parallel()

	reference := kmsKeyReference("arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/abcd-1234")

	require.NotNil(t, reference)
	assert.Equal(t, "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/abcd-1234", reference.Arn)
	assert.Equal(t, "abcd-1234", reference.KeyId)
	assert.Equal(t, "us-gov-west-1", reference.Region)
}

func TestNormalizeBucketRegion(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "us-east-1", normalizeBucketRegion(""))
	assert.Equal(t, "eu-west-1", normalizeBucketRegion(types.BucketLocationConstraint("EU")))
	assert.Equal(t, "ap-south-2", normalizeBucketRegion(types.BucketLocationConstraint("ap-south-2")))
}

func TestS3RequestRegion(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "us-gov-east-1", s3RequestRegion("us-east-1", []string{"us-gov-east-1"}))
	assert.Equal(t, "cn-north-1", s3RequestRegion("", []string{"cn-north-1", "cn-northwest-1"}))
	assert.Equal(t, "eu-west-1", s3RequestRegion("eu-west-1", nil))
	assert.Empty(t, s3RequestRegion("", nil))
}

func TestKmsKeyReferenceRejectsIdentifiersThatAreNotKeyARNs(t *testing.T) {
	t.Parallel()

	assert.Nil(t, kmsKeyReference("abcd-1234"))
	assert.Nil(t, kmsKeyReference("alias/example"))
	assert.Nil(t, kmsKeyReference("arn:aws:kms:us-east-1:123456789012:alias/example"))
}

func TestBucketEncryptionPreservesConfiguredKeyIdentifier(t *testing.T) {
	for _, identifier := range []string{
		"abcd-1234", "alias/example", "arn:aws:kms:us-east-1:123456789012:alias/example",
		"arn:aws:kms:us-east-1:123456789012:key/abcd-1234",
	} {
		t.Run(identifier, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err := fmt.Fprintf(w, `<ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm><KMSMasterKeyID>%s</KMSMasterKeyID></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`, identifier)
				assert.NoError(t, err)
			}))
			defer server.Close()
			client := s3.NewFromConfig(aws.Config{
				Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: aws.AnonymousCredentials{},
			}, func(options *s3.Options) { options.UsePathStyle = true })
			bucket := &s3fern.S3Bucket{
				Identification: &s3fern.S3BucketIdentificationInfo{Name: "example-bucket"},
				Configuration:  &s3fern.S3BucketConfigurationInfo{},
			}
			result, err := bucketEncryption(context.Background(), client, bucket)
			require.NoError(t, err)
			require.Len(t, result.Configuration.EncryptionRules, 1)
			assert.Equal(t, aws.String(identifier), result.Configuration.EncryptionRules[0].KmsKeyIdentifier)
			assert.Equal(t, kmsKeyReference(identifier), result.Configuration.EncryptionRules[0].KmsKey)
		})
	}
}

func TestListBucketsPaginates(t *testing.T) {
	t.Parallel()

	client := &stubListBucketsClient{outputs: []*s3.ListBucketsOutput{
		{
			Buckets:           []types.Bucket{{Name: aws.String("first")}},
			ContinuationToken: aws.String("next-page"),
		},
		{Buckets: []types.Bucket{{Name: aws.String("second")}}},
	}}

	output, err := listBuckets(context.Background(), client)

	require.NoError(t, err)
	require.Len(t, output.Buckets, 2)
	assert.Equal(t, "first", aws.ToString(output.Buckets[0].Name))
	assert.Equal(t, "second", aws.ToString(output.Buckets[1].Name))
	require.Len(t, client.inputs, 2)
	assert.Equal(t, int32(1000), aws.ToInt32(client.inputs[0].MaxBuckets))
	assert.Nil(t, client.inputs[0].ContinuationToken)
	assert.Equal(t, "next-page", aws.ToString(client.inputs[1].ContinuationToken))
}
