package s3

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseBucketURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		url            string
		expectedBucket string
		expectedRegion string
	}{
		{name: "virtual hosted regional", url: "https://bucket.s3.us-east-1.amazonaws.com", expectedBucket: "bucket", expectedRegion: "us-east-1"},
		{name: "virtual hosted global", url: "bucket.s3.amazonaws.com", expectedBucket: "bucket"},
		{name: "virtual hosted dualstack", url: "bucket.s3.dualstack.us-west-2.amazonaws.com", expectedBucket: "bucket", expectedRegion: "us-west-2"},
		{name: "dotted bucket", url: "sub.domain.bucket.s3.eu-west-1.amazonaws.com", expectedBucket: "sub.domain.bucket", expectedRegion: "eu-west-1"},
		{name: "China endpoint", url: "bucket.s3.cn-north-1.amazonaws.com.cn", expectedBucket: "bucket", expectedRegion: "cn-north-1"},
		{name: "GovCloud endpoint", url: "bucket.s3.us-gov-west-1.amazonaws.com", expectedBucket: "bucket", expectedRegion: "us-gov-west-1"},
		{name: "path style regional", url: "https://s3.us-east-2.amazonaws.com/bucket", expectedBucket: "bucket", expectedRegion: "us-east-2"},
		{name: "path style global", url: "https://s3.amazonaws.com/bucket", expectedBucket: "bucket"},
		{name: "path style dualstack", url: "https://s3.dualstack.us-west-2.amazonaws.com/bucket", expectedBucket: "bucket", expectedRegion: "us-west-2"},
		{name: "legacy path style dualstack", url: "https://s3-dualstack.us-west-2.amazonaws.com/bucket", expectedBucket: "bucket", expectedRegion: "us-west-2"},
		{name: "website hyphen", url: "bucket.s3-website-us-east-1.amazonaws.com", expectedBucket: "bucket", expectedRegion: "us-east-1"},
		{name: "website dot", url: "bucket.s3-website.us-east-1.amazonaws.com", expectedBucket: "bucket", expectedRegion: "us-east-1"},
		{name: "accelerate", url: "bucket.s3-accelerate.amazonaws.com", expectedBucket: "bucket"},
		{name: "accelerate dualstack", url: "bucket.s3-accelerate.dualstack.amazonaws.com", expectedBucket: "bucket"},
		{name: "custom domain", url: "https://assets.example.com/object", expectedBucket: "assets.example.com"},
		{name: "unrecognized AWS endpoint", url: "https://ec2.us-east-1.amazonaws.com", expectedBucket: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			bucket, region := parseBucketURL(test.url)
			assert.Equal(t, test.expectedBucket, bucket)
			assert.Equal(t, test.expectedRegion, region)
		})
	}
}
