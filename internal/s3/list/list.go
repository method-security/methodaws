// Package list provides S3 bucket object listing.
package list

import (
	// Standard
	"context"
	"errors"
	"fmt"
	"net/http"

	// Generated
	s3fern "github.com/Method-Security/methodaws/generated/go/s3"
	// Internal
	// External
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// ListS3Bucket retrieves the objects stored in an S3 bucket and returns an LsResourceReport struct
func ListS3Bucket(ctx context.Context, awscfg aws.Config, config s3fern.ListS3BucketConfig) *s3fern.S3ListReport {
	// Initialize logger
	log := svc1log.FromContext(ctx)
	log.Info("Starting S3 bucket listing", svc1log.SafeParam("bucketName", config.BucketName))

	// Initialize report
	report := s3fern.S3ListReport{
		Config: &config,
		Result: &s3fern.ListResult{},
	}
	errors := []string{}
	var allBucketObjects []*s3fern.BucketObject

	awscfg = awscfg.Copy()
	if awscfg.Region == "" {
		awscfg.Region = "us-east-1"
	}
	s3Client := s3.NewFromConfig(awscfg)
	region, err := bucketRegion(ctx, s3Client, config.BucketName)
	if err != nil {
		// A failed metadata lookup should not prevent a permitted object listing.
		errors = append(errors, err.Error())
	} else if region != awscfg.Region {
		awscfg.Region = region
		s3Client = s3.NewFromConfig(awscfg)
	}
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(config.BucketName),
	}

	// List objects in the bucket
	paginator := s3.NewListObjectsV2Paginator(s3Client, input)
	pageCount := 0
	for paginator.HasMorePages() {
		pageCount++
		output, err := paginator.NextPage(ctx)
		if err != nil {
			log.Error("Error fetching page from S3 bucket",
				svc1log.SafeParam("bucketName", config.BucketName),
				svc1log.SafeParam("pageNumber", pageCount),
				svc1log.Stacktrace(err))
			errors = append(errors, err.Error())
			break
		} else {
			for _, item := range output.Contents {
				if item.Size == nil {
					continue
				}
				allBucketObjects = append(allBucketObjects, &s3fern.BucketObject{
					Name: *item.Key,
					Size: int(*item.Size),
				})
			}
		}
	}

	// Only add if there are objects in the bucket
	if len(allBucketObjects) > 0 {
		resources := s3fern.ListResources{
			Name:    aws.String(config.BucketName),
			Objects: allBucketObjects,
		}
		report.Result.Resources = &resources
	}
	report.Errors = errors
	return &report
}

func bucketRegion(ctx context.Context, client *s3.Client, bucketName string) (string, error) {
	output, err := client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(bucketName)})
	if err == nil {
		if output != nil && aws.ToString(output.BucketRegion) != "" {
			return *output.BucketRegion, nil
		}
		return "", fmt.Errorf("HeadBucket returned no region for bucket %s", bucketName)
	}
	var responseError *smithyhttp.ResponseError
	if errors.As(err, &responseError) {
		response := responseError.HTTPResponse()
		if response != nil {
			region := response.Header.Get("X-Amz-Bucket-Region")
			switch response.StatusCode {
			case http.StatusMovedPermanently, http.StatusTemporaryRedirect, http.StatusBadRequest, http.StatusForbidden:
				if region != "" {
					return region, nil
				}
			}
		}
	}
	return "", fmt.Errorf("discover region for bucket %s: %w", bucketName, err)
}
