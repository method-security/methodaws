// Package list provides S3 bucket object listing.
package list

import (
	// Standard
	"context"
	// Generated
	s3fern "github.com/Method-Security/methodaws/generated/go/s3"
	// Internal
	// External
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
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

	// Initialize S3 client - S3 will route to the correct region automatically
	s3Client := s3.NewFromConfig(awscfg)
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
