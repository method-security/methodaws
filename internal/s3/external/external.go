package s3

import (
	// Standard
	"context"
	"fmt"
	"strings"

	// Generated
	s3fern "github.com/Method-Security/methodaws/generated/go/s3"
	methodconfig "github.com/Method-Security/methodaws/internal/config"
	"github.com/Method-Security/methodaws/utils"

	// External
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// bucketExists checks if a bucket exists and is accessible
func bucketExists(ctx context.Context, region string, bucketName string) (bool, error) {
	log := svc1log.FromContext(ctx)

	// Create a custom AWS config with anonymous credentials
	loadOptions, err := methodconfig.AWSLoadOptionsFromContext(ctx)
	if err != nil {
		log.Error("Failed to configure proxy for bucket existence check",
			svc1log.SafeParam("bucketName", bucketName),
			svc1log.SafeParam("region", region),
			svc1log.Stacktrace(err))
		return false, fmt.Errorf("error configuring proxy: %v", err)
	}
	loadOptions = append([]methodconfig.AWSLoadOption{
		awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(aws.AnonymousCredentials{}),
	}, loadOptions...)
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		loadOptions...,
	)
	if err != nil {
		log.Error("Failed to load AWS config for bucket existence check",
			svc1log.SafeParam("bucketName", bucketName),
			svc1log.SafeParam("region", region),
			svc1log.Stacktrace(err))
		return false, fmt.Errorf("error loading AWS config: %v", err)
	}

	// Create an S3 client
	client := s3.NewFromConfig(cfg)

	// Try HeadBucket to check existence
	_, err = client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucketName),
	})

	if err != nil {
		errStr := err.Error()

		if strings.Contains(errStr, "NotFound") || strings.Contains(errStr, "NoSuchBucket") {
			log.Info("Bucket not found",
				svc1log.SafeParam("bucketName", bucketName),
				svc1log.SafeParam("region", region))
			return false, nil
		}

		if strings.Contains(errStr, "Forbidden") || strings.Contains(errStr, "AccessDenied") {
			log.Warn("Bucket exists but access is denied",
				svc1log.SafeParam("bucketName", bucketName),
				svc1log.SafeParam("region", region))
			return true, nil // Bucket exists but we don't have access
		}

		log.Error("Error checking bucket existence",
			svc1log.SafeParam("bucketName", bucketName),
			svc1log.SafeParam("region", region),
			svc1log.Stacktrace(err))
		return false, fmt.Errorf("error checking bucket: %v", err)
	}

	return true, nil
}

// listBucketContents attempts to list objects in the bucket
func listBucketContents(ctx context.Context, client *s3.Client, bucketName string) ([]*s3fern.DirectoryContents, error) {
	log := svc1log.FromContext(ctx)
	maxKeys := int32(100) // Limit the number of objects to list
	directoryContents := []*s3fern.DirectoryContents{}

	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket:     aws.String(bucketName),
		MaxKeys:    &maxKeys,
		FetchOwner: aws.Bool(true),
	})

	// Get first page only to avoid overwhelming the API
	page, err := paginator.NextPage(ctx)
	if err != nil {
		log.Error("Failed to list bucket contents",
			svc1log.SafeParam("bucketName", bucketName),
			svc1log.Stacktrace(err))
		return nil, fmt.Errorf("error listing bucket contents: %v", err)
	}
	if page == nil {
		return nil, fmt.Errorf("listing bucket contents returned no response")
	}

	for _, object := range page.Contents {
		if object.Key == nil {
			continue
		}
		var size int
		if object.Size != nil {
			size = int(*object.Size)
		}

		details := &s3fern.DirectoryContents{
			Key:          *object.Key,
			LastModified: object.LastModified,
			Size:         &size,
		}

		if object.Owner != nil {
			details.OwnerId = object.Owner.ID
			details.OwnerName = object.Owner.DisplayName
		}

		directoryContents = append(directoryContents, details)
	}

	return directoryContents, nil
}

// checkListingAllowed checks if listing objects is allowed on a bucket
func checkListingAllowed(ctx context.Context, client *s3.Client, bucketName string) bool {
	maxKeys := int32(1)
	_, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:     aws.String(bucketName),
		MaxKeys:    &maxKeys,
		FetchOwner: aws.Bool(true),
	})
	return err == nil
}

// checkAnonymousReadAllowed checks if anonymous read is allowed on a bucket
func checkAnonymousReadAllowed(ctx context.Context, client *s3.Client, bucketName string, directoryContents []*s3fern.DirectoryContents) bool {
	if len(directoryContents) > 0 {
		_, err := client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(directoryContents[0].Key),
		})
		return err == nil
	}
	return false
}

// checkPolicy checks the bucket policy
func checkPolicy(ctx context.Context, client *s3.Client, bucketName string) (string, error) {
	policyOutput, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: aws.String(bucketName),
	})
	if err == nil && policyOutput.Policy != nil {
		return *policyOutput.Policy, nil
	}
	return "", fmt.Errorf("error getting bucket policy: %v", err)
}

// checkACL checks the bucket ACL
func checkACL(ctx context.Context, client *s3.Client, bucketName string) ([]*s3fern.S3BucketAccessControl, *string, *string, error) {
	output, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		return nil, nil, nil, err
	}

	// Extract owner information
	var ownerID, ownerName *string
	if output.Owner != nil {
		ownerID = output.Owner.ID
		ownerName = output.Owner.DisplayName
	}

	// Process ACL grants
	acls := processS3ACLGrants(output.Grants)

	return acls, ownerID, ownerName, nil
}

// processS3ACLGrants converts AWS S3 ACL grants to boolean-based ACL structures
func processS3ACLGrants(grants []types.Grant) []*s3fern.S3BucketAccessControl {
	if len(grants) == 0 {
		return nil
	}

	// Group grants by grantee type to create consolidated ACL objects
	publicACL := &s3fern.S3BucketAccessControl{}
	authUserACL := &s3fern.S3BucketAccessControl{}
	logDeliveryACL := &s3fern.S3BucketAccessControl{}

	hasPublic := false
	hasAuthUser := false
	hasLogDelivery := false

	for _, grant := range grants {
		if grant.Grantee == nil || grant.Grantee.URI == nil {
			continue
		}

		granteeURI := *grant.Grantee.URI
		permission := string(grant.Permission)

		// Public Access permissions (AllUsers)
		if granteeURI == "http://acs.amazonaws.com/groups/global/AllUsers" {
			hasPublic = true
			switch permission {
			case "READ":
				publicACL.AllowPublicRead = aws.Bool(true)
			case "WRITE":
				publicACL.AllowPublicWrite = aws.Bool(true)
			case "READ_ACP":
				publicACL.AllowPublicReadAcp = aws.Bool(true)
			case "WRITE_ACP":
				publicACL.AllowPublicWriteAcp = aws.Bool(true)
			case "FULL_CONTROL":
				publicACL.AllowPublicFullControl = aws.Bool(true)
			}
		}

		// Authenticated users permissions
		if granteeURI == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" {
			hasAuthUser = true
			switch permission {
			case "READ":
				authUserACL.AllowAuthenticatedUsersRead = aws.Bool(true)
			case "WRITE":
				authUserACL.AllowAuthenticatedUsersWrite = aws.Bool(true)
			case "READ_ACP":
				authUserACL.AllowAuthenticatedUsersReadAcp = aws.Bool(true)
			case "WRITE_ACP":
				authUserACL.AllowAuthenticatedUsersWriteAcp = aws.Bool(true)
			case "FULL_CONTROL":
				authUserACL.AllowAuthenticatedUsersFullControl = aws.Bool(true)
			}
		}

		// Log delivery permissions
		if granteeURI == "http://acs.amazonaws.com/groups/s3/LogDelivery" {
			hasLogDelivery = true
			switch permission {
			case "WRITE":
				logDeliveryACL.AllowLogDeliveryWrite = aws.Bool(true)
			case "READ_ACP":
				logDeliveryACL.AllowLogDeliveryReadAcp = aws.Bool(true)
			}
		}
	}

	var acls []*s3fern.S3BucketAccessControl
	if hasPublic {
		acls = append(acls, publicACL)
	}
	if hasAuthUser {
		acls = append(acls, authUserACL)
	}
	if hasLogDelivery {
		acls = append(acls, logDeliveryACL)
	}

	return acls
}

// EnumerateS3Region enumerates a single public facing S3 bucket in a specific region
func externalS3Region(ctx context.Context, bucketURL string, bucketName string, region string) (*s3fern.ExternalS3BucketResult, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting external S3 bucket enumeration",
		svc1log.SafeParam("bucketName", bucketName),
		svc1log.SafeParam("region", region),
		svc1log.SafeParam("bucketURL", bucketURL))

	// Initialize variables
	report := s3fern.ExternalS3BucketResult{}

	// Construct ARN for the bucket
	bucketARN, err := utils.BuildGlobalARNForRegion(region, "s3", "", bucketName)
	if err != nil {
		return nil, []string{err.Error()}
	}

	externalBucket := s3fern.ExternalBucket{
		Identification: &s3fern.ExternalBucketIdentificationInfo{
			Name:   bucketName,
			Region: region,
			Url:    bucketURL,
			Arn:    bucketARN,
		},
		Configuration: &s3fern.ExternalBucketConfigurationInfo{},
		Resources:     &s3fern.ExternalBucketResourceInfo{},
	}
	errors := []string{}

	// Create a custom AWS config with anonymous credentials
	loadOptions, err := methodconfig.AWSLoadOptionsFromContext(ctx)
	if err != nil {
		log.Error("Failed to configure proxy for external enumeration",
			svc1log.SafeParam("region", region),
			svc1log.Stacktrace(err))
		errors = append(errors, fmt.Sprintf("error configuring proxy: %v", err))
		return nil, errors
	}
	loadOptions = append([]methodconfig.AWSLoadOption{
		awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(aws.AnonymousCredentials{}),
	}, loadOptions...)
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		loadOptions...,
	)
	if err != nil {
		log.Error("Failed to load AWS config for external enumeration",
			svc1log.SafeParam("region", region),
			svc1log.Stacktrace(err))
		errors = append(errors, fmt.Sprintf("error loading AWS config: %v", err))
		return nil, errors
	}

	// Create an S3 client
	client := s3.NewFromConfig(cfg)

	// Check if listing is allowed and get directory contents
	externalBucket.Configuration.AllowDirectoryListing = checkListingAllowed(ctx, client, bucketName)
	if externalBucket.Configuration.AllowDirectoryListing {
		directoryContents, err := listBucketContents(ctx, client, bucketName)
		if err != nil {
			errors = append(errors, fmt.Sprintf("error listing bucket contents: %v", err))
		} else {
			externalBucket.Resources.DirectoryContents = directoryContents
			// Check anonymous read access if we found any objects
			externalBucket.Configuration.AllowAnonymousRead = checkAnonymousReadAllowed(ctx, client, bucketName, directoryContents)
		}
	}

	// Check bucket policy
	policy, err := checkPolicy(ctx, client, bucketName)
	if err == nil {
		externalBucket.Configuration.Policy = &policy
	} else {
		log.Warn("Failed to get bucket policy",
			svc1log.SafeParam("bucketName", bucketName),
			svc1log.Stacktrace(err))
		errors = append(errors, fmt.Sprintf("Error getting bucket policy: %v", err))
	}

	// Check bucket ACL and get owner information
	acls, ownerID, ownerName, err := checkACL(ctx, client, bucketName)
	if err == nil {
		externalBucket.Configuration.Acls = acls
		externalBucket.Configuration.OwnerId = ownerID
		externalBucket.Configuration.OwnerName = ownerName
	} else {
		log.Warn("Failed to get bucket ACL",
			svc1log.SafeParam("bucketName", bucketName),
			svc1log.Stacktrace(err))
		errors = append(errors, fmt.Sprintf("Error getting bucket ACL: %v", err))
	}

	report.ExternalBuckets = append(report.ExternalBuckets, &externalBucket)

	log.Info("External S3 bucket enumeration completed",
		svc1log.SafeParam("bucketName", bucketName),
		svc1log.SafeParam("region", region),
		svc1log.SafeParam("allowDirectoryListing", externalBucket.Configuration.AllowDirectoryListing),
		svc1log.SafeParam("allowAnonymousRead", externalBucket.Configuration.AllowAnonymousRead),
		svc1log.SafeParam("errorCount", len(errors)))

	return &report, errors
}

// EnumerateS3 attempts to enumerate a public facing S3 bucket with no credentials.
// When TargetSeed is set, candidate bucket names are generated from the seed and
// each is probed; otherwise a single bucket is enumerated from Url.
func EnumerateS3(ctx context.Context, config s3fern.S3ExternalConfig) s3fern.ExternalS3Report {
	log := svc1log.FromContext(ctx)

	report := s3fern.ExternalS3Report{Config: &config}
	result := s3fern.ExternalS3BucketResult{}
	errors := []string{}

	// Seed-based candidate discovery takes precedence when provided. A
	// whitespace-only seed normalizes to zero candidates, so treat it as unset.
	if config.TargetSeed != nil && strings.TrimSpace(*config.TargetSeed) != "" {
		seedResult, seedErrors := enumerateBySeed(ctx, config)
		if config.Url != nil && *config.Url != "" {
			// The CLI rejects supplying both modes; a programmatic caller still can.
			// Seed discovery wins, but surface the ignored url rather than silently
			// dropping it so the caller is not misled into thinking it was probed.
			log.Warn("Both url and targetSeed provided; enumerating by seed and ignoring url",
				svc1log.SafeParam("url", *config.Url))
			seedErrors = append(seedErrors, fmt.Sprintf("both url and targetSeed were provided; enumerated by seed and ignored url %q", *config.Url))
		}
		report.Result = seedResult
		report.Errors = seedErrors
		return report
	}

	if config.Url == nil || *config.Url == "" {
		report.Result = &result
		report.Errors = []string{"either url or targetSeed must be provided"}
		return report
	}

	bucketURL := *config.Url
	log.Info("Starting external S3 enumeration", svc1log.SafeParam("bucketURL", bucketURL))

	// Parse the bucket URL to get name and potentially region
	bucketName, urlRegion := parseBucketURL(bucketURL)

	// If we got a region from the URL, only check that region
	// First try user input, then URL region, then all regions if no input or URL region
	var regionsToCheck []string
	if len(config.Regions) > 0 {
		regionsToCheck = config.Regions
	} else if urlRegion != "" {
		regionsToCheck = []string{urlRegion}
	} else {
		regionsToCheck = utils.GetGeneralRegionsList()
	}

	bucketFound := false
	for _, region := range regionsToCheck {
		exists, err := bucketExists(ctx, region, bucketName)
		if err != nil {
			log.Warn("Error checking bucket in region",
				svc1log.SafeParam("region", region),
				svc1log.SafeParam("bucketName", bucketName),
				svc1log.Stacktrace(err))
			errors = append(errors, fmt.Sprintf("Error checking bucket in region %s: %v", region, err))
			continue
		}
		if exists {
			log.Info("Found bucket in region",
				svc1log.SafeParam("bucketName", bucketName),
				svc1log.SafeParam("region", region))
			functionResult, functionErrors := externalS3Region(ctx, bucketURL, bucketName, region)
			if functionResult != nil {
				result = *functionResult
			}
			errors = append(errors, functionErrors...)
			bucketFound = true
			break
		}
	}

	if !bucketFound {
		log.Warn("Bucket not found in any specified regions",
			svc1log.SafeParam("bucketName", bucketName),
			svc1log.SafeParam("regionsChecked", len(regionsToCheck)))
		errors = append(errors, "Bucket not found in any of the specified regions")
	}

	report.Result = &result
	report.Errors = errors

	log.Info("External S3 enumeration completed",
		svc1log.SafeParam("bucketFound", bucketFound),
		svc1log.SafeParam("totalErrors", len(errors)))

	return report
}
