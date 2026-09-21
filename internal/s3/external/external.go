package s3

import (
	// Standard
	"context"
	"errors"
	"fmt"
	"net/http"
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
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

type headBucketAPI interface {
	HeadBucket(context.Context, *s3.HeadBucketInput, ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
}

func locateBucketWithClient(ctx context.Context, client headBucketAPI, probeRegion, bucketName string) (bool, string, error) {
	if strings.TrimSpace(bucketName) == "" {
		return false, "", fmt.Errorf("bucket name is required")
	}
	for _, suffix := range []string{"-s3alias", "--ol-s3", "--x-s3", ".mrap", "--table-s3"} {
		if strings.HasSuffix(bucketName, suffix) {
			return false, "", fmt.Errorf("%s is not a supported general-purpose bucket name", bucketName)
		}
	}
	output, err := client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(bucketName)})
	if err == nil {
		if output != nil && aws.ToBool(output.AccessPointAlias) {
			return false, "", fmt.Errorf("%s is an access point alias, not a bucket name", bucketName)
		}
		if output != nil && output.BucketRegion != nil && *output.BucketRegion != "" {
			return true, *output.BucketRegion, nil
		}
		return false, "", fmt.Errorf("head bucket %s in %s returned no bucket region", bucketName, probeRegion)
	}

	var responseError *smithyhttp.ResponseError
	if errors.As(err, &responseError) {
		statusCode := responseError.HTTPStatusCode()
		if statusCode == http.StatusNotFound {
			return false, "", nil
		}
		bucketRegion := responseError.HTTPResponse().Header.Get("X-Amz-Bucket-Region")
		if strings.EqualFold(responseError.HTTPResponse().Header.Get("X-Amz-Access-Point-Alias"), "true") {
			return false, "", fmt.Errorf("%s is an access point alias, not a bucket name", bucketName)
		}
		if bucketRegion != "" && (statusCode == http.StatusMovedPermanently || statusCode == http.StatusTemporaryRedirect ||
			statusCode == http.StatusBadRequest || statusCode == http.StatusForbidden) {
			return true, bucketRegion, nil
		}
	}

	return false, "", fmt.Errorf("head bucket %s: %w", bucketName, err)
}

// locateBucket checks whether a bucket exists and returns the region reported by S3.
func locateBucket(ctx context.Context, probeRegion string, bucketName string) (bool, string, error) {
	log := svc1log.FromContext(ctx)

	// Create a custom AWS config with anonymous credentials
	loadOptions, err := methodconfig.AWSLoadOptionsFromContext(ctx)
	if err != nil {
		log.Error("Failed to configure proxy for bucket existence check",
			svc1log.SafeParam("bucketName", bucketName),
			svc1log.SafeParam("region", probeRegion),
			svc1log.Stacktrace(err))
		return false, "", fmt.Errorf("error configuring proxy: %v", err)
	}
	loadOptions = append([]methodconfig.AWSLoadOption{
		awsconfig.WithRegion(probeRegion),
		awsconfig.WithCredentialsProvider(aws.AnonymousCredentials{}),
	}, loadOptions...)
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		loadOptions...,
	)
	if err != nil {
		log.Error("Failed to load AWS config for bucket existence check",
			svc1log.SafeParam("bucketName", bucketName),
			svc1log.SafeParam("region", probeRegion),
			svc1log.Stacktrace(err))
		return false, "", fmt.Errorf("error loading AWS config: %v", err)
	}

	// Create an S3 client
	client := s3.NewFromConfig(cfg)

	return locateBucketWithClient(ctx, client, probeRegion, bucketName)
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
func checkListingAllowed(ctx context.Context, client *s3.Client, bucketName string) (*bool, error) {
	maxKeys := int32(1)
	_, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:     aws.String(bucketName),
		MaxKeys:    &maxKeys,
		FetchOwner: aws.Bool(true),
	})
	if err == nil {
		return aws.Bool(true), nil
	}
	if isAccessDenied(err) {
		return aws.Bool(false), nil
	}
	return nil, fmt.Errorf("anonymous listing probe for bucket %s: %w", bucketName, err)
}

// checkAnonymousReadAllowed checks if anonymous read is allowed on a bucket
func checkAnonymousReadAllowed(ctx context.Context, client *s3.Client, bucketName string, directoryContents []*s3fern.DirectoryContents) (*bool, error) {
	if len(directoryContents) == 0 {
		return nil, nil
	}
	object := directoryContents[0]
	input := &s3.GetObjectInput{Bucket: aws.String(bucketName), Key: aws.String(object.Key)}
	if object.Size == nil || *object.Size > 0 {
		input.Range = aws.String("bytes=0-0")
	}
	output, err := client.GetObject(ctx, input)
	if err != nil {
		if isAccessDenied(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("anonymous read probe for bucket %s key %q: %w", bucketName, object.Key, err)
	}
	if output == nil || output.Body == nil {
		return nil, fmt.Errorf("anonymous read probe for bucket %s key %q returned no body", bucketName, object.Key)
	}
	if err := output.Body.Close(); err != nil {
		return aws.Bool(true), fmt.Errorf("closing anonymous read probe for bucket %s key %q: %w", bucketName, object.Key, err)
	}
	return aws.Bool(true), nil
}

func isAccessDenied(err error) bool {
	var apiError smithy.APIError
	return errors.As(err, &apiError) && apiError.ErrorCode() == "AccessDenied"
}

// checkPolicy checks the bucket policy
func checkPolicy(ctx context.Context, client bucketEnrichmentAPI, bucketName string) (*string, error) {
	policyOutput, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		var apiError smithy.APIError
		if errors.As(err, &apiError) && apiError.ErrorCode() == "NoSuchBucketPolicy" {
			return nil, nil
		}
		return nil, fmt.Errorf("get bucket policy for %s: %w", bucketName, err)
	}
	if policyOutput == nil || policyOutput.Policy == nil || strings.TrimSpace(*policyOutput.Policy) == "" {
		return nil, fmt.Errorf("GetBucketPolicy returned no policy for bucket %s", bucketName)
	}
	return policyOutput.Policy, nil
}

type bucketEnrichmentAPI interface {
	GetBucketPolicy(context.Context, *s3.GetBucketPolicyInput, ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
	GetBucketAcl(context.Context, *s3.GetBucketAclInput, ...func(*s3.Options)) (*s3.GetBucketAclOutput, error)
}

// checkACL checks the bucket ACL
func checkACL(ctx context.Context, client bucketEnrichmentAPI, bucketName string) ([]*s3fern.S3BucketAccessControl, *string, *string, error) {
	output, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		return nil, nil, nil, err
	}
	if output == nil {
		return nil, nil, nil, fmt.Errorf("GetBucketAcl returned no response for bucket %s", bucketName)
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
				publicACL.AllowPublicList = aws.Bool(true)
			case "WRITE":
				publicACL.AllowPublicWrite = aws.Bool(true)
			case "READ_ACP":
				publicACL.AllowPublicReadAcp = aws.Bool(true)
			case "WRITE_ACP":
				publicACL.AllowPublicWriteAcp = aws.Bool(true)
			case "FULL_CONTROL":
				publicACL.AllowPublicList = aws.Bool(true)
				publicACL.AllowPublicWrite = aws.Bool(true)
				publicACL.AllowPublicReadAcp = aws.Bool(true)
				publicACL.AllowPublicWriteAcp = aws.Bool(true)
				publicACL.AllowPublicFullControl = aws.Bool(true)
			}
		}

		// Authenticated users permissions
		if granteeURI == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" {
			hasAuthUser = true
			switch permission {
			case "READ":
				authUserACL.AllowAuthenticatedUsersList = aws.Bool(true)
			case "WRITE":
				authUserACL.AllowAuthenticatedUsersWrite = aws.Bool(true)
			case "READ_ACP":
				authUserACL.AllowAuthenticatedUsersReadAcp = aws.Bool(true)
			case "WRITE_ACP":
				authUserACL.AllowAuthenticatedUsersWriteAcp = aws.Bool(true)
			case "FULL_CONTROL":
				authUserACL.AllowAuthenticatedUsersList = aws.Bool(true)
				authUserACL.AllowAuthenticatedUsersWrite = aws.Bool(true)
				authUserACL.AllowAuthenticatedUsersReadAcp = aws.Bool(true)
				authUserACL.AllowAuthenticatedUsersWriteAcp = aws.Bool(true)
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
			case "FULL_CONTROL":
				logDeliveryACL.AllowLogDeliveryWrite = aws.Bool(true)
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
func externalS3Region(ctx context.Context, bucketName string, region string) (*s3fern.ExternalS3BucketResult, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting external S3 bucket enumeration",
		svc1log.SafeParam("bucketName", bucketName),
		svc1log.SafeParam("region", region))

	// Initialize variables
	report := s3fern.ExternalS3BucketResult{}

	// Construct ARN for the bucket
	bucketARN, err := utils.BuildGlobalARNForRegion(region, "s3", "", bucketName)
	if err != nil {
		return nil, []string{err.Error()}
	}
	dnsSuffix, err := utils.AWSDNSSuffixForRegion(region)
	if err != nil {
		return nil, []string{err.Error()}
	}
	bucketURL := fmt.Sprintf("https://%s.s3.%s.%s", bucketName, region, dnsSuffix)
	if strings.ContainsAny(bucketName, "._") || bucketName != strings.ToLower(bucketName) {
		bucketURL = fmt.Sprintf("https://s3.%s.%s/%s", region, dnsSuffix, bucketName)
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
	externalBucket.Configuration.AllowDirectoryListing, err = checkListingAllowed(ctx, client, bucketName)
	if err != nil {
		errors = append(errors, err.Error())
	}
	if aws.ToBool(externalBucket.Configuration.AllowDirectoryListing) {
		directoryContents, err := listBucketContents(ctx, client, bucketName)
		if err != nil {
			errors = append(errors, fmt.Sprintf("error listing bucket contents: %v", err))
		} else {
			externalBucket.Resources.DirectoryContents = directoryContents
			// Check anonymous read access if we found any objects
			externalBucket.Configuration.AllowAnonymousRead, err = checkAnonymousReadAllowed(ctx, client, bucketName, directoryContents)
			if err != nil {
				errors = append(errors, err.Error())
			}
		}
	}

	// Check bucket policy
	policy, err := checkPolicy(ctx, client, bucketName)
	if err == nil {
		externalBucket.Configuration.Policy = policy
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

	// Prefer explicit input and URL-derived regions. Otherwise, S3 reports the
	// authoritative bucket region from a single request to its standard endpoint.
	var regionsToCheck []string
	if len(config.Regions) > 0 {
		regionsToCheck = config.Regions
	} else if urlRegion != "" {
		regionsToCheck = []string{urlRegion}
	} else {
		regionsToCheck = []string{"us-east-1"}
	}

	bucketFound := false
	for _, region := range regionsToCheck {
		exists, bucketRegion, err := locateBucket(ctx, region, bucketName)
		if err != nil {
			log.Warn("Error checking bucket in region",
				svc1log.SafeParam("region", region),
				svc1log.SafeParam("bucketName", bucketName),
				svc1log.Stacktrace(err))
			errors = append(errors, fmt.Sprintf("Error checking bucket in region %s: %v", region, err))
			continue
		}
		if exists {
			if len(config.Regions) > 0 && !containsString(config.Regions, bucketRegion) {
				continue
			}
			log.Info("Found bucket in region",
				svc1log.SafeParam("bucketName", bucketName),
				svc1log.SafeParam("region", bucketRegion))
			functionResult, functionErrors := externalS3Region(ctx, bucketName, bucketRegion)
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
		errors = append(errors, "Could not confirm a supported bucket in the requested regions")
	}

	report.Result = &result
	report.Errors = errors

	log.Info("External S3 enumeration completed",
		svc1log.SafeParam("bucketFound", bucketFound),
		svc1log.SafeParam("totalErrors", len(errors)))

	return report
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
