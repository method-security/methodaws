// Package enumerate provides the data structures and logic necessary to enumerate and integrate AWS S3 resources.
package enumerate

import (
	// Standard
	"context"
	"errors"
	"fmt"
	"strings"

	// Generated
	common "github.com/Method-Security/methodaws/generated/go/common"
	s3fern "github.com/Method-Security/methodaws/generated/go/s3"
	methodawsutils "github.com/Method-Security/methodaws/utils"

	// External
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3controltypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	"github.com/aws/smithy-go"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func bucketEncryption(ctx context.Context, s3Client *s3.Client, bucket *s3fern.S3Bucket) (*s3fern.S3Bucket, error) {
	log := svc1log.FromContext(ctx)

	input := &s3.GetBucketEncryptionInput{
		Bucket: aws.String(bucket.Identification.Name),
	}

	result, err := s3Client.GetBucketEncryption(ctx, input)

	if err != nil {
		log.Warn("Failed to get bucket encryption configuration",
			svc1log.SafeParam("bucketName", bucket.Identification.Name),
			svc1log.Stacktrace(err))
		return bucket, err
	}
	if result == nil {
		return bucket, fmt.Errorf("GetBucketEncryption returned no response for bucket %s", bucket.Identification.Name)
	}

	var conversionErrors []error
	if result.ServerSideEncryptionConfiguration != nil {
		encryptionRules := []*s3fern.EncryptionRule{}
		for _, rule := range result.ServerSideEncryptionConfiguration.Rules {
			if rule.ApplyServerSideEncryptionByDefault == nil {
				continue
			}
			encryptionRule := s3fern.EncryptionRule{}
			sseAlgorithm, err := s3fern.NewS3ServerSideEncryptionFromString(string(rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm))
			if err != nil {
				conversionErrors = append(conversionErrors, fmt.Errorf("bucket %s encryption: %w", bucket.Identification.Name, err))
			} else {
				encryptionRule.SseAlgorithm = &sseAlgorithm
			}
			if rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID != nil {
				encryptionRule.KmsKeyIdentifier = rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID
				encryptionRule.KmsKey = kmsKeyReference(*rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID)
			}
			encryptionRules = append(encryptionRules, &encryptionRule)
		}
		bucket.Configuration.EncryptionRules = encryptionRules
	}
	return bucket, errors.Join(conversionErrors...)
}

func kmsKeyReference(value string) *common.KmsKeyReference {
	keyARN, err := arn.Parse(value)
	if err != nil || keyARN.Partition == "" || keyARN.Service != "kms" || keyARN.Region == "" ||
		keyARN.AccountID == "" || !strings.HasPrefix(keyARN.Resource, "key/") {
		return nil
	}

	keyID := strings.TrimPrefix(keyARN.Resource, "key/")
	if keyID == "" {
		return nil
	}

	return &common.KmsKeyReference{
		Arn:    keyARN.String(),
		KeyId:  keyID,
		Region: keyARN.Region,
	}
}

func objectVersioning(ctx context.Context, s3Client *s3.Client, bucket *s3fern.S3Bucket) (*s3fern.S3Bucket, []string) {
	errors := []string{}
	input := &s3.GetBucketVersioningInput{
		Bucket: aws.String(bucket.Identification.Name),
	}

	result, err := s3Client.GetBucketVersioning(ctx, input)
	if err != nil {
		errors = append(errors, err.Error())
		return bucket, errors
	}
	if result == nil {
		return bucket, append(errors, fmt.Sprintf("GetBucketVersioning returned no response for bucket %s", bucket.Identification.Name))
	}

	if result.Status != "" {
		bucketVersioning, err := s3fern.NewBucketVersioningStatusFromString(strings.ToUpper(string(result.Status)))
		if err != nil {
			errors = append(errors, err.Error())
		} else {
			bucket.Configuration.BucketVersioning = &bucketVersioning
		}
	}

	if result.MFADelete != "" {
		mfaDelete, err := s3fern.NewS3MfaDeleteStatusFromString(strings.ToUpper(string(result.MFADelete)))
		if err != nil {
			errors = append(errors, err.Error())
		} else {
			bucket.Configuration.MfaDelete = &mfaDelete
		}
	}

	return bucket, errors
}

func bucketPermissions(
	ctx context.Context,
	s3Client *s3.Client,
	bucket *s3fern.S3Bucket,
	accountPublicAccessBlock publicAccessBlockState,
) (*s3fern.S3Bucket, error) {
	log := svc1log.FromContext(ctx)
	var permissionErrors []error

	// Get bucket policy
	var policyDocument *string
	policyKnown := false
	policyInput := s3.GetBucketPolicyInput{
		Bucket: aws.String(bucket.Identification.Name),
	}
	policyResult, policyErr := s3Client.GetBucketPolicy(ctx, &policyInput)
	if policyErr != nil {
		if isAWSAPIError(policyErr, "NoSuchBucketPolicy") {
			policyKnown = true
		} else {
			permissionErrors = append(permissionErrors, fmt.Errorf("get bucket policy: %w", policyErr))
			log.Debug("Failed to get bucket policy",
				svc1log.SafeParam("bucketName", bucket.Identification.Name))
		}
	} else if policyResult != nil {
		policyKnown = true
		bucket.Configuration.Policy = policyResult.Policy
		policyDocument = policyResult.Policy
	} else {
		permissionErrors = append(permissionErrors, fmt.Errorf("GetBucketPolicy returned no response"))
	}

	// Get bucket ACL
	var grants []types.Grant
	aclInput := &s3.GetBucketAclInput{
		Bucket: aws.String(bucket.Identification.Name),
	}
	aclResult, aclErr := s3Client.GetBucketAcl(ctx, aclInput)
	aclKnown := false
	if aclErr != nil {
		log.Warn("Failed to get bucket ACL",
			svc1log.SafeParam("bucketName", bucket.Identification.Name),
			svc1log.Stacktrace(aclErr))
		permissionErrors = append(permissionErrors, fmt.Errorf("get bucket ACL: %w", aclErr))
	} else if aclResult == nil {
		permissionErrors = append(permissionErrors, fmt.Errorf("GetBucketAcl returned no response for bucket %s", bucket.Identification.Name))
	} else {
		aclKnown = true
		grants = aclResult.Grants
	}

	// Get public access block configuration
	bucketPublicAccessBlock := publicAccessBlockState{}
	publicAccessInput := &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucket.Identification.Name),
	}
	publicAccessResult, publicAccessErr := s3Client.GetPublicAccessBlock(ctx, publicAccessInput)
	if publicAccessErr != nil {
		if isAWSAPIError(publicAccessErr, "NoSuchPublicAccessBlockConfiguration") {
			bucketPublicAccessBlock.known = true
		} else {
			permissionErrors = append(permissionErrors, fmt.Errorf("get bucket Public Access Block: %w", publicAccessErr))
			log.Debug("Failed to get bucket Public Access Block configuration",
				svc1log.SafeParam("bucketName", bucket.Identification.Name))
		}
	} else if publicAccessResult == nil || publicAccessResult.PublicAccessBlockConfiguration == nil {
		permissionErrors = append(permissionErrors, fmt.Errorf("GetPublicAccessBlock returned no bucket configuration"))
	} else {
		bucketPublicAccessBlock = publicAccessBlockState{
			configuration: publicAccessResult.PublicAccessBlockConfiguration,
			known:         true,
		}
	}

	accessControl, evaluationErr := evaluateS3Access(accessEvaluationInput{
		bucketARN:                bucket.Identification.Arn,
		grants:                   grants,
		aclKnown:                 aclKnown,
		policyDocument:           policyDocument,
		policyKnown:              policyKnown,
		bucketPublicAccessBlock:  bucketPublicAccessBlock,
		accountPublicAccessBlock: accountPublicAccessBlock,
	})
	if evaluationErr != nil {
		permissionErrors = append(permissionErrors, evaluationErr)
	}
	if accessControl != nil {
		bucket.Configuration.AccessControl = accessControl
	}

	return bucket, errors.Join(permissionErrors...)
}

func isAWSAPIError(err error, code string) bool {
	var apiError smithy.APIError
	return errors.As(err, &apiError) && apiError.ErrorCode() == code
}

func accountPublicAccessBlock(
	ctx context.Context,
	awsConfig aws.Config,
	accountID string,
) (publicAccessBlockState, error) {
	output, err := s3control.NewFromConfig(awsConfig).GetPublicAccessBlock(ctx, &s3control.GetPublicAccessBlockInput{
		AccountId: &accountID,
	})
	if err != nil {
		if isAWSAPIError(err, "NoSuchPublicAccessBlockConfiguration") {
			return publicAccessBlockState{known: true}, nil
		}
		return publicAccessBlockState{}, fmt.Errorf("get account Public Access Block: %w", err)
	}
	if output == nil || output.PublicAccessBlockConfiguration == nil {
		return publicAccessBlockState{}, fmt.Errorf("GetPublicAccessBlock returned no account configuration")
	}
	return publicAccessBlockState{
		configuration: convertAccountPublicAccessBlock(output.PublicAccessBlockConfiguration),
		known:         true,
	}, nil
}

func convertAccountPublicAccessBlock(
	configuration *s3controltypes.PublicAccessBlockConfiguration,
) *types.PublicAccessBlockConfiguration {
	if configuration == nil {
		return nil
	}
	return &types.PublicAccessBlockConfiguration{
		BlockPublicAcls:       configuration.BlockPublicAcls,
		IgnorePublicAcls:      configuration.IgnorePublicAcls,
		BlockPublicPolicy:     configuration.BlockPublicPolicy,
		RestrictPublicBuckets: configuration.RestrictPublicBuckets,
	}
}

// EnumerateS3 retrieves all S3 buckets available to the caller and returns an EnumerateResourceReport struct. Non-fatal
// errors that occur during the execution of the `methodaws s3 enumerate` subcommand are included in the report, but
// the function will not return an error unless there is an issue retrieving the account ID.

func EnumerateS3(ctx context.Context, awscfg aws.Config, config s3fern.S3EnumerateConfig) *s3fern.S3EnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting S3 enumeration", svc1log.SafeParam("regionsCount", len(config.Regions)))

	// Initialize report
	report := &s3fern.S3EnumerateReport{
		Config: &config,
		Result: &s3fern.S3EnumerateResult{},
	}
	if len(config.Regions) > 0 {
		regions, err := methodawsutils.NormalizeSelectedRegions(config.Regions)
		if err != nil {
			report.Errors = []string{err.Error()}
			return report
		}
		config.Regions = regions
	}
	errors := []string{}

	// Use a single region to list all buckets (buckets are globally shared)
	// S3 bucket location constraints explained:
	//
	// 1. Empty LocationConstraint:
	//    - Indicates the bucket is in the US East (N. Virginia) region (us-east-1).
	//    - Example: &{LocationConstraint: ResultMetadata:{...}}
	//    - This is due to historical reasons:
	//      a) When S3 was first launched, it was only available in us-east-1.
	//      b) To maintain backwards compatibility, buckets in this region have an empty location constraint.
	//
	// 2. Non-empty LocationConstraint:
	//    - Directly corresponds to the region code where the bucket is located.
	//    - Example: &{LocationConstraint:us-west-1 ResultMetadata:{...}}
	//
	// The region field in the final signal output will always explicitly state the correct region,
	// regardless of whether the LocationConstraint is empty or not.
	initialS3Config := awscfg.Copy()
	initialS3Config.Region = s3RequestRegion(initialS3Config.Region, config.Regions)
	if initialS3Config.Region == "" {
		report.Errors = []string{"list S3 buckets: AWS region is unavailable"}
		return report
	}
	client := s3.NewFromConfig(initialS3Config)

	log.Info("Listing S3 buckets", svc1log.SafeParam("accountId", aws.ToString(&config.AccountId)))
	listBucketsOutput, err := listBuckets(ctx, client)
	if err != nil {
		log.Error("Failed to list S3 buckets", svc1log.Stacktrace(err))
		errors = append(errors, err.Error())
	}
	if listBucketsOutput == nil {
		report.Errors = append(errors, "ListBuckets returned no response")
		return report
	}

	accountPABConfig := awscfg.Copy()
	accountPABConfig.Region = s3RequestRegion(accountPABConfig.Region, config.Regions)
	accountPAB := publicAccessBlockState{}
	if accountPABConfig.Region == "" {
		errors = append(errors, "get account Public Access Block: AWS region is unavailable")
	} else {
		var accountPABErr error
		accountPAB, accountPABErr = accountPublicAccessBlock(ctx, accountPABConfig, config.AccountId)
		if accountPABErr != nil {
			errors = append(errors, accountPABErr.Error())
		}
	}

	// Create a map of buckets by region for efficient processing
	bucketsByRegion := make(map[string][]s3fern.S3Bucket)
	errorMessages := []string{}

	// First pass: get all bucket regions and group them
	for _, bucket := range listBucketsOutput.Buckets {
		if bucket.Name == nil || *bucket.Name == "" {
			errorMessages = append(errorMessages, "S3 bucket name is missing")
			continue
		}
		var ownerID *string
		var ownerName *string
		if listBucketsOutput.Owner != nil {
			ownerID = listBucketsOutput.Owner.ID
			ownerName = listBucketsOutput.Owner.DisplayName
		}
		s3Bucket := s3fern.S3Bucket{
			Identification: &s3fern.S3BucketIdentificationInfo{
				Name: aws.ToString(bucket.Name),
				// Arn, Url, and Region will be set later
			},
			Configuration: &s3fern.S3BucketConfigurationInfo{
				CreationDate: bucket.CreationDate,
				OwnerId:      ownerID,
				OwnerName:    ownerName,
			},
		}

		region := aws.ToString(bucket.BucketRegion)
		if region == "" {
			regionOutput, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: bucket.Name})
			if err != nil {
				errorMessages = append(errorMessages, fmt.Sprintf("Error getting location for bucket %s: %v", *bucket.Name, err))
				continue
			}
			if regionOutput == nil {
				errorMessages = append(errorMessages, fmt.Sprintf("GetBucketLocation returned no response for bucket %s", *bucket.Name))
				continue
			}
			region = normalizeBucketRegion(regionOutput.LocationConstraint)
		}

		s3Bucket.Identification.Region = region
		bucketARN, err := methodawsutils.BuildGlobalARNForRegion(region, "s3", "", s3Bucket.Identification.Name)
		if err != nil {
			errorMessages = append(errorMessages, err.Error())
			continue
		}
		s3Bucket.Identification.Arn = bucketARN
		dnsSuffix, err := methodawsutils.AWSDNSSuffixForRegion(region)
		if err != nil {
			errorMessages = append(errorMessages, err.Error())
			continue
		}
		s3Bucket.Identification.Url = fmt.Sprintf(
			"https://%s.s3.%s.%s",
			s3Bucket.Identification.Name,
			s3Bucket.Identification.Region,
			dnsSuffix,
		)
		if strings.ContainsAny(*bucket.Name, "._") || *bucket.Name != strings.ToLower(*bucket.Name) {
			s3Bucket.Identification.Url = fmt.Sprintf("https://s3.%s.%s/%s", region, dnsSuffix, *bucket.Name)
		}

		// Group buckets by region
		bucketsByRegion[region] = append(bucketsByRegion[region], s3Bucket)
	}

	s3Buckets := []*s3fern.S3Bucket{}

	// Determine which regions to process
	regionsToProcess := config.Regions
	if len(config.Regions) == 0 {
		// If no regions specified, process all regions found
		regionsToProcess = make([]string, 0, len(bucketsByRegion))
		for region := range bucketsByRegion {
			regionsToProcess = append(regionsToProcess, region)
		}
	}

	// Process buckets for each region
	for _, region := range regionsToProcess {
		bucketsInRegion, exists := bucketsByRegion[region]
		if !exists {
			log.Info("No buckets found in region", svc1log.SafeParam("region", region))
			continue
		}

		log.Info("Processing S3 buckets in region",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("bucketCount", len(bucketsInRegion)))

		// Create a new AWS config for this region
		regionCfg := awscfg.Copy()
		regionCfg.Region = region
		regionClient := s3.NewFromConfig(regionCfg)

		// Process each bucket in this region
		for _, s3Bucket := range bucketsInRegion {
			bucketPtr := &s3Bucket

			// Fetch additional bucket details
			bucketPtr, errs := objectVersioning(ctx, regionClient, bucketPtr)
			if errs != nil {
				errorMessages = append(errorMessages, errs...)
			}

			bucketPtr, err = bucketEncryption(ctx, regionClient, bucketPtr)
			if err != nil {
				errorMessages = append(errorMessages, err.Error())
			}

			// Process bucket policy, ACL, and public access block together to avoid redundant permissions
			bucketPtr, err = bucketPermissions(ctx, regionClient, bucketPtr, accountPAB)
			if err != nil {
				errorMessages = append(errorMessages, err.Error())
			}
			bucketPtr.Resources, errs = configuredBucketResources(ctx, regionClient, bucketPtr)
			errorMessages = append(errorMessages, errs...)

			s3Buckets = append(s3Buckets, bucketPtr)
		}
	}
	if len(s3Buckets) > 0 {
		report.Result.S3Buckets = s3Buckets
	}
	report.Errors = append(errors, errorMessages...)
	return report
}

type listBucketsAPI interface {
	ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
}

func listBuckets(ctx context.Context, client listBucketsAPI) (*s3.ListBucketsOutput, error) {
	result := &s3.ListBucketsOutput{}
	input := &s3.ListBucketsInput{MaxBuckets: aws.Int32(1000)}
	seenTokens := make(map[string]struct{})

	for {
		page, err := client.ListBuckets(ctx, input)
		if err != nil {
			return result, err
		}
		if page == nil {
			return result, fmt.Errorf("ListBuckets returned no response")
		}
		result.Buckets = append(result.Buckets, page.Buckets...)
		if result.Owner == nil {
			result.Owner = page.Owner
		}
		if page.ContinuationToken == nil || *page.ContinuationToken == "" {
			return result, nil
		}
		if _, exists := seenTokens[*page.ContinuationToken]; exists {
			return result, fmt.Errorf("ListBuckets returned duplicate continuation token")
		}
		seenTokens[*page.ContinuationToken] = struct{}{}
		input.ContinuationToken = page.ContinuationToken
	}
}

func s3RequestRegion(configRegion string, regions []string) string {
	if len(regions) > 0 {
		return regions[0]
	}
	return configRegion
}

func normalizeBucketRegion(location types.BucketLocationConstraint) string {
	switch string(location) {
	case "":
		return "us-east-1"
	case "EU":
		return "eu-west-1"
	default:
		return string(location)
	}
}
