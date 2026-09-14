// Package s3 provides the data structures and logic necessary to enumerate and integrate AWS S3 resources.
package s3

import (
	// Standard
	"context"
	"errors"
	"fmt"
	"regexp"
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

	if result.ServerSideEncryptionConfiguration != nil {
		encryptionRules := []*s3fern.EncryptionRule{}
		for _, rule := range result.ServerSideEncryptionConfiguration.Rules {
			if rule.ApplyServerSideEncryptionByDefault == nil {
				continue
			}
			encryptionRule := s3fern.EncryptionRule{}
			sseAlgorithm, _ := s3fern.NewS3ServerSideEncryptionFromString(string(rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm))
			encryptionRule.SseAlgorithm = &sseAlgorithm
			if rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID != nil {
				encryptionRule.KmsKey = kmsKeyReference(*rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID)
			}
			encryptionRules = append(encryptionRules, &encryptionRule)
		}
		bucket.Configuration.EncryptionRules = encryptionRules
	}
	return bucket, nil
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
	client := s3.NewFromConfig(awscfg)

	log.Info("Listing S3 buckets", svc1log.SafeParam("accountId", aws.ToString(&config.AccountId)))
	listBucketsOutput, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		log.Error("Failed to list S3 buckets", svc1log.Stacktrace(err))
		errors = append(errors, err.Error())
		report.Errors = errors
		return report
	}
	if listBucketsOutput == nil {
		report.Errors = []string{"ListBuckets returned no response"}
		return report
	}

	accountPABConfig := awscfg.Copy()
	if accountPABConfig.Region == "" {
		if len(config.Regions) > 0 {
			accountPABConfig.Region = config.Regions[0]
		} else {
			accountPABConfig.Region = "us-east-1"
		}
	}
	accountPAB, accountPABErr := accountPublicAccessBlock(ctx, accountPABConfig, config.AccountId)
	if accountPABErr != nil {
		errors = append(errors, accountPABErr.Error())
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

		// Get the bucket's region
		regionOutput, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: bucket.Name})
		if err != nil {
			log.Warn("Failed to get bucket region",
				svc1log.SafeParam("bucketName", *bucket.Name),
				svc1log.Stacktrace(err))
			errorMessages = append(errorMessages, fmt.Sprintf("Error getting location for bucket %s: %v", *bucket.Name, err))
			continue
		}
		if regionOutput == nil {
			errorMessages = append(errorMessages, fmt.Sprintf("GetBucketLocation returned no response for bucket %s", *bucket.Name))
			continue
		}

		region := normalizeBucketRegion(regionOutput.LocationConstraint)
		s3Bucket.Identification.Region = region
		bucketARN, err := methodawsutils.BuildGlobalARNForRegion(region, "s3", "", s3Bucket.Identification.Name)
		if err != nil {
			errorMessages = append(errorMessages, err.Error())
			continue
		}
		s3Bucket.Identification.Arn = bucketARN
		s3Bucket.Identification.Url = fmt.Sprintf(
			"https://%s.s3.%s.amazonaws.com",
			s3Bucket.Identification.Name,
			s3Bucket.Identification.Region,
		)

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

			// Add resource discovery
			bucketPtr.Resources = discoverS3Resources(bucketPtr)

			s3Buckets = append(s3Buckets, bucketPtr)
		}
	}
	if len(s3Buckets) > 0 {
		report.Result.S3Buckets = s3Buckets
	}
	report.Errors = append(errors, errorMessages...)
	return report
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

// Resource discovery functions with deduplication
func discoverS3Resources(bucket *s3fern.S3Bucket) *s3fern.S3BucketResourceInfo {
	resources := &s3fern.S3BucketResourceInfo{}

	// KMS keys are now handled directly in EncryptionRules via KmsKey references

	// Discover IAM roles and Lambda functions from bucket policy
	if bucket.Configuration.Policy != nil {
		if iamRoles := discoverIamRolesFromPolicy(*bucket.Configuration.Policy, bucket.Identification.Region); len(iamRoles) > 0 {
			resources.IamRoles = iamRoles
		}
		if lambdaFunctions := discoverLambdaFromPolicy(*bucket.Configuration.Policy, bucket.Identification.Region); len(lambdaFunctions) > 0 {
			resources.LambdaFunctions = lambdaFunctions
		}
	}

	// Return nil if no resources were discovered
	if resources.IamRoles == nil && resources.LambdaFunctions == nil {
		return nil
	}

	return resources
}

func discoverIamRolesFromPolicy(policyDocument, region string) []*common.IamRoleReference {
	iamMap := make(map[string]*common.IamRoleReference)

	// Regex to match IAM role ARNs in policy documents
	iamRoleArnRegex := regexp.MustCompile(`arn:aws[a-z-]*:iam::([^:]+):role/([^\"'\\s]+)`)

	matches := iamRoleArnRegex.FindAllStringSubmatch(policyDocument, -1)
	for _, match := range matches {
		if len(match) > 2 {
			arn := match[0]
			roleName := match[2]

			key := arn
			if _, exists := iamMap[key]; !exists {
				iamMap[key] = &common.IamRoleReference{
					Arn:      arn,
					RoleName: &roleName,
					Region:   region, // IAM is global but we store the bucket's region for context
				}
			}
		}
	}

	var iamRoles []*common.IamRoleReference
	for _, role := range iamMap {
		iamRoles = append(iamRoles, role)
	}
	return iamRoles
}

func discoverLambdaFromPolicy(policyDocument, region string) []*common.LambdaReference {
	lambdaMap := make(map[string]*common.LambdaReference)

	// Regex to match Lambda function ARNs in policy documents
	lambdaArnRegex := regexp.MustCompile(`arn:aws[a-z-]*:lambda:([^:]+):([^:]+):function:([^\"'\\s]+)`)

	matches := lambdaArnRegex.FindAllStringSubmatch(policyDocument, -1)
	for _, match := range matches {
		if len(match) > 3 {
			arn := match[0]
			functionRegion := match[1]
			functionName := match[3]

			key := arn
			if _, exists := lambdaMap[key]; !exists {
				lambdaMap[key] = &common.LambdaReference{
					Arn:          arn,
					FunctionName: &functionName,
					Region:       functionRegion,
				}
			}
		}
	}

	var lambdaFunctions []*common.LambdaReference
	for _, lambda := range lambdaMap {
		lambdaFunctions = append(lambdaFunctions, lambda)
	}
	return lambdaFunctions
}
