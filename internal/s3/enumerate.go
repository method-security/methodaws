// Package s3 provides the data structures and logic necessary to enumerate and integrate AWS S3 resources.
package s3

import (
	// Standard
	"context"
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

func bucketPermissions(ctx context.Context, s3Client *s3.Client, bucket *s3fern.S3Bucket) (*s3fern.S3Bucket, error) {
	log := svc1log.FromContext(ctx)

	// Get bucket policy
	var policyDocument *string
	policyInput := s3.GetBucketPolicyInput{
		Bucket: aws.String(bucket.Identification.Name),
	}
	policyResult, policyErr := s3Client.GetBucketPolicy(ctx, &policyInput)
	if policyErr != nil {
		log.Debug("Failed to get bucket policy (may not exist)",
			svc1log.SafeParam("bucketName", bucket.Identification.Name))
		// Policy may not exist, continue without it
	} else if policyResult != nil {
		bucket.Configuration.Policy = policyResult.Policy
		policyDocument = policyResult.Policy
	}

	// Get bucket ACL
	var grants []types.Grant
	aclInput := &s3.GetBucketAclInput{
		Bucket: aws.String(bucket.Identification.Name),
	}
	aclResult, aclErr := s3Client.GetBucketAcl(ctx, aclInput)
	if aclErr != nil {
		log.Warn("Failed to get bucket ACL",
			svc1log.SafeParam("bucketName", bucket.Identification.Name),
			svc1log.Stacktrace(aclErr))
		return bucket, aclErr
	}
	if aclResult == nil {
		return bucket, fmt.Errorf("GetBucketAcl returned no response for bucket %s", bucket.Identification.Name)
	}
	grants = aclResult.Grants

	// Get public access block configuration
	var publicAccessBlock *types.PublicAccessBlockConfiguration
	publicAccessInput := &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucket.Identification.Name),
	}
	publicAccessResult, publicAccessErr := s3Client.GetPublicAccessBlock(ctx, publicAccessInput)
	if publicAccessErr != nil {
		log.Debug("Failed to get public access block configuration (may not exist)",
			svc1log.SafeParam("bucketName", bucket.Identification.Name))
		// Public access block may not exist, continue without it
	} else if publicAccessResult != nil {
		publicAccessBlock = publicAccessResult.PublicAccessBlockConfiguration
	}

	// Process ACL grants, policy, and public access block together
	accessControl := processS3Permissions(grants, policyDocument, publicAccessBlock)
	if accessControl != nil {
		bucket.Configuration.AccessControl = accessControl
	}

	return bucket, nil
}

// processS3Permissions analyzes ACL grants, bucket policy, and public access block to create comprehensive access control
func processS3Permissions(grants []types.Grant, policyDocument *string, publicAccessBlock *types.PublicAccessBlockConfiguration) *s3fern.S3BucketAccessControl {
	accessControl := &s3fern.S3BucketAccessControl{}
	hasPermissions := false

	// First, process ACL grants
	if len(grants) > 0 {
		for _, grant := range grants {
			if grant.Grantee == nil || grant.Grantee.URI == nil {
				continue
			}

			granteeURI := *grant.Grantee.URI
			permission := string(grant.Permission)

			// Public Access permissions (AllUsers)
			if granteeURI == "http://acs.amazonaws.com/groups/global/AllUsers" {
				hasPermissions = true
				switch permission {
				case "READ":
					accessControl.AllowPublicRead = aws.Bool(true)
				case "WRITE":
					accessControl.AllowPublicWrite = aws.Bool(true)
				case "READ_ACP":
					accessControl.AllowPublicReadAcp = aws.Bool(true)
				case "WRITE_ACP":
					accessControl.AllowPublicWriteAcp = aws.Bool(true)
				case "FULL_CONTROL":
					accessControl.AllowPublicFullControl = aws.Bool(true)
				}
			}

			// Authenticated users permissions
			if granteeURI == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" {
				hasPermissions = true
				switch permission {
				case "READ":
					accessControl.AllowAuthenticatedUsersRead = aws.Bool(true)
				case "WRITE":
					accessControl.AllowAuthenticatedUsersWrite = aws.Bool(true)
				case "READ_ACP":
					accessControl.AllowAuthenticatedUsersReadAcp = aws.Bool(true)
				case "WRITE_ACP":
					accessControl.AllowAuthenticatedUsersWriteAcp = aws.Bool(true)
				case "FULL_CONTROL":
					accessControl.AllowAuthenticatedUsersFullControl = aws.Bool(true)
				}
			}

			// Log delivery permissions
			if granteeURI == "http://acs.amazonaws.com/groups/s3/LogDelivery" {
				hasPermissions = true
				switch permission {
				case "WRITE":
					accessControl.AllowLogDeliveryWrite = aws.Bool(true)
				case "READ_ACP":
					accessControl.AllowLogDeliveryReadAcp = aws.Bool(true)
				}
			}
		}
	}

	// Second, analyze bucket policy for additional permissions
	if policyDocument != nil && *policyDocument != "" {
		policyPermissions := analyzeBucketPolicy(*policyDocument)

		// Merge policy-derived permissions with ACL permissions
		if policyPermissions.AllowPublicRead && (accessControl.AllowPublicRead == nil || !*accessControl.AllowPublicRead) {
			accessControl.AllowPublicRead = aws.Bool(true)
			hasPermissions = true
		}
		if policyPermissions.AllowPublicWrite && (accessControl.AllowPublicWrite == nil || !*accessControl.AllowPublicWrite) {
			accessControl.AllowPublicWrite = aws.Bool(true)
			hasPermissions = true
		}
		if policyPermissions.AllowAuthenticatedUsersRead && (accessControl.AllowAuthenticatedUsersRead == nil || !*accessControl.AllowAuthenticatedUsersRead) {
			accessControl.AllowAuthenticatedUsersRead = aws.Bool(true)
			hasPermissions = true
		}
		if policyPermissions.AllowAuthenticatedUsersWrite && (accessControl.AllowAuthenticatedUsersWrite == nil || !*accessControl.AllowAuthenticatedUsersWrite) {
			accessControl.AllowAuthenticatedUsersWrite = aws.Bool(true)
			hasPermissions = true
		}
	}

	// Third, add public access block configuration
	if publicAccessBlock != nil {
		accessControl.BlockPublicAcls = publicAccessBlock.BlockPublicAcls
		accessControl.IgnorePublicAcls = publicAccessBlock.IgnorePublicAcls
		accessControl.BlockPublicPolicy = publicAccessBlock.BlockPublicPolicy
		accessControl.RestrictPublicBuckets = publicAccessBlock.RestrictPublicBuckets
		hasPermissions = true // Public access block config is always relevant
	}

	if !hasPermissions {
		return nil
	}

	return accessControl
}

// PolicyPermissions represents permissions derived from bucket policy analysis
type PolicyPermissions struct {
	AllowPublicRead              bool
	AllowPublicWrite             bool
	AllowAuthenticatedUsersRead  bool
	AllowAuthenticatedUsersWrite bool
}

// analyzeBucketPolicy analyzes a bucket policy JSON and extracts permission flags
func analyzeBucketPolicy(policyJSON string) PolicyPermissions {
	permissions := PolicyPermissions{}

	// Simple pattern matching for common policy patterns
	// This could be enhanced with full JSON parsing for more complex scenarios

	// Check for public read access: "Principal":"*" with "s3:GetObject"
	if strings.Contains(policyJSON, `"Principal":"*"`) || strings.Contains(policyJSON, `"Principal": "*"`) {
		if strings.Contains(policyJSON, `"s3:GetObject"`) {
			permissions.AllowPublicRead = true
		}
		if strings.Contains(policyJSON, `"s3:PutObject"`) || strings.Contains(policyJSON, `"s3:DeleteObject"`) {
			permissions.AllowPublicWrite = true
		}
	}

	// Check for authenticated users: AWS account principals
	if strings.Contains(policyJSON, `"AWS"`) {
		if strings.Contains(policyJSON, `"s3:GetObject"`) {
			permissions.AllowAuthenticatedUsersRead = true
		}
		if strings.Contains(policyJSON, `"s3:PutObject"`) || strings.Contains(policyJSON, `"s3:DeleteObject"`) {
			permissions.AllowAuthenticatedUsersWrite = true
		}
	}

	return permissions
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

	// Create a map of buckets by region for efficient processing
	bucketsByRegion := make(map[string][]s3fern.S3Bucket)
	errorMessages := []string{}

	// First pass: get all bucket regions and group them
	for _, bucket := range listBucketsOutput.Buckets {
		if bucket.Name == nil || *bucket.Name == "" {
			errorMessages = append(errorMessages, "S3 bucket name is missing")
			continue
		}
		ownerID := ""
		ownerName := ""
		if listBucketsOutput.Owner != nil {
			ownerID = aws.ToString(listBucketsOutput.Owner.ID)
			ownerName = aws.ToString(listBucketsOutput.Owner.DisplayName)
		}
		s3Bucket := s3fern.S3Bucket{
			Identification: &s3fern.S3BucketIdentificationInfo{
				Name: aws.ToString(bucket.Name),
				// Arn, Url, and Region will be set later
			},
			Configuration: &s3fern.S3BucketConfigurationInfo{
				CreationDate: aws.ToTime(bucket.CreationDate),
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
			bucketPtr, err = bucketPermissions(ctx, regionClient, bucketPtr)
			if err != nil {
				errorMessages = append(errorMessages, err.Error())
			}

			bucketPtr.Identification.Url = fmt.Sprintf("https://%s.s3.%s.amazonaws.com", bucketPtr.Identification.Name, bucketPtr.Identification.Region)

			bucketARN, err := methodawsutils.BuildGlobalARNForRegion(region, "s3", "", bucketPtr.Identification.Name)
			if err != nil {
				errorMessages = append(errorMessages, err.Error())
				continue
			}
			bucketPtr.Identification.Arn = bucketARN

			// Add resource discovery
			bucketPtr.Resources = discoverS3Resources(bucketPtr)

			s3Buckets = append(s3Buckets, bucketPtr)
		}
	}
	if len(s3Buckets) > 0 {
		report.Result.S3Buckets = s3Buckets
	}
	report.Errors = errorMessages
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
