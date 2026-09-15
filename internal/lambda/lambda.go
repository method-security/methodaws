package lambda

import (
	//standard
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	// generated
	common "github.com/Method-Security/methodaws/generated/go/common"
	lambdafern "github.com/Method-Security/methodaws/generated/go/lambda"
	"github.com/Method-Security/methodaws/utils"

	// external
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func parseLambdaFunctionConfiguration(ctx context.Context, function types.FunctionConfiguration, region string) (*lambdafern.LambdaFunction, error) {
	log := svc1log.FromContext(ctx)
	log.Info("Parsing Lambda function configuration",
		svc1log.SafeParam("functionName", function.FunctionName),
		svc1log.SafeParam("region", region))

	if aws.ToString(function.FunctionName) == "" || aws.ToString(function.FunctionArn) == "" || region == "" {
		return nil, errors.New("function missing required name, ARN, or region")
	}
	functionARN, err := arn.Parse(*function.FunctionArn)
	if err != nil || functionARN.Partition == "" || functionARN.AccountID == "" || functionARN.Service != "lambda" ||
		functionARN.Region != region || !strings.HasPrefix(functionARN.Resource, "function:") ||
		strings.TrimPrefix(functionARN.Resource, "function:") == "" {
		return nil, fmt.Errorf("invalid function ARN %q for region %s", *function.FunctionArn, region)
	}
	var parseErrors []error

	var lastModified *time.Time
	if aws.ToString(function.LastModified) != "" {
		parsed, err := time.Parse("2006-01-02T15:04:05.999999999-0700", *function.LastModified)
		if err != nil {
			parsed, err = time.Parse(time.RFC3339Nano, *function.LastModified)
		}
		if err != nil {
			parseErrors = append(parseErrors, fmt.Errorf("invalid last modified timestamp: %w", err))
		} else {
			lastModified = &parsed
		}
	}

	var lambdaArchitectures []lambdafern.LambdaArchitecture
	for _, architecture := range function.Architectures {
		parsed, err := lambdafern.NewLambdaArchitectureFromString(strings.ToUpper(string(architecture)))
		if err != nil {
			parseErrors = append(parseErrors, fmt.Errorf("unsupported architecture %q: %w", architecture, err))
			continue
		}
		lambdaArchitectures = append(lambdaArchitectures, parsed)
	}

	var lambdaPackageType *lambdafern.LambdaPackageType
	if function.PackageType != "" {
		parsed, err := lambdafern.NewLambdaPackageTypeFromString(strings.ToUpper(string(function.PackageType)))
		if err != nil {
			parseErrors = append(parseErrors, fmt.Errorf("unsupported package type %q: %w", function.PackageType, err))
		} else {
			lambdaPackageType = &parsed
		}
	}

	var vpcReference *common.VpcReference
	var securityGroupIds []string
	if function.VpcConfig != nil {
		vpcReference = createVpcReference(aws.ToString(function.VpcConfig.VpcId), function.VpcConfig.SubnetIds, region)
		securityGroupIds = function.VpcConfig.SecurityGroupIds
		if vpcReference == nil && (len(function.VpcConfig.SubnetIds) > 0 || len(securityGroupIds) > 0) {
			parseErrors = append(parseErrors, errors.New("VPC configuration has subnet or security group entries but no VPC ID"))
		}
	}

	var loggingConfig *lambdafern.LambdaLoggingConfig
	if function.LoggingConfig != nil && aws.ToString(function.LoggingConfig.LogGroup) != "" {
		loggingConfig = &lambdafern.LambdaLoggingConfig{LogGroup: *function.LoggingConfig.LogGroup}
		if function.LoggingConfig.LogFormat != "" {
			parsed, err := lambdafern.NewLambdaLoggingFormatFromString(strings.ToUpper(string(function.LoggingConfig.LogFormat)))
			if err != nil {
				parseErrors = append(parseErrors, fmt.Errorf("unsupported log format %q: %w", function.LoggingConfig.LogFormat, err))
			} else {
				loggingConfig.LogFormat = &parsed
			}
		}
	}

	cloudWatchLogs, err := createCloudWatchLogReferences(loggingConfig, *function.FunctionArn, region)
	if err != nil {
		parseErrors = append(parseErrors, err)
	}

	roleReference := createIamRoleReference(aws.ToString(function.Role), region)
	if roleReference == nil {
		parseErrors = append(parseErrors, fmt.Errorf("missing or invalid execution role ARN %q", aws.ToString(function.Role)))
	}

	var runtime *string
	if function.Runtime != "" {
		runtime = aws.String(string(function.Runtime))
	}
	var timeoutInSeconds *int
	if function.Timeout != nil {
		timeoutInSeconds = aws.Int(int(*function.Timeout))
	}
	var memorySizeInMb *int
	if function.MemorySize != nil {
		memorySizeInMb = aws.Int(int(*function.MemorySize))
	}
	var ephemeralStorageInMb *int
	if function.EphemeralStorage != nil && function.EphemeralStorage.Size != nil {
		ephemeralStorageInMb = aws.Int(int(*function.EphemeralStorage.Size))
	}

	result := &lambdafern.LambdaFunction{
		Identification: &lambdafern.LambdaIdentificationInfo{
			Name:   *function.FunctionName,
			Arn:    *function.FunctionArn,
			Region: region,
		},
		Configuration: &lambdafern.LambdaConfigurationInfo{
			RevisionId:           function.RevisionId,
			Runtime:              runtime,
			Handler:              function.Handler,
			CodeSizeInBytes:      function.CodeSize,
			TimeoutInSeconds:     timeoutInSeconds,
			MemorySizeInMb:       memorySizeInMb,
			EphemeralStorageInMb: ephemeralStorageInMb,
			LastModified:         lastModified,
			PackageType:          lambdaPackageType,
			Description:          function.Description,
			CodeSha256:           function.CodeSha256,
			Architectures:        lambdaArchitectures,
			LoggingConfig:        loggingConfig,
		},
		Resources: &lambdafern.LambdaResourceInfo{
			Vpc:            vpcReference,
			IamRole:        roleReference,
			SecurityGroups: createSecurityGroupReferences(securityGroupIds, region),
			CloudWatchLogs: cloudWatchLogs,
		},
	}
	return result, errors.Join(parseErrors...)
}

func enumerateLambdaForRegion(ctx context.Context, awsConfig aws.Config, region string) ([]*lambdafern.LambdaFunction, []error) {
	log := svc1log.FromContext(ctx)
	log.Info("Enumerating Lambda functions for region", svc1log.SafeParam("region", region))

	awsConfig.Region = region
	lambdaClient := lambda.NewFromConfig(awsConfig)
	paginator := lambda.NewListFunctionsPaginator(lambdaClient, &lambda.ListFunctionsInput{
		MaxItems: aws.Int32(50),
	})

	var functions []*lambdafern.LambdaFunction
	var errors []error
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.Error("Failed to get next page of Lambda functions",
				svc1log.SafeParam("region", region),
				svc1log.Stacktrace(err))
			wrappedErr := fmt.Errorf("region %s: %w", region, err)
			return functions, append(errors, wrappedErr)
		}
		for _, function := range page.Functions {
			parsedFunction, err := parseLambdaFunctionConfiguration(ctx, function, region)
			if err != nil {
				wrappedErr := fmt.Errorf("function %s (%s) in region %s: %w",
					aws.ToString(function.FunctionName), aws.ToString(function.FunctionArn), region, err)
				errors = append(errors, wrappedErr)
			}
			if parsedFunction != nil {
				functions = append(functions, parsedFunction)
			}
		}
	}
	return functions, errors
}

func EnumerateLambda(ctx context.Context, awsConfig aws.Config, config lambdafern.LambdaEnumerateConfig) *lambdafern.LambdaEnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting Lambda enumeration",
		svc1log.SafeParam("regionsCount", len(config.Regions)),
		svc1log.SafeParam("accountId", config.AccountId))

	// Initialize report
	report := &lambdafern.LambdaEnumerateReport{
		Config: &config,
		Result: &lambdafern.LambdaEnumerateResult{},
	}

	var allFunctions []*lambdafern.LambdaFunction
	var allErrors []string

	for _, region := range config.Regions {
		log.Info("Processing Lambda functions in region", svc1log.SafeParam("region", region))
		functions, errs := enumerateLambdaForRegion(ctx, awsConfig, region)
		allFunctions = append(allFunctions, functions...)
		for _, err := range errs {
			allErrors = append(allErrors, err.Error())
		}
	}

	// Populate report
	if len(allFunctions) > 0 {
		report.Result.Functions = allFunctions
	}
	report.Errors = allErrors
	return report
}

// Resource reference helper functions with deduplication
func createVpcReference(vpcID string, subnetIds []string, region string) *common.VpcReference {
	if vpcID == "" {
		return nil
	}

	var validSubnetIDs []string
	for _, subnetID := range subnetIds {
		if subnetID != "" {
			validSubnetIDs = append(validSubnetIDs, subnetID)
		}
	}
	return &common.VpcReference{
		Id:        vpcID,
		Region:    region,
		SubnetIds: validSubnetIDs,
	}
}

func createIamRoleReference(roleArn, region string) *common.IamRoleReference {
	parsed, err := arn.Parse(roleArn)
	if err != nil || parsed.Partition == "" || parsed.AccountID == "" || parsed.Service != "iam" || parsed.Region != "" ||
		!strings.HasPrefix(parsed.Resource, "role/") || strings.HasSuffix(parsed.Resource, "/") {
		return nil
	}

	// Extract role name from ARN
	roleName := extractRoleNameFromArn(roleArn)
	var roleNamePtr *string
	if roleName != "" {
		roleNamePtr = &roleName
	}

	return &common.IamRoleReference{
		Arn:      roleArn,
		RoleName: roleNamePtr,
		Region:   region,
	}
}

func createSecurityGroupReferences(sgIDs []string, region string) []*common.SecurityGroupReference {
	sgMap := make(map[string]*common.SecurityGroupReference)

	for _, sgID := range sgIDs {
		if sgID != "" {
			key := sgID
			if _, exists := sgMap[key]; !exists {
				sgMap[key] = &common.SecurityGroupReference{
					Id:     sgID,
					Region: region,
				}
			}
		}
	}

	var securityGroups []*common.SecurityGroupReference
	for _, sg := range sgMap {
		securityGroups = append(securityGroups, sg)
	}
	return securityGroups
}

func createCloudWatchLogReferences(
	loggingConfig *lambdafern.LambdaLoggingConfig,
	functionARN string,
	region string,
) ([]*common.CloudWatchLogReference, error) {
	if loggingConfig == nil || loggingConfig.LogGroup == "" {
		return nil, nil
	}
	logGroupName := loggingConfig.LogGroup

	logGroupARN, err := utils.BuildRelatedARN(functionARN, "logs", region, "log-group:"+logGroupName)
	if err != nil {
		return nil, fmt.Errorf("build CloudWatch log group ARN: %w", err)
	}

	return []*common.CloudWatchLogReference{{
		Arn:          logGroupARN,
		LogGroupName: logGroupName,
		Region:       region,
	}}, nil
}

// Helper function to extract role name from ARN
func extractRoleNameFromArn(roleArn string) string {
	parts := strings.Split(roleArn, "/")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	return ""
}
