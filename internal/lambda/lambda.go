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
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func parseLambdaFunctionConfiguration(ctx context.Context, function types.FunctionConfiguration, region string) (*lambdafern.LambdaFunction, error) {
	log := svc1log.FromContext(ctx)
	log.Info("Parsing Lambda function configuration",
		svc1log.SafeParam("functionName", function.FunctionName),
		svc1log.SafeParam("region", region))

	if function.FunctionName == nil {
		return nil, errors.New("function name is nil")
	}
	if function.FunctionArn == nil {
		return nil, errors.New("function arn is nil")
	}
	if function.Role == nil {
		return nil, errors.New("function role is nil")
	}
	if function.RevisionId == nil {
		return nil, errors.New("function revision id is nil")
	}
	if function.LastModified == nil {
		return nil, errors.New("function LastModified is nil")
	}

	lastModified, err := time.Parse("2006-01-02T15:04:05.000-0700", *function.LastModified)
	if err != nil {
		return nil, err
	}

	lambdaArchitectures := []lambdafern.LambdaArchitecture{}
	for _, architecture := range function.Architectures {
		architecture, err := lambdafern.NewLambdaArchitectureFromString(strings.ToUpper(string(architecture)))
		if err != nil {
			return nil, err
		}
		lambdaArchitectures = append(lambdaArchitectures, architecture)
	}

	lambdaPackageType, err := lambdafern.NewLambdaPackageTypeFromString(strings.ToUpper(string(function.PackageType)))
	if err != nil {
		return nil, err
	}

	var vpcReference *common.VpcReference
	if function.VpcConfig != nil && function.VpcConfig.VpcId != nil {
		vpcReference = createVpcReference(*function.VpcConfig.VpcId, function.VpcConfig.SubnetIds, region)
	}

	var securityGroupIds []string
	if function.VpcConfig != nil {
		securityGroupIds = append(securityGroupIds, function.VpcConfig.SecurityGroupIds...)
	}

	var loggingConfig *lambdafern.LambdaLoggingConfig
	if function.LoggingConfig != nil {
		if function.LoggingConfig.LogGroup != nil {
			logFormat, err := lambdafern.NewLambdaLoggingFormatFromString(strings.ToUpper(string(function.LoggingConfig.LogFormat)))
			if err != nil {
				return nil, err
			}
			loggingConfig = &lambdafern.LambdaLoggingConfig{
				LogFormat: logFormat,
				LogGroup:  *function.LoggingConfig.LogGroup,
			}
		}
	}

	cloudWatchLogs, err := createCloudWatchLogReferences(
		loggingConfig,
		*function.FunctionName,
		*function.FunctionArn,
		region,
	)
	if err != nil {
		return nil, err
	}

	// Handler can be nil for container-image-based Lambda functions
	var handler string
	if function.Handler != nil {
		handler = *function.Handler
	}

	var timeoutInSeconds int
	if function.Timeout != nil {
		timeoutInSeconds = int(*function.Timeout)
	}

	var memorySizeInMb int
	if function.MemorySize != nil {
		memorySizeInMb = int(*function.MemorySize)
	}

	var ephemeralStorageInMb int
	if function.EphemeralStorage != nil && function.EphemeralStorage.Size != nil {
		ephemeralStorageInMb = int(*function.EphemeralStorage.Size)
	}

	var result = &lambdafern.LambdaFunction{
		Identification: &lambdafern.LambdaIdentificationInfo{
			Name:   *function.FunctionName,
			Arn:    *function.FunctionArn,
			Region: region,
		},
		Configuration: &lambdafern.LambdaConfigurationInfo{
			RevisionId:           *function.RevisionId,
			Runtime:              string(function.Runtime),
			Handler:              handler,
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
			IamRole:        createIamRoleReference(*function.Role, region),
			SecurityGroups: createSecurityGroupReferences(securityGroupIds, region),
			CloudWatchLogs: cloudWatchLogs,
		},
	}
	return result, nil
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
			// failed to page so just return an empty list and the error with region context
			wrappedErr := fmt.Errorf("region %s: %w", region, err)
			return []*lambdafern.LambdaFunction{}, append(errors, wrappedErr)
		}
		for _, function := range page.Functions {
			parsedFunction, err := parseLambdaFunctionConfiguration(ctx, function, region)
			if err != nil {
				wrappedErr := fmt.Errorf("region %s: %w", region, err)
				errors = append(errors, wrappedErr)
			} else {
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

	return &common.VpcReference{
		Id:        vpcID,
		Region:    region,
		SubnetIds: subnetIds,
	}
}

func createIamRoleReference(roleArn, region string) *common.IamRoleReference {
	if roleArn == "" {
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
	functionName string,
	functionARN string,
	region string,
) ([]*common.CloudWatchLogReference, error) {
	logGroupName := "/aws/lambda/" + functionName
	if loggingConfig != nil {
		logGroupName = loggingConfig.LogGroup
	}

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
