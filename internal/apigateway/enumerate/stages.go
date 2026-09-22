package apigateway

import (
	"fmt"
	"sort"
	"strings"

	apigatewayfern "github.com/Method-Security/methodaws/generated/go/apigateway"
	"github.com/Method-Security/methodaws/generated/go/common"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	v1types "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	v2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
)

func stageIdentification(apiARN, name string) (*apigatewayfern.StageIdentificationInfo, error) {
	parsed, err := arn.Parse(apiARN)
	if err != nil || parsed.Service != "apigateway" || parsed.AccountID != "" || parsed.Partition == "" || parsed.Region == "" {
		return nil, fmt.Errorf("Invalid parent API ARN %q", apiARN)
	}
	parts := strings.Split(parsed.Resource, "/")
	if len(parts) != 3 || parts[0] != "" || (parts[1] != "restapis" && parts[1] != "apis") || parts[2] == "" {
		return nil, fmt.Errorf("Invalid parent API resource in ARN %q", apiARN)
	}
	validName := name != "" && len(name) <= 128
	for _, char := range name {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-", char) {
			validName = false
			break
		}
	}
	if !validName && !(name == "$default" && parts[1] == "apis") {
		return nil, fmt.Errorf("Invalid or missing stage name %q for API %s", name, apiARN)
	}
	parsed.Resource += "/stages/" + name
	return &apigatewayfern.StageIdentificationInfo{Arn: parsed.String(), Name: name, Region: parsed.Region}, nil
}

func restAPIStages(apiARN string, stages []v1types.Stage) ([]*apigatewayfern.Stage, []string) {
	var result []*apigatewayfern.Stage
	var errors []string
	for _, stage := range stages {
		identification, err := stageIdentification(apiARN, aws.ToString(stage.StageName))
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}
		configuration := &apigatewayfern.StageConfigurationInfo{
			Description:         stage.Description,
			DeploymentId:        stage.DeploymentId,
			Variables:           stage.Variables,
			ClientCertificateId: stage.ClientCertificateId,
		}
		if stage.AccessLogSettings != nil {
			configuration.AccessLogSettings, err = stageAccessLogs(stage.AccessLogSettings.DestinationArn, stage.AccessLogSettings.Format)
			if err != nil {
				errors = append(errors, fmt.Sprintf("Stage %s: %s", identification.Arn, err))
			}
		}
		converted := &apigatewayfern.Stage{Identification: identification, Configuration: configuration}
		if aws.ToString(stage.WebAclArn) != "" {
			webACL, parseErr := arn.Parse(*stage.WebAclArn)
			parent, _ := arn.Parse(apiARN)
			parts := strings.Split(webACL.Resource, "/")
			validResource := webACL.Service == "wafv2" && len(parts) == 4 && parts[0] == "regional" &&
				parts[1] == "webacl" && strings.TrimSpace(parts[2]) != "" && strings.TrimSpace(parts[3]) != ""
			if webACL.Service == "waf-regional" {
				validResource = len(parts) == 2 && parts[0] == "webacl" && strings.TrimSpace(parts[1]) != ""
			}
			if parseErr != nil || !validResource || webACL.Region != parent.Region || webACL.Partition != parent.Partition ||
				strings.TrimSpace(webACL.AccountID) == "" {
				errors = append(errors, fmt.Sprintf("Stage %s: invalid Web ACL ARN %q", identification.Arn, *stage.WebAclArn))
			} else {
				converted.Resources = &apigatewayfern.StageResourceInfo{
					WebAcl: &common.WebAclReference{Arn: *stage.WebAclArn, Region: webACL.Region},
				}
			}
		}
		result = append(result, converted)
	}
	return sortedStages(result), errors
}

func httpAPIStages(apiARN string, stages []v2types.Stage) ([]*apigatewayfern.Stage, []string) {
	var result []*apigatewayfern.Stage
	var errors []string
	for _, stage := range stages {
		identification, err := stageIdentification(apiARN, aws.ToString(stage.StageName))
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}
		configuration := &apigatewayfern.StageConfigurationInfo{
			Description:  stage.Description,
			DeploymentId: stage.DeploymentId,
			Variables:    stage.StageVariables,
			AutoDeploy:   stage.AutoDeploy,
		}
		if stage.AccessLogSettings != nil {
			configuration.AccessLogSettings, err = stageAccessLogs(stage.AccessLogSettings.DestinationArn, stage.AccessLogSettings.Format)
			if err != nil {
				errors = append(errors, fmt.Sprintf("Stage %s: %s", identification.Arn, err))
			}
		}
		result = append(result, &apigatewayfern.Stage{Identification: identification, Configuration: configuration})
	}
	return sortedStages(result), errors
}

func stageAccessLogs(destination, format *string) (*apigatewayfern.AccessLogSettings, error) {
	if strings.TrimSpace(aws.ToString(destination)) == "" {
		return nil, fmt.Errorf("Access log settings are missing a destination ARN")
	}
	return &apigatewayfern.AccessLogSettings{DestinationArn: *destination, Format: format}, nil
}

func sortedStages(stages []*apigatewayfern.Stage) []*apigatewayfern.Stage {
	sort.Slice(stages, func(i, j int) bool { return stages[i].Identification.Arn < stages[j].Identification.Arn })
	result := stages[:0]
	for _, stage := range stages {
		if len(result) == 0 || result[len(result)-1].Identification.Arn != stage.Identification.Arn {
			result = append(result, stage)
		}
	}
	return result
}
