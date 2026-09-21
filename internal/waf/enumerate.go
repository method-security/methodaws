// Package waf provides functionality to enumerate and integrate AWS WAF resources.
package waf

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	common "github.com/Method-Security/methodaws/generated/go/common"
	waffern "github.com/Method-Security/methodaws/generated/go/waf"
	methodawsutils "github.com/Method-Security/methodaws/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// EnumerateWAF enumerates WAFs based on the provided configuration
func EnumerateWAF(ctx context.Context, awsConfig aws.Config, config waffern.WafEnumerateConfig) *waffern.WafEnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting WAF enumeration",
		svc1log.SafeParam("regionsCount", len(config.Regions)),
		svc1log.SafeParam("accountId", config.AccountId))

	// Initialize report
	report := &waffern.WafEnumerateReport{
		Config: &config,
		Result: &waffern.WafEnumerateResult{},
	}

	var allErrors []string
	var allWafs []*waffern.WafInstance
	for _, region := range config.Regions {
		log.Info("Processing WAF instances in region", svc1log.SafeParam("region", region))
		wafs, errors := enumerateWAFForRegion(ctx, awsConfig, region)

		if len(errors) > 0 {
			log.Warn("Errors occurred while enumerating WAF instances in region",
				svc1log.SafeParam("region", region),
				svc1log.SafeParam("errorCount", len(errors)))
		}

		allErrors = append(allErrors, errors...)
		allWafs = append(allWafs, wafs...)

		log.Info("Successfully processed WAF instances in region",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("wafCount", len(wafs)))
	}

	if cloudFrontRegion, ok := cloudFrontWAFRegion(awsConfig.Region, config.Regions); ok {
		cloudFrontConfig := awsConfig.Copy()
		cloudFrontConfig.Region = cloudFrontRegion
		cloudFrontWAFs, cloudFrontErrors := enumerateWAFForScope(
			ctx,
			wafv2.NewFromConfig(cloudFrontConfig),
			cloudFrontRegion,
			types.ScopeCloudfront,
			waffern.ScopeTypeCloudfront,
		)
		allErrors = append(allErrors, cloudFrontErrors...)
		cloudFrontClient := cloudfront.NewFromConfig(cloudFrontConfig)
		for _, webACL := range cloudFrontWAFs {
			distributions, errs := distributionsForWebACL(ctx, cloudFrontClient, webACL.Identification.Arn)
			webACL.Resources.CloudFrontDistributions = distributions
			allErrors = append(allErrors, errs...)
		}
		allWafs = append(allWafs, cloudFrontWAFs...)
	}

	// Set the results
	if len(allWafs) > 0 {
		report.Result.Wafs = allWafs
	}
	report.Errors = allErrors
	return report
}

func cloudFrontWAFRegion(configRegion string, regions []string) (string, bool) {
	region := configRegion
	if len(regions) > 0 {
		region = regions[0]
	}
	isCommercial, err := methodawsutils.IsCommercialAWSRegion(region)
	if err != nil || !isCommercial {
		return "", false
	}
	return "us-east-1", true
}

// enumerateWAFForRegion enumerates WAFs for a given region
func enumerateWAFForRegion(ctx context.Context, awsConfig aws.Config, region string) ([]*waffern.WafInstance, []string) {
	awsConfig.Region = region
	return enumerateWAFForScope(
		ctx,
		wafv2.NewFromConfig(awsConfig),
		region,
		types.ScopeRegional,
		waffern.ScopeTypeRegional,
	)
}

type wafAPI interface {
	ListWebACLs(context.Context, *wafv2.ListWebACLsInput, ...func(*wafv2.Options)) (*wafv2.ListWebACLsOutput, error)
	GetWebACL(context.Context, *wafv2.GetWebACLInput, ...func(*wafv2.Options)) (*wafv2.GetWebACLOutput, error)
	ListResourcesForWebACL(context.Context, *wafv2.ListResourcesForWebACLInput, ...func(*wafv2.Options)) (*wafv2.ListResourcesForWebACLOutput, error)
}

func enumerateWAFForScope(
	ctx context.Context,
	wafClient wafAPI,
	region string,
	awsScope types.Scope,
	fernScope waffern.ScopeType,
) ([]*waffern.WafInstance, []string) {
	if strings.TrimSpace(region) == "" {
		return nil, []string{"Cannot enumerate WAFs without a region"}
	}
	log := svc1log.FromContext(ctx)
	var errors []string

	// List WAF WebACLs with pagination
	var allWebACLs []types.WebACLSummary
	var nextMarker *string
	for {
		listWebACLsInput := &wafv2.ListWebACLsInput{
			Scope:      awsScope,
			NextMarker: nextMarker,
		}
		webACLsOutput, err := wafClient.ListWebACLs(ctx, listWebACLsInput)
		if err != nil {
			errorMsg := "Failed to list WAF WebACLs in region " + region + ": " + err.Error()
			log.Error("Error listing WAF WebACLs", svc1log.SafeParam("error", err.Error()))
			errors = append(errors, errorMsg)
			break
		}
		if webACLsOutput == nil {
			errors = append(errors, "ListWebACLs returned no response")
			break
		}
		allWebACLs = append(allWebACLs, webACLsOutput.WebACLs...)
		if !hasValue(webACLsOutput.NextMarker) {
			break
		}
		if aws.ToString(nextMarker) == *webACLsOutput.NextMarker {
			errors = append(errors, "ListWebACLs returned a repeated pagination marker")
			break
		}
		nextMarker = webACLsOutput.NextMarker
	}

	log.Info("Successfully listed WAF WebACLs", svc1log.SafeParam("count", len(allWebACLs)))

	var wafs []*waffern.WafInstance
	for _, webACL := range allWebACLs {
		webACLARN, err := validateWebACLIdentity(webACL, region, awsScope)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		// Get the rules for the WAF
		rules, defaultAction, errs := getRules(ctx, wafClient, awsScope, webACL.Id, webACL.Name, webACLARN.String())
		for _, err := range errs {
			errors = append(errors, fmt.Sprintf("WebACL %s: %s", webACLARN.String(), err))
		}

		// Get the resources for the WAF
		resourceInfo := &waffern.WafResourceInfo{
			Rules: rules,
		}
		var stageAssociations []*waffern.ApiGatewayStageAssociation

		if awsScope == types.ScopeRegional {
			resourceArns, resourceErrors := resourcesForWebACL(ctx, wafClient, webACL.ARN, region)
			errors = append(errors, resourceErrors...)
			var referenceErrors []string
			resourceInfo.LoadBalancers, stageAssociations, referenceErrors = referencesFromResourceARNs(resourceArns, webACLARN)
			for _, err := range referenceErrors {
				errors = append(errors, fmt.Sprintf("WebACL %s: %s", webACLARN.String(), err))
			}
		}

		waf := waffern.WafInstance{
			Identification: &waffern.WafIdentificationInfo{
				Arn:    aws.ToString(webACL.ARN),
				Name:   webACL.Name,
				Region: region,
			},
			Configuration: &waffern.WafConfigurationInfo{
				Scope:                       fernScope,
				Description:                 webACL.Description,
				DefaultAction:               defaultAction,
				ApiGatewayStageAssociations: stageAssociations,
			},
			Resources: resourceInfo,
		}
		wafs = append(wafs, &waf)
	}

	return wafs, errors
}

// getRules gets the rules for a given WebACL
func getRules(ctx context.Context, wafClient wafAPI, scope types.Scope, webACLId, webACLName *string, webACLARN string) ([]*waffern.RuleInfo, *waffern.ActionType, []string) {
	log := svc1log.FromContext(ctx)
	if !hasValue(webACLId) || !hasValue(webACLName) {
		return nil, nil, []string{"Cannot call GetWebACL without its ID and name"}
	}
	getWebACLInput := &wafv2.GetWebACLInput{Id: webACLId, Name: webACLName, Scope: scope}
	webACLOutput, err := wafClient.GetWebACL(ctx, getWebACLInput)
	if err != nil {
		return nil, nil, []string{"GetWebACL: " + err.Error()}
	}
	if webACLOutput == nil || webACLOutput.WebACL == nil {
		return nil, nil, []string{"GetWebACL returned no WebACL"}
	}

	var rules []*waffern.RuleInfo
	var errors []string
	defaultActionType, err := getDefaultActionType(webACLOutput.WebACL.DefaultAction)
	if err != nil {
		errors = append(errors, err.Error())
	}
	for _, rule := range webACLOutput.WebACL.Rules {
		if !hasValue(rule.Name) {
			errors = append(errors, "WAF rule has no name")
			continue
		}
		if rule.Statement == nil {
			log.Warn("WAF Rule Statement is nil", svc1log.SafeParam("ruleName", *rule.Name))
			errors = append(errors, fmt.Sprintf("WAF Rule %s Statement is nil", *rule.Name))
			continue
		}
		actionType, overrideAction, err := ruleActions(rule)
		if err != nil {
			errors = append(errors, fmt.Sprintf("WAF rule %s: %v", *rule.Name, err))
			continue
		}
		ruleJSON, err := json.Marshal(rule)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		statementJSON, err := json.Marshal(rule.Statement)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		var actionJSONString *string
		var actionInfo *waffern.ActionInfo

		if rule.Action != nil {
			actionJSON, err := json.Marshal(rule.Action)
			if err != nil {
				errors = append(errors, err.Error())
				continue
			}
			actionJSONStr := string(actionJSON)
			actionJSONString = &actionJSONStr
			actionInfo = &waffern.ActionInfo{
				Type:       *actionType,
				JsonString: actionJSONString,
			}
		}
		var labels []string
		for _, label := range rule.RuleLabels {
			if hasValue(label.Name) {
				labels = append(labels, *label.Name)
			}
		}

		statementJSONString := string(statementJSON)
		ruleInfo := waffern.RuleInfo{
			Identification: &waffern.RuleIdentificationInfo{
				Id:   webACLARN + "/rule/" + *rule.Name,
				Name: aws.ToString(rule.Name),
			},
			Configuration: &waffern.RuleConfigurationInfo{
				Priority: int(rule.Priority),
				Statement: &waffern.StatementInfo{
					Type:         getStatementType(rule.Statement),
					RawStatement: &statementJSONString,
				},
				Action:         actionInfo,
				OverrideAction: overrideAction,
				Labels:         labels,
				RawRule:        string(ruleJSON),
			},
		}
		rules = append(rules, &ruleInfo)
	}

	return rules, defaultActionType, errors
}

func ruleActions(rule types.Rule) (*waffern.ActionType, *waffern.OverrideActionType, error) {
	isGroup := rule.Statement.ManagedRuleGroupStatement != nil || rule.Statement.RuleGroupReferenceStatement != nil
	if isGroup {
		if rule.Action != nil || rule.OverrideAction == nil ||
			(rule.OverrideAction.None == nil) == (rule.OverrideAction.Count == nil) {
			return nil, nil, fmt.Errorf("rule group reference requires exactly one override action and no direct action")
		}
		override := waffern.OverrideActionTypeNone
		if rule.OverrideAction.Count != nil {
			override = waffern.OverrideActionTypeCount
		}
		return nil, &override, nil
	}
	if rule.Action == nil || rule.OverrideAction != nil {
		return nil, nil, fmt.Errorf("non-group rule requires a direct action and no override action")
	}
	var actions []waffern.ActionType
	if rule.Action.Allow != nil {
		actions = append(actions, waffern.ActionTypeAllow)
	}
	if rule.Action.Block != nil {
		actions = append(actions, waffern.ActionTypeBlock)
	}
	if rule.Action.Captcha != nil {
		actions = append(actions, waffern.ActionTypeCaptcha)
	}
	if rule.Action.Challenge != nil {
		actions = append(actions, waffern.ActionTypeChallenge)
	}
	if rule.Action.Count != nil {
		actions = append(actions, waffern.ActionTypeCount)
	}
	if len(actions) != 1 {
		return nil, nil, fmt.Errorf("rule must specify exactly one supported action")
	}
	return &actions[0], nil, nil
}

// getDefaultActionType gets the default action type for a given DefaultAction
func getDefaultActionType(action *types.DefaultAction) (*waffern.ActionType, error) {
	if action == nil || (action.Allow == nil) == (action.Block == nil) {
		return nil, fmt.Errorf("WebACL default action is missing or invalid")
	}
	value := waffern.ActionTypeBlock
	if action.Allow != nil {
		value = waffern.ActionTypeAllow
	}
	return &value, nil
}

// getStatementType gets the statement type for a given Statement
func getStatementType(statement *types.Statement) waffern.StatementType {
	switch {
	case statement.AndStatement != nil:
		return waffern.StatementTypeAnd
	case statement.ByteMatchStatement != nil:
		return waffern.StatementTypeByteMatch
	case statement.GeoMatchStatement != nil:
		return waffern.StatementTypeGeoMatch
	case statement.IPSetReferenceStatement != nil:
		return waffern.StatementTypeIpSetReference
	case statement.LabelMatchStatement != nil:
		return waffern.StatementTypeLabelMatch
	case statement.ManagedRuleGroupStatement != nil:
		return waffern.StatementTypeManagedRuleGroup
	case statement.NotStatement != nil:
		return waffern.StatementTypeNot
	case statement.OrStatement != nil:
		return waffern.StatementTypeOr
	case statement.RateBasedStatement != nil:
		return waffern.StatementTypeRateBased
	case statement.RegexMatchStatement != nil:
		return waffern.StatementTypeRegexMatch
	case statement.RegexPatternSetReferenceStatement != nil:
		return waffern.StatementTypeRegexPatternsetRefence
	case statement.RuleGroupReferenceStatement != nil:
		return waffern.StatementTypeRuleGroupReference
	case statement.SizeConstraintStatement != nil:
		return waffern.StatementTypeSizeConstraint
	case statement.SqliMatchStatement != nil:
		return waffern.StatementTypeSqliMatch
	case statement.XssMatchStatement != nil:
		return waffern.StatementTypeXssMatch
	default:
		return waffern.StatementTypeOther
	}
}

func resourcesForWebACL(ctx context.Context, wafClient wafAPI, webACLArn *string, region string) ([]string, []string) {
	log := svc1log.FromContext(ctx)
	resourceTypes := []types.ResourceType{
		types.ResourceTypeApplicationLoadBalancer,
		types.ResourceTypeApiGateway,
	}
	var resourceARNs []string
	var errors []string
	for _, resourceType := range resourceTypes {
		output, err := wafClient.ListResourcesForWebACL(ctx, &wafv2.ListResourcesForWebACLInput{
			WebACLArn:    webACLArn,
			ResourceType: resourceType,
		})
		if err != nil {
			log.Warn("Failed to list resources for WebACL",
				svc1log.SafeParam("webACLArn", aws.ToString(webACLArn)),
				svc1log.SafeParam("resourceType", resourceType),
				svc1log.SafeParam("region", region),
				svc1log.Stacktrace(err))
			errors = append(errors, fmt.Sprintf("ListResourcesForWebACL %s (%s, %s): %v", aws.ToString(webACLArn), region, resourceType, err))
			continue
		}
		if output == nil {
			errors = append(errors, fmt.Sprintf("ListResourcesForWebACL %s (%s, %s) returned no response", aws.ToString(webACLArn), region, resourceType))
			continue
		}
		resourceARNs = append(resourceARNs, output.ResourceArns...)
	}
	return resourceARNs, errors
}

func referencesFromResourceARNs(
	resourceARNs []string,
	webACLARN arn.ARN,
) ([]*common.LoadBalancerReference, []*waffern.ApiGatewayStageAssociation, []string) {
	var loadBalancers []*common.LoadBalancerReference
	var stages []*waffern.ApiGatewayStageAssociation
	var errors []string
	for _, resourceARN := range resourceARNs {
		parsed, err := arn.Parse(resourceARN)
		if err != nil || parsed.Partition != webACLARN.Partition || parsed.Region != webACLARN.Region {
			errors = append(errors, fmt.Sprintf("Invalid or out-of-scope associated resource ARN %q", resourceARN))
			continue
		}
		parts := strings.Split(parsed.Resource, "/")
		if parsed.Service == "elasticloadbalancing" && hasValue(&parsed.AccountID) &&
			len(parts) == 4 && parts[0] == "loadbalancer" && parts[1] == "app" && hasValue(&parts[2]) && hasValue(&parts[3]) {
			loadBalancers = append(loadBalancers, &common.LoadBalancerReference{
				Arn:    resourceARN,
				Region: parsed.Region,
				Type:   common.LoadBalancerTypeApplication,
			})
			continue
		}
		if parsed.Service == "apigateway" && parsed.AccountID == "" && len(parts) == 5 &&
			parts[0] == "" && parts[1] == "restapis" && hasValue(&parts[2]) && parts[3] == "stages" && hasValue(&parts[4]) {
			apiID := parts[2]
			parsed.Resource = "/restapis/" + apiID
			stages = append(stages, &waffern.ApiGatewayStageAssociation{
				StageArn:  resourceARN,
				StageName: parts[4],
				Api:       &common.ApiGatewayReference{Arn: parsed.String(), ApiId: &apiID, Region: parsed.Region},
			})
			continue
		}
		errors = append(errors, fmt.Sprintf("Invalid or unsupported associated resource ARN %q", resourceARN))
	}
	return loadBalancers, stages, errors
}

func hasValue(value *string) bool {
	return value != nil && strings.TrimSpace(*value) != ""
}

func validateWebACLIdentity(webACL types.WebACLSummary, region string, scope types.Scope) (arn.ARN, error) {
	parsed, err := arn.Parse(aws.ToString(webACL.ARN))
	parts := strings.Split(parsed.Resource, "/")
	resourceScope := "regional"
	if scope == types.ScopeCloudfront {
		resourceScope = "global"
	}
	if err != nil || parsed.Service != "wafv2" || !hasValue(&parsed.Partition) || !hasValue(&parsed.AccountID) ||
		parsed.Region != region || len(parts) != 4 || parts[0] != resourceScope || parts[1] != "webacl" ||
		!hasValue(&parts[2]) || !hasValue(&parts[3]) {
		return arn.ARN{}, fmt.Errorf("Invalid WebACL ARN %q for region %s and scope %s", aws.ToString(webACL.ARN), region, scope)
	}
	if (hasValue(webACL.Name) && *webACL.Name != parts[2]) || (hasValue(webACL.Id) && *webACL.Id != parts[3]) {
		return arn.ARN{}, fmt.Errorf("WebACL ARN %q does not match its reported name or ID", *webACL.ARN)
	}
	return parsed, nil
}
