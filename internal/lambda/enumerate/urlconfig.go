package lambda

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	lambdafern "github.com/Method-Security/methodaws/generated/go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

func enrichFunctionURLs(ctx context.Context, client *lambda.Client, function *lambdafern.LambdaFunction) []error {
	functionARN := function.Identification.Arn
	var errs []error
	policy, err := getFunctionResourcePolicy(ctx, client, functionARN)
	if err != nil {
		errs = append(errs, err)
	}
	function.Configuration.ResourcePolicy = policy
	policies := map[string]*string{functionARN: policy}

	paginator := lambda.NewListFunctionUrlConfigsPaginator(client, &lambda.ListFunctionUrlConfigsInput{
		FunctionName: aws.String(functionARN),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("list function URLs: %w", err))
			break
		}
		for _, config := range page.FunctionUrlConfigs {
			entry, err := parseFunctionURLConfig(config, functionARN)
			if err != nil {
				errs = append(errs, err)
			}
			if entry == nil {
				continue
			}
			targetARN := functionARN
			if entry.Alias != nil {
				targetARN += ":" + *entry.Alias
			}
			document, ok := policies[targetARN]
			if !ok {
				document, err = getFunctionResourcePolicy(ctx, client, targetARN)
				policies[targetARN] = document
				if err != nil {
					errs = append(errs, err)
				}
			}
			entry.ResourcePolicy = document
			function.Configuration.FunctionUrls = append(function.Configuration.FunctionUrls, entry)
		}
	}
	return errs
}

var functionURLAliasPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

func parseFunctionURLConfig(config types.FunctionUrlConfig, functionARN string) (*lambdafern.LambdaFunctionUrlConfig, error) {
	endpoint := aws.ToString(config.FunctionUrl)
	parsedURL, err := url.Parse(endpoint)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Hostname() == "" || parsedURL.User != nil || parsedURL.Fragment != "" {
		return nil, fmt.Errorf("missing or invalid function URL %q", endpoint)
	}

	// Compare the entire parent ARN so another account, region, or similarly named function cannot be linked.
	targetARN := aws.ToString(config.FunctionArn)
	var alias *string
	if targetARN != functionARN && targetARN != functionARN+":$LATEST" {
		qualifier, ok := strings.CutPrefix(targetARN, functionARN+":")
		if !ok || !functionURLAliasPattern.MatchString(qualifier) || strings.Trim(qualifier, "0123456789") == "" {
			return nil, fmt.Errorf("function URL %s has missing or invalid target ARN %q for parent %s", endpoint, targetARN, functionARN)
		}
		alias = &qualifier
	}
	entry := &lambdafern.LambdaFunctionUrlConfig{Url: endpoint, Alias: alias}
	authType, err := lambdafern.NewLambdaUrlAuthTypeFromString(string(config.AuthType))
	if err != nil {
		return entry, fmt.Errorf("function URL %s has missing or unsupported authentication mode %q", endpoint, config.AuthType)
	}
	entry.AuthType = &authType
	return entry, nil
}

func getFunctionResourcePolicy(ctx context.Context, client *lambda.Client, targetARN string) (*string, error) {
	result, err := client.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: aws.String(targetARN)})
	if err != nil {
		var notFound *types.ResourceNotFoundException
		if errors.As(err, &notFound) {
			// A function or alias need not have a resource-based policy.
			return nil, nil
		}
		return nil, fmt.Errorf("get resource policy for %s: %w", targetARN, err)
	}
	if result == nil || aws.ToString(result.Policy) == "" {
		return nil, fmt.Errorf("resource policy response for %s has no document", targetARN)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal([]byte(*result.Policy), &document); err != nil || document == nil {
		return nil, fmt.Errorf("resource policy for %s is not a JSON object", targetARN)
	}
	return result.Policy, nil
}
