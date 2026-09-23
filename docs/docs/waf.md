# WAF

methodaws provides the capability to enumerate AWS WAF (Web Application Firewall) resources.

## Usage
```bash
methodaws waf [command]
```

## Commands

### Enumerate

#### Usage
```bash
methodaws waf enumerate --regions <regions>
```

## Examples

```bash
# Enumerate WAF resources in us-east-1
methodaws waf enumerate --regions us-east-1

# Enumerate WAF resources in multiple regions
methodaws waf enumerate --regions us-east-1 --regions us-west-2

# Enumerate WAF resources in all regions (default behavior)
methodaws waf enumerate

# Output to JSON format
methodaws waf enumerate --output json
```

## Resources Enumerated

The WAF enumerate command gathers information about:

- WAF Web ACLs
- Web ACL default actions and configured rules, including priorities, statements, actions, overrides, and labels
- Associated Application Load Balancer and CloudFront distribution references
- API Gateway stage associations, including the exact stage ARN and parent API reference

Rules include a required scoped ID formed from the parent Web ACL ARN and rule name. This is not an AWS-issued rule ARN. Rule-group references report `overrideAction` (`NONE` or `COUNT`) separately from direct rule actions. Invalid action combinations are reported as errors and skipped.

`resources` contains rule objects and load balancer/distribution references. Stage-scoped associations are retained under `configuration.apiGatewayStageAssociations`; they do not imply that every stage of an API is protected. CloudFront distributions are global resources and their references omit `region`.

CloudFront associations use `cloudfront:ListDistributionsByWebACLId`. If this lookup fails, the Web ACL and previously collected associations are retained with an error. Referenced rule groups, IP sets, and regex sets are not expanded into separate inventories.

## Output

The output includes detailed information about your WAF resources and their configurations in the specified output format (signal, JSON, or YAML).

## Security Considerations

When enumerating WAF resources, methodaws will collect:
- Web ACL configurations and rules
- Reported matching statements and referenced set identifiers
- Rate limiting configurations
- Associated protected resources
- Per-rule settings preserved in the raw rule configuration

This information is valuable for security assessments and ensuring proper web application protection is in place.
