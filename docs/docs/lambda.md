# Lambda

methodaws provides the capability to enumerate AWS Lambda functions and their configurations.

## Usage
```bash
methodaws lambda [command]
```

## Commands

### Enumerate

#### Usage
```bash
methodaws lambda enumerate --regions <regions>
```

## Examples

```bash
# Enumerate Lambda functions in us-east-1
methodaws lambda enumerate --regions us-east-1

# Enumerate Lambda functions in multiple regions
methodaws lambda enumerate --regions us-east-1 --regions us-west-2

# Enumerate Lambda functions in all regions (default behavior)
methodaws lambda enumerate

# Output to JSON format
methodaws lambda enumerate --output json
```

## Resources Enumerated

The Lambda enumerate command gathers information about:

- Lambda functions
- Function configurations
- Runtime environments
- Environment variables
- Memory and timeout settings
- IAM roles and permissions
- VPC configurations
- Function aliases and versions
- Event source mappings
- Layer associations

## Output

The output includes detailed information about your Lambda functions and their configurations in the specified output format (signal, JSON, or YAML).

## Security Considerations

When enumerating Lambda functions, methodaws will collect configuration details that may include:
- Environment variable names (values are not exposed)
- IAM role ARNs
- VPC and subnet configurations
- Security group associations
