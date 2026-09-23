# CloudFront

methodaws provides the capability to enumerate AWS CloudFront distributions and their related resources.

## Usage
```bash
methodaws cloudfront [command]
```

## Commands

### Enumerate

#### Usage
```bash
methodaws cloudfront enumerate
```

## Examples

```bash
# Enumerate CloudFront distributions
methodaws cloudfront enumerate

# Output to JSON format
methodaws cloudfront enumerate --output json

# Save output to file
methodaws cloudfront enumerate --output-file cloudfront-report.json
```

## Resources Enumerated

The CloudFront enumerate command gathers information about:

- CloudFront distributions
- Distribution configurations
- Origins and origin access identities
- Behaviors and caching settings
- SSL/TLS certificates
- Geographic restrictions
- WAF associations

## Output

The output includes detailed information about your CloudFront distributions and their configurations in the specified output format (signal, JSON, or YAML).

## Note

CloudFront is a global service, so the enumerate command will gather information about all distributions regardless of the regions specified in the `--regions` flag.
