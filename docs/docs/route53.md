# Route53

The `methodaws route53` family of commands provide information about an account's Route53 DNS entries and hosted zones.

## Usage
```bash
methodaws route53 [command]
```

## Commands

### Enumerate

The enumerate command will gather information about all of the Route53 hosted zones and DNS entries, that the provided credentials have access to.

Each hosted zone has its own `identification` (required ARN, canonical ID, and name),
`configuration` (including public/private status when returned), and `resources.recordSets`.
Hosted-zone ARNs use the configured AWS partition and contain neither an account ID nor a region.
Record sets remain nested under their owning zone. Alias targets retain their reported DNS name and
target hosted-zone ID; no load balancer, distribution, or other resource ARN is inferred from a hostname.

#### Usage

```bash
methodaws route53 enumerate --regions us-east-1 --output json

```

#### Help Text

```bash
$ methodaws route53 enumerate --help
Enumerate Route53 records

Usage:
  methodaws route53 enumerate [flags]

Flags:
  -h, --help   help for enumerate

Global Flags:
  -o, --output string          Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string     Path to output file. If blank, will output to STDOUT
  -q, --quiet                  Suppress output
  -r, --regions stringArray    AWS Regions to search for resources. You can specify multiple regions by providing the flag multiple times. If blank, will search all regions.
  -v, --verbose                Verbose output
```
