# VPC

The `methodaws vpc` family of commands provide information about an account's VPCs.

## Usage
```bash
methodaws vpc [command]
```

## Commands

### Enumerate

The enumerate command will gather information about all of the VPCs that the provided credentials have access to.

VPCs and subnets include native IDs and required ARNs. VPC ARNs are constructed using the reported owner account and region, not the caller's account. Returned subnet ARNs are validated; when absent, they are constructed from the reported subnet owner and region.

Resources without a complete identity are skipped and reported as errors. Subnets whose parent VPC was not collected are also skipped; enumeration does not create incomplete parent VPCs. Errors preserve valid results already collected and do not prevent enumeration of other regions.

#### Usage

```bash
methodaws vpc enumerate --regions us-east-1 --output json
```

#### Help Text

```bash
$ methodaws vpc enumerate -h
Enumerate all VPCs in your AWS account.

Usage:
  methodaws vpc enumerate [flags]

Flags:
  -h, --help   help for enumerate

Global Flags:
  -o, --output string          Output format (signal, json). Default value is signal (default "signal")
  -f, --output-file string     Path to output file. If blank, will output to STDOUT
  -q, --quiet                  Suppress output
  -r, --regions stringArray    AWS Regions to search for resources. You can specify multiple regions by providing the flag multiple times. If blank, will search all regions.
  -v, --verbose                Verbose output
```
