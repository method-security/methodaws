# IAM

The `methodaws iam` family of commands provide information about an account's IAM roles and policies.

## Usage
```bash
methodaws iam [command]
```

## Commands

### Enumerate

The enumerate command will gather information about all of the IAM roles, along with their attached and/or inline policies, that the provided credentials have access to.

#### Usage

```bash
methodaws iam enumerate --regions us-east-1 --output json

```

#### Help Text

```bash
$ methodaws iam enumerate -h
Enumerate IAM resources

Usage:
  methodaws iam enumerate [flags]

Flags:
      --exclude-aws-managed-roles   Exclude AWS managed roles
  -h, --help                        help for enumerate

Global Flags:
  -o, --output string          Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string     Path to output file. If blank, will output to STDOUT
  -q, --quiet                  Suppress output
  -r, --regions stringArray    AWS Regions to search for resources. You can specify multiple regions by providing the flag multiple times. If blank, will search all regions.
  -v, --verbose                Verbose output
```
