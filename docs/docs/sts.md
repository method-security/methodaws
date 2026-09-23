# STS

The `methodaws sts` family of commands provide common utilities that are leveraged by other commands when interacting with the AWS STS service.

## Usage
```bash
methodaws sts [command]
```

## Commands

### arn

The arn command returns the ARN of the caller. This is leveraged when information about the provided AWS IAM role or credentials are needed by other commands. Primarily necessary to provide a clean data picture and improving data integration quality.

#### Usage

```bash
methodaws sts arn --regions us-east-1 --output json
```

#### Help Text

```bash
$ methodaws sts arn -h
Get the caller ARN

Usage:
  methodaws sts arn [flags]

Flags:
  -h, --help   help for arn

Global Flags:
  -o, --output string          Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string     Path to output file. If blank, will output to STDOUT
  -q, --quiet                  Suppress output
  -r, --regions stringArray    AWS Regions to search for resources. You can specify multiple regions by providing the flag multiple times. If blank, will search all regions.
  -v, --verbose                Verbose output
```
