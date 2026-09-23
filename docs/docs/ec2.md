# EC2

The `methodaws ec2` family of commands provide information about an account's EC2 instances.

## Usage
```bash
methodaws ec2 [command]
```

## Commands

### Enumerate

The enumerate command will gather information about all of the EC2 instances that the provided credentials have access to.

#### Usage

```bash
methodaws ec2 enumerate --regions us-east-1 --output json
```

#### Help Text

```bash
$ methodaws ec2 enumerate -h
Enumerate EC2 instances

Usage:
  methodaws ec2 enumerate [flags]

Flags:
  -h, --help   help for enumerate

Global Flags:
  -o, --output string          Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string     Path to output file. If blank, will output to STDOUT
  -q, --quiet                  Suppress output
  -r, --regions stringArray    AWS Regions to search for resources. You can specify multiple regions by providing the flag multiple times. If blank, will search all regions.
  -v, --verbose                Verbose output
```
