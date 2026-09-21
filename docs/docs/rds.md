# RDS

The `methodaws rds` family of commands provide information about an account's RDS databases.

## Usage
```bash
methodaws rds [command]
```

## Commands

### Enumerate

The enumerate command will gather information about all of the RDS databases, that the provided credentials have access to.

The signal includes configured IAM role associations, including their feature and association status.
These associations are separate from the Enhanced Monitoring role and IAM database authentication settings;
they do not establish effective permissions.

Network references include the resource ARN and the owner account reported by EC2. Shared VPCs and subnets
are not assumed to belong to the database's account. This enrichment requires `ec2:DescribeVpcs`,
`ec2:DescribeSubnets`, and `ec2:DescribeSecurityGroups` in addition to `rds:DescribeDBInstances`.
Lookups target referenced IDs and are cached per region for the duration of enumeration.
Failed lookups are reported as errors; the database is retained and the unresolved resource reference is omitted.
`dbSubnetGroupSubnetIds` retains the IDs reported by RDS, while `resources.dbSubnetGroupSubnets` contains
only resolved references. Both describe configured subnet-group membership, not active instance attachments.

#### Usage

```bash
methodaws rds enumerate --regions us-east-1 --output json

```

#### Help Text

```bash
$ methodaws rds enumerate -h
Enumerate RDS instances in your AWS account.

Usage:
  methodaws rds enumerate [flags]

Flags:
  -h, --help   help for enumerate

Global Flags:
  -o, --output string          Output format (signal, json). Default value is signal (default "signal")
  -f, --output-file string     Path to output file. If blank, will output to STDOUT
  -q, --quiet                  Suppress output
  -r, --regions stringArray    AWS Regions to search for resources. You can specify multiple regions by providing the flag multiple times. If blank, will search all regions.
  -v, --verbose                Verbose output
```
