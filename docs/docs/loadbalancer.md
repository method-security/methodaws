# Load Balancer

methodaws provides the capability to enumerate AWS Load Balancers including both Classic Load Balancers (v1) and Application/Network Load Balancers (v2).

## Usage
```bash
methodaws load-balancer [command]
```

## Commands

### Enumerate

#### Usage
```bash
methodaws load-balancer enumerate --regions <regions> --versions <versions>
```

## Examples

```bash
# Enumerate all load balancer types in us-east-1
methodaws load-balancer enumerate --regions us-east-1

# Enumerate only Application/Network Load Balancers (v2)
methodaws load-balancer enumerate --regions us-east-1 --versions V2

# Enumerate only Classic Load Balancers (v1)
methodaws load-balancer enumerate --regions us-east-1 --versions V1

# Enumerate specific versions in multiple regions
methodaws load-balancer enumerate --regions us-east-1 --regions us-west-2 --versions V1 --versions V2
```

## Flags

### --versions

Specify which load balancer versions to enumerate:
- `V1`: Classic Load Balancers (ELB)
- `V2`: Application Load Balancers (ALB) and Network Load Balancers (NLB)

**Default:** `["V1", "V2"]` (both versions)

## Resources Enumerated

The Load Balancer enumerate command gathers information about:

### Classic Load Balancers (V1)
- Load balancer configurations
- Listeners with separate frontend and backend port/protocol settings
- Instance registrations
- Security groups
- Subnets and availability zones

### Application/Network/Gateway Load Balancers (V2)
- Load balancer configurations
- Target groups and targets
- Listeners and their default forwarding target-group references, including configured weights
- Listener certificate references
- Security groups and subnets

Non-default listener rules are not collected. A target group listed under a load balancer is not automatically
the destination of every listener. Default forwarding references include zero-weight targets and describe
configuration, not proof of active forwarding or reachability.

Classic instance registrations do not carry a target port. Use each listener's backend port and protocol;
these settings are not copied onto all registered instances.

## Output

The output includes detailed information about your load balancers and their configurations in the specified output format (signal, json).

## Security Considerations

When enumerating load balancers, methodaws will collect:
- Security group associations
- SSL/TLS certificate information
- Registered targets, without a determination of target health
- Network configuration details
