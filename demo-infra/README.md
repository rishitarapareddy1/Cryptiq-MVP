# demo-infra — Cryptiq PQC Demo ALB

Provisions a minimal, real ALB on a classical TLS policy in the default VPC.
This is the target that Cryptiq will discover, plan a migration for, and
roll back — the "hero moment" of the vertical slice.

## What gets created

| Resource | Notes |
|---|---|
| `aws_lb` (ALB) | Public-facing, default VPC |
| `aws_lb_listener` (HTTPS:443) | `ssl_policy = ELBSecurityPolicy-TLS13-1-2-2021-06` set **explicitly** |
| `aws_lb_target_group` | Empty — demo only, no real backend |
| `aws_security_group` | Allows 443 inbound |
| `aws_acm_certificate` | Self-signed cert imported via ACM |
| `tls_private_key` + `tls_self_signed_cert` | Demo cert, not for production |

**Estimated cost:** ~$0.018/hour for the ALB (~$13/month if left running).
Destroy when done. There is no backend traffic so no LCU charges accrue.

## Prerequisites

- Terraform >= 1.5
- AWS credentials configured (`aws configure` or env vars)
- Default VPC with at least 2 subnets in your chosen region

## Apply

```bash
cd demo-infra
terraform init
terraform plan     # review — confirm only the resources above are created
terraform apply    # YOU run this, not Cryptiq
```

After apply, Cryptiq discovery should find the ALB and report `is_post_quantum: false`.

## Destroy (always do this after the demo)

```bash
cd demo-infra
terraform destroy
```

All resources are tagged `Project = cryptiq-pqc-demo` so you can also use
the AWS console to verify nothing was missed.

## What the migration changes

When Cryptiq opens a migration PR, the only change in the diff will be:

```hcl
-  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
+  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"
```

All other fields remain untouched. The rollback PR reverses this exactly.
