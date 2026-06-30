# IAM Policy — Cryptiq Discovery Role

## `discovery-readonly.json`

Least-privilege policy for the Cryptiq discovery credential.

| Permission group | Why |
|---|---|
| `elasticloadbalancing:Describe*` | Read ALB/NLB listeners and their current TLS policies |
| `elasticloadbalancing:DescribeTags` | Read the `Environment` tag to scope migrations |
| `acm:ListCertificates`, `acm:DescribeCertificate` | Scan ACM certs for classical algorithms |
| `kms:ListKeys`, `kms:DescribeKey` | Scan KMS keys for quantum-vulnerable algorithms |
| `ec2:DescribeInstances` | Discover EC2 hosts for SSH scanning |
| `route53:ListHostedZones`, `route53:ListResourceRecordSets` | Enumerate domains from Route53 |

**No write permissions are granted.** There is no `Create*`, `Update*`, `Delete*`,
`Modify*`, `Put*`, or `Tag*` action in this policy.

---

## Blast-radius statement

> The worst thing a credential compromise of this role can do is **read TLS
> configuration metadata and open a GitHub pull request**.

Specifically:
- It cannot modify, create, or delete any AWS resource.
- It cannot change any TLS policy, certificate, or key material.
- It cannot access any encrypted data.
- It cannot read secret values from Secrets Manager or Parameter Store.
- It has no IAM permissions and cannot escalate privilege.

The only write surface Cryptiq holds is **GitHub** (via `GITHUB_TOKEN`), and
that token is scoped to branch-create / commit / open-PR only — enforced by
the chokepoint in `tls_migration/github_pr.py` which raises `PermissionError`
on any merge, force-push, or delete attempt.

**The customer's own CI/CD pipeline applies merged changes using the customer's
own infrastructure credentials.** Cryptiq never holds those credentials and never
applies changes directly.

---

## Attaching this policy

```bash
aws iam create-policy \
  --policy-name CryptiqDiscoveryReadOnly \
  --policy-document file://iam/discovery-readonly.json

aws iam attach-role-policy \
  --role-name CryptiqDiscoveryRole \
  --policy-arn arn:aws:iam::<account-id>:policy/CryptiqDiscoveryReadOnly
```

For cross-account access (multi-tenant), use an IAM role with `ExternalId` —
never long-lived access keys.
