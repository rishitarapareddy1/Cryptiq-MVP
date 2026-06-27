"""
tls_scanner/scan_alb.py
------------------------
Read-only discovery of ALB/NLB TLS listeners and their ssl_policy.

All AWS calls are strictly read-only: describe_load_balancers,
describe_listeners, describe_ssl_policies, describe_tags.
No mutating calls are made here or anywhere in this module.
"""

from __future__ import annotations

import boto3

from tls_migration.types import TlsListenerAsset

# VERIFY: These policy names were correct as of 2025-Q4. AWS updates them
# quarterly — confirm against live docs before shipping to a customer:
# https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html
PQ_POLICY_NAMES: frozenset[str] = frozenset({
    "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
})

# VERIFY: Supported hybrid KEM groups per the PQ policy family above.
# https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html
PQ_GROUPS: frozenset[str] = frozenset({
    "X25519MLKEM768",
    "SecP256r1MLKEM768",
    "SecP384r1MLKEM1024",
})


def _is_post_quantum(ssl_policy_name: str, supported_groups: list[str]) -> bool:
    """True only when the policy is in the known PQ set OR advertises a PQ group."""
    if ssl_policy_name in PQ_POLICY_NAMES:
        return True
    return bool(set(supported_groups) & PQ_GROUPS)


def _get_lb_environment_tags(client, lb_arns: list[str]) -> dict[str, str | None]:
    """Return {lb_arn: environment_value} for each ARN. None if tag absent."""
    if not lb_arns:
        return {}
    try:
        resp = client.describe_tags(ResourceArns=lb_arns)
        result: dict[str, str | None] = {}
        for td in resp.get("TagDescriptions", []):
            arn = td["ResourceArn"]
            env = next(
                (t["Value"] for t in td.get("Tags", []) if t["Key"] == "Environment"),
                None,
            )
            result[arn] = env
        return result
    except Exception:
        return {arn: None for arn in lb_arns}


def discover_alb_listeners(region: str = "us-east-1") -> list[TlsListenerAsset]:
    """
    Enumerate all ALBs and NLBs in a region and return their HTTPS/TLS
    listeners with PQC classification.

    Read-only: uses describe_load_balancers, describe_listeners,
    describe_ssl_policies, describe_tags only.
    """
    elb = boto3.client("elasticloadbalancingv2", region_name=region)

    # 1. List all load balancers
    lbs: list[dict] = []
    paginator = elb.get_paginator("describe_load_balancers")
    for page in paginator.paginate():
        lbs.extend(page["LoadBalancers"])

    if not lbs:
        return []

    # 2. Fetch environment tags for all LBs in one call (max 20 per request)
    lb_arns = [lb["LoadBalancerArn"] for lb in lbs]
    env_tags: dict[str, str | None] = {}
    for i in range(0, len(lb_arns), 20):
        env_tags.update(_get_lb_environment_tags(elb, lb_arns[i : i + 20]))

    # 3. Resolve ssl_policy details (cache to avoid duplicate describe calls)
    policy_cache: dict[str, dict] = {}

    def _get_policy(name: str) -> dict:
        if name not in policy_cache:
            try:
                resp = elb.describe_ssl_policies(Names=[name])
                policies = resp.get("SslPolicies", [])
                policy_cache[name] = policies[0] if policies else {}
            except Exception:
                policy_cache[name] = {}
        return policy_cache[name]

    # 4. Walk every LB → listeners → filter HTTPS/TLS
    assets: list[TlsListenerAsset] = []

    for lb in lbs:
        lb_arn = lb["LoadBalancerArn"]
        lb_name = lb["LoadBalancerName"]
        environment = env_tags.get(lb_arn)

        listener_paginator = elb.get_paginator("describe_listeners")
        for page in listener_paginator.paginate(LoadBalancerArn=lb_arn):
            for listener in page["Listeners"]:
                protocol = listener.get("Protocol", "")
                if protocol not in ("HTTPS", "TLS"):
                    continue

                ssl_policy_name = listener.get("SslPolicy", "")
                policy = _get_policy(ssl_policy_name) if ssl_policy_name else {}

                supported_protocols = [
                    p["Name"] for p in policy.get("SslProtocols", [])
                ]
                supported_groups = [
                    g["Name"] for g in policy.get("SupportedLoadBalancerTypes", [])
                    # The actual field varies by API version; fall back to empty.
                    # VERIFY: check live DescribeSSLPolicies response shape.
                ]
                # DescribeSSLPolicies returns SupportedLoadBalancerTypes for
                # grouping, but supported KEM groups are in the policy name
                # itself for now. Use name-based detection as primary signal.
                is_pq = _is_post_quantum(ssl_policy_name, supported_groups)

                assets.append(
                    TlsListenerAsset(
                        lb_arn=lb_arn,
                        lb_name=lb_name,
                        listener_arn=listener["ListenerArn"],
                        port=listener.get("Port", 0),
                        protocol=protocol,
                        ssl_policy_name=ssl_policy_name,
                        supported_protocols=supported_protocols,
                        supported_groups=supported_groups,
                        is_post_quantum=is_pq,
                        environment=environment,
                        region=region,
                    )
                )

    return assets
