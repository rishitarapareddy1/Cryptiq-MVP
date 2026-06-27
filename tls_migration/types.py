"""
tls_migration/types.py
-----------------------
Shared data types for ALB TLS discovery and migration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TlsListenerAsset:
    lb_arn: str
    lb_name: str
    listener_arn: str
    port: int
    protocol: str               # "HTTPS" | "TLS"
    ssl_policy_name: str
    supported_protocols: list[str]
    supported_groups: list[str]
    is_post_quantum: bool
    environment: Optional[str] = None   # from ALB tag "Environment"
    region: str = "us-east-1"

    def to_dict(self) -> dict:
        return {
            "lb_arn": self.lb_arn,
            "lb_name": self.lb_name,
            "listener_arn": self.listener_arn,
            "port": self.port,
            "protocol": self.protocol,
            "ssl_policy_name": self.ssl_policy_name,
            "supported_protocols": self.supported_protocols,
            "supported_groups": self.supported_groups,
            "is_post_quantum": self.is_post_quantum,
            "environment": self.environment,
            "region": self.region,
        }
