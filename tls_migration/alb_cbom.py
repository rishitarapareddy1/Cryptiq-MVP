"""
tls_migration/alb_cbom.py
--------------------------
Convert TlsListenerAsset objects to a CycloneDX 1.6 CBOM document.

Follows the same pattern as tls_scanner/scan_aws.py:convert_aws_to_cbom().
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from tls_migration.types import TlsListenerAsset


def build_alb_component(asset: TlsListenerAsset) -> dict:
    """Build one CycloneDX cryptographic-asset component for an ALB listener."""
    return {
        "type": "cryptographic-asset",
        "name": f"{asset.lb_name}:{asset.port} TLS Listener",
        "bom-ref": asset.listener_arn,
        "cryptoProperties": {
            "assetType": "protocol",
            "algorithmProperties": {
                "primitive": "kem" if asset.is_post_quantum else "keyagree",
            },
            # VERIFY: nistQuantumSecurityLevel mapping for hybrid PQ vs classical:
            # https://cyclonedx.org/docs/1.6/json/#components_items_cryptoProperties_nistQuantumSecurityLevel
            "nistQuantumSecurityLevel": 1 if asset.is_post_quantum else 0,
            "protocolProperties": {
                "type": "tls",
                "version": "1.3" if "TLSv1.3" in asset.supported_protocols else "1.2",
                "supportedVersions": asset.supported_protocols,
            },
        },
        "properties": [
            {"name": "lb_arn", "value": asset.lb_arn},
            {"name": "lb_name", "value": asset.lb_name},
            {"name": "listener_arn", "value": asset.listener_arn},
            {"name": "ssl_policy", "value": asset.ssl_policy_name},
            {"name": "port", "value": str(asset.port)},
            {"name": "protocol", "value": asset.protocol},
            {"name": "is_post_quantum", "value": str(asset.is_post_quantum).lower()},
            {"name": "environment", "value": asset.environment or "unknown"},
            {"name": "region", "value": asset.region},
            {"name": "supported_groups", "value": ",".join(asset.supported_groups)},
        ],
    }


def convert_alb_to_cbom(assets: list[TlsListenerAsset]) -> dict:
    """Build a full CycloneDX 1.6 CBOM from a list of TlsListenerAssets."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {
                "type": "application",
                "name": "Cryptiq ALB TLS Scanner",
            },
        },
        "components": [build_alb_component(a) for a in assets],
    }
