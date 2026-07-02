"""
password_hashing/cbom.py
---------------------------
CycloneDX-flavored inventory of password-hashing findings. Note this is
NOT a cryptographic-asset CBOM in the classic sense (no key material) —
CycloneDX 1.6 supports "data" components for exactly this case.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from password_hashing.types import ScanSummary


def generate_password_hash_cbom(summary: ScanSummary) -> dict:
    components = []
    for f in summary.findings:
        components.append({
            "type": "data",
            "name": f"{f.platform.value}:{f.identifier}",
            "properties": [
                {"name": "cryptiq:algorithm", "value": f.algorithm},
                {"name": "cryptiq:risk", "value": f.risk.value},
                {"name": "cryptiq:source", "value": f.source},
                {"name": "cryptiq:recommendation", "value": f.recommendation},
            ],
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "Cryptiq", "name": "password-hashing", "version": "1.0.0"}],
            "properties": [
                {"name": "cryptiq:platform", "value": summary.platform.value},
                {"name": "cryptiq:source", "value": summary.source},
            ],
        },
        "components": components,
    }