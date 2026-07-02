"""
code_signing/cbom.py
-----------------------
CycloneDX-flavored inventory of signed artifacts, consistent with the
CBOM outputs already produced for TLS/SSH/ALB assets elsewhere in Cryptiq.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from code_signing.types import SigningManifest


def generate_signing_cbom(manifest: SigningManifest) -> dict:
    components = []
    for entry in manifest.entries:
        components.append({
            "type": "file",
            "name": entry.path,
            "hashes": [{"alg": "SHA-256", "content": entry.sha256}],
            "properties": [
                {"name": "cryptiq:signer_kind", "value": entry.signer_kind.value},
                {"name": "cryptiq:algorithm", "value": entry.algorithm or "unknown"},
                {"name": "cryptiq:key_id", "value": entry.key_id or ""},
                {"name": "cryptiq:signed", "value": str(entry.success).lower()},
                {"name": "cryptiq:signed_at", "value": entry.signed_at},
            ],
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "Cryptiq", "name": "code-signing", "version": "1.0.0"}],
            "properties": [
                {"name": "cryptiq:manifest_id", "value": manifest.manifest_id},
                {"name": "cryptiq:root_path", "value": manifest.root_path},
                {"name": "cryptiq:key_id", "value": manifest.key_id},
            ],
        },
        "components": components,
    }