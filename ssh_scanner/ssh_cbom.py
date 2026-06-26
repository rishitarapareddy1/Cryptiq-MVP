"""
ssh_cbom.py
-----------
Cryptography Bill of Materials (CBOM) generation for SSH assets.

Follows CycloneDX 1.6 CBOM schema (cryptographic-asset component type).
Mirrors the TLS CBOM module but represents SSH-specific asset types:
  - ssh-host-key
  - ssh-kex
  - ssh-cipher
  - ssh-mac

Spec reference:
  https://cyclonedx.org/docs/1.6/json/#components_items_cryptoProperties

CBOM philosophy:
  Every cryptographic primitive in use IS an asset and belongs in the
  inventory — host key, KEX, cipher, MAC.  The CBOM is the source of
  truth that feeds readiness reports and migration planning.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Optional, Any

from ssh_scanner.scan_ssh import SSHScanResult, SSHHostKey
from ssh_scanner.ssh_risk import SSHRiskAssessment, assess_risk, classify_kex, classify_cipher, classify_mac


# ---------------------------------------------------------------------------
# CycloneDX helpers
# ---------------------------------------------------------------------------

def _bom_ref() -> str:
    return str(uuid.uuid4())


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Component builders
# ---------------------------------------------------------------------------

def _host_key_component(
    host: str,
    host_key: SSHHostKey,
    risk: SSHRiskAssessment,
) -> dict:
    """
    CycloneDX cryptographic-asset component for an SSH host key.
    Analogous to a TLS certificate component.
    """
    hk_risk = _classify_host_key_risk(host_key.algorithm, host_key.key_size)

    component: dict[str, Any] = {
        "type": "cryptographic-asset",
        "bom-ref": _bom_ref(),
        "name": f"{host} SSH Host Key ({host_key.algorithm})",
        "cryptoProperties": {
            "assetType": "ssh-host-key",
            "algorithmProperties": {
                "primitive": _primitive_type(host_key.algorithm),
                "hostKeyAlgorithm": host_key.algorithm,
            },
            "classicalSecurityLevel": _classical_security_level(host_key.algorithm, host_key.key_size),
            "quantumSecurityLevel": 0,  # 0 = not quantum-safe
        },
        "evidence": {
            "identity": {
                "field": "host-key",
                "confidence": 1.0,
                "methods": [{"technique": "network-probe", "confidence": 1.0}],
            }
        },
        "properties": [
            {"name": "cryptiq:host", "value": host},
            {"name": "cryptiq:keyAlgorithm", "value": host_key.algorithm},
            {"name": "cryptiq:quantumVulnerable", "value": str(risk.host_key_quantum_vulnerable).lower()},
            {"name": "cryptiq:riskLevel", "value": hk_risk},
        ],
    }

    if host_key.key_size is not None:
        component["cryptoProperties"]["algorithmProperties"]["keySize"] = host_key.key_size

    if host_key.fingerprint is not None:
        component["properties"].append(
            {"name": "cryptiq:fingerprint", "value": host_key.fingerprint}
        )

    return component


def _kex_component(host: str, kex: str) -> dict:
    kex_info = classify_kex(kex)
    return {
        "type": "cryptographic-asset",
        "bom-ref": _bom_ref(),
        "name": f"{host} SSH KEX ({kex})",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": "key-agreement",
                "parameterSetIdentifier": kex,
            },
            "quantumSecurityLevel": 1 if kex_info["pqc_status"] in ("hybrid", "pqc_ready") else 0,
        },
        "properties": [
            {"name": "cryptiq:host", "value": host},
            {"name": "cryptiq:kexAlgorithm", "value": kex},
            {"name": "cryptiq:pqcStatus", "value": kex_info["pqc_status"]},
            {"name": "cryptiq:riskLevel", "value": kex_info["risk_contribution"]},
        ],
    }


def _cipher_component(host: str, cipher: str) -> dict:
    cip_info = classify_cipher(cipher)
    return {
        "type": "cryptographic-asset",
        "bom-ref": _bom_ref(),
        "name": f"{host} SSH Cipher ({cipher})",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": "symmetric-encryption",
                "parameterSetIdentifier": cipher,
            },
            "quantumSecurityLevel": 1,  # symmetric ciphers need doubled key lengths, not replacement
        },
        "properties": [
            {"name": "cryptiq:host", "value": host},
            {"name": "cryptiq:cipher", "value": cipher},
            {"name": "cryptiq:weakCipher", "value": str(cip_info["weak"]).lower()},
        ],
    }


def _mac_component(host: str, mac: str) -> dict:
    mac_info = classify_mac(mac)
    return {
        "type": "cryptographic-asset",
        "bom-ref": _bom_ref(),
        "name": f"{host} SSH MAC ({mac})",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": "hash",
                "parameterSetIdentifier": mac,
            },
            "quantumSecurityLevel": 1,
        },
        "properties": [
            {"name": "cryptiq:host", "value": host},
            {"name": "cryptiq:mac", "value": mac},
            {"name": "cryptiq:weakMac", "value": str(mac_info["weak"]).lower()},
        ],
    }


# ---------------------------------------------------------------------------
# Per-scan CBOM
# ---------------------------------------------------------------------------

def generate_ssh_cbom(
    scan_result: SSHScanResult,
    risk: SSHRiskAssessment,
) -> dict:
    """
    Generate a CycloneDX CBOM for a single SSH scan result.

    Each cryptographic asset (host keys, KEX, cipher, MAC) becomes its own
    component so the inventory is maximally granular.
    """
    components = []

    # Host key components (one per key type the server advertises)
    for hk in scan_result.host_keys:
        components.append(_host_key_component(scan_result.host, hk, risk))

    # KEX component
    kex = scan_result.negotiated_kex or (
        scan_result.server_kex_algorithms[0] if scan_result.server_kex_algorithms else None
    )
    if kex:
        components.append(_kex_component(scan_result.host, kex))

    # Cipher component
    cipher = scan_result.negotiated_cipher or (
        scan_result.server_ciphers[0] if scan_result.server_ciphers else None
    )
    if cipher:
        components.append(_cipher_component(scan_result.host, cipher))

    # MAC component
    mac = scan_result.negotiated_mac or (
        scan_result.server_macs[0] if scan_result.server_macs else None
    )
    if mac:
        components.append(_mac_component(scan_result.host, mac))

    cbom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _now_iso(),
            "tools": [
                {
                    "vendor": "Cryptiq",
                    "name": "SSH Scanner",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "type": "device",
                "name": scan_result.host,
                "properties": [
                    {"name": "cryptiq:port", "value": str(scan_result.port)},
                    {"name": "cryptiq:sshVersion", "value": scan_result.ssh_version or "unknown"},
                    {"name": "cryptiq:sshProtocol", "value": scan_result.ssh_protocol or "unknown"},
                    {"name": "cryptiq:overallRisk", "value": risk.risk_level},
                    {"name": "cryptiq:pqcStatus", "value": risk.pqc_status},
                    {"name": "cryptiq:quantumVulnerable", "value": str(risk.quantum_vulnerable).lower()},
                    {"name": "cryptiq:migrationPriority", "value": risk.migration_priority},
                ],
            },
        },
        "components": components,
        "dependencies": _build_dependencies(scan_result, components),
    }

    # Attach full advertised algorithm lists as metadata for inventory purposes
    cbom["metadata"]["advertisedAlgorithms"] = {
        "kex": scan_result.server_kex_algorithms,
        "hostKey": scan_result.server_host_key_algorithms,
        "cipher": scan_result.server_ciphers,
        "mac": scan_result.server_macs,
        "compression": scan_result.server_compression,
    }

    return cbom


def _build_dependencies(scan_result: SSHScanResult, components: list[dict]) -> list[dict]:
    """
    Express that each crypto component is used by the SSH server component.
    This makes the CBOM graph navigable.
    """
    if not components:
        return []
    server_ref = _bom_ref()
    return [
        {
            "ref": server_ref,
            "dependsOn": [c["bom-ref"] for c in components],
        }
    ]


# ---------------------------------------------------------------------------
# Bulk CBOM (multiple hosts → one document)
# ---------------------------------------------------------------------------

def generate_bulk_cbom(
    scan_results: list[SSHScanResult],
    risks: list[SSHRiskAssessment],
) -> dict:
    """
    Merge multiple per-host CBOMs into a single inventory document.
    Useful for org-wide readiness reporting.
    """
    all_components = []
    metadata_hosts = []

    for scan_result, risk in zip(scan_results, risks):
        if not scan_result.scan_success:
            continue
        per_host_cbom = generate_ssh_cbom(scan_result, risk)
        all_components.extend(per_host_cbom["components"])
        metadata_hosts.append({
            "host": scan_result.host,
            "port": scan_result.port,
            "sshVersion": scan_result.ssh_version,
            "riskLevel": risk.risk_level,
            "pqcStatus": risk.pqc_status,
        })

    # Deduplicate by algorithm (same primitive on many hosts → same component type)
    # We keep all for accurate inventory counts.

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _now_iso(),
            "tools": [{"vendor": "Cryptiq", "name": "SSH Scanner", "version": "1.0.0"}],
            "properties": [
                {"name": "cryptiq:scanType", "value": "bulk-ssh"},
                {"name": "cryptiq:hostsScanned", "value": str(len(scan_results))},
                {"name": "cryptiq:hostsSucceeded", "value": str(len(metadata_hosts))},
            ],
        },
        "components": all_components,
        "externalReferences": [
            {
                "type": "documentation",
                "url": "https://cyclonedx.org/docs/1.6/",
                "comment": "CycloneDX CBOM spec",
            }
        ],
        "_cryptiq_inventory": metadata_hosts,  # non-standard extension for UI layer
    }


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def cbom_to_json(cbom: dict, indent: int = 2) -> str:
    return json.dumps(cbom, indent=indent, default=str)


def save_cbom(cbom: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(cbom_to_json(cbom))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _primitive_type(algorithm: str) -> str:
    a = algorithm.lower()
    if "rsa" in a:
        return "signature"
    if "ecdsa" in a or "dss" in a:
        return "signature"
    if "ed25519" in a or "ed448" in a:
        return "signature"
    if "ml-dsa" in a or "falcon" in a or "slh-dsa" in a:
        return "signature"
    return "unknown"


def _classical_security_level(algorithm: str, key_size: Optional[int]) -> int:
    """Approximate classical security in bits."""
    a = algorithm.lower()
    if "rsa" in a:
        if key_size is None:
            return 0
        # RSA security approximation: log2(exp(1.923 * (ln(n))^(1/3) * (ln(ln(n)))^(2/3)))
        # Rough lookup table is cleaner for inventory purposes
        table = {512: 56, 1024: 80, 2048: 112, 3072: 128, 4096: 140, 8192: 175}
        for bits, sec in sorted(table.items()):
            if key_size <= bits:
                return sec
        return 200
    if "ecdsa" in a:
        if "nistp256" in a:
            return 128
        if "nistp384" in a:
            return 192
        if "nistp521" in a:
            return 260
    if "ed25519" in a:
        return 128
    if "ed448" in a:
        return 224
    return 0


def _classify_host_key_risk(algorithm: Optional[str], key_size: Optional[int]) -> str:
    """Local shortcut for the risk level of just the host key."""
    from ssh_risk import classify_host_key
    return classify_host_key(algorithm, key_size)["risk_contribution"]