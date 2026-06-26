"""
ssh_risk.py
-----------
PQC risk classification for SSH cryptographic assets.

Mirrors tls_risk.py but tuned for SSH primitives:
  - Host key algorithms (RSA, ECDSA, Ed25519, …)
  - Key exchange algorithms (DH groups, ECDH, Curve25519, ML-KEM hybrids, …)
  - Ciphers (symmetric — not quantum-vulnerable, but flagged if weak)
  - MACs  (not quantum-vulnerable per se, but flagged if weak)

Risk levels:
  critical  — actively broken OR trivially harvested by a CRQC today
  high      — Shor-vulnerable; priority migration target
  medium    — quantum-safe symmetric/hash but relies on vulnerable KEX/keys
  low       — PQC or hybrid; current best practice
  unknown   — algorithm not in our taxonomy

PQC statuses:
  vulnerable   — no PQC protection whatsoever
  hybrid       — classical + PQC hybrid (e.g. OpenSSH 9.x sntrup761x25519)
  pqc_ready    — standardised PQC algorithm (post-NIST finalisation)
  unknown      — cannot determine
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# Algorithm taxonomies
# ---------------------------------------------------------------------------

# Host-key algorithms broken down by quantum vulnerability
QUANTUM_VULNERABLE_HOST_KEY_ALGOS = {
    # RSA (all variants)
    "ssh-rsa",
    "rsa-sha2-256",
    "rsa-sha2-512",
    # DSA
    "ssh-dss",
    # ECDSA (NIST curves — discrete log on elliptic curves, Shor-vulnerable)
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ecdsa-sha2-nistp256@openssh.com",
}

# Ed25519 / Ed448: NOT Shor-vulnerable in the classical sense, but still
# broken by a large enough CRQC via Pollard-rho or similar.
# We flag these as "medium" — better than RSA/ECDSA but not PQC-safe.
MEDIUM_RISK_HOST_KEY_ALGOS = {
    "ssh-ed25519",
    "sk-ssh-ed25519@openssh.com",
    "ssh-ed448",
}

# Standardised PQC host key algorithms (post NIST finalisation, SSH drafts)
PQC_HOST_KEY_ALGOS = {
    "ml-dsa-65",          # FIPS 204
    "slh-dsa-sha2-128s",  # FIPS 205
    "falcon-512",
    "falcon-1024",
}

# KEX algorithms
QUANTUM_VULNERABLE_KEX = {
    # Classic DH
    "diffie-hellman-group1-sha1",    # CRITICAL — 768-bit, SHA-1
    "diffie-hellman-group14-sha1",   # HIGH — SHA-1
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group-exchange-sha256",
    # ECDH (Shor-vulnerable)
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
}

# Curve25519/448 — not Shor-vulnerable in the classical sense but still
# broken by a CRQC; better than ECDH on NIST curves
MEDIUM_RISK_KEX = {
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "curve448-sha512",
    "ecdh-sha2-curve25519",
}

# PQC / hybrid KEX
HYBRID_KEX = {
    # OpenSSH 9.x default
    "sntrup761x25519-sha512@openssh.com",
    "sntrup761x25519-sha512",
    "mlkem768x25519-sha256",          # IETF draft-josefsson
    "x25519-kyber-512r3-sha256-d00@amazon.com",
}

PQC_KEX = {
    "mlkem768-sha256",   # pure ML-KEM (FIPS 203)
    "mlkem1024-sha384",
}

# Weak ciphers (classical security concern, included for completeness)
WEAK_CIPHERS = {
    "3des-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
    "blowfish-cbc",
    "cast128-cbc",
    "aes128-cbc",   # CBC mode oracle-vulnerable
    "aes192-cbc",
    "aes256-cbc",
}

# Weak MACs
WEAK_MACS = {
    "hmac-md5",
    "hmac-md5-96",
    "hmac-sha1",
    "hmac-sha1-96",
    "umac-32@openssh.com",
    "umac-64@openssh.com",
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class SSHRiskAssessment:
    # Inputs (populated for context)
    host: str
    host_key_algorithm: Optional[str]
    key_size: Optional[int]
    kex_algorithm: Optional[str]
    cipher: Optional[str]
    mac: Optional[str]

    # Risk outputs
    quantum_vulnerable: bool = False
    risk_level: str = "unknown"       # critical | high | medium | low | unknown
    pqc_status: str = "unknown"       # vulnerable | hybrid | pqc_ready | unknown

    # Granular flags
    host_key_quantum_vulnerable: bool = False
    kex_quantum_vulnerable: bool = False
    weak_cipher: bool = False
    weak_mac: bool = False

    # Human-readable findings
    findings: list[str] = None        # type: ignore[assignment]
    migration_priority: str = "normal"  # critical | high | normal | low

    def __post_init__(self):
        if self.findings is None:
            self.findings = []


# ---------------------------------------------------------------------------
# Individual classifiers
# ---------------------------------------------------------------------------

def classify_host_key(algorithm: Optional[str], key_size: Optional[int]) -> dict:
    """
    Returns:
        quantum_vulnerable : bool
        risk_contribution  : "critical" | "high" | "medium" | "low" | "unknown"
        findings           : list[str]
    """
    if algorithm is None:
        return {"quantum_vulnerable": True, "risk_contribution": "unknown", "findings": ["No host key algorithm detected"]}

    findings = []
    algo = algorithm.lower()

    if algorithm in QUANTUM_VULNERABLE_HOST_KEY_ALGOS:
        if "rsa" in algo:
            if key_size is not None and key_size < 2048:
                findings.append(f"RSA host key too small ({key_size}-bit) — critical classical AND quantum risk")
                return {"quantum_vulnerable": True, "risk_contribution": "critical", "findings": findings}
            findings.append(f"RSA host key ({key_size or '?'}-bit) — Shor-vulnerable, harvest-now-decrypt-later risk")
            return {"quantum_vulnerable": True, "risk_contribution": "high", "findings": findings}
        if "ecdsa" in algo or "dss" in algo:
            findings.append(f"ECDSA/DSA host key — Shor-vulnerable")
            return {"quantum_vulnerable": True, "risk_contribution": "high", "findings": findings}

    if algorithm in MEDIUM_RISK_HOST_KEY_ALGOS:
        findings.append(f"Ed25519/Ed448 host key — not immediately Shor-vulnerable but not PQC-safe")
        return {"quantum_vulnerable": False, "risk_contribution": "medium", "findings": findings}

    if algorithm in PQC_HOST_KEY_ALGOS:
        findings.append(f"PQC host key algorithm ({algorithm}) — quantum-safe")
        return {"quantum_vulnerable": False, "risk_contribution": "low", "findings": findings}

    findings.append(f"Unknown host key algorithm: {algorithm}")
    return {"quantum_vulnerable": True, "risk_contribution": "unknown", "findings": findings}


def classify_kex(kex: Optional[str]) -> dict:
    """
    Returns:
        quantum_vulnerable : bool
        risk_contribution  : "critical" | "high" | "medium" | "low" | "unknown"
        pqc_status         : "vulnerable" | "hybrid" | "pqc_ready" | "unknown"
        findings           : list[str]
    """
    if kex is None:
        return {"quantum_vulnerable": True, "risk_contribution": "unknown",
                "pqc_status": "unknown", "findings": ["No KEX algorithm detected"]}

    findings = []

    if kex in QUANTUM_VULNERABLE_KEX:
        if "group1" in kex or "sha1" in kex.split("-")[-1]:
            findings.append(f"Critically weak KEX: {kex} (legacy DH + SHA-1)")
            return {"quantum_vulnerable": True, "risk_contribution": "critical",
                    "pqc_status": "vulnerable", "findings": findings}
        findings.append(f"Quantum-vulnerable KEX: {kex}")
        return {"quantum_vulnerable": True, "risk_contribution": "high",
                "pqc_status": "vulnerable", "findings": findings}

    if kex in MEDIUM_RISK_KEX:
        findings.append(f"Curve25519 KEX: {kex} — better than ECDH/DH but still not PQC-safe")
        return {"quantum_vulnerable": False, "risk_contribution": "medium",
                "pqc_status": "vulnerable", "findings": findings}

    if kex in HYBRID_KEX:
        findings.append(f"Hybrid PQC KEX: {kex} — provides harvest-now-decrypt-later protection")
        return {"quantum_vulnerable": False, "risk_contribution": "low",
                "pqc_status": "hybrid", "findings": findings}

    if kex in PQC_KEX:
        findings.append(f"Pure PQC KEX: {kex} — quantum-safe")
        return {"quantum_vulnerable": False, "risk_contribution": "low",
                "pqc_status": "pqc_ready", "findings": findings}

    findings.append(f"Unknown KEX: {kex}")
    return {"quantum_vulnerable": True, "risk_contribution": "unknown",
            "pqc_status": "unknown", "findings": findings}


def classify_cipher(cipher: Optional[str]) -> dict:
    if cipher and cipher in WEAK_CIPHERS:
        return {"weak": True, "findings": [f"Weak/deprecated cipher: {cipher}"]}
    return {"weak": False, "findings": []}


def classify_mac(mac: Optional[str]) -> dict:
    if mac and mac in WEAK_MACS:
        return {"weak": True, "findings": [f"Weak/deprecated MAC: {mac}"]}
    return {"weak": False, "findings": []}


# ---------------------------------------------------------------------------
# Risk aggregation
# ---------------------------------------------------------------------------

_RISK_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


def _max_risk(*levels: str) -> str:
    return max(levels, key=lambda l: _RISK_ORDER.get(l, 0))


def _derive_pqc_status(kex_status: str, host_key_quantum_vulnerable: bool) -> str:
    """
    The overall PQC status is the worst of KEX and host key.
    If either is vulnerable, the session key agreement or authentication
    can be broken by a CRQC.
    """
    if host_key_quantum_vulnerable:
        return "vulnerable"
    return kex_status


def _migration_priority(risk_level: str, host_key_algo: Optional[str], key_size: Optional[int]) -> str:
    if risk_level == "critical":
        return "critical"
    if risk_level == "high":
        # RSA-1024 or smaller → critical priority
        if host_key_algo and "rsa" in host_key_algo.lower():
            if key_size is not None and key_size < 2048:
                return "critical"
        return "high"
    if risk_level == "medium":
        return "normal"
    return "low"


def assess_risk(
    host: str,
    host_key_algorithm: Optional[str],
    key_size: Optional[int],
    kex_algorithm: Optional[str],
    cipher: Optional[str] = None,
    mac: Optional[str] = None,
) -> SSHRiskAssessment:
    """
    Assess PQC risk for a single SSH session's crypto parameters.
    """
    hk = classify_host_key(host_key_algorithm, key_size)
    kex = classify_kex(kex_algorithm)
    cip = classify_cipher(cipher)
    mac_r = classify_mac(mac)

    overall_risk = _max_risk(
        hk["risk_contribution"],
        kex["risk_contribution"],
        "high" if cip["weak"] else "low",
        "medium" if mac_r["weak"] else "low",
    )

    pqc_status = _derive_pqc_status(kex["pqc_status"], hk["quantum_vulnerable"])
    quantum_vulnerable = hk["quantum_vulnerable"] or kex["quantum_vulnerable"]

    all_findings = (
        hk["findings"]
        + kex["findings"]
        + cip["findings"]
        + mac_r["findings"]
    )

    return SSHRiskAssessment(
        host=host,
        host_key_algorithm=host_key_algorithm,
        key_size=key_size,
        kex_algorithm=kex_algorithm,
        cipher=cipher,
        mac=mac,
        quantum_vulnerable=quantum_vulnerable,
        risk_level=overall_risk,
        pqc_status=pqc_status,
        host_key_quantum_vulnerable=hk["quantum_vulnerable"],
        kex_quantum_vulnerable=kex["quantum_vulnerable"],
        weak_cipher=cip["weak"],
        weak_mac=mac_r["weak"],
        findings=all_findings,
        migration_priority=_migration_priority(overall_risk, host_key_algorithm, key_size),
    )


def assess_risk_from_scan(scan_result) -> SSHRiskAssessment:
    """
    Convenience wrapper: takes an SSHScanResult, picks the primary
    (first advertised) host key and the negotiated KEX/cipher/MAC.
    """
    primary_key = scan_result.host_keys[0] if scan_result.host_keys else None
    return assess_risk(
        host=scan_result.host,
        host_key_algorithm=primary_key.algorithm if primary_key else None,
        key_size=primary_key.key_size if primary_key else None,
        kex_algorithm=scan_result.negotiated_kex or (
            scan_result.server_kex_algorithms[0] if scan_result.server_kex_algorithms else None
        ),
        cipher=scan_result.negotiated_cipher or (
            scan_result.server_ciphers[0] if scan_result.server_ciphers else None
        ),
        mac=scan_result.negotiated_mac or (
            scan_result.server_macs[0] if scan_result.server_macs else None
        ),
    )


# ---------------------------------------------------------------------------
# Bulk summary
# ---------------------------------------------------------------------------

def summarise_risk_assessments(assessments: list[SSHRiskAssessment]) -> dict:
    """
    Aggregate multiple assessments into an inventory summary.
    This is the organisational view the product is meant to provide.
    """
    total = len(assessments)
    by_risk = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    by_pqc_status = {"vulnerable": 0, "hybrid": 0, "pqc_ready": 0, "unknown": 0}
    by_host_key_algo: dict[str, int] = {}
    by_kex_algo: dict[str, int] = {}
    quantum_vulnerable_count = 0

    for a in assessments:
        by_risk[a.risk_level] = by_risk.get(a.risk_level, 0) + 1
        by_pqc_status[a.pqc_status] = by_pqc_status.get(a.pqc_status, 0) + 1
        if a.quantum_vulnerable:
            quantum_vulnerable_count += 1
        if a.host_key_algorithm:
            by_host_key_algo[a.host_key_algorithm] = by_host_key_algo.get(a.host_key_algorithm, 0) + 1
        if a.kex_algorithm:
            by_kex_algo[a.kex_algorithm] = by_kex_algo.get(a.kex_algorithm, 0) + 1

    pqc_ready_pct = (
        round(by_pqc_status["pqc_ready"] / total * 100, 1) if total > 0 else 0.0
    )

    return {
        "total_scanned": total,
        "quantum_vulnerable": quantum_vulnerable_count,
        "by_risk_level": by_risk,
        "by_pqc_status": by_pqc_status,
        "by_host_key_algorithm": dict(
            sorted(by_host_key_algo.items(), key=lambda x: -x[1])
        ),
        "by_kex_algorithm": dict(
            sorted(by_kex_algo.items(), key=lambda x: -x[1])
        ),
        "pqc_readiness_percent": pqc_ready_pct,
        "critical_migration_targets": [
            a.host for a in assessments if a.migration_priority == "critical"
        ],
        "high_priority_targets": [
            a.host for a in assessments if a.migration_priority == "high"
        ],
    }