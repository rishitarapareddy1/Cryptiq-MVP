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
from dataclasses import dataclass, field
from typing import Optional

from ssh_scanner.ssh_algorithms import normalize, normalize_list, is_extension_pseudo_algo


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
class MigrationRecommendation:
    """
    A concrete, actionable recommendation produced by the risk engine.
    Replaces ad-hoc string findings with structured objects that the
    migration planner and UI can act on directly.
    """
    title: str
    severity: str                   # "critical" | "high" | "medium" | "low" | "info"
    reason: str                     # why this is a problem
    action: str                     # what to do
    estimated_effort: str           # "minutes" | "hours" | "days"
    requires_restart: bool = False
    requires_client_update: bool = False
    requires_upgrade: bool = False  # needs software version upgrade
    reference: Optional[str] = None  # NIST doc, CVE, RFC, etc.
    algorithm: Optional[str] = None  # which algorithm this applies to

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "reason": self.reason,
            "action": self.action,
            "estimated_effort": self.estimated_effort,
            "requires_restart": self.requires_restart,
            "requires_client_update": self.requires_client_update,
            "requires_upgrade": self.requires_upgrade,
            "reference": self.reference,
            "algorithm": self.algorithm,
        }


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

    # Human-readable findings (kept for backward compatibility)
    findings: list[str] = None        # type: ignore[assignment]
    migration_priority: str = "normal"  # critical | high | normal | low

    # Structured recommendations (new — use these instead of findings)
    recommendations: list = None      # type: ignore[assignment]  list[MigrationRecommendation]

    # Weighted risk score (0-100) for richer reporting
    # Host key 40%, KEX 40%, Cipher 10%, MAC 10%
    weighted_score: float = 0.0
    score_breakdown: dict = None      # type: ignore[assignment]

    # Algorithm family analysis (uses ssh_algorithms.py normalization)
    kex_families: dict = None         # type: ignore[assignment]
    host_key_family: Optional[str] = None

    def __post_init__(self):
        if self.findings is None:
            self.findings = []
        if self.recommendations is None:
            self.recommendations = []
        if self.score_breakdown is None:
            self.score_breakdown = {}
        if self.kex_families is None:
            self.kex_families = {}


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
        return {"quantum_vulnerable": True, "risk_contribution": "high",
                "findings": ["No host key algorithm detected — assume quantum-vulnerable"]}

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
        # Cannot determine KEX — treat as worst-case (high) not unknown
        # This happens when paramiko can't negotiate (e.g. very old server
        # with group1-sha1 that modern clients reject). The server is
        # definitely not PQC-safe.
        return {"quantum_vulnerable": True, "risk_contribution": "high",
                "pqc_status": "vulnerable", "findings": [
                    "KEX negotiation failed — server likely uses legacy algorithms "
                    "(group1-sha1, group14-sha1) rejected by modern SSH clients. "
                    "Treat as high risk."
                ]}

    findings = []

    if kex in QUANTUM_VULNERABLE_KEX:
        # Critical: group1 (768-bit) or SHA-1 based — both classically weak too
        parts = kex.split("-")
        uses_sha1 = parts[-1] in ("sha1", "sha1@openssh.com")
        is_group1 = "group1" in parts
        if is_group1 or uses_sha1:
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


# ---------------------------------------------------------------------------
# Weighted scoring constants
# ---------------------------------------------------------------------------

# Component weights — must sum to 100
_WEIGHT_HOST_KEY = 40
_WEIGHT_KEX      = 40
_WEIGHT_CIPHER   = 10
_WEIGHT_MAC      = 10

# Risk level -> numeric score for weighting
_RISK_SCORE = {"critical": 100, "high": 75, "medium": 40, "low": 10, "unknown": 60}

# Score thresholds -> risk level
def _score_to_risk(score: float) -> str:
    if score >= 85:  return "critical"
    if score >= 60:  return "high"
    if score >= 30:  return "medium"
    return "low"


def assess_risk(
    host: str,
    host_key_algorithm: Optional[str],
    key_size: Optional[int],
    kex_algorithm: Optional[str],
    cipher: Optional[str] = None,
    mac: Optional[str] = None,
    server_kex_algorithms: Optional[list] = None,
) -> SSHRiskAssessment:
    """
    Assess PQC risk using weighted scoring.

    Weights: host_key=40%, kex=40%, cipher=10%, mac=10%

    The weighted score (0-100) is mapped to a risk level, giving richer
    nuance than a pure max() approach. For example:
      - critical KEX + good cipher/MAC = score ~82 -> high (not critical)
      - critical KEX + critical host key = score ~100 -> critical
    The external API is unchanged: callers still get risk_level as a string.
    """
    hk = classify_host_key(host_key_algorithm, key_size)
    kex = classify_kex(kex_algorithm)
    cip = classify_cipher(cipher)
    mac_r = classify_mac(mac)

    # ── Weighted score ─────────────────────────────────────────────────
    hk_score  = _RISK_SCORE.get(hk["risk_contribution"], 60)
    kex_score = _RISK_SCORE.get(kex["risk_contribution"], 60)
    cip_score = 100 if cip["weak"] else 10
    mac_score = 60 if mac_r["weak"] else 10

    weighted = (
        hk_score  * _WEIGHT_HOST_KEY / 100 +
        kex_score * _WEIGHT_KEX      / 100 +
        cip_score * _WEIGHT_CIPHER   / 100 +
        mac_score * _WEIGHT_MAC      / 100
    )

    overall_risk = _score_to_risk(weighted)
    score_breakdown = {
        "host_key":  {"score": hk_score,  "weight": _WEIGHT_HOST_KEY, "contribution": round(hk_score * _WEIGHT_HOST_KEY / 100, 1)},
        "kex":       {"score": kex_score, "weight": _WEIGHT_KEX,      "contribution": round(kex_score * _WEIGHT_KEX / 100, 1)},
        "cipher":    {"score": cip_score, "weight": _WEIGHT_CIPHER,   "contribution": round(cip_score * _WEIGHT_CIPHER / 100, 1)},
        "mac":       {"score": mac_score, "weight": _WEIGHT_MAC,      "contribution": round(mac_score * _WEIGHT_MAC / 100, 1)},
        "total":     round(weighted, 1),
    }

    pqc_status = _derive_pqc_status(kex["pqc_status"], hk["quantum_vulnerable"])
    quantum_vulnerable = hk["quantum_vulnerable"] or kex["quantum_vulnerable"]

    all_findings = (
        hk["findings"] + kex["findings"] + cip["findings"] + mac_r["findings"]
    )

    # ── MigrationRecommendation objects ───────────────────────────────
    recs: list[MigrationRecommendation] = []

    if hk["quantum_vulnerable"] and host_key_algorithm:
        if "rsa" in (host_key_algorithm or "").lower():
            recs.append(MigrationRecommendation(
                title="Replace RSA host key with Ed25519",
                severity=hk["risk_contribution"],
                reason=f"RSA host keys are broken by Shor's algorithm on a CRQC. "
                       f"Harvest-now-decrypt-later attacks are active.",
                action="Generate Ed25519 host key and update sshd_config HostKey directive",
                estimated_effort="minutes",
                requires_restart=True,
                requires_client_update=True,
                algorithm=host_key_algorithm,
                reference="NIST SP 800-208",
            ))
        elif "ecdsa" in (host_key_algorithm or "").lower():
            recs.append(MigrationRecommendation(
                title="Replace ECDSA host key with Ed25519",
                severity="high",
                reason="ECDSA on NIST curves is Shor-vulnerable.",
                action="Generate Ed25519 host key, remove ECDSA",
                estimated_effort="minutes",
                requires_restart=True,
                algorithm=host_key_algorithm,
            ))

    if kex["quantum_vulnerable"] and kex_algorithm:
        if kex["risk_contribution"] == "critical":
            recs.append(MigrationRecommendation(
                title=f"Remove critically weak KEX: {kex_algorithm}",
                severity="critical",
                reason="SHA-1 or 768-bit DH. Classically broken, not just quantum-vulnerable.",
                action="Remove from KexAlgorithms in sshd_config. Add sntrup761x25519-sha512@openssh.com",
                estimated_effort="minutes",
                requires_restart=False,
                algorithm=kex_algorithm,
                reference="RFC 8270, NIST SP 800-175B",
            ))
        else:
            recs.append(MigrationRecommendation(
                title="Enable hybrid PQC key exchange",
                severity="high",
                reason="Current KEX is quantum-vulnerable to harvest-now-decrypt-later attacks.",
                action="Add sntrup761x25519-sha512@openssh.com to KexAlgorithms (OpenSSH 8.5+) "
                       "or mlkem768x25519-sha256 (OpenSSH 9.9+)",
                estimated_effort="minutes",
                requires_restart=False,
                algorithm=kex_algorithm,
                reference="NIST FIPS 203",
            ))

    if cip["weak"] and cipher:
        recs.append(MigrationRecommendation(
            title=f"Remove weak cipher: {cipher}",
            severity="high",
            reason="CBC mode ciphers are vulnerable to padding oracle attacks. "
                   "3DES has 64-bit block size (SWEET32).",
            action="Remove from Ciphers in sshd_config. Use chacha20-poly1305 or aes256-gcm",
            estimated_effort="minutes",
            requires_restart=False,
            algorithm=cipher,
        ))

    if mac_r["weak"] and mac:
        recs.append(MigrationRecommendation(
            title=f"Remove weak MAC: {mac}",
            severity="medium",
            reason="HMAC-MD5 and HMAC-SHA1 are cryptographically weak.",
            action="Remove from MACs in sshd_config. Use hmac-sha2-256-etm@openssh.com",
            estimated_effort="minutes",
            requires_restart=False,
            algorithm=mac,
        ))

    # ── Algorithm family normalization ────────────────────────────────
    kex_list = server_kex_algorithms or ([kex_algorithm] if kex_algorithm else [])
    real_kex = [k for k in kex_list if not is_extension_pseudo_algo(k)]
    kex_normalized = normalize_list(real_kex)

    hk_desc = normalize(host_key_algorithm) if host_key_algorithm else None
    hk_family = hk_desc.family if hk_desc else None

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
        recommendations=recs,
        weighted_score=round(weighted, 1),
        score_breakdown=score_breakdown,
        kex_families=kex_normalized.get("families", {}),
        host_key_family=hk_family,
    )


def assess_risk_from_scan(scan_result) -> SSHRiskAssessment:
    """
    Convenience wrapper: takes an SSHScanResult, picks the primary
    (first advertised) host key and the negotiated KEX/cipher/MAC.

    KEX selection priority:
      1. Negotiated KEX (what was actually agreed)
      2. Worst KEX from advertised list (most dangerous one the server offers)
         — this is more accurate for risk assessment than "first advertised"
         because we want to report the worst-case the server exposes
    """
    primary_key = scan_result.host_keys[0] if scan_result.host_keys else None

    # Pick the worst-case KEX from advertised list for risk scoring
    # "worst" = highest risk_contribution
    kex_to_score = scan_result.negotiated_kex
    if not kex_to_score and scan_result.server_kex_algorithms:
        risk_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
        worst_kex = max(
            scan_result.server_kex_algorithms,
            key=lambda k: risk_order.get(classify_kex(k)["risk_contribution"], 0)
        )
        kex_to_score = worst_kex

    return assess_risk(
        host=scan_result.host,
        host_key_algorithm=primary_key.algorithm if primary_key else None,
        key_size=primary_key.key_size if primary_key else None,
        kex_algorithm=kex_to_score,
        cipher=scan_result.negotiated_cipher or (
            scan_result.server_ciphers[0] if scan_result.server_ciphers else None
        ),
        mac=scan_result.negotiated_mac or (
            scan_result.server_macs[0] if scan_result.server_macs else None
        ),
        server_kex_algorithms=scan_result.server_kex_algorithms,
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