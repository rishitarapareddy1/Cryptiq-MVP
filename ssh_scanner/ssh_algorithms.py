"""
ssh_scanner/ssh_algorithms.py
------------------------------
Algorithm normalization and canonical descriptors.

Solves the problem where:
    curve25519-sha256
    curve25519-sha256@libssh.org
    ecdh-sha2-curve25519

...are all the same family and should be treated identically in analytics.

Also normalizes:
    rsa-sha2-256
    rsa-sha2-512
    ssh-rsa

...into family=RSA with different signature hash strength.

Each AlgorithmDescriptor has:
    canonical_name   — normalized name for grouping
    family           — algorithm family (Curve25519, RSA, DH, ML-KEM, ...)
    algorithm_type   — kex | host_key | cipher | mac
    strength_bits    — classical security level
    quantum_bits     — post-quantum security level (0 = broken by CRQC)
    pqc_status       — vulnerable | hybrid | pqc_ready
    vendor_variants  — all known string aliases for this algorithm
    min_openssh      — minimum OpenSSH version that supports this
    deprecated       — should be removed from configs
    recommended      — should be included in hardened configs
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AlgorithmDescriptor:
    canonical_name: str
    family: str
    algorithm_type: str         # "kex" | "host_key" | "cipher" | "mac"
    strength_bits: int          # classical security
    quantum_bits: int           # 0 = broken, 64 = partial, 128 = safe, 256 = strong
    pqc_status: str             # "vulnerable" | "hybrid" | "pqc_ready"
    vendor_variants: list[str] = field(default_factory=list)
    min_openssh: Optional[str] = None
    deprecated: bool = False
    recommended: bool = False
    notes: str = ""

    @property
    def risk_level(self) -> str:
        if self.quantum_bits == 0:
            if self.strength_bits < 80:
                return "critical"
            return "high"
        if self.quantum_bits < 128:
            return "medium"
        return "low"


# ---------------------------------------------------------------------------
# KEX algorithm registry
# ---------------------------------------------------------------------------

KEX_DESCRIPTORS: list[AlgorithmDescriptor] = [
    # ── Broken / critical ────────────────────────────────────────────────
    AlgorithmDescriptor(
        canonical_name="diffie-hellman-group1",
        family="DH-Group1",
        algorithm_type="kex",
        strength_bits=56, quantum_bits=0,
        pqc_status="vulnerable",
        vendor_variants=["diffie-hellman-group1-sha1"],
        min_openssh="2.0",
        deprecated=True,
        notes="768-bit MODP group + SHA-1. Logjam attack (2015). Remove immediately.",
    ),
    AlgorithmDescriptor(
        canonical_name="diffie-hellman-group14-sha1",
        family="DH-Group14",
        algorithm_type="kex",
        strength_bits=112, quantum_bits=0,
        pqc_status="vulnerable",
        vendor_variants=["diffie-hellman-group14-sha1"],
        min_openssh="2.0",
        deprecated=True,
        notes="2048-bit DH + SHA-1. SHA-1 is broken. Remove.",
    ),
    # ── Quantum vulnerable but classically ok ────────────────────────────
    AlgorithmDescriptor(
        canonical_name="diffie-hellman-group14-sha256",
        family="DH-Group14",
        algorithm_type="kex",
        strength_bits=112, quantum_bits=0,
        pqc_status="vulnerable",
        vendor_variants=["diffie-hellman-group14-sha256"],
        min_openssh="7.4",
        deprecated=True,
        notes="2048-bit DH + SHA-256. Quantum-vulnerable. Replace with curve25519 minimum.",
    ),
    AlgorithmDescriptor(
        canonical_name="diffie-hellman-group16-sha512",
        family="DH-Group16",
        algorithm_type="kex",
        strength_bits=128, quantum_bits=0,
        pqc_status="vulnerable",
        vendor_variants=["diffie-hellman-group16-sha512"],
        min_openssh="7.4",
        notes="4096-bit DH. Classically strong, quantum-vulnerable.",
    ),
    AlgorithmDescriptor(
        canonical_name="diffie-hellman-group18-sha512",
        family="DH-Group18",
        algorithm_type="kex",
        strength_bits=192, quantum_bits=0,
        pqc_status="vulnerable",
        vendor_variants=["diffie-hellman-group18-sha512"],
        min_openssh="7.4",
        notes="8192-bit DH. Classically very strong, still quantum-vulnerable.",
    ),
    AlgorithmDescriptor(
        canonical_name="ecdh-nistp256",
        family="ECDH-NIST",
        algorithm_type="kex",
        strength_bits=128, quantum_bits=0,
        pqc_status="vulnerable",
        vendor_variants=["ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521"],
        min_openssh="5.7",
        deprecated=False,
        notes="ECDH on NIST curves. Shor-vulnerable. Replace with Curve25519 or hybrid.",
    ),
    # ── Classical best ───────────────────────────────────────────────────
    AlgorithmDescriptor(
        canonical_name="curve25519-sha256",
        family="Curve25519",
        algorithm_type="kex",
        strength_bits=128, quantum_bits=0,
        pqc_status="vulnerable",
        vendor_variants=[
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
            "ecdh-sha2-curve25519",
        ],
        min_openssh="6.7",
        recommended=False,
        notes="Best classical KEX. Not Shor-vulnerable via standard path but CRQC-broken. "
              "Good baseline but add hybrid PQC on top.",
    ),
    # ── Hybrid PQC ───────────────────────────────────────────────────────
    AlgorithmDescriptor(
        canonical_name="sntrup761x25519",
        family="NTRU-Hybrid",
        algorithm_type="kex",
        strength_bits=128, quantum_bits=128,
        pqc_status="hybrid",
        vendor_variants=[
            "sntrup761x25519-sha512@openssh.com",
            "sntrup761x25519-sha512",
        ],
        min_openssh="8.5",
        recommended=True,
        notes="NTRU Prime 761 + Curve25519 hybrid. OpenSSH 9.x default. "
              "Deploy now — no upgrade needed on most servers.",
    ),
    AlgorithmDescriptor(
        canonical_name="mlkem768x25519",
        family="ML-KEM-Hybrid",
        algorithm_type="kex",
        strength_bits=128, quantum_bits=192,
        pqc_status="hybrid",
        vendor_variants=[
            "mlkem768x25519-sha256",
            "x25519-kyber-512r3-sha256-d00@amazon.com",
        ],
        min_openssh="9.9",
        recommended=True,
        notes="ML-KEM-768 (FIPS 203) + Curve25519 hybrid. IETF standard. "
              "Best currently available. Requires OpenSSH 9.9+.",
    ),
    # ── Pure PQC ─────────────────────────────────────────────────────────
    AlgorithmDescriptor(
        canonical_name="mlkem768",
        family="ML-KEM",
        algorithm_type="kex",
        strength_bits=128, quantum_bits=256,
        pqc_status="pqc_ready",
        vendor_variants=["mlkem768-sha256", "mlkem1024-sha384"],
        min_openssh="10.0",
        recommended=True,
        notes="Pure ML-KEM. NIST FIPS 203 standard. Requires OpenSSH 10.0+ (not yet released).",
    ),
    # ── Internal / extension pseudoalgorithms ────────────────────────────
    AlgorithmDescriptor(
        canonical_name="kex-strict",
        family="Extension",
        algorithm_type="kex",
        strength_bits=0, quantum_bits=0,
        pqc_status="vulnerable",
        vendor_variants=["kex-strict-s-v00@openssh.com", "kex-strict-c-v00@openssh.com"],
        min_openssh="9.6",
        notes="Terrapin attack mitigation extension. Not a real KEX — ignore in scoring.",
    ),
    AlgorithmDescriptor(
        canonical_name="ext-info",
        family="Extension",
        algorithm_type="kex",
        strength_bits=0, quantum_bits=0,
        pqc_status="vulnerable",
        vendor_variants=["ext-info-s", "ext-info-c"],
        min_openssh="7.2",
        notes="Extension negotiation signal. Not a real KEX — ignore in scoring.",
    ),
]

# ---------------------------------------------------------------------------
# Host key algorithm registry
# ---------------------------------------------------------------------------

HOST_KEY_DESCRIPTORS: list[AlgorithmDescriptor] = [
    AlgorithmDescriptor(
        canonical_name="rsa",
        family="RSA",
        algorithm_type="host_key",
        strength_bits=112, quantum_bits=0,
        pqc_status="vulnerable",
        vendor_variants=["ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"],
        min_openssh="2.0",
        deprecated=False,
        notes="RSA with SHA-1 (ssh-rsa) or SHA-256/512 (rsa-sha2-*). "
              "All variants Shor-vulnerable. Replace with Ed25519.",
    ),
    AlgorithmDescriptor(
        canonical_name="dsa",
        family="DSA",
        algorithm_type="host_key",
        strength_bits=56, quantum_bits=0,
        pqc_status="vulnerable",
        vendor_variants=["ssh-dss"],
        min_openssh="2.0",
        deprecated=True,
        notes="1024-bit DSA. Classically broken (too small). Remove immediately.",
    ),
    AlgorithmDescriptor(
        canonical_name="ecdsa-nist",
        family="ECDSA-NIST",
        algorithm_type="host_key",
        strength_bits=128, quantum_bits=0,
        pqc_status="vulnerable",
        vendor_variants=[
            "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
            "sk-ecdsa-sha2-nistp256@openssh.com",
        ],
        min_openssh="5.7",
        deprecated=False,
        notes="ECDSA on NIST curves. Shor-vulnerable. Replace with Ed25519.",
    ),
    AlgorithmDescriptor(
        canonical_name="ed25519",
        family="EdDSA",
        algorithm_type="host_key",
        strength_bits=128, quantum_bits=64,
        pqc_status="vulnerable",
        vendor_variants=["ssh-ed25519", "sk-ssh-ed25519@openssh.com", "ssh-ed448"],
        min_openssh="6.5",
        recommended=True,
        notes="Edwards curve signatures. Not immediately Shor-vulnerable but not PQC-safe. "
              "Best classical host key. Use until ML-DSA is available.",
    ),
    AlgorithmDescriptor(
        canonical_name="ml-dsa",
        family="ML-DSA",
        algorithm_type="host_key",
        strength_bits=128, quantum_bits=256,
        pqc_status="pqc_ready",
        vendor_variants=["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"],
        min_openssh="10.0",
        recommended=True,
        notes="NIST FIPS 204 lattice-based signatures. Post-quantum safe. "
              "Requires OpenSSH 10.0+ (not yet released).",
    ),
]

# ---------------------------------------------------------------------------
# Build lookup tables
# ---------------------------------------------------------------------------

_ALL_DESCRIPTORS: list[AlgorithmDescriptor] = KEX_DESCRIPTORS + HOST_KEY_DESCRIPTORS

# Map every variant string -> canonical descriptor
_VARIANT_TO_DESCRIPTOR: dict[str, AlgorithmDescriptor] = {}
for _desc in _ALL_DESCRIPTORS:
    for _variant in _desc.vendor_variants:
        _VARIANT_TO_DESCRIPTOR[_variant.lower()] = _desc


def normalize(algorithm: str) -> Optional[AlgorithmDescriptor]:
    """
    Look up an algorithm string and return its canonical descriptor.
    Returns None if the algorithm is unknown.

    Examples:
        normalize("curve25519-sha256@libssh.org")
            -> AlgorithmDescriptor(canonical_name="curve25519-sha256", family="Curve25519", ...)

        normalize("rsa-sha2-256")
            -> AlgorithmDescriptor(canonical_name="rsa", family="RSA", ...)
    """
    return _VARIANT_TO_DESCRIPTOR.get(algorithm.lower())


def normalize_list(algorithms: list[str]) -> dict:
    """
    Normalize a list of algorithm strings.
    Returns a dict grouping by family, with deduplicated descriptors.

    Useful for analytics: "this server has 3 variants of Curve25519" → family=Curve25519 count=1
    """
    families: dict[str, AlgorithmDescriptor] = {}
    unknown: list[str] = []
    extension_flags: list[str] = []

    for algo in algorithms:
        desc = normalize(algo)
        if desc is None:
            unknown.append(algo)
        elif desc.family == "Extension":
            extension_flags.append(algo)
        elif desc.canonical_name not in families:
            families[desc.canonical_name] = desc

    return {
        "families": {name: desc for name, desc in families.items()},
        "unknown": unknown,
        "extension_flags": extension_flags,
        "worst_risk": _worst_risk(list(families.values())),
        "best_pqc": _best_pqc(list(families.values())),
    }


def _worst_risk(descriptors: list[AlgorithmDescriptor]) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    if not descriptors:
        return "unknown"
    return max((d.risk_level for d in descriptors), key=lambda r: order.get(r, 0))


def _best_pqc(descriptors: list[AlgorithmDescriptor]) -> str:
    order = {"pqc_ready": 3, "hybrid": 2, "vulnerable": 1}
    if not descriptors:
        return "unknown"
    return max((d.pqc_status for d in descriptors), key=lambda s: order.get(s, 0))


def is_extension_pseudo_algo(algorithm: str) -> bool:
    """Return True for kex-strict, ext-info, etc. — ignore these in scoring."""
    desc = normalize(algorithm)
    return desc is not None and desc.family == "Extension"