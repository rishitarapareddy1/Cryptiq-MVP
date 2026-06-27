"""
ssh_migration/algorithms.py
---------------------------
PQC algorithm registry for SSH migration.

Defines every algorithm option the user can choose from when migrating,
including:
  - Host key algorithms (what the server presents)
  - KEX algorithms (key exchange during handshake)
  - Hybrid combinations (classical + PQC stacked)
  - Compatibility requirements (minimum OpenSSH version, etc.)

This is the source of truth for the UI algorithm picker and the
key generation / config hardening modules.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Algorithm:
    id: str                          # machine identifier
    name: str                        # display name
    type: str                        # "host_key" | "kex" | "cipher" | "mac"
    category: str                    # "classical" | "hybrid" | "pqc"
    security_level: int              # classical security bits
    quantum_security_level: int      # 0 = broken, 1 = partial, 2 = safe, 3 = recommended
    min_openssh_version: str         # e.g. "8.5"
    description: str
    nist_standard: Optional[str] = None   # e.g. "FIPS 204"
    recommended: bool = False
    deprecated: bool = False
    stacks_with: list[str] = field(default_factory=list)  # IDs of algos this pairs with
    keygen_cmd: Optional[str] = None      # ssh-keygen -t argument
    openssl_curve: Optional[str] = None   # openssl genpkey argument


# ---------------------------------------------------------------------------
# Host key algorithms
# ---------------------------------------------------------------------------

HOST_KEY_ALGORITHMS: list[Algorithm] = [
    Algorithm(
        id="ssh-ed25519",
        name="Ed25519",
        type="host_key",
        category="classical",
        security_level=128,
        quantum_security_level=1,
        min_openssh_version="6.5",
        description="Fast, compact elliptic curve signatures. Not Shor-vulnerable in the classical sense but broken by a large enough CRQC. Best classical option available today. Good migration step from RSA.",
        recommended=False,
        keygen_cmd="ed25519",
    ),
    Algorithm(
        id="ecdsa-sha2-nistp256",
        name="ECDSA P-256",
        type="host_key",
        category="classical",
        security_level=128,
        quantum_security_level=0,
        min_openssh_version="5.7",
        description="ECDSA on NIST P-256. Shor-vulnerable. Avoid for new deployments.",
        deprecated=True,
        keygen_cmd="ecdsa",
    ),
    Algorithm(
        id="ssh-rsa",
        name="RSA-3072",
        type="host_key",
        category="classical",
        security_level=128,
        quantum_security_level=0,
        min_openssh_version="2.0",
        description="RSA with 3072-bit key. Harvest-now-decrypt-later risk. Migrate away from this as a priority.",
        deprecated=True,
        keygen_cmd="rsa",
    ),
    Algorithm(
        id="ml-dsa-65",
        name="ML-DSA-65 (FIPS 204)",
        type="host_key",
        category="pqc",
        security_level=128,
        quantum_security_level=3,
        min_openssh_version="10.0",   # future — not yet in mainline
        description="NIST FIPS 204 standardised lattice-based signature scheme. The post-quantum replacement for RSA/ECDSA host keys. Requires OpenSSH 10.0+ when support ships.",
        nist_standard="FIPS 204",
        recommended=True,
    ),
    Algorithm(
        id="ml-dsa-44",
        name="ML-DSA-44 (FIPS 204, level 1)",
        type="host_key",
        category="pqc",
        security_level=128,
        quantum_security_level=2,
        min_openssh_version="10.0",
        description="Lower security level ML-DSA variant. Smaller keys/signatures at NIST level 1.",
        nist_standard="FIPS 204",
    ),
    Algorithm(
        id="ssh-ed25519+ml-dsa-65",
        name="Ed25519 + ML-DSA-65 (Hybrid)",
        type="host_key",
        category="hybrid",
        security_level=128,
        quantum_security_level=3,
        min_openssh_version="10.0",
        description="Hybrid host key combining Ed25519 (classical) and ML-DSA-65 (PQC). Both must be broken to compromise the key. Recommended transition approach.",
        nist_standard="FIPS 204",
        recommended=True,
        stacks_with=["ssh-ed25519", "ml-dsa-65"],
    ),
]

# ---------------------------------------------------------------------------
# KEX algorithms
# ---------------------------------------------------------------------------

KEX_ALGORITHMS: list[Algorithm] = [
    Algorithm(
        id="curve25519-sha256",
        name="Curve25519-SHA256",
        type="kex",
        category="classical",
        security_level=128,
        quantum_security_level=1,
        min_openssh_version="6.7",
        description="Elliptic curve Diffie-Hellman on Curve25519. Better than NIST curves but still broken by a CRQC. Good intermediate step.",
    ),
    Algorithm(
        id="sntrup761x25519-sha512",
        name="sntrup761 + Curve25519 (Hybrid)",
        type="kex",
        category="hybrid",
        security_level=128,
        quantum_security_level=2,
        min_openssh_version="8.5",
        description="NTRU Prime 761 combined with Curve25519. OpenSSH 9.x default. Provides harvest-now-decrypt-later protection. Available now — deploy immediately.",
        recommended=True,
        stacks_with=["curve25519-sha256"],
    ),
    Algorithm(
        id="mlkem768x25519-sha256",
        name="ML-KEM-768 + Curve25519 (Hybrid)",
        type="kex",
        category="hybrid",
        security_level=128,
        quantum_security_level=3,
        min_openssh_version="9.9",
        description="FIPS 203 ML-KEM-768 combined with Curve25519. IETF draft standard. The recommended hybrid KEX going forward.",
        nist_standard="FIPS 203",
        recommended=True,
        stacks_with=["curve25519-sha256"],
    ),
    Algorithm(
        id="mlkem768-sha256",
        name="ML-KEM-768 Pure PQC",
        type="kex",
        category="pqc",
        security_level=128,
        quantum_security_level=3,
        min_openssh_version="10.0",
        description="Pure ML-KEM key exchange with no classical component. Maximum PQC protection. Requires all endpoints to support it.",
        nist_standard="FIPS 203",
    ),
    Algorithm(
        id="diffie-hellman-group14-sha256",
        name="DH Group 14 SHA-256",
        type="kex",
        category="classical",
        security_level=112,
        quantum_security_level=0,
        min_openssh_version="7.4",
        description="2048-bit Diffie-Hellman. Quantum-vulnerable. Disable in favour of Curve25519 or hybrid.",
        deprecated=True,
    ),
    Algorithm(
        id="diffie-hellman-group1-sha1",
        name="DH Group 1 SHA-1 (BROKEN)",
        type="kex",
        category="classical",
        security_level=56,
        quantum_security_level=0,
        min_openssh_version="2.0",
        description="768-bit DH + SHA-1. Classically broken. Must be removed immediately.",
        deprecated=True,
    ),
]

# ---------------------------------------------------------------------------
# Cipher algorithms (for config hardening)
# ---------------------------------------------------------------------------

CIPHER_ALGORITHMS: list[Algorithm] = [
    Algorithm(
        id="chacha20-poly1305@openssh.com",
        name="ChaCha20-Poly1305",
        type="cipher",
        category="classical",
        security_level=256,
        quantum_security_level=2,
        min_openssh_version="6.5",
        description="Stream cipher + AEAD. Resistant to quantum attacks at 256-bit key length. Recommended.",
        recommended=True,
    ),
    Algorithm(
        id="aes256-gcm@openssh.com",
        name="AES-256-GCM",
        type="cipher",
        category="classical",
        security_level=256,
        quantum_security_level=2,
        min_openssh_version="6.2",
        description="AES-256 in GCM mode. 256-bit symmetric keys are sufficient against Grover's algorithm. Recommended.",
        recommended=True,
    ),
    Algorithm(
        id="aes128-gcm@openssh.com",
        name="AES-128-GCM",
        type="cipher",
        category="classical",
        security_level=128,
        quantum_security_level=1,
        min_openssh_version="6.2",
        description="AES-128 in GCM mode. Grover's algorithm halves effective key length to 64 bits. Prefer AES-256.",
    ),
    Algorithm(
        id="aes128-cbc",
        name="AES-128-CBC (deprecated)",
        type="cipher",
        category="classical",
        security_level=128,
        quantum_security_level=0,
        min_openssh_version="2.0",
        description="CBC mode is vulnerable to padding oracle attacks. Disable immediately.",
        deprecated=True,
    ),
    Algorithm(
        id="3des-cbc",
        name="3DES-CBC (broken)",
        type="cipher",
        category="classical",
        security_level=56,
        quantum_security_level=0,
        min_openssh_version="2.0",
        description="Triple DES in CBC mode. 64-bit block size (SWEET32 attack). Must be disabled.",
        deprecated=True,
    ),
]

# ---------------------------------------------------------------------------
# MAC algorithms (for config hardening)
# ---------------------------------------------------------------------------

MAC_ALGORITHMS: list[Algorithm] = [
    Algorithm(
        id="hmac-sha2-256-etm@openssh.com",
        name="HMAC-SHA2-256-ETM",
        type="mac",
        category="classical",
        security_level=256,
        quantum_security_level=2,
        min_openssh_version="6.2",
        description="Encrypt-then-MAC with SHA-256. ETM mode is more secure than MtE. Recommended.",
        recommended=True,
    ),
    Algorithm(
        id="hmac-sha2-512-etm@openssh.com",
        name="HMAC-SHA2-512-ETM",
        type="mac",
        category="classical",
        security_level=512,
        quantum_security_level=3,
        min_openssh_version="6.2",
        description="Encrypt-then-MAC with SHA-512. Maximum MAC security.",
        recommended=True,
    ),
    Algorithm(
        id="hmac-sha1",
        name="HMAC-SHA1 (deprecated)",
        type="mac",
        category="classical",
        security_level=80,
        quantum_security_level=0,
        min_openssh_version="2.0",
        description="SHA-1 is cryptographically broken. Disable immediately.",
        deprecated=True,
    ),
    Algorithm(
        id="hmac-md5",
        name="HMAC-MD5 (broken)",
        type="mac",
        category="classical",
        security_level=64,
        quantum_security_level=0,
        min_openssh_version="2.0",
        description="MD5 is cryptographically broken. Must be disabled.",
        deprecated=True,
    ),
]

# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------

ALL_ALGORITHMS: list[Algorithm] = (
    HOST_KEY_ALGORITHMS + KEX_ALGORITHMS + CIPHER_ALGORITHMS + MAC_ALGORITHMS
)

_BY_ID: dict[str, Algorithm] = {a.id: a for a in ALL_ALGORITHMS}


def get_algorithm(algo_id: str) -> Optional[Algorithm]:
    return _BY_ID.get(algo_id)


def get_recommended(algo_type: str) -> list[Algorithm]:
    return [a for a in ALL_ALGORITHMS if a.type == algo_type and a.recommended]


def get_by_category(category: str) -> list[Algorithm]:
    return [a for a in ALL_ALGORITHMS if a.category == category]


def algorithms_as_dict() -> dict:
    """Serialise all algorithms for the UI."""
    def _ser(a: Algorithm) -> dict:
        return {
            "id": a.id,
            "name": a.name,
            "type": a.type,
            "category": a.category,
            "security_level": a.security_level,
            "quantum_security_level": a.quantum_security_level,
            "min_openssh_version": a.min_openssh_version,
            "description": a.description,
            "nist_standard": a.nist_standard,
            "recommended": a.recommended,
            "deprecated": a.deprecated,
            "stacks_with": a.stacks_with,
        }
    return {
        "host_key": [_ser(a) for a in HOST_KEY_ALGORITHMS],
        "kex": [_ser(a) for a in KEX_ALGORITHMS],
        "cipher": [_ser(a) for a in CIPHER_ALGORITHMS],
        "mac": [_ser(a) for a in MAC_ALGORITHMS],
    }


# ---------------------------------------------------------------------------
# Compatibility matrix
# ---------------------------------------------------------------------------

def check_compatibility(algo_ids: list[str], openssh_version: str) -> list[dict]:
    """
    Check whether a set of chosen algorithms are compatible with a given
    OpenSSH version string (e.g. "OpenSSH_9.3").

    Returns list of compatibility issues.
    """
    issues = []
    # Parse version number from strings like "OpenSSH_9.3p1 Ubuntu-3"
    import re
    m = re.search(r"OpenSSH[_\s](\d+)\.(\d+)", openssh_version or "")
    if not m:
        return [{"algo": "unknown", "issue": f"Cannot parse OpenSSH version: {openssh_version}"}]

    maj, min_ = int(m.group(1)), int(m.group(2))
    server_ver = maj * 10 + min_

    for algo_id in algo_ids:
        algo = get_algorithm(algo_id)
        if algo is None:
            continue
        req_m = re.match(r"(\d+)\.(\d+)", algo.min_openssh_version)
        if not req_m:
            continue
        req_ver = int(req_m.group(1)) * 10 + int(req_m.group(2))
        if server_ver < req_ver:
            issues.append({
                "algo_id": algo_id,
                "algo_name": algo.name,
                "required_version": algo.min_openssh_version,
                "server_version": f"{maj}.{min_}",
                "issue": f"{algo.name} requires OpenSSH {algo.min_openssh_version} but server runs {maj}.{min_}",
            })
    return issues