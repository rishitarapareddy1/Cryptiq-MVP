"""
ssh_migration/keygen.py
-----------------------
Key generation for SSH migration.

Wraps ssh-keygen (and optionally openssl) to generate:
  - Ed25519 host keys and user keys
  - RSA keys (for legacy compatibility during transition)
  - Future PQC keys (ML-DSA) once OpenSSH support ships
  - Hybrid key pairs

All generation happens locally. Keys are returned as strings or written
to specified paths. The executor module handles pushing them to remote hosts.

Design:
  generate_host_key(algorithm, output_dir, comment) -> KeyPair
  generate_user_key(algorithm, output_path, comment, passphrase) -> KeyPair
  generate_hybrid_key_pair(primary, secondary, output_dir) -> HybridKeyPair
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class KeyPair:
    algorithm: str
    private_key_path: str
    public_key_path: str
    private_key: str        # PEM / OpenSSH format string
    public_key: str         # authorized_keys format string
    fingerprint: str
    comment: str
    key_size: Optional[int] = None
    error: Optional[str] = None
    success: bool = True


@dataclass
class HybridKeyPair:
    primary: KeyPair
    secondary: KeyPair
    algorithm_ids: list[str] = field(default_factory=list)
    description: str = ""


@dataclass
class KeyGenResult:
    success: bool
    algorithm: str
    key_pair: Optional[KeyPair] = None
    error: Optional[str] = None
    command: Optional[str] = None
    stdout: str = ""
    stderr: str = ""


# ---------------------------------------------------------------------------
# Core generation functions
# ---------------------------------------------------------------------------

def _run(cmd: list[str], input_data: str = "") -> tuple[int, str, str]:
    """Run a subprocess command, return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 1, "", "Command timed out after 30s"
    except FileNotFoundError as e:
        return 1, "", f"Command not found: {e}"


def _get_fingerprint(pubkey_path: str) -> str:
    """Extract SHA-256 fingerprint from a public key file."""
    rc, stdout, stderr = _run(["ssh-keygen", "-l", "-E", "sha256", "-f", pubkey_path])
    if rc == 0:
        # Output: "256 SHA256:abc... comment (ED25519)"
        parts = stdout.strip().split()
        if len(parts) >= 2:
            return parts[1]
    return "unknown"


def _read_file(path: str) -> str:
    try:
        with open(path) as f:
            return f.read()
    except Exception:
        return ""


def generate_host_key(
    algorithm: str = "ed25519",
    output_dir: Optional[str] = None,
    comment: str = "cryptiq-migration",
    key_size: Optional[int] = None,
    passphrase: str = "",
) -> KeyGenResult:
    """
    Generate an SSH host key pair.

    Args:
        algorithm   : "ed25519", "rsa", "ecdsa", "ml-dsa-65"
        output_dir  : Directory to write key files. Uses temp dir if None.
        comment     : Key comment (appears in public key)
        key_size    : For RSA: 3072 or 4096. Ignored for Ed25519.
        passphrase  : Passphrase for private key (empty = no passphrase)

    Returns:
        KeyGenResult with the generated key pair
    """
    work_dir = output_dir or tempfile.mkdtemp(prefix="cryptiq_keygen_")
    Path(work_dir).mkdir(parents=True, exist_ok=True)

    # Map algorithm id to ssh-keygen -t argument
    type_map = {
        "ed25519": "ed25519",
        "ssh-ed25519": "ed25519",
        "rsa": "rsa",
        "ssh-rsa": "rsa",
        "ecdsa": "ecdsa",
        "ecdsa-sha2-nistp256": "ecdsa",
        "ml-dsa-65": "ml-dsa-65",    # future
    }

    keygen_type = type_map.get(algorithm.lower(), algorithm)
    key_filename = f"ssh_host_{keygen_type}_key"
    private_path = os.path.join(work_dir, key_filename)
    public_path = private_path + ".pub"

    # Remove existing key files if present
    for p in [private_path, public_path]:
        if os.path.exists(p):
            os.remove(p)

    cmd = [
        "ssh-keygen",
        "-t", keygen_type,
        "-f", private_path,
        "-C", comment,
        "-N", passphrase,  # empty string = no passphrase
        "-q",
    ]
    if key_size and keygen_type == "rsa":
        cmd += ["-b", str(key_size or 3072)]
    if key_size and keygen_type == "ecdsa":
        cmd += ["-b", str(key_size or 256)]

    rc, stdout, stderr = _run(cmd)
    cmd_str = " ".join(cmd)

    if rc != 0:
        return KeyGenResult(
            success=False,
            algorithm=algorithm,
            error=stderr.strip() or f"ssh-keygen exited with code {rc}",
            command=cmd_str,
            stdout=stdout,
            stderr=stderr,
        )

    private_key = _read_file(private_path)
    public_key = _read_file(public_path)
    fingerprint = _get_fingerprint(public_path)

    key_pair = KeyPair(
        algorithm=algorithm,
        private_key_path=private_path,
        public_key_path=public_path,
        private_key=private_key,
        public_key=public_key,
        fingerprint=fingerprint,
        comment=comment,
        key_size=key_size,
    )

    return KeyGenResult(
        success=True,
        algorithm=algorithm,
        key_pair=key_pair,
        command=cmd_str,
        stdout=stdout,
        stderr=stderr,
    )


def generate_user_key(
    algorithm: str = "ed25519",
    output_path: Optional[str] = None,
    comment: str = "",
    passphrase: str = "",
    key_size: Optional[int] = None,
) -> KeyGenResult:
    """
    Generate a user authentication key pair (for ~/.ssh/).

    Same as generate_host_key but with user-appropriate defaults
    and naming conventions.
    """
    if output_path is None:
        tmp = tempfile.mkdtemp(prefix="cryptiq_userkey_")
        type_map = {"ed25519": "id_ed25519", "rsa": "id_rsa", "ecdsa": "id_ecdsa"}
        keygen_type = algorithm.replace("ssh-", "").replace("ecdsa-sha2-nistp256", "ecdsa")
        output_path = os.path.join(tmp, type_map.get(keygen_type, f"id_{keygen_type}"))

    return generate_host_key(
        algorithm=algorithm,
        output_dir=os.path.dirname(output_path),
        comment=comment or f"user@cryptiq-migration",
        key_size=key_size,
        passphrase=passphrase,
    )


def generate_key_pair_set(
    host_key_algorithms: list[str],
    output_dir: Optional[str] = None,
    comment: str = "cryptiq-migration",
) -> dict[str, KeyGenResult]:
    """
    Generate multiple host key types at once.
    Returns dict of {algorithm_id: KeyGenResult}.

    Typical usage: generate ed25519 + (future) ml-dsa-65 together
    so the server can offer both during a transition period.
    """
    work_dir = output_dir or tempfile.mkdtemp(prefix="cryptiq_keyset_")
    Path(work_dir).mkdir(parents=True, exist_ok=True)

    results = {}
    for algo in host_key_algorithms:
        result = generate_host_key(
            algorithm=algo,
            output_dir=work_dir,
            comment=comment,
        )
        results[algo] = result
        if result.success:
            logger.info("Generated %s key: %s", algo, result.key_pair.fingerprint)
        else:
            logger.error("Failed to generate %s key: %s", algo, result.error)

    return results


# ---------------------------------------------------------------------------
# OpenSSL-based generation (for certificate-style operations)
# ---------------------------------------------------------------------------

def generate_with_openssl(
    curve: str = "prime256v1",
    output_dir: Optional[str] = None,
    comment: str = "cryptiq-openssl",
) -> KeyGenResult:
    """
    Generate an EC key using openssl genpkey.
    Useful for generating keys in PEM format for non-SSH contexts
    or for testing openssl availability.

    Supported curves: prime256v1, secp384r1, secp521r1
    """
    work_dir = output_dir or tempfile.mkdtemp(prefix="cryptiq_openssl_")
    Path(work_dir).mkdir(parents=True, exist_ok=True)

    private_path = os.path.join(work_dir, f"ec_{curve}.pem")
    public_path = os.path.join(work_dir, f"ec_{curve}.pub.pem")

    # Generate private key
    rc, stdout, stderr = _run([
        "openssl", "genpkey",
        "-algorithm", "EC",
        "-pkeyopt", f"ec_paramgen_curve:{curve}",
        "-out", private_path,
    ])
    if rc != 0:
        return KeyGenResult(
            success=False,
            algorithm=f"ecdsa-{curve}",
            error=stderr.strip(),
            stdout=stdout,
            stderr=stderr,
        )

    # Extract public key
    rc2, stdout2, stderr2 = _run([
        "openssl", "pkey", "-in", private_path, "-pubout", "-out", public_path
    ])

    private_key = _read_file(private_path)
    public_key = _read_file(public_path)

    key_pair = KeyPair(
        algorithm=f"ecdsa-{curve}",
        private_key_path=private_path,
        public_key_path=public_path,
        private_key=private_key,
        public_key=public_key,
        fingerprint="(openssl-generated)",
        comment=comment,
    )

    return KeyGenResult(
        success=True,
        algorithm=f"ecdsa-{curve}",
        key_pair=key_pair,
    )


# ---------------------------------------------------------------------------
# System checks
# ---------------------------------------------------------------------------

def check_tools() -> dict:
    """
    Check which key generation tools are available on the system.
    Returns dict of {tool: {available, version}}.
    """
    tools = {}

    # ssh-keygen
    rc, stdout, stderr = _run(["ssh-keygen", "--help"])
    # ssh-keygen --help exits with code 1 but prints to stderr
    output = stdout + stderr
    tools["ssh-keygen"] = {
        "available": "ssh-keygen" in output or rc in (0, 1),
        "version": _extract_version(output, "OpenSSH"),
    }

    # openssl
    rc, stdout, stderr = _run(["openssl", "version"])
    tools["openssl"] = {
        "available": rc == 0,
        "version": stdout.strip(),
    }

    # Check for PQC support in ssh-keygen (future)
    rc, stdout, stderr = _run(["ssh-keygen", "-t", "ml-dsa-65", "--help"])
    tools["ml-dsa-65"] = {
        "available": "ml-dsa" in (stdout + stderr).lower(),
        "version": "not yet in mainline OpenSSH",
    }

    return tools


def _extract_version(text: str, prefix: str) -> str:
    import re
    m = re.search(rf"{prefix}[_\s](\S+)", text)
    return m.group(1) if m else "unknown"