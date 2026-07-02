"""
code_signing/keystore.py
--------------------------
Signing key lifecycle. Mirrors ssh_migration/keygen.py's invariant:
private key material never leaves disk / is never returned over the API.

Keys live under CODESIGN_KEY_DIR (default ~/.cryptiq/codesign_keys), each as
  <key_id>.private.pem   (0600, unencrypted PEM -- see note below)
  <key_id>.public.pem

If ENCRYPTION_KEY (same env var database.py uses) is set, the private key
is additionally wrapped with Fernet before being written to disk, so a
stolen backup of the key directory alone is not enough to sign as Cryptiq.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding

from code_signing.types import SigningKeyInfo, KeyAlgorithm, now_iso

KEY_DIR = Path(os.environ.get("CODESIGN_KEY_DIR", str(Path.home() / ".cryptiq" / "codesign_keys")))


def _fernet():
    key = os.environ.get("ENCRYPTION_KEY")
    if not key:
        return None
    from cryptography.fernet import Fernet
    return Fernet(key.encode())


def _ensure_dir() -> None:
    KEY_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)


def _fingerprint(public_bytes: bytes) -> str:
    return hashlib.sha256(public_bytes).hexdigest()


def generate_key(algorithm: KeyAlgorithm = KeyAlgorithm.ED25519, label: str = "default") -> SigningKeyInfo:
    """Generate a new signing keypair and persist the private key to disk only."""
    _ensure_dir()
    key_id = uuid.uuid4().hex[:16]

    if algorithm == KeyAlgorithm.ED25519:
        priv = ed25519.Ed25519PrivateKey.generate()
    elif algorithm in (KeyAlgorithm.RSA_PSS_3072, KeyAlgorithm.RSA_PSS_4096):
        bits = 3072 if algorithm == KeyAlgorithm.RSA_PSS_3072 else 4096
        priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = priv.public_key()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    f = _fernet()
    on_disk = f.encrypt(priv_pem) if f else priv_pem
    priv_path = KEY_DIR / f"{key_id}.private.pem{'.enc' if f else ''}"
    pub_path = KEY_DIR / f"{key_id}.public.pem"

    priv_path.write_bytes(on_disk)
    os.chmod(priv_path, 0o600)
    pub_path.write_bytes(pub_pem)

    info = SigningKeyInfo(
        key_id=key_id, algorithm=algorithm, public_key_pem=pub_pem.decode(),
        fingerprint_sha256=_fingerprint(pub_pem), created_at=now_iso(), label=label,
    )
    (KEY_DIR / f"{key_id}.meta").write_text(
        f"{info.algorithm.value}|{info.created_at}|{info.label}"
    )
    return info


def _load_private(key_id: str):
    enc_path = KEY_DIR / f"{key_id}.private.pem.enc"
    plain_path = KEY_DIR / f"{key_id}.private.pem"
    f = _fernet()
    if enc_path.exists():
        if not f:
            raise RuntimeError(
                f"Key {key_id} is encrypted at rest but ENCRYPTION_KEY is not set in this environment."
            )
        priv_pem = f.decrypt(enc_path.read_bytes())
    elif plain_path.exists():
        priv_pem = plain_path.read_bytes()
    else:
        raise FileNotFoundError(f"No private key found for key_id={key_id}")
    return serialization.load_pem_private_key(priv_pem, password=None)


def load_public_info(key_id: str) -> SigningKeyInfo:
    pub_path = KEY_DIR / f"{key_id}.public.pem"
    meta_path = KEY_DIR / f"{key_id}.meta"
    if not pub_path.exists():
        raise FileNotFoundError(f"No public key found for key_id={key_id}")
    pub_pem = pub_path.read_bytes()
    algo, created_at, label = ("ed25519", now_iso(), "default")
    if meta_path.exists():
        parts = meta_path.read_text().split("|")
        if len(parts) == 3:
            algo, created_at, label = parts
    return SigningKeyInfo(
        key_id=key_id, algorithm=KeyAlgorithm(algo), public_key_pem=pub_pem.decode(),
        fingerprint_sha256=_fingerprint(pub_pem), created_at=created_at, label=label,
    )


def list_keys() -> list[SigningKeyInfo]:
    if not KEY_DIR.exists():
        return []
    out = []
    for p in KEY_DIR.glob("*.public.pem"):
        key_id = p.name.split(".public.pem")[0]
        try:
            out.append(load_public_info(key_id))
        except Exception:
            continue
    return sorted(out, key=lambda k: k.created_at, reverse=True)


def default_key() -> Optional[SigningKeyInfo]:
    keys = list_keys()
    return keys[0] if keys else None


def sign_digest(key_id: str, digest: bytes) -> bytes:
    priv = _load_private(key_id)
    if isinstance(priv, ed25519.Ed25519PrivateKey):
        return priv.sign(digest)
    if isinstance(priv, rsa.RSAPrivateKey):
        return priv.sign(
            digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    raise TypeError(f"Unsupported key type for key_id={key_id}")


def verify_digest(key_id: str, digest: bytes, signature: bytes) -> bool:
    info = load_public_info(key_id)
    pub = serialization.load_pem_public_key(info.public_key_pem.encode())
    try:
        if isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(signature, digest)
        else:
            pub.verify(
                signature, digest,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
        return True
    except Exception:
        return False