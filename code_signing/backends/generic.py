"""
code_signing/backends/generic.py
------------------------------------
Registers Cryptiq's own generic Ed25519/RSA-PSS signing path as a backend.
Always available — no external tool dependency.
"""

from __future__ import annotations

from code_signing.backends import SigningBackendInfo, register
from code_signing import signer, keystore


def run(path: str, key_id: str | None = None, dry_run: bool = True, **_kwargs):
    result = signer.sign_file(path, key_id=key_id, prefer_native=False, dry_run=dry_run)
    return result.to_dict()


register(SigningBackendInfo(
    id="generic", label="Cryptiq generic (Ed25519 / RSA-PSS)", kind="direct",
    description="Signs the SHA-256 digest of any file with an Ed25519 or RSA-PSS key managed by "
                "Cryptiq. Portable — verifiable anywhere, no OS-specific tooling required. This is "
                "the fallback for any file type without a native signer, and works for everything "
                "(scripts, configs, tarballs, arbitrary build artifacts).",
    available=lambda: True,
    run=run,
))