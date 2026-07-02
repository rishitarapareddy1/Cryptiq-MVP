"""
code_signing/signer.py
-------------------------
Signs files. Two paths:

  1. Native path: if the OS-appropriate signing tool is installed and
     configured (signtool.exe + a cert in the Windows cert store, macOS
     `codesign` + a Developer ID identity in Keychain, `gpg` with a
     secret key, `jarsigner` + a keystore), Cryptiq shells out to it.
     This is the path that produces a signature the OS/package manager
     actually trusts (Authenticode chain, Gatekeeper, apt/yum, etc).
     Cryptiq does NOT manage those certs/identities -- that's owned by
     your existing PKI/HSM/cert process, same as it doesn't manage your
     TLS cert chain. It only invokes the tool if it's already present.

  2. Generic path (default, always available): Cryptiq signs the file's
     SHA-256 digest with its own Ed25519/RSA-PSS key and writes a
     `<file>.cryptiq.sig.json` sidecar. Every signed file also gets an
     entry in a signed manifest (`code_signing/types.SigningManifest`),
     which is the artifact you actually hand to a counterparty/auditor.
     This is the same shape as Sigstore/in-toto attestations and is what
     "sign it for sending" means for arbitrary internal files that don't
     have an OS-native signing format (scripts, tarballs, configs, etc).

Industry note on automatic vs. manual (you asked where this is normally
triggered): in mature pipelines, signing is automatic and happens as a
CI/CD release step, immediately after build and before publish/upload --
never as a manual ad hoc action on a developer laptop, because that's
where key material leaks. Cryptiq supports both: call /codesign/sign
directly (manual/ad hoc, what's implemented here), or wire the same
function into a CI step keyed off your build artifacts directory (the
sign_directory() entrypoint below is what you'd call from CI).
"""

from __future__ import annotations

import base64
import hashlib
import shutil
import platform as _platform
import subprocess
import uuid
from pathlib import Path
from typing import Optional

from code_signing.types import (
    DiscoveredFile, FileSignature, SignerKind, SigningManifest, now_iso,
)
from code_signing import keystore
from code_signing.discovery import discover_signable_files

# Native tool -> (the shell command that checks availability, OS it requires or None for any)
# The OS gate matters: a same-named-but-unrelated binary can exist on the "wrong" OS
# (e.g. Mozilla NSS ships its own `signtool` on Linux/macOS that has nothing to do with
# Windows Authenticode) -- PATH presence alone is not sufficient evidence.
_NATIVE_AVAILABILITY_CHECK: dict[SignerKind, tuple[str, Optional[str]]] = {
    SignerKind.AUTHENTICODE: ("signtool", "Windows"),
    SignerKind.MACOS_CODESIGN: ("codesign", "Darwin"),
    SignerKind.GPG: ("gpg", None),
    SignerKind.JARSIGNER: ("jarsigner", None),
}


def native_tool_available(kind: SignerKind) -> Optional[str]:
    """Return the resolved binary path if the native signer is on PATH *and* we're
    running on the OS that tool is meaningful for, else None."""
    entry = _NATIVE_AVAILABILITY_CHECK.get(kind)
    if not entry:
        return None
    binary, required_os = entry
    if required_os and _platform.system() != required_os:
        return None
    return shutil.which(binary)


def _sha256_bytes(path: Path) -> bytes:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.digest()


def _sign_generic(path: Path, key_id: str) -> FileSignature:
    digest = _sha256_bytes(path)
    try:
        sig = keystore.sign_digest(key_id, digest)
        sidecar = {
            "file": path.name,
            "sha256": digest.hex(),
            "key_id": key_id,
            "signature_b64": base64.b64encode(sig).decode(),
            "signed_at": now_iso(),
        }
        (path.parent / f"{path.name}.cryptiq.sig.json").write_text(
            __import__("json").dumps(sidecar, indent=2)
        )
        return FileSignature(
            path=str(path), sha256=digest.hex(), signer_kind=SignerKind.GENERIC,
            algorithm=keystore.load_public_info(key_id).algorithm.value, key_id=key_id,
            signature_b64=sidecar["signature_b64"], native_tool_used=None,
            signed_at=sidecar["signed_at"], success=True,
        )
    except Exception as e:
        return FileSignature(
            path=str(path), sha256=digest.hex(), signer_kind=SignerKind.GENERIC,
            algorithm=None, key_id=key_id, signature_b64=None, native_tool_used=None,
            signed_at=now_iso(), success=False, error=str(e),
        )


def _sign_native(path: Path, kind: SignerKind, native_identity: Optional[str], dry_run: bool) -> FileSignature:
    tool = native_tool_available(kind)
    digest = _sha256_bytes(path)
    if not tool:
        # Fall back to generic and say so loudly via native_tool_used=None
        return FileSignature(
            path=str(path), sha256=digest.hex(), signer_kind=kind, algorithm=None,
            key_id=None, signature_b64=None, native_tool_used=None, signed_at=now_iso(),
            success=False, error=f"Native tool for {kind.value} not found on PATH. "
                                  f"Install it, or sign generically instead.",
        )

    cmd = _build_native_command(tool, kind, path, native_identity)
    if dry_run:
        return FileSignature(
            path=str(path), sha256=digest.hex(), signer_kind=kind, algorithm="native",
            key_id=native_identity, signature_b64=None, native_tool_used=tool,
            signed_at=now_iso(), success=True, error=f"DRY RUN — would run: {' '.join(cmd)}",
        )

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        ok = proc.returncode == 0
        return FileSignature(
            path=str(path), sha256=digest.hex(), signer_kind=kind, algorithm="native",
            key_id=native_identity, signature_b64=None, native_tool_used=tool,
            signed_at=now_iso(), success=ok,
            error=None if ok else (proc.stderr.strip() or proc.stdout.strip()),
        )
    except Exception as e:
        return FileSignature(
            path=str(path), sha256=digest.hex(), signer_kind=kind, algorithm="native",
            key_id=native_identity, signature_b64=None, native_tool_used=tool,
            signed_at=now_iso(), success=False, error=str(e),
        )


def _build_native_command(tool: str, kind: SignerKind, path: Path, identity: Optional[str]) -> list[str]:
    if kind == SignerKind.AUTHENTICODE:
        # signtool sign /sha1 <thumbprint-or-subject> /fd SHA256 /tr <timestamp-url> /td SHA256 file
        return [tool, "sign", "/sha1", identity or "", "/fd", "SHA256",
                "/tr", "http://timestamp.digicert.com", "/td", "SHA256", str(path)]
    if kind == SignerKind.MACOS_CODESIGN:
        return [tool, "--force", "--options", "runtime", "--timestamp",
                "--sign", identity or "-", str(path)]
    if kind == SignerKind.GPG:
        cmd = [tool, "--batch", "--yes", "--detach-sign", "--armor"]
        if identity:
            cmd += ["--local-user", identity]
        cmd.append(str(path))
        return cmd
    if kind == SignerKind.JARSIGNER:
        cmd = [tool, str(path), identity or "cryptiq"]
        return cmd
    raise ValueError(f"No native command builder for {kind}")


def sign_file(
    path: str,
    key_id: Optional[str] = None,
    prefer_native: bool = True,
    native_identity: Optional[str] = None,
    dry_run: bool = False,
) -> FileSignature:
    p = Path(path).expanduser().resolve()
    if not p.exists() or not p.is_file():
        return FileSignature(
            path=path, sha256="", signer_kind=SignerKind.GENERIC, algorithm=None,
            key_id=None, signature_b64=None, native_tool_used=None, signed_at=now_iso(),
            success=False, error="File does not exist.",
        )

    from code_signing.types import SIGNABLE_EXTENSIONS
    recommended = SIGNABLE_EXTENSIONS.get(p.suffix.lower(), SignerKind.GENERIC)

    if prefer_native and recommended != SignerKind.GENERIC:
        result = _sign_native(p, recommended, native_identity, dry_run)
        if result.success or result.native_tool_used:
            return result
        # native tool missing entirely -> fall through to generic below

    key = key_id or (keystore.default_key() or keystore.generate_key()).key_id
    if dry_run:
        digest = _sha256_bytes(p)
        return FileSignature(
            path=str(p), sha256=digest.hex(), signer_kind=SignerKind.GENERIC,
            algorithm="generic", key_id=key, signature_b64=None, native_tool_used=None,
            signed_at=now_iso(), success=True, error="DRY RUN — would sign with generic Ed25519/RSA-PSS scheme.",
        )
    return _sign_generic(p, key)


def sign_directory(
    root: str,
    key_id: Optional[str] = None,
    extensions: Optional[list[str]] = None,
    prefer_native: bool = True,
    native_identity: Optional[str] = None,
    dry_run: bool = False,
    max_files: int = 5000,
) -> SigningManifest:
    files: list[DiscoveredFile] = discover_signable_files(root, extensions=extensions, max_files=max_files)
    key = key_id or (keystore.default_key() or keystore.generate_key()).key_id

    manifest = SigningManifest(
        manifest_id=uuid.uuid4().hex[:16], root_path=str(Path(root).resolve()),
        key_id=key, created_at=now_iso(),
    )
    for f in files:
        sig = sign_file(
            f.path, key_id=key, prefer_native=prefer_native,
            native_identity=native_identity, dry_run=dry_run,
        )
        manifest.entries.append(sig)

    # Sign the manifest itself (over the sorted list of file sha256s) so the
    # manifest can't be tampered with after the fact without invalidating it.
    manifest_digest = hashlib.sha256(
        "".join(sorted(e.sha256 for e in manifest.entries)).encode()
    ).digest()
    if not dry_run:
        try:
            sig_bytes = keystore.sign_digest(key, manifest_digest)
            manifest.manifest_signature_b64 = base64.b64encode(sig_bytes).decode()
        except Exception:
            pass

    return manifest


def verify_file(path: str, key_id: str, signature_b64: Optional[str] = None) -> bool:
    """
    Verify a generically-signed file. If signature_b64 isn't passed, reads it
    from the `<file>.cryptiq.sig.json` sidecar next to the file.
    """
    p = Path(path).expanduser().resolve()
    digest = _sha256_bytes(p)
    if signature_b64 is None:
        sidecar = p.parent / f"{p.name}.cryptiq.sig.json"
        if not sidecar.exists():
            raise FileNotFoundError(f"No sidecar signature found for {path}")
        import json
        data = json.loads(sidecar.read_text())
        signature_b64 = data["signature_b64"]
        key_id = data.get("key_id", key_id)
    sig_bytes = base64.b64decode(signature_b64)
    return keystore.verify_digest(key_id, digest, sig_bytes)