"""
code_signing/types.py
----------------------
Shared dataclasses for the code-signing product slice.

Design note (read this first):
  Cryptiq does NOT try to reimplement Authenticode, Apple codesign, or
  jarsigner from scratch -- those formats are proprietary/OS-owned and
  re-implementing them badly is worse than not touching them. Instead:

    1. If the platform's native signing tool is present on the machine
       Cryptiq is running on (signtool.exe, codesign, jarsigner, gpg,
       rpmsign), Cryptiq shells out to it -- this produces a signature
       the OS/package manager actually recognises (Authenticode-valid,
       notarizable, etc).
    2. For everything else (scripts, configs, tarballs, arbitrary build
       artifacts, or any host without the native tool installed), Cryptiq
       produces a generic detached signature + signed manifest, in the
       same spirit as Sigstore/in-toto: sha256 digest of the file, signed
       with Ed25519 (or RSA-PSS), recorded in a JSON manifest that is
       itself signed. This is portable, verifiable anywhere, and is what
       most companies actually use today for internal artifacts, releases,
       and supply-chain provenance (see "industry notes" in ReadMe section
       added by this change).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class SignerKind(str, Enum):
    GENERIC = "generic"                 # Cryptiq detached signature (Ed25519/RSA-PSS)
    AUTHENTICODE = "authenticode"        # Windows signtool.exe (.exe/.dll/.msi/.ps1)
    MACOS_CODESIGN = "macos_codesign"    # macOS `codesign` (.app/.dylib/Mach-O binaries)
    GPG = "gpg"                          # gpg --detach-sign (.deb/.rpm/.tar.gz/release files)
    JARSIGNER = "jarsigner"              # Java jarsigner (.jar/.war/.ear)


class KeyAlgorithm(str, Enum):
    ED25519 = "ed25519"
    RSA_PSS_3072 = "rsa-pss-3072"
    RSA_PSS_4096 = "rsa-pss-4096"


# Extensions Cryptiq will pick up during recursive discovery, mapped to the
# native signer that *should* handle them when available.
SIGNABLE_EXTENSIONS: dict[str, SignerKind] = {
    # Windows
    ".exe": SignerKind.AUTHENTICODE, ".dll": SignerKind.AUTHENTICODE,
    ".msi": SignerKind.AUTHENTICODE, ".sys": SignerKind.AUTHENTICODE,
    ".ps1": SignerKind.AUTHENTICODE, ".cab": SignerKind.AUTHENTICODE,
    # macOS
    ".app": SignerKind.MACOS_CODESIGN, ".dylib": SignerKind.MACOS_CODESIGN,
    ".pkg": SignerKind.MACOS_CODESIGN, ".framework": SignerKind.MACOS_CODESIGN,
    # Linux packages
    ".deb": SignerKind.GPG, ".rpm": SignerKind.GPG,
    # Java
    ".jar": SignerKind.JARSIGNER, ".war": SignerKind.JARSIGNER, ".ear": SignerKind.JARSIGNER,
    # Everything else Cryptiq is willing to sign generically:
    ".so": SignerKind.GENERIC, ".bin": SignerKind.GENERIC,
    ".sh": SignerKind.GENERIC, ".bash": SignerKind.GENERIC,
    ".py": SignerKind.GENERIC, ".js": SignerKind.GENERIC, ".ts": SignerKind.GENERIC,
    ".tar": SignerKind.GENERIC, ".tar.gz": SignerKind.GENERIC, ".tgz": SignerKind.GENERIC,
    ".zip": SignerKind.GENERIC, ".whl": SignerKind.GENERIC, ".gz": SignerKind.GENERIC,
    ".yaml": SignerKind.GENERIC, ".yml": SignerKind.GENERIC, ".json": SignerKind.GENERIC,
    ".tf": SignerKind.GENERIC, ".conf": SignerKind.GENERIC,
}

# Directories never worth walking into.
DEFAULT_EXCLUDE_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
    ".next", ".idea", ".vscode", "site-packages", ".pytest_cache",
}


@dataclass
class DiscoveredFile:
    path: str
    size_bytes: int
    sha256: str
    extension: str
    recommended_signer: SignerKind
    mtime: str

    def to_dict(self) -> dict:
        return {
            "path": self.path, "size_bytes": self.size_bytes, "sha256": self.sha256,
            "extension": self.extension, "recommended_signer": self.recommended_signer.value,
            "mtime": self.mtime,
        }


@dataclass
class SigningKeyInfo:
    key_id: str
    algorithm: KeyAlgorithm
    public_key_pem: str
    fingerprint_sha256: str
    created_at: str
    label: str = "default"

    def to_dict(self) -> dict:
        return {
            "key_id": self.key_id, "algorithm": self.algorithm.value,
            "public_key_pem": self.public_key_pem, "fingerprint_sha256": self.fingerprint_sha256,
            "created_at": self.created_at, "label": self.label,
        }


@dataclass
class FileSignature:
    path: str
    sha256: str
    signer_kind: SignerKind
    algorithm: Optional[str]
    key_id: Optional[str]
    signature_b64: Optional[str]
    native_tool_used: Optional[str]
    signed_at: str
    success: bool
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "path": self.path, "sha256": self.sha256, "signer_kind": self.signer_kind.value,
            "algorithm": self.algorithm, "key_id": self.key_id,
            "signature_b64": self.signature_b64, "native_tool_used": self.native_tool_used,
            "signed_at": self.signed_at, "success": self.success, "error": self.error,
        }


@dataclass
class SigningManifest:
    manifest_id: str
    root_path: str
    key_id: str
    created_at: str
    entries: list[FileSignature] = field(default_factory=list)
    manifest_signature_b64: Optional[str] = None  # signature over the manifest itself

    def to_dict(self) -> dict:
        return {
            "manifest_id": self.manifest_id, "root_path": self.root_path, "key_id": self.key_id,
            "created_at": self.created_at, "entries": [e.to_dict() for e in self.entries],
            "manifest_signature_b64": self.manifest_signature_b64,
            "file_count": len(self.entries),
            "success_count": sum(1 for e in self.entries if e.success),
        }


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()