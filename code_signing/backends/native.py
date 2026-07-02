"""
code_signing/backends/native.py
----------------------------------
Registers the existing native-tool signing paths (signer.py's
_sign_native / native_tool_available) as backends, so they show up in
GET /codesign/backends alongside anything else registered.

This file is intentionally thin — the actual OS-tool-invocation logic
still lives in signer.py (native_tool_available, sign_file). Duplicating
it here would just create two places to fix a bug; this module exists
purely so the registry has one entry per native tool for discoverability.
"""

from __future__ import annotations

from code_signing.backends import SigningBackendInfo, register
from code_signing.types import SignerKind
from code_signing import signer


def _make_native_backend(kind: SignerKind, label: str, description: str) -> SigningBackendInfo:
    def run(path: str, native_identity: str | None = None, dry_run: bool = True, **_kwargs):
        result = signer._sign_native(  # noqa: SLF001 — intentional reuse of the existing implementation
            __import__("pathlib").Path(path), kind, native_identity, dry_run,
        )
        return result.to_dict()

    return SigningBackendInfo(
        id=kind.value, label=label, kind="direct", description=description,
        available=lambda k=kind: signer.native_tool_available(k) is not None,
        run=run,
    )


register(_make_native_backend(
    SignerKind.AUTHENTICODE, "Windows Authenticode (signtool)",
    "Signs .exe/.dll/.msi/.ps1 via Windows signtool.exe against a certificate already in the "
    "Windows cert store. Only available when running on/against a Windows build agent with "
    "signtool installed and configured.",
))
register(_make_native_backend(
    SignerKind.MACOS_CODESIGN, "macOS codesign",
    "Signs .app/.dylib/.pkg via macOS `codesign` against a Developer ID identity in Keychain. "
    "Only available on macOS with a configured signing identity.",
))
register(_make_native_backend(
    SignerKind.GPG, "GPG detached signature",
    "Signs .deb/.rpm/release artifacts via `gpg --detach-sign` against a configured secret key. "
    "Available anywhere gpg is installed with a usable secret key.",
))
register(_make_native_backend(
    SignerKind.JARSIGNER, "Java jarsigner",
    "Signs .jar/.war/.ear via `jarsigner` against a configured keystore. Available anywhere a "
    "JDK is installed.",
))