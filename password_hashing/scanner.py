"""
password_hashing/scanner.py
------------------------------
Parsers that turn raw platform-specific text into PasswordHashFinding
objects. Each scanner is read-only — it only classifies what's there.

Coverage:
  - Linux/BSD /etc/shadow              (crypt(3) format markers)
  - Windows SAM/secretsdump-style dump  (user:rid:LM:NTLM:::  lines)
  - Cisco IOS / IOS-XE running-config   (password 7 / secret 5|8|9 lines)
  - Generic / database dumps            (bare md5/sha1 hex, crypt-style strings)

macOS note: modern macOS does not expose password verifiers in a flat
file the way Linux/Cisco do — they live inside the encrypted
AuthenticationAuthority/ShadowHashData plist managed by opendirectoryd,
and reading them requires root + `dscl . -read /Users/<user>
AuthenticationAuthority` mediated by the OS itself. Cryptiq does not
attempt to bypass that; macOS support here is "tell the operator how to
check/harden the policy" (see hardener.py) rather than file scanning.
"""

from __future__ import annotations

import platform as _platform
import re
from pathlib import Path
from typing import Optional

from password_hashing.types import PasswordHashFinding, Platform, ScanSummary
from password_hashing.risk import (
    classify_crypt_prefix, WINDOWS_HASH_INFO, CISCO_TYPE_INFO, GENERIC_PATTERNS,
)

_MD5_HEX = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_HEX = re.compile(r"^[a-fA-F0-9]{40}$")


def detect_local_platform() -> Platform:
    sysname = _platform.system().lower()
    if sysname == "linux":
        return Platform.LINUX
    if sysname == "darwin":
        return Platform.MACOS
    if sysname == "windows":
        return Platform.WINDOWS
    return Platform.GENERIC


def _summarize(platform: Platform, source: str, findings: list[PasswordHashFinding]) -> ScanSummary:
    by_risk: dict[str, int] = {}
    for f in findings:
        by_risk[f.risk.value] = by_risk.get(f.risk.value, 0) + 1
    return ScanSummary(platform=platform, source=source, total_findings=len(findings),
                        by_risk=by_risk, findings=findings)


# ---------------------------------------------------------------------------
# Linux /etc/shadow
# ---------------------------------------------------------------------------

def scan_shadow_text(text: str, source: str = "/etc/shadow") -> ScanSummary:
    """
    Parse /etc/shadow-formatted text:  username:hash:lastchg:min:max:warn:inactive:expire:
    Lines for locked (!,!!,*) or empty (no password set) accounts are skipped.
    """
    findings: list[PasswordHashFinding] = []
    for i, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 2:
            continue
        user, hash_field = parts[0], parts[1]
        if hash_field in ("", "*", "!", "!!") or hash_field.startswith("!"):
            continue  # locked / no password — nothing to hash-classify
        info = classify_crypt_prefix(hash_field)
        prefix = hash_field.split("$")[1] if hash_field.startswith("$") and "$" in hash_field[1:] else None
        findings.append(PasswordHashFinding(
            source=source, identifier=user, platform=Platform.LINUX, algorithm=info.name,
            risk=info.risk, reason=info.reason, recommendation=info.recommendation,
            raw_prefix=f"${prefix}$" if prefix else None, line_number=i,
        ))
    return _summarize(Platform.LINUX, source, findings)


def scan_shadow_file(path: str = "/etc/shadow") -> ScanSummary:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"{path} not found.")
    try:
        text = p.read_text()
    except PermissionError:
        raise PermissionError(
            f"Cannot read {path} — this scan must run as root (shadow is 0600 root:shadow by design)."
        )
    return scan_shadow_text(text, source=path)


# ---------------------------------------------------------------------------
# Windows (secretsdump / pwdump-style export: user:rid:LM:NTLM:::)
# ---------------------------------------------------------------------------

_EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"  # constant for "no LM hash"
_EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"  # constant for "empty NTLM"
_HEX32_RE = re.compile(r"^[a-fA-F0-9]{32}$")


def scan_windows_dump_text(text: str, source: str = "windows_dump") -> ScanSummary:
    """
    Parse pwdump/secretsdump-style lines: username:rid:LMHASH:NTHASH:::
    Cryptiq never asks for or stores these dumps long-term — this is a
    classify-and-discard operation; see API layer for handling guidance.
    """
    findings: list[PasswordHashFinding] = []
    for i, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or ":" not in line:
            continue
        parts = line.split(":")
        if len(parts) < 4:
            continue
        user, _rid, lm, nt = parts[0], parts[1], parts[2], parts[3]
        # Only treat these as real hash fields if they're actually 32-char hex --
        # otherwise a malformed/garbage line with 4 colon-separated fields would
        # get misclassified as a credential finding.
        lm_valid = bool(_HEX32_RE.match(lm))
        nt_valid = bool(_HEX32_RE.match(nt))
        if lm_valid and lm.lower() != _EMPTY_LM.lower():
            info = WINDOWS_HASH_INFO["lm"]
            findings.append(PasswordHashFinding(
                source=source, identifier=user, platform=Platform.WINDOWS, algorithm=info.name,
                risk=info.risk, reason=info.reason, recommendation=info.recommendation, line_number=i,
            ))
        if nt_valid and nt.lower() != _EMPTY_NT.lower():
            info = WINDOWS_HASH_INFO["ntlm"]
            findings.append(PasswordHashFinding(
                source=source, identifier=user, platform=Platform.WINDOWS, algorithm=info.name,
                risk=info.risk, reason=info.reason, recommendation=info.recommendation, line_number=i,
            ))
    return _summarize(Platform.WINDOWS, source, findings)


# ---------------------------------------------------------------------------
# Cisco IOS / IOS-XE running-config
# ---------------------------------------------------------------------------

_CISCO_SECRET_RE = re.compile(r"^\s*(?:enable\s+)?secret\s+(\d+)\s+\S+", re.IGNORECASE)
_CISCO_PASSWORD_RE = re.compile(r"^\s*(?:enable\s+)?password\s+(\d+)\s+\S+", re.IGNORECASE)
_CISCO_USERNAME_RE = re.compile(r"^\s*username\s+(\S+)\s+.*?(?:secret|password)\s+(\d+)\s+\S+", re.IGNORECASE)


def scan_cisco_config_text(text: str, source: str = "running-config") -> ScanSummary:
    findings: list[PasswordHashFinding] = []
    for i, line in enumerate(text.splitlines(), start=1):
        m = _CISCO_USERNAME_RE.match(line)
        if m:
            user, type_id = m.group(1), m.group(2)
        else:
            m2 = _CISCO_SECRET_RE.match(line) or _CISCO_PASSWORD_RE.match(line)
            if not m2:
                continue
            user, type_id = "(enable/line password)", m2.group(1)

        info = CISCO_TYPE_INFO.get(type_id)
        if not info:
            continue
        findings.append(PasswordHashFinding(
            source=source, identifier=user, platform=Platform.NETWORK_CISCO_IOS,
            algorithm=info.name, risk=info.risk, reason=info.reason,
            recommendation=info.recommendation, raw_prefix=f"type {type_id}", line_number=i,
        ))
    return _summarize(Platform.NETWORK_CISCO_IOS, source, findings)


# ---------------------------------------------------------------------------
# Generic: paste a single hash, a CSV column, or unknown text and classify
# ---------------------------------------------------------------------------

def classify_single_hash(value: str, identifier: str = "(value)", source: str = "manual_input") -> PasswordHashFinding:
    value = value.strip()
    if value.startswith("$"):
        info = classify_crypt_prefix(value)
        return PasswordHashFinding(
            source=source, identifier=identifier, platform=Platform.GENERIC, algorithm=info.name,
            risk=info.risk, reason=info.reason, recommendation=info.recommendation,
        )
    if _MD5_HEX.match(value):
        info = GENERIC_PATTERNS["md5_hex32"]
        return PasswordHashFinding(source=source, identifier=identifier, platform=Platform.GENERIC,
                                    algorithm=info.name, risk=info.risk, reason=info.reason,
                                    recommendation=info.recommendation)
    if _SHA1_HEX.match(value):
        info = GENERIC_PATTERNS["sha1_hex40"]
        return PasswordHashFinding(source=source, identifier=identifier, platform=Platform.GENERIC,
                                    algorithm=info.name, risk=info.risk, reason=info.reason,
                                    recommendation=info.recommendation)
    info = classify_crypt_prefix(value)  # falls through to "unknown" classification
    return PasswordHashFinding(source=source, identifier=identifier, platform=Platform.GENERIC,
                                algorithm=info.name, risk=info.risk, reason=info.reason,
                                recommendation=info.recommendation)


def scan_generic_text(text: str, source: str = "pasted_text") -> ScanSummary:
    findings = [classify_single_hash(line, identifier=f"line_{i}", source=source)
                for i, line in enumerate(text.splitlines(), start=1) if line.strip()]
    return _summarize(Platform.GENERIC, source, findings)


# ---------------------------------------------------------------------------
# PAN-OS (Palo Alto) — set-format config or XML config export
# ---------------------------------------------------------------------------
# PAN-OS stores local-account password verifiers as a "phash" field. Under
# the hood this is a standard crypt(3) string (usually $6$ SHA-512 crypt,
# $1$ MD5 crypt on very old PAN-OS) -- so once we've extracted the value,
# classification is a straight reuse of classify_crypt_prefix(), same as
# Linux. This is the whole point of the platform-plugin split in
# platforms.py: a "new platform" is very often just "a new way to locate a
# hash inside some vendor's text format", not a new hash format.

_PANOS_SET_RE = re.compile(
    r"^\s*set\s+(?:mgt-config\s+users|shared\s+local-user-database\s+user)\s+(\S+)\s+phash\s+(\S+)",
    re.IGNORECASE,
)
_PANOS_XML_ENTRY_RE = re.compile(
    r'<entry\s+name="([^"]+)">.*?<phash>([^<]+)</phash>', re.IGNORECASE | re.DOTALL,
)


def scan_panos_config_text(text: str, source: str = "panos-config") -> ScanSummary:
    findings: list[PasswordHashFinding] = []
    for i, line in enumerate(text.splitlines(), start=1):
        m = _PANOS_SET_RE.match(line)
        if not m:
            continue
        user, hash_value = m.group(1), m.group(2)
        info = classify_crypt_prefix(hash_value)
        findings.append(PasswordHashFinding(
            source=source, identifier=user, platform=Platform.NETWORK_PANOS, algorithm=info.name,
            risk=info.risk, reason=info.reason, recommendation=info.recommendation, line_number=i,
        ))
    # XML export format spans multiple lines, so scan the whole blob separately
    # from the line-oriented set-format scan above.
    for m in _PANOS_XML_ENTRY_RE.finditer(text):
        user, hash_value = m.group(1), m.group(2)
        info = classify_crypt_prefix(hash_value)
        findings.append(PasswordHashFinding(
            source=source, identifier=user, platform=Platform.NETWORK_PANOS, algorithm=info.name,
            risk=info.risk, reason=info.reason, recommendation=info.recommendation,
        ))
    return _summarize(Platform.NETWORK_PANOS, source, findings)