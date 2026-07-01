"""
ssh_scanner/ssh_versions.py
---------------------------
SSH software lifecycle knowledge base.

Parses SSH banners into structured SoftwareInfo objects with:
  - Vendor / distribution detection
  - Version parsing (major, minor, patch, release)
  - Support status (is the software still maintained?)
  - PQC capability (what algorithms does this version support?)
  - EOL dates

This is separate from configuration — a server can RUN OpenSSH 9.8
but be CONFIGURED to only use curve25519. Both matter for migration.

Banner examples:
  SSH-2.0-OpenSSH_9.8p1 Ubuntu-3
  SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8
  SSH-2.0-dropbear_2022.83
  SSH-2.0-Cisco-1.25
  SSH-2.0-babeld-...
  SSH-2.0-ROSSSH
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class SoftwareInfo:
    # Identity
    raw_version: str                    # e.g. "OpenSSH_9.8p1 Ubuntu-3"
    vendor: str                         # "OpenSSH" | "Dropbear" | "Cisco" | ...
    distribution: Optional[str]         # "Ubuntu" | "Debian" | "RHEL" | None

    # Version components
    major: int = 0
    minor: int = 0
    patch: int = 0                      # p1, p2, etc.
    release_string: Optional[str] = None  # full version string like "9.8p1"

    # Lifecycle
    release_year: Optional[int] = None
    is_supported: bool = True           # still receiving security patches?
    eol: bool = False                   # explicitly end-of-life?
    eol_reason: Optional[str] = None

    # PQC capabilities (what this VERSION can support, regardless of config)
    supports_mlkem: bool = False        # ML-KEM-768 (FIPS 203) — OpenSSH 9.9+
    supports_sntrup761: bool = False    # sntrup761x25519 hybrid — OpenSSH 8.5+
    supports_curve25519: bool = False   # Curve25519 — OpenSSH 6.7+
    supports_ed25519: bool = False      # Ed25519 host key — OpenSSH 6.5+
    supports_chacha20: bool = False     # ChaCha20-Poly1305 — OpenSSH 6.5+
    supports_etm_macs: bool = False     # ETM MACs — OpenSSH 6.2+

    # Migration implications
    can_be_hardened: bool = True        # can config be improved without upgrade?
    requires_upgrade_for_pqc: bool = True  # needs newer version for any PQC?
    upgrade_target: Optional[str] = None   # recommended version to upgrade to

    # Notes
    notes: list[str] = field(default_factory=list)

    @property
    def version_tuple(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)

    @property
    def version_display(self) -> str:
        if self.release_string:
            return f"{self.vendor} {self.release_string}"
        return f"{self.vendor} {self.major}.{self.minor}"

    @property
    def pqc_capability_level(self) -> str:
        """What's the best PQC this version can achieve?"""
        if self.supports_mlkem:
            return "pqc_ready"      # can do pure PQC KEX
        if self.supports_sntrup761:
            return "hybrid"         # can do hybrid PQC KEX
        if self.supports_curve25519:
            return "classical_best" # best classical, no PQC
        return "legacy"             # old DH only

    def to_dict(self) -> dict:
        return {
            "raw_version": self.raw_version,
            "vendor": self.vendor,
            "distribution": self.distribution,
            "major": self.major,
            "minor": self.minor,
            "patch": self.patch,
            "release_string": self.release_string,
            "release_year": self.release_year,
            "is_supported": self.is_supported,
            "eol": self.eol,
            "eol_reason": self.eol_reason,
            "supports_mlkem": self.supports_mlkem,
            "supports_sntrup761": self.supports_sntrup761,
            "supports_curve25519": self.supports_curve25519,
            "supports_ed25519": self.supports_ed25519,
            "pqc_capability_level": self.pqc_capability_level,
            "can_be_hardened": self.can_be_hardened,
            "requires_upgrade_for_pqc": self.requires_upgrade_for_pqc,
            "upgrade_target": self.upgrade_target,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# OpenSSH version database
# ---------------------------------------------------------------------------

# (major, minor) -> {release_year, eol, notes}
OPENSSH_VERSION_DB: dict[tuple[int,int], dict] = {
    # Ancient — classically broken
    (1, 0): {"year": 1999, "eol": True},
    (2, 0): {"year": 2000, "eol": True},
    (3, 0): {"year": 2001, "eol": True},
    (4, 0): {"year": 2005, "eol": True},
    (5, 0): {"year": 2008, "eol": True},
    (5, 9): {"year": 2011, "eol": True},
    # OpenSSH 6.x — introduced modern primitives
    (6, 2): {"year": 2013, "eol": True,  "note": "ETM MACs, AES-GCM introduced"},
    (6, 5): {"year": 2014, "eol": True,  "note": "Ed25519, ChaCha20-Poly1305 introduced"},
    (6, 6): {"year": 2014, "eol": True},
    (6, 7): {"year": 2014, "eol": True,  "note": "Curve25519 KEX introduced"},
    (6, 9): {"year": 2015, "eol": True},
    # OpenSSH 7.x — DSA disabled by default
    (7, 0): {"year": 2015, "eol": True,  "note": "DSA disabled by default"},
    (7, 2): {"year": 2016, "eol": True,  "note": "Very common in Ubuntu 16.04 LTS"},
    (7, 4): {"year": 2016, "eol": True},
    (7, 6): {"year": 2017, "eol": True,  "note": "Common in Ubuntu 18.04 LTS"},
    (7, 9): {"year": 2018, "eol": True},
    # OpenSSH 8.x — RSA-SHA1 deprecated
    (8, 0): {"year": 2019, "eol": True},
    (8, 1): {"year": 2019, "eol": True},
    (8, 2): {"year": 2020, "eol": True,  "note": "Ubuntu 20.04 LTS — RSA-SHA1 deprecated"},
    (8, 3): {"year": 2020, "eol": True},
    (8, 4): {"year": 2020, "eol": True},
    (8, 5): {"year": 2021, "eol": True,  "note": "sntrup761x25519 hybrid KEX introduced"},
    (8, 6): {"year": 2021, "eol": True},
    (8, 7): {"year": 2021, "eol": True},
    (8, 8): {"year": 2021, "eol": True,  "note": "RSA-SHA1 signatures disabled by default"},
    (8, 9): {"year": 2022, "eol": False, "note": "Ubuntu 22.04 LTS"},
    # OpenSSH 9.x — quantum transition begins
    (9, 0): {"year": 2022, "eol": False},
    (9, 1): {"year": 2022, "eol": False},
    (9, 2): {"year": 2023, "eol": False, "note": "Debian 12 (Bookworm)"},
    (9, 3): {"year": 2023, "eol": False},
    (9, 4): {"year": 2023, "eol": False},
    (9, 5): {"year": 2023, "eol": False},
    (9, 6): {"year": 2023, "eol": False},
    (9, 7): {"year": 2024, "eol": False},
    (9, 8): {"year": 2024, "eol": False, "note": "Ubuntu 24.04 LTS"},
    (9, 9): {"year": 2024, "eol": False, "note": "ML-KEM-768 hybrid KEX introduced"},
    # OpenSSH 10.x — future PQC host keys
    (10, 0): {"year": 2025, "eol": False, "note": "ML-DSA host key support (anticipated)"},
}


# ---------------------------------------------------------------------------
# Banner parser
# ---------------------------------------------------------------------------

def parse_banner(banner: str) -> SoftwareInfo:
    """
    Parse an SSH banner string into a SoftwareInfo object.

    Handles:
      OpenSSH_9.8p1 Ubuntu-3
      OpenSSH_7.2p2 Ubuntu-4ubuntu2.8
      dropbear_2022.83
      Cisco-1.25
      babeld-...
      libssh-0.9.6
      ROSSSH
    """
    if not banner:
        return SoftwareInfo(
            raw_version="unknown",
            vendor="Unknown",
            distribution=None,
            is_supported=False,
            notes=["No banner received"],
        )

    # Strip the "SSH-2.0-" prefix if present
    version_str = banner
    if banner.startswith("SSH-"):
        parts = banner.split("-", 2)
        version_str = parts[2] if len(parts) > 2 else banner

    # Try each vendor parser in order
    for parser in [
        _parse_openssh,
        _parse_dropbear,
        _parse_cisco,
        _parse_libssh,
        _parse_bitvise,
        _parse_generic,
    ]:
        result = parser(version_str)
        if result is not None:
            return result

    return SoftwareInfo(
        raw_version=version_str,
        vendor="Unknown",
        distribution=None,
        is_supported=False,
        notes=[f"Unrecognised SSH software: {version_str}"],
    )


def _parse_openssh(version_str: str) -> Optional[SoftwareInfo]:
    """Parse OpenSSH_X.Yp1 [Distribution-version] banners."""
    # Match: OpenSSH_9.8p1 or OpenSSH_9.8p1 Ubuntu-3ubuntu0.1
    m = re.match(
        r"OpenSSH[_\s](\d+)\.(\d+)(p(\d+))?"
        r"(?:\s+([A-Za-z][A-Za-z0-9_.-]*))?",
        version_str, re.IGNORECASE
    )
    if not m:
        return None

    major = int(m.group(1))
    minor = int(m.group(2))
    patch = int(m.group(4)) if m.group(4) else 0
    dist_raw = m.group(5)  # e.g. "Ubuntu-3ubuntu0.1" or "Debian-1"

    # Parse distribution
    distribution = None
    if dist_raw:
        if "ubuntu" in dist_raw.lower():
            distribution = "Ubuntu"
        elif "debian" in dist_raw.lower():
            distribution = "Debian"
        elif "rhel" in dist_raw.lower() or "redhat" in dist_raw.lower():
            distribution = "RHEL"
        elif "alpine" in dist_raw.lower():
            distribution = "Alpine"
        elif "freebsd" in dist_raw.lower():
            distribution = "FreeBSD"
        else:
            distribution = dist_raw.split("-")[0].capitalize()

    # Look up version info
    ver_key = (major, minor)
    db_entry = OPENSSH_VERSION_DB.get(ver_key, {})

    # Find closest lower version if exact match not found
    if not db_entry:
        candidates = [(k, v) for k, v in OPENSSH_VERSION_DB.items()
                      if k[0] < major or (k[0] == major and k[1] <= minor)]
        if candidates:
            closest_key, db_entry = max(candidates, key=lambda x: x[0])

    release_year = db_entry.get("year")
    eol = db_entry.get("eol", major < 8)

    notes = []
    if db_entry.get("note"):
        notes.append(db_entry["note"])

    # PQC capabilities based on version
    supports_etm     = (major, minor) >= (6, 2)
    supports_ed25519 = (major, minor) >= (6, 5)
    supports_chacha20 = (major, minor) >= (6, 5)
    supports_curve25519 = (major, minor) >= (6, 7)
    supports_sntrup761 = (major, minor) >= (8, 5)
    supports_mlkem    = (major, minor) >= (9, 9)

    # Support status
    is_supported = not eol and (major, minor) >= (8, 9)
    if eol:
        notes.append(f"OpenSSH {major}.{minor} is end-of-life")
    elif not is_supported:
        notes.append(f"OpenSSH {major}.{minor} is outdated — upgrade recommended")

    # Migration implications
    requires_upgrade = not supports_sntrup761
    if requires_upgrade:
        upgrade_target = "9.8"
        notes.append(f"Upgrade to OpenSSH 9.8+ to enable hybrid PQC KEX (sntrup761x25519)")
    elif not supports_mlkem:
        upgrade_target = "9.9"
        notes.append("Upgrade to OpenSSH 9.9+ for ML-KEM-768 hybrid KEX")
    else:
        upgrade_target = None

    release_string = f"{major}.{minor}p{patch}" if patch else f"{major}.{minor}"

    return SoftwareInfo(
        raw_version=version_str,
        vendor="OpenSSH",
        distribution=distribution,
        major=major,
        minor=minor,
        patch=patch,
        release_string=release_string,
        release_year=release_year,
        is_supported=is_supported,
        eol=eol,
        supports_mlkem=supports_mlkem,
        supports_sntrup761=supports_sntrup761,
        supports_curve25519=supports_curve25519,
        supports_ed25519=supports_ed25519,
        supports_chacha20=supports_chacha20,
        supports_etm_macs=supports_etm,
        can_be_hardened=True,
        requires_upgrade_for_pqc=requires_upgrade,
        upgrade_target=upgrade_target,
        notes=notes,
    )


def _parse_dropbear(version_str: str) -> Optional[SoftwareInfo]:
    """Parse dropbear_YYYY.NN banners."""
    m = re.match(r"dropbear[_\s](\d{4})\.(\d+)", version_str, re.IGNORECASE)
    if not m:
        return None

    year = int(m.group(1))
    build = int(m.group(2))

    # Dropbear lifecycle
    # 2022.83+ added Ed25519 and curve25519
    # No PQC support as of 2025
    eol = year < 2020
    supports_curve25519 = year >= 2016
    supports_ed25519 = year >= 2016

    notes = ["Dropbear is common on embedded devices (routers, NAS, IoT)"]
    if eol:
        notes.append(f"Dropbear {year}.{build} is end-of-life")
    notes.append("Dropbear has no PQC support — upgrade to OpenSSH for quantum safety")

    return SoftwareInfo(
        raw_version=version_str,
        vendor="Dropbear",
        distribution=None,
        major=year,
        minor=build,
        release_string=f"{year}.{build}",
        release_year=year,
        is_supported=not eol,
        eol=eol,
        supports_mlkem=False,
        supports_sntrup761=False,
        supports_curve25519=supports_curve25519,
        supports_ed25519=supports_ed25519,
        supports_chacha20=False,
        supports_etm_macs=False,
        can_be_hardened=supports_curve25519,
        requires_upgrade_for_pqc=True,
        upgrade_target="OpenSSH 9.8",
        notes=notes,
    )


def _parse_cisco(version_str: str) -> Optional[SoftwareInfo]:
    m = re.match(r"Cisco[_\-\s](\d+)\.(\d+)", version_str, re.IGNORECASE)
    if not m:
        return None
    major, minor = int(m.group(1)), int(m.group(2))
    return SoftwareInfo(
        raw_version=version_str,
        vendor="Cisco",
        distribution="IOS/NX-OS",
        major=major, minor=minor,
        release_string=f"{major}.{minor}",
        is_supported=True,
        eol=False,
        supports_mlkem=False,
        supports_sntrup761=False,
        supports_curve25519=(major, minor) >= (2, 0),
        supports_ed25519=(major, minor) >= (2, 0),
        can_be_hardened=True,
        requires_upgrade_for_pqc=True,
        upgrade_target="Vendor PQC firmware",
        notes=["Cisco SSH — PQC roadmap depends on IOS/NX-OS version; check vendor advisories"],
    )


def _parse_libssh(version_str: str) -> Optional[SoftwareInfo]:
    m = re.match(r"libssh[_\-\s](\d+)\.(\d+)\.(\d+)", version_str, re.IGNORECASE)
    if not m:
        return None
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    return SoftwareInfo(
        raw_version=version_str,
        vendor="libssh",
        distribution=None,
        major=major, minor=minor, patch=patch,
        release_string=f"{major}.{minor}.{patch}",
        is_supported=(major, minor) >= (0, 10),
        supports_mlkem=False,
        supports_sntrup761=False,
        supports_curve25519=(major, minor) >= (0, 8),
        supports_ed25519=(major, minor) >= (0, 8),
        can_be_hardened=True,
        requires_upgrade_for_pqc=True,
        upgrade_target="libssh 0.11+ (PQC roadmap pending)",
        notes=["libssh — check upstream for PQC timeline"],
    )


def _parse_bitvise(version_str: str) -> Optional[SoftwareInfo]:
    m = re.match(r"WinSSHD|Bitvise", version_str, re.IGNORECASE)
    if not m:
        return None
    return SoftwareInfo(
        raw_version=version_str,
        vendor="Bitvise",
        distribution="Windows",
        is_supported=True,
        supports_mlkem=False,
        supports_sntrup761=False,
        supports_curve25519=True,
        supports_ed25519=True,
        can_be_hardened=True,
        requires_upgrade_for_pqc=True,
        notes=["Bitvise WinSSHD — check vendor for PQC support timeline"],
    )


def _parse_generic(version_str: str) -> Optional[SoftwareInfo]:
    """Catch-all for unrecognised vendors."""
    # Try to extract a version number
    m = re.search(r"(\d+)\.(\d+)", version_str)
    major = int(m.group(1)) if m else 0
    minor = int(m.group(2)) if m else 0

    # Guess vendor from common patterns
    vendor = "Unknown"
    notes = []
    if "babeld" in version_str.lower():
        vendor = "babeld (GitHub)"
        notes.append("GitHub's custom SSH implementation")
    elif "rosssh" in version_str.lower():
        vendor = "ROSSSH (MikroTik)"
        notes.append("MikroTik RouterOS SSH — limited PQC roadmap")
    elif "fortissh" in version_str.lower() or "forti" in version_str.lower():
        vendor = "Fortinet"
        notes.append("Fortinet SSH — check FortiOS PQC advisories")
    elif "paramiko" in version_str.lower():
        vendor = "Paramiko (Python)"
        notes.append("Python paramiko SSH implementation")

    return SoftwareInfo(
        raw_version=version_str,
        vendor=vendor,
        distribution=None,
        major=major, minor=minor,
        release_string=f"{major}.{minor}" if major else None,
        is_supported=False,
        can_be_hardened=False,
        requires_upgrade_for_pqc=True,
        notes=notes or [f"Unrecognised SSH implementation: {version_str[:40]}"],
    )


# ---------------------------------------------------------------------------
# Capability vs configuration gap analysis
# ---------------------------------------------------------------------------

def analyse_capability_gap(
    software: SoftwareInfo,
    configured_kex: list[str],
    configured_host_keys: list[str],
) -> dict:
    """
    Compare what the software CAN support vs what IS configured.

    Returns a gap analysis with specific upgrade-vs-reconfigure recommendations.

    Two distinct migration paths:
      1. Reconfigure (no upgrade needed) — software supports it, just not enabled
      2. Upgrade required — software version too old

    This is the key insight: many servers can get hybrid PQC TODAY
    just by changing sshd_config, no package upgrade needed.
    """
    gaps = []
    recommendations = []

    has_sntrup = any("sntrup" in k for k in configured_kex)
    has_mlkem  = any("mlkem" in k for k in configured_kex)
    has_curve25519 = any("curve25519" in k for k in configured_kex)
    has_ed25519_key = any("ed25519" in k for k in configured_host_keys)

    # Gap 1: sntrup761 hybrid KEX
    if not has_sntrup:
        if software.supports_sntrup761:
            gaps.append({
                "gap": "sntrup761x25519 hybrid KEX not configured",
                "action": "reconfigure",
                "effort": "low",
                "detail": "Add sntrup761x25519-sha512@openssh.com to KexAlgorithms in sshd_config",
                "impact": "Enables harvest-now-decrypt-later protection immediately",
            })
            recommendations.append("reconfigure_sntrup761")
        else:
            gaps.append({
                "gap": "Software too old for hybrid PQC KEX",
                "action": "upgrade",
                "effort": "medium",
                "detail": f"Upgrade to OpenSSH 8.5+ (current: {software.version_display})",
                "impact": "Required before any PQC KEX is possible",
            })
            recommendations.append("upgrade_for_sntrup761")

    # Gap 2: ML-KEM hybrid KEX
    if not has_mlkem:
        if software.supports_mlkem:
            gaps.append({
                "gap": "ML-KEM-768 hybrid KEX not configured",
                "action": "reconfigure",
                "effort": "low",
                "detail": "Add mlkem768x25519-sha256 to KexAlgorithms",
                "impact": "Enables FIPS 203 standard hybrid KEX",
            })
        else:
            gaps.append({
                "gap": "Software too old for ML-KEM KEX",
                "action": "upgrade",
                "effort": "medium",
                "detail": f"Upgrade to OpenSSH 9.9+ (current: {software.version_display})",
                "impact": "Required for FIPS 203 ML-KEM support",
            })

    # Gap 3: Ed25519 host key
    if not has_ed25519_key:
        if software.supports_ed25519:
            gaps.append({
                "gap": "Ed25519 host key not configured",
                "action": "reconfigure",
                "effort": "low",
                "detail": "Generate and configure ssh-ed25519 host key",
                "impact": "Removes RSA/ECDSA as the only host key option",
            })
            recommendations.append("generate_ed25519_key")
        else:
            gaps.append({
                "gap": "Software too old for Ed25519 host keys",
                "action": "upgrade",
                "effort": "medium",
                "detail": f"Upgrade to OpenSSH 6.5+ (current: {software.version_display})",
                "impact": "Required for Ed25519 host keys",
            })

    # Compute overall
    upgrade_needed = any(g["action"] == "upgrade" for g in gaps)
    reconfigure_only = len(gaps) > 0 and not upgrade_needed

    return {
        "software": software.to_dict(),
        "configured_kex": configured_kex,
        "configured_host_keys": configured_host_keys,
        "gaps": gaps,
        "recommendations": recommendations,
        "upgrade_required": upgrade_needed,
        "reconfigure_only": reconfigure_only,
        "immediate_wins": [g for g in gaps if g["action"] == "reconfigure"],
        "blocked_by_version": [g for g in gaps if g["action"] == "upgrade"],
        "summary": (
            "Upgrade required before PQC is possible" if upgrade_needed
            else "PQC can be enabled by reconfiguring sshd_config only" if reconfigure_only
            else "Software is PQC-capable and configured correctly"
        ),
    }