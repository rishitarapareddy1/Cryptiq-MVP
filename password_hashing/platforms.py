"""
password_hashing/platforms.py
--------------------------------
Plugin registry for "what system am I scanning". This is the answer to
"how do I add support for a new system without editing core logic":

    from password_hashing.platforms import PlatformPlugin, register

    register(PlatformPlugin(
        id="my_new_system",
        label="My New System",
        description="...",
        placeholder="paste example config here",
        scan_text=my_scan_function,          # str -> ScanSummary
        harden=my_hardening_plan_function,   # () -> HardeningPlan
    ))

That's the whole contract. Nothing else in the codebase needs to change:
- api.py's /pwhash/platforms and /pwhash/scan/{platform_id} routes are
  driven entirely off this registry, so a new plugin is live the moment
  it's registered (no new endpoint, no new pydantic model).
- The frontend renders platform tabs from GET /pwhash/platforms, so a new
  registration shows up in the UI automatically too.

WHAT COUNTS AS "A NEW PLATFORM" IN PRACTICE
--------------------------------------------
Most of the time a "new platform" is just a new way to *locate* a hash
inside some vendor's text format -- the hash itself is very often a
standard crypt(3) string once extracted (see PAN-OS below, which reuses
risk.classify_crypt_prefix() wholesale). So adding a platform is usually:
  1. Write a regex/parser that finds "username -> hash string" pairs in
     that vendor's config export format (see scanner.py's
     scan_panos_config_text for a template).
  2. Feed each extracted hash through classify_crypt_prefix() (works for
     any crypt(3)-derived scheme) or write a small lookup table if the
     vendor uses its own numbered scheme (see risk.CISCO_TYPE_INFO for
     that pattern).
  3. Register it here.

You do NOT need a new hash-format table for most Linux-family systems --
that's the point of classifying by crypt(3) prefix rather than by distro.
The prefix ($1$/$5$/$6$/$y$/$2b$/$argon2id$/etc.) identifies the actual
KDF regardless of whether the box is Ubuntu, RHEL, Debian, Amazon Linux,
Alpine, or a Linux-based appliance (PAN-OS, most other network OSes with
a Linux/BSD userland). The one real caveat: musl-libc distros (Alpine)
top out at bcrypt/sha512crypt and don't support yescrypt -- worth a note
in the UI if you're auditing Alpine, not a new scanner.

Windows Server vs Workstation is the same story: the on-disk verifier
format (NTLM/LM in SAM, or NTDS.dit for a Domain Controller) is identical
either way -- what differs is the *hardening* lever (local security policy
vs. domain GPO). scan_windows_dump_text() already covers both; only the
hardening plan needs a variant, which is exactly the kind of small,
additive change this registry is built for (see windows_plan()).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from password_hashing.types import ScanSummary
from password_hashing.hardener import HardeningPlan, get_hardening_plan
from password_hashing.types import Platform
from password_hashing import scanner


@dataclass
class PlatformPlugin:
    id: str
    label: str
    description: str
    placeholder: str
    scan_text: Callable[[str], ScanSummary]
    harden: Callable[[], HardeningPlan]
    scan_file: Optional[Callable[[str], ScanSummary]] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id, "label": self.label, "description": self.description,
            "placeholder": self.placeholder, "supports_file_scan": self.scan_file is not None,
        }


_REGISTRY: dict[str, PlatformPlugin] = {}


def register(plugin: PlatformPlugin) -> None:
    """Register a platform plugin. Re-registering an existing id overwrites it,
    which is intentional -- it lets a deployment override a built-in plugin
    (e.g. swap in a company-specific PAN-OS parser) without forking this file."""
    _REGISTRY[plugin.id] = plugin


def get(platform_id: str) -> Optional[PlatformPlugin]:
    return _REGISTRY.get(platform_id)


def list_platforms() -> list[dict]:
    return [p.to_dict() for p in _REGISTRY.values()]


def scan(platform_id: str, text: str) -> ScanSummary:
    plugin = get(platform_id)
    if not plugin:
        raise KeyError(f"Unknown platform '{platform_id}'. Known: {list(_REGISTRY.keys())}")
    return plugin.scan_text(text)


def harden(platform_id: str) -> HardeningPlan:
    plugin = get(platform_id)
    if not plugin:
        raise KeyError(f"Unknown platform '{platform_id}'. Known: {list(_REGISTRY.keys())}")
    return plugin.harden()


# ── Built-in registrations ──────────────────────────────────────────────
# Each of these is exactly the pattern described in the module docstring --
# a scan_text callable + a harden callable, nothing more.

register(PlatformPlugin(
    id="linux", label="Linux / Unix (/etc/shadow)",
    description="Any glibc- or musl-based system reading crypt(3) hashes from /etc/shadow — "
                "distro-agnostic (Ubuntu, RHEL, Debian, Amazon Linux, Alpine, etc).",
    placeholder="root:$6$abc123$longhash...:19000:0:99999:7:::\nalice:$1$salt$weakhash:19000:0:99999:7:::",
    scan_text=scanner.scan_shadow_text,
    harden=lambda: get_hardening_plan(Platform.LINUX),
    scan_file=scanner.scan_shadow_file,
))

register(PlatformPlugin(
    id="windows", label="Windows (SAM / secretsdump dump)",
    description="LM/NTLM hashes from a pwdump or secretsdump-style export. Covers both Windows "
                "Server (local SAM or NTDS.dit dump) and Windows workstation — the hash format "
                "is identical; only the hardening lever (local policy vs. domain GPO) differs.",
    placeholder="Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
                "bob:1001:01fc5a6be7bc6929aad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::",
    scan_text=scanner.scan_windows_dump_text,
    harden=lambda: get_hardening_plan(Platform.WINDOWS),
))

register(PlatformPlugin(
    id="network_cisco_ios", label="Cisco IOS / IOS-XE",
    description="Parses `password`/`secret` lines from a running-config (types 0/5/7/8/9).",
    placeholder="username admin secret 9 $9$abc$def\nusername legacy password 7 0822455D0A16\n"
                "enable secret 5 $1$salt$hash",
    scan_text=scanner.scan_cisco_config_text,
    harden=lambda: get_hardening_plan(Platform.NETWORK_CISCO_IOS),
))

register(PlatformPlugin(
    id="network_panos", label="Palo Alto PAN-OS",
    description="Parses `phash` fields from set-format or XML PAN-OS config exports. The phash "
                "itself is a standard crypt(3) string, so classification reuses the same table "
                "as Linux — this plugin is mostly just the config-format parser.",
    placeholder="set mgt-config users admin phash $6$rounds=656000$saltsalt$hashhashhash...",
    scan_text=scanner.scan_panos_config_text,
    harden=lambda: get_hardening_plan(Platform.NETWORK_PANOS),
))

register(PlatformPlugin(
    id="generic", label="Generic / Paste a hash",
    description="No known vendor format — classify one or more bare hash values by pattern "
                "(crypt-style, raw MD5/SHA1 hex, etc).",
    placeholder="5f4dcc3b5aa765d61d8327deb882cf99\n$2b$12$KIXQ1z5z5z5z5z5z5z5z5uQ1z5z5z5z5z5z5z5z5z5z5z5z5z5z",
    scan_text=scanner.scan_generic_text,
    harden=lambda: get_hardening_plan(Platform.GENERIC),
))