"""
password_hashing/types.py
----------------------------
Shared types for the password-hashing audit/hardening product slice.

IMPORTANT — read before wiring this into anything customer-facing:
Cryptiq can identify which hashing scheme protects an existing password
(by its format prefix/structure) and tell you whether it's weak. It
CANNOT "re-hash" an existing credential to a stronger algorithm, because
a hash is one-way by design — there is no plaintext to re-hash without
either the user typing their password again or you knowing it outright
(which you shouldn't). So remediation here always means one of:
  1. Reconfigure the system so the NEXT password set/change uses a strong
     scheme (PAM config, login.defs, network device "secret" algorithm, a
     web app's password hashing library config).
  2. Force a password reset for accounts still on a weak/legacy scheme so
     they get re-hashed under the new policy.
This mirrors how every real identity system (Linux PAM, Windows AD, Okta,
Auth0, etc.) actually handles a hashing-algorithm upgrade — there is no
shortcut, anywhere, for anyone.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Platform(str, Enum):
    LINUX = "linux"
    MACOS = "macos"
    WINDOWS = "windows"
    NETWORK_CISCO_IOS = "network_cisco_ios"
    NETWORK_JUNIPER = "network_juniper"
    NETWORK_PANOS = "network_panos"
    DATABASE = "database"
    GENERIC = "generic"


class HashRisk(str, Enum):
    CRITICAL = "critical"   # plaintext / reversible / trivially crackable
    HIGH = "high"           # unsalted or fast general-purpose hash (MD5, SHA1, NTLM)
    MEDIUM = "medium"       # salted but not memory-hard (SHA-256/512 crypt, single-round)
    LOW = "low"             # adaptive, slow, salted (bcrypt, sha512crypt w/ high rounds)
    BEST = "best"           # memory-hard modern KDF (argon2id, yescrypt, scrypt)


@dataclass
class HashAlgorithmInfo:
    name: str
    risk: HashRisk
    reason: str
    recommendation: str


@dataclass
class PasswordHashFinding:
    source: str                 # e.g. "/etc/shadow", "running-config", uploaded filename
    identifier: str             # username / device hostname / record key
    platform: Platform
    algorithm: str               # detected scheme name, e.g. "sha512crypt", "cisco-type-7"
    risk: HashRisk
    reason: str
    recommendation: str
    raw_prefix: Optional[str] = None   # the format marker matched (e.g. "$6$"), never the full hash
    line_number: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "source": self.source, "identifier": self.identifier, "platform": self.platform.value,
            "algorithm": self.algorithm, "risk": self.risk.value, "reason": self.reason,
            "recommendation": self.recommendation, "raw_prefix": self.raw_prefix,
            "line_number": self.line_number,
        }


@dataclass
class ScanSummary:
    platform: Platform
    source: str
    total_findings: int
    by_risk: dict
    findings: list[PasswordHashFinding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "platform": self.platform.value, "source": self.source,
            "total_findings": self.total_findings, "by_risk": self.by_risk,
            "findings": [f.to_dict() for f in self.findings],
        }