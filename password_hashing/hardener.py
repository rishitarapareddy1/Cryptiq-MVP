"""
password_hashing/hardener.py
-------------------------------
Per-platform "what to actually change" commands, returned for review —
none of these are auto-executed (consistent with CLAUDE.md's posture for
anything that touches an identity/auth surface: propose, don't auto-apply,
unless the user explicitly runs it via the SSH executor with dry_run=False
the same way ssh_migration/executor.py works).

These only affect future password sets/changes; see types.py docstring on
why existing hashes can't be transformed in place.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from password_hashing.types import Platform


@dataclass
class HardeningPlan:
    platform: Platform
    summary: str
    commands: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"platform": self.platform.value, "summary": self.summary,
                "commands": self.commands, "notes": self.notes}


def linux_plan() -> HardeningPlan:
    return HardeningPlan(
        platform=Platform.LINUX,
        summary="Set the system default password hash to yescrypt (memory-hard) and force "
                "re-hash of accounts still on a weak scheme.",
        commands=[
            "# 1. Check current default and libxcrypt support",
            "authselect current  # or: grep -i pam_unix /etc/pam.d/common-password",
            "# 2. Set the hashing method (RHEL/Fedora/SUSE style):",
            "authselect select sssd --force && authselect enable-feature with-pwhistory",
            "# Debian/Ubuntu style — edit /etc/pam.d/common-password:",
            "#   pam_unix.so obscure yescrypt",
            "# 3. Or set system-wide default in /etc/login.defs:",
            "sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD YESCRYPT/' /etc/login.defs",
            "# 4. Force a re-hash for every account still on a weak scheme (run per flagged user):",
            "chage -d 0 <username>   # forces password change at next login -> re-hashed under new policy",
        ],
        notes=[
            "yescrypt requires glibc/libxcrypt >= 4.4.17 (default on Debian 11+, Ubuntu 22.04+, Fedora 35+, RHEL 9+).",
            "SHA-512 ($6$) is an acceptable fallback on older distros without yescrypt support.",
            "This only affects future password changes — existing weak hashes stay weak until the user resets.",
        ],
    )


def macos_plan() -> HardeningPlan:
    return HardeningPlan(
        platform=Platform.MACOS,
        summary="macOS already uses SALTED-SHA512-PBKDF2 for local accounts by default (since 10.8) "
                "and stores it inside opendirectoryd, not a flat file — there's no algorithm choice "
                "to change. Harden the policy around it instead.",
        commands=[
            "pwpolicy -u <username> -setpolicy 'minChars=14 requiresAlpha=1 requiresNumeric=1 requiresSymbol=1'",
            "pwpolicy -u <username> -setpolicy 'maxMinutesUntilChangePassword=129600'  # 90 days",
            "sysadminctl -screenLock immediate -password -",
            "# Enforce FileVault so the on-disk password verifier is encrypted at rest:",
            "fdesetup enable",
        ],
        notes=[
            "Cryptiq cannot read macOS password verifiers directly — they're not exposed in a "
            "scannable file the way /etc/shadow is, by OS design.",
            "If you need to assess a fleet of Macs, the realistic lever is MDM-enforced policy "
            "(Jamf/Kandji/Intune), not direct hash inspection.",
        ],
    )


def windows_plan() -> HardeningPlan:
    return HardeningPlan(
        platform=Platform.WINDOWS,
        summary="Disable legacy LM hash storage, restrict NTLM, and push toward Kerberos + MFA. "
                "Windows does not offer a 'stronger hash algorithm' knob for local password "
                "storage the way Linux/Cisco do — the lever is eliminating the weak fallback "
                "and reducing reliance on hash-based auth entirely.",
        commands=[
            "# Disable LM hash generation (GPO or registry):",
            "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v NoLMHash /t REG_DWORD /d 1 /f",
            "# Restrict NTLM (GPO: Network security: Restrict NTLM: NTLM authentication in this domain):",
            "secedit /export /cfg current.inf   # review, then set RestrictNTLM via GPO console",
            "# Rotate the krbtgt account password twice (standard AD hygiene, closes golden-ticket exposure):",
            "Set-ADAccountPassword krbtgt -Reset",
            "# Force re-hash by requiring password change at next logon for flagged accounts:",
            "Set-ADUser <username> -ChangePasswordAtLogon $true",
        ],
        notes=[
            "An LM or NTLM hash finding in a secretsdump-style export means the SAM/NTDS.dit was "
            "already exfiltrated or dumped from memory — treat that as an active incident, not just "
            "a config gap.",
            "Enforce MFA via Entra ID/AD FS so a cracked NTLM hash alone isn't sufficient for access.",
        ],
    )


def cisco_ios_plan() -> HardeningPlan:
    return HardeningPlan(
        platform=Platform.NETWORK_CISCO_IOS,
        summary="Replace type 0/7/5 password and secret lines with type 9 (scrypt) or type 8 (PBKDF2-SHA256).",
        commands=[
            "configure terminal",
            "service password-encryption",
            "username <user> secret 9 <new-password>   ! re-enter the password — Cisco re-hashes on input",
            "enable secret 9 <new-password>",
            "no enable password",
            "line vty 0 4",
            " no password",
            " login local",
            "end",
            "write memory",
        ],
        notes=[
            "Type 9 (scrypt) requires IOS 15.3(3)M or IOS-XE — check `show version` first; "
            "fall back to type 8 (PBKDF2-SHA256) on older trains.",
            "Type 7 is not encryption — anyone with the running-config can decode it offline in "
            "under a second with public tools. Treat any type 7 finding as already-disclosed.",
        ],
    )


def panos_plan() -> HardeningPlan:
    return HardeningPlan(
        platform=Platform.NETWORK_PANOS,
        summary="PAN-OS generates the phash itself (SHA-512 crypt on current releases) — there's no "
                "algorithm knob to turn. Hardening here means password policy + forcing a reset for "
                "any account still showing a weak/legacy phash (e.g. $1$ MD5 crypt from a very old "
                "PAN-OS release still active after an upgrade).",
        commands=[
            "configure",
            "set mgt-config password-complexity enabled yes",
            "set mgt-config password-complexity minimum-length 14",
            "set mgt-config password-complexity minimum-uppercase-letters 1",
            "set mgt-config password-complexity minimum-lowercase-letters 1",
            "set mgt-config password-complexity minimum-numeric-letters 1",
            "set mgt-config password-complexity minimum-special-characters 1",
            "set mgt-config password-complexity block-username-inclusion yes",
            "# Force a reset for a specific weak-phash account (re-hashes under current PAN-OS crypt scheme):",
            "set mgt-config users <username> password",
            "commit",
        ],
        notes=[
            "phash values are standard crypt(3) strings under the hood — a $1$ (MD5 crypt) finding "
            "usually means the account's password hasn't been changed since a very old PAN-OS "
            "version; current releases produce $6$ (SHA-512 crypt) on password set.",
            "Prefer SAML/RADIUS/LDAP + MFA for admin auth over local accounts entirely where your "
            "deployment allows it — local phash accounts should be break-glass only.",
        ],
    )


_PLANS = {
    Platform.LINUX: linux_plan,
    Platform.MACOS: macos_plan,
    Platform.WINDOWS: windows_plan,
    Platform.NETWORK_CISCO_IOS: cisco_ios_plan,
    Platform.NETWORK_PANOS: panos_plan,
}


def get_hardening_plan(platform: Platform) -> HardeningPlan:
    fn = _PLANS.get(platform)
    if not fn:
        return HardeningPlan(
            platform=platform,
            summary="No platform-specific hardening template yet for this platform.",
            commands=[], notes=["Open a request to add a template for this platform."],
        )
    return fn()