"""
ssh_migration/config_hardener.py
---------------------------------
sshd_config analysis and patch generation.

Given a scan result (or a raw sshd_config string), this module:
  1. Analyses what algorithms are currently configured
  2. Compares against the target algorithm set
  3. Generates a patch (diff-style) and a ready-to-deploy config snippet
  4. Produces a rollback config to restore the original state

This never touches a remote server directly — that's the executor's job.
This module produces the config text; executor applies it.
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Optional

from ssh_migration.algorithms import Algorithm, get_recommended

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ConfigAnalysis:
    """Analysis of an existing sshd_config."""
    host: str
    ssh_version: Optional[str]

    # Current config values (parsed from sshd_config or inferred from scan)
    current_kex: list[str] = field(default_factory=list)
    current_ciphers: list[str] = field(default_factory=list)
    current_macs: list[str] = field(default_factory=list)
    current_host_key_types: list[str] = field(default_factory=list)

    # Issues found
    weak_kex: list[str] = field(default_factory=list)
    weak_ciphers: list[str] = field(default_factory=list)
    weak_macs: list[str] = field(default_factory=list)
    missing_host_keys: list[str] = field(default_factory=list)

    # Counts
    issue_count: int = 0
    critical_count: int = 0


@dataclass
class ConfigPatch:
    """A ready-to-apply sshd_config patch."""
    host: str

    # The full config snippet to append / replace
    hardened_snippet: str = ""

    # Diff-style description of changes
    changes: list[dict] = field(default_factory=list)

    # Backup of original config lines affected
    original_lines: list[str] = field(default_factory=list)

    # Shell commands to apply the patch (for reference / executor use)
    apply_commands: list[str] = field(default_factory=list)

    # Shell commands to validate after applying
    validate_commands: list[str] = field(default_factory=list)

    # Rollback commands
    rollback_commands: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Weak algorithm sets (same as ssh_risk.py but for config context)
# ---------------------------------------------------------------------------

WEAK_KEX = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
}

WEAK_CIPHERS = {
    "3des-cbc",
    "arcfour", "arcfour128", "arcfour256",
    "blowfish-cbc", "cast128-cbc",
    "aes128-cbc", "aes192-cbc", "aes256-cbc",
}

WEAK_MACS = {
    "hmac-md5", "hmac-md5-96",
    "hmac-sha1", "hmac-sha1-96",
    "umac-32@openssh.com", "umac-64@openssh.com",
}

# ---------------------------------------------------------------------------
# Recommended sets (ordered — first is most preferred)
# ---------------------------------------------------------------------------

RECOMMENDED_KEX = [
    "mlkem768x25519-sha256",              # FIPS 203 hybrid — best
    "sntrup761x25519-sha512@openssh.com", # OpenSSH 9.x hybrid — available now
    "sntrup761x25519-sha512",
    "curve25519-sha256",                  # classical fallback
    "curve25519-sha256@libssh.org",
    "diffie-hellman-group16-sha512",      # large DH — classical only fallback
    "diffie-hellman-group18-sha512",
]

RECOMMENDED_CIPHERS = [
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-ctr",
    "aes192-ctr",
    "aes128-ctr",
]

RECOMMENDED_MACS = [
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "umac-128-etm@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
]

RECOMMENDED_HOST_KEY_TYPES = [
    "ssh-ed25519",
    "rsa-sha2-512",
    "rsa-sha2-256",
    # ecdsa deliberately omitted — Shor-vulnerable
]


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyse_from_scan(scan_result: dict) -> ConfigAnalysis:
    """
    Build a ConfigAnalysis from a scan result dict
    (as returned by the /ssh/scan endpoint).
    """
    host = scan_result.get("host", "unknown")
    ssh_version = scan_result.get("ssh_version")

    current_kex = scan_result.get("server_kex_algorithms", [])
    current_ciphers = scan_result.get("server_ciphers", [])
    current_macs = scan_result.get("server_macs", [])
    current_host_keys = [
        hk.get("algorithm") if isinstance(hk, dict) else str(hk)
        for hk in scan_result.get("host_keys", [])
    ]

    return _build_analysis(
        host, ssh_version,
        current_kex, current_ciphers, current_macs, current_host_keys,
    )


def analyse_from_config(host: str, config_text: str, ssh_version: str = "") -> ConfigAnalysis:
    """
    Parse an sshd_config file content and build a ConfigAnalysis.
    """
    kex = _parse_config_list(config_text, "KexAlgorithms")
    ciphers = _parse_config_list(config_text, "Ciphers")
    macs = _parse_config_list(config_text, "MACs")
    host_keys = _parse_config_values(config_text, "HostKey")

    return _build_analysis(host, ssh_version, kex, ciphers, macs, host_keys)


def _build_analysis(
    host: str,
    ssh_version: Optional[str],
    kex: list[str],
    ciphers: list[str],
    macs: list[str],
    host_keys: list[str],
) -> ConfigAnalysis:
    analysis = ConfigAnalysis(
        host=host,
        ssh_version=ssh_version,
        current_kex=kex,
        current_ciphers=ciphers,
        current_macs=macs,
        current_host_key_types=host_keys,
    )

    for k in kex:
        if k in WEAK_KEX:
            analysis.weak_kex.append(k)
            analysis.issue_count += 1
            if "group1" in k or "sha1" in k.split("-")[-1]:
                analysis.critical_count += 1

    for c in ciphers:
        if c in WEAK_CIPHERS:
            analysis.weak_ciphers.append(c)
            analysis.issue_count += 1

    for m in macs:
        if m in WEAK_MACS:
            analysis.weak_macs.append(m)
            analysis.issue_count += 1

    # Check if Ed25519 host key is present
    has_ed25519 = any("ed25519" in hk.lower() for hk in host_keys)
    if not has_ed25519:
        analysis.missing_host_keys.append("ssh-ed25519")
        analysis.issue_count += 1

    return analysis


def _parse_config_list(config_text: str, directive: str) -> list[str]:
    """Extract comma-separated values from a config directive."""
    pattern = rf"^\s*{directive}\s+(.+)$"
    for line in config_text.splitlines():
        m = re.match(pattern, line, re.IGNORECASE)
        if m:
            return [v.strip() for v in m.group(1).split(",") if v.strip()]
    return []


def _parse_config_values(config_text: str, directive: str) -> list[str]:
    """Extract values from repeated single-value directives (e.g. HostKey)."""
    values = []
    pattern = rf"^\s*{directive}\s+(.+)$"
    for line in config_text.splitlines():
        m = re.match(pattern, line, re.IGNORECASE)
        if m:
            values.append(m.group(1).strip())
    return values


# ---------------------------------------------------------------------------
# Patch generation
# ---------------------------------------------------------------------------

def generate_patch(
    analysis: ConfigAnalysis,
    target_kex: Optional[list[str]] = None,
    target_ciphers: Optional[list[str]] = None,
    target_macs: Optional[list[str]] = None,
    add_host_key_types: Optional[list[str]] = None,
    conservative: bool = True,
) -> ConfigPatch:
    """
    Generate a hardened sshd_config patch.

    Args:
        analysis        : Result of analyse_from_scan() or analyse_from_config()
        target_kex      : Desired KEX list. Defaults to RECOMMENDED_KEX.
        target_ciphers  : Desired cipher list. Defaults to RECOMMENDED_CIPHERS.
        target_macs     : Desired MAC list. Defaults to RECOMMENDED_MACS.
        add_host_key_types : Extra host key directives to add.
        conservative    : If True, keep any currently-configured safe algorithms
                          (don't remove things that aren't weak). If False,
                          replace entirely with the target lists.

    Returns:
        ConfigPatch with snippet, change list, and shell commands.
    """
    patch = ConfigPatch(host=analysis.host)

    # Resolve targets
    kex = target_kex or RECOMMENDED_KEX
    ciphers = target_ciphers or RECOMMENDED_CIPHERS
    macs = target_macs or RECOMMENDED_MACS

    if conservative:
        # Filter current list: keep safe ones, add recommended ones at the front
        current_safe_kex = [k for k in analysis.current_kex if k not in WEAK_KEX]
        kex = _merge_preferred(RECOMMENDED_KEX[:3], current_safe_kex)

        current_safe_ciphers = [c for c in analysis.current_ciphers if c not in WEAK_CIPHERS]
        ciphers = _merge_preferred(RECOMMENDED_CIPHERS[:3], current_safe_ciphers)

        current_safe_macs = [m for m in analysis.current_macs if m not in WEAK_MACS]
        macs = _merge_preferred(RECOMMENDED_MACS[:2], current_safe_macs)

    # Track changes
    if set(kex) != set(analysis.current_kex):
        removed = [k for k in analysis.current_kex if k not in kex]
        added = [k for k in kex if k not in analysis.current_kex]
        patch.changes.append({
            "directive": "KexAlgorithms",
            "action": "replace",
            "removed": removed,
            "added": added,
            "before": ",".join(analysis.current_kex),
            "after": ",".join(kex),
        })

    if set(ciphers) != set(analysis.current_ciphers):
        removed = [c for c in analysis.current_ciphers if c not in ciphers]
        added = [c for c in ciphers if c not in analysis.current_ciphers]
        patch.changes.append({
            "directive": "Ciphers",
            "action": "replace",
            "removed": removed,
            "added": added,
            "before": ",".join(analysis.current_ciphers),
            "after": ",".join(ciphers),
        })

    if set(macs) != set(analysis.current_macs):
        removed = [m for m in analysis.current_macs if m not in macs]
        added = [m for m in macs if m not in analysis.current_macs]
        patch.changes.append({
            "directive": "MACs",
            "action": "replace",
            "removed": removed,
            "added": added,
            "before": ",".join(analysis.current_macs),
            "after": ",".join(macs),
        })

    # Build the config snippet
    host_key_lines = ""
    if add_host_key_types:
        host_key_lines = "\n".join(
            f"HostKey /etc/ssh/ssh_host_{t.replace('ssh-','').replace('ecdsa-sha2-nistp256','ecdsa')}_key"
            for t in add_host_key_types
        )

    patch.hardened_snippet = _build_snippet(kex, ciphers, macs, host_key_lines)

    # Shell commands to apply
    patch.apply_commands = _build_apply_commands(analysis.host, patch.hardened_snippet)
    patch.validate_commands = _build_validate_commands()
    patch.rollback_commands = _build_rollback_commands()

    return patch


def _merge_preferred(preferred: list[str], existing: list[str]) -> list[str]:
    """Put preferred algorithms first, then any safe existing ones not already listed."""
    result = list(preferred)
    for e in existing:
        if e not in result:
            result.append(e)
    return result


def _build_snippet(
    kex: list[str],
    ciphers: list[str],
    macs: list[str],
    host_key_lines: str = "",
) -> str:
    lines = [
        "# ── Cryptiq PQC Hardening ──────────────────────────────────────",
        "# Generated by Cryptiq SSH Migration Tool",
        "# Apply to /etc/ssh/sshd_config or /etc/ssh/sshd_config.d/cryptiq.conf",
        "#",
        f"KexAlgorithms {','.join(kex)}",
        f"Ciphers {','.join(ciphers)}",
        f"MACs {','.join(macs)}",
        "",
        "# Disable password authentication (use key-based auth only)",
        "PasswordAuthentication no",
        "PermitRootLogin prohibit-password",
        "",
        "# Disable legacy protocol features",
        "PermitEmptyPasswords no",
        "X11Forwarding no",
        "AllowAgentForwarding no",
    ]
    if host_key_lines:
        lines = [host_key_lines, ""] + lines
    return "\n".join(lines)


def _build_apply_commands(host: str, snippet: str) -> list[str]:
    """Shell commands to apply the patch on the target host."""
    escaped = snippet.replace("'", "'\\''")
    return [
        "# Create a backup first",
        "sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d_%H%M%S)",
        "",
        "# Write hardened config to a drop-in file (recommended)",
        "sudo mkdir -p /etc/ssh/sshd_config.d",
        f"sudo tee /etc/ssh/sshd_config.d/00-cryptiq-hardening.conf << 'EOF'\n{snippet}\nEOF",
        "",
        "# Ensure sshd_config includes the drop-in directory",
        "grep -q 'Include /etc/ssh/sshd_config.d' /etc/ssh/sshd_config || "
        "echo 'Include /etc/ssh/sshd_config.d/*.conf' | sudo tee -a /etc/ssh/sshd_config",
        "",
        "# Test config before restarting",
        "sudo sshd -t",
        "",
        "# Restart sshd (keep existing sessions alive)",
        "sudo systemctl reload sshd || sudo service ssh reload",
    ]


def _build_validate_commands() -> list[str]:
    return [
        "# Verify the config was applied",
        "sudo sshd -T | grep -E 'kexalgorithms|ciphers|macs|passwordauthentication'",
        "",
        "# Test connection (from another terminal before closing this one!)",
        "ssh -o StrictHostKeyChecking=no -v localhost 2>&1 | grep -E 'KEX|cipher|MAC|Host key'",
    ]


def _build_rollback_commands() -> list[str]:
    return [
        "# Rollback: remove the drop-in and restore backup",
        "sudo rm -f /etc/ssh/sshd_config.d/00-cryptiq-hardening.conf",
        "# Restore backup (replace TIMESTAMP with actual backup timestamp)",
        "sudo cp /etc/ssh/sshd_config.bak.TIMESTAMP /etc/ssh/sshd_config",
        "sudo systemctl reload sshd",
    ]


# ---------------------------------------------------------------------------
# Summary helpers
# ---------------------------------------------------------------------------

def analysis_summary(analysis: ConfigAnalysis) -> dict:
    return {
        "host": analysis.host,
        "ssh_version": analysis.ssh_version,
        "total_issues": analysis.issue_count,
        "critical_issues": analysis.critical_count,
        "weak_kex": analysis.weak_kex,
        "weak_ciphers": analysis.weak_ciphers,
        "weak_macs": analysis.weak_macs,
        "missing_host_keys": analysis.missing_host_keys,
        "current": {
            "kex": analysis.current_kex,
            "ciphers": analysis.current_ciphers,
            "macs": analysis.current_macs,
            "host_keys": analysis.current_host_key_types,
        },
    }


def patch_summary(patch: ConfigPatch) -> dict:
    return {
        "host": patch.host,
        "changes": patch.changes,
        "change_count": len(patch.changes),
        "hardened_snippet": patch.hardened_snippet,
        "apply_commands": patch.apply_commands,
        "validate_commands": patch.validate_commands,
        "rollback_commands": patch.rollback_commands,
    }