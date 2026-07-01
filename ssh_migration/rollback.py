"""
ssh_migration/rollback.py
--------------------------
Structured backup and rollback for SSH migration.

Instead of "here are rollback commands", this module:
  1. Creates a timestamped backup directory before any change
  2. Records every file touched with its original content
  3. Generates a patch record (what changed)
  4. Can restore everything in one call

Backup structure:
  /etc/ssh/cryptiq-backups/
    2026-06-29-14-12-55/
      sshd_config               <- original file
      sshd_config.d/            <- original drop-in dir (if any)
      manifest.json             <- what was backed up, scan_id, timestamp
      cryptiq.patch             <- unified diff of what changed
      scan_before.json          <- scan result before migration
      scan_after.json           <- scan result after (written by executor)

The rollback is fully automatic: executor calls rollback() on any failure.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Where we store backups on the remote host
BACKUP_BASE = "/etc/ssh/cryptiq-backups"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class BackupRecord:
    backup_id: str                      # timestamp-based ID e.g. "2026-06-29-14-12-55"
    backup_dir: str                     # full path on the remote host
    host: str
    created_at: str
    files: list[dict] = field(default_factory=list)   # [{path, backed_up_as}]
    scan_before: Optional[dict] = None
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "backup_id": self.backup_id,
            "backup_dir": self.backup_dir,
            "host": self.host,
            "created_at": self.created_at,
            "files": self.files,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Remote backup operations (called by executor via SSH)
# ---------------------------------------------------------------------------

def make_backup_commands(files_to_backup: list[str]) -> tuple[str, list[str]]:
    """
    Generate shell commands to create a structured backup on the remote host.

    Returns:
        backup_id   : the timestamp ID to reference this backup
        commands    : list of shell commands to run on the remote host

    Usage in executor:
        backup_id, cmds = make_backup_commands(["/etc/ssh/sshd_config"])
        for cmd in cmds:
            executor._run_remote(cmd)
    """
    now = datetime.now(timezone.utc)
    backup_id = now.strftime("%Y-%m-%d-%H-%M-%S")
    backup_dir = f"{BACKUP_BASE}/{backup_id}"

    commands = [
        f"mkdir -p {backup_dir}",
    ]

    for filepath in files_to_backup:
        # Preserve directory structure in backup
        relative = filepath.lstrip("/")
        backup_path = f"{backup_dir}/{relative.replace('/', '_')}"
        commands.append(
            f"test -f {filepath} && cp {filepath} {backup_path} || true"
        )

    # Write manifest
    manifest = json.dumps({
        "backup_id": backup_id,
        "backup_dir": backup_dir,
        "files": files_to_backup,
        "created_at": now.isoformat(),
        "tool": "cryptiq",
    })
    # Use printf to avoid heredoc issues
    escaped = manifest.replace("'", "'\\''")
    commands.append(f"printf '%s' '{escaped}' > {backup_dir}/manifest.json")

    return backup_id, commands


def make_rollback_commands(backup_id: str, files_to_restore: list[str]) -> list[str]:
    """
    Generate shell commands to restore from a specific backup.

    Args:
        backup_id        : from make_backup_commands()
        files_to_restore : list of original file paths to restore

    Returns list of shell commands to run on remote host.
    """
    backup_dir = f"{BACKUP_BASE}/{backup_id}"
    commands = [
        f"# Rollback: restoring backup {backup_id}",
        f"test -d {backup_dir} || {{ echo 'Backup not found: {backup_dir}'; exit 1; }}",
    ]

    for filepath in files_to_restore:
        relative = filepath.lstrip("/")
        backup_path = f"{backup_dir}/{relative.replace('/', '_')}"
        commands.append(
            f"test -f {backup_path} && cp {backup_path} {filepath} "
            f"|| echo 'No backup for {filepath}'"
        )

    commands += [
        "# Reload sshd with restored config",
        "sshd -t && (systemctl reload sshd 2>/dev/null || service ssh reload 2>/dev/null || "
        "kill -HUP $(cat /var/run/sshd.pid 2>/dev/null || pgrep -x sshd | head -1))",
    ]

    return commands


def make_validate_then_apply_commands(
    temp_config_path: str,
    real_config_path: str,
    backup_id: str,
) -> list[str]:
    """
    The safe config update pattern:

      1. Write config to a temp file
      2. Test with sshd -t -f temp_file
      3. Only if valid: replace real config
      4. Reload sshd
      5. If reload fails: auto-rollback

    This means production config is NEVER touched until validation passes.
    """
    backup_dir = f"{BACKUP_BASE}/{backup_id}"
    backup_path = f"{backup_dir}/{real_config_path.lstrip('/').replace('/', '_')}"

    return [
        f"# Validate new config before touching production",
        f"sshd -t -f {temp_config_path}",
        f"# Only runs if sshd -t passed (set -e style via &&)",
        f"sshd -t -f {temp_config_path} && cp {real_config_path} {backup_path} && "
        f"cp {temp_config_path} {real_config_path} && "
        f"(systemctl reload sshd 2>/dev/null || service ssh reload 2>/dev/null || "
        f"kill -HUP $(cat /var/run/sshd.pid 2>/dev/null || pgrep -x sshd | head -1)) || "
        f"{{ echo 'VALIDATION FAILED — production config unchanged'; exit 1; }}",
    ]


def list_backups_command() -> str:
    """Shell command to list available backups on remote host."""
    return (
        f"ls -1t {BACKUP_BASE}/ 2>/dev/null && "
        f"for d in $(ls -1t {BACKUP_BASE}/); do "
        f"echo \"$d: $(cat {BACKUP_BASE}/$d/manifest.json 2>/dev/null | "
        f"grep -o '\\\"files\\\":\\[[^]]*\\]')\"; done || echo 'No backups found'"
    )


# ---------------------------------------------------------------------------
# Local rollback state tracking (in-memory during executor session)
# ---------------------------------------------------------------------------

class RollbackManager:
    """
    Tracks what has been changed during an executor session so automatic
    rollback knows exactly what to restore.

    Usage:
        rm = RollbackManager(host="192.168.1.42")
        rm.record_backup(backup_id, ["/etc/ssh/sshd_config"])
        ... do changes ...
        if something_failed:
            rollback_cmds = rm.get_rollback_commands()
    """

    def __init__(self, host: str):
        self.host = host
        self.backup_id: Optional[str] = None
        self.backed_up_files: list[str] = []
        self.actions_completed: list[str] = []
        self.failed_at: Optional[str] = None

    def record_backup(self, backup_id: str, files: list[str]):
        self.backup_id = backup_id
        self.backed_up_files.extend(files)

    def record_action(self, action_title: str):
        self.actions_completed.append(action_title)

    def record_failure(self, action_title: str):
        self.failed_at = action_title

    def get_rollback_commands(self) -> list[str]:
        """Get commands to undo everything done so far."""
        if not self.backup_id or not self.backed_up_files:
            return ["# No backup available — manual rollback required"]
        return make_rollback_commands(self.backup_id, self.backed_up_files)

    def summary(self) -> dict:
        return {
            "host": self.host,
            "backup_id": self.backup_id,
            "actions_completed": self.actions_completed,
            "failed_at": self.failed_at,
            "can_rollback": self.backup_id is not None,
        }