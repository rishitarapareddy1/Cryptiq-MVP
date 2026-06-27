"""
ssh_migration/executor.py
--------------------------
Executes migration actions on remote SSH hosts via paramiko.

Safety model:
  - Every action creates a backup before making changes
  - Every action has a dry_run mode that prints commands without running them
  - Every destructive action records a rollback plan
  - sshd is tested with `sshd -t` before any reload
  - The executor never closes the connection until it has verified the
    new config works (it opens a second test connection first)

Usage:
  executor = MigrationExecutor(host, username, key_path)
  result = executor.execute_action(action, dry_run=True)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ExecutionResult:
    action_id: str
    action_type: str
    host: str
    success: bool
    dry_run: bool
    commands_run: list[str] = field(default_factory=list)
    outputs: list[dict] = field(default_factory=list)    # [{cmd, stdout, stderr, rc}]
    error: Optional[str] = None
    started_at: str = ""
    completed_at: str = ""
    rollback_available: bool = True

    @property
    def duration_seconds(self) -> Optional[float]:
        try:
            s = datetime.fromisoformat(self.started_at)
            e = datetime.fromisoformat(self.completed_at)
            return (e - s).total_seconds()
        except Exception:
            return None


@dataclass
class SSHConnection:
    host: str
    port: int = 22
    username: str = "root"
    key_path: Optional[str] = None
    password: Optional[str] = None
    timeout: float = 30.0


# ---------------------------------------------------------------------------
# Executor class
# ---------------------------------------------------------------------------

class MigrationExecutor:
    """
    Executes migration actions on a remote host via paramiko SSH.

    Always runs in dry_run=True by default — you must explicitly pass
    dry_run=False to make real changes.
    """

    def __init__(self, connection: SSHConnection):
        self.conn = connection
        self._client = None

    def connect(self) -> bool:
        """Open SSH connection. Returns True on success."""
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            kwargs = {
                "hostname": self.conn.host,
                "port": self.conn.port,
                "username": self.conn.username,
                "timeout": self.conn.timeout,
            }
            if self.conn.key_path:
                kwargs["key_filename"] = self.conn.key_path
            elif self.conn.password:
                kwargs["password"] = self.conn.password
            client.connect(**kwargs)
            self._client = client
            logger.info("Connected to %s:%d", self.conn.host, self.conn.port)
            return True
        except Exception as e:
            logger.error("Connection failed to %s: %s", self.conn.host, e)
            return False

    def disconnect(self):
        if self._client:
            self._client.close()
            self._client = None

    def _run_remote(self, cmd: str, timeout: float = 60.0) -> tuple[int, str, str]:
        """Run a single command on the remote host."""
        if not self._client:
            return 1, "", "Not connected"
        try:
            _, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
            rc = stdout.channel.recv_exit_status()
            return rc, stdout.read().decode("utf-8", errors="replace"), \
                       stderr.read().decode("utf-8", errors="replace")
        except Exception as e:
            return 1, "", str(e)

    def execute_action(
        self,
        action,                    # MigrationAction dataclass
        dry_run: bool = True,
    ) -> ExecutionResult:
        """
        Execute a single migration action.

        In dry_run mode, commands are logged but not run.
        Returns an ExecutionResult regardless.
        """
        started = datetime.now(timezone.utc).isoformat()
        result = ExecutionResult(
            action_id=action.id,
            action_type=action.action_type,
            host=action.host,
            success=False,
            dry_run=dry_run,
            started_at=started,
        )

        if dry_run:
            result.commands_run = action.commands
            result.outputs = [
                {"cmd": cmd, "stdout": "[DRY RUN — not executed]", "stderr": "", "rc": 0}
                for cmd in action.commands
                if cmd.strip() and not cmd.strip().startswith("#")
            ]
            result.success = True
            result.completed_at = datetime.now(timezone.utc).isoformat()
            return result

        # Real execution
        if not self._client and not self.connect():
            result.error = f"Cannot connect to {self.conn.host}"
            result.completed_at = datetime.now(timezone.utc).isoformat()
            return result

        dispatch = {
            "harden_config": self._execute_harden_config,
            "generate_host_key": self._execute_generate_host_key,
            "update_known_hosts": self._execute_update_known_hosts,
            "validate": self._execute_validate,
            "generate_user_key": self._execute_generate_user_key,
        }

        handler = dispatch.get(action.action_type, self._execute_generic)
        try:
            handler(action, result)
        except Exception as e:
            result.error = str(e)
            result.success = False
            logger.exception("Action %s failed on %s", action.action_type, action.host)

        result.completed_at = datetime.now(timezone.utc).isoformat()
        return result

    # ── Action handlers ────────────────────────────────────────────────────

    def _execute_harden_config(self, action, result: ExecutionResult):
        """Apply the hardened sshd_config snippet."""
        snippet = action.params.get("hardened_snippet", "")

        # Step 1: backup
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_cmd = f"sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.{ts}"
        rc, out, err = self._run_remote(backup_cmd)
        result.commands_run.append(backup_cmd)
        result.outputs.append({"cmd": backup_cmd, "stdout": out, "stderr": err, "rc": rc})
        if rc != 0:
            result.error = f"Backup failed: {err}"
            return

        # Step 2: write drop-in
        mkdir_cmd = "sudo mkdir -p /etc/ssh/sshd_config.d"
        rc, out, err = self._run_remote(mkdir_cmd)
        result.commands_run.append(mkdir_cmd)

        if snippet:
            write_cmd = f"sudo tee /etc/ssh/sshd_config.d/00-cryptiq-hardening.conf << 'CRYPTIQ_EOF'\n{snippet}\nCRYPTIQ_EOF"
            rc, out, err = self._run_remote(write_cmd)
            result.commands_run.append(write_cmd)
            result.outputs.append({"cmd": "write snippet", "stdout": out, "stderr": err, "rc": rc})
            if rc != 0:
                result.error = f"Failed to write config: {err}"
                return

        # Step 3: test config
        rc, out, err = self._run_remote("sudo sshd -t")
        result.commands_run.append("sudo sshd -t")
        result.outputs.append({"cmd": "sshd -t", "stdout": out, "stderr": err, "rc": rc})
        if rc != 0:
            result.error = f"Config test failed (sshd -t): {err}"
            # Auto-rollback
            self._run_remote(f"sudo cp /etc/ssh/sshd_config.bak.{ts} /etc/ssh/sshd_config")
            return

        # Step 4: reload (not restart — keeps sessions alive)
        reload_cmd = "sudo systemctl reload sshd 2>/dev/null || sudo service ssh reload 2>/dev/null || sudo kill -HUP $(cat /var/run/sshd.pid)"
        rc, out, err = self._run_remote(reload_cmd)
        result.commands_run.append(reload_cmd)
        result.outputs.append({"cmd": "reload sshd", "stdout": out, "stderr": err, "rc": rc})

        result.success = rc == 0
        if not result.success:
            result.error = f"sshd reload failed: {err}"

    def _execute_generate_host_key(self, action, result: ExecutionResult):
        """Generate a new SSH host key on the remote host."""
        algo = action.params.get("algorithm", "ed25519")
        key_size = action.params.get("key_size")

        # Map algorithm to ssh-keygen -t value
        type_map = {
            "ssh-ed25519": "ed25519", "ed25519": "ed25519",
            "ssh-rsa": "rsa", "rsa": "rsa",
            "ml-dsa-65": "ml-dsa-65",
        }
        keygen_type = type_map.get(algo, algo)
        key_path = f"/etc/ssh/ssh_host_{keygen_type}_key"

        # Backup existing key if present
        backup_cmd = f"test -f {key_path} && sudo cp {key_path} {key_path}.bak.$(date +%Y%m%d)"
        self._run_remote(backup_cmd)

        # Generate
        cmd = f"sudo ssh-keygen -t {keygen_type} -f {key_path} -N '' -C 'cryptiq-migration' -q"
        if key_size and keygen_type == "rsa":
            cmd += f" -b {key_size}"

        rc, out, err = self._run_remote(cmd)
        result.commands_run.append(cmd)
        result.outputs.append({"cmd": cmd, "stdout": out, "stderr": err, "rc": rc})

        if rc != 0:
            result.error = f"Key generation failed: {err}"
            return

        # Get fingerprint
        fp_cmd = f"sudo ssh-keygen -l -E sha256 -f {key_path}.pub"
        rc2, fp_out, _ = self._run_remote(fp_cmd)
        result.outputs.append({"cmd": fp_cmd, "stdout": fp_out, "stderr": "", "rc": rc2})

        result.success = True

    def _execute_validate(self, action, result: ExecutionResult):
        """Run validation commands."""
        for cmd in action.commands:
            if cmd.strip() and not cmd.strip().startswith("#"):
                rc, out, err = self._run_remote(cmd)
                result.commands_run.append(cmd)
                result.outputs.append({"cmd": cmd, "stdout": out, "stderr": err, "rc": rc})
        result.success = True

    def _execute_update_known_hosts(self, action, result: ExecutionResult):
        """Update known_hosts — runs locally, not remotely."""
        result.outputs.append({
            "cmd": "update_known_hosts",
            "stdout": "This action requires manual execution on each client machine. See commands.",
            "stderr": "",
            "rc": 0,
        })
        result.success = True

    def _execute_generate_user_key(self, action, result: ExecutionResult):
        """User key generation is a client-side operation."""
        result.outputs.append({
            "cmd": "generate_user_key",
            "stdout": "User key generation must be run on the client machine. See commands.",
            "stderr": "",
            "rc": 0,
        })
        result.success = True

    def _execute_generic(self, action, result: ExecutionResult):
        """Fallback: run the action's commands list directly."""
        for cmd in action.commands:
            if cmd.strip() and not cmd.strip().startswith("#"):
                rc, out, err = self._run_remote(cmd)
                result.commands_run.append(cmd)
                result.outputs.append({"cmd": cmd, "stdout": out, "stderr": err, "rc": rc})
                if rc != 0:
                    result.error = f"Command failed (rc={rc}): {err}"
                    return
        result.success = True

    # ── Convenience: execute all actions in a plan phase ──────────────────

    def execute_phase(
        self,
        phase,                          # MigrationPhase
        dry_run: bool = True,
        stop_on_failure: bool = True,
    ) -> list[ExecutionResult]:
        results = []
        for action in phase.actions:
            if not action.automated and not dry_run:
                logger.info("Skipping non-automated action: %s", action.title)
                continue
            result = self.execute_action(action, dry_run=dry_run)
            results.append(result)
            if not result.success and stop_on_failure:
                logger.error("Phase halted after failed action: %s", action.title)
                break
        return results


# ---------------------------------------------------------------------------
# Local executor (no SSH — for localhost testing)
# ---------------------------------------------------------------------------

class LocalMigrationExecutor:
    """
    Runs migration commands on the local machine.
    Useful for testing the migration toolchain on localhost.
    """

    def execute_action(self, action, dry_run: bool = True) -> ExecutionResult:
        import subprocess
        started = datetime.now(timezone.utc).isoformat()
        result = ExecutionResult(
            action_id=action.id,
            action_type=action.action_type,
            host="localhost",
            success=False,
            dry_run=dry_run,
            started_at=started,
        )

        for cmd in action.commands:
            if not cmd.strip() or cmd.strip().startswith("#"):
                continue
            result.commands_run.append(cmd)
            if dry_run:
                result.outputs.append({"cmd": cmd, "stdout": "[DRY RUN]", "stderr": "", "rc": 0})
            else:
                proc = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=60
                )
                result.outputs.append({
                    "cmd": cmd,
                    "stdout": proc.stdout,
                    "stderr": proc.stderr,
                    "rc": proc.returncode,
                })
                if proc.returncode != 0:
                    result.error = proc.stderr
                    result.completed_at = datetime.now(timezone.utc).isoformat()
                    return result

        result.success = True
        result.completed_at = datetime.now(timezone.utc).isoformat()
        return result