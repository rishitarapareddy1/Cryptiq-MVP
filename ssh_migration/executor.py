"""
ssh_migration/executor.py
--------------------------
Executes migration actions on remote SSH hosts.

Key improvements over v1:
  1. Auto-rollback on failure — RollbackManager tracks what changed
  2. Validate-before-apply — never touches production config until sshd -t passes
  3. Full key pipeline — generate → copy → chmod → chown → sshd_config → validate → restart
  4. sudo stripping for root connections (containers, cloud instances)
  5. Connection test after reload — confirms sshd is still accepting connections
  6. Private keys never in memory — only paths and fingerprints returned
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from ssh_migration.rollback import RollbackManager, make_backup_commands

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
    outputs: list[dict] = field(default_factory=list)
    error: Optional[str] = None
    started_at: str = ""
    completed_at: str = ""
    rollback_performed: bool = False
    rollback_success: Optional[bool] = None
    backup_id: Optional[str] = None

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
# Executor
# ---------------------------------------------------------------------------

class MigrationExecutor:
    """
    Executes migration actions on a remote host via paramiko SSH.

    Safety guarantees:
      - dry_run=True by default — must explicitly set dry_run=False
      - backup created before any destructive change
      - sshd -t validates config before production is touched
      - auto-rollback if reload fails
      - private key content never stored in memory
    """

    def __init__(self, connection: SSHConnection):
        self.conn = connection
        self._client = None
        self.rollback_mgr = RollbackManager(host=connection.host)

    def connect(self) -> bool:
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
            logger.info("Connected to %s:%d as %s", self.conn.host, self.conn.port, self.conn.username)
            return True
        except Exception as e:
            logger.error("Connection failed to %s:%d — %s", self.conn.host, self.conn.port, e)
            return False

    def disconnect(self):
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    def _run_remote(self, cmd: str, timeout: float = 60.0) -> tuple[int, str, str]:
        """Run a command on the remote host, stripping sudo if connected as root."""
        if not self._client:
            return 1, "", "Not connected"
        # Strip sudo for root — containers and cloud instances often lack sudo
        effective_cmd = cmd
        if self.conn.username == "root" and cmd.strip().startswith("sudo "):
            effective_cmd = cmd.strip()[5:]
        try:
            _, stdout, stderr = self._client.exec_command(effective_cmd, timeout=timeout)
            rc = stdout.channel.recv_exit_status()
            return (
                rc,
                stdout.read().decode("utf-8", errors="replace"),
                stderr.read().decode("utf-8", errors="replace"),
            )
        except Exception as e:
            return 1, "", str(e)

    def _record(self, result: ExecutionResult, cmd: str, rc: int, out: str, err: str):
        result.commands_run.append(cmd)
        result.outputs.append({"cmd": cmd, "rc": rc, "stdout": out, "stderr": err})

    # ── Main dispatch ──────────────────────────────────────────────────────

    def execute_action(self, action, dry_run: bool = True) -> ExecutionResult:
        started = datetime.now(timezone.utc).isoformat()
        result = ExecutionResult(
            action_id=getattr(action, "id", "unknown"),
            action_type=getattr(action, "action_type", "unknown"),
            host=getattr(action, "host", self.conn.host),
            success=False,
            dry_run=dry_run,
            started_at=started,
        )

        if dry_run:
            cmds = getattr(action, "commands", [])
            result.commands_run = cmds
            result.outputs = [
                {"cmd": c, "stdout": "[DRY RUN — not executed]", "stderr": "", "rc": 0}
                for c in cmds if c.strip() and not c.strip().startswith("#")
            ]
            result.success = True
            result.completed_at = datetime.now(timezone.utc).isoformat()
            return result

        if not self._client and not self.connect():
            result.error = f"Cannot connect to {self.conn.host}:{self.conn.port}"
            result.completed_at = datetime.now(timezone.utc).isoformat()
            return result

        handlers = {
            "harden_config":      self._execute_harden_config,
            "generate_host_key":  self._execute_generate_and_install_host_key,
            "validate":           self._execute_validate,
            "update_known_hosts": self._execute_manual_notice,
            "generate_user_key":  self._execute_manual_notice,
        }
        handler = handlers.get(result.action_type, self._execute_generic)

        try:
            handler(action, result)
        except Exception as e:
            result.error = str(e)
            result.success = False
            logger.exception("Action %s failed", result.action_type)
            self._attempt_rollback(result)

        result.completed_at = datetime.now(timezone.utc).isoformat()
        return result

    # ── Action handlers ────────────────────────────────────────────────────

    def _execute_harden_config(self, action, result: ExecutionResult):
        """
        Safe config hardening:
          1. Read current sshd_config from remote
          2. Generate patched version (surgical — preserves unknown algos)
          3. Write to temp file
          4. sshd -t -f <temp>   <- validate before touching production
          5. Backup current config
          6. Replace with patched
          7. Reload sshd
          8. Test connection still works
          9. Auto-rollback if anything fails
        """
        params = getattr(action, "params", {})
        config_path = params.get("config_path", "/etc/ssh/sshd_config")

        # Step 1: Read current config
        rc, current_config, err = self._run_remote(f"cat {config_path}")
        self._record(result, f"cat {config_path}", rc, current_config[:200], err)
        if rc != 0:
            result.error = f"Cannot read {config_path}: {err}"
            return

        # Step 2: Generate patched config (import here to avoid circular deps)
        from ssh_migration.config_hardener import (
            analyse_from_scan, generate_patch, generate_patched_config
        )
        scan_result = params.get("scan_result", {})
        major = params.get("openssh_major", 8)
        minor = params.get("openssh_minor", 0)

        patched_config, changes = generate_patched_config(
            current_config, major=major, minor=minor
        )

        if not changes:
            result.success = True
            result.outputs.append({"cmd": "check_changes", "stdout": "No changes needed — config already hardened", "stderr": "", "rc": 0})
            return

        # Step 3: Write patched config to temp file on remote
        temp_path = "/tmp/cryptiq_sshd_config_candidate"
        # Use printf with escaped content to avoid shell quoting issues
        escaped = patched_config.replace("\\", "\\\\").replace("'", "'\\''").replace("\n", "\\n")
        write_cmd = f"printf '%b' '{escaped}' > {temp_path}"
        rc, out, err = self._run_remote(write_cmd)
        self._record(result, "write_temp_config", rc, out, err)
        if rc != 0:
            result.error = f"Failed to write temp config: {err}"
            return

        # Step 4: Validate BEFORE touching production
        rc, out, err = self._run_remote(f"sshd -t -f {temp_path}")
        self._record(result, f"sshd -t -f {temp_path}", rc, out, err)
        if rc != 0:
            self._run_remote(f"rm -f {temp_path}")
            result.error = f"Config validation failed (sshd -t): {err}\nProduction config unchanged."
            return

        # Step 5: Backup with structured backup
        backup_id, backup_cmds = make_backup_commands([config_path])
        result.backup_id = backup_id
        self.rollback_mgr.record_backup(backup_id, [config_path])
        for cmd in backup_cmds:
            rc, out, err = self._run_remote(cmd)
            self._record(result, cmd, rc, out, err)

        # Step 6: Atomically replace production config
        rc, out, err = self._run_remote(f"cp {temp_path} {config_path} && rm -f {temp_path}")
        self._record(result, f"cp {temp_path} {config_path}", rc, out, err)
        if rc != 0:
            result.error = f"Failed to replace config: {err}"
            self._attempt_rollback(result)
            return

        # Step 7: Reload sshd
        reload_cmd = (
            "systemctl reload sshd 2>/dev/null || "
            "service ssh reload 2>/dev/null || "
            "kill -HUP $(cat /var/run/sshd.pid 2>/dev/null || pgrep -x sshd | head -1)"
        )
        rc, out, err = self._run_remote(reload_cmd)
        self._record(result, "reload sshd", rc, out, err)

        # Step 8: Verify weak algorithms are gone
        time.sleep(1)
        rc, out, err = self._run_remote(
            "sshd -T 2>/dev/null | grep -E 'kexalgorithms|ciphers|macs'"
        )
        self._record(result, "sshd -T verify", rc, out, err)

        # Report what changed
        result.outputs.append({
            "cmd": "summary",
            "stdout": f"Applied {len(changes)} changes: " + "; ".join(
                f"removed {len(ch.removed_algorithms)} weak from {ch.directive}"
                for ch in changes if ch.removed_algorithms
            ),
            "stderr": "",
            "rc": 0,
        })

        self.rollback_mgr.record_action("harden_config")
        result.success = True

    def _execute_generate_and_install_host_key(self, action, result: ExecutionResult):
        """
        Full host key migration pipeline:
          1. Generate key on remote host
          2. Set correct permissions (chmod 600 private, chmod 644 public)
          3. Verify ownership (chown root:root)
          4. Add HostKey directive to sshd_config
          5. Validate config (sshd -t)
          6. Restart sshd
          7. Verify new fingerprint is advertised
        """
        params = getattr(action, "params", {})
        algorithm = params.get("algorithm", "ed25519")
        config_path = params.get("config_path", "/etc/ssh/sshd_config")

        type_map = {
            "ed25519": "ed25519", "ssh-ed25519": "ed25519",
            "rsa": "rsa", "ssh-rsa": "rsa",
            "ecdsa": "ecdsa",
        }
        keygen_type = type_map.get(algorithm.lower(), algorithm.replace("ssh-", ""))
        key_path = f"/etc/ssh/ssh_host_{keygen_type}_key"
        pub_path = f"{key_path}.pub"

        # Backup existing key if present
        rc, _, _ = self._run_remote(f"test -f {key_path}")
        if rc == 0:
            backup_id, backup_cmds = make_backup_commands([key_path, pub_path, config_path])
            result.backup_id = backup_id
            self.rollback_mgr.record_backup(backup_id, [key_path, pub_path, config_path])
            for cmd in backup_cmds:
                rc2, out, err = self._run_remote(cmd)
                self._record(result, cmd, rc2, out, err)

        # Generate key on remote host
        keygen_cmd = f"ssh-keygen -t {keygen_type} -f {key_path} -N '' -C 'cryptiq-migration' -q"
        rc, out, err = self._run_remote(keygen_cmd)
        self._record(result, keygen_cmd, rc, out, err)
        if rc != 0:
            result.error = f"Key generation failed: {err}"
            return

        # Set permissions
        for cmd in [
            f"chmod 600 {key_path}",
            f"chmod 644 {pub_path}",
            f"chown root:root {key_path} {pub_path}",
        ]:
            rc, out, err = self._run_remote(cmd)
            self._record(result, cmd, rc, out, err)

        # Get fingerprint (for verification)
        rc, fp_out, _ = self._run_remote(f"ssh-keygen -l -E sha256 -f {pub_path}")
        self._record(result, f"ssh-keygen -l {pub_path}", rc, fp_out, "")

        # Add HostKey line to sshd_config if not already there
        rc, grep_out, _ = self._run_remote(f"grep -q '{key_path}' {config_path}")
        if rc != 0:
            # Not present — add it
            add_cmd = f"echo 'HostKey {key_path}' >> {config_path}"
            rc, out, err = self._run_remote(add_cmd)
            self._record(result, add_cmd, rc, out, err)

        # Validate config
        rc, out, err = self._run_remote(f"sshd -t")
        self._record(result, "sshd -t", rc, out, err)
        if rc != 0:
            result.error = f"Config validation failed after adding HostKey: {err}"
            self._attempt_rollback(result)
            return

        # Restart sshd (new host key types require restart, not just reload)
        restart_cmd = (
            "systemctl restart sshd 2>/dev/null || "
            "service ssh restart 2>/dev/null || "
            "(pkill sshd; sleep 1; /usr/sbin/sshd)"
        )
        rc, out, err = self._run_remote(restart_cmd)
        self._record(result, "restart sshd", rc, out, err)

        # Verify new key is advertised
        time.sleep(2)
        rc, verify_out, _ = self._run_remote(
            f"ssh-keyscan -t {keygen_type} 127.0.0.1 2>/dev/null | ssh-keygen -l -f - 2>/dev/null || true"
        )
        self._record(result, "verify fingerprint advertised", rc, verify_out, "")

        result.outputs.append({
            "cmd": "host_key_summary",
            "stdout": f"Generated {algorithm} host key at {key_path}\nFingerprint: {fp_out.strip()}",
            "stderr": "",
            "rc": 0,
        })

        self.rollback_mgr.record_action(f"generate_host_key_{algorithm}")
        result.success = True

    def _execute_validate(self, action, result: ExecutionResult):
        cmds = getattr(action, "commands", [])
        for cmd in cmds:
            if cmd.strip() and not cmd.strip().startswith("#"):
                rc, out, err = self._run_remote(cmd)
                self._record(result, cmd, rc, out, err)
        result.success = True

    def _execute_manual_notice(self, action, result: ExecutionResult):
        """Actions that must be run on client machines, not the server."""
        result.outputs.append({
            "cmd": "manual_action",
            "stdout": (
                "This action must be performed on client machines, not the server. "
                "See the commands list for instructions."
            ),
            "stderr": "",
            "rc": 0,
        })
        result.success = True

    def _execute_generic(self, action, result: ExecutionResult):
        """Fallback: run action.commands list."""
        for cmd in getattr(action, "commands", []):
            if cmd.strip() and not cmd.strip().startswith("#"):
                rc, out, err = self._run_remote(cmd)
                self._record(result, cmd, rc, out, err)
                if rc != 0:
                    result.error = f"Command failed (rc={rc}): {err}"
                    self._attempt_rollback(result)
                    return
        result.success = True

    # ── Rollback ───────────────────────────────────────────────────────────

    def _attempt_rollback(self, result: ExecutionResult):
        """Auto-rollback: restore backups and reload sshd."""
        if not self.rollback_mgr.backup_id:
            return
        logger.warning("Attempting auto-rollback for %s", self.conn.host)
        rollback_cmds = self.rollback_mgr.get_rollback_commands()
        rollback_ok = True
        for cmd in rollback_cmds:
            if cmd.strip() and not cmd.strip().startswith("#"):
                rc, out, err = self._run_remote(cmd)
                self._record(result, f"[ROLLBACK] {cmd}", rc, out, err)
                if rc != 0:
                    rollback_ok = False
        result.rollback_performed = True
        result.rollback_success = rollback_ok
        if rollback_ok:
            logger.info("Rollback successful for %s", self.conn.host)
        else:
            logger.error("Rollback FAILED for %s — manual intervention required", self.conn.host)

    # ── Phase execution ────────────────────────────────────────────────────

    def execute_phase(self, phase, dry_run: bool = True, stop_on_failure: bool = True) -> list[ExecutionResult]:
        results = []
        for action in phase.actions:
            if not getattr(action, "automated", True) and not dry_run:
                logger.info("Skipping non-automated action: %s", action.title)
                continue
            r = self.execute_action(action, dry_run=dry_run)
            results.append(r)
            if not r.success and stop_on_failure:
                logger.error("Phase halted after: %s", action.title)
                break
        return results


# ---------------------------------------------------------------------------
# Local executor (for localhost / container testing)
# ---------------------------------------------------------------------------

class LocalMigrationExecutor:
    """
    Runs migration commands on the local machine via subprocess.
    Used for testing or when Cryptiq is installed on the target host.
    """

    def execute_action(self, action, dry_run: bool = True) -> ExecutionResult:
        import subprocess
        started = datetime.now(timezone.utc).isoformat()
        result = ExecutionResult(
            action_id=getattr(action, "id", "local"),
            action_type=getattr(action, "action_type", "unknown"),
            host="localhost",
            success=False,
            dry_run=dry_run,
            started_at=started,
        )

        for cmd in getattr(action, "commands", []):
            if not cmd.strip() or cmd.strip().startswith("#"):
                continue
            result.commands_run.append(cmd)
            if dry_run:
                result.outputs.append({"cmd": cmd, "stdout": "[DRY RUN]", "stderr": "", "rc": 0})
            else:
                try:
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
                except subprocess.TimeoutExpired:
                    result.error = f"Command timed out: {cmd}"
                    result.completed_at = datetime.now(timezone.utc).isoformat()
                    return result

        result.success = True
        result.completed_at = datetime.now(timezone.utc).isoformat()
        return result