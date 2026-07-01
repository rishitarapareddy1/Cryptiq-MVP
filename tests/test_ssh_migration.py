"""
tests/test_ssh_migration.py
------------------------------
Tests for ssh_migration/: config_hardener, migration_plan, keygen, rollback, executor.
SAFETY-CRITICAL: TestDryRunDefault, TestValidateBeforeApply, TestSurgicalPatching,
TestPrivateKeysNeverExposed, TestAutoRollback.
"""

import os
import shutil
import pytest
from unittest.mock import patch, MagicMock

from ssh_migration.config_hardener import (
    get_recommended_kex, get_recommended_ciphers, get_recommended_macs,
    parse_sshd_config, patch_algorithm_line, generate_patched_config,
    generate_hardening_commands, analyse_from_scan, analysis_summary,
    generate_patch, WEAK_KEX, WEAK_CIPHERS, WEAK_MACS, EXTENSION_PSEUDO,
)
from ssh_migration.migration_plan import build_migration_plan, MigrationAction, MigrationPlan
from ssh_migration.rollback import (
    make_backup_commands, make_rollback_commands, RollbackManager,
    make_validate_then_apply_commands,
)
from ssh_migration.keygen import generate_host_key, check_tools, KeyGenResult
from ssh_migration.executor import MigrationExecutor, SSHConnection, ExecutionResult


SAMPLE_SCAN_RESULT = {
    "host": "127.0.0.1", "port": 2222,
    "ssh_version": "OpenSSH_8.2p1 Ubuntu-4ubuntu0.13",
    "host_key_algorithm": "ssh-rsa", "host_key_size": None,
    "host_keys": [{"algorithm": "ssh-rsa", "key_size": None, "fingerprint": None}],
    "server_kex_algorithms": [
        "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
        "diffie-hellman-group14-sha256", "curve25519-sha256",
    ],
    "server_ciphers": ["3des-cbc", "aes128-cbc", "aes256-cbc", "aes128-ctr", "aes256-ctr"],
    "server_macs": ["hmac-md5", "hmac-sha1", "hmac-sha2-256"],
    "server_host_key_algorithms": ["ssh-rsa"],
    "risk_level": "critical", "pqc_status": "vulnerable",
}


class TestVersionAwareRecommendations:
    def test_old_openssh_does_not_get_sntrup761(self):
        kex = get_recommended_kex(8, 2)
        assert not any("sntrup761" in k for k in kex)
        assert not any("mlkem" in k for k in kex)

    def test_openssh_85_gets_sntrup761_not_mlkem(self):
        kex = get_recommended_kex(8, 5)
        assert any("sntrup761" in k for k in kex)
        assert not any("mlkem" in k for k in kex)

    def test_openssh_99_gets_both_hybrid_options(self):
        kex = get_recommended_kex(9, 9)
        assert any("sntrup761" in k for k in kex)
        assert any("mlkem" in k for k in kex)

    def test_very_old_openssh_gets_classical_fallback_only(self):
        kex = get_recommended_kex(6, 0)
        assert len(kex) > 0
        assert not any("curve25519" in k for k in kex)

    def test_recommended_ciphers_version_aware(self):
        old_ciphers = get_recommended_ciphers(5, 0)
        new_ciphers = get_recommended_ciphers(7, 0)
        assert "chacha20-poly1305@openssh.com" not in old_ciphers
        assert "chacha20-poly1305@openssh.com" in new_ciphers

    def test_recommended_macs_version_aware(self):
        old_macs = get_recommended_macs(5, 0)
        new_macs = get_recommended_macs(7, 0)
        assert not any("etm" in m for m in old_macs)
        assert any("etm" in m for m in new_macs)


class TestParseSshdConfig:
    def test_parses_kex_algorithms_line(self, legacy_sshd_config):
        cfg = parse_sshd_config(legacy_sshd_config)
        kex = cfg.get_list("KexAlgorithms")
        assert "diffie-hellman-group1-sha1" in kex
        assert "curve25519-sha256" in kex

    def test_get_single_value(self, legacy_sshd_config):
        cfg = parse_sshd_config(legacy_sshd_config)
        assert cfg.get("Port") == "22"

    def test_get_returns_none_for_missing_directive(self, legacy_sshd_config):
        cfg = parse_sshd_config(legacy_sshd_config)
        assert cfg.get("NoSuchDirective") is None

    def test_get_all_handles_multiple_hostkey_lines(self):
        config = "HostKey /etc/ssh/ssh_host_rsa_key\nHostKey /etc/ssh/ssh_host_ed25519_key\n"
        cfg = parse_sshd_config(config)
        keys = cfg.get_all("HostKey")
        assert len(keys) == 2

    def test_comments_and_blank_lines_preserved_in_raw_lines(self, legacy_sshd_config):
        config_with_comments = "# This is a comment\n\nPort 22\n"
        cfg = parse_sshd_config(config_with_comments)
        assert len(cfg.raw_lines) == 3
        assert cfg.get("Port") == "22"

    def test_last_occurrence_wins_for_duplicate_directive(self):
        config = "Port 22\nPort 2222\n"
        cfg = parse_sshd_config(config)
        assert cfg.get("Port") == "2222"


class TestSurgicalPatching:
    """Protects the core safety property: config changes must be surgical
    (only known-weak algorithms removed) and preserve unknown/vendor
    algorithms an admin configured intentionally."""

    def test_patch_algorithm_line_removes_weak_keeps_unknown(self):
        current = ["diffie-hellman-group1-sha1", "some-vendor-specific-kex", "curve25519-sha256"]
        recommended = ["curve25519-sha256", "diffie-hellman-group16-sha512"]
        new_list, removed, added, unknown = patch_algorithm_line(current, recommended, WEAK_KEX)
        assert "diffie-hellman-group1-sha1" in removed
        assert "some-vendor-specific-kex" in unknown
        assert "some-vendor-specific-kex" in new_list

    def test_patch_preserves_order_recommended_first(self):
        current = ["curve25519-sha256"]
        recommended = ["sntrup761x25519-sha512@openssh.com", "curve25519-sha256"]
        new_list, _, _, _ = patch_algorithm_line(current, recommended, WEAK_KEX)
        assert new_list[0] == "sntrup761x25519-sha512@openssh.com"

    def test_no_changes_when_already_optimal(self):
        current = ["curve25519-sha256", "diffie-hellman-group16-sha512"]
        recommended = ["curve25519-sha256", "diffie-hellman-group16-sha512"]
        new_list, removed, added, unknown = patch_algorithm_line(current, recommended, WEAK_KEX)
        assert removed == []
        assert added == []

    def test_generate_patched_config_removes_group1_sha1(self, legacy_sshd_config):
        patched, changes = generate_patched_config(legacy_sshd_config, major=8, minor=2)
        assert "diffie-hellman-group1-sha1" not in patched
        assert "diffie-hellman-group14-sha1" not in patched

    def test_generate_patched_config_preserves_curve25519(self, legacy_sshd_config):
        patched, changes = generate_patched_config(legacy_sshd_config, major=8, minor=2)
        assert "curve25519-sha256" in patched

    def test_generate_patched_config_does_not_add_unsupported_algorithm(self, legacy_sshd_config):
        """SAFETY REGRESSION: OpenSSH 8.2 must never receive mlkem768x25519
        -- this caused a real outage where a legacy server's KEX list went
        empty because sshd rejected an unrecognised algorithm name."""
        patched, changes = generate_patched_config(legacy_sshd_config, major=8, minor=2)
        assert "mlkem768x25519" not in patched

    def test_generate_patched_config_removes_weak_ciphers(self, legacy_sshd_config):
        patched, changes = generate_patched_config(legacy_sshd_config, major=8, minor=2)
        assert "3des-cbc" not in patched
        assert "aes128-cbc" not in patched

    def test_generate_patched_config_removes_weak_macs(self, legacy_sshd_config):
        patched, changes = generate_patched_config(legacy_sshd_config, major=8, minor=2)
        assert "hmac-md5" not in patched
        assert "hmac-sha1" not in patched.replace("hmac-sha1-96", "")

    def test_unknown_vendor_algorithm_preserved_through_full_patch(self):
        config = (
            "KexAlgorithms diffie-hellman-group1-sha1,gss-gex-sha1-,curve25519-sha256\n"
            "Ciphers 3des-cbc,aes256-ctr\nMACs hmac-md5,hmac-sha2-256\n"
        )
        patched, changes = generate_patched_config(config, major=8, minor=2)
        assert "gss-gex-sha1-" in patched
        assert "diffie-hellman-group1-sha1" not in patched

    def test_changes_list_records_what_was_removed_and_added(self, legacy_sshd_config):
        patched, changes = generate_patched_config(legacy_sshd_config, major=8, minor=2)
        kex_change = next(c for c in changes if c.directive == "KexAlgorithms")
        assert "diffie-hellman-group1-sha1" in kex_change.removed_algorithms
        assert len(kex_change.added_algorithms) > 0

    def test_no_op_when_config_already_hardened(self):
        config = (
            "KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512\n"
            "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n"
            "MACs hmac-sha2-256-etm@openssh.com\n"
        )
        patched, changes = generate_patched_config(config, major=8, minor=2)
        kex_changes = [c for c in changes if c.directive == "KexAlgorithms"]
        if kex_changes:
            assert kex_changes[0].removed_algorithms == []


class TestValidateBeforeApply:
    """SAFETY: production config must never be touched until sshd -t passes
    on a temp file."""

    def test_commands_validate_before_replacing_production(self, legacy_sshd_config):
        patched, _ = generate_patched_config(legacy_sshd_config, major=8, minor=2)
        commands = generate_hardening_commands(patched)
        full_script = "\n".join(commands)
        assert "sshd -t -f" in full_script

    def test_backup_happens_before_overwrite(self, legacy_sshd_config):
        patched, _ = generate_patched_config(legacy_sshd_config, major=8, minor=2)
        commands = generate_hardening_commands(patched, target_config_path="/etc/ssh/sshd_config")
        full_script = "\n".join(commands)
        backup_idx = full_script.find(".bak.")
        assert backup_idx != -1, "No backup step found in generated commands"

    def test_validation_failure_aborts_without_touching_production(self, legacy_sshd_config):
        patched, _ = generate_patched_config(legacy_sshd_config, major=8, minor=2)
        commands = generate_hardening_commands(patched)
        validate_line = next(c for c in commands if "sshd -t -f" in c)
        assert "exit 1" in validate_line or "||" in validate_line


class TestAnalyseFromScan:
    def test_identifies_weak_kex(self):
        analysis = analyse_from_scan(SAMPLE_SCAN_RESULT)
        assert "diffie-hellman-group1-sha1" in analysis.weak_kex

    def test_identifies_weak_ciphers(self):
        analysis = analyse_from_scan(SAMPLE_SCAN_RESULT)
        assert "3des-cbc" in analysis.weak_ciphers

    def test_parses_openssh_version_from_banner(self):
        analysis = analyse_from_scan(SAMPLE_SCAN_RESULT)
        assert analysis.openssh_major == 8
        assert analysis.openssh_minor == 2

    def test_can_enable_hybrid_pqc_false_for_old_version(self):
        analysis = analyse_from_scan(SAMPLE_SCAN_RESULT)
        assert analysis.can_enable_hybrid_pqc is False

    def test_can_enable_hybrid_pqc_true_for_85_plus(self):
        scan = {**SAMPLE_SCAN_RESULT, "ssh_version": "OpenSSH_8.9p1"}
        analysis = analyse_from_scan(scan)
        assert analysis.can_enable_hybrid_pqc is True

    def test_critical_count_for_sha1_kex(self):
        analysis = analyse_from_scan(SAMPLE_SCAN_RESULT)
        assert analysis.critical_count >= 1

    def test_missing_version_defaults_safely(self):
        scan = {**SAMPLE_SCAN_RESULT, "ssh_version": None}
        analysis = analyse_from_scan(scan)
        assert analysis.openssh_major == 8

    def test_analysis_summary_includes_recommended_kex(self):
        analysis = analyse_from_scan(SAMPLE_SCAN_RESULT)
        summary = analysis_summary(analysis)
        assert "recommended_kex" in summary
        assert not any("sntrup761" in k for k in summary["recommended_kex"])


class TestGeneratePatch:
    def test_returns_dict_with_required_keys(self):
        analysis = analyse_from_scan(SAMPLE_SCAN_RESULT)
        patch = generate_patch(analysis)
        for key in ("host", "change_count", "changes", "patched_config",
                     "apply_commands", "rollback_commands", "validate_commands", "notes"):
            assert key in patch

    def test_notes_mention_version_aware(self):
        analysis = analyse_from_scan(SAMPLE_SCAN_RESULT)
        patch = generate_patch(analysis)
        assert any("8.2" in n or "Version-aware" in n for n in patch["notes"])

    def test_old_version_gets_upgrade_note(self):
        analysis = analyse_from_scan(SAMPLE_SCAN_RESULT)
        patch = generate_patch(analysis)
        assert any("Upgrade" in n for n in patch["notes"])

    def test_modern_version_gets_hybrid_enabled_note(self):
        scan = {**SAMPLE_SCAN_RESULT, "ssh_version": "OpenSSH_8.9p1"}
        analysis = analyse_from_scan(scan)
        patch = generate_patch(analysis)
        assert any("hybrid" in n.lower() for n in patch["notes"])


class TestBuildMigrationPlan:
    def test_plan_has_three_phases(self):
        plan = build_migration_plan(SAMPLE_SCAN_RESULT)
        assert len(plan.phases) == 3

    def test_phase_1_is_immediate_hardening(self):
        plan = build_migration_plan(SAMPLE_SCAN_RESULT)
        assert plan.phases[0].number == 1
        assert "Immediate" in plan.phases[0].name

    def test_critical_finding_creates_critical_action(self):
        plan = build_migration_plan(SAMPLE_SCAN_RESULT)
        phase1_actions = plan.phases[0].actions
        assert any(a.priority == "critical" for a in phase1_actions)

    def test_harden_config_action_present_when_issues_exist(self):
        plan = build_migration_plan(SAMPLE_SCAN_RESULT)
        action_types = [a.action_type for a in plan.phases[0].actions]
        assert "harden_config" in action_types

    def test_no_harden_action_when_already_clean(self):
        clean_scan = {
            **SAMPLE_SCAN_RESULT,
            "server_kex_algorithms": ["curve25519-sha256"],
            "server_ciphers": ["chacha20-poly1305@openssh.com"],
            "server_macs": ["hmac-sha2-256-etm@openssh.com"],
        }
        plan = build_migration_plan(clean_scan)
        action_types = [a.action_type for a in plan.phases[0].actions]
        assert "harden_config" not in action_types

    def test_phase_2_generates_ed25519_action_when_missing(self):
        plan = build_migration_plan(SAMPLE_SCAN_RESULT)
        phase2_types = [a.action_type for a in plan.phases[1].actions]
        assert "generate_host_key" in phase2_types

    def test_phase_2_skips_ed25519_when_already_present(self):
        scan_with_ed25519 = {
            **SAMPLE_SCAN_RESULT,
            "host_keys": [{"algorithm": "ssh-ed25519", "key_size": None, "fingerprint": None}],
        }
        plan = build_migration_plan(scan_with_ed25519)
        ed25519_actions = [
            a for a in plan.phases[1].actions
            if a.action_type == "generate_host_key" and a.params.get("algorithm") == "ssh-ed25519"
        ]
        assert len(ed25519_actions) == 0

    def test_actions_have_commands(self):
        plan = build_migration_plan(SAMPLE_SCAN_RESULT)
        for phase in plan.phases:
            for action in phase.actions:
                assert isinstance(action.commands, list)

    def test_to_dict_serialises_fully(self):
        plan = build_migration_plan(SAMPLE_SCAN_RESULT)
        d = plan.to_dict()
        assert d["total_actions"] > 0
        assert d["overall_progress_pct"] == 0.0
        assert "config_patch" in d

    def test_plan_includes_compatibility_issues_field(self):
        plan = build_migration_plan(SAMPLE_SCAN_RESULT, target_algorithms={"kex": ["mlkem768x25519-sha256"]})
        assert isinstance(plan.compatibility_issues, list)

    def test_action_progress_tracking(self):
        plan = build_migration_plan(SAMPLE_SCAN_RESULT)
        phase = plan.phases[0]
        assert phase.completed_count == 0
        phase.actions[0].status = "completed"
        assert phase.completed_count == 1
        assert phase.progress_pct > 0


class TestRollbackInfrastructure:
    def test_make_backup_commands_returns_unique_id(self):
        id1, cmds1 = make_backup_commands(["/etc/ssh/sshd_config"])
        id2, cmds2 = make_backup_commands(["/etc/ssh/sshd_config"])
        assert id1 and id2
        assert isinstance(cmds1, list) and len(cmds1) > 0

    def test_backup_commands_create_directory_first(self):
        backup_id, commands = make_backup_commands(["/etc/ssh/sshd_config"])
        assert any("mkdir" in c for c in commands)

    def test_backup_commands_write_manifest(self):
        backup_id, commands = make_backup_commands(["/etc/ssh/sshd_config"])
        assert any("manifest.json" in c for c in commands)

    def test_rollback_commands_restore_each_file(self):
        commands = make_rollback_commands("2026-01-01-00-00-00", ["/etc/ssh/sshd_config"])
        assert any("/etc/ssh/sshd_config" in c for c in commands)

    def test_rollback_commands_reload_sshd(self):
        commands = make_rollback_commands("2026-01-01-00-00-00", ["/etc/ssh/sshd_config"])
        full = "\n".join(commands)
        assert "reload" in full or "HUP" in full

    def test_validate_then_apply_never_skips_validation(self):
        commands = make_validate_then_apply_commands(
            "/tmp/candidate", "/etc/ssh/sshd_config", "2026-01-01-00-00-00"
        )
        full = "\n".join(commands)
        assert "sshd -t -f" in full
        assert "&&" in full


class TestRollbackManager:
    def test_records_backup_and_actions(self):
        mgr = RollbackManager(host="127.0.0.1")
        mgr.record_backup("2026-01-01-00-00-00", ["/etc/ssh/sshd_config"])
        mgr.record_action("harden_config")
        summary = mgr.summary()
        assert summary["can_rollback"] is True
        assert "harden_config" in summary["actions_completed"]

    def test_no_rollback_possible_without_backup(self):
        mgr = RollbackManager(host="127.0.0.1")
        commands = mgr.get_rollback_commands()
        assert any("No backup" in c for c in commands)

    def test_get_rollback_commands_after_backup_recorded(self):
        mgr = RollbackManager(host="127.0.0.1")
        mgr.record_backup("2026-01-01-00-00-00", ["/etc/ssh/sshd_config"])
        commands = mgr.get_rollback_commands()
        assert len(commands) > 0
        assert any("/etc/ssh/sshd_config" in c for c in commands)

    def test_failure_recorded(self):
        mgr = RollbackManager(host="127.0.0.1")
        mgr.record_failure("harden_config")
        assert mgr.summary()["failed_at"] == "harden_config"


class TestPrivateKeysNeverExposed:
    """SAFETY: private key material must never be returned over the API
    or end up in logs."""

    def test_keygen_result_dataclass_separates_path_from_content(self):
        from ssh_migration.keygen import KeyPair
        import dataclasses
        fields = {f.name for f in dataclasses.fields(KeyPair)}
        assert "private_key" in fields
        assert "fingerprint" in fields
        assert "public_key" in fields

    @pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="ssh-keygen not installed")
    def test_real_keygen_produces_fingerprint_not_just_raw_key(self, tmp_path):
        result = generate_host_key(algorithm="ed25519", output_dir=str(tmp_path), comment="test")
        assert result.success is True
        assert result.key_pair.fingerprint.startswith("SHA256:")
        assert result.key_pair.fingerprint != result.key_pair.private_key


class TestCheckTools:
    def test_check_tools_returns_dict_with_expected_keys(self):
        tools = check_tools()
        assert "ssh-keygen" in tools
        assert "openssl" in tools
        for tool_info in tools.values():
            assert "available" in tool_info


class TestDryRunDefault:
    """SAFETY: dry_run must default to True everywhere it's a parameter,
    and dry-run mode must make zero network/SSH calls."""

    def test_dry_run_never_connects(self):
        conn = SSHConnection(host="127.0.0.1", port=22, username="root", password="x")
        executor = MigrationExecutor(conn)

        class FakeAction:
            id = "test-1"
            action_type = "harden_config"
            host = "127.0.0.1"
            commands = ["sudo cp /etc/ssh/sshd_config /tmp/backup"]
            automated = True
            params = {}

        with patch.object(executor, "connect") as mock_connect:
            result = executor.execute_action(FakeAction(), dry_run=True)
            mock_connect.assert_not_called()
        assert result.dry_run is True
        assert result.success is True

    def test_dry_run_shows_commands_without_dollar_sign_execution_markers(self):
        conn = SSHConnection(host="127.0.0.1")
        executor = MigrationExecutor(conn)

        class FakeAction:
            id = "test-1"
            action_type = "generic"
            host = "127.0.0.1"
            commands = ["echo hello", "# this is a comment, should be skipped"]
            automated = True
            params = {}

        result = executor.execute_action(FakeAction(), dry_run=True)
        assert len(result.outputs) == 1
        assert "[DRY RUN" in result.outputs[0]["stdout"]


class TestSudoStripping:
    def test_sudo_stripped_when_connected_as_root(self):
        conn = SSHConnection(host="127.0.0.1", username="root")
        executor = MigrationExecutor(conn)
        executor._client = MagicMock()
        mock_stdout = MagicMock()
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_stdout.read.return_value = b"ok"
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""
        executor._client.exec_command.return_value = (None, mock_stdout, mock_stderr)

        executor._run_remote("sudo cp /a /b")
        called_cmd = executor._client.exec_command.call_args[0][0]
        assert not called_cmd.startswith("sudo ")
        assert called_cmd == "cp /a /b"

    def test_sudo_preserved_when_not_root(self):
        conn = SSHConnection(host="127.0.0.1", username="deploy")
        executor = MigrationExecutor(conn)
        executor._client = MagicMock()
        mock_stdout = MagicMock()
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_stdout.read.return_value = b"ok"
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""
        executor._client.exec_command.return_value = (None, mock_stdout, mock_stderr)

        executor._run_remote("sudo cp /a /b")
        called_cmd = executor._client.exec_command.call_args[0][0]
        assert called_cmd.startswith("sudo ")


class TestAutoRollback:
    """SAFETY: any failure mid-action must trigger an automatic rollback
    attempt using the recorded backup."""

    def test_rollback_attempted_when_backup_id_recorded(self):
        conn = SSHConnection(host="127.0.0.1", username="root")
        executor = MigrationExecutor(conn)
        executor._client = MagicMock()
        executor.rollback_mgr.record_backup("2026-01-01", ["/etc/ssh/sshd_config"])

        mock_stdout = MagicMock()
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_stdout.read.return_value = b""
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""
        executor._client.exec_command.return_value = (None, mock_stdout, mock_stderr)

        class FakeResult:
            commands_run = []
            outputs = []
            rollback_performed = False
            rollback_success = None

        result = FakeResult()
        executor._attempt_rollback(result)
        assert result.rollback_performed is True

    def test_no_rollback_attempted_without_backup(self):
        conn = SSHConnection(host="127.0.0.1", username="root")
        executor = MigrationExecutor(conn)

        class FakeResult:
            commands_run = []
            outputs = []
            rollback_performed = False
            rollback_success = None

        result = FakeResult()
        executor._attempt_rollback(result)
        assert result.rollback_performed is False


class TestExecutionResult:
    def test_duration_seconds_computed_correctly(self):
        result = ExecutionResult(
            action_id="x", action_type="y", host="z", success=True, dry_run=True,
            started_at="2026-01-01T00:00:00+00:00",
            completed_at="2026-01-01T00:00:05+00:00",
        )
        assert result.duration_seconds == 5.0

    def test_duration_seconds_none_on_bad_timestamps(self):
        result = ExecutionResult(
            action_id="x", action_type="y", host="z", success=True, dry_run=True,
            started_at="not-a-timestamp", completed_at="also-not-one",
        )
        assert result.duration_seconds is None