"""
ssh_migration/migration_plan.py
--------------------------------
Migration plan generator.

Takes a scan result (or list of them) and produces a structured,
prioritised migration plan with concrete actions, estimated effort,
and ordering.

A plan has:
  - Phases  : ordered groups of actions (immediate / short / medium term)
  - Actions : individual steps (generate key, update config, etc.)
  - For each action: what to do, commands, risk, rollback

This is the bridge between the scanner ("here's what you have")
and the executor ("here's what to run").
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from ssh_migration.algorithms import check_compatibility
from ssh_migration.config_hardener import (
    analyse_from_scan, generate_patch,
    analysis_summary, patch_summary,
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class MigrationAction:
    id: str
    phase: int                    # 1 = immediate, 2 = near-term, 3 = medium
    action_type: str              # "generate_host_key" | "harden_config" |
                                  # "generate_user_key" | "update_known_hosts" | "validate"
    title: str
    description: str
    host: str
    priority: str                 # "critical" | "high" | "normal" | "low"
    estimated_minutes: int        # rough effort estimate
    automated: bool               # can Cryptiq execute this automatically?
    requires_downtime: bool       # does sshd need to restart?
    commands: list[str] = field(default_factory=list)
    rollback_commands: list[str] = field(default_factory=list)
    params: dict = field(default_factory=dict)  # action-specific parameters
    status: str = "pending"       # pending | in_progress | completed | failed | skipped
    completed_at: Optional[str] = None
    notes: str = ""


@dataclass
class MigrationPhase:
    number: int
    name: str
    description: str
    timeline: str                 # "0-30 days" etc.
    actions: list[MigrationAction] = field(default_factory=list)

    @property
    def action_count(self) -> int:
        return len(self.actions)

    @property
    def completed_count(self) -> int:
        return sum(1 for a in self.actions if a.status == "completed")

    @property
    def progress_pct(self) -> float:
        if not self.actions:
            return 0.0
        return round(self.completed_count / len(self.actions) * 100, 1)


@dataclass
class MigrationPlan:
    id: str
    host: str
    created_at: str
    scan_risk_level: str
    scan_pqc_status: str
    phases: list[MigrationPhase] = field(default_factory=list)
    config_analysis: Optional[dict] = None
    config_patch: Optional[dict] = None
    compatibility_issues: list[dict] = field(default_factory=list)
    notes: str = ""

    @property
    def total_actions(self) -> int:
        return sum(p.action_count for p in self.phases)

    @property
    def completed_actions(self) -> int:
        return sum(p.completed_count for p in self.phases)

    @property
    def overall_progress_pct(self) -> float:
        if not self.total_actions:
            return 0.0
        return round(self.completed_actions / self.total_actions * 100, 1)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "host": self.host,
            "created_at": self.created_at,
            "scan_risk_level": self.scan_risk_level,
            "scan_pqc_status": self.scan_pqc_status,
            "total_actions": self.total_actions,
            "completed_actions": self.completed_actions,
            "overall_progress_pct": self.overall_progress_pct,
            "config_analysis": self.config_analysis,
            "config_patch": self.config_patch,
            "compatibility_issues": self.compatibility_issues,
            "phases": [
                {
                    "number": p.number,
                    "name": p.name,
                    "description": p.description,
                    "timeline": p.timeline,
                    "action_count": p.action_count,
                    "completed_count": p.completed_count,
                    "progress_pct": p.progress_pct,
                    "actions": [
                        {
                            "id": a.id,
                            "phase": a.phase,
                            "action_type": a.action_type,
                            "title": a.title,
                            "description": a.description,
                            "host": a.host,
                            "priority": a.priority,
                            "estimated_minutes": a.estimated_minutes,
                            "automated": a.automated,
                            "requires_downtime": a.requires_downtime,
                            "commands": a.commands,
                            "rollback_commands": a.rollback_commands,
                            "params": a.params,
                            "status": a.status,
                            "completed_at": a.completed_at,
                            "notes": a.notes,
                        }
                        for a in p.actions
                    ],
                }
                for p in self.phases
            ],
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Plan builder
# ---------------------------------------------------------------------------

def build_migration_plan(
    scan_result: dict,
    target_algorithms: Optional[dict] = None,
    conservative: bool = True,
) -> MigrationPlan:
    """
    Build a full migration plan for a scanned SSH host.

    Args:
        scan_result       : Dict from /ssh/scan endpoint
        target_algorithms : Override algorithm choices. Dict with optional keys:
                              host_key, kex, ciphers, macs (each a list of algo IDs)
        conservative      : Keep existing safe algorithms (don't rip and replace)

    Returns:
        MigrationPlan with all phases and actions populated.
    """
    host = scan_result.get("host", "unknown")
    ssh_version = scan_result.get("ssh_version", "")
    risk_level = scan_result.get("risk_level", "unknown")
    pqc_status = scan_result.get("pqc_status", "unknown")
    host_key_algo = scan_result.get("host_key_algorithm", "")
    host_key_size = scan_result.get("host_key_size")

    plan = MigrationPlan(
        id=str(uuid.uuid4()),
        host=host,
        created_at=datetime.now(timezone.utc).isoformat(),
        scan_risk_level=risk_level,
        scan_pqc_status=pqc_status,
    )

    # Config analysis
    analysis = analyse_from_scan(scan_result)
    plan.config_analysis = analysis_summary(analysis)

    # Compatibility check
    chosen_algos = []
    if target_algorithms:
        for v in target_algorithms.values():
            chosen_algos.extend(v if isinstance(v, list) else [v])
    plan.compatibility_issues = check_compatibility(chosen_algos, ssh_version or "")

    # Config patch
    ta = target_algorithms or {}
    patch = generate_patch(
        analysis,
        target_kex=ta.get("kex"),
        target_ciphers=ta.get("ciphers"),
        target_macs=ta.get("macs"),
        add_host_key_types=ta.get("host_key"),
        conservative=conservative,
    )
    plan.config_patch = patch_summary(patch)

    # ── Phase 1: Immediate (0–30 days) ──────────────────────────────────────
    phase1 = MigrationPhase(
        number=1,
        name="Immediate hardening",
        description="Remove critically weak algorithms and enable hybrid PQC KEX. No key generation required. Low disruption.",
        timeline="0–30 days",
    )

    # Action: harden sshd_config
    if analysis.issue_count > 0:
        cmds = patch.apply_commands
        phase1.actions.append(MigrationAction(
            id=str(uuid.uuid4()),
            phase=1,
            action_type="harden_config",
            title="Harden sshd_config",
            description=(
                f"Remove {len(analysis.weak_kex)} weak KEX, "
                f"{len(analysis.weak_ciphers)} weak ciphers, "
                f"{len(analysis.weak_macs)} weak MACs. "
                f"Enable hybrid PQC KEX (sntrup761x25519 / mlkem768x25519)."
            ),
            host=host,
            priority="critical" if analysis.critical_count > 0 else "high",
            estimated_minutes=15,
            automated=True,
            requires_downtime=False,  # reload, not restart
            commands=cmds,
            rollback_commands=patch.rollback_commands,
            params={
                "weak_kex_removed": analysis.weak_kex,
                "weak_ciphers_removed": analysis.weak_ciphers,
                "weak_macs_removed": analysis.weak_macs,
                "target_kex": patch.changes[0]["after"].split(",") if patch.changes else [],
            },
        ))

    # Action: validate config
    phase1.actions.append(MigrationAction(
        id=str(uuid.uuid4()),
        phase=1,
        action_type="validate",
        title="Validate hardened config",
        description="Run sshd -t and verify the daemon reloads cleanly. Test a new SSH connection before closing the existing one.",
        host=host,
        priority="high",
        estimated_minutes=5,
        automated=True,
        requires_downtime=False,
        commands=patch.validate_commands,
        rollback_commands=patch.rollback_commands,
    ))

    plan.phases.append(phase1)

    # ── Phase 2: Host key migration (30–90 days) ─────────────────────────────
    phase2 = MigrationPhase(
        number=2,
        name="Host key migration",
        description="Generate Ed25519 host keys (if missing) and prepare for PQC host keys once OpenSSH support ships.",
        timeline="30–90 days",
    )

    # Generate Ed25519 host key if the server only has RSA/ECDSA
    has_ed25519 = any(
        "ed25519" in (hk.get("algorithm", "") if isinstance(hk, dict) else str(hk)).lower()
        for hk in scan_result.get("host_keys", [])
    )
    if not has_ed25519:
        phase2.actions.append(MigrationAction(
            id=str(uuid.uuid4()),
            phase=2,
            action_type="generate_host_key",
            title="Generate Ed25519 host key",
            description="Generate a new Ed25519 host key. Ed25519 is faster and more compact than RSA, and is a required stepping stone before PQC host keys.",
            host=host,
            priority="high",
            estimated_minutes=10,
            automated=True,
            requires_downtime=True,  # sshd restart needed for new host key type
            commands=[
                "# Generate Ed25519 host key",
                "sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N '' -C 'cryptiq-migration'",
                "# Add to sshd_config",
                "echo 'HostKey /etc/ssh/ssh_host_ed25519_key' | sudo tee -a /etc/ssh/sshd_config.d/00-cryptiq-hardening.conf",
                "sudo systemctl restart sshd",
                "# Verify",
                "sudo ssh-keygen -l -f /etc/ssh/ssh_host_ed25519_key.pub",
            ],
            rollback_commands=[
                "sudo rm -f /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key.pub",
                "sudo systemctl restart sshd",
            ],
            params={"algorithm": "ssh-ed25519"},
        ))

    # Keep RSA for now (compatibility), but upgrade size if small
    if host_key_algo and "rsa" in host_key_algo.lower():
        if host_key_size and host_key_size < 3072:
            phase2.actions.append(MigrationAction(
                id=str(uuid.uuid4()),
                phase=2,
                action_type="generate_host_key",
                title=f"Upgrade RSA host key to 3072-bit",
                description=f"Current RSA key is {host_key_size}-bit. Upgrade to 3072-bit as a minimum. This is a transitional measure — RSA will be removed in Phase 3.",
                host=host,
                priority="high",
                estimated_minutes=10,
                automated=True,
                requires_downtime=True,
                commands=[
                    "# Backup old key",
                    "sudo cp /etc/ssh/ssh_host_rsa_key /etc/ssh/ssh_host_rsa_key.old",
                    "sudo cp /etc/ssh/ssh_host_rsa_key.pub /etc/ssh/ssh_host_rsa_key.pub.old",
                    "# Generate new 3072-bit RSA key",
                    "sudo ssh-keygen -t rsa -b 3072 -f /etc/ssh/ssh_host_rsa_key -N '' -C 'cryptiq-migration'",
                    "sudo systemctl restart sshd",
                    "# Clients will see a new fingerprint — update known_hosts",
                    "ssh-keyscan -H <hostname> >> ~/.ssh/known_hosts",
                ],
                rollback_commands=[
                    "sudo cp /etc/ssh/ssh_host_rsa_key.old /etc/ssh/ssh_host_rsa_key",
                    "sudo cp /etc/ssh/ssh_host_rsa_key.pub.old /etc/ssh/ssh_host_rsa_key.pub",
                    "sudo systemctl restart sshd",
                ],
                params={"algorithm": "ssh-rsa", "key_size": 3072},
            ))

    # Update known_hosts on connecting clients
    phase2.actions.append(MigrationAction(
        id=str(uuid.uuid4()),
        phase=2,
        action_type="update_known_hosts",
        title="Update known_hosts on connecting clients",
        description="After changing host keys, connecting clients will see a fingerprint mismatch. Distribute the new fingerprint or run ssh-keyscan to update known_hosts.",
        host=host,
        priority="normal",
        estimated_minutes=20,
        automated=False,
        requires_downtime=False,
        commands=[
            f"# Run this on each connecting client machine",
            f"ssh-keygen -R {host}",
            f"ssh-keyscan -H {host} >> ~/.ssh/known_hosts",
            f"# Or verify the new fingerprint matches:",
            f"ssh-keygen -l -f <(ssh-keyscan {host} 2>/dev/null)",
        ],
        rollback_commands=[],
        notes="Must be done on every machine that connects to this host.",
    ))

    plan.phases.append(phase2)

    # ── Phase 3: Full PQC migration (90+ days) ──────────────────────────────
    phase3 = MigrationPhase(
        number=3,
        name="Full PQC migration",
        description="Deploy PQC host keys and pure PQC KEX once OpenSSH 10.x ships ML-DSA support. Remove all classical-only host keys.",
        timeline="90+ days (pending OpenSSH 10.x)",
    )

    phase3.actions.append(MigrationAction(
        id=str(uuid.uuid4()),
        phase=3,
        action_type="generate_host_key",
        title="Generate ML-DSA-65 host key (FIPS 204)",
        description="Generate a post-quantum ML-DSA-65 host key. Requires OpenSSH 10.0+ with ML-DSA support. This replaces RSA/ECDSA host keys entirely.",
        host=host,
        priority="normal",
        estimated_minutes=15,
        automated=True,
        requires_downtime=True,
        commands=[
            "# Requires OpenSSH 10.0+ with ML-DSA support",
            "sudo ssh-keygen -t ml-dsa-65 -f /etc/ssh/ssh_host_ml_dsa_65_key -N '' -C 'cryptiq-pqc'",
            "echo 'HostKey /etc/ssh/ssh_host_ml_dsa_65_key' | sudo tee -a /etc/ssh/sshd_config.d/00-cryptiq-hardening.conf",
            "sudo systemctl restart sshd",
        ],
        rollback_commands=[
            "sudo rm -f /etc/ssh/ssh_host_ml_dsa_65_key*",
            "sudo systemctl restart sshd",
        ],
        params={"algorithm": "ml-dsa-65", "nist_standard": "FIPS 204"},
        notes="Blocked pending OpenSSH ML-DSA support (tracked: https://bugzilla.mindrot.org/show_bug.cgi?id=3697)",
    ))

    phase3.actions.append(MigrationAction(
        id=str(uuid.uuid4()),
        phase=3,
        action_type="harden_config",
        title="Remove RSA/ECDSA host keys",
        description="Once all connecting clients support Ed25519 and ML-DSA, remove the RSA and ECDSA host keys from sshd_config.",
        host=host,
        priority="normal",
        estimated_minutes=10,
        automated=True,
        requires_downtime=True,
        commands=[
            "# Remove RSA and ECDSA host key directives",
            "sudo sed -i '/HostKey.*rsa/d' /etc/ssh/sshd_config.d/00-cryptiq-hardening.conf",
            "sudo sed -i '/HostKey.*ecdsa/d' /etc/ssh/sshd_config.d/00-cryptiq-hardening.conf",
            "sudo systemctl restart sshd",
        ],
        rollback_commands=[
            "# Restore host key directives from backup",
            "sudo cp /etc/ssh/sshd_config.bak.TIMESTAMP /etc/ssh/sshd_config",
            "sudo systemctl restart sshd",
        ],
        params={"removes": ["ssh-rsa", "ecdsa-sha2-nistp256"]},
    ))

    phase3.actions.append(MigrationAction(
        id=str(uuid.uuid4()),
        phase=3,
        action_type="generate_user_key",
        title="Migrate user auth keys to Ed25519 / ML-DSA",
        description="Generate new Ed25519 (or ML-DSA) user auth keys for all users connecting to this host. Revoke old RSA user keys from authorized_keys.",
        host=host,
        priority="normal",
        estimated_minutes=30,
        automated=False,
        requires_downtime=False,
        commands=[
            "# Generate new Ed25519 user key (run as the user)",
            "ssh-keygen -t ed25519 -C 'user@$(hostname)-pqc-migration' -f ~/.ssh/id_ed25519_pqc",
            "# Push to server",
            f"ssh-copy-id -i ~/.ssh/id_ed25519_pqc.pub user@{host}",
            "# After verifying login works, remove old RSA key from authorized_keys",
            f"ssh user@{host} 'sed -i \"/ssh-rsa/d\" ~/.ssh/authorized_keys'",
        ],
        rollback_commands=[
            f"# Re-add old RSA key to authorized_keys on {host}",
        ],
        notes="Coordinate with all users who SSH into this host.",
    ))

    plan.phases.append(phase3)

    return plan


# ---------------------------------------------------------------------------
# Fleet-level plan
# ---------------------------------------------------------------------------

def build_fleet_migration_plan(scan_results: list[dict]) -> dict:
    """
    Build migration plans for multiple hosts and produce a fleet summary.
    """
    plans = []
    for result in scan_results:
        plan = build_migration_plan(result)
        plans.append(plan.to_dict())

    total_actions = sum(p["total_actions"] for p in plans)
    critical = [p for p in plans if p["scan_risk_level"] == "critical"]
    high = [p for p in plans if p["scan_risk_level"] == "high"]

    return {
        "fleet_plan_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "hosts_planned": len(plans),
        "total_actions": total_actions,
        "critical_hosts": [p["host"] for p in critical],
        "high_priority_hosts": [p["host"] for p in high],
        "host_plans": plans,
        "recommended_order": (
            [p["host"] for p in critical]
            + [p["host"] for p in high]
            + [p["host"] for p in plans if p not in critical + high]
        ),
    }