"""
tls_migration/run.py
---------------------
Orchestrator for the ALB TLS → PQC migration flow.

Pipeline: discover listener → compute diff → open PR (or dry-run preview).

Environment scoping:
  - By default only non-prod targets are acted on.
  - Prod targets require allow_prod=True AND a typed confirmation token.
  - The prod confirmation token is: "I-UNDERSTAND-PROD" (case-sensitive).

All GitHub writes route through tls_migration/github_pr.py (the chokepoint).
Every action is recorded to the audit log.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from tls_migration import audit
from tls_migration.alb_plan import compute_migration_diff, TARGET_PQ_POLICY, MigrationDiff
from tls_migration.github_pr import open_migration_pr, PRResult
from tls_migration.types import TlsListenerAsset

PROD_CONFIRMATION_TOKEN = "I-UNDERSTAND-PROD"

_PR_BODY_TEMPLATE = """## Cryptiq PQC Migration — ALB TLS Policy

**Listener:** `{listener_arn}`
**Load Balancer:** `{lb_name}` (`{lb_arn}`)
**Environment:** `{environment}`
**Port:** {port} / {protocol}

### Current state
- Policy: `{current_policy}` — **classical TLS, not post-quantum safe**

### Proposed change
- Policy: `{target_policy}` — **hybrid post-quantum (ML-KEM + classical)**

### Why this matters (HNDL risk)
Harvest-Now-Decrypt-Later (HNDL) attacks allow adversaries to capture TLS traffic
today and decrypt it once a sufficiently powerful quantum computer is available.
Migrating to a hybrid PQ policy eliminates this exposure without breaking
compatibility with classical clients (hybrid = both algorithms negotiated).

### Diff
```diff
{diff}
```

---

> **Review and merge to apply. Cryptiq will not merge this pull request.**
> After merging, your CI/CD pipeline applies the change using your own credentials.
> To roll back: use the Cryptiq rollback endpoint — it will open a separate PR
> restoring the original policy.

<!-- cryptiq-metadata
original_policy={current_policy}
listener_arn={listener_arn}
-->
"""


@dataclass
class MigrationResult:
    status: str              # "dry_run" | "pr_opened" | "already_pq" | "manual_review" | "prod_blocked" | "error"
    listener_arn: str
    current_policy: Optional[str] = None
    target_policy: Optional[str] = None
    diff: Optional[str] = None
    pr_url: Optional[str] = None
    pr_number: Optional[int] = None
    pr_branch: Optional[str] = None
    pr_body_preview: Optional[str] = None
    reason: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "listener_arn": self.listener_arn,
            "current_policy": self.current_policy,
            "target_policy": self.target_policy,
            "diff": self.diff,
            "pr_url": self.pr_url,
            "pr_number": self.pr_number,
            "pr_branch": self.pr_branch,
            "pr_body_preview": self.pr_body_preview,
            "reason": self.reason,
        }


def run_migration(
    asset: TlsListenerAsset,
    tf_repo: str,
    gh_repo: str,
    gh_base_branch: str = "main",
    dry_run: bool = True,
    allow_prod: bool = False,
    prod_token: Optional[str] = None,
) -> MigrationResult:
    """
    Run the full migration pipeline for one ALB listener.

    Args:
        asset           : TlsListenerAsset from discover_alb_listeners()
        tf_repo         : Local path to the Terraform repo managing this listener
        gh_repo         : GitHub repo "owner/name" to open the PR against
        gh_base_branch  : Branch to base the PR on
        dry_run         : If True, compute diff/PR body but do NOT write to GitHub
        allow_prod      : Required to act on prod-tagged listeners
        prod_token      : Must equal PROD_CONFIRMATION_TOKEN when allow_prod=True

    Returns:
        MigrationResult
    """
    listener_arn = asset.listener_arn

    # ── Environment scoping ───────────────────────────────────────────────────
    if asset.environment and asset.environment.lower() == "prod":
        if not allow_prod:
            audit.log(
                action="migrate",
                target=listener_arn,
                outcome="prod_blocked",
                environment=asset.environment,
            )
            return MigrationResult(
                status="prod_blocked",
                listener_arn=listener_arn,
                reason=(
                    "Listener is tagged Environment=prod. "
                    "Pass allow_prod=true and the prod confirmation token to proceed."
                ),
            )
        if prod_token != PROD_CONFIRMATION_TOKEN:
            audit.log(
                action="migrate",
                target=listener_arn,
                outcome="prod_blocked",
                reason="invalid_prod_token",
            )
            return MigrationResult(
                status="prod_blocked",
                listener_arn=listener_arn,
                reason="Invalid prod confirmation token.",
            )

    # ── Already PQ? ───────────────────────────────────────────────────────────
    if asset.is_post_quantum:
        audit.log(
            action="migrate",
            target=listener_arn,
            outcome="already_pq",
            policy=asset.ssl_policy_name,
        )
        return MigrationResult(
            status="already_pq",
            listener_arn=listener_arn,
            current_policy=asset.ssl_policy_name,
            reason="Listener is already using a post-quantum policy. No action taken.",
        )

    # ── Compute diff ─────────────────────────────────────────────────────────
    migration: MigrationDiff = compute_migration_diff(asset, tf_repo)

    if migration.status == "manual_review_required":
        audit.log(
            action="plan",
            target=listener_arn,
            outcome="manual_review_required",
            reason=migration.reason,
        )
        return MigrationResult(
            status="manual_review",
            listener_arn=listener_arn,
            reason=migration.reason,
        )

    if migration.status == "already_pq":
        audit.log(action="plan", target=listener_arn, outcome="already_pq")
        return MigrationResult(
            status="already_pq",
            listener_arn=listener_arn,
            current_policy=migration.current_policy,
        )

    audit.log(
        action="plan",
        target=listener_arn,
        outcome="success",
        current_policy=migration.current_policy,
        target_policy=migration.target_policy,
    )

    # ── Build PR body ─────────────────────────────────────────────────────────
    pr_body = _PR_BODY_TEMPLATE.format(
        listener_arn=listener_arn,
        lb_name=asset.lb_name,
        lb_arn=asset.lb_arn,
        environment=asset.environment or "unknown",
        port=asset.port,
        protocol=asset.protocol,
        current_policy=migration.current_policy,
        target_policy=migration.target_policy,
        diff=migration.diff or "",
    )

    branch_name = (
        f"cryptiq/migrate-{asset.lb_name}-{asset.port}"
        .replace("_", "-")
        .lower()[:60]
    )
    pr_title = f"cryptiq: migrate {asset.lb_name}:{asset.port} to PQ TLS policy"

    if dry_run:
        audit.log(
            action="migrate",
            target=listener_arn,
            outcome="dry_run",
            branch=branch_name,
        )
        return MigrationResult(
            status="dry_run",
            listener_arn=listener_arn,
            current_policy=migration.current_policy,
            target_policy=migration.target_policy,
            diff=migration.diff,
            pr_branch=branch_name,
            pr_body_preview=pr_body,
        )

    # ── Open PR ───────────────────────────────────────────────────────────────
    pr_result: PRResult = open_migration_pr(
        repo_full_name=gh_repo,
        base_branch=gh_base_branch,
        new_branch=branch_name,
        file_path=migration.tf_file.split("/", 1)[-1] if migration.tf_file else "",
        new_file_content=_apply_diff_to_file(migration),
        pr_title=pr_title,
        pr_body=pr_body,
    )

    audit.log(
        action="open_pr",
        target=listener_arn,
        outcome="success",
        pr_url=pr_result.pr_url,
        branch=branch_name,
    )

    return MigrationResult(
        status="pr_opened",
        listener_arn=listener_arn,
        current_policy=migration.current_policy,
        target_policy=migration.target_policy,
        diff=migration.diff,
        pr_url=pr_result.pr_url,
        pr_number=pr_result.pr_number,
        pr_branch=branch_name,
    )


def _apply_diff_to_file(migration: MigrationDiff) -> str:
    """Return the full new file content after applying the ssl_policy change."""
    import re
    from tls_migration.alb_plan import _SSL_POLICY_RE, TARGET_PQ_POLICY

    if not migration.tf_file:
        return ""
    from pathlib import Path
    content = Path(migration.tf_file).read_text(encoding="utf-8")
    return _SSL_POLICY_RE.sub(
        lambda m: m.group(1) + TARGET_PQ_POLICY + m.group(2),
        content,
        count=1,
    )
