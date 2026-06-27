"""
tls_migration/rollback.py
--------------------------
Generate and open a rollback PR that restores the original ssl_policy.

The original policy is read from the PR body (stored in a <!-- cryptiq-metadata -->
comment block at migration time) — never inferred or guessed.

All GitHub writes route through the chokepoint in github_pr.py.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from tls_migration import audit
from tls_migration.alb_plan import _SSL_POLICY_RE, MigrationDiff
from tls_migration.github_pr import open_migration_pr, PRResult
from tls_migration.types import TlsListenerAsset

_METADATA_RE = re.compile(
    r"<!--\s*cryptiq-metadata\s*(.*?)\s*-->",
    re.DOTALL,
)
_FIELD_RE = re.compile(r"^(\w+)=(.+)$", re.MULTILINE)

_ROLLBACK_BODY_TEMPLATE = """## Cryptiq PQC Rollback — ALB TLS Policy

**Listener:** `{listener_arn}`
**Load Balancer:** `{lb_name}`
**Reverting:** `{current_policy}` → `{original_policy}`

This pull request restores the TLS policy to its state before the Cryptiq migration.
The original policy value was captured at migration time from PR #{migration_pr_number}.

### Diff
```diff
{diff}
```

---

> **Review and merge to apply. Cryptiq will not merge this pull request.**

<!-- cryptiq-metadata
original_policy={original_policy}
listener_arn={listener_arn}
rollback=true
-->
"""


@dataclass
class RollbackResult:
    status: str              # "pr_opened" | "dry_run" | "error"
    listener_arn: str
    original_policy: Optional[str] = None
    current_policy: Optional[str] = None
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
            "original_policy": self.original_policy,
            "current_policy": self.current_policy,
            "diff": self.diff,
            "pr_url": self.pr_url,
            "pr_number": self.pr_number,
            "pr_branch": self.pr_branch,
            "pr_body_preview": self.pr_body_preview,
            "reason": self.reason,
        }


def extract_metadata_from_pr_body(pr_body: str) -> dict[str, str]:
    """Parse the <!-- cryptiq-metadata ... --> block from a PR body."""
    m = _METADATA_RE.search(pr_body)
    if not m:
        return {}
    fields = {}
    for field_m in _FIELD_RE.finditer(m.group(1)):
        fields[field_m.group(1).strip()] = field_m.group(2).strip()
    return fields


def compute_rollback_diff(tf_file: str, current_policy: str, original_policy: str) -> Optional[str]:
    """
    Produce a unified diff that changes ssl_policy from current back to original.
    Returns None if the ssl_policy line can't be found.
    """
    import difflib
    path = Path(tf_file)
    content = path.read_text(encoding="utf-8")

    if current_policy not in content:
        return None

    new_content = _SSL_POLICY_RE.sub(
        lambda m: m.group(1) + original_policy + m.group(2),
        content,
        count=1,
    )

    diff_lines = list(
        difflib.unified_diff(
            content.splitlines(keepends=True),
            new_content.splitlines(keepends=True),
            fromfile=str(path),
            tofile=str(path) + " (rollback)",
            n=3,
        )
    )
    return "".join(diff_lines)


def run_rollback(
    asset: TlsListenerAsset,
    migration_pr_body: str,
    migration_pr_number: int,
    tf_file: str,
    gh_repo: str,
    gh_base_branch: str = "main",
    dry_run: bool = True,
) -> RollbackResult:
    """
    Open a rollback PR that restores the ssl_policy to its pre-migration value.

    The original policy is sourced exclusively from the migration PR body —
    never inferred from the current state of the file.
    """
    listener_arn = asset.listener_arn

    # Extract original policy from PR metadata
    metadata = extract_metadata_from_pr_body(migration_pr_body)
    original_policy = metadata.get("original_policy")

    if not original_policy:
        audit.log(action="rollback", target=listener_arn, outcome="error:no_metadata")
        return RollbackResult(
            status="error",
            listener_arn=listener_arn,
            reason="Could not extract original_policy from migration PR body.",
        )

    current_policy = asset.ssl_policy_name

    diff = compute_rollback_diff(tf_file, current_policy, original_policy)
    if diff is None:
        audit.log(action="rollback", target=listener_arn, outcome="error:diff_failed")
        return RollbackResult(
            status="error",
            listener_arn=listener_arn,
            reason=f"Could not find current policy '{current_policy}' in {tf_file}.",
        )

    branch_name = (
        f"cryptiq/rollback-{asset.lb_name}-{asset.port}"
        .replace("_", "-")
        .lower()[:60]
    )

    pr_body = _ROLLBACK_BODY_TEMPLATE.format(
        listener_arn=listener_arn,
        lb_name=asset.lb_name,
        current_policy=current_policy,
        original_policy=original_policy,
        migration_pr_number=migration_pr_number,
        diff=diff,
    )

    if dry_run:
        audit.log(action="rollback", target=listener_arn, outcome="dry_run", branch=branch_name)
        return RollbackResult(
            status="dry_run",
            listener_arn=listener_arn,
            original_policy=original_policy,
            current_policy=current_policy,
            diff=diff,
            pr_branch=branch_name,
            pr_body_preview=pr_body,
        )

    # Read the new file content (rollback applied)
    path = Path(tf_file)
    content = path.read_text(encoding="utf-8")
    new_content = _SSL_POLICY_RE.sub(
        lambda m: m.group(1) + original_policy + m.group(2),
        content,
        count=1,
    )

    pr_result: PRResult = open_migration_pr(
        repo_full_name=gh_repo,
        base_branch=gh_base_branch,
        new_branch=branch_name,
        file_path=str(path.relative_to(path.anchor) if path.is_absolute() else path),
        new_file_content=new_content,
        pr_title=f"cryptiq: rollback {asset.lb_name}:{asset.port} TLS policy",
        pr_body=pr_body,
        label="cryptiq-rollback",
    )

    audit.log(
        action="rollback",
        target=listener_arn,
        outcome="success",
        pr_url=pr_result.pr_url,
        branch=branch_name,
    )

    return RollbackResult(
        status="pr_opened",
        listener_arn=listener_arn,
        original_policy=original_policy,
        current_policy=current_policy,
        diff=diff,
        pr_url=pr_result.pr_url,
        pr_number=pr_result.pr_number,
        pr_branch=branch_name,
    )
