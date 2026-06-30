"""
tls_migration/alb_plan.py
--------------------------
Generate a Terraform diff that migrates one ALB listener from a classical
TLS policy to the post-quantum hybrid policy.

Constraints:
  - ONLY changes ssl_policy. No other field is touched.
  - If the listener resource cannot be located confidently, returns a
    manual_review_required result instead of guessing.
  - No AWS calls, no file writes, no terraform execution.
"""

from __future__ import annotations

import difflib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from tls_migration.types import TlsListenerAsset

# VERIFY: Confirm this policy name against live AWS docs before each release.
# https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html
TARGET_PQ_POLICY = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"

_SSL_POLICY_RE = re.compile(
    r'(\bssl_policy\s*=\s*")[^"]*(")',
    re.MULTILINE,
)

_LISTENER_RESOURCE_RE = re.compile(
    r'resource\s+"aws_lb_listener"\s+"[^"]+"\s*\{',
    re.MULTILINE,
)


@dataclass
class MigrationDiff:
    status: str                      # "ok" | "manual_review_required" | "already_pq"
    diff: Optional[str] = None
    current_policy: Optional[str] = None
    target_policy: Optional[str] = None
    resource_address: Optional[str] = None
    tf_file: Optional[str] = None
    reason: Optional[str] = None     # populated when status != "ok"

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "diff": self.diff,
            "current_policy": self.current_policy,
            "target_policy": self.target_policy,
            "resource_address": self.resource_address,
            "tf_file": self.tf_file,
            "reason": self.reason,
        }


def _find_tf_files(tf_repo: str) -> list[Path]:
    root = Path(tf_repo)
    return sorted(root.rglob("*.tf"))


def _extract_listener_blocks(content: str) -> list[tuple[str, int, int]]:
    """
    Return (resource_address, start_char, end_char) for each aws_lb_listener block.
    Uses brace counting to find the block boundary.
    """
    blocks = []
    for m in _LISTENER_RESOURCE_RE.finditer(content):
        # Parse the resource address from the match
        header = m.group(0)
        name_match = re.search(r'"aws_lb_listener"\s+"([^"]+)"', header)
        resource_address = f"aws_lb_listener.{name_match.group(1)}" if name_match else "aws_lb_listener.unknown"

        start = m.start()
        depth = 0
        pos = m.start()
        while pos < len(content):
            if content[pos] == "{":
                depth += 1
            elif content[pos] == "}":
                depth -= 1
                if depth == 0:
                    blocks.append((resource_address, start, pos + 1))
                    break
            pos += 1
    return blocks


def compute_migration_diff(
    asset: TlsListenerAsset,
    tf_repo: str,
    target_policy: str = TARGET_PQ_POLICY,
) -> MigrationDiff:
    """
    Locate the aws_lb_listener resource for the given asset in a Terraform repo
    and produce a unified diff that changes ONLY ssl_policy.

    Returns MigrationDiff with status="ok" on success, "manual_review_required"
    if the listener can't be found confidently, or "already_pq" if it's already
    on the target policy.
    """
    if asset.is_post_quantum:
        return MigrationDiff(
            status="already_pq",
            current_policy=asset.ssl_policy_name,
            target_policy=target_policy,
            reason="Listener is already using a post-quantum policy.",
        )

    tf_files = _find_tf_files(tf_repo)
    if not tf_files:
        return MigrationDiff(
            status="manual_review_required",
            reason=f"No .tf files found in {tf_repo}",
        )

    candidates: list[tuple[Path, str, str]] = []  # (file, resource_address, block)

    for tf_file in tf_files:
        content = tf_file.read_text(encoding="utf-8")
        blocks = _extract_listener_blocks(content)
        for resource_address, start, end in blocks:
            block = content[start:end]
            # Match by lb_name in resource name, or accept if only one listener exists
            candidates.append((tf_file, resource_address, block))

    if not candidates:
        return MigrationDiff(
            status="manual_review_required",
            reason="No aws_lb_listener resources found in the Terraform repo.",
        )

    if len(candidates) > 1:
        # Try to narrow by matching lb_name in the resource label
        lb_name = asset.lb_name.replace("-", "_")
        narrowed = [c for c in candidates if lb_name in c[1] or lb_name in c[2]]
        if len(narrowed) == 1:
            candidates = narrowed
        else:
            return MigrationDiff(
                status="manual_review_required",
                reason=(
                    f"Found {len(candidates)} aws_lb_listener resources; "
                    f"cannot confidently identify which one manages listener "
                    f"{asset.listener_arn}. Manual review required."
                ),
            )

    tf_file, resource_address, block = candidates[0]

    # Find the ssl_policy line in the block
    policy_match = _SSL_POLICY_RE.search(block)
    if not policy_match:
        return MigrationDiff(
            status="manual_review_required",
            reason=f"No ssl_policy attribute found in {resource_address}.",
        )

    current_policy = block[policy_match.start(): policy_match.end()]
    current_policy_value = re.search(r'"([^"]+)"', current_policy.split("=")[1]).group(1)

    if current_policy_value == target_policy:
        return MigrationDiff(
            status="already_pq",
            current_policy=current_policy_value,
            target_policy=target_policy,
            resource_address=resource_address,
            tf_file=str(tf_file),
            reason="ssl_policy is already set to the target PQ policy.",
        )

    new_block = _SSL_POLICY_RE.sub(
        lambda m: m.group(1) + target_policy + m.group(2),
        block,
    )

    # Read the full file and produce a file-level unified diff
    full_content = tf_file.read_text(encoding="utf-8")
    new_content = full_content.replace(block, new_block, 1)

    diff_lines = list(
        difflib.unified_diff(
            full_content.splitlines(keepends=True),
            new_content.splitlines(keepends=True),
            fromfile=str(tf_file),
            tofile=str(tf_file) + " (migrated)",
            n=3,
        )
    )
    unified_diff = "".join(diff_lines)

    # Verify exactly one ssl_policy line changed
    changed = [l for l in diff_lines if l.startswith(("+", "-")) and "ssl_policy" in l and not l.startswith("---") and not l.startswith("+++")]
    if len(changed) != 2:  # one removal + one addition
        return MigrationDiff(
            status="manual_review_required",
            reason=(
                f"Diff produced {len(changed)} ssl_policy line changes (expected exactly 2). "
                "Manual review required."
            ),
        )

    return MigrationDiff(
        status="ok",
        diff=unified_diff,
        current_policy=current_policy_value,
        target_policy=target_policy,
        resource_address=resource_address,
        tf_file=str(tf_file),
    )
