"""
tls_migration/audit.py
-----------------------
Append-only JSONL audit log for every Cryptiq action.

Every line is a JSON object with: timestamp, action, target, actor, outcome.
The file is append-only — lines are never deleted or modified.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

_DEFAULT_LOG_PATH = Path("out") / "audit.log"


def _log_path() -> Path:
    p = Path(os.environ.get("CRYPTIQ_AUDIT_LOG", str(_DEFAULT_LOG_PATH)))
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _actor() -> str:
    return os.environ.get("CRYPTIQ_ACTOR", "unknown")


def log(action: str, target: str, outcome: str, **extra) -> dict:
    """
    Append one record to the audit log. Returns the record dict.

    Args:
        action  : "discovery" | "plan" | "open_pr" | "rollback" | etc.
        target  : ARN, hostname, or other identifier of the affected resource.
        outcome : "success" | "dry_run" | "manual_review_required" | "error:<msg>"
        **extra : Any additional fields to include in the record.
    """
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "target": target,
        "actor": _actor(),
        "outcome": outcome,
        **extra,
    }
    with open(_log_path(), "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
    return record


def read_log(limit: int = 100) -> list[dict]:
    """Return the last `limit` entries from the audit log (newest last)."""
    p = _log_path()
    if not p.exists():
        return []
    lines = p.read_text(encoding="utf-8").strip().splitlines()
    records = []
    for line in lines:
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return records[-limit:]
