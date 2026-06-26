"""
ssh_assets.py
-------------
Asset metadata and tagging layer.

Raw scan results say "192.168.1.42 has RSA-2048".
This module lets you attach business context:
  - "This is the Jenkins CI server"
  - "Owner: DevOps team"
  - "Environment: Production"
  - "Cannot be upgraded until Q3 2026"

That context is what makes a consulting report actionable.

Also tracks:
  - Remediation status per asset
  - Scan history trends (for weekly delta reports)
  - Export to structured formats for report generation
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass, field, asdict

from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Index
)
from sqlalchemy.orm import relationship, Session

from ssh_scanner.ssh_database import Base, SSHScanRecord


# ---------------------------------------------------------------------------
# ORM: Asset metadata table
# ---------------------------------------------------------------------------

class SSHAssetMetadata(Base):
    """
    Business context attached to an SSH host.
    One row per (host, port) — updated in place as context changes.
    """
    __tablename__ = "ssh_asset_metadata"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Identity
    host = Column(String(255), nullable=False)
    port = Column(Integer, nullable=False, default=22)

    # Business context
    asset_name = Column(String(255))          # "Jenkins CI", "Production DB-01"
    asset_owner = Column(String(255))         # "DevOps team", "john@company.com"
    environment = Column(String(64))          # "production", "staging", "dev", "dmz"
    business_unit = Column(String(255))       # "Engineering", "Finance"
    location = Column(String(255))            # "AWS us-east-1", "DC-Chicago-Rack-12"
    device_type = Column(String(64))          # from network discovery: "server","router",…
    os_hint = Column(String(128))             # "Ubuntu 22.04", "Cisco IOS 15.x"

    # Upgrade constraints
    can_upgrade = Column(Boolean, default=True)
    upgrade_blocker = Column(Text)            # "Vendor EOL — no PQC support until firmware 2.0"
    planned_upgrade_date = Column(String(64)) # "Q3 2026"

    # Remediation tracking
    remediation_status = Column(String(64), default="pending")
    # pending | in_progress | completed | blocked | waiver
    remediation_notes = Column(Text)
    last_remediation_check = Column(DateTime(timezone=True))

    # Tags (stored as JSON array: ["internet-facing","critical-infra"])
    tags_json = Column(Text, default="[]")

    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))

    notes = Column(Text)

    __table_args__ = (
        Index("ix_asset_host_port", "host", "port", unique=True),
        Index("ix_asset_env", "environment"),
        Index("ix_asset_remediation", "remediation_status"),
    )

    @property
    def tags(self) -> list[str]:
        return json.loads(self.tags_json or "[]")

    @tags.setter
    def tags(self, value: list[str]) -> None:
        self.tags_json = json.dumps(value)


# ---------------------------------------------------------------------------
# ORM: Scan trend snapshots
# ---------------------------------------------------------------------------

class SSHFleetSnapshot(Base):
    """
    Weekly/daily snapshot of the fleet's crypto posture.
    Enables "you reduced RSA hosts from 47 to 31 this month" reporting.
    """
    __tablename__ = "ssh_fleet_snapshots"

    id = Column(Integer, primary_key=True, autoincrement=True)
    snapshot_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    label = Column(String(128))  # "2026-W25", "baseline", "post-remediation"

    total_hosts = Column(Integer, default=0)
    quantum_vulnerable = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    pqc_ready_count = Column(Integer, default=0)
    hybrid_count = Column(Integer, default=0)
    pqc_readiness_percent = Column(Integer, default=0)

    # JSON blobs for detail
    by_host_key_algo_json = Column(Text, default="{}")
    by_kex_json = Column(Text, default="{}")
    critical_hosts_json = Column(Text, default="[]")

    @property
    def by_host_key_algo(self) -> dict:
        return json.loads(self.by_host_key_algo_json or "{}")

    @property
    def by_kex(self) -> dict:
        return json.loads(self.by_kex_json or "{}")

    @property
    def critical_hosts(self) -> list[str]:
        return json.loads(self.critical_hosts_json or "[]")


# ---------------------------------------------------------------------------
# Asset metadata helpers
# ---------------------------------------------------------------------------

def upsert_asset_metadata(
    db: Session,
    host: str,
    port: int = 22,
    **kwargs,
) -> SSHAssetMetadata:
    """
    Create or update asset metadata for a host.
    kwargs can include any column on SSHAssetMetadata.
    """
    record = (
        db.query(SSHAssetMetadata)
        .filter(SSHAssetMetadata.host == host, SSHAssetMetadata.port == port)
        .first()
    )
    if record is None:
        record = SSHAssetMetadata(host=host, port=port)
        db.add(record)

    for k, v in kwargs.items():
        if k == "tags":
            record.tags = v
        elif hasattr(record, k):
            setattr(record, k, v)

    record.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(record)
    return record


def get_asset_metadata(db: Session, host: str, port: int = 22) -> Optional[SSHAssetMetadata]:
    return (
        db.query(SSHAssetMetadata)
        .filter(SSHAssetMetadata.host == host, SSHAssetMetadata.port == port)
        .first()
    )


def list_asset_metadata(
    db: Session,
    environment: Optional[str] = None,
    remediation_status: Optional[str] = None,
    tag: Optional[str] = None,
) -> list[SSHAssetMetadata]:
    q = db.query(SSHAssetMetadata)
    if environment:
        q = q.filter(SSHAssetMetadata.environment == environment)
    if remediation_status:
        q = q.filter(SSHAssetMetadata.remediation_status == remediation_status)
    if tag:
        # Simple JSON search — works on SQLite; use JSONB ops on Postgres
        q = q.filter(SSHAssetMetadata.tags_json.like(f'%"{tag}"%'))
    return q.all()


# ---------------------------------------------------------------------------
# Fleet snapshot helpers
# ---------------------------------------------------------------------------

def take_fleet_snapshot(db: Session, label: Optional[str] = None) -> SSHFleetSnapshot:
    """
    Capture current inventory state as a snapshot.
    Call this weekly via a cron job to build trend data.
    """
    from ssh_scanner.ssh_database import get_inventory_summary
    summary = get_inventory_summary(db)

    snap = SSHFleetSnapshot(
        label=label or datetime.now(timezone.utc).strftime("%Y-W%W"),
        total_hosts=summary["total_hosts"],
        quantum_vulnerable=summary["quantum_vulnerable"],
        critical_count=summary["by_risk_level"].get("critical", 0),
        high_count=summary["by_risk_level"].get("high", 0),
        medium_count=summary["by_risk_level"].get("medium", 0),
        low_count=summary["by_risk_level"].get("low", 0),
        pqc_ready_count=summary["by_pqc_status"].get("pqc_ready", 0),
        hybrid_count=summary["by_pqc_status"].get("hybrid", 0),
        pqc_readiness_percent=int(summary["pqc_readiness_percent"]),
        by_host_key_algo_json=json.dumps(summary.get("all_host_key_algorithms", {})),
        by_kex_json=json.dumps(summary.get("by_negotiated_kex", {})),
        critical_hosts_json=json.dumps(summary.get("critical_migration_targets", [])),
    )
    db.add(snap)
    db.commit()
    db.refresh(snap)
    return snap


def get_fleet_trend(db: Session, limit: int = 12) -> list[SSHFleetSnapshot]:
    """Return recent snapshots for trend charting."""
    return (
        db.query(SSHFleetSnapshot)
        .order_by(SSHFleetSnapshot.snapshot_at.desc())
        .limit(limit)
        .all()
    )


# ---------------------------------------------------------------------------
# Enriched asset view (scan + metadata joined)
# ---------------------------------------------------------------------------

@dataclass
class EnrichedAsset:
    """Scan result + business context combined for reporting."""
    host: str
    port: int

    # From scan
    ssh_version: Optional[str]
    host_key_algorithm: Optional[str]
    host_key_size: Optional[int]
    key_exchange: Optional[str]
    cipher: Optional[str]
    mac: Optional[str]
    quantum_vulnerable: bool
    risk_level: str
    pqc_status: str
    migration_priority: str
    findings: list[str]
    scanned_at: Optional[datetime]
    all_host_keys: list[dict] = field(default_factory=list)

    # From metadata (may be None if not tagged)
    asset_name: Optional[str] = None
    asset_owner: Optional[str] = None
    environment: Optional[str] = None
    business_unit: Optional[str] = None
    location: Optional[str] = None
    device_type: Optional[str] = None
    os_hint: Optional[str] = None
    can_upgrade: bool = True
    upgrade_blocker: Optional[str] = None
    planned_upgrade_date: Optional[str] = None
    remediation_status: str = "pending"
    tags: list[str] = field(default_factory=list)
    notes: Optional[str] = None


def get_enriched_assets(db: Session, limit: int = 1000) -> list[EnrichedAsset]:
    """
    Join latest scan per host with asset metadata.
    This is the data source for report generation.
    """
    from sqlalchemy import func
    from ssh_scanner.ssh_database import SSHScanRecord, SSHHostKeyRecord

    # Latest scan per host+port
    latest_sub = (
        db.query(
            SSHScanRecord.host,
            SSHScanRecord.port,
            func.max(SSHScanRecord.scanned_at).label("max_ts"),
        )
        .group_by(SSHScanRecord.host, SSHScanRecord.port)
        .subquery()
    )

    scans = (
        db.query(SSHScanRecord)
        .join(
            latest_sub,
            (SSHScanRecord.host == latest_sub.c.host)
            & (SSHScanRecord.port == latest_sub.c.port)
            & (SSHScanRecord.scanned_at == latest_sub.c.max_ts),
        )
        .filter(SSHScanRecord.scan_success == True)
        .limit(limit)
        .all()
    )

    # Build metadata lookup
    meta_lookup: dict[tuple, SSHAssetMetadata] = {}
    for m in db.query(SSHAssetMetadata).all():
        meta_lookup[(m.host, m.port)] = m

    assets = []
    for scan in scans:
        meta = meta_lookup.get((scan.host, scan.port))
        assets.append(EnrichedAsset(
            host=scan.host,
            port=scan.port,
            ssh_version=scan.ssh_version,
            host_key_algorithm=scan.host_key_algorithm,
            host_key_size=scan.host_key_size,
            key_exchange=scan.key_exchange,
            cipher=scan.cipher,
            mac=scan.mac,
            quantum_vulnerable=scan.quantum_vulnerable,
            risk_level=scan.risk_level,
            pqc_status=scan.pqc_status,
            migration_priority=scan.migration_priority,
            findings=scan.findings,
            scanned_at=scan.scanned_at,
            all_host_keys=[
                {"algorithm": hk.algorithm, "key_size": hk.key_size, "fingerprint": hk.fingerprint}
                for hk in scan.host_keys
            ],
            asset_name=meta.asset_name if meta else None,
            asset_owner=meta.asset_owner if meta else None,
            environment=meta.environment if meta else None,
            business_unit=meta.business_unit if meta else None,
            location=meta.location if meta else None,
            device_type=meta.device_type if meta else None,
            os_hint=meta.os_hint if meta else None,
            can_upgrade=meta.can_upgrade if meta else True,
            upgrade_blocker=meta.upgrade_blocker if meta else None,
            planned_upgrade_date=meta.planned_upgrade_date if meta else None,
            remediation_status=meta.remediation_status if meta else "pending",
            tags=meta.tags if meta else [],
            notes=meta.notes if meta else None,
        ))

    return sorted(assets, key=lambda a: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}.get(a.risk_level, 5)
    ))