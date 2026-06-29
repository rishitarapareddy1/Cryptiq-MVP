"""
ssh_database.py
---------------
SQLAlchemy ORM models and persistence layer for SSH scan results.

Design decisions vs TLS scanner:
  - SSHScanRecord : one row per scan of a host (point-in-time snapshot)
  - SSHHostKeyRecord : separate table for host keys — a server can have
    multiple (RSA + Ed25519 + ECDSA all at once), so 1:N with the scan.
  - SSHAlgorithmAdvertisement : stores the full advertised algorithm lists
    for inventory / trend analysis.

This separation lets you answer:
  "How many servers still advertise RSA host keys, even if they also offer Ed25519?"
  "Which servers dropped group14-sha1 after we sent the remediation notice?"
"""

from __future__ import annotations

import os
import json
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Boolean,
    DateTime,
    Text,
    Float,
    ForeignKey,
    Index,
    text,
)
from sqlalchemy.orm import DeclarativeBase, relationship, Session, sessionmaker
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import JSON  # fallback for SQLite

from ssh_scanner.scan_ssh import SSHScanResult
from ssh_scanner.ssh_risk import SSHRiskAssessment


# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------

DATABASE_URL = os.environ.get(
    "SSH_SCANNER_DATABASE_URL",
    os.environ.get("DATABASE_URL", "sqlite:///./ssh_scanner.db")
)


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# ORM models
# ---------------------------------------------------------------------------

class SSHScanRecord(Base):
    """
    One row = one full scan of one SSH endpoint.
    Captures the primary (negotiated / first-advertised) crypto params
    plus risk scoring for fast querying.
    """
    __tablename__ = "ssh_scans"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Endpoint identity
    host = Column(String(255), nullable=False, index=True)
    port = Column(Integer, nullable=False, default=22)

    # Server identity
    ssh_version = Column(String(128))         # "OpenSSH_9.7p1 Ubuntu-3"
    ssh_protocol = Column(String(16))         # "2.0"
    raw_banner = Column(String(512))

    # Primary / negotiated crypto (denormalised for fast querying)
    host_key_algorithm = Column(String(128))  # e.g. "ssh-rsa"
    host_key_size = Column(Integer)           # bits; NULL for fixed-size
    key_exchange = Column(String(128))        # negotiated KEX
    cipher = Column(String(128))             # negotiated cipher
    mac = Column(String(128))               # negotiated MAC

    # Risk classification
    quantum_vulnerable = Column(Boolean, nullable=False, default=True)
    risk_level = Column(String(32), nullable=False, default="unknown")
    pqc_status = Column(String(32), nullable=False, default="unknown")
    migration_priority = Column(String(32), default="normal")
    host_key_quantum_vulnerable = Column(Boolean, default=True)
    kex_quantum_vulnerable = Column(Boolean, default=True)
    weak_cipher = Column(Boolean, default=False)
    weak_mac = Column(Boolean, default=False)

    # Full risk detail (findings list serialised as JSON)
    findings_json = Column(Text)

    # Scan metadata
    scan_success = Column(Boolean, nullable=False, default=False)
    scan_error = Column(String(512))
    scanned_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    # Relationships
    host_keys = relationship(
        "SSHHostKeyRecord",
        back_populates="scan",
        cascade="all, delete-orphan",
    )
    algorithm_advertisement = relationship(
        "SSHAlgorithmAdvertisement",
        back_populates="scan",
        uselist=False,
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_ssh_scans_host_port", "host", "port"),
        Index("ix_ssh_scans_risk_level", "risk_level"),
        Index("ix_ssh_scans_pqc_status", "pqc_status"),
    )

    @property
    def findings(self) -> list[str]:
        if self.findings_json:
            return json.loads(self.findings_json)
        return []


class SSHHostKeyRecord(Base):
    """
    One row per host key offered by the server.
    A single server commonly offers 3–4 host key types.
    """
    __tablename__ = "ssh_host_keys"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("ssh_scans.id", ondelete="CASCADE"), nullable=False, index=True)

    algorithm = Column(String(128), nullable=False)    # "ssh-rsa", "ssh-ed25519", …
    key_size = Column(Integer)                          # bits; NULL for Ed25519
    fingerprint = Column(String(128))                  # "SHA256:abc123…"

    # Redundant but useful for fast aggregations without joining
    quantum_vulnerable = Column(Boolean, default=True)
    risk_level = Column(String(32), default="unknown")

    scan = relationship("SSHScanRecord", back_populates="host_keys")

    __table_args__ = (
        Index("ix_ssh_host_keys_algo", "algorithm"),
    )


class SSHAlgorithmAdvertisement(Base):
    """
    Full algorithm lists advertised by the server during KEX_INIT.
    Stored as JSON arrays for post-hoc inventory analysis.

    Example use:
      "Find all servers that still advertise diffie-hellman-group14-sha1
       even if they don't use it as the negotiated KEX."
    """
    __tablename__ = "ssh_algorithm_advertisements"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("ssh_scans.id", ondelete="CASCADE"), nullable=False, unique=True)

    # Stored as JSON arrays; use JSONB on PostgreSQL for indexing
    kex_algorithms_json = Column(Text)
    host_key_algorithms_json = Column(Text)
    ciphers_json = Column(Text)
    macs_json = Column(Text)
    compression_json = Column(Text)

    scan = relationship("SSHScanRecord", back_populates="algorithm_advertisement")

    @property
    def kex_algorithms(self) -> list[str]:
        return json.loads(self.kex_algorithms_json or "[]")

    @property
    def host_key_algorithms(self) -> list[str]:
        return json.loads(self.host_key_algorithms_json or "[]")

    @property
    def ciphers(self) -> list[str]:
        return json.loads(self.ciphers_json or "[]")

    @property
    def macs(self) -> list[str]:
        return json.loads(self.macs_json or "[]")

    @property
    def compression(self) -> list[str]:
        return json.loads(self.compression_json or "[]")


# ---------------------------------------------------------------------------
# Engine / session factory
# ---------------------------------------------------------------------------

def get_engine(database_url: str = DATABASE_URL):
    kwargs = {}
    if database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    return create_engine(database_url, **kwargs)


def create_tables(engine=None) -> None:
    if engine is None:
        engine = get_engine()
    Base.metadata.create_all(bind=engine)


_engine = None
_SessionLocal = None


def _get_session_factory():
    global _engine, _SessionLocal
    if _SessionLocal is None:
        _engine = get_engine()
        create_tables(_engine)
        _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)
    return _SessionLocal


def get_db() -> Session:
    """FastAPI dependency — yields a session and closes it afterwards."""
    factory = _get_session_factory()
    db = factory()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------

def save_scan(
    db: Session,
    scan_result: SSHScanResult,
    risk: SSHRiskAssessment,
) -> SSHScanRecord:
    """
    Persist a scan result + risk assessment to the database.
    Returns the newly created SSHScanRecord.
    """
    # Determine primary host key (first in the list; typically what the server
    # negotiated or the most preferred type it advertises)
    primary_key = scan_result.host_keys[0] if scan_result.host_keys else None

    record = SSHScanRecord(
        host=scan_result.host,
        port=scan_result.port,
        ssh_version=scan_result.ssh_version,
        ssh_protocol=scan_result.ssh_protocol,
        raw_banner=scan_result.raw_banner,
        host_key_algorithm=primary_key.algorithm if primary_key else None,
        host_key_size=primary_key.key_size if primary_key else None,
        key_exchange=scan_result.negotiated_kex or (
            scan_result.server_kex_algorithms[0] if scan_result.server_kex_algorithms else None
        ),
        cipher=scan_result.negotiated_cipher or (
            scan_result.server_ciphers[0] if scan_result.server_ciphers else None
        ),
        mac=scan_result.negotiated_mac or (
            scan_result.server_macs[0] if scan_result.server_macs else None
        ),
        quantum_vulnerable=risk.quantum_vulnerable,
        risk_level=risk.risk_level,
        pqc_status=risk.pqc_status,
        migration_priority=risk.migration_priority,
        host_key_quantum_vulnerable=risk.host_key_quantum_vulnerable,
        kex_quantum_vulnerable=risk.kex_quantum_vulnerable,
        weak_cipher=risk.weak_cipher,
        weak_mac=risk.weak_mac,
        findings_json=json.dumps(risk.findings),
        scan_success=scan_result.scan_success,
        scan_error=scan_result.scan_error,
        scanned_at=datetime.now(timezone.utc),
    )

    db.add(record)
    db.flush()  # get record.id before adding children

    # Host key records (all advertised keys)
    for hk in scan_result.host_keys:
        from ssh_scanner.ssh_risk import classify_host_key
        hk_risk = classify_host_key(hk.algorithm, hk.key_size)
        db.add(SSHHostKeyRecord(
            scan_id=record.id,
            algorithm=hk.algorithm,
            key_size=hk.key_size,
            fingerprint=hk.fingerprint,
            quantum_vulnerable=hk_risk["quantum_vulnerable"],
            risk_level=hk_risk["risk_contribution"],
        ))

    # Algorithm advertisement
    if any([
        scan_result.server_kex_algorithms,
        scan_result.server_host_key_algorithms,
        scan_result.server_ciphers,
        scan_result.server_macs,
    ]):
        db.add(SSHAlgorithmAdvertisement(
            scan_id=record.id,
            kex_algorithms_json=json.dumps(scan_result.server_kex_algorithms),
            host_key_algorithms_json=json.dumps(scan_result.server_host_key_algorithms),
            ciphers_json=json.dumps(scan_result.server_ciphers),
            macs_json=json.dumps(scan_result.server_macs),
            compression_json=json.dumps(scan_result.server_compression),
        ))

    db.commit()
    db.refresh(record)
    return record


def get_scan_history(
    db: Session,
    host: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    risk_level: Optional[str] = None,
    pqc_status: Optional[str] = None,
) -> list[SSHScanRecord]:
    """
    Query scan history with optional filters.
    """
    q = db.query(SSHScanRecord)
    if host:
        q = q.filter(SSHScanRecord.host == host)
    if risk_level:
        q = q.filter(SSHScanRecord.risk_level == risk_level)
    if pqc_status:
        q = q.filter(SSHScanRecord.pqc_status == pqc_status)
    return (
        q.order_by(SSHScanRecord.scanned_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


def get_latest_scan(db: Session, host: str, port: int = 22) -> Optional[SSHScanRecord]:
    return (
        db.query(SSHScanRecord)
        .filter(SSHScanRecord.host == host, SSHScanRecord.port == port)
        .order_by(SSHScanRecord.scanned_at.desc())
        .first()
    )


def get_inventory_summary(db: Session) -> dict:
    """
    Aggregate stats across all scans — the inventory view.
    Computes from the latest scan per host to avoid double-counting.
    """
    from sqlalchemy import func

    # Subquery: latest scan id per host+port
    latest_sub = (
        db.query(
            SSHScanRecord.host,
            SSHScanRecord.port,
            func.max(SSHScanRecord.scanned_at).label("max_ts"),
        )
        .group_by(SSHScanRecord.host, SSHScanRecord.port)
        .subquery()
    )

    latest_records = (
        db.query(SSHScanRecord)
        .join(
            latest_sub,
            (SSHScanRecord.host == latest_sub.c.host)
            & (SSHScanRecord.port == latest_sub.c.port)
            & (SSHScanRecord.scanned_at == latest_sub.c.max_ts),
        )
        .all()
    )

    total = len(latest_records)
    by_risk: dict[str, int] = {}
    by_pqc: dict[str, int] = {}
    by_host_key_algo: dict[str, int] = {}
    by_kex: dict[str, int] = {}
    quantum_vulnerable = 0

    for r in latest_records:
        by_risk[r.risk_level] = by_risk.get(r.risk_level, 0) + 1
        by_pqc[r.pqc_status] = by_pqc.get(r.pqc_status, 0) + 1
        if r.quantum_vulnerable:
            quantum_vulnerable += 1
        if r.host_key_algorithm:
            by_host_key_algo[r.host_key_algorithm] = by_host_key_algo.get(r.host_key_algorithm, 0) + 1
        if r.key_exchange:
            by_kex[r.key_exchange] = by_kex.get(r.key_exchange, 0) + 1

    # Host key inventory from the dedicated table (all keys, not just primary)
    all_host_keys: dict[str, int] = {}
    for hkr in db.query(SSHHostKeyRecord).all():
        all_host_keys[hkr.algorithm] = all_host_keys.get(hkr.algorithm, 0) + 1

    return {
        "total_hosts": total,
        "quantum_vulnerable": quantum_vulnerable,
        "by_risk_level": by_risk,
        "by_pqc_status": by_pqc,
        "by_primary_host_key_algorithm": dict(
            sorted(by_host_key_algo.items(), key=lambda x: -x[1])
        ),
        "by_negotiated_kex": dict(
            sorted(by_kex.items(), key=lambda x: -x[1])
        ),
        "all_host_key_algorithms": dict(
            sorted(all_host_keys.items(), key=lambda x: -x[1])
        ),
        "pqc_readiness_percent": round(
            by_pqc.get("pqc_ready", 0) / total * 100, 1
        ) if total > 0 else 0.0,
        "critical_migration_targets": [
            r.host for r in latest_records if r.migration_priority == "critical"
        ],
        "high_priority_targets": [
            r.host for r in latest_records if r.migration_priority == "high"
        ],
    }