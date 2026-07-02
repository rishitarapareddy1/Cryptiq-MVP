"""
password_hashing/database.py
-------------------------------
Persistence for password-hash scan history. Same module-local engine
pattern as ssh_database.py / code_signing/database.py.

Note: only classification metadata is stored — never the hash value
itself and never the raw shadow/dump text. raw_prefix on a finding is
at most a short format marker like "$6$", not the secret material.
"""

from __future__ import annotations

import json
import os
from datetime import datetime

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.environ.get(
    "PWHASH_DATABASE_URL", os.environ.get("DATABASE_URL", "sqlite:///./password_hashing.db")
)

Base = declarative_base()


class PasswordHashScanRecord(Base):
    __tablename__ = "pwhash_scans"

    id = Column(Integer, primary_key=True)
    platform = Column(String)
    source = Column(String)
    total_findings = Column(Integer, default=0)
    by_risk_json = Column(Text)       # {"critical": 2, "high": 5, ...}
    findings_json = Column(Text)      # list of finding dicts (no raw hash material)
    scanned_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "platform": self.platform, "source": self.source,
            "total_findings": self.total_findings,
            "by_risk": json.loads(self.by_risk_json) if self.by_risk_json else {},
            "scanned_at": self.scanned_at.isoformat() if self.scanned_at else None,
        }

    def to_full_dict(self) -> dict:
        d = self.to_dict()
        d["findings"] = json.loads(self.findings_json) if self.findings_json else []
        return d


def get_engine():
    connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
    return create_engine(DATABASE_URL, connect_args=connect_args)


_engine = get_engine()
SessionLocal = sessionmaker(bind=_engine)


def create_tables(engine=None):
    Base.metadata.create_all(engine or _engine)


def save_scan(summary_dict: dict) -> PasswordHashScanRecord:
    session = SessionLocal()
    try:
        rec = PasswordHashScanRecord(
            platform=summary_dict["platform"], source=summary_dict["source"],
            total_findings=summary_dict["total_findings"],
            by_risk_json=json.dumps(summary_dict["by_risk"]),
            findings_json=json.dumps(summary_dict["findings"]),
        )
        session.add(rec)
        session.commit()
        session.refresh(rec)
        return rec
    finally:
        session.close()


def list_scans(limit: int = 50) -> list[dict]:
    session = SessionLocal()
    try:
        recs = (session.query(PasswordHashScanRecord)
                .order_by(PasswordHashScanRecord.scanned_at.desc()).limit(limit).all())
        return [r.to_dict() for r in recs]
    finally:
        session.close()


def get_scan(scan_id: int) -> dict | None:
    session = SessionLocal()
    try:
        rec = session.query(PasswordHashScanRecord).filter_by(id=scan_id).first()
        return rec.to_full_dict() if rec else None
    finally:
        session.close()