"""
code_signing/database.py
---------------------------
Persistence for signing manifests/history. Mirrors ssh_database.py's
module-local engine pattern so this product slice can be deployed/scaled
independently of the main TLS database.
"""

from __future__ import annotations

import json
import os
from datetime import datetime

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.environ.get(
    "CODESIGN_DATABASE_URL", os.environ.get("DATABASE_URL", "sqlite:///./codesign.db")
)

Base = declarative_base()


class SigningManifestRecord(Base):
    __tablename__ = "codesign_manifests"

    id = Column(Integer, primary_key=True)
    manifest_id = Column(String, unique=True, index=True)
    root_path = Column(String)
    key_id = Column(String)
    file_count = Column(Integer, default=0)
    success_count = Column(Integer, default=0)
    dry_run = Column(Boolean, default=False)
    manifest_json = Column(Text)  # full SigningManifest.to_dict() blob
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "manifest_id": self.manifest_id,
            "root_path": self.root_path,
            "key_id": self.key_id,
            "file_count": self.file_count,
            "success_count": self.success_count,
            "dry_run": self.dry_run,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


def get_engine():
    connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
    return create_engine(DATABASE_URL, connect_args=connect_args)


_engine = get_engine()
SessionLocal = sessionmaker(bind=_engine)


def create_tables(engine=None):
    Base.metadata.create_all(engine or _engine)


def save_manifest(manifest_dict: dict, dry_run: bool) -> SigningManifestRecord:
    session = SessionLocal()
    try:
        rec = SigningManifestRecord(
            manifest_id=manifest_dict["manifest_id"],
            root_path=manifest_dict["root_path"],
            key_id=manifest_dict["key_id"],
            file_count=manifest_dict["file_count"],
            success_count=manifest_dict["success_count"],
            dry_run=dry_run,
            manifest_json=json.dumps(manifest_dict),
        )
        session.add(rec)
        session.commit()
        session.refresh(rec)
        return rec
    finally:
        session.close()


def get_manifest(manifest_id: str) -> dict | None:
    session = SessionLocal()
    try:
        rec = session.query(SigningManifestRecord).filter_by(manifest_id=manifest_id).first()
        if not rec:
            return None
        return json.loads(rec.manifest_json)
    finally:
        session.close()


def list_manifests(limit: int = 50) -> list[dict]:
    session = SessionLocal()
    try:
        recs = (session.query(SigningManifestRecord)
                .order_by(SigningManifestRecord.created_at.desc())
                .limit(limit).all())
        return [r.to_dict() for r in recs]
    finally:
        session.close()