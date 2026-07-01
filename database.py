import os
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
from cryptography.fernet import Fernet

ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")

def encrypt_value(value: str) -> str:
    if not value or not ENCRYPTION_KEY:
        return value
    f = Fernet(ENCRYPTION_KEY.encode())
    return f.encrypt(value.encode()).decode()

def decrypt_value(value: str) -> str:
    if not value or not ENCRYPTION_KEY:
        return value
    f = Fernet(ENCRYPTION_KEY.encode())
    return f.decrypt(value.encode()).decode()

Base = declarative_base()

class ScanRecord(Base):
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True)
    workspace_id = Column(Integer, nullable=True)  # add this
    domain = Column(String)
    tls_version = Column(String)
    algorithm = Column(String)
    quantum_vulnerable = Column(Boolean)
    risk_level = Column(String)
    pqc_status = Column(String)
    scanned_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<ScanRecord domain={self.domain} risk={self.risk_level}>"

    def to_dict(self):
        return {
            'id': self.id,
            'domain': self.domain,
            'tls_version': self.tls_version,
            'algorithm': self.algorithm,
            'quantum_vulnerable': self.quantum_vulnerable,
            'risk_level': self.risk_level,
            'pqc_status': self.pqc_status,
            'scanned_at': str(self.scanned_at)
        }

class Workspace(Base):
    __tablename__ = 'workspaces'

    id = Column(Integer, primary_key=True)
    org_name = Column(String, nullable=False)
    root_domain = Column(String)
    aws_access_key = Column(String)
    aws_secret_key = Column(String)
    aws_region = Column(String, default='us-east-1')
    github_org = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Workspace org_name={self.org_name} root_domain={self.root_domain}>"

    def to_dict(self):
        return {
            'id': self.id,
            'org_name': self.org_name,
            'root_domain': self.root_domain,
            'aws_region': self.aws_region,
            'github_org': self.github_org,
            'aws_connected': bool(self.aws_access_key),
            'created_at': str(self.created_at)
        }
class ScanJob(Base):
    __tablename__ = 'scan_jobs'

    id = Column(Integer, primary_key=True)
    workspace_id = Column(Integer, nullable=False)
    status = Column(String, default='pending')  # pending, running, complete, failed
    domains_found = Column(Integer, default=0)
    domains_scanned = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    error = Column(String, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'workspace_id': self.workspace_id,
            'status': self.status,
            'domains_found': self.domains_found,
            'domains_scanned': self.domains_scanned,
            'created_at': str(self.created_at),
            'completed_at': str(self.completed_at) if self.completed_at else None,
            'error': self.error
        }
# engine and tables — must come after ALL model classes
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///cryptiq.db")

if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(
        DATABASE_URL,
        pool_size=5,
        max_overflow=2,
        pool_timeout=30,
        pool_pre_ping=True,
    )

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)