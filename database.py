import os
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

Base = declarative_base()

class ScanRecord(Base):
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True)
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

# engine and tables — must come after ALL model classes
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///cryptiq.db")

if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL)

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)