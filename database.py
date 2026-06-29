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

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///cryptiq.db")

if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL)

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

# --- test code, only runs if you execute this file directly ---
if __name__ == '__main__':
    session = Session()
    # actually open a session using the factory above

    scan_record = ScanRecord(
        domain='example.com',
        tls_version='TLS 1.2',
        algorithm='RSA',
        quantum_vulnerable=False,
        risk_level='Low',
        pqc_status='Unknown'
    )
    # this creates one row, but only in memory — not saved yet

    session.add(scan_record)
    # tells the session "I want to save this row"

    session.commit()
    # actually writes it to the database file

    all_records = session.query(ScanRecord).all()
    # .query(ScanRecord) asks "give me rows from the scans table"
    # .all() means "give me every row, no filtering"

    print(all_records)