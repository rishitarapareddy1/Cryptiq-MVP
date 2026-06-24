# --- imports ---
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
# create_engine: opens a connection to the database file
# Column, Integer, String, Boolean, DateTime: define what type each field is

from sqlalchemy.orm import declarative_base, sessionmaker
# declarative_base: lets us define database tables as Python classes
# sessionmaker: creates a tool for talking to the database (adding, querying, saving)

from datetime import datetime
# used to timestamp when a scan happened

# --- table definition ---
Base = declarative_base()
# Base is the parent class every database table inherits from

class ScanRecord(Base):
    # this class represents one row in the 'scans' table
    # each attribute below becomes a column in that table
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True)
    # primary_key=True means this uniquely identifies each row, auto-increments

    id = Column(Integer, primary_key=True)
    domain = Column(String)
    tls_version = Column(String)
    algorithm = Column(String)
    quantum_vulnerable = Column(Boolean)
    risk_level = Column(String)
    pqc_status = Column(String)
    scanned_at = Column(DateTime, default=datetime.utcnow)
    # default=datetime.utcnow means this fills in automatically if not provided

    def __repr__(self):
        return f"<ScanRecord domain={self.domain} risk={self.risk_level} pqc_status={self.pqc_status}>"

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
    
# --- database setup ---
engine = create_engine('sqlite:///cryptiq.db')
# engine is the actual connection to the database file 'cryptiq.db'
    # this file gets created automatically the first time you run this

Base.metadata.create_all(engine)
# this looks at every class that inherits from Base (just ScanRecord right now)
# and creates the actual table in the database file if it doesn't exist yet

Session = sessionmaker(bind=engine)
# Session is a factory — every time you call Session() it gives you
# a fresh connection you can use to add/query/save data

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