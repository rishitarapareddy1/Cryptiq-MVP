from tls_scanner.scan_tls import scan_domain, convert_to_cbom
# 1. imports
from fastapi import FastAPI
from pydantic import BaseModel
from database import Session, ScanRecord
from tls_scanner.scan_aws import scan_acm_certificates, scan_kms_keys, convert_aws_to_cbom

from ssh_scanner.scan_ssh import scan_ssh, scan_ssh_bulk
from ssh_scanner.ssh_risk import assess_risk_from_scan
from ssh_scanner.ssh_database import save_scan, get_scan_history, get_latest_scan, get_inventory_summary, get_db


# also import scan_domain and convert_to_cbom from your scanner file

# 2. create the app
app = FastAPI()

# 3. define the request model
# this tells FastAPI what the request body looks like
class ScanRequest(BaseModel):
    domain: str
   
# 4. create the endpoint
# @app.post("/scan") means: when someone sends a POST request to /scan, run this function
@app.post("/scan")
def scan(request: ScanRequest):
    result = scan_domain(request.domain)
    cbom = convert_to_cbom(result)
    
    # now save result to the database
    # open a session
    session = Session()
    # create a ScanRecord using fields from result
    scan_record = ScanRecord(
        domain=result['domain'],
        tls_version=result['tls_version'],
        algorithm=result['algorithm'],
        quantum_vulnerable=result['quantum_vulnerable'],
        risk_level=result['risk_level'],
        pqc_status=result['pqc_status']
    )
    session.add(scan_record)
    session.commit()
    session.close()
    # add and commit
    # close the session
    
    return {"result": result, "cbom": cbom}
# endpoint 1 — health check
# GET /health
# returns {"status": "ok"}
# this is standard for any API — lets you verify it's running

@app.get("/scans")
def get_scans():
    # open a session
    # query all ScanRecord rows
    # return them
    # close the session
    session = Session()
    scans = session.query(ScanRecord).all()
    session.close()
    return {"scans": [scan.to_dict() for scan in scans]}

@app.get("/health")
def health():
    # your code
    return {"status": "ok"}
# endpoint 2 — bulk scan
# POST /scan/bulk
# request body: { "domains": ["google.com", "github.com", "stripe.com"] }
# returns list of scan results + one combined CBOM

class BulkScanRequest(BaseModel):
    domains: list[str]

@app.post("/scan/bulk")
def bulk_scan(request: BulkScanRequest):
    # loop through request.domains
    # call scan_domain on each
    # convert all results to one CBOM
    # return results and cbom
    results = []
    session = Session()  # open once before the loop
    
    for domain in request.domains:
        result = scan_domain(domain)
        results.append(result)
        # save each result here — same pattern as /scan

        # create a ScanRecord, add it to session
        scan_record = ScanRecord(
            domain=result['domain'],
            tls_version=result['tls_version'],
            algorithm=result['algorithm'],
            quantum_vulnerable=result['quantum_vulnerable'],
            risk_level=result['risk_level'],
            pqc_status=result['pqc_status']
        )
        session.add(scan_record)
    
    session.commit()  # commit once after all records are added
    session.close()
    
    cbom = convert_to_cbom(results)
    return {"results": results, "cbom": cbom}

@app.get("/scans/{domain}")
def get_scans_by_domain(domain: str):
    # open a session
    # query ScanRecord filtering by domain
    # hint: session.query(ScanRecord).filter(ScanRecord.domain == domain).all()
    # close session
    # return results
    session = Session()
    scans = session.query(ScanRecord).filter(ScanRecord.domain == domain).all()
    session.close()
    return {"scans": [scan.to_dict() for scan in scans]}

@app.get("/aws/certificates")
def get_aws_certificates():
    # call scan_acm_certificates()
    results = scan_acm_certificates()
    # return the results
    return {"results": results}

@app.get("/aws/keys")  
def get_aws_keys():
    # call scan_kms_keys()
    results = scan_kms_keys()
    # return the results
    return {"results": results}

@app.get("/aws/cbom")
def get_aws_cbom():
    cert_results = scan_acm_certificates()
    kms_results = scan_kms_keys()
    cbom = convert_aws_to_cbom(cert_results, kms_results)
    return cbom

class SSHScanRequest(BaseModel):
    host: str
    port: int = 22

class SSHBulkScanRequest(BaseModel):
    hosts: list[str]
    port: int = 22

@app.post("/ssh/scan")
def ssh_scan(request: SSHScanRequest):
    try:
        result = scan_ssh(request.host, request.port)
        risk = assess_risk_from_scan(result)
        db = next(get_db())
        record = save_scan(db, result, risk)
        return {
            'host': result.host,
            'port': result.port,
            'ssh_version': result.ssh_version,
            'host_key_algorithm': record.host_key_algorithm,
            'host_key_size': record.host_key_size,
            'key_exchange': record.key_exchange,
            'cipher': record.cipher,
            'quantum_vulnerable': risk.quantum_vulnerable,
            'risk_level': risk.risk_level,
            'pqc_status': risk.pqc_status,
            'migration_priority': risk.migration_priority,
            'findings': risk.findings
        }
    except Exception as e:
        return {"error": str(e), "host": request.host}

@app.post("/ssh/scan/bulk")
def ssh_scan_bulk(request: SSHBulkScanRequest):
    results = scan_ssh_bulk(request.hosts, request.port)
    db = next(get_db())
    output = []
    for result in results:
        risk = assess_risk_from_scan(result)
        record = save_scan(db, result, risk)
        output.append({
            'host': result.host,
            'ssh_version': result.ssh_version,
            'risk_level': risk.risk_level,
            'pqc_status': risk.pqc_status,
            'quantum_vulnerable': risk.quantum_vulnerable,
            'findings': risk.findings
        })
    return {"results": output}

@app.get("/ssh/scans")
def get_ssh_scans():
    db = next(get_db())
    scans = get_scan_history(db)
    return {"scans": [
        {
            'host': s.host,
            'risk_level': s.risk_level,
            'pqc_status': s.pqc_status,
            'scanned_at': str(s.scanned_at)
        } for s in scans
    ]}

@app.get("/ssh/scans/{host}")
def get_ssh_scans_by_host(host: str):
    db = next(get_db())
    scans = get_scan_history(db, host=host)
    return {"scans": [
        {
            'host': s.host,
            'risk_level': s.risk_level,
            'pqc_status': s.pqc_status,
            'scanned_at': str(s.scanned_at)
        } for s in scans
    ]}

@app.get("/ssh/inventory")
def get_ssh_inventory():
    db = next(get_db())
    return get_inventory_summary(db)

@app.get("/ssh/cbom/{host}")
def get_ssh_cbom(host: str):
    from ssh_scanner.ssh_cbom import generate_ssh_cbom
    from ssh_scanner.scan_ssh import scan_ssh
    from ssh_scanner.ssh_risk import assess_risk_from_scan
    result = scan_ssh(host)
    risk = assess_risk_from_scan(result)
    cbom = generate_ssh_cbom(result, risk)
    return cbom