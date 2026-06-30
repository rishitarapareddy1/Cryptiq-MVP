"""
api.py  (root)
--------------
Unified Cryptiq API — serves all scanners from a single FastAPI app.

Routes:
  /               → landing page
  /tls            → TLS scanner UI
  /ssh            → SSH scanner UI (mounted sub-app)

  TLS endpoints (from tls_scanner/):
    POST /scan
    POST /scan/bulk
    GET  /scans
    GET  /scans/{domain}
    GET  /aws/certificates
    GET  /aws/keys
    GET  /aws/cbom
    GET  /health
    GET  /docs  (Swagger)

  SSH endpoints (from ssh_scanner/):
    All mounted under /ssh/... — served by ssh_scanner/api.py sub-application
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

# ── TLS scanner imports ─────────────────────────────────────────
from tls_scanner.scan_tls import scan_domain, convert_to_cbom
from tls_scanner.scan_aws import scan_acm_certificates, scan_kms_keys, convert_aws_to_cbom
from database import Session as DBSession, ScanRecord

# ── SSH scanner imports ─────────────────────────────────────────
from ssh_scanner.scan_ssh import scan_ssh, scan_ssh_bulk
from ssh_scanner.ssh_risk import assess_risk_from_scan, summarise_risk_assessments
from ssh_scanner.ssh_cbom import generate_ssh_cbom
from ssh_scanner.ssh_database import (
    save_scan, get_scan_history, get_latest_scan,
    get_inventory_summary, get_db, SSHScanRecord, create_tables, get_engine,
)
from ssh_scanner.ssh_network import discover_network
from ssh_scanner.ssh_assets import (
    upsert_asset_metadata, list_asset_metadata,
    get_enriched_assets, take_fleet_snapshot, get_fleet_trend,
)
from ssh_scanner.ssh_report import generate_report

from ssh_migration.api import router as migration_router

logger = logging.getLogger(__name__)

# Silence paramiko's internal thread exceptions — these are expected when
# we attempt host key types the server doesn't support (get_host_keys loop).
# The scanner handles these gracefully; the log noise is just confusing.
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)

# ── App ─────────────────────────────────────────────────────────
app = FastAPI(
    title="Cryptiq PQC Scanner",
    description="Post-quantum cryptography readiness platform. TLS, SSH, AWS crypto asset discovery.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── Static files ─────────────────────────────────────────────────
_here = os.path.dirname(os.path.abspath(__file__))
_static = os.path.join(_here, "static")
if os.path.isdir(_static):
    app.mount("/static", StaticFiles(directory=_static), name="static")

# ── Initialise SSH DB tables on startup ─────────────────────────
@app.on_event("startup")
def startup():
    create_tables(get_engine())

# Mount SSH migration router
app.include_router(migration_router)


# ==================================================================
# Page routes
# ==================================================================

@app.get("/", include_in_schema=False)
def root():
    index = os.path.join(_here, "static", "index.html")
    if os.path.exists(index):
        return FileResponse(index)
    return JSONResponse({"message": "Cryptiq API", "docs": "/docs"})


@app.get("/tls", include_in_schema=False)
def tls_ui():
    page = os.path.join(_here, "static", "tls.html")
    if os.path.exists(page):
        return FileResponse(page)
    return RedirectResponse("/docs")


@app.get("/migrate", include_in_schema=False)
def migrate_ui():
    page = os.path.join(_here, "static", "migration.html")
    if os.path.exists(page):
        return FileResponse(page)
    return RedirectResponse("/docs")


@app.get("/ssh", include_in_schema=False)
def ssh_ui():
    page = os.path.join(_here, "static", "ssh.html")
    if os.path.exists(page):
        return FileResponse(page)
    return RedirectResponse("/docs")


# ==================================================================
# TLS Scanner endpoints
# ==================================================================

class ScanRequest(BaseModel):
    domain: str

class BulkScanRequest(BaseModel):
    domains: list[str]


def _save_tls_scan(result: dict) -> None:
    session = DBSession()
    try:
        record = ScanRecord(
            domain=result["domain"],
            tls_version=result["tls_version"],
            algorithm=result["algorithm"],
            quantum_vulnerable=result["quantum_vulnerable"],
            risk_level=result["risk_level"],
            pqc_status=result["pqc_status"],
        )
        session.add(record)
        session.commit()
    finally:
        session.close()


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok", "service": "cryptiq", "version": "1.0.0"}


@app.post("/scan", tags=["tls"])
def scan(request: ScanRequest):
    """Scan a single HTTPS domain for TLS crypto assets."""
    result = scan_domain(request.domain)
    cbom = convert_to_cbom(result)
    _save_tls_scan(result)
    return {"result": result, "cbom": cbom}


@app.post("/scan/bulk", tags=["tls"])
def bulk_scan(request: BulkScanRequest):
    """Scan multiple domains concurrently."""
    session = DBSession()
    results = []
    try:
        for domain in request.domains:
            result = scan_domain(domain)
            results.append(result)
            session.add(ScanRecord(
                domain=result["domain"],
                tls_version=result["tls_version"],
                algorithm=result["algorithm"],
                quantum_vulnerable=result["quantum_vulnerable"],
                risk_level=result["risk_level"],
                pqc_status=result["pqc_status"],
            ))
        session.commit()
    finally:
        session.close()
    return {"results": results, "cbom": convert_to_cbom(results)}


@app.get("/scans", tags=["tls"])
def get_scans():
    """Return all TLS scan history."""
    session = DBSession()
    try:
        scans = session.query(ScanRecord).all()
        return {"scans": [s.to_dict() for s in scans]}
    finally:
        session.close()


@app.get("/scans/{domain}", tags=["tls"])
def get_scans_by_domain(domain: str):
    """Return TLS scan history for a specific domain."""
    session = DBSession()
    try:
        scans = session.query(ScanRecord).filter(ScanRecord.domain == domain).all()
        return {"scans": [s.to_dict() for s in scans]}
    finally:
        session.close()


@app.get("/aws/certificates", tags=["aws"])
def get_aws_certificates():
    """List and classify all ACM certificates (us-east-1)."""
    return {"results": scan_acm_certificates()}


@app.get("/aws/keys", tags=["aws"])
def get_aws_keys():
    """List and classify all KMS keys (us-east-1)."""
    return {"results": scan_kms_keys()}


@app.get("/aws/cbom", tags=["aws"])
def get_aws_cbom():
    """CycloneDX CBOM for all AWS crypto assets."""
    return convert_aws_to_cbom(scan_acm_certificates(), scan_kms_keys())


# ==================================================================
# SSH Scanner endpoints
# ==================================================================

class SSHScanRequest(BaseModel):
    host: str
    port: int = Field(22, ge=1, le=65535)
    timeout: float = Field(10.0, ge=1.0, le=60.0)

class SSHBulkScanRequest(BaseModel):
    hosts: list[str]
    port: int = Field(22, ge=1, le=65535)
    timeout: float = Field(10.0, ge=1.0, le=60.0)
    max_workers: int = Field(20, ge=1, le=100)

class SSHDiscoverRequest(BaseModel):
    target: str
    port: int = Field(22, ge=1, le=65535)
    timeout: float = Field(3.0, ge=0.5, le=30.0)
    max_workers: int = Field(100, ge=1, le=500)
    auto_scan: bool = False

class SSHAssetTagRequest(BaseModel):
    host: str
    port: int = 22
    asset_name: Optional[str] = None
    asset_owner: Optional[str] = None
    environment: Optional[str] = None
    business_unit: Optional[str] = None
    location: Optional[str] = None
    device_type: Optional[str] = None
    can_upgrade: Optional[bool] = None
    upgrade_blocker: Optional[str] = None
    planned_upgrade_date: Optional[str] = None
    remediation_status: Optional[str] = None
    tags: Optional[list[str]] = None
    notes: Optional[str] = None


def _ssh_result_to_dict(scan_result, risk, db_record=None):
    primary_key = scan_result.host_keys[0] if scan_result.host_keys else None
    return {
        "host": scan_result.host,
        "port": scan_result.port,
        "ssh_version": scan_result.ssh_version,
        "ssh_protocol": scan_result.ssh_protocol,
        "raw_banner": scan_result.raw_banner,
        "host_key_algorithm": primary_key.algorithm if primary_key else None,
        "host_key_size": primary_key.key_size if primary_key else None,
        "key_exchange": scan_result.negotiated_kex or (scan_result.server_kex_algorithms[0] if scan_result.server_kex_algorithms else None),
        "cipher": scan_result.negotiated_cipher or (scan_result.server_ciphers[0] if scan_result.server_ciphers else None),
        "mac": scan_result.negotiated_mac or (scan_result.server_macs[0] if scan_result.server_macs else None),
        "host_keys": [{"algorithm": hk.algorithm, "key_size": hk.key_size, "fingerprint": hk.fingerprint} for hk in scan_result.host_keys],
        "server_kex_algorithms": scan_result.server_kex_algorithms,
        "server_ciphers": scan_result.server_ciphers,
        "server_macs": scan_result.server_macs,
        "server_host_key_algorithms": scan_result.server_host_key_algorithms,
        "server_compression": scan_result.server_compression,
        "quantum_vulnerable": risk.quantum_vulnerable,
        "risk_level": risk.risk_level,
        "pqc_status": risk.pqc_status,
        "migration_priority": risk.migration_priority,
        "findings": risk.findings,
        "scan_success": scan_result.scan_success,
        "scan_error": scan_result.scan_error,
        "scanned_at": db_record.scanned_at.isoformat() if db_record and db_record.scanned_at else None,
        "db_id": db_record.id if db_record else None,
    }


@app.post("/ssh/scan", tags=["ssh"])
def ssh_scan(request: SSHScanRequest):
    """Scan a single SSH host for cryptographic assets."""
    try:
        result = scan_ssh(request.host, request.port, request.timeout)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")
    risk = assess_risk_from_scan(result)
    db = next(get_db())
    try:
        record = save_scan(db, result, risk)
    except Exception as e:
        logger.warning("DB save failed: %s", e)
        record = None
    return _ssh_result_to_dict(result, risk, record)


@app.post("/ssh/scan/bulk", tags=["ssh"])
def ssh_scan_bulk(request: SSHBulkScanRequest):
    """Scan multiple SSH hosts concurrently."""
    seen, unique = set(), []
    for h in request.hosts:
        h = h.strip()
        if h and h not in seen:
            seen.add(h); unique.append(h)

    results = scan_ssh_bulk(unique, request.port, request.timeout, request.max_workers)
    db = next(get_db())
    output, risks = [], []
    for r in results:
        risk = assess_risk_from_scan(r)
        risks.append(risk)
        try:
            record = save_scan(db, r, risk)
        except Exception:
            record = None
        output.append(_ssh_result_to_dict(r, risk, record))
    return {
        "results": output,
        "summary": summarise_risk_assessments(risks),
        "total_succeeded": sum(1 for r in results if r.scan_success),
    }


@app.post("/ssh/discover", tags=["ssh"])
def ssh_discover(request: SSHDiscoverRequest):
    """Discover SSH hosts on a network range (CIDR, IP range, hostname list)."""
    try:
        discovered = discover_network(request.target, request.port, request.timeout, request.max_workers)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    result = [{"ip": h.ip, "hostname": h.hostname, "port": h.port, "ssh_banner": h.ssh_banner,
               "ssh_version": h.ssh_version, "os_hint": h.os_hint, "device_type": h.device_type}
              for h in discovered]

    if request.auto_scan and discovered:
        hosts = [h.hostname or h.ip for h in discovered]
        scan_results = scan_ssh_bulk(hosts, request.port, 10.0, 20)
        db = next(get_db())
        scan_out, risks = [], []
        for r in scan_results:
            risk = assess_risk_from_scan(r)
            risks.append(risk)
            try:
                record = save_scan(db, r, risk)
            except Exception:
                record = None
            scan_out.append(_ssh_result_to_dict(r, risk, record))
        return {"discovered": result, "total_discovered": len(discovered),
                "scan_results": scan_out, "summary": summarise_risk_assessments(risks)}

    return {"discovered": result, "total_discovered": len(discovered)}


@app.get("/ssh/scans", tags=["ssh"])
def ssh_scans(
    host: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    pqc_status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Paginated SSH scan history."""
    db = next(get_db())
    records = get_scan_history(db, host=host, limit=limit, offset=offset,
                               risk_level=risk_level, pqc_status=pqc_status)
    return [_db_record_to_dict(r) for r in records]


def _db_record_to_dict(r: SSHScanRecord) -> dict:
    import json
    return {
        "host": r.host, "port": r.port,
        "ssh_version": r.ssh_version, "ssh_protocol": r.ssh_protocol,
        "raw_banner": r.raw_banner,
        "host_key_algorithm": r.host_key_algorithm, "host_key_size": r.host_key_size,
        "key_exchange": r.key_exchange, "cipher": r.cipher, "mac": r.mac,
        "host_keys": [{"algorithm": hk.algorithm, "key_size": hk.key_size, "fingerprint": hk.fingerprint} for hk in r.host_keys],
        "server_kex_algorithms": r.algorithm_advertisement.kex_algorithms if r.algorithm_advertisement else [],
        "server_ciphers": r.algorithm_advertisement.ciphers if r.algorithm_advertisement else [],
        "server_macs": r.algorithm_advertisement.macs if r.algorithm_advertisement else [],
        "server_host_key_algorithms": r.algorithm_advertisement.host_key_algorithms if r.algorithm_advertisement else [],
        "server_compression": r.algorithm_advertisement.compression if r.algorithm_advertisement else [],
        "quantum_vulnerable": r.quantum_vulnerable, "risk_level": r.risk_level,
        "pqc_status": r.pqc_status, "migration_priority": r.migration_priority,
        "findings": json.loads(r.findings_json) if r.findings_json else [],
        "scan_success": r.scan_success, "scan_error": r.scan_error,
        "scanned_at": r.scanned_at.isoformat() if r.scanned_at else None,
        "db_id": r.id,
    }


@app.get("/ssh/scans/{host}", tags=["ssh"])
def ssh_scans_for_host(host: str, limit: int = Query(20, ge=1, le=200)):
    db = next(get_db())
    records = get_scan_history(db, host=host, limit=limit)
    if not records:
        raise HTTPException(status_code=404, detail=f"No scans found for {host}")
    return [_db_record_to_dict(r) for r in records]


@app.get("/ssh/latest/{host}", tags=["ssh"])
def ssh_latest(host: str, port: int = Query(22)):
    db = next(get_db())
    r = get_latest_scan(db, host=host, port=port)
    if not r:
        raise HTTPException(status_code=404, detail=f"No scan found for {host}:{port}")
    return _db_record_to_dict(r)


@app.post("/ssh/rescan/{host}", tags=["ssh"])
def ssh_rescan(host: str, port: int = Query(22), timeout: float = Query(10.0)):
    return ssh_scan(SSHScanRequest(host=host, port=port, timeout=timeout))


@app.get("/ssh/cbom/{host}", tags=["ssh"])
def ssh_cbom(host: str, port: int = Query(22)):
    from ssh_scanner.scan_ssh import SSHScanResult, SSHHostKey
    from ssh_scanner.ssh_risk import assess_risk
    db = next(get_db())
    r = get_latest_scan(db, host=host, port=port)
    if not r:
        raise HTTPException(status_code=404, detail=f"No scan found for {host}:{port}")
    scan_result = SSHScanResult(
        host=r.host, port=r.port, ssh_version=r.ssh_version, ssh_protocol=r.ssh_protocol,
        raw_banner=r.raw_banner,
        host_keys=[SSHHostKey(algorithm=hk.algorithm, key_size=hk.key_size, fingerprint=hk.fingerprint) for hk in r.host_keys],
        negotiated_kex=r.key_exchange, negotiated_cipher=r.cipher, negotiated_mac=r.mac,
        server_kex_algorithms=r.algorithm_advertisement.kex_algorithms if r.algorithm_advertisement else [],
        server_ciphers=r.algorithm_advertisement.ciphers if r.algorithm_advertisement else [],
        server_macs=r.algorithm_advertisement.macs if r.algorithm_advertisement else [],
        server_host_key_algorithms=r.algorithm_advertisement.host_key_algorithms if r.algorithm_advertisement else [],
        server_compression=r.algorithm_advertisement.compression if r.algorithm_advertisement else [],
        scan_success=r.scan_success,
    )
    risk = assess_risk(host=r.host, host_key_algorithm=r.host_key_algorithm, key_size=r.host_key_size,
                       kex_algorithm=r.key_exchange, cipher=r.cipher, mac=r.mac)
    cbom = generate_ssh_cbom(scan_result, risk)
    return JSONResponse(content=cbom, media_type="application/vnd.cyclonedx+json; version=1.6")


@app.get("/ssh/inventory", tags=["ssh"])
def ssh_inventory():
    db = next(get_db())
    return get_inventory_summary(db)


@app.post("/ssh/assets/tag", tags=["ssh"])
def ssh_tag_asset(request: SSHAssetTagRequest):
    db = next(get_db())
    kwargs = {k: v for k, v in request.model_dump().items() if k not in ("host", "port") and v is not None}
    record = upsert_asset_metadata(db, request.host, request.port, **kwargs)
    return {"status": "ok", "host": record.host, "port": record.port}


@app.get("/ssh/assets", tags=["ssh"])
def ssh_list_assets(
    environment: Optional[str] = Query(None),
    remediation_status: Optional[str] = Query(None),
    tag: Optional[str] = Query(None),
):
    db = next(get_db())
    records = list_asset_metadata(db, environment=environment, remediation_status=remediation_status, tag=tag)
    return [{"host": r.host, "port": r.port, "asset_name": r.asset_name, "asset_owner": r.asset_owner,
             "environment": r.environment, "business_unit": r.business_unit, "location": r.location,
             "can_upgrade": r.can_upgrade, "remediation_status": r.remediation_status, "tags": r.tags}
            for r in records]


@app.get("/ssh/assets/enriched", tags=["ssh"])
def ssh_enriched_assets():
    db = next(get_db())
    assets = get_enriched_assets(db)
    return [{"host": a.host, "port": a.port, "ssh_version": a.ssh_version,
             "host_key_algorithm": a.host_key_algorithm, "host_key_size": a.host_key_size,
             "key_exchange": a.key_exchange, "cipher": a.cipher, "mac": a.mac,
             "quantum_vulnerable": a.quantum_vulnerable, "risk_level": a.risk_level,
             "pqc_status": a.pqc_status, "migration_priority": a.migration_priority,
             "findings": a.findings, "scanned_at": a.scanned_at.isoformat() if a.scanned_at else None,
             "asset_name": a.asset_name, "asset_owner": a.asset_owner, "environment": a.environment,
             "remediation_status": a.remediation_status, "tags": a.tags}
            for a in assets]


@app.post("/ssh/snapshot", tags=["ssh"])
def ssh_snapshot(label: Optional[str] = Query(None)):
    db = next(get_db())
    snap = take_fleet_snapshot(db, label)
    return {"id": snap.id, "label": snap.label, "snapshot_at": snap.snapshot_at.isoformat(),
            "total_hosts": snap.total_hosts, "quantum_vulnerable": snap.quantum_vulnerable,
            "pqc_readiness_percent": snap.pqc_readiness_percent}


@app.get("/ssh/trend", tags=["ssh"])
def ssh_trend(limit: int = Query(12, ge=1, le=52)):
    db = next(get_db())
    snaps = get_fleet_trend(db, limit)
    return [{"id": s.id, "label": s.label, "snapshot_at": s.snapshot_at.isoformat(),
             "total_hosts": s.total_hosts, "quantum_vulnerable": s.quantum_vulnerable,
             "critical_count": s.critical_count, "high_count": s.high_count,
             "pqc_ready_count": s.pqc_ready_count, "hybrid_count": s.hybrid_count,
             "pqc_readiness_percent": s.pqc_readiness_percent}
            for s in snaps]


@app.post("/ssh/report", tags=["ssh"])
def ssh_report(org_name: str = Query("Organisation")):
    """Generate a consulting PDF report for all scanned SSH assets."""
    db = next(get_db())
    assets = get_enriched_assets(db)
    if not assets:
        raise HTTPException(status_code=404, detail="No scanned assets. Run scans first.")
    snapshots = get_fleet_trend(db, limit=12)
    try:
        pdf_bytes = generate_report(assets, org_name=org_name, snapshots=snapshots)
    except Exception as e:
        logger.exception("Report generation failed")
        raise HTTPException(status_code=500, detail=f"Report failed: {e}")
    filename = f"cryptiq_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return Response(content=pdf_bytes, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


# ==================================================================
# Entry point
# ==================================================================

if __name__ == "__main__":
    import uvicorn
    print("\n  Cryptiq PQC Scanner")
    print("  Home      →  http://localhost:8000")
    print("  TLS       →  http://localhost:8000/tls")
    print("  SSH       →  http://localhost:8000/ssh")
    print("  Migration →  http://localhost:8000/migrate")
    print("  Docs      →  http://localhost:8000/docs\n")
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True, log_level="info")