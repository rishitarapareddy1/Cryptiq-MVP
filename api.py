"""
api.py  (root)
--------------
Unified Cryptiq API — serves all scanners and migration tools from one FastAPI app.

This is a pure JSON API backend, designed to be consumed by the Next.js
frontend in /frontend. There is no server-rendered HTML here — the UI
lives entirely in the Next.js app.

Two product surfaces live here:
  1. Single-shot tools (no workspace needed): TLS scan, SSH scan, SSH migration.
     Use these directly — POST /scan, POST /ssh/scan, etc.
  2. Workspace-based tools (multi-tenant): create a Workspace, connect AWS,
     run background discovery+scan jobs, track ALB TLS migrations with
     real GitHub PRs. Use these via POST /workspace and friends.

Routes:
  TLS endpoints (from tls_scanner/):
    POST /scan, /scan/bulk, /discover, /discover/scan
    GET  /scans, /scans/{domain}
    GET  /aws/certificates, /aws/keys, /aws/cbom
    GET  /aws/alb-listeners, /aws/alb-cbom

  SSH endpoints (from ssh_scanner/):
    All mounted under /ssh/...

  SSH migration endpoints (from ssh_migration/):
    All mounted under /migrate/ssh/...

  ALB TLS migration endpoints (from tls_migration/):
    POST /migrate/alb-tls            — propose a migration PR (dry_run default)
    POST /migrate/alb-tls/rollback   — propose a rollback PR
    GET  /audit-log                  — append-only record of all migration actions

  Workspace endpoints (multi-tenant, from database.py):
    POST /workspace                              — create a workspace
    GET  /workspace/{id}                         — get workspace
    POST /workspace/{id}/connect/aws             — store encrypted AWS creds
    POST /workspace/{id}/scan                    — start background discovery+scan
    GET  /workspace/{id}/scan/{job_id}/status    — poll job status
    GET  /workspace/{id}/results                 — get all scan results for workspace

SAFETY INVARIANT (see CLAUDE.md):
  The ALB migration endpoints (/migrate/alb-tls*) NEVER mutate AWS resources
  and NEVER merge GitHub PRs. They only read AWS state (discovery) and
  propose changes via GitHub pull requests. A human merges. This is enforced
  in tls_migration/github_pr.py — see that module's chokepoint design.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, BackgroundTasks, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

# ── Database (TLS scans, workspaces, async jobs) ────────────────────────────
from database import (
    Session as DBSession, ScanRecord, Workspace, ScanJob,
    encrypt_value, decrypt_value,
)

# ── TLS scanner ──────────────────────────────────────────────────────────
from tls_scanner.scan_tls import scan_domain, convert_to_cbom
from tls_scanner.scan_aws import scan_acm_certificates, scan_kms_keys, convert_aws_to_cbom
from tls_scanner.scan_alb import discover_alb_listeners

# ── Domain/asset auto-discovery (CT logs, Route53, EC2) ─────────────────────
from discovery import discover_assets

# ── TLS/ALB migration (propose-only — see tls_migration/github_pr.py) ──────
from tls_migration.alb_cbom import convert_alb_to_cbom
from tls_migration.run import run_migration, PROD_CONFIRMATION_TOKEN
from tls_migration.rollback import run_rollback
from tls_migration.audit import read_log

# ── SSH scanner ──────────────────────────────────────────────────────────
from ssh_scanner.scan_ssh import scan_ssh, scan_ssh_bulk
from ssh_scanner.ssh_risk import assess_risk_from_scan, summarise_risk_assessments, assess_risk
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

# ── SSH migration router (mounted as a sub-router) ──────────────────────────
from ssh_migration.api import router as migration_router

logger = logging.getLogger(__name__)

# Silence paramiko's internal thread exceptions — expected when the scanner
# probes host key types the server doesn't support. Handled gracefully;
# the log noise is just confusing.
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)

# ── App ─────────────────────────────────────────────────────────
app = FastAPI(
    title="Cryptiq PQC Platform",
    description="Post-quantum cryptography readiness platform. TLS, SSH, AWS, and ALB crypto asset discovery and migration.",
    version="1.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Allow the Next.js frontend during development.
# Tighten this list in production to your deployed frontend URL(s).
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://cryptiq-frontend-whyk.onrender.com"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Initialise SSH DB tables on startup ─────────────────────────
@app.on_event("startup")
def startup():
    create_tables(get_engine())

# Mount SSH migration router
app.include_router(migration_router)


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok", "service": "cryptiq", "version": "1.1.0"}


# ==================================================================
# TLS Scanner endpoints
# ==================================================================

class ScanRequest(BaseModel):
    domain: str

class BulkScanRequest(BaseModel):
    domains: list[str]


def _save_tls_scan(result: dict, workspace_id: Optional[int] = None) -> None:
    session = DBSession()
    try:
        record = ScanRecord(
            workspace_id=workspace_id,
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


@app.post("/scan", tags=["tls"])
def scan(request: ScanRequest):
    """Scan a single HTTPS domain for TLS crypto assets."""
    result = scan_domain(request.domain)
    cbom = convert_to_cbom(result)
    _save_tls_scan(result)
    return {"result": result, "cbom": cbom}


class DiscoverRequest(BaseModel):
    root_domain: str
    region: str = "us-east-1"


@app.post("/discover", tags=["discovery"])
def discover(request: DiscoverRequest):
    """Auto-discover all domains and hosts for a root domain (CT logs + Route53 + EC2)."""
    assets = discover_assets(request.root_domain, request.region)
    return assets


@app.post("/discover/scan", tags=["discovery"])
def discover_and_scan(request: DiscoverRequest):
    """Discover all domains then immediately bulk scan them."""
    assets = discover_assets(request.root_domain, request.region)
    domains = assets["domains"]
    if not domains:
        return {"domains_found": 0, "results": [], "cbom": None}

    session = DBSession()
    results = []
    try:
        for domain in domains:
            try:
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
            except Exception:
                pass  # skip domains that fail to connect
        session.commit()
    finally:
        session.close()

    cbom = convert_to_cbom(results)
    return {
        "domains_found": len(domains),
        "domains_scanned": len(results),
        "ec2_hosts": assets["hosts"],
        "results": results,
        "cbom": cbom,
    }


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


@app.get("/aws/alb-listeners", tags=["aws"])
def get_alb_listeners(region: str = "us-east-1"):
    """
    Discover all ALB/NLB HTTPS/TLS listeners and classify PQC readiness.
    READ-ONLY — uses only Describe* operations. See iam/discovery-readonly.json.
    """
    assets = discover_alb_listeners(region=region)
    return {"region": region, "count": len(assets), "listeners": [a.to_dict() for a in assets]}


@app.get("/aws/alb-cbom", tags=["aws"])
def get_alb_cbom(region: str = "us-east-1"):
    """CycloneDX 1.6 CBOM for all ALB/NLB TLS listeners."""
    assets = discover_alb_listeners(region=region)
    return convert_alb_to_cbom(assets)


# ==================================================================
# Workspace endpoints (multi-tenant)
# ==================================================================

class WorkspaceCreateRequest(BaseModel):
    org_name: str
    root_domain: str
    aws_region: str = "us-east-1"
    github_org: Optional[str] = None


class WorkspaceAWSRequest(BaseModel):
    aws_access_key: str
    aws_secret_key: str
    aws_region: str = "us-east-1"


@app.post("/workspace", tags=["workspace"])
def create_workspace(request: WorkspaceCreateRequest):
    session = DBSession()
    try:
        workspace = Workspace(
            org_name=request.org_name,
            root_domain=request.root_domain,
            aws_region=request.aws_region,
            github_org=request.github_org,
        )
        session.add(workspace)
        session.commit()
        session.refresh(workspace)
        return workspace.to_dict()
    finally:
        session.close()


@app.get("/workspace/{workspace_id}", tags=["workspace"])
def get_workspace(workspace_id: int):
    session = DBSession()
    try:
        workspace = session.query(Workspace).filter(Workspace.id == workspace_id).first()
        if not workspace:
            raise HTTPException(status_code=404, detail="Workspace not found")
        return workspace.to_dict()
    finally:
        session.close()


@app.post("/workspace/{workspace_id}/connect/aws", tags=["workspace"])
def connect_aws(workspace_id: int, request: WorkspaceAWSRequest):
    """
    Store AWS credentials for this workspace, encrypted at rest (Fernet).

    Set the ENCRYPTION_KEY environment variable in production — without it,
    credentials are stored in PLAINTEXT (see database.py for details).
    """
    session = DBSession()
    try:
        workspace = session.query(Workspace).filter(Workspace.id == workspace_id).first()
        if not workspace:
            raise HTTPException(status_code=404, detail="Workspace not found")
        workspace.aws_access_key = encrypt_value(request.aws_access_key)
        workspace.aws_secret_key = encrypt_value(request.aws_secret_key)
        workspace.aws_region = request.aws_region
        session.commit()
        session.refresh(workspace)
        return workspace.to_dict()
    finally:
        session.close()


def run_workspace_scan(workspace_id: int, job_id: int):
    """Background task: discover + scan all domains for a workspace."""
    session = DBSession()
    try:
        job = session.query(ScanJob).filter(ScanJob.id == job_id).first()
        job.status = "running"
        session.commit()

        workspace = session.query(Workspace).filter(Workspace.id == workspace_id).first()
        assets = discover_assets(workspace.root_domain, workspace.aws_region or "us-east-1")
        domains = assets["domains"]

        job.domains_found = len(domains)
        session.commit()

        results = []
        for domain in domains:
            try:
                result = scan_domain(domain)
                results.append(result)
                session.add(ScanRecord(
                    workspace_id=workspace_id,
                    domain=result["domain"],
                    tls_version=result["tls_version"],
                    algorithm=result["algorithm"],
                    quantum_vulnerable=result["quantum_vulnerable"],
                    risk_level=result["risk_level"],
                    pqc_status=result["pqc_status"],
                ))
                job.domains_scanned = len(results)
                session.commit()
            except Exception:
                pass  # skip domains that fail to connect

        job.status = "complete"
        job.completed_at = datetime.utcnow()
        session.commit()

    except Exception as e:
        job = session.query(ScanJob).filter(ScanJob.id == job_id).first()
        if job:
            job.status = "failed"
            job.error = str(e)
            session.commit()
    finally:
        session.close()


@app.post("/workspace/{workspace_id}/scan", tags=["workspace"])
def workspace_scan(workspace_id: int, background_tasks: BackgroundTasks):
    """Start a background discovery+scan job for this workspace. Poll status via the returned job_id."""
    session = DBSession()
    try:
        workspace = session.query(Workspace).filter(Workspace.id == workspace_id).first()
        if not workspace:
            raise HTTPException(status_code=404, detail="Workspace not found")
        job = ScanJob(workspace_id=workspace_id, status="pending")
        session.add(job)
        session.commit()
        session.refresh(job)
        job_id = job.id
    finally:
        session.close()

    background_tasks.add_task(run_workspace_scan, workspace_id, job_id)
    return {"job_id": job_id, "status": "pending", "message": f"Scan started — poll /workspace/{workspace_id}/scan/{job_id}/status for progress"}


@app.get("/workspace/{workspace_id}/scan/{job_id}/status", tags=["workspace"])
def scan_status(workspace_id: int, job_id: int):
    session = DBSession()
    try:
        job = session.query(ScanJob).filter(
            ScanJob.id == job_id, ScanJob.workspace_id == workspace_id
        ).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        return job.to_dict()
    finally:
        session.close()


@app.get("/workspace/{workspace_id}/results", tags=["workspace"])
def workspace_results(workspace_id: int):
    session = DBSession()
    try:
        scans = session.query(ScanRecord).filter(
            ScanRecord.workspace_id == workspace_id
        ).order_by(ScanRecord.scanned_at.desc()).all()
        return {"results": [s.to_dict() for s in scans]}
    finally:
        session.close()

@app.get("/workspace/{workspace_id}/cbom", tags=["workspace"])
def workspace_cbom(workspace_id: int):
    session = DBSession()
    try:
        scans = session.query(ScanRecord).filter(
            ScanRecord.workspace_id == workspace_id
        ).order_by(ScanRecord.scanned_at.desc()).all()
        if not scans:
            raise HTTPException(status_code=404, detail="No scans found for this workspace")
        
        import uuid
        from datetime import datetime, timezone
        bom = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.6',
            'serialNumber': str(uuid.uuid4()),
            'version': 1,
            'metadata': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'component': {'type': 'application', 'name': 'Cryptiq PQC Scanner'}
            },
            'components': []
        }
        for s in scans:
            bom['components'].append({
                'type': 'cryptographic-asset',
                'name': f"{s.domain} TLS Certificate",
                'cryptoProperties': {
                    'assetType': 'certificate',
                    'algorithmProperties': {'primitive': 'keyagree'},
                    'nistQuantumSecurityLevel': 0 if s.quantum_vulnerable else 3,
                },
                'properties': [
                    {'name': 'quantum_vulnerable', 'value': str(s.quantum_vulnerable).lower()},
                    {'name': 'risk_level', 'value': s.risk_level},
                    {'name': 'pqc_status', 'value': s.pqc_status},
                    {'name': 'algorithm', 'value': s.algorithm or 'Unknown'},
                ]
            })
        return JSONResponse(content=bom, media_type="application/vnd.cyclonedx+json; version=1.6")
    finally:
        session.close()

class WorkspaceSSHScanRequest(BaseModel):
    hosts: Optional[list[str]] = None

@app.post("/workspace/{workspace_id}/scan/ssh", tags=["workspace"])
def workspace_ssh_scan(
    workspace_id: int,
    background_tasks: BackgroundTasks,
    request: WorkspaceSSHScanRequest = Body(default_factory=WorkspaceSSHScanRequest)
):
    session = DBSession()
    try:
        workspace = session.query(Workspace).filter(Workspace.id == workspace_id).first()
        if not workspace:
            raise HTTPException(status_code=404, detail="Workspace not found")
        job = ScanJob(workspace_id=workspace_id, status="pending")
        session.add(job)
        session.commit()
        session.refresh(job)
        job_id = job.id
    finally:
        session.close()
    background_tasks.add_task(run_workspace_ssh_scan, workspace_id, job_id, request.hosts)
    return {"job_id": job_id, "status": "pending", "message": "SSH scan started"}


def run_workspace_ssh_scan(workspace_id: int, job_id: int, manual_hosts: Optional[list[str]] = None):
    session = DBSession()
    try:
        job = session.query(ScanJob).filter(ScanJob.id == job_id).first()
        job.status = "running"
        session.commit()

        workspace = session.query(Workspace).filter(Workspace.id == workspace_id).first()

        if manual_hosts:
            hosts = manual_hosts
        else:
            assets = discover_assets(workspace.root_domain, workspace.aws_region or "us-east-1")
            hosts = assets.get("hosts", [])

        job.domains_found = len(hosts)
        session.commit()

        if not hosts:
            job.status = "complete"
            job.completed_at = datetime.utcnow()
            session.commit()
            return

        scan_results = scan_ssh_bulk(hosts, 22, 10.0, 20)
        db = next(get_db())
        scanned = 0
        for r in scan_results:
            try:
                risk = assess_risk_from_scan(r)
                record = save_scan(db, r, risk)
                record.workspace_id = workspace_id
                db.commit()
                scanned += 1
                job.domains_scanned = scanned
                session.commit()
            except Exception:
                pass

        job.status = "complete"
        job.completed_at = datetime.utcnow()
        session.commit()

    except Exception as e:
        job = session.query(ScanJob).filter(ScanJob.id == job_id).first()
        if job:
            job.status = "failed"
            job.error = str(e)
            session.commit()
    finally:
        session.close()

@app.get("/workspace/{workspace_id}/ssh/results", tags=["workspace"])
def workspace_ssh_results(workspace_id: int):
    db = next(get_db())
    from ssh_scanner.ssh_database import SSHScanRecord
    records = db.query(SSHScanRecord).filter(
        SSHScanRecord.workspace_id == workspace_id
    ).order_by(SSHScanRecord.scanned_at.desc()).all()
    return {"results": [_db_record_to_dict(r) for r in records]}
        
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
        "software_info": getattr(scan_result, "software_info", None),
        "capability_gap": getattr(scan_result, "capability_gap", None),
        "quantum_vulnerable": risk.quantum_vulnerable,
        "risk_level": risk.risk_level,
        "pqc_status": risk.pqc_status,
        "migration_priority": risk.migration_priority,
        "findings": risk.findings,
        "weighted_score": getattr(risk, "weighted_score", None),
        "score_breakdown": getattr(risk, "score_breakdown", None),
        "recommendations": [r.to_dict() for r in getattr(risk, "recommendations", [])],
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
        "total_requested": len(unique),
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
# ALB TLS Migration endpoints (propose-only — see CLAUDE.md)
# ==================================================================

class ALBMigrateRequest(BaseModel):
    listener_arn: str
    tf_repo: str
    gh_repo: str
    gh_base_branch: str = "main"
    dry_run: bool = True
    allow_prod: bool = False
    prod_token: Optional[str] = None


@app.post("/migrate/alb-tls", tags=["migration"])
def migrate_alb_tls(request: ALBMigrateRequest):
    """
    Discover an ALB listener and open a migration PR to a PQ TLS policy.

    dry_run=true (default): returns diff + PR body preview without writing to GitHub.
    dry_run=false: creates branch, commits change, opens PR. Returns PR URL.

    SAFETY: this endpoint NEVER merges the PR and NEVER mutates the AWS
    listener directly — it only reads AWS state and proposes a Terraform
    diff via a GitHub pull request. A human merges. See CLAUDE.md.

    Prod-tagged listeners are blocked unless allow_prod=true and prod_token matches.
    """
    region = request.listener_arn.split(":")[3] if ":" in request.listener_arn else "us-east-1"
    all_assets = discover_alb_listeners(region=region)
    asset = next((a for a in all_assets if a.listener_arn == request.listener_arn), None)

    if not asset:
        raise HTTPException(
            status_code=404,
            detail=f"Listener {request.listener_arn} not found in region {region}.",
        )

    result = run_migration(
        asset=asset,
        tf_repo=request.tf_repo,
        gh_repo=request.gh_repo,
        gh_base_branch=request.gh_base_branch,
        dry_run=request.dry_run,
        allow_prod=request.allow_prod,
        prod_token=request.prod_token,
    )
    return result.to_dict()


@app.get("/audit-log", tags=["migration"])
def get_audit_log(limit: int = 100):
    """Return recent entries from the Cryptiq audit log (append-only, never modified)."""
    return {"entries": read_log(limit=limit)}


class ALBRollbackRequest(BaseModel):
    listener_arn: str
    migration_pr_body: str
    migration_pr_number: int
    tf_file: str
    gh_repo: str
    gh_base_branch: str = "main"
    dry_run: bool = True


@app.post("/migrate/alb-tls/rollback", tags=["migration"])
def rollback_alb_tls(request: ALBRollbackRequest):
    """
    Open a rollback PR that restores the ssl_policy to its pre-migration value.

    The original policy is read from the migration PR body — never guessed.
    dry_run=true (default): returns diff + PR body preview.
    dry_run=false: opens the rollback PR.
    """
    region = request.listener_arn.split(":")[3] if ":" in request.listener_arn else "us-east-1"
    all_assets = discover_alb_listeners(region=region)
    asset = next((a for a in all_assets if a.listener_arn == request.listener_arn), None)

    if not asset:
        raise HTTPException(
            status_code=404,
            detail=f"Listener {request.listener_arn} not found in region {region}.",
        )

    result = run_rollback(
        asset=asset,
        migration_pr_body=request.migration_pr_body,
        migration_pr_number=request.migration_pr_number,
        tf_file=request.tf_file,
        gh_repo=request.gh_repo,
        gh_base_branch=request.gh_base_branch,
        dry_run=request.dry_run,
    )
    return result.to_dict()


# ==================================================================
# Entry point
# ==================================================================

if __name__ == "__main__":
    import uvicorn
    print("\n🚀 Cryptiq FastAPI Backend")
    print("API Docs  → http://127.0.0.1:8000/docs")
    print("Health    → http://127.0.0.1:8000/health")
    print("Frontend  → http://localhost:3000\n")
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True, log_level="info")