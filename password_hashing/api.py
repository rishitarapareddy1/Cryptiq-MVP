"""
password_hashing/api.py
--------------------------
FastAPI router for the password-hashing audit/hardening product slice.
Mounted in root api.py:

    from password_hashing.api import router as pwhash_router
    app.include_router(pwhash_router)

Routes (all under /pwhash):
  GET  /pwhash/platform                 — detect the local OS Cryptiq is running on
  GET  /pwhash/platforms                — list registered platform plugins (drives the UI)
  POST /pwhash/scan/{platform_id}       — scan text against any registered platform plugin
  POST /pwhash/scan/shadow              — alias for /pwhash/scan/linux (also accepts file_path)
  POST /pwhash/scan/windows-dump        — alias for /pwhash/scan/windows
  POST /pwhash/scan/cisco-config        — alias for /pwhash/scan/network_cisco_ios
  POST /pwhash/scan/generic             — alias for /pwhash/scan/generic
  POST /pwhash/classify                 — classify a single hash value
  GET  /pwhash/harden/{platform}        — hardening command plan for a platform
  GET  /pwhash/scans                    — scan history
  GET  /pwhash/scans/{id}               — one stored scan, full findings
  GET  /pwhash/scans/{id}/cbom          — CycloneDX view of a stored scan

Adding support for a new system does NOT require touching this file —
register a new password_hashing.platforms.PlatformPlugin and it shows up
in GET /pwhash/platforms and becomes scannable via
POST /pwhash/scan/{your_new_id} automatically. See platforms.py's module
docstring for the pattern (PAN-OS is a worked example).
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from password_hashing import scanner, hardener, database, platforms
from password_hashing.types import Platform, ScanSummary, PasswordHashFinding
from password_hashing.cbom import generate_password_hash_cbom

router = APIRouter(prefix="/pwhash", tags=["password-hashing"])

database.create_tables()


@router.get("/platform")
def get_platform():
    return {"detected_platform": scanner.detect_local_platform().value}


@router.get("/platforms")
def get_platforms():
    """List every registered platform plugin — id, label, description, placeholder text.
    The frontend builds its platform tabs from this instead of a hardcoded list, so a
    newly-registered plugin appears in the UI with no frontend change."""
    return platforms.list_platforms()


def _persist(summary: ScanSummary) -> dict:
    d = summary.to_dict()
    rec = database.save_scan(d)
    d["scan_id"] = rec.id
    return d


# ── Linux /etc/shadow (kept as an explicit route: it's the only platform
#    that supports scanning a server-local file path, not just pasted text) ──

class ShadowScanRequest(BaseModel):
    text: Optional[str] = None       # paste shadow contents directly
    file_path: Optional[str] = None  # or point at a local path (server must have read access)


@router.post("/scan/shadow")
def scan_shadow(request: ShadowScanRequest):
    if not request.text and not request.file_path:
        raise HTTPException(400, "Provide either 'text' or 'file_path'.")
    try:
        if request.text:
            summary = scanner.scan_shadow_text(request.text)
        else:
            summary = scanner.scan_shadow_file(request.file_path)
    except (FileNotFoundError, PermissionError) as e:
        raise HTTPException(400, str(e))
    return _persist(summary)


class PlatformScanRequest(BaseModel):
    text: str


# ── Legacy aliases — kept for backward compatibility with existing callers.
#    New integrations should prefer POST /pwhash/scan/{platform_id}. ──────

@router.post("/scan/windows-dump")
def scan_windows_dump(request: PlatformScanRequest):
    return _persist(platforms.scan("windows", request.text))


@router.post("/scan/cisco-config")
def scan_cisco_config(request: PlatformScanRequest):
    return _persist(platforms.scan("network_cisco_ios", request.text))


@router.post("/scan/generic")
def scan_generic(request: PlatformScanRequest):
    return _persist(platforms.scan("generic", request.text))


# ── Generic, registry-driven scan endpoint. MUST be declared after every
#    literal /scan/<word> route above — FastAPI/Starlette matches routes in
#    registration order, and this catch-all would otherwise intercept
#    requests meant for /scan/shadow, /scan/windows-dump, etc. ─────────────

@router.post("/scan/{platform_id}")
def scan_platform(platform_id: str, request: PlatformScanRequest):
    try:
        summary = platforms.scan(platform_id, request.text)
    except KeyError as e:
        raise HTTPException(404, str(e))
    return _persist(summary)


class ClassifyRequest(BaseModel):
    value: str
    identifier: str = "(value)"


@router.post("/classify")
def classify(request: ClassifyRequest):
    finding = scanner.classify_single_hash(request.value, identifier=request.identifier)
    return finding.to_dict()


# ── Hardening guidance ───────────────────────────────────────────────────

@router.get("/harden/{platform}")
def harden(platform: str):
    try:
        p = Platform(platform)
    except ValueError:
        raise HTTPException(400, f"Unknown platform '{platform}'. Use one of: {[p.value for p in Platform]}")
    return hardener.get_hardening_plan(p).to_dict()


# ── History ──────────────────────────────────────────────────────────────

@router.get("/scans")
def scans(limit: int = 50):
    return database.list_scans(limit=limit)


@router.get("/scans/{scan_id}")
def get_scan(scan_id: int):
    d = database.get_scan(scan_id)
    if not d:
        raise HTTPException(404, "Scan not found")
    return d


@router.get("/scans/{scan_id}/cbom")
def get_scan_cbom(scan_id: int):
    d = database.get_scan(scan_id)
    if not d:
        raise HTTPException(404, "Scan not found")
    findings = [PasswordHashFinding(
        source=f["source"], identifier=f["identifier"], platform=Platform(f["platform"]),
        algorithm=f["algorithm"], risk=f["risk"], reason=f["reason"],
        recommendation=f["recommendation"], raw_prefix=f.get("raw_prefix"),
        line_number=f.get("line_number"),
    ) for f in d["findings"]]
    # risk field on dataclass expects HashRisk enum; coerce strings back
    from password_hashing.types import HashRisk
    for f, raw in zip(findings, d["findings"]):
        f.risk = HashRisk(raw["risk"])
    summary = ScanSummary(platform=Platform(d["platform"]), source=d["source"],
                           total_findings=d["total_findings"], by_risk=d["by_risk"], findings=findings)
    return JSONResponse(content=generate_password_hash_cbom(summary),
                         media_type="application/vnd.cyclonedx+json; version=1.6")