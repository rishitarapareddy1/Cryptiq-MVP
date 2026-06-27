"""
ssh_migration/api.py
---------------------
FastAPI endpoints for the SSH migration module.

Mounts into the root api.py under /migrate/ssh/...

  GET  /migrate/ssh/algorithms              — full algorithm registry
  GET  /migrate/ssh/algorithms/recommended  — recommended choices only
  POST /migrate/ssh/plan                    — generate migration plan for a host
  POST /migrate/ssh/plan/fleet              — generate plans for multiple hosts
  POST /migrate/ssh/keygen                  — generate key pair(s) locally
  POST /migrate/ssh/analyse                 — analyse a scan result
  POST /migrate/ssh/patch                   — generate sshd_config patch
  POST /migrate/ssh/execute                 — execute an action (dry_run by default)
  GET  /migrate/ssh/tools                   — check available tools (ssh-keygen, openssl)
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ssh_migration.algorithms import algorithms_as_dict, get_recommended, check_compatibility
from ssh_migration.keygen import generate_host_key, generate_key_pair_set, check_tools
from ssh_migration.config_hardener import (
    analyse_from_scan, generate_patch,
    analysis_summary, patch_summary,
)
from ssh_migration.migration_plan import build_migration_plan, build_fleet_migration_plan
from ssh_migration.executor import MigrationExecutor, LocalMigrationExecutor, SSHConnection

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/migrate/ssh", tags=["migration"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class PlanRequest(BaseModel):
    scan_result: dict = Field(..., description="Full scan result from /ssh/scan")
    target_algorithms: Optional[dict] = Field(
        None,
        description="Optional algorithm overrides: {host_key: [...], kex: [...], ciphers: [...], macs: [...]}"
    )
    conservative: bool = Field(True, description="Keep existing safe algorithms (don't replace everything)")


class FleetPlanRequest(BaseModel):
    scan_results: list[dict] = Field(..., description="List of scan results from /ssh/scan/bulk")


class KeyGenRequest(BaseModel):
    algorithms: list[str] = Field(
        default=["ed25519"],
        description="List of algorithm IDs to generate. e.g. ['ed25519', 'rsa']"
    )
    comment: str = Field(default="cryptiq-migration", description="Key comment")
    key_size: Optional[int] = Field(None, description="Key size in bits (RSA only)")


class AnalyseRequest(BaseModel):
    scan_result: dict = Field(..., description="Full scan result from /ssh/scan")


class PatchRequest(BaseModel):
    scan_result: dict
    target_kex: Optional[list[str]] = None
    target_ciphers: Optional[list[str]] = None
    target_macs: Optional[list[str]] = None
    add_host_key_types: Optional[list[str]] = None
    conservative: bool = True


class ExecuteRequest(BaseModel):
    action: dict = Field(..., description="MigrationAction dict from a plan")
    connection: Optional[dict] = Field(
        None,
        description="SSH connection details: {host, port, username, key_path, password}. Omit for localhost."
    )
    dry_run: bool = Field(True, description="Set to false to actually run commands")


class CompatibilityRequest(BaseModel):
    algorithm_ids: list[str]
    openssh_version: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/algorithms")
def get_algorithms():
    """Full algorithm registry — all options for host keys, KEX, ciphers, MACs."""
    return algorithms_as_dict()


@router.get("/algorithms/recommended")
def get_recommended_algorithms():
    """Recommended algorithms only — what Cryptiq suggests for new deployments."""
    return {
        "host_key": [a.__dict__ for a in get_recommended("host_key")],
        "kex": [a.__dict__ for a in get_recommended("kex")],
        "cipher": [a.__dict__ for a in get_recommended("cipher")],
        "mac": [a.__dict__ for a in get_recommended("mac")],
    }


@router.post("/analyse")
def analyse_scan(request: AnalyseRequest):
    """
    Analyse a scan result and identify weak algorithms, missing host keys, etc.
    First step before generating a migration plan.
    """
    try:
        analysis = analyse_from_scan(request.scan_result)
        return analysis_summary(analysis)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/patch")
def generate_config_patch(request: PatchRequest):
    """
    Generate a hardened sshd_config patch for a scanned host.
    Returns the config snippet + shell commands to apply it.
    """
    try:
        analysis = analyse_from_scan(request.scan_result)
        patch = generate_patch(
            analysis,
            target_kex=request.target_kex,
            target_ciphers=request.target_ciphers,
            target_macs=request.target_macs,
            add_host_key_types=request.add_host_key_types,
            conservative=request.conservative,
        )
        return patch_summary(patch)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/plan")
def create_migration_plan(request: PlanRequest):
    """
    Generate a full migration plan for a scanned SSH host.

    Returns a phased action plan with:
      - Phase 1: Immediate config hardening (no key gen needed)
      - Phase 2: Host key migration (Ed25519 generation)
      - Phase 3: Full PQC migration (pending OpenSSH 10.x)
    """
    try:
        plan = build_migration_plan(
            request.scan_result,
            target_algorithms=request.target_algorithms,
            conservative=request.conservative,
        )
        return plan.to_dict()
    except Exception as e:
        logger.exception("Plan generation failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/plan/fleet")
def create_fleet_migration_plan(request: FleetPlanRequest):
    """
    Generate migration plans for multiple hosts at once.
    Returns a fleet summary with ordered migration priorities.
    """
    if not request.scan_results:
        raise HTTPException(status_code=400, detail="No scan results provided")
    try:
        return build_fleet_migration_plan(request.scan_results)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/keygen")
def generate_keys(request: KeyGenRequest):
    """
    Generate SSH key pairs locally on the Cryptiq server.
    Returns the public keys and fingerprints.
    Private keys are NOT returned in the response for security —
    they are stored temporarily and paths are provided.

    Use these keys as inputs to the execute endpoint.
    """
    try:
        results = generate_key_pair_set(
            host_key_algorithms=request.algorithms,
            comment=request.comment,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    output = {}
    for algo, result in results.items():
        if result.success and result.key_pair:
            output[algo] = {
                "success": True,
                "algorithm": algo,
                "fingerprint": result.key_pair.fingerprint,
                "public_key": result.key_pair.public_key,
                "public_key_path": result.key_pair.public_key_path,
                # private key path provided but not the key content itself
                "private_key_path": result.key_pair.private_key_path,
                "comment": result.key_pair.comment,
            }
        else:
            output[algo] = {
                "success": False,
                "algorithm": algo,
                "error": result.error,
            }

    return output


@router.post("/execute")
def execute_action(request: ExecuteRequest):
    """
    Execute a single migration action.

    IMPORTANT: dry_run defaults to True. You must explicitly set dry_run=false
    to make real changes. Always test with dry_run=true first.

    For remote execution, provide connection details.
    For localhost testing, omit connection.
    """
    if not request.dry_run:
        logger.warning(
            "LIVE execution requested for action type: %s on host: %s",
            request.action.get("action_type"), request.action.get("host")
        )

    # Build a minimal action object from the dict
    class _Action:
        pass

    action = _Action()
    for k, v in request.action.items():
        setattr(action, k, v)

    # Ensure required fields exist
    if not hasattr(action, "id"):
        import uuid
        action.id = str(uuid.uuid4())
    if not hasattr(action, "commands"):
        action.commands = []
    if not hasattr(action, "rollback_commands"):
        action.rollback_commands = []
    if not hasattr(action, "params"):
        action.params = {}

    try:
        if request.connection:
            conn_data = request.connection
            conn = SSHConnection(
                host=conn_data.get("host", action.host),
                port=conn_data.get("port", 22),
                username=conn_data.get("username", "root"),
                key_path=conn_data.get("key_path"),
                password=conn_data.get("password"),
            )
            executor = MigrationExecutor(conn)
        else:
            executor = LocalMigrationExecutor()

        result = executor.execute_action(action, dry_run=request.dry_run)
        return {
            "action_id": result.action_id,
            "action_type": result.action_type,
            "host": result.host,
            "success": result.success,
            "dry_run": result.dry_run,
            "error": result.error,
            "commands_run": result.commands_run,
            "outputs": result.outputs,
            "started_at": result.started_at,
            "completed_at": result.completed_at,
            "duration_seconds": result.duration_seconds,
        }
    except Exception as e:
        logger.exception("Execution failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/compatibility")
def check_algo_compatibility(request: CompatibilityRequest):
    """
    Check whether chosen algorithms are compatible with a given OpenSSH version.
    """
    issues = check_compatibility(request.algorithm_ids, request.openssh_version)
    return {
        "openssh_version": request.openssh_version,
        "algorithm_ids": request.algorithm_ids,
        "compatible": len(issues) == 0,
        "issues": issues,
    }


@router.get("/tools")
def get_available_tools():
    """Check which key generation tools are available on the Cryptiq server."""
    return check_tools()