"""
code_signing/api.py
----------------------
FastAPI router for the code-signing product slice. Mounted in root api.py:

    from code_signing.api import router as codesign_router
    app.include_router(codesign_router)

Routes (all under /codesign):
  POST /codesign/keys                 — generate a new signing keypair
  GET  /codesign/keys                 — list known keys (public info only)
  POST /codesign/discover             — recursive directory scan
  POST /codesign/sign/file            — sign a single file
  POST /codesign/sign/directory       — sign every signable file under a directory
  POST /codesign/verify               — verify a generic signature
  GET  /codesign/manifest/{id}        — fetch a stored manifest
  GET  /codesign/manifest/{id}/cbom   — CycloneDX view of a manifest
  GET  /codesign/manifests            — recent signing runs
  GET  /codesign/native-tools         — which native signers are available on this host (legacy)
  GET  /codesign/backends             — registered signing backends (native + generic + proposal)
  POST /codesign/propose/github-actions — generate a CI signing workflow (proposal backend)

Adding a new signing backend — a new CI system, a cloud KMS/HSM signer,
Sigstore/cosign, Azure Trusted Signing, whatever the counterparty's process
requires — does NOT require touching this file. Register a new
code_signing.backends.SigningBackendInfo and it shows up in
GET /codesign/backends automatically. See backends/__init__.py's module
docstring for the pattern (github_actions.py is a worked example of a
"proposal" backend for CI/CD-based signing).
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from code_signing import keystore, signer, database, backends
from code_signing.discovery import discover_signable_files, summarize_discovery
from code_signing.cbom import generate_signing_cbom
from code_signing.types import KeyAlgorithm, SignerKind

router = APIRouter(prefix="/codesign", tags=["code-signing"])

database.create_tables()


# ── Keys ─────────────────────────────────────────────────────────────────

class KeygenRequest(BaseModel):
    algorithm: str = "ed25519"   # ed25519 | rsa-pss-3072 | rsa-pss-4096
    label: str = "default"


@router.post("/keys")
def create_key(request: KeygenRequest):
    try:
        algo = KeyAlgorithm(request.algorithm)
    except ValueError:
        raise HTTPException(400, f"Unknown algorithm '{request.algorithm}'. "
                                  f"Use one of: {[a.value for a in KeyAlgorithm]}")
    info = keystore.generate_key(algorithm=algo, label=request.label)
    return info.to_dict()


@router.get("/keys")
def get_keys():
    return [k.to_dict() for k in keystore.list_keys()]


# ── Discovery ────────────────────────────────────────────────────────────

class DiscoverRequest(BaseModel):
    root_path: str
    extensions: Optional[list[str]] = None
    sign_everything: bool = False
    max_files: int = 5000


@router.post("/discover")
def discover(request: DiscoverRequest):
    try:
        files = discover_signable_files(
            request.root_path, extensions=request.extensions,
            sign_everything=request.sign_everything, max_files=request.max_files,
        )
    except (FileNotFoundError, NotADirectoryError) as e:
        raise HTTPException(404, str(e))
    return {
        "summary": summarize_discovery(files),
        "files": [f.to_dict() for f in files],
    }


# ── Signing ──────────────────────────────────────────────────────────────

class SignFileRequest(BaseModel):
    path: str
    key_id: Optional[str] = None
    prefer_native: bool = True
    native_identity: Optional[str] = None
    dry_run: bool = True


@router.post("/sign/file")
def sign_file(request: SignFileRequest):
    result = signer.sign_file(
        path=request.path, key_id=request.key_id, prefer_native=request.prefer_native,
        native_identity=request.native_identity, dry_run=request.dry_run,
    )
    return result.to_dict()


class SignDirectoryRequest(BaseModel):
    root_path: str
    key_id: Optional[str] = None
    extensions: Optional[list[str]] = None
    prefer_native: bool = True
    native_identity: Optional[str] = None
    dry_run: bool = True
    max_files: int = 5000


@router.post("/sign/directory")
def sign_directory(request: SignDirectoryRequest):
    try:
        manifest = signer.sign_directory(
            root=request.root_path, key_id=request.key_id, extensions=request.extensions,
            prefer_native=request.prefer_native, native_identity=request.native_identity,
            dry_run=request.dry_run, max_files=request.max_files,
        )
    except (FileNotFoundError, NotADirectoryError) as e:
        raise HTTPException(404, str(e))

    manifest_dict = manifest.to_dict()
    database.save_manifest(manifest_dict, dry_run=request.dry_run)
    return manifest_dict


# ── Verify ───────────────────────────────────────────────────────────────

class VerifyRequest(BaseModel):
    path: str
    key_id: str
    signature_b64: Optional[str] = None


@router.post("/verify")
def verify(request: VerifyRequest):
    try:
        valid = signer.verify_file(request.path, request.key_id, request.signature_b64)
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    return {"path": request.path, "valid": valid}


# ── Manifests / history ──────────────────────────────────────────────────

@router.get("/manifests")
def manifests(limit: int = 50):
    return database.list_manifests(limit=limit)


@router.get("/manifest/{manifest_id}")
def get_manifest(manifest_id: str):
    m = database.get_manifest(manifest_id)
    if not m:
        raise HTTPException(404, "Manifest not found")
    return m


@router.get("/manifest/{manifest_id}/cbom")
def get_manifest_cbom(manifest_id: str):
    from code_signing.types import SigningManifest, FileSignature, SignerKind
    m = database.get_manifest(manifest_id)
    if not m:
        raise HTTPException(404, "Manifest not found")
    entries = [
        FileSignature(
            path=e["path"], sha256=e["sha256"], signer_kind=SignerKind(e["signer_kind"]),
            algorithm=e["algorithm"], key_id=e["key_id"], signature_b64=e["signature_b64"],
            native_tool_used=e["native_tool_used"], signed_at=e["signed_at"],
            success=e["success"], error=e.get("error"),
        ) for e in m["entries"]
    ]
    manifest = SigningManifest(
        manifest_id=m["manifest_id"], root_path=m["root_path"], key_id=m["key_id"],
        created_at=m["created_at"], entries=entries,
        manifest_signature_b64=m.get("manifest_signature_b64"),
    )
    from fastapi.responses import JSONResponse
    return JSONResponse(content=generate_signing_cbom(manifest),
                         media_type="application/vnd.cyclonedx+json; version=1.6")


# ── Native tool availability (legacy — prefer /backends below) ───────────

@router.get("/native-tools")
def native_tools():
    """Which OS-native signing tools are installed on the machine running Cryptiq."""
    return {
        kind.value: bool(signer.native_tool_available(kind))
        for kind in (SignerKind.AUTHENTICODE, SignerKind.MACOS_CODESIGN,
                     SignerKind.GPG, SignerKind.JARSIGNER)
    }


# ── Signing backends registry ────────────────────────────────────────────

@router.get("/backends")
def get_backends():
    """List every registered signing backend — native tools, the generic
    Ed25519/RSA-PSS path, and any proposal backends (e.g. github_actions).
    Drives the frontend's backend picker instead of a hardcoded list."""
    return backends.list_backends()


class GithubActionsProposalRequest(BaseModel):
    method: str = "cosign"            # "cosign" | "gpg"
    glob_pattern: str = "dist/*"
    workflow_filename: str = "sign-release.yml"
    dry_run: bool = True
    output_repo_path: Optional[str] = None  # only used if dry_run=False


@router.post("/propose/github-actions")
def propose_github_actions(request: GithubActionsProposalRequest):
    """Generate a GitHub Actions workflow that signs release artifacts automatically.
    dry_run=true (default) returns the YAML for review without writing anything.
    dry_run=false + output_repo_path writes it to <repo>/.github/workflows/<name>.yml
    directly (no PR opened — see backends/github_actions.py's docstring for how to
    wire this into the existing tls_migration GitHub-PR pipeline instead)."""
    backend = backends.get("github_actions")
    if not backend:
        raise HTTPException(500, "github_actions backend not registered")
    try:
        return backend.run(
            method=request.method, glob_pattern=request.glob_pattern,
            workflow_filename=request.workflow_filename, dry_run=request.dry_run,
            output_repo_path=request.output_repo_path,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))