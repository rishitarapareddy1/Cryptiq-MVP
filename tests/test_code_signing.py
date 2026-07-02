"""
tests/test_code_signing.py
-----------------------------
Tests for code_signing/: types, discovery, keystore, signer, cbom, database, api.

Mirrors the structure of test_ssh_scanner.py — class-per-module, unit tests
for pure logic, a thin integration class at the bottom for the FastAPI router.
"""

import base64
import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from code_signing.types import (
    SignerKind, KeyAlgorithm, DiscoveredFile, SigningKeyInfo, FileSignature,
    SigningManifest, SIGNABLE_EXTENSIONS, DEFAULT_EXCLUDE_DIRS,
)
from code_signing.discovery import discover_signable_files, summarize_discovery
from code_signing import keystore, signer
from code_signing.cbom import generate_signing_cbom


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def isolated_key_dir(monkeypatch, tmp_path):
    """
    Point the keystore at a throwaway directory for every test.

    Also strips ENCRYPTION_KEY so tests get deterministic behavior --
    the shared conftest.py sets ENCRYPTION_KEY via os.environ.setdefault()
    at *session* import time (for the AWS-credential-encryption tests),
    which persists even when this file is run on its own. Individual tests
    that want to exercise the encrypted-at-rest path (see
    test_encryption_key_wraps_private_key_at_rest) set it back explicitly.
    """
    key_dir = tmp_path / "codesign_keys"
    monkeypatch.setattr(keystore, "KEY_DIR", key_dir)
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
    return key_dir


@pytest.fixture
def sample_tree(tmp_path):
    """A small realistic directory tree with signable and non-signable files."""
    root = tmp_path / "release"
    (root / "sub").mkdir(parents=True)
    (root / "node_modules" / "pkg").mkdir(parents=True)  # should be excluded

    (root / "app.py").write_text("print('hello')\n")
    (root / "sub" / "run.sh").write_text("#!/bin/sh\necho hi\n")
    (root / "readme.md").write_text("not signable by default\n")  # no .md in map
    (root / "node_modules" / "pkg" / "index.js").write_text("module.exports = {}\n")
    return root


# ---------------------------------------------------------------------------
# types.py
# ---------------------------------------------------------------------------

class TestTypes:
    def test_signable_extensions_cover_major_platforms(self):
        assert SIGNABLE_EXTENSIONS[".exe"] == SignerKind.AUTHENTICODE
        assert SIGNABLE_EXTENSIONS[".dll"] == SignerKind.AUTHENTICODE
        assert SIGNABLE_EXTENSIONS[".app"] == SignerKind.MACOS_CODESIGN
        assert SIGNABLE_EXTENSIONS[".dylib"] == SignerKind.MACOS_CODESIGN
        assert SIGNABLE_EXTENSIONS[".deb"] == SignerKind.GPG
        assert SIGNABLE_EXTENSIONS[".rpm"] == SignerKind.GPG
        assert SIGNABLE_EXTENSIONS[".jar"] == SignerKind.JARSIGNER
        assert SIGNABLE_EXTENSIONS[".py"] == SignerKind.GENERIC
        assert SIGNABLE_EXTENSIONS[".sh"] == SignerKind.GENERIC

    def test_default_exclude_dirs_covers_vendor_noise(self):
        for d in ("node_modules", ".git", "__pycache__", "venv", ".venv"):
            assert d in DEFAULT_EXCLUDE_DIRS

    def test_discovered_file_to_dict_roundtrip(self):
        f = DiscoveredFile(path="/x/y.py", size_bytes=10, sha256="ab" * 32,
                            extension=".py", recommended_signer=SignerKind.GENERIC, mtime="now")
        d = f.to_dict()
        assert d["recommended_signer"] == "generic"
        assert d["sha256"] == "ab" * 32

    def test_signing_manifest_to_dict_counts_successes(self):
        entries = [
            FileSignature(path="a", sha256="x", signer_kind=SignerKind.GENERIC, algorithm="ed25519",
                          key_id="k1", signature_b64="sig", native_tool_used=None, signed_at="t", success=True),
            FileSignature(path="b", sha256="y", signer_kind=SignerKind.GENERIC, algorithm="ed25519",
                          key_id="k1", signature_b64=None, native_tool_used=None, signed_at="t",
                          success=False, error="boom"),
        ]
        manifest = SigningManifest(manifest_id="m1", root_path="/x", key_id="k1",
                                    created_at="t", entries=entries)
        d = manifest.to_dict()
        assert d["file_count"] == 2
        assert d["success_count"] == 1


# ---------------------------------------------------------------------------
# discovery.py
# ---------------------------------------------------------------------------

class TestDiscovery:
    def test_discovers_only_known_extensions_by_default(self, sample_tree):
        files = discover_signable_files(str(sample_tree))
        paths = {Path(f.path).name for f in files}
        assert "app.py" in paths
        assert "run.sh" in paths
        assert "readme.md" not in paths  # .md not in the signable map

    def test_excludes_node_modules(self, sample_tree):
        files = discover_signable_files(str(sample_tree))
        # Check path *components*, not a raw substring — pytest's own tmp_path
        # directory is named after the test function and can itself contain
        # "node_modules"-like substrings, so a naive `in` check is unreliable.
        assert not any("node_modules" in Path(f.path).relative_to(sample_tree).parts for f in files)

    def test_sign_everything_includes_unmapped_extensions(self, sample_tree):
        files = discover_signable_files(str(sample_tree), sign_everything=True)
        names = {Path(f.path).name for f in files}
        assert "readme.md" in names
        md_file = next(f for f in files if Path(f.path).name == "readme.md")
        assert md_file.recommended_signer == SignerKind.GENERIC

    def test_extensions_filter_restricts_results(self, sample_tree):
        files = discover_signable_files(str(sample_tree), extensions=[".py"])
        assert all(f.extension == ".py" for f in files)
        assert len(files) == 1

    def test_hashes_are_deterministic_sha256(self, sample_tree):
        files1 = discover_signable_files(str(sample_tree))
        files2 = discover_signable_files(str(sample_tree))
        by_path1 = {f.path: f.sha256 for f in files1}
        by_path2 = {f.path: f.sha256 for f in files2}
        assert by_path1 == by_path2
        assert all(len(h) == 64 for h in by_path1.values())

    def test_nonexistent_root_raises(self):
        with pytest.raises(FileNotFoundError):
            discover_signable_files("/definitely/not/a/real/path/xyz")

    def test_file_instead_of_dir_raises(self, tmp_path):
        f = tmp_path / "file.txt"
        f.write_text("x")
        with pytest.raises(NotADirectoryError):
            discover_signable_files(str(f))

    def test_max_files_cap_respected(self, tmp_path):
        for i in range(10):
            (tmp_path / f"f{i}.py").write_text("x")
        files = discover_signable_files(str(tmp_path), max_files=3)
        assert len(files) == 3

    def test_summarize_discovery_groups_by_signer(self, sample_tree):
        files = discover_signable_files(str(sample_tree))
        summary = summarize_discovery(files)
        assert summary["total_files"] == len(files)
        assert "generic" in summary["by_recommended_signer"]

    def test_our_own_sig_sidecars_never_rediscovered(self, sample_tree):
        sidecar = sample_tree / "app.py.cryptiq.sig.json"
        sidecar.write_text("{}")
        files = discover_signable_files(str(sample_tree), sign_everything=True)
        assert not any(f.path.endswith(".cryptiq.sig.json") for f in files)


# ---------------------------------------------------------------------------
# keystore.py
# ---------------------------------------------------------------------------

class TestKeystore:
    def test_generate_ed25519_key(self, isolated_key_dir):
        info = keystore.generate_key(KeyAlgorithm.ED25519)
        assert info.algorithm == KeyAlgorithm.ED25519
        assert "BEGIN PUBLIC KEY" in info.public_key_pem
        assert len(info.fingerprint_sha256) == 64

    def test_generate_rsa_key(self, isolated_key_dir):
        info = keystore.generate_key(KeyAlgorithm.RSA_PSS_3072)
        assert info.algorithm == KeyAlgorithm.RSA_PSS_3072

    def test_private_key_never_returned(self, isolated_key_dir):
        info = keystore.generate_key(KeyAlgorithm.ED25519)
        assert "PRIVATE" not in json_safe(info.to_dict())

    def test_private_key_file_permissions_locked_down(self, isolated_key_dir):
        info = keystore.generate_key(KeyAlgorithm.ED25519)
        priv_path = isolated_key_dir / f"{info.key_id}.private.pem"
        mode = oct(priv_path.stat().st_mode)[-3:]
        assert mode == "600"

    def test_list_keys_returns_generated_keys(self, isolated_key_dir):
        keystore.generate_key(KeyAlgorithm.ED25519, label="a")
        keystore.generate_key(KeyAlgorithm.ED25519, label="b")
        keys = keystore.list_keys()
        assert len(keys) == 2
        assert {k.label for k in keys} == {"a", "b"}

    def test_default_key_is_most_recent(self, isolated_key_dir):
        keystore.generate_key(KeyAlgorithm.ED25519, label="first")
        second = keystore.generate_key(KeyAlgorithm.ED25519, label="second")
        assert keystore.default_key().key_id == second.key_id

    def test_sign_and_verify_digest_roundtrip(self, isolated_key_dir):
        info = keystore.generate_key(KeyAlgorithm.ED25519)
        digest = b"x" * 32
        sig = keystore.sign_digest(info.key_id, digest)
        assert keystore.verify_digest(info.key_id, digest, sig) is True

    def test_verify_fails_on_tampered_digest(self, isolated_key_dir):
        info = keystore.generate_key(KeyAlgorithm.ED25519)
        sig = keystore.sign_digest(info.key_id, b"x" * 32)
        assert keystore.verify_digest(info.key_id, b"y" * 32, sig) is False

    def test_rsa_pss_sign_and_verify_roundtrip(self, isolated_key_dir):
        info = keystore.generate_key(KeyAlgorithm.RSA_PSS_3072)
        digest = b"z" * 32
        sig = keystore.sign_digest(info.key_id, digest)
        assert keystore.verify_digest(info.key_id, digest, sig) is True

    def test_load_public_info_unknown_key_raises(self, isolated_key_dir):
        with pytest.raises(FileNotFoundError):
            keystore.load_public_info("does-not-exist")

    def test_encryption_key_wraps_private_key_at_rest(self, isolated_key_dir, monkeypatch):
        from cryptography.fernet import Fernet
        monkeypatch.setenv("ENCRYPTION_KEY", Fernet.generate_key().decode())
        info = keystore.generate_key(KeyAlgorithm.ED25519)
        enc_path = isolated_key_dir / f"{info.key_id}.private.pem.enc"
        plain_path = isolated_key_dir / f"{info.key_id}.private.pem"
        assert enc_path.exists()
        assert not plain_path.exists()
        # Should still be usable end-to-end
        sig = keystore.sign_digest(info.key_id, b"a" * 32)
        assert keystore.verify_digest(info.key_id, b"a" * 32, sig) is True


def json_safe(d: dict) -> str:
    return json.dumps(d)


# ---------------------------------------------------------------------------
# signer.py
# ---------------------------------------------------------------------------

class TestSigner:
    def test_sign_file_generic_creates_sidecar(self, isolated_key_dir, sample_tree):
        target = sample_tree / "app.py"
        result = signer.sign_file(str(target), dry_run=False)
        assert result.success is True
        assert result.signer_kind == SignerKind.GENERIC
        sidecar = sample_tree / "app.py.cryptiq.sig.json"
        assert sidecar.exists()
        data = json.loads(sidecar.read_text())
        assert data["key_id"] == result.key_id

    def test_sign_file_dry_run_does_not_write_sidecar(self, isolated_key_dir, sample_tree):
        target = sample_tree / "app.py"
        result = signer.sign_file(str(target), dry_run=True)
        assert result.success is True
        assert "DRY RUN" in (result.error or "")
        assert not (sample_tree / "app.py.cryptiq.sig.json").exists()

    def test_sign_missing_file_fails_gracefully(self, isolated_key_dir):
        result = signer.sign_file("/no/such/file.py", dry_run=False)
        assert result.success is False
        assert "does not exist" in result.error.lower()

    def test_verify_file_true_for_untampered_file(self, isolated_key_dir, sample_tree):
        target = sample_tree / "app.py"
        signer.sign_file(str(target), dry_run=False)
        assert signer.verify_file(str(target), keystore.default_key().key_id) is True

    def test_verify_file_false_after_tamper(self, isolated_key_dir, sample_tree):
        target = sample_tree / "app.py"
        signer.sign_file(str(target), dry_run=False)
        target.write_text("print('tampered')\n")
        assert signer.verify_file(str(target), keystore.default_key().key_id) is False

    def test_verify_missing_sidecar_raises(self, isolated_key_dir, sample_tree):
        target = sample_tree / "run.sh"  # never signed
        with pytest.raises(FileNotFoundError):
            signer.verify_file(str(target.parent / "sub" / "run.sh"), "whatever")

    def test_sign_directory_signs_all_discovered_files(self, isolated_key_dir, sample_tree):
        manifest = signer.sign_directory(str(sample_tree), dry_run=False)
        assert manifest.to_dict()["file_count"] == 2  # app.py + sub/run.sh
        assert manifest.to_dict()["success_count"] == 2
        assert manifest.manifest_signature_b64 is not None

    def test_sign_directory_manifest_signature_verifies(self, isolated_key_dir, sample_tree):
        import hashlib
        manifest = signer.sign_directory(str(sample_tree), dry_run=False)
        digest = hashlib.sha256(
            "".join(sorted(e.sha256 for e in manifest.entries)).encode()
        ).digest()
        sig_bytes = base64.b64decode(manifest.manifest_signature_b64)
        assert keystore.verify_digest(manifest.key_id, digest, sig_bytes) is True

    def test_native_tool_available_returns_none_when_absent(self, monkeypatch):
        monkeypatch.setattr(shutil, "which", lambda name: None)
        assert signer.native_tool_available(SignerKind.AUTHENTICODE) is None

    def test_native_signer_falls_back_to_generic_when_tool_missing(self, isolated_key_dir, sample_tree, monkeypatch):
        monkeypatch.setattr(shutil, "which", lambda name: None)
        target = sample_tree / "app.py"
        exe_stub = sample_tree / "app.exe"
        exe_stub.write_bytes(b"MZ fake pe header")
        result = signer.sign_file(str(exe_stub), prefer_native=True, dry_run=False)
        # native tool absent -> falls through to generic and succeeds
        assert result.success is True
        assert result.signer_kind == SignerKind.GENERIC


# ---------------------------------------------------------------------------
# cbom.py
# ---------------------------------------------------------------------------

class TestCBOM:
    def test_generate_signing_cbom_shape(self, isolated_key_dir, sample_tree):
        manifest = signer.sign_directory(str(sample_tree), dry_run=False)
        cbom = generate_signing_cbom(manifest)
        assert cbom["bomFormat"] == "CycloneDX"
        assert cbom["specVersion"] == "1.6"
        assert len(cbom["components"]) == 2
        props = {p["name"]: p["value"] for p in cbom["components"][0]["properties"]}
        assert "cryptiq:algorithm" in props
        assert "cryptiq:signed" in props


# ---------------------------------------------------------------------------
# database.py
# ---------------------------------------------------------------------------

class TestDatabase:
    @pytest.fixture(autouse=True)
    def _isolated_db(self, monkeypatch, tmp_path):
        from code_signing import database as cs_db
        db_path = tmp_path / "codesign_test.db"
        monkeypatch.setenv("CODESIGN_DATABASE_URL", f"sqlite:///{db_path}")
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        cs_db._engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
        cs_db.SessionLocal = sessionmaker(bind=cs_db._engine)
        cs_db.create_tables()
        yield

    def test_save_and_get_manifest_roundtrip(self, isolated_key_dir, sample_tree):
        from code_signing import database as cs_db
        manifest = signer.sign_directory(str(sample_tree), dry_run=False)
        d = manifest.to_dict()
        cs_db.save_manifest(d, dry_run=False)
        fetched = cs_db.get_manifest(d["manifest_id"])
        assert fetched is not None
        assert fetched["manifest_id"] == d["manifest_id"]

    def test_list_manifests_returns_saved_entries(self, isolated_key_dir, sample_tree):
        from code_signing import database as cs_db
        manifest = signer.sign_directory(str(sample_tree), dry_run=False)
        cs_db.save_manifest(manifest.to_dict(), dry_run=False)
        entries = cs_db.list_manifests()
        assert len(entries) == 1
        assert entries[0]["file_count"] == 2

    def test_get_unknown_manifest_returns_none(self):
        from code_signing import database as cs_db
        assert cs_db.get_manifest("nope") is None


# ---------------------------------------------------------------------------
# api.py — thin FastAPI integration test (standalone app, not the full
# Cryptiq api.py, so this suite has no dependency on tls_scanner/boto3/etc.)
# ---------------------------------------------------------------------------

class TestAPIIntegration:
    @pytest.fixture
    def api_client(self, isolated_key_dir, monkeypatch, tmp_path):
        monkeypatch.setenv("CODESIGN_DATABASE_URL", f"sqlite:///{tmp_path / 'api_test.db'}")
        import importlib
        from code_signing import database as cs_db
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        cs_db._engine = create_engine(f"sqlite:///{tmp_path / 'api_test.db'}", connect_args={"check_same_thread": False})
        cs_db.SessionLocal = sessionmaker(bind=cs_db._engine)
        cs_db.create_tables()

        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from code_signing.api import router
        app = FastAPI()
        app.include_router(router)
        return TestClient(app)

    def test_keygen_endpoint(self, api_client):
        r = api_client.post("/codesign/keys", json={"algorithm": "ed25519"})
        assert r.status_code == 200
        assert "key_id" in r.json()

    def test_keygen_invalid_algorithm_400(self, api_client):
        r = api_client.post("/codesign/keys", json={"algorithm": "not-a-real-algo"})
        assert r.status_code == 400

    def test_discover_endpoint(self, api_client, sample_tree):
        r = api_client.post("/codesign/discover", json={"root_path": str(sample_tree)})
        assert r.status_code == 200
        assert r.json()["summary"]["total_files"] == 2

    def test_discover_missing_path_404(self, api_client):
        r = api_client.post("/codesign/discover", json={"root_path": "/no/such/dir"})
        assert r.status_code == 404

    def test_sign_directory_endpoint_dry_run(self, api_client, sample_tree):
        r = api_client.post("/codesign/sign/directory", json={"root_path": str(sample_tree), "dry_run": True})
        assert r.status_code == 200
        assert r.json()["file_count"] == 2

    def test_sign_directory_then_fetch_manifest(self, api_client, sample_tree):
        r = api_client.post("/codesign/sign/directory", json={"root_path": str(sample_tree), "dry_run": False})
        manifest_id = r.json()["manifest_id"]
        r2 = api_client.get(f"/codesign/manifest/{manifest_id}")
        assert r2.status_code == 200
        assert r2.json()["manifest_id"] == manifest_id

    def test_manifest_cbom_endpoint(self, api_client, sample_tree):
        r = api_client.post("/codesign/sign/directory", json={"root_path": str(sample_tree), "dry_run": False})
        manifest_id = r.json()["manifest_id"]
        r2 = api_client.get(f"/codesign/manifest/{manifest_id}/cbom")
        assert r2.status_code == 200
        assert r2.json()["bomFormat"] == "CycloneDX"

    def test_manifest_not_found_404(self, api_client):
        r = api_client.get("/codesign/manifest/does-not-exist")
        assert r.status_code == 404

    def test_native_tools_endpoint_shape(self, api_client):
        r = api_client.get("/codesign/native-tools")
        assert r.status_code == 200
        body = r.json()
        assert set(body.keys()) == {"authenticode", "macos_codesign", "gpg", "jarsigner"}
        assert all(isinstance(v, bool) for v in body.values())

    def test_verify_endpoint_roundtrip(self, api_client, sample_tree):
        r = api_client.post("/codesign/sign/directory", json={"root_path": str(sample_tree), "dry_run": False})
        key_id = r.json()["key_id"]
        target = str(sample_tree / "app.py")
        r2 = api_client.post("/codesign/verify", json={"path": target, "key_id": key_id})
        assert r2.status_code == 200
        assert r2.json()["valid"] is True