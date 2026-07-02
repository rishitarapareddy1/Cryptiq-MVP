"""
tests/test_extensibility.py
------------------------------
Tests for the plugin registries added on top of code_signing and
password_hashing — the parts that let a new platform / signing backend
be added by registering something, not by editing core logic.
"""

import pytest

from password_hashing import platforms as pw_platforms
from password_hashing.types import Platform, HashRisk
from password_hashing import scanner as pw_scanner
from password_hashing.hardener import get_hardening_plan

from code_signing import backends as cs_backends


# ---------------------------------------------------------------------------
# password_hashing.platforms — the plugin registry
# ---------------------------------------------------------------------------

class TestPasswordHashingPlatformRegistry:
    def test_all_built_ins_registered(self):
        ids = {p["id"] for p in pw_platforms.list_platforms()}
        assert ids == {"linux", "windows", "network_cisco_ios", "network_panos", "generic"}

    def test_each_platform_has_required_fields(self):
        for p in pw_platforms.list_platforms():
            assert p["label"]
            assert p["description"]
            assert "placeholder" in p
            assert isinstance(p["supports_file_scan"], bool)

    def test_scan_via_registry_matches_direct_call(self):
        text = "root:$6$s$" + "a" * 86 + ":1:::::"
        via_registry = pw_platforms.scan("linux", text)
        direct = pw_scanner.scan_shadow_text(text)
        assert via_registry.total_findings == direct.total_findings == 1

    def test_scan_unknown_platform_raises_keyerror(self):
        with pytest.raises(KeyError):
            pw_platforms.scan("does_not_exist", "irrelevant")

    def test_harden_via_registry_matches_direct_call(self):
        plan = pw_platforms.harden("linux")
        assert plan.platform == Platform.LINUX
        assert len(plan.commands) > 0

    def test_registering_a_new_platform_requires_no_core_changes(self):
        """The whole point of the registry: adding a platform is exactly this
        much code, in a test, with zero edits to scanner.py/api.py/hardener.py."""
        from password_hashing.types import ScanSummary
        from password_hashing.hardener import HardeningPlan

        def toy_scan(text: str) -> ScanSummary:
            return ScanSummary(platform=Platform.GENERIC, source="toy",
                                total_findings=1 if text else 0, by_risk={}, findings=[])

        def toy_harden() -> HardeningPlan:
            return HardeningPlan(platform=Platform.GENERIC, summary="toy", commands=["noop"])

        pw_platforms.register(pw_platforms.PlatformPlugin(
            id="toy_system", label="Toy System", description="test-only",
            placeholder="n/a", scan_text=toy_scan, harden=toy_harden,
        ))
        try:
            assert "toy_system" in {p["id"] for p in pw_platforms.list_platforms()}
            result = pw_platforms.scan("toy_system", "anything")
            assert result.total_findings == 1
        finally:
            del pw_platforms._REGISTRY["toy_system"]  # clean up after ourselves

    def test_re_registering_existing_id_overrides_it(self):
        """A deployment can swap in a custom parser for a built-in platform id
        without forking platforms.py — re-registration is intentional."""
        original = pw_platforms.get("generic")
        try:
            from password_hashing.types import ScanSummary
            pw_platforms.register(pw_platforms.PlatformPlugin(
                id="generic", label="Custom generic", description="overridden",
                placeholder="n/a",
                scan_text=lambda t: ScanSummary(platform=Platform.GENERIC, source="x",
                                                 total_findings=999, by_risk={}, findings=[]),
                harden=original.harden,
            ))
            assert pw_platforms.scan("generic", "x").total_findings == 999
        finally:
            pw_platforms.register(original)  # restore


# ---------------------------------------------------------------------------
# password_hashing PAN-OS plugin — worked example of "new platform"
# ---------------------------------------------------------------------------

class TestPanOSPlugin:
    SET_FORMAT = (
        "set mgt-config users admin phash $6$rounds=656000$saltsalt$" + "h" * 86 + "\n"
        "set mgt-config users legacyadmin phash $1$oldsalt$" + "h" * 22 + "\n"
    )

    XML_FORMAT = (
        '<entry name="admin"><phash>$6$xmlsalt$' + "h" * 86 + '</phash></entry>'
    )

    def test_set_format_finds_both_accounts(self):
        summary = pw_scanner.scan_panos_config_text(self.SET_FORMAT)
        assert summary.total_findings == 2
        assert summary.platform == Platform.NETWORK_PANOS

    def test_reuses_crypt_classification_sha512_vs_md5(self):
        summary = pw_scanner.scan_panos_config_text(self.SET_FORMAT)
        admin = next(f for f in summary.findings if f.identifier == "admin")
        legacy = next(f for f in summary.findings if f.identifier == "legacyadmin")
        assert admin.algorithm == "sha512crypt"
        assert admin.risk == HashRisk.MEDIUM
        assert legacy.algorithm == "md5crypt"
        assert legacy.risk == HashRisk.HIGH

    def test_xml_format_also_parsed(self):
        summary = pw_scanner.scan_panos_config_text(self.XML_FORMAT)
        assert summary.total_findings == 1
        assert summary.findings[0].identifier == "admin"

    def test_non_matching_lines_ignored(self):
        text = "set deviceconfig system hostname fw01\nset network interface ethernet1/1 ip 10.0.0.1/24"
        summary = pw_scanner.scan_panos_config_text(text)
        assert summary.total_findings == 0

    def test_panos_hardening_plan_registered(self):
        plan = get_hardening_plan(Platform.NETWORK_PANOS)
        assert plan.commands
        assert "password-complexity" in " ".join(plan.commands)

    def test_panos_reachable_through_registry(self):
        summary = pw_platforms.scan("network_panos", self.SET_FORMAT)
        assert summary.total_findings == 2


# ---------------------------------------------------------------------------
# code_signing.backends — the signing-backend registry
# ---------------------------------------------------------------------------

class TestSigningBackendRegistry:
    def test_all_built_ins_registered(self):
        ids = {b["id"] for b in cs_backends.list_backends()}
        assert ids == {"authenticode", "macos_codesign", "gpg", "jarsigner", "generic", "github_actions"}

    def test_native_backends_marked_direct_github_actions_marked_proposal(self):
        by_id = {b["id"]: b for b in cs_backends.list_backends()}
        assert by_id["authenticode"]["kind"] == "direct"
        assert by_id["generic"]["kind"] == "direct"
        assert by_id["github_actions"]["kind"] == "proposal"

    def test_availability_is_os_gated_not_just_path(self, monkeypatch):
        """A same-named-but-unrelated binary on the wrong OS must not count as available
        (regression test for the NSS signtool false-positive)."""
        import shutil
        monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/" + name)  # everything "found"
        by_id = {b["id"]: b for b in cs_backends.list_backends()}
        # authenticode requires Windows; macos_codesign requires Darwin.
        # On whatever OS these tests run on (not both), at least one must be False
        # even though `which` claims every binary exists.
        assert by_id["authenticode"]["available"] is False or by_id["macos_codesign"]["available"] is False

    def test_generic_backend_always_available(self):
        by_id = {b["id"]: b for b in cs_backends.list_backends()}
        assert by_id["generic"]["available"] is True

    def test_registering_a_new_backend_requires_no_core_changes(self):
        cs_backends.register(cs_backends.SigningBackendInfo(
            id="toy_backend", label="Toy", kind="direct", description="test-only",
            available=lambda: True, run=lambda path, **kw: {"ok": True, "path": path},
        ))
        try:
            assert "toy_backend" in {b["id"] for b in cs_backends.list_backends()}
            backend = cs_backends.get("toy_backend")
            assert backend.run("/some/path")["ok"] is True
        finally:
            del cs_backends._REGISTRY["toy_backend"]


class TestGithubActionsProposalBackend:
    def test_cosign_workflow_contains_expected_steps(self):
        backend = cs_backends.get("github_actions")
        result = backend.run(method="cosign", dry_run=True)
        assert "cosign sign-blob" in result["content"]
        assert result["path"] == ".github/workflows/sign-release.yml"
        assert result["applied"] is False

    def test_gpg_workflow_contains_expected_steps(self):
        backend = cs_backends.get("github_actions")
        result = backend.run(method="gpg", dry_run=True)
        assert "gpg --batch" in result["content"]

    def test_unknown_method_raises(self):
        backend = cs_backends.get("github_actions")
        with pytest.raises(ValueError):
            backend.run(method="not-a-real-method", dry_run=True)

    def test_custom_glob_pattern_interpolated(self):
        backend = cs_backends.get("github_actions")
        result = backend.run(method="cosign", glob_pattern="build/output/*.whl", dry_run=True)
        assert "build/output/*.whl" in result["content"]

    def test_apply_writes_file_to_disk(self, tmp_path):
        backend = cs_backends.get("github_actions")
        result = backend.run(method="cosign", dry_run=False, output_repo_path=str(tmp_path))
        assert result["applied"] is True
        written = tmp_path / ".github" / "workflows" / "sign-release.yml"
        assert written.exists()
        assert "cosign sign-blob" in written.read_text()

    def test_dry_run_does_not_write_file(self, tmp_path):
        backend = cs_backends.get("github_actions")
        backend.run(method="cosign", dry_run=True, output_repo_path=str(tmp_path))
        assert not (tmp_path / ".github").exists()


# ---------------------------------------------------------------------------
# API integration for both registries
# ---------------------------------------------------------------------------

class TestExtensibilityAPIIntegration:
    @pytest.fixture
    def pwhash_client(self, monkeypatch, tmp_path):
        monkeypatch.setenv("PWHASH_DATABASE_URL", f"sqlite:///{tmp_path / 'ext_api.db'}")
        from password_hashing import database as pw_db
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        pw_db._engine = create_engine(f"sqlite:///{tmp_path / 'ext_api.db'}", connect_args={"check_same_thread": False})
        pw_db.SessionLocal = sessionmaker(bind=pw_db._engine)
        pw_db.create_tables()

        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from password_hashing.api import router
        app = FastAPI()
        app.include_router(router)
        return TestClient(app)

    def test_platforms_endpoint_lists_panos(self, pwhash_client):
        r = pwhash_client.get("/pwhash/platforms")
        assert r.status_code == 200
        ids = {p["id"] for p in r.json()}
        assert "network_panos" in ids

    def test_generic_scan_endpoint_reaches_panos_plugin(self, pwhash_client):
        r = pwhash_client.post("/pwhash/scan/network_panos", json={
            "text": "set mgt-config users admin phash $6$s$" + "h" * 86
        })
        assert r.status_code == 200
        assert r.json()["total_findings"] == 1

    def test_generic_scan_endpoint_unknown_platform_404(self, pwhash_client):
        r = pwhash_client.post("/pwhash/scan/not_a_platform", json={"text": "x"})
        assert r.status_code == 404

    def test_legacy_shadow_route_still_works_alongside_generic_route(self, pwhash_client):
        """Regression test for the route-ordering bug: /scan/shadow must not be
        shadowed by the catch-all /scan/{platform_id} route."""
        r = pwhash_client.post("/pwhash/scan/shadow", json={"text": "root:$6$s$" + "a" * 86 + ":1:::::"})
        assert r.status_code == 200
        assert r.json()["total_findings"] == 1

    def test_legacy_windows_dump_route_still_works(self, pwhash_client):
        r = pwhash_client.post("/pwhash/scan/windows-dump", json={
            "text": "bob:1001:01fc5a6be7bc6929aad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::"
        })
        assert r.status_code == 200
        assert r.json()["total_findings"] == 2

    @pytest.fixture
    def codesign_client(self, monkeypatch, tmp_path):
        monkeypatch.setattr(__import__("code_signing.keystore", fromlist=["KEY_DIR"]),
                             "KEY_DIR", tmp_path / "keys")
        monkeypatch.setenv("CODESIGN_DATABASE_URL", f"sqlite:///{tmp_path / 'ext_cs_api.db'}")
        from code_signing import database as cs_db
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        cs_db._engine = create_engine(f"sqlite:///{tmp_path / 'ext_cs_api.db'}", connect_args={"check_same_thread": False})
        cs_db.SessionLocal = sessionmaker(bind=cs_db._engine)
        cs_db.create_tables()

        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from code_signing.api import router
        app = FastAPI()
        app.include_router(router)
        return TestClient(app)

    def test_backends_endpoint(self, codesign_client):
        r = codesign_client.get("/codesign/backends")
        assert r.status_code == 200
        ids = {b["id"] for b in r.json()}
        assert "github_actions" in ids
        assert "generic" in ids

    def test_propose_github_actions_endpoint(self, codesign_client):
        r = codesign_client.post("/codesign/propose/github-actions", json={"method": "cosign"})
        assert r.status_code == 200
        assert "cosign sign-blob" in r.json()["content"]

    def test_propose_github_actions_invalid_method_400(self, codesign_client):
        r = codesign_client.post("/codesign/propose/github-actions", json={"method": "bogus"})
        assert r.status_code == 400