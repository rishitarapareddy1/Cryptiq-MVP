"""
tests/test_password_hashing.py
---------------------------------
Tests for password_hashing/: types, risk, scanner, hardener, cbom, database, api.
"""

import json

import pytest

from password_hashing.types import Platform, HashRisk, PasswordHashFinding, ScanSummary
from password_hashing.risk import classify_crypt_prefix, CISCO_TYPE_INFO, WINDOWS_HASH_INFO
from password_hashing import scanner, hardener
from password_hashing.cbom import generate_password_hash_cbom


# ---------------------------------------------------------------------------
# risk.py
# ---------------------------------------------------------------------------

class TestRiskClassification:
    @pytest.mark.parametrize("hash_value,expected_name,expected_risk", [
        ("$6$abcsalt$" + "x" * 86, "sha512crypt", HashRisk.MEDIUM),
        ("$5$abcsalt$" + "x" * 43, "sha256crypt", HashRisk.MEDIUM),
        ("$1$abcsalt$" + "x" * 22, "md5crypt", HashRisk.HIGH),
        ("$2b$12$" + "x" * 53, "bcrypt", HashRisk.LOW),
        ("$2a$10$" + "x" * 53, "bcrypt", HashRisk.LOW),
        ("$y$j9T$" + "x" * 40, "yescrypt", HashRisk.BEST),
        ("$7$" + "x" * 40, "scrypt", HashRisk.BEST),
        ("$argon2id$v=19$m=65536,t=3,p=4$" + "x" * 40, "argon2id", HashRisk.BEST),
        ("$argon2i$v=19$m=65536,t=3,p=4$" + "x" * 40, "argon2i", HashRisk.BEST),
    ])
    def test_crypt_prefix_classification(self, hash_value, expected_name, expected_risk):
        info = classify_crypt_prefix(hash_value)
        assert info.name == expected_name
        assert info.risk == expected_risk

    def test_classic_des_crypt_13_chars_is_critical(self):
        info = classify_crypt_prefix("abcdefghijklm")  # exactly 13 chars, no $
        assert info.name == "des-crypt"
        assert info.risk == HashRisk.CRITICAL

    def test_unrecognized_value_falls_back_to_unknown(self):
        info = classify_crypt_prefix("totally-not-a-hash-format")
        assert info.name == "unknown"
        assert info.risk == HashRisk.MEDIUM

    def test_cisco_type_table_orders_weak_to_strong(self):
        assert CISCO_TYPE_INFO["0"].risk == HashRisk.CRITICAL
        assert CISCO_TYPE_INFO["7"].risk == HashRisk.CRITICAL
        assert CISCO_TYPE_INFO["5"].risk == HashRisk.MEDIUM
        assert CISCO_TYPE_INFO["8"].risk == HashRisk.LOW
        assert CISCO_TYPE_INFO["9"].risk == HashRisk.BEST

    def test_windows_lm_is_worse_than_ntlm(self):
        assert WINDOWS_HASH_INFO["lm"].risk == HashRisk.CRITICAL
        assert WINDOWS_HASH_INFO["ntlm"].risk == HashRisk.HIGH


# ---------------------------------------------------------------------------
# scanner.py — Linux /etc/shadow
# ---------------------------------------------------------------------------

class TestShadowScanner:
    SHADOW_TEXT = (
        "root:$6$rootsalt$" + "a" * 86 + ":19000:0:99999:7:::\n"
        "alice:$1$weaksalt$" + "b" * 22 + ":19000:0:99999:7:::\n"
        "bob:$y$j9T$bobsalt$" + "c" * 40 + ":19000:0:99999:7:::\n"
        "locked1:!:19000:0:99999:7:::\n"
        "locked2:!!:19000:0:99999:7:::\n"
        "nopass:*:19000:0:99999:7:::\n"
        "des_user:abcdefghijklm:19000:0:99999:7:::\n"
        "# a comment line, should be skipped\n"
    )

    def test_finds_expected_number_of_classifiable_accounts(self):
        summary = scanner.scan_shadow_text(self.SHADOW_TEXT)
        # root, alice, bob, des_user = 4 classifiable; locked/nopass skipped
        assert summary.total_findings == 4

    def test_locked_and_empty_accounts_skipped(self):
        summary = scanner.scan_shadow_text(self.SHADOW_TEXT)
        identifiers = {f.identifier for f in summary.findings}
        assert "locked1" not in identifiers
        assert "locked2" not in identifiers
        assert "nopass" not in identifiers

    def test_root_classified_sha512crypt_medium(self):
        summary = scanner.scan_shadow_text(self.SHADOW_TEXT)
        root = next(f for f in summary.findings if f.identifier == "root")
        assert root.algorithm == "sha512crypt"
        assert root.risk == HashRisk.MEDIUM
        assert root.platform == Platform.LINUX

    def test_alice_classified_md5crypt_high(self):
        summary = scanner.scan_shadow_text(self.SHADOW_TEXT)
        alice = next(f for f in summary.findings if f.identifier == "alice")
        assert alice.algorithm == "md5crypt"
        assert alice.risk == HashRisk.HIGH

    def test_des_user_classified_critical(self):
        summary = scanner.scan_shadow_text(self.SHADOW_TEXT)
        des_user = next(f for f in summary.findings if f.identifier == "des_user")
        assert des_user.risk == HashRisk.CRITICAL

    def test_by_risk_tally_matches_findings(self):
        summary = scanner.scan_shadow_text(self.SHADOW_TEXT)
        total_from_tally = sum(summary.by_risk.values())
        assert total_from_tally == summary.total_findings

    def test_line_numbers_recorded(self):
        summary = scanner.scan_shadow_text(self.SHADOW_TEXT)
        root = next(f for f in summary.findings if f.identifier == "root")
        assert root.line_number == 1

    def test_missing_shadow_file_raises(self):
        with pytest.raises(FileNotFoundError):
            scanner.scan_shadow_file("/definitely/not/etc/shadow")

    def test_scan_shadow_file_reads_real_file(self, tmp_path):
        p = tmp_path / "shadow"
        p.write_text(self.SHADOW_TEXT)
        summary = scanner.scan_shadow_file(str(p))
        assert summary.total_findings == 4
        assert summary.source == str(p)


# ---------------------------------------------------------------------------
# scanner.py — Windows dump
# ---------------------------------------------------------------------------

class TestWindowsDumpScanner:
    EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"
    EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"

    def test_account_with_only_empty_hashes_produces_no_findings(self):
        text = f"Guest:501:{self.EMPTY_LM}:{self.EMPTY_NT}:::"
        summary = scanner.scan_windows_dump_text(text)
        assert summary.total_findings == 0

    def test_real_lm_and_ntlm_both_flagged(self):
        text = "bob:1001:01fc5a6be7bc6929aad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::"
        summary = scanner.scan_windows_dump_text(text)
        algos = {f.algorithm for f in summary.findings}
        assert "LM hash" in algos
        assert "NTLM hash" in algos
        assert summary.total_findings == 2

    def test_lm_risk_is_critical_ntlm_is_high(self):
        text = "bob:1001:01fc5a6be7bc6929aad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::"
        summary = scanner.scan_windows_dump_text(text)
        lm = next(f for f in summary.findings if f.algorithm == "LM hash")
        ntlm = next(f for f in summary.findings if f.algorithm == "NTLM hash")
        assert lm.risk == HashRisk.CRITICAL
        assert ntlm.risk == HashRisk.HIGH

    def test_malformed_lines_ignored(self):
        summary = scanner.scan_windows_dump_text("not:a:valid:line\ngarbage\n")
        assert summary.total_findings == 0


# ---------------------------------------------------------------------------
# scanner.py — Cisco IOS config
# ---------------------------------------------------------------------------

class TestCiscoConfigScanner:
    CONFIG = (
        "username admin secret 9 $9$abc$def\n"
        "username legacy password 7 0822455D0A16\n"
        "enable secret 5 $1$salt$hash\n"
        "enable password 0 supersecret\n"
        "interface GigabitEthernet0/1\n"
        " description uplink\n"
    )

    def test_finds_all_four_credential_lines(self):
        summary = scanner.scan_cisco_config_text(self.CONFIG)
        assert summary.total_findings == 4

    def test_type_9_is_best(self):
        summary = scanner.scan_cisco_config_text(self.CONFIG)
        admin = next(f for f in summary.findings if f.identifier == "admin")
        assert admin.risk == HashRisk.BEST
        assert admin.raw_prefix == "type 9"

    def test_type_7_is_critical(self):
        summary = scanner.scan_cisco_config_text(self.CONFIG)
        legacy = next(f for f in summary.findings if f.identifier == "legacy")
        assert legacy.risk == HashRisk.CRITICAL

    def test_type_0_enable_password_is_critical(self):
        summary = scanner.scan_cisco_config_text(self.CONFIG)
        enable_findings = [f for f in summary.findings if f.algorithm == "cisco-type-0"]
        assert len(enable_findings) == 1
        assert enable_findings[0].risk == HashRisk.CRITICAL

    def test_non_credential_lines_ignored(self):
        summary = scanner.scan_cisco_config_text(self.CONFIG)
        assert not any("interface" in f.identifier for f in summary.findings)


# ---------------------------------------------------------------------------
# scanner.py — generic / classify single value
# ---------------------------------------------------------------------------

class TestGenericClassification:
    def test_classify_bare_md5(self):
        f = scanner.classify_single_hash("5" * 32)
        assert f.algorithm == "raw-md5"
        assert f.risk == HashRisk.HIGH

    def test_classify_bare_sha1(self):
        f = scanner.classify_single_hash("a" * 40)
        assert f.algorithm == "raw-sha1"
        assert f.risk == HashRisk.HIGH

    def test_classify_crypt_style_value(self):
        f = scanner.classify_single_hash("$2b$12$" + "x" * 53)
        assert f.algorithm == "bcrypt"
        assert f.risk == HashRisk.LOW

    def test_classify_unknown_value(self):
        f = scanner.classify_single_hash("clearly-not-a-hash")
        assert f.algorithm == "unknown"

    def test_scan_generic_text_multiple_lines(self):
        text = "5" * 32 + "\n" + "a" * 40 + "\n$2b$12$" + "x" * 53
        summary = scanner.scan_generic_text(text)
        assert summary.total_findings == 3


# ---------------------------------------------------------------------------
# scanner.py — platform detection
# ---------------------------------------------------------------------------

class TestPlatformDetection:
    def test_detect_local_platform_returns_valid_enum_member(self):
        p = scanner.detect_local_platform()
        assert p in (Platform.LINUX, Platform.MACOS, Platform.WINDOWS, Platform.GENERIC)


# ---------------------------------------------------------------------------
# hardener.py
# ---------------------------------------------------------------------------

class TestHardener:
    @pytest.mark.parametrize("platform", [
        Platform.LINUX, Platform.MACOS, Platform.WINDOWS, Platform.NETWORK_CISCO_IOS,
    ])
    def test_every_supported_platform_has_commands(self, platform):
        plan = hardener.get_hardening_plan(platform)
        assert plan.platform == platform
        assert len(plan.commands) > 0
        assert plan.summary

    def test_unsupported_platform_returns_empty_plan_not_error(self):
        plan = hardener.get_hardening_plan(Platform.DATABASE)
        assert plan.commands == []
        assert plan.notes

    def test_linux_plan_mentions_yescrypt(self):
        plan = hardener.linux_plan()
        assert any("yescrypt" in c.lower() or "YESCRYPT" in c for c in plan.commands + [plan.summary])

    def test_windows_plan_mentions_lm_hash(self):
        plan = hardener.windows_plan()
        assert any("lmhash" in c.lower().replace(" ", "") for c in plan.commands)

    def test_cisco_plan_mentions_secret_9(self):
        plan = hardener.cisco_ios_plan()
        assert any("secret 9" in c for c in plan.commands)


# ---------------------------------------------------------------------------
# cbom.py
# ---------------------------------------------------------------------------

class TestCBOM:
    def test_generate_password_hash_cbom_shape(self):
        finding = PasswordHashFinding(
            source="/etc/shadow", identifier="root", platform=Platform.LINUX,
            algorithm="sha512crypt", risk=HashRisk.MEDIUM, reason="r", recommendation="rec",
        )
        summary = ScanSummary(platform=Platform.LINUX, source="/etc/shadow",
                               total_findings=1, by_risk={"medium": 1}, findings=[finding])
        cbom = generate_password_hash_cbom(summary)
        assert cbom["bomFormat"] == "CycloneDX"
        assert cbom["components"][0]["type"] == "data"
        props = {p["name"]: p["value"] for p in cbom["components"][0]["properties"]}
        assert props["cryptiq:algorithm"] == "sha512crypt"


# ---------------------------------------------------------------------------
# database.py
# ---------------------------------------------------------------------------

class TestDatabase:
    @pytest.fixture(autouse=True)
    def _isolated_db(self, monkeypatch, tmp_path):
        from password_hashing import database as pw_db
        db_path = tmp_path / "pwhash_test.db"
        monkeypatch.setenv("PWHASH_DATABASE_URL", f"sqlite:///{db_path}")
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        pw_db._engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
        pw_db.SessionLocal = sessionmaker(bind=pw_db._engine)
        pw_db.create_tables()
        yield

    def test_save_and_list_scan(self):
        from password_hashing import database as pw_db
        summary = scanner.scan_cisco_config_text(TestCiscoConfigScanner.CONFIG)
        pw_db.save_scan(summary.to_dict())
        scans = pw_db.list_scans()
        assert len(scans) == 1
        assert scans[0]["total_findings"] == 4

    def test_get_scan_includes_full_findings(self):
        from password_hashing import database as pw_db
        summary = scanner.scan_cisco_config_text(TestCiscoConfigScanner.CONFIG)
        rec = pw_db.save_scan(summary.to_dict())
        full = pw_db.get_scan(rec.id)
        assert len(full["findings"]) == 4

    def test_get_unknown_scan_returns_none(self):
        from password_hashing import database as pw_db
        assert pw_db.get_scan(999999) is None

    def test_never_stores_raw_hash_material(self):
        """The stored blob should only ever contain short format markers (raw_prefix),
        never a full hash value — spot check with a value that would be unmistakable
        if accidentally persisted whole."""
        from password_hashing import database as pw_db
        distinctive_hash = "$6$distinctivesalt$" + "Q" * 86
        summary = scanner.scan_shadow_text(f"root:{distinctive_hash}:1:::::")
        pw_db.save_scan(summary.to_dict())
        session = pw_db.SessionLocal()
        try:
            raw_row = session.query(pw_db.PasswordHashScanRecord).first()
            assert distinctive_hash not in raw_row.findings_json
        finally:
            session.close()


# ---------------------------------------------------------------------------
# api.py — thin FastAPI integration test (standalone app; no dependency on
# the rest of Cryptiq's api.py / boto3 / paramiko / etc.)
# ---------------------------------------------------------------------------

class TestAPIIntegration:
    @pytest.fixture
    def api_client(self, monkeypatch, tmp_path):
        monkeypatch.setenv("PWHASH_DATABASE_URL", f"sqlite:///{tmp_path / 'api_test.db'}")
        from password_hashing import database as pw_db
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        pw_db._engine = create_engine(f"sqlite:///{tmp_path / 'api_test.db'}", connect_args={"check_same_thread": False})
        pw_db.SessionLocal = sessionmaker(bind=pw_db._engine)
        pw_db.create_tables()

        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from password_hashing.api import router
        app = FastAPI()
        app.include_router(router)
        return TestClient(app)

    def test_platform_endpoint(self, api_client):
        r = api_client.get("/pwhash/platform")
        assert r.status_code == 200
        assert "detected_platform" in r.json()

    def test_scan_shadow_endpoint_with_text(self, api_client):
        r = api_client.post("/pwhash/scan/shadow", json={"text": "root:$6$s$" + "a" * 86 + ":1:::::"})
        assert r.status_code == 200
        assert r.json()["total_findings"] == 1
        assert "scan_id" in r.json()

    def test_scan_shadow_requires_text_or_path(self, api_client):
        r = api_client.post("/pwhash/scan/shadow", json={})
        assert r.status_code == 400

    def test_scan_windows_dump_endpoint(self, api_client):
        r = api_client.post("/pwhash/scan/windows-dump", json={
            "text": "bob:1001:01fc5a6be7bc6929aad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::"
        })
        assert r.status_code == 200
        assert r.json()["total_findings"] == 2

    def test_scan_cisco_config_endpoint(self, api_client):
        r = api_client.post("/pwhash/scan/cisco-config", json={"text": TestCiscoConfigScanner.CONFIG})
        assert r.status_code == 200
        assert r.json()["total_findings"] == 4

    def test_classify_endpoint(self, api_client):
        r = api_client.post("/pwhash/classify", json={"value": "5" * 32})
        assert r.status_code == 200
        assert r.json()["algorithm"] == "raw-md5"

    def test_harden_endpoint_known_platform(self, api_client):
        r = api_client.get("/pwhash/harden/linux")
        assert r.status_code == 200
        assert len(r.json()["commands"]) > 0

    def test_harden_endpoint_unknown_platform_400(self, api_client):
        r = api_client.get("/pwhash/harden/not-a-platform")
        assert r.status_code == 400

    def test_scans_history_endpoint(self, api_client):
        api_client.post("/pwhash/scan/shadow", json={"text": "root:$6$s$" + "a" * 86 + ":1:::::"})
        r = api_client.get("/pwhash/scans")
        assert r.status_code == 200
        assert len(r.json()) == 1

    def test_scan_by_id_and_cbom_endpoints(self, api_client):
        r = api_client.post("/pwhash/scan/shadow", json={"text": "root:$6$s$" + "a" * 86 + ":1:::::"})
        scan_id = r.json()["scan_id"]
        r2 = api_client.get(f"/pwhash/scans/{scan_id}")
        assert r2.status_code == 200
        r3 = api_client.get(f"/pwhash/scans/{scan_id}/cbom")
        assert r3.status_code == 200
        assert r3.json()["bomFormat"] == "CycloneDX"

    def test_scan_not_found_404(self, api_client):
        r = api_client.get("/pwhash/scans/999999")
        assert r.status_code == 404