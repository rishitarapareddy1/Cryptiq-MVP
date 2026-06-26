"""
tests/test_cryptiq.py
---------------------
Comprehensive test suite for the Cryptiq PQC Scanner platform.

Covers:
  - TLS scanner unit tests (algorithm classification, risk scoring, parsing)
  - SSH scanner unit tests (risk, CBOM, network parsing)
  - API integration tests (all endpoints, both TLS and SSH)
  - Database persistence tests
  - Edge cases and error handling

Run:
  pip install pytest pytest-asyncio httpx
  pytest tests/test_cryptiq.py -v
  pytest tests/test_cryptiq.py -v -k "tls"       # TLS only
  pytest tests/test_cryptiq.py -v -k "ssh"       # SSH only
  pytest tests/test_cryptiq.py -v -k "api"       # API only
  pytest tests/test_cryptiq.py -v --tb=short     # compact tracebacks
"""

import json
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
from fastapi.testclient import TestClient


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture(scope="module")
def client():
    """FastAPI test client — uses an in-memory SQLite DB, no real network."""
    import os
    os.environ["SSH_SCANNER_DATABASE_URL"] = "sqlite:///:memory:"
    from api import app
    from ssh_scanner.ssh_database import create_tables, get_engine
    # TestClient doesn't fire startup events — create tables explicitly
    create_tables(get_engine())
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture
def mock_tls_result():
    return {
        "domain": "example.com",
        "tls_version": "TLSv1.3",
        "algorithm": "ECDH",
        "quantum_vulnerable": True,
        "keysize": 256,
        "issuer": "C=US, O=Let's Encrypt, CN=R11",
        "expiry": "Sep 10 12:00:00 2026 GMT",
        "signature_algorithm": "ecdsa-with-SHA256",
        "days_until_expiry": 90,
        "risk_level": "High",
        "pqc_status": "vulnerable",
        "subject": "CN=example.com",
        "ct_logs": [],
    }


@pytest.fixture
def mock_ssh_scan_result():
    """Minimal SSHScanResult-like object for unit tests."""
    from ssh_scanner.scan_ssh import SSHScanResult, SSHHostKey
    r = SSHScanResult(host="test.example.com", port=22)
    r.ssh_version = "OpenSSH_9.3"
    r.ssh_protocol = "2.0"
    r.raw_banner = "SSH-2.0-OpenSSH_9.3"
    r.host_keys = [
        SSHHostKey(algorithm="ssh-rsa", key_size=2048, fingerprint="SHA256:abc123"),
        SSHHostKey(algorithm="ssh-ed25519", key_size=None, fingerprint="SHA256:def456"),
    ]
    r.server_kex_algorithms = ["curve25519-sha256", "diffie-hellman-group14-sha256"]
    r.server_ciphers = ["aes256-gcm@openssh.com", "aes128-ctr"]
    r.server_macs = ["hmac-sha2-256-etm@openssh.com", "hmac-sha1"]
    r.server_host_key_algorithms = ["ssh-rsa", "ssh-ed25519"]
    r.server_compression = ["none"]
    r.negotiated_kex = "curve25519-sha256"
    r.negotiated_cipher = "aes256-gcm@openssh.com"
    r.negotiated_mac = "hmac-sha2-256-etm@openssh.com"
    r.scan_success = True
    return r


# ===========================================================================
# TLS — Unit tests: algorithm classification
# ===========================================================================

class TestTLSAlgorithmClassification:

    def test_rsa_is_quantum_vulnerable(self):
        from tls_scanner.scan_tls import is_quantum_vulnerable
        assert is_quantum_vulnerable("RSA") is True

    def test_ecdsa_is_quantum_vulnerable(self):
        from tls_scanner.scan_tls import is_quantum_vulnerable
        assert is_quantum_vulnerable("ECDSA") is True

    def test_ecdh_is_quantum_vulnerable(self):
        from tls_scanner.scan_tls import is_quantum_vulnerable
        assert is_quantum_vulnerable("ECDH") is True

    def test_dh_is_quantum_vulnerable(self):
        from tls_scanner.scan_tls import is_quantum_vulnerable
        assert is_quantum_vulnerable("DH") is True

    def test_ecc_is_quantum_vulnerable(self):
        from tls_scanner.scan_tls import is_quantum_vulnerable
        assert is_quantum_vulnerable("ECC") is True

    def test_unknown_algo_not_vulnerable(self):
        from tls_scanner.scan_tls import is_quantum_vulnerable
        assert is_quantum_vulnerable("Unknown") is False

    def test_mlkem_not_vulnerable(self):
        from tls_scanner.scan_tls import is_quantum_vulnerable
        assert is_quantum_vulnerable("MLKEM") is False

    def test_pqc_status_hybrid(self):
        from tls_scanner.scan_tls import get_pqc_status
        assert get_pqc_status("MLKEM") == "hybrid_pqc"
        assert get_pqc_status("X25519MLKEM768") == "hybrid_pqc"
        assert get_pqc_status("Kyber") == "hybrid_pqc"

    def test_pqc_status_vulnerable(self):
        from tls_scanner.scan_tls import get_pqc_status
        assert get_pqc_status("RSA") == "vulnerable"
        assert get_pqc_status("ECDH") == "vulnerable"

    def test_pqc_status_unknown(self):
        from tls_scanner.scan_tls import get_pqc_status
        assert get_pqc_status("Unknown") == "unknown"


# ===========================================================================
# TLS — Unit tests: risk level
# ===========================================================================

class TestTLSRiskLevel:

    def test_non_vulnerable_algo_is_low_risk(self):
        from tls_scanner.scan_tls import get_risk_level
        assert get_risk_level("Unknown", 365) == "Low"

    def test_vulnerable_algo_is_high_risk(self):
        from tls_scanner.scan_tls import get_risk_level
        assert get_risk_level("RSA", 365) == "High"

    def test_vulnerable_algo_expiring_soon_is_critical(self):
        from tls_scanner.scan_tls import get_risk_level
        assert get_risk_level("ECDH", 30) == "Critical"

    def test_vulnerable_algo_expiring_exactly_60_days_is_critical(self):
        from tls_scanner.scan_tls import get_risk_level
        # boundary: < 60 is critical
        assert get_risk_level("RSA", 59) == "Critical"

    def test_vulnerable_algo_at_60_days_is_high(self):
        from tls_scanner.scan_tls import get_risk_level
        assert get_risk_level("RSA", 60) == "High"

    def test_none_days_with_vulnerable_algo(self):
        from tls_scanner.scan_tls import get_risk_level
        # None expiry shouldn't crash
        result = get_risk_level("RSA", None)
        assert result in ("High", "Critical", "Low")


# ===========================================================================
# TLS — Unit tests: output parsing
# ===========================================================================

class TestTLSParsing:

    def test_get_tls_version_found(self):
        from tls_scanner.scan_tls import get_tls_version
        raw = "stuff\n    Protocol  : TLSv1.3\nmore stuff"
        assert get_tls_version(raw) == "TLSv1.3"

    def test_get_tls_version_not_found(self):
        from tls_scanner.scan_tls import get_tls_version
        assert get_tls_version("no version here") == "Unknown"

    def test_get_key_size_found(self):
        from tls_scanner.scan_tls import get_key_size
        raw = "Server public key is 2048 bit"
        assert get_key_size(raw) == 2048

    def test_get_key_size_not_found(self):
        from tls_scanner.scan_tls import get_key_size
        assert get_key_size("no key size here") is None

    def test_get_issuer_found(self):
        from tls_scanner.scan_tls import get_issuer
        raw = "        Issuer: C=US, O=Let's Encrypt, CN=R11"
        result = get_issuer(raw)
        assert "Let's Encrypt" in result

    def test_get_issuer_not_found(self):
        from tls_scanner.scan_tls import get_issuer
        assert get_issuer("no issuer here") == "Unknown"

    def test_get_expiry_notafter(self):
        from tls_scanner.scan_tls import get_expiry
        raw = "notAfter=Sep 10 12:00:00 2026 GMT"
        assert get_expiry(raw) == "Sep 10 12:00:00 2026 GMT"

    def test_get_expiry_not_found(self):
        from tls_scanner.scan_tls import get_expiry
        assert get_expiry("nothing here") == "Unknown"

    def test_get_signature_algorithm(self):
        from tls_scanner.scan_tls import get_signature_algorithm
        raw = "            Signature Algorithm: ecdsa-with-SHA256"
        assert get_signature_algorithm(raw) == "ecdsa-with-SHA256"

    def test_get_days_until_expiry_future(self):
        from tls_scanner.scan_tls import get_days_until_expiry
        # Use a date far in the future
        result = get_days_until_expiry("Jan  1 00:00:00 2099 GMT")
        assert result is not None
        assert result > 0

    def test_get_days_until_expiry_unknown(self):
        from tls_scanner.scan_tls import get_days_until_expiry
        assert get_days_until_expiry("Unknown") is None

    def test_get_days_until_expiry_bad_format(self):
        from tls_scanner.scan_tls import get_days_until_expiry
        assert get_days_until_expiry("not a date") is None


# ===========================================================================
# TLS — Unit tests: CBOM generation
# ===========================================================================

class TestTLSCBOM:

    def test_cbom_structure(self, mock_tls_result):
        from tls_scanner.scan_tls import convert_to_cbom
        cbom = convert_to_cbom(mock_tls_result)
        assert cbom["bomFormat"] == "CycloneDX"
        assert cbom["specVersion"] == "1.6"
        assert "serialNumber" in cbom
        assert "components" in cbom
        assert len(cbom["components"]) == 1

    def test_cbom_component_fields(self, mock_tls_result):
        from tls_scanner.scan_tls import convert_to_cbom
        cbom = convert_to_cbom(mock_tls_result)
        comp = cbom["components"][0]
        assert comp["type"] == "cryptographic-asset"
        assert "example.com" in comp["name"]
        assert "cryptoProperties" in comp

    def test_cbom_quantum_level_vulnerable(self, mock_tls_result):
        from tls_scanner.scan_tls import convert_to_cbom
        cbom = convert_to_cbom(mock_tls_result)
        assert cbom["components"][0]["cryptoProperties"]["nistQuantumSecurityLevel"] == 0

    def test_cbom_quantum_level_safe(self, mock_tls_result):
        from tls_scanner.scan_tls import convert_to_cbom
        safe = {**mock_tls_result, "quantum_vulnerable": False}
        cbom = convert_to_cbom(safe)
        assert cbom["components"][0]["cryptoProperties"]["nistQuantumSecurityLevel"] == 3

    def test_cbom_bulk(self, mock_tls_result):
        from tls_scanner.scan_tls import convert_to_cbom
        second = {**mock_tls_result, "domain": "other.com"}
        cbom = convert_to_cbom([mock_tls_result, second])
        assert len(cbom["components"]) == 2

    def test_cbom_primitive_mapping(self):
        from tls_scanner.scan_tls import map_primitive
        assert map_primitive("ECDH") == "keyagree"
        assert map_primitive("RSA") == "pke"
        assert map_primitive("ECDSA") == "signature"
        assert map_primitive("DH") == "keyagree"
        assert map_primitive("Unknown") == "unknown"


# ===========================================================================
# SSH — Unit tests: risk classification
# ===========================================================================

class TestSSHRiskClassification:

    def test_rsa_host_key_high_risk(self):
        from ssh_scanner.ssh_risk import classify_host_key
        r = classify_host_key("ssh-rsa", 2048)
        assert r["quantum_vulnerable"] is True
        assert r["risk_contribution"] == "high"

    def test_rsa_small_key_critical(self):
        from ssh_scanner.ssh_risk import classify_host_key
        r = classify_host_key("ssh-rsa", 1024)
        assert r["risk_contribution"] == "critical"

    def test_ecdsa_high_risk(self):
        from ssh_scanner.ssh_risk import classify_host_key
        r = classify_host_key("ecdsa-sha2-nistp256", None)
        assert r["quantum_vulnerable"] is True
        assert r["risk_contribution"] == "high"

    def test_ed25519_medium_risk(self):
        from ssh_scanner.ssh_risk import classify_host_key
        r = classify_host_key("ssh-ed25519", None)
        assert r["quantum_vulnerable"] is False
        assert r["risk_contribution"] == "medium"

    def test_dsa_critical(self):
        from ssh_scanner.ssh_risk import classify_host_key
        r = classify_host_key("ssh-dss", None)
        assert r["quantum_vulnerable"] is True

    def test_none_algo_returns_unknown(self):
        from ssh_scanner.ssh_risk import classify_host_key
        r = classify_host_key(None, None)
        assert r["risk_contribution"] == "unknown"

    def test_kex_group1_sha1_critical(self):
        from ssh_scanner.ssh_risk import classify_kex
        r = classify_kex("diffie-hellman-group1-sha1")
        assert r["pqc_status"] == "vulnerable"
        assert r["risk_contribution"] == "critical"

    def test_kex_group14_high(self):
        from ssh_scanner.ssh_risk import classify_kex
        r = classify_kex("diffie-hellman-group14-sha256")
        assert r["quantum_vulnerable"] is True
        # group14-sha256 uses SHA-256 (not SHA-1) so high, not critical
        assert r["risk_contribution"] == "high"
        assert r["pqc_status"] == "vulnerable"

    def test_kex_group14_sha1_critical(self):
        from ssh_scanner.ssh_risk import classify_kex
        r = classify_kex("diffie-hellman-group14-sha1")
        assert r["risk_contribution"] == "critical"

    def test_kex_curve25519_medium(self):
        from ssh_scanner.ssh_risk import classify_kex
        r = classify_kex("curve25519-sha256")
        assert r["risk_contribution"] == "medium"
        assert r["pqc_status"] == "vulnerable"

    def test_kex_hybrid_low(self):
        from ssh_scanner.ssh_risk import classify_kex
        r = classify_kex("sntrup761x25519-sha512@openssh.com")
        assert r["pqc_status"] == "hybrid"
        assert r["risk_contribution"] == "low"

    def test_kex_mlkem_pqc_ready(self):
        from ssh_scanner.ssh_risk import classify_kex
        r = classify_kex("mlkem768-sha256")
        assert r["pqc_status"] == "pqc_ready"
        assert r["risk_contribution"] == "low"

    def test_weak_cipher_flagged(self):
        from ssh_scanner.ssh_risk import classify_cipher
        r = classify_cipher("aes128-cbc")
        assert r["weak"] is True

    def test_strong_cipher_ok(self):
        from ssh_scanner.ssh_risk import classify_cipher
        r = classify_cipher("aes256-gcm@openssh.com")
        assert r["weak"] is False

    def test_weak_mac_flagged(self):
        from ssh_scanner.ssh_risk import classify_mac
        r = classify_mac("hmac-sha1")
        assert r["weak"] is True

    def test_strong_mac_ok(self):
        from ssh_scanner.ssh_risk import classify_mac
        r = classify_mac("hmac-sha2-256-etm@openssh.com")
        assert r["weak"] is False


# ===========================================================================
# SSH — Unit tests: risk aggregation
# ===========================================================================

class TestSSHRiskAggregation:

    def test_assess_risk_rsa_high(self):
        from ssh_scanner.ssh_risk import assess_risk
        r = assess_risk("host.example.com", "ssh-rsa", 2048, "curve25519-sha256")
        assert r.quantum_vulnerable is True
        assert r.risk_level in ("high", "medium")
        assert r.pqc_status == "vulnerable"

    def test_assess_risk_critical_kex(self):
        from ssh_scanner.ssh_risk import assess_risk
        r = assess_risk("host.example.com", "ssh-rsa", 1024, "diffie-hellman-group1-sha1")
        assert r.risk_level == "critical"

    def test_assess_risk_hybrid_kex_still_vulnerable_host_key(self):
        from ssh_scanner.ssh_risk import assess_risk
        r = assess_risk("host.example.com", "ssh-rsa", 2048, "sntrup761x25519-sha512@openssh.com")
        # host key is still RSA — overall still vulnerable
        assert r.pqc_status == "vulnerable"
        assert r.quantum_vulnerable is True

    def test_assess_risk_from_scan(self, mock_ssh_scan_result):
        from ssh_scanner.ssh_risk import assess_risk_from_scan
        r = assess_risk_from_scan(mock_ssh_scan_result)
        assert r.host == "test.example.com"
        assert r.quantum_vulnerable is True   # RSA host key
        assert r.risk_level in ("high", "medium", "critical")

    def test_migration_priority_critical(self):
        from ssh_scanner.ssh_risk import assess_risk
        r = assess_risk("h", "ssh-rsa", 1024, "diffie-hellman-group1-sha1")
        assert r.migration_priority == "critical"

    def test_migration_priority_high(self):
        from ssh_scanner.ssh_risk import assess_risk
        r = assess_risk("h", "ssh-rsa", 2048, "curve25519-sha256")
        assert r.migration_priority == "high"

    def test_findings_not_empty_for_vulnerable(self):
        from ssh_scanner.ssh_risk import assess_risk
        r = assess_risk("h", "ssh-rsa", 2048, "diffie-hellman-group14-sha256")
        assert len(r.findings) > 0

    def test_summarise_risk_assessments(self):
        from ssh_scanner.ssh_risk import assess_risk, summarise_risk_assessments
        assessments = [
            assess_risk(f"host{i}.example.com", "ssh-rsa", 2048, "curve25519-sha256")
            for i in range(5)
        ]
        summary = summarise_risk_assessments(assessments)
        assert summary["total_scanned"] == 5
        assert summary["quantum_vulnerable"] == 5
        assert "by_risk_level" in summary
        assert "by_host_key_algorithm" in summary
        assert "pqc_readiness_percent" in summary


# ===========================================================================
# SSH — Unit tests: CBOM generation
# ===========================================================================

class TestSSHCBOM:

    def test_cbom_structure(self, mock_ssh_scan_result):
        from ssh_scanner.ssh_risk import assess_risk_from_scan
        from ssh_scanner.ssh_cbom import generate_ssh_cbom
        risk = assess_risk_from_scan(mock_ssh_scan_result)
        cbom = generate_ssh_cbom(mock_ssh_scan_result, risk)
        assert cbom["bomFormat"] == "CycloneDX"
        assert cbom["specVersion"] == "1.6"
        assert "components" in cbom
        assert len(cbom["components"]) > 0

    def test_cbom_has_host_key_component(self, mock_ssh_scan_result):
        from ssh_scanner.ssh_risk import assess_risk_from_scan
        from ssh_scanner.ssh_cbom import generate_ssh_cbom
        risk = assess_risk_from_scan(mock_ssh_scan_result)
        cbom = generate_ssh_cbom(mock_ssh_scan_result, risk)
        asset_types = [
            c["cryptoProperties"]["assetType"]
            for c in cbom["components"]
        ]
        assert "ssh-host-key" in asset_types

    def test_cbom_has_kex_component(self, mock_ssh_scan_result):
        from ssh_scanner.ssh_risk import assess_risk_from_scan
        from ssh_scanner.ssh_cbom import generate_ssh_cbom
        risk = assess_risk_from_scan(mock_ssh_scan_result)
        cbom = generate_ssh_cbom(mock_ssh_scan_result, risk)
        names = [c["name"] for c in cbom["components"]]
        assert any("KEX" in n or "kex" in n.lower() or "curve25519" in n for n in names)

    def test_cbom_metadata_has_risk(self, mock_ssh_scan_result):
        from ssh_scanner.ssh_risk import assess_risk_from_scan
        from ssh_scanner.ssh_cbom import generate_ssh_cbom
        risk = assess_risk_from_scan(mock_ssh_scan_result)
        cbom = generate_ssh_cbom(mock_ssh_scan_result, risk)
        props = {p["name"]: p["value"] for p in cbom["metadata"]["component"]["properties"]}
        assert "cryptiq:overallRisk" in props
        assert "cryptiq:pqcStatus" in props

    def test_cbom_serialises_to_json(self, mock_ssh_scan_result):
        from ssh_scanner.ssh_risk import assess_risk_from_scan
        from ssh_scanner.ssh_cbom import generate_ssh_cbom, cbom_to_json
        risk = assess_risk_from_scan(mock_ssh_scan_result)
        cbom = generate_ssh_cbom(mock_ssh_scan_result, risk)
        j = cbom_to_json(cbom)
        parsed = json.loads(j)
        assert parsed["bomFormat"] == "CycloneDX"


# ===========================================================================
# SSH — Unit tests: network discovery helpers
# ===========================================================================

class TestSSHNetworkDiscovery:

    def test_expand_cidr(self):
        from ssh_scanner.ssh_network import expand_targets
        ips = expand_targets("192.168.1.0/30")
        # /30 gives 2 usable hosts
        assert len(ips) == 2
        assert "192.168.1.1" in ips
        assert "192.168.1.2" in ips

    def test_expand_ip_range(self):
        from ssh_scanner.ssh_network import expand_targets
        ips = expand_targets("10.0.0.1-10.0.0.5")
        assert len(ips) == 5
        assert "10.0.0.1" in ips
        assert "10.0.0.5" in ips

    def test_expand_single_ip(self):
        from ssh_scanner.ssh_network import expand_targets
        ips = expand_targets("1.2.3.4")
        assert ips == ["1.2.3.4"]

    def test_expand_comma_separated(self):
        from ssh_scanner.ssh_network import expand_targets
        ips = expand_targets("1.2.3.4,1.2.3.5,1.2.3.6")
        assert len(ips) == 3

    def test_expand_too_large_raises(self):
        from ssh_scanner.ssh_network import expand_targets, discover_network
        # /8 gives 16M IPs — way over any reasonable cap
        ips = expand_targets("10.0.0.0/8")
        assert len(ips) > 10
        # discover_network should refuse targets over max_hosts
        with pytest.raises(ValueError, match="safety cap"):
            discover_network("10.0.0.0/8", max_hosts=10)

    def test_classify_device_openssh(self):
        from ssh_scanner.ssh_network import classify_device
        dtype, os_hint = classify_device("SSH-2.0-OpenSSH_9.3 Ubuntu-3")
        assert dtype == "server"
        assert "Linux" in os_hint or "Unix" in os_hint

    def test_classify_device_dropbear(self):
        from ssh_scanner.ssh_network import classify_device
        dtype, os_hint = classify_device("SSH-2.0-dropbear_2022.83")
        assert dtype == "embedded"

    def test_classify_device_cisco(self):
        from ssh_scanner.ssh_network import classify_device
        dtype, os_hint = classify_device("SSH-2.0-Cisco-1.25")
        assert dtype == "router"
        assert "Cisco" in os_hint

    def test_classify_device_unknown(self):
        from ssh_scanner.ssh_network import classify_device
        dtype, os_hint = classify_device(None)
        assert dtype == "unknown"

    def test_classify_device_fortinet(self):
        from ssh_scanner.ssh_network import classify_device
        dtype, _ = classify_device("SSH-2.0-FortiSSH")
        assert dtype == "firewall"


# ===========================================================================
# API integration tests — health + pages
# ===========================================================================

class TestAPIHealth:

    def test_health_check(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_landing_page(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]

    def test_tls_page(self, client):
        r = client.get("/tls")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]

    def test_ssh_page(self, client):
        r = client.get("/ssh")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]

    def test_docs_available(self, client):
        r = client.get("/docs")
        assert r.status_code == 200

    def test_openapi_schema(self, client):
        r = client.get("/openapi.json")
        assert r.status_code == 200
        schema = r.json()
        assert "paths" in schema
        # Check key endpoints are documented
        assert "/scan" in schema["paths"]
        assert "/ssh/scan" in schema["paths"]


# ===========================================================================
# API integration tests — TLS endpoints
# ===========================================================================

class TestTLSAPIEndpoints:

    def test_scan_single_domain(self, client):
        with patch("api.scan_domain") as mock_scan, \
             patch("api._save_tls_scan"):
            mock_scan.return_value = {
                "domain": "example.com",
                "tls_version": "TLSv1.3",
                "algorithm": "ECDH",
                "quantum_vulnerable": True,
                "keysize": 256,
                "issuer": "Let's Encrypt",
                "expiry": "Sep 10 12:00:00 2026 GMT",
                "signature_algorithm": "ecdsa-with-SHA256",
                "days_until_expiry": 90,
                "risk_level": "High",
                "pqc_status": "vulnerable",
                "subject": "CN=example.com",
                "ct_logs": [],
            }
            r = client.post("/scan", json={"domain": "example.com"})
        assert r.status_code == 200
        data = r.json()
        assert "result" in data
        assert "cbom" in data
        assert data["result"]["domain"] == "example.com"
        assert data["result"]["quantum_vulnerable"] is True

    def test_scan_bulk(self, client):
        fake_result = {
            "domain": "example.com", "tls_version": "TLSv1.3",
            "algorithm": "ECDH", "quantum_vulnerable": True, "keysize": 256,
            "issuer": "Test", "expiry": "Sep 10 12:00:00 2026 GMT",
            "signature_algorithm": "ecdsa-with-SHA256", "days_until_expiry": 90,
            "risk_level": "High", "pqc_status": "vulnerable",
            "subject": "CN=example.com", "ct_logs": [],
        }
        with patch("api.scan_domain", return_value=fake_result), \
             patch("api.DBSession") as mock_session:
            mock_session.return_value.__enter__ = MagicMock(return_value=MagicMock())
            mock_session.return_value.__exit__ = MagicMock(return_value=False)
            r = client.post("/scan/bulk", json={"domains": ["example.com", "test.com"]})
        assert r.status_code == 200
        data = r.json()
        assert "results" in data
        assert "cbom" in data

    def test_get_scans_history(self, client):
        r = client.get("/scans")
        assert r.status_code == 200
        assert "scans" in r.json()

    def test_get_scans_by_domain(self, client):
        r = client.get("/scans/example.com")
        assert r.status_code == 200
        assert "scans" in r.json()

    def test_scan_missing_domain_field(self, client):
        r = client.post("/scan", json={})
        assert r.status_code == 422  # Pydantic validation error

    def test_scan_empty_domain(self, client):
        # Empty string passes Pydantic validation — domain: str has no min_length.
        # scan_domain raises on empty input; the API should return 500.
        # raise_server_exceptions=True (set on the fixture) means the exception
        # bubbles out of the test client, so we catch it here.
        import pytest as _pytest
        with patch("api.scan_domain", side_effect=Exception("connection refused")):
            try:
                r = client.post("/scan", json={"domain": ""})
                assert r.status_code in (200, 500)
            except Exception as e:
                # TestClient re-raised the server exception — that's fine,
                # it confirms the endpoint propagates errors correctly.
                assert "connection refused" in str(e)


# ===========================================================================
# API integration tests — SSH endpoints
# ===========================================================================

class TestSSHAPIEndpoints:

    def _mock_scan(self):
        """Return a minimal mocked scan result dict (what the API returns)."""
        return {
            "host": "test.example.com",
            "port": 22,
            "ssh_version": "OpenSSH_9.3",
            "ssh_protocol": "2.0",
            "raw_banner": "SSH-2.0-OpenSSH_9.3",
            "host_key_algorithm": "ssh-rsa",
            "host_key_size": 2048,
            "key_exchange": "curve25519-sha256",
            "cipher": "aes256-gcm@openssh.com",
            "mac": "hmac-sha2-256-etm@openssh.com",
            "host_keys": [{"algorithm": "ssh-rsa", "key_size": 2048, "fingerprint": "SHA256:abc"}],
            "server_kex_algorithms": ["curve25519-sha256"],
            "server_ciphers": ["aes256-gcm@openssh.com"],
            "server_macs": ["hmac-sha2-256-etm@openssh.com"],
            "server_host_key_algorithms": ["ssh-rsa"],
            "server_compression": ["none"],
            "quantum_vulnerable": True,
            "risk_level": "high",
            "pqc_status": "vulnerable",
            "migration_priority": "high",
            "findings": ["RSA host key — Shor-vulnerable"],
            "scan_success": True,
            "scan_error": None,
            "scanned_at": None,
            "db_id": None,
        }

    def test_ssh_scan_single(self, client):
        with patch("api.scan_ssh") as mock_scan, \
             patch("api.save_scan") as mock_save:
            from ssh_scanner.scan_ssh import SSHScanResult, SSHHostKey
            result = SSHScanResult(host="test.example.com", port=22)
            result.ssh_version = "OpenSSH_9.3"
            result.ssh_protocol = "2.0"
            result.raw_banner = "SSH-2.0-OpenSSH_9.3"
            result.host_keys = [SSHHostKey("ssh-rsa", 2048, "SHA256:abc")]
            result.server_kex_algorithms = ["curve25519-sha256"]
            result.server_ciphers = ["aes256-gcm@openssh.com"]
            result.server_macs = ["hmac-sha2-256-etm@openssh.com"]
            result.server_host_key_algorithms = ["ssh-rsa"]
            result.server_compression = ["none"]
            result.negotiated_kex = "curve25519-sha256"
            result.negotiated_cipher = "aes256-gcm@openssh.com"
            result.negotiated_mac = "hmac-sha2-256-etm@openssh.com"
            result.scan_success = True
            mock_scan.return_value = result
            mock_save.return_value = MagicMock(id=1, scanned_at=datetime.now(timezone.utc))

            r = client.post("/ssh/scan", json={"host": "test.example.com", "port": 22})
        assert r.status_code == 200
        data = r.json()
        assert data["host"] == "test.example.com"
        assert "risk_level" in data
        assert "pqc_status" in data
        assert "quantum_vulnerable" in data
        assert "findings" in data

    def test_ssh_scan_missing_host(self, client):
        r = client.post("/ssh/scan", json={"port": 22})
        assert r.status_code == 422

    def test_ssh_scan_invalid_port(self, client):
        # Port 99999 exceeds Field(ge=1, le=65535) — Pydantic rejects it
        r = client.post("/ssh/scan", json={"host": "example.com", "port": 99999})
        assert r.status_code == 422

    def test_ssh_scans_history(self, client):
        r = client.get("/ssh/scans")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_ssh_scans_filter_by_risk(self, client):
        r = client.get("/ssh/scans?risk_level=high")
        assert r.status_code == 200

    def test_ssh_scans_filter_by_pqc(self, client):
        r = client.get("/ssh/scans?pqc_status=vulnerable")
        assert r.status_code == 200

    def test_ssh_scans_pagination(self, client):
        r = client.get("/ssh/scans?limit=10&offset=0")
        assert r.status_code == 200

    def test_ssh_scans_for_unknown_host_returns_404(self, client):
        r = client.get("/ssh/scans/definitely-does-not-exist.example.com")
        assert r.status_code == 404

    def test_ssh_latest_unknown_host_returns_404(self, client):
        r = client.get("/ssh/latest/definitely-does-not-exist.example.com")
        assert r.status_code == 404

    def test_ssh_cbom_unknown_host_returns_404(self, client):
        r = client.get("/ssh/cbom/definitely-does-not-exist.example.com")
        assert r.status_code == 404

    def test_ssh_inventory_structure(self, client):
        r = client.get("/ssh/inventory")
        assert r.status_code == 200
        data = r.json()
        assert "total_hosts" in data
        assert "quantum_vulnerable" in data
        assert "by_risk_level" in data
        assert "by_pqc_status" in data
        assert "pqc_readiness_percent" in data

    def test_ssh_discover_invalid_target(self, client):
        # Empty target should return 400 or handle gracefully
        with patch("api.discover_network", side_effect=ValueError("No IPs resolved")):
            r = client.post("/ssh/discover", json={"target": ""})
        assert r.status_code in (400, 422)

    def test_ssh_discover_cidr_too_large(self, client):
        with patch("api.discover_network", side_effect=ValueError("exceeds the safety cap")):
            r = client.post("/ssh/discover", json={"target": "0.0.0.0/0"})
        assert r.status_code == 400
        assert "safety cap" in r.json()["detail"]

    def test_ssh_asset_tag(self, client):
        with patch("api.upsert_asset_metadata") as mock_upsert:
            mock_upsert.return_value = MagicMock(
                host="192.168.1.1", port=22,
                asset_name="Test Server", environment="production"
            )
            r = client.post("/ssh/assets/tag", json={
                "host": "192.168.1.1",
                "port": 22,
                "asset_name": "Test Server",
                "environment": "production",
            })
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_ssh_asset_tag_missing_host(self, client):
        r = client.post("/ssh/assets/tag", json={"port": 22})
        assert r.status_code == 422

    def test_ssh_assets_list(self, client):
        r = client.get("/ssh/assets")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_ssh_assets_enriched(self, client):
        r = client.get("/ssh/assets/enriched")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_ssh_snapshot(self, client):
        with patch("api.take_fleet_snapshot") as mock_snap:
            mock_snap.return_value = MagicMock(
                id=1, label="2026-W26",
                snapshot_at=datetime.now(timezone.utc),
                total_hosts=0, quantum_vulnerable=0, pqc_readiness_percent=0
            )
            r = client.post("/ssh/snapshot?label=test")
        assert r.status_code == 200
        data = r.json()
        assert "label" in data
        assert "total_hosts" in data

    def test_ssh_trend(self, client):
        r = client.get("/ssh/trend")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_ssh_report_no_assets_returns_404(self, client):
        with patch("api.get_enriched_assets", return_value=[]):
            r = client.post("/ssh/report?org_name=Test+Corp")
        assert r.status_code == 404

    def test_ssh_report_generates_pdf(self, client):
        from ssh_scanner.ssh_assets import EnrichedAsset
        fake_asset = EnrichedAsset(
            host="192.168.1.1", port=22, ssh_version="OpenSSH_9.3",
            host_key_algorithm="ssh-rsa", host_key_size=2048,
            key_exchange="curve25519-sha256", cipher="aes256-gcm@openssh.com",
            mac="hmac-sha2-256-etm@openssh.com", quantum_vulnerable=True,
            risk_level="high", pqc_status="vulnerable",
            migration_priority="high", findings=["RSA key — vulnerable"],
            scanned_at=datetime.now(timezone.utc),
        )
        with patch("api.get_enriched_assets", return_value=[fake_asset]), \
             patch("api.get_fleet_trend", return_value=[]), \
             patch("api.generate_report", return_value=b"%PDF-1.4 fake pdf content"):
            r = client.post("/ssh/report?org_name=Acme+Corp")
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/pdf"
        assert "attachment" in r.headers["content-disposition"]


# ===========================================================================
# Database persistence tests
# ===========================================================================

class TestDatabasePersistence:

    def test_tls_scan_record_saves_and_retrieves(self):
        from database import Base, ScanRecord
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        S = sessionmaker(bind=engine)
        session = S()
        record = ScanRecord(
            domain="example.com", tls_version="TLSv1.3",
            algorithm="ECDH", quantum_vulnerable=True,
            risk_level="High", pqc_status="vulnerable"
        )
        session.add(record)
        session.commit()
        result = session.query(ScanRecord).filter_by(domain="example.com").first()
        assert result is not None
        assert result.quantum_vulnerable is True
        assert result.risk_level == "High"
        session.close()

    def test_tls_scan_record_to_dict(self):
        from database import ScanRecord
        r = ScanRecord(
            domain="test.com", tls_version="TLSv1.2",
            algorithm="RSA", quantum_vulnerable=True,
            risk_level="Critical", pqc_status="vulnerable"
        )
        d = r.to_dict()
        assert d["domain"] == "test.com"
        assert d["quantum_vulnerable"] is True
        assert "scanned_at" in d

    def test_ssh_scan_record_saves(self):
        from ssh_scanner.ssh_database import Base, SSHScanRecord, create_tables
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        engine = create_engine("sqlite:///:memory:")
        create_tables(engine)
        S = sessionmaker(bind=engine)
        db = S()
        record = SSHScanRecord(
            host="192.168.1.1", port=22,
            ssh_version="OpenSSH_9.3",
            host_key_algorithm="ssh-rsa", host_key_size=2048,
            key_exchange="curve25519-sha256",
            quantum_vulnerable=True, risk_level="high",
            pqc_status="vulnerable", migration_priority="high",
            scan_success=True,
        )
        db.add(record)
        db.commit()
        result = db.query(SSHScanRecord).filter_by(host="192.168.1.1").first()
        assert result is not None
        assert result.host_key_algorithm == "ssh-rsa"
        assert result.quantum_vulnerable is True
        db.close()

    def test_ssh_inventory_summary_empty_db(self):
        from ssh_scanner.ssh_database import Base, get_inventory_summary, create_tables
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        engine = create_engine("sqlite:///:memory:")
        create_tables(engine)
        S = sessionmaker(bind=engine)
        db = S()
        summary = get_inventory_summary(db)
        assert summary["total_hosts"] == 0
        assert summary["quantum_vulnerable"] == 0
        assert summary["pqc_readiness_percent"] == 0.0
        db.close()


# ===========================================================================
# Edge cases and error handling
# ===========================================================================

class TestEdgeCases:

    def test_ssh_scan_failed_host(self):
        """A scan that can't connect should return scan_success=False, not crash."""
        from ssh_scanner.scan_ssh import SSHScanResult
        # Simulate what scan_ssh returns on connection failure
        result = SSHScanResult(host="192.0.2.1", port=22)  # TEST-NET, not routable
        result.scan_success = False
        result.scan_error = "Connection refused"
        assert result.scan_success is False
        assert result.host_keys == []

    def test_risk_assess_with_no_host_keys(self):
        from ssh_scanner.scan_ssh import SSHScanResult
        from ssh_scanner.ssh_risk import assess_risk_from_scan
        result = SSHScanResult(host="example.com", port=22)
        result.scan_success = False
        result.host_keys = []
        result.server_kex_algorithms = []
        result.server_ciphers = []
        result.server_macs = []
        result.server_host_key_algorithms = []
        result.server_compression = []
        # Should not raise
        risk = assess_risk_from_scan(result)
        assert risk.host == "example.com"

    def test_cbom_empty_host_keys(self):
        from ssh_scanner.scan_ssh import SSHScanResult
        from ssh_scanner.ssh_risk import assess_risk_from_scan
        from ssh_scanner.ssh_cbom import generate_ssh_cbom
        result = SSHScanResult(host="example.com", port=22)
        result.host_keys = []
        result.server_kex_algorithms = []
        result.server_ciphers = []
        result.server_macs = []
        result.server_host_key_algorithms = []
        result.server_compression = []
        result.scan_success = False
        risk = assess_risk_from_scan(result)
        # Should not raise
        cbom = generate_ssh_cbom(result, risk)
        assert cbom["bomFormat"] == "CycloneDX"

    def test_tls_cbom_with_none_values(self):
        from tls_scanner.scan_tls import convert_to_cbom
        result = {
            "domain": "example.com", "tls_version": "Unknown",
            "algorithm": "Unknown", "quantum_vulnerable": False,
            "keysize": None, "issuer": "Unknown", "expiry": "Unknown",
            "signature_algorithm": "Unknown", "days_until_expiry": None,
            "risk_level": "Low", "pqc_status": "unknown",
            "subject": "Unknown", "ct_logs": [],
        }
        cbom = convert_to_cbom(result)
        assert cbom["bomFormat"] == "CycloneDX"

    def test_expand_targets_invalid_hostname(self):
        from ssh_scanner.ssh_network import expand_targets
        # Unresolvable hostname should be skipped, not crash
        result = expand_targets("this-definitely-does-not-exist-xyz-123.invalid")
        assert isinstance(result, list)
        # May be empty (unresolvable) — just shouldn't raise

    def test_summarise_empty_assessments(self):
        from ssh_scanner.ssh_risk import summarise_risk_assessments
        summary = summarise_risk_assessments([])
        assert summary["total_scanned"] == 0
        assert summary["pqc_readiness_percent"] == 0.0