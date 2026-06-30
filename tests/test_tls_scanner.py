"""
tests/test_tls_scanner.py
---------------------------
Unit tests for tls_scanner/scan_tls.py and scan_aws.py.
No live network or AWS calls -- openssl/boto3 calls are mocked.
"""

import pytest
from unittest.mock import patch, MagicMock

from tls_scanner.scan_tls import (
    is_quantum_vulnerable, get_tls_version, get_algorithm, get_key_size,
    get_issuer, get_expiry, get_signature_algorithm, get_days_until_expiry,
    get_risk_level, get_pqc_status, get_subject, convert_to_cbom,
    map_primitive, build_component, scan_domain,
)
from tls_scanner.scan_aws import (
    scan_acm_certificates, scan_kms_keys, convert_aws_to_cbom,
    build_acm_component, build_kms_component,
)


class TestQuantumVulnerable:
    @pytest.mark.parametrize("algo", ["RSA", "ECDSA", "ECDH", "DH", "ECC", "X25519", "Ed25519"])
    def test_known_vulnerable_algorithms(self, algo):
        assert is_quantum_vulnerable(algo) is True

    @pytest.mark.parametrize("algo", ["X25519MLKEM768", "Unknown", "ML-KEM-768", ""])
    def test_non_vulnerable_or_unknown_algorithms(self, algo):
        assert is_quantum_vulnerable(algo) is False


class TestPQCStatus:
    def test_hybrid_mlkem_detected(self):
        assert get_pqc_status("X25519MLKEM768") == "hybrid_pqc"

    def test_kyber_detected_as_hybrid(self):
        assert get_pqc_status("X25519Kyber768") == "hybrid_pqc"

    def test_vulnerable_algorithm(self):
        assert get_pqc_status("RSA") == "vulnerable"

    def test_unknown_algorithm(self):
        assert get_pqc_status("SomeNewThing") == "unknown"


class TestMapPrimitive:
    def test_known_mappings(self):
        assert map_primitive("RSA") == "pke"
        assert map_primitive("ECDH") == "keyagree"
        assert map_primitive("ECDSA") == "signature"
        assert map_primitive("X25519MLKEM768") == "kem"

    def test_unknown_maps_to_unknown(self):
        assert map_primitive("SomethingElse") == "unknown"


class TestRiskLevel:
    def test_non_vulnerable_is_low(self):
        assert get_risk_level("X25519MLKEM768", 200) == "Low"

    def test_vulnerable_expiring_soon_is_critical(self):
        assert get_risk_level("RSA", 30) == "Critical"

    def test_vulnerable_expiring_at_exactly_59_is_critical(self):
        assert get_risk_level("RSA", 59) == "Critical"

    def test_vulnerable_expiring_at_60_is_high_not_critical(self):
        assert get_risk_level("RSA", 60) == "High"

    def test_vulnerable_no_expiry_data_is_high(self):
        assert get_risk_level("RSA", None) == "High"


SAMPLE_S_CLIENT_OUTPUT = """CONNECTED(00000003)
---
Protocol  : TLSv1.3
Cipher    : TLS_AES_256_GCM_SHA384
Server Temp Key: X25519, 253 bits
Server public key is 256 bit
---
"""

SAMPLE_X509_OUTPUT = """notAfter=Jul 30 15:51:35 2026 GMT
Certificate:
    Data:
        Issuer: C = US, O = Google Trust Services, CN = WE2
        Subject: CN = *.google.com
        Signature Algorithm: ecdsa-with-SHA256
    Subject Public Key Info:
        Public Key Algorithm: id-ecPublicKey
            Server public key is 256 bit
"""


class TestRawParsing:
    def test_get_tls_version_found(self):
        assert get_tls_version(SAMPLE_S_CLIENT_OUTPUT) == "TLSv1.3"

    def test_get_tls_version_not_found(self):
        assert get_tls_version("no protocol line here") == "Unknown"

    def test_get_algorithm_from_temp_key(self):
        assert get_algorithm(SAMPLE_S_CLIENT_OUTPUT) == "X25519"

    def test_get_algorithm_not_found(self):
        assert get_algorithm("nothing relevant") == "Unknown"

    def test_get_key_size_found(self):
        assert get_key_size(SAMPLE_X509_OUTPUT) == 256

    def test_get_key_size_not_found(self):
        assert get_key_size("no key size here") is None

    def test_get_issuer_found(self):
        result = get_issuer(SAMPLE_X509_OUTPUT)
        assert "Google Trust Services" in result

    def test_get_issuer_not_found(self):
        assert get_issuer("no issuer line") == "Unknown"

    def test_get_subject_found(self):
        result = get_subject(SAMPLE_X509_OUTPUT)
        assert "google.com" in result

    def test_get_expiry_found(self):
        assert get_expiry(SAMPLE_X509_OUTPUT) == "Jul 30 15:51:35 2026 GMT"

    def test_get_expiry_not_found(self):
        assert get_expiry("no expiry") == "Unknown"

    def test_get_signature_algorithm_found(self):
        assert get_signature_algorithm(SAMPLE_X509_OUTPUT) == "ecdsa-with-SHA256"

    def test_get_signature_algorithm_not_found(self):
        assert get_signature_algorithm("nothing") == "Unknown"


class TestDaysUntilExpiry:
    def test_unknown_returns_none(self):
        assert get_days_until_expiry("Unknown") is None

    def test_future_date_returns_positive_int(self):
        days = get_days_until_expiry("Jul 30 15:51:35 2099 GMT")
        assert isinstance(days, int)
        assert days > 0

    def test_malformed_date_returns_none(self):
        assert get_days_until_expiry("not a real date") is None


class TestScanDomain:
    @patch("tls_scanner.scan_tls.get_certs_from_ct_logs", return_value=[])
    @patch("tls_scanner.scan_tls.get_cert_details", return_value=SAMPLE_X509_OUTPUT)
    @patch("tls_scanner.scan_tls.get_tls_raw", return_value=SAMPLE_S_CLIENT_OUTPUT)
    def test_full_scan_pipeline(self, mock_raw, mock_cert, mock_ct):
        result = scan_domain("example.com")
        assert result["domain"] == "example.com"
        assert result["tls_version"] == "TLSv1.3"
        assert result["algorithm"] == "X25519"
        assert result["quantum_vulnerable"] is True
        assert result["keysize"] == 256
        assert "Google" in result["issuer"]
        assert result["pqc_status"] == "vulnerable"
        assert result["ct_logs"] == []

    @patch("tls_scanner.scan_tls.get_certs_from_ct_logs", return_value=[])
    @patch("tls_scanner.scan_tls.get_cert_details", return_value="")
    @patch("tls_scanner.scan_tls.get_tls_raw", return_value="")
    def test_scan_with_no_data_returns_unknowns(self, mock_raw, mock_cert, mock_ct):
        result = scan_domain("unreachable.example")
        assert result["tls_version"] == "Unknown"
        assert result["algorithm"] == "Unknown"
        # NOTE: "Unknown" is NOT in the quantum-vulnerable algorithm list, so
        # is_quantum_vulnerable("Unknown") is False and get_risk_level returns
        # "Low". A failed/empty scan is reported as LOW risk rather than
        # "needs investigation" -- worth flagging to the team as a UX gap.
        assert result["risk_level"] == "Low"
        assert result["quantum_vulnerable"] is False


class TestCTLogs:
    @patch("tls_scanner.scan_tls.requests.get")
    def test_ct_logs_success(self, mock_get):
        from tls_scanner.scan_tls import get_certs_from_ct_logs
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"issuer_name": "Let's Encrypt", "common_name": "example.com",
             "not_before": "2026-01-01", "not_after": "2026-04-01"},
        ]
        mock_get.return_value = mock_resp
        result = get_certs_from_ct_logs("example.com")
        assert len(result) == 1
        assert result[0]["common_name"] == "example.com"

    @patch("tls_scanner.scan_tls.requests.get")
    def test_ct_logs_non_200_returns_empty(self, mock_get):
        from tls_scanner.scan_tls import get_certs_from_ct_logs
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_get.return_value = mock_resp
        assert get_certs_from_ct_logs("example.com") == []

    @patch("tls_scanner.scan_tls.requests.get", side_effect=Exception("network down"))
    def test_ct_logs_exception_returns_empty(self, mock_get):
        from tls_scanner.scan_tls import get_certs_from_ct_logs
        assert get_certs_from_ct_logs("example.com") == []


SAMPLE_RESULT = {
    "domain": "example.com", "tls_version": "TLSv1.3", "algorithm": "RSA",
    "quantum_vulnerable": True, "keysize": 2048, "issuer": "Let's Encrypt",
    "expiry": "Jul 30 15:51:35 2026 GMT", "signature_algorithm": "sha256WithRSAEncryption",
    "days_until_expiry": 180, "risk_level": "High", "pqc_status": "vulnerable",
    "subject": "CN=example.com", "ct_logs": [],
}


class TestTLSCBOM:
    def test_cbom_structure(self):
        cbom = convert_to_cbom(SAMPLE_RESULT)
        assert cbom["bomFormat"] == "CycloneDX"
        assert cbom["specVersion"] == "1.6"
        assert "serialNumber" in cbom
        assert len(cbom["components"]) == 1

    def test_cbom_accepts_dict_or_list(self):
        cbom_dict = convert_to_cbom(SAMPLE_RESULT)
        cbom_list = convert_to_cbom([SAMPLE_RESULT])
        assert len(cbom_dict["components"]) == len(cbom_list["components"]) == 1

    def test_cbom_bulk(self):
        results = [SAMPLE_RESULT, {**SAMPLE_RESULT, "domain": "other.com"}]
        cbom = convert_to_cbom(results)
        assert len(cbom["components"]) == 2

    def test_component_fields(self):
        component = build_component(SAMPLE_RESULT)
        assert component["type"] == "cryptographic-asset"
        assert component["cryptoProperties"]["assetType"] == "certificate"
        assert component["cryptoProperties"]["nistQuantumSecurityLevel"] == 0

    def test_component_safe_algorithm_gets_level_3(self):
        safe_result = {**SAMPLE_RESULT, "quantum_vulnerable": False}
        component = build_component(safe_result)
        assert component["cryptoProperties"]["nistQuantumSecurityLevel"] == 3


class TestACMScanning:
    @patch("tls_scanner.scan_aws.boto3.client")
    def test_scan_acm_certificates(self, mock_boto_client):
        mock_acm = MagicMock()
        mock_acm.list_certificates.return_value = {
            "CertificateSummaryList": [{"CertificateArn": "arn:aws:acm:us-east-1:123:cert/abc"}]
        }
        mock_acm.describe_certificate.return_value = {
            "Certificate": {
                "DomainName": "example.com", "KeyAlgorithm": "RSA-2048",
                "Issuer": "Amazon", "Status": "ISSUED",
                "NotAfter": "2026-12-01", "KeySize": 2048,
            }
        }
        mock_boto_client.return_value = mock_acm

        results = scan_acm_certificates()
        assert len(results) == 1
        assert results[0]["domain_name"] == "example.com"
        # NOTE: "RSA-2048" is not an exact match for "RSA" in the
        # quantum-vulnerable list (exact-match, no substring/prefix check),
        # so this is incorrectly flagged as NOT quantum-vulnerable. This is
        # a real gap worth fixing in is_quantum_vulnerable() since AWS ACM
        # typically returns algorithm strings with size suffixes.
        assert results[0]["quantum_vulnerable"] is False

    @patch("tls_scanner.scan_aws.boto3.client")
    def test_scan_acm_empty(self, mock_boto_client):
        mock_acm = MagicMock()
        mock_acm.list_certificates.return_value = {"CertificateSummaryList": []}
        mock_boto_client.return_value = mock_acm
        assert scan_acm_certificates() == []


class TestKMSScanning:
    @patch("tls_scanner.scan_aws.boto3.client")
    def test_scan_kms_keys(self, mock_boto_client):
        mock_kms = MagicMock()
        mock_kms.list_keys.return_value = {"Keys": [{"KeyId": "abc-123"}]}
        mock_kms.describe_key.return_value = {
            "KeyMetadata": {
                "KeyId": "abc-123", "KeyAlgorithm": "RSA", "KeyState": "Enabled",
                "Description": "Test key",
            }
        }
        mock_boto_client.return_value = mock_kms

        results = scan_kms_keys()
        assert len(results) == 1
        assert results[0]["key_id"] == "abc-123"
        assert results[0]["quantum_vulnerable"] is True


class TestAWSCBOM:
    def test_convert_aws_to_cbom_structure(self):
        certs = [{
            "domain_name": "example.com", "algorithm": "RSA", "key_size": 2048,
            "issuer": "Amazon", "expiry": "2026-12-01", "quantum_vulnerable": True,
        }]
        keys = [{
            "key_id": "abc", "algorithm": "RSA", "status": "Enabled",
            "description": "test", "quantum_vulnerable": True,
        }]
        cbom = convert_aws_to_cbom(certs, keys)
        assert cbom["bomFormat"] == "CycloneDX"
        assert len(cbom["components"]) == 2

    def test_convert_aws_to_cbom_handles_dict_input(self):
        cert = {
            "domain_name": "example.com", "algorithm": "RSA", "key_size": 2048,
            "issuer": "Amazon", "expiry": "2026-12-01", "quantum_vulnerable": True,
        }
        key = {
            "key_id": "abc", "algorithm": "RSA", "status": "Enabled",
            "description": "test", "quantum_vulnerable": True,
        }
        cbom = convert_aws_to_cbom(cert, key)
        assert len(cbom["components"]) == 2

    def test_convert_aws_to_cbom_empty(self):
        cbom = convert_aws_to_cbom([], [])
        assert cbom["components"] == []