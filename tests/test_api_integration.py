"""
tests/test_api_integration.py
--------------------------------
Integration tests against the live FastAPI app via TestClient.
All external boundaries (openssl subprocess, boto3, paramiko/SSH sockets,
GitHub) are mocked.
"""

import json
import pytest
from unittest.mock import patch, MagicMock


class TestMeta:
    def test_health_check(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_docs_available(self, client):
        r = client.get("/docs")
        assert r.status_code == 200

    def test_openapi_schema_valid(self, client):
        r = client.get("/openapi.json")
        assert r.status_code == 200
        schema = r.json()
        assert "paths" in schema


class TestPageRoutes:
    @pytest.mark.parametrize("path", ["/", "/tls", "/ssh", "/alb", "/migrate"])
    def test_page_routes_return_200_or_redirect(self, client, path):
        r = client.get(path, follow_redirects=False)
        assert r.status_code in (200, 307, 302)


class TestTLSEndpoints:
    def test_scan_single_domain(self, client):
        fake_result = {
            "domain": "example.com", "tls_version": "TLSv1.3", "algorithm": "RSA",
            "quantum_vulnerable": True, "keysize": 2048, "issuer": "Test CA",
            "expiry": "Unknown", "signature_algorithm": "sha256",
            "days_until_expiry": None, "risk_level": "High", "pqc_status": "vulnerable",
            "subject": "CN=example.com", "ct_logs": [],
        }
        with patch("api.scan_domain", return_value=fake_result):
            r = client.post("/scan", json={"domain": "example.com"})
        assert r.status_code == 200
        assert r.json()["result"]["domain"] == "example.com"
        assert "cbom" in r.json()

    def test_scan_missing_domain_field_is_422(self, client):
        r = client.post("/scan", json={})
        assert r.status_code == 422

    def test_bulk_scan(self, client):
        fake_result = {
            "domain": "x.com", "tls_version": "TLSv1.3", "algorithm": "RSA",
            "quantum_vulnerable": True, "keysize": 2048, "issuer": "T",
            "expiry": "U", "signature_algorithm": "s", "days_until_expiry": None,
            "risk_level": "High", "pqc_status": "vulnerable", "subject": "s", "ct_logs": [],
        }
        with patch("api.scan_domain", side_effect=lambda d: {**fake_result, "domain": d}):
            r = client.post("/scan/bulk", json={"domains": ["a.com", "b.com"]})
        assert r.status_code == 200
        assert len(r.json()["results"]) == 2

    def test_get_scans_empty_initially(self, client):
        r = client.get("/scans")
        assert r.status_code == 200
        assert "scans" in r.json()

    def test_aws_certificates_mocked(self, client):
        with patch("api.scan_acm_certificates", return_value=[]):
            r = client.get("/aws/certificates")
        assert r.status_code == 200

    def test_aws_alb_listeners_mocked(self, client):
        with patch("api.discover_alb_listeners", return_value=[]):
            r = client.get("/aws/alb-listeners?region=us-east-1")
        assert r.status_code == 200
        assert r.json()["count"] == 0


class TestWorkspaceEndpoints:
    def test_create_workspace(self, client):
        r = client.post("/workspace", json={
            "org_name": "Acme Corp", "root_domain": "acme.com",
        })
        assert r.status_code == 200
        body = r.json()
        assert body["org_name"] == "Acme Corp"
        assert "id" in body

    def test_get_nonexistent_workspace_404(self, client):
        r = client.get("/workspace/999999")
        assert r.status_code == 404

    def test_get_workspace_after_creation(self, client):
        created = client.post("/workspace", json={
            "org_name": "Test Org", "root_domain": "test.com",
        }).json()
        r = client.get(f"/workspace/{created['id']}")
        assert r.status_code == 200
        assert r.json()["org_name"] == "Test Org"

    def test_connect_aws_encrypts_credentials(self, client):
        created = client.post("/workspace", json={
            "org_name": "AWS Org", "root_domain": "awsorg.com",
        }).json()
        r = client.post(f"/workspace/{created['id']}/connect/aws", json={
            "aws_access_key": "AKIAFAKE123", "aws_secret_key": "fakesecretkey",
        })
        assert r.status_code == 200
        assert r.json()["aws_connected"] is True
        assert "AKIAFAKE123" not in json.dumps(r.json())

    def test_connect_aws_to_nonexistent_workspace_404(self, client):
        r = client.post("/workspace/999999/connect/aws", json={
            "aws_access_key": "x", "aws_secret_key": "y",
        })
        assert r.status_code == 404

    def test_workspace_scan_starts_background_job(self, client):
        created = client.post("/workspace", json={
            "org_name": "Scan Org", "root_domain": "scanorg.com",
        }).json()
        with patch("api.discover_assets", return_value={"domains": [], "hosts": []}):
            r = client.post(f"/workspace/{created['id']}/scan")
        assert r.status_code == 200
        assert "job_id" in r.json()

    def test_scan_status_for_unknown_job_404(self, client):
        created = client.post("/workspace", json={
            "org_name": "Job Org", "root_domain": "joborg.com",
        }).json()
        r = client.get(f"/workspace/{created['id']}/scan/999999/status")
        assert r.status_code == 404

    def test_workspace_results_empty_initially(self, client):
        created = client.post("/workspace", json={
            "org_name": "Results Org", "root_domain": "resultsorg.com",
        }).json()
        r = client.get(f"/workspace/{created['id']}/results")
        assert r.status_code == 200
        assert r.json()["results"] == []


class TestSSHEndpoints:
    def test_ssh_scan_single(self, client, fake_ssh_scan_result):
        # NOTE: fake_ssh_scan_result has negotiated_kex="curve25519-sha256"
        # (medium risk), which assess_risk_from_scan prioritises over the
        # worst-case advertised KEX (group1-sha1, critical) -- negotiated
        # values are trusted over advertised-but-unused ones. Combined with
        # an RSA-2048 host key (high), the weighted score lands at "medium".
        with patch("api.scan_ssh", return_value=fake_ssh_scan_result):
            r = client.post("/ssh/scan", json={"host": "test.example.com", "port": 22})
        assert r.status_code == 200
        body = r.json()
        assert body["host"] == "test.example.com"
        assert body["risk_level"] == "medium"
        assert "recommendations" in body
        assert "weighted_score" in body

    def test_ssh_scan_invalid_port_422(self, client):
        r = client.post("/ssh/scan", json={"host": "example.com", "port": 99999})
        assert r.status_code == 422

    def test_ssh_scan_missing_host_422(self, client):
        r = client.post("/ssh/scan", json={"port": 22})
        assert r.status_code == 422

    def test_ssh_scan_bulk(self, client, fake_ssh_scan_result, fake_hybrid_scan_result):
        with patch("api.scan_ssh_bulk", return_value=[fake_ssh_scan_result, fake_hybrid_scan_result]):
            r = client.post("/ssh/scan/bulk", json={"hosts": ["a.com", "b.com"]})
        assert r.status_code == 200
        assert len(r.json()["results"]) == 2
        assert "summary" in r.json()

    def test_ssh_discover_invalid_target_400(self, client):
        with patch("api.discover_network", side_effect=ValueError("Target too large")):
            r = client.post("/ssh/discover", json={"target": "0.0.0.0/0"})
        assert r.status_code == 400

    def test_ssh_inventory_empty(self, client):
        r = client.get("/ssh/inventory")
        assert r.status_code == 200

    def test_ssh_asset_tag(self, client):
        r = client.post("/ssh/assets/tag", json={
            "host": "127.0.0.1", "port": 22, "asset_name": "Test Server",
            "environment": "staging",
        })
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_ssh_assets_enriched_empty(self, client):
        r = client.get("/ssh/assets/enriched")
        assert r.status_code == 200
        assert r.json() == []

    def test_ssh_snapshot_and_trend(self, client):
        r1 = client.post("/ssh/snapshot?label=test-snap")
        assert r1.status_code == 200
        r2 = client.get("/ssh/trend")
        assert r2.status_code == 200
        labels = [s["label"] for s in r2.json()]
        assert "test-snap" in labels

    def test_ssh_report_404_when_no_assets(self, client):
        r = client.post("/ssh/report?org_name=Test")
        assert r.status_code == 404

    def test_ssh_latest_unknown_host_404(self, client):
        r = client.get("/ssh/latest/nonexistent-host.example")
        assert r.status_code == 404


class TestSSHMigrationEndpoints:
    def test_algorithms_endpoint(self, client):
        r = client.get("/migrate/ssh/algorithms")
        assert r.status_code == 200

    def test_tools_endpoint(self, client):
        r = client.get("/migrate/ssh/tools")
        assert r.status_code == 200

    def test_plan_endpoint(self, client):
        scan_result = {
            "host": "127.0.0.1", "port": 22,
            "ssh_version": "OpenSSH_8.2p1 Ubuntu-4ubuntu0.13",
            "host_key_algorithm": "ssh-rsa", "host_key_size": None,
            "host_keys": [{"algorithm": "ssh-rsa", "key_size": None, "fingerprint": None}],
            "server_kex_algorithms": ["diffie-hellman-group1-sha1", "curve25519-sha256"],
            "server_ciphers": ["3des-cbc"], "server_macs": ["hmac-md5"],
            "server_host_key_algorithms": ["ssh-rsa"],
            "risk_level": "critical", "pqc_status": "vulnerable",
        }
        r = client.post("/migrate/ssh/plan", json={"scan_result": scan_result})
        assert r.status_code == 200
        assert r.json()["total_actions"] > 0

    def test_execute_dry_run_default(self, client):
        action = {
            "id": "test", "action_type": "generic", "host": "127.0.0.1",
            "commands": ["echo hello"], "params": {},
        }
        r = client.post("/migrate/ssh/execute", json={"action": action})
        assert r.status_code == 200
        assert r.json()["dry_run"] is True


class TestALBMigrationEndpoints:
    def test_migrate_alb_tls_listener_not_found_404(self, client):
        with patch("api.discover_alb_listeners", return_value=[]):
            r = client.post("/migrate/alb-tls", json={
                "listener_arn": "arn:aws:elasticloadbalancing:us-east-1:123:listener/x",
                "tf_repo": "/tmp/tf", "gh_repo": "owner/repo",
            })
        assert r.status_code == 404

    def test_migrate_alb_tls_dry_run_default(self, client, tmp_path):
        from tls_migration.types import TlsListenerAsset
        asset = TlsListenerAsset(
            lb_arn="arn:lb:1", lb_name="demo", listener_arn="arn:aws:elasticloadbalancing:us-east-1:123:listener/x",
            port=443, protocol="HTTPS", ssl_policy_name="ELBSecurityPolicy-TLS13-1-2-2021-06",
            supported_protocols=["TLSv1.2"], supported_groups=[], is_post_quantum=False,
            environment="staging",
        )
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(
            'resource "aws_lb_listener" "demo" {\n  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"\n}\n'
        )
        with patch("api.discover_alb_listeners", return_value=[asset]):
            r = client.post("/migrate/alb-tls", json={
                "listener_arn": asset.listener_arn,
                "tf_repo": str(tmp_path), "gh_repo": "owner/repo",
            })
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "dry_run"
        assert body.get("pr_url") is None

    def test_migrate_alb_tls_prod_blocked_by_default(self, client, tmp_path):
        from tls_migration.types import TlsListenerAsset
        asset = TlsListenerAsset(
            lb_arn="arn:lb:1", lb_name="prod-demo", listener_arn="arn:aws:elasticloadbalancing:us-east-1:123:listener/y",
            port=443, protocol="HTTPS", ssl_policy_name="ELBSecurityPolicy-TLS13-1-2-2021-06",
            supported_protocols=["TLSv1.2"], supported_groups=[], is_post_quantum=False,
            environment="prod",
        )
        with patch("api.discover_alb_listeners", return_value=[asset]):
            r = client.post("/migrate/alb-tls", json={
                "listener_arn": asset.listener_arn,
                "tf_repo": str(tmp_path), "gh_repo": "owner/repo",
            })
        assert r.status_code == 200
        assert r.json()["status"] == "prod_blocked"

    def test_audit_log_endpoint(self, client):
        r = client.get("/audit-log")
        assert r.status_code == 200
        assert "entries" in r.json()