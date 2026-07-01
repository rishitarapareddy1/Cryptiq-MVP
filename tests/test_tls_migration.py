"""
tests/test_tls_migration.py
-----------------------------
Tests for the ALB TLS -> PQC migration pipeline, matching the REAL source
contracts in tls_migration/ (types, alb_plan, run, rollback, github_pr, audit, alb_cbom).

SAFETY-CRITICAL test classes: TestProdGating, TestNeverMergesOrDeletes,
TestRollbackNeverGuesses.
"""

import json
import os
import pytest
from unittest.mock import patch, MagicMock

from tls_migration.types import TlsListenerAsset
from tls_migration.alb_plan import compute_migration_diff, TARGET_PQ_POLICY, MigrationDiff
from tls_migration.run import run_migration, PROD_CONFIRMATION_TOKEN
from tls_migration.rollback import (
    run_rollback, extract_metadata_from_pr_body, compute_rollback_diff,
)
from tls_migration import audit
from tls_migration.alb_cbom import convert_alb_to_cbom, build_alb_component
from tls_scanner.scan_alb import discover_alb_listeners, _is_post_quantum, PQ_POLICY_NAMES, PQ_GROUPS


def make_asset(**overrides) -> TlsListenerAsset:
    defaults = dict(
        lb_arn="arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/demo-alb/abc123",
        lb_name="demo-alb",
        listener_arn="arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/demo-alb/abc123/def456",
        port=443,
        protocol="HTTPS",
        ssl_policy_name="ELBSecurityPolicy-TLS13-1-2-2021-06",
        supported_protocols=["TLSv1.2", "TLSv1.3"],
        supported_groups=[],
        is_post_quantum=False,
        environment="staging",
        region="us-east-1",
    )
    defaults.update(overrides)
    return TlsListenerAsset(**defaults)


VALID_TF_CONTENT = """resource "aws_lb_listener" "demo_alb" {
  load_balancer_arn = aws_lb.demo_alb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.demo.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.demo.arn
  }
}
"""

AMBIGUOUS_TF_CONTENT = """resource "aws_lb_listener" "frontend" {
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

resource "aws_lb_listener" "backend" {
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}
"""


@pytest.fixture(autouse=True)
def isolated_audit_log(tmp_path, monkeypatch):
    """Redirect CRYPTIQ_AUDIT_LOG to a temp file for every test (audit.py
    reads this env var fresh on each call via _log_path(), so no module
    attribute patching is needed -- just set the env var)."""
    monkeypatch.setenv("CRYPTIQ_AUDIT_LOG", str(tmp_path / "audit_out" / "audit.log"))
    yield


def _paginator_returning(pages):
    paginator = MagicMock()
    paginator.paginate.return_value = pages
    return paginator


class TestIsPostQuantum:
    def test_known_pq_policy_name_detected(self):
        assert _is_post_quantum("ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09", []) is True

    def test_classical_policy_name_not_detected(self):
        assert _is_post_quantum("ELBSecurityPolicy-TLS13-1-2-2021-06", []) is False

    def test_pq_group_in_supported_groups_detected(self):
        assert _is_post_quantum("SomeCustomPolicy", ["X25519MLKEM768"]) is True

    def test_no_pq_signal_at_all(self):
        assert _is_post_quantum("SomeCustomPolicy", ["secp256r1"]) is False

    def test_pq_group_constants_are_nonempty(self):
        assert len(PQ_POLICY_NAMES) > 0
        assert len(PQ_GROUPS) > 0


class TestDiscoverAlbListeners:
    @patch("tls_scanner.scan_alb.boto3.client")
    def test_discovers_https_listener_classical_policy(self, mock_client):
        elb = MagicMock()
        elb.get_paginator.side_effect = lambda op: {
            "describe_load_balancers": _paginator_returning([{
                "LoadBalancers": [{"LoadBalancerArn": "arn:lb:1", "LoadBalancerName": "demo-alb"}]
            }]),
            "describe_listeners": _paginator_returning([{
                "Listeners": [{
                    "ListenerArn": "arn:listener:1", "Port": 443, "Protocol": "HTTPS",
                    "SslPolicy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
                }]
            }]),
        }[op]
        elb.describe_tags.return_value = {"TagDescriptions": [
            {"ResourceArn": "arn:lb:1", "Tags": [{"Key": "Environment", "Value": "prod"}]}
        ]}
        elb.describe_ssl_policies.return_value = {"SslPolicies": [{"SslProtocols": [{"Name": "TLSv1.2"}]}]}
        mock_client.return_value = elb

        assets = discover_alb_listeners(region="us-east-1")
        assert len(assets) == 1
        assert assets[0].is_post_quantum is False
        assert assets[0].environment == "prod"
        assert assets[0].port == 443

    @patch("tls_scanner.scan_alb.boto3.client")
    def test_non_https_listener_filtered_out(self, mock_client):
        elb = MagicMock()
        elb.get_paginator.side_effect = lambda op: {
            "describe_load_balancers": _paginator_returning([{
                "LoadBalancers": [{"LoadBalancerArn": "arn:lb:1", "LoadBalancerName": "demo-alb"}]
            }]),
            "describe_listeners": _paginator_returning([{
                "Listeners": [{"ListenerArn": "arn:l:1", "Port": 80, "Protocol": "HTTP"}]
            }]),
        }[op]
        elb.describe_tags.return_value = {"TagDescriptions": []}
        mock_client.return_value = elb

        assets = discover_alb_listeners()
        assert assets == []

    @patch("tls_scanner.scan_alb.boto3.client")
    def test_no_load_balancers_returns_empty(self, mock_client):
        elb = MagicMock()
        elb.get_paginator.return_value = _paginator_returning([{"LoadBalancers": []}])
        mock_client.return_value = elb
        assert discover_alb_listeners() == []

    @patch("tls_scanner.scan_alb.boto3.client")
    def test_describe_tags_failure_does_not_crash(self, mock_client):
        elb = MagicMock()
        elb.get_paginator.side_effect = lambda op: {
            "describe_load_balancers": _paginator_returning([{
                "LoadBalancers": [{"LoadBalancerArn": "arn:lb:1", "LoadBalancerName": "demo-alb"}]
            }]),
            "describe_listeners": _paginator_returning([{
                "Listeners": [{"ListenerArn": "arn:l:1", "Port": 443, "Protocol": "HTTPS",
                               "SslPolicy": "x"}]
            }]),
        }[op]
        elb.describe_tags.side_effect = Exception("AccessDenied")
        elb.describe_ssl_policies.return_value = {"SslPolicies": []}
        mock_client.return_value = elb

        assets = discover_alb_listeners()
        assert len(assets) == 1
        assert assets[0].environment is None


class TestComputeMigrationDiff:
    def test_already_pq_short_circuits(self, tmp_path):
        asset = make_asset(is_post_quantum=True, ssl_policy_name=TARGET_PQ_POLICY)
        result = compute_migration_diff(asset, str(tmp_path))
        assert result.status == "already_pq"

    def test_no_tf_files_requires_manual_review(self, tmp_path):
        asset = make_asset()
        result = compute_migration_diff(asset, str(tmp_path))
        assert result.status == "manual_review_required"
        assert "No .tf files" in result.reason

    def test_single_unambiguous_listener_produces_ok_diff(self, tmp_path):
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(VALID_TF_CONTENT)
        asset = make_asset()
        result = compute_migration_diff(asset, str(tmp_path))
        assert result.status == "ok"
        assert result.current_policy == "ELBSecurityPolicy-TLS13-1-2-2021-06"
        assert result.target_policy == TARGET_PQ_POLICY
        assert TARGET_PQ_POLICY in result.diff
        assert "ELBSecurityPolicy-TLS13-1-2-2021-06" in result.diff

    def test_diff_changes_only_ssl_policy_line(self, tmp_path):
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(VALID_TF_CONTENT)
        asset = make_asset()
        result = compute_migration_diff(asset, str(tmp_path))
        assert result.status == "ok"

        changed_lines = [
            l for l in result.diff.splitlines()
            if (l.startswith("+") or l.startswith("-"))
            and not l.startswith("+++") and not l.startswith("---")
        ]
        assert len(changed_lines) == 2
        removed = [l for l in changed_lines if l.startswith("-")][0]
        added = [l for l in changed_lines if l.startswith("+")][0]
        assert "ssl_policy" in removed
        assert "ssl_policy" in added
        assert "port" not in removed and "port" not in added
        assert "certificate_arn" not in removed and "certificate_arn" not in added

    def test_ambiguous_multiple_listeners_requires_manual_review(self, tmp_path):
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(AMBIGUOUS_TF_CONTENT)
        asset = make_asset(lb_name="something-not-in-either-resource-name")
        result = compute_migration_diff(asset, str(tmp_path))
        assert result.status == "manual_review_required"
        assert "manual review" in result.reason.lower() or "Manual review" in result.reason

    def test_ambiguous_listeners_narrowed_by_lb_name_match(self, tmp_path):
        tf_content = """resource "aws_lb_listener" "frontend_demo_alb" {
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

resource "aws_lb_listener" "backend_other_alb" {
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}
"""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(tf_content)
        asset = make_asset(lb_name="demo-alb")
        result = compute_migration_diff(asset, str(tmp_path))
        assert result.status == "ok"
        assert "frontend_demo_alb" in result.resource_address

    def test_no_ssl_policy_attribute_requires_manual_review(self, tmp_path):
        tf_content = 'resource "aws_lb_listener" "x" {\n  port = 443\n}\n'
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(tf_content)
        asset = make_asset()
        result = compute_migration_diff(asset, str(tmp_path))
        assert result.status == "manual_review_required"
        assert "ssl_policy" in result.reason

    def test_already_at_target_policy_in_file(self, tmp_path):
        tf_content = VALID_TF_CONTENT.replace(
            "ELBSecurityPolicy-TLS13-1-2-2021-06", TARGET_PQ_POLICY
        )
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(tf_content)
        asset = make_asset()
        result = compute_migration_diff(asset, str(tmp_path))
        assert result.status == "already_pq"

    def test_no_listener_resources_at_all(self, tmp_path):
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('resource "aws_s3_bucket" "x" {}\n')
        asset = make_asset()
        result = compute_migration_diff(asset, str(tmp_path))
        assert result.status == "manual_review_required"


class TestProdGating:
    """Protects the single most important safety property: production
    listeners are never touched without explicit, typed confirmation."""

    def test_prod_listener_blocked_by_default(self, tmp_path):
        asset = make_asset(environment="prod")
        result = run_migration(asset, str(tmp_path), "owner/repo", dry_run=True)
        assert result.status == "prod_blocked"

    def test_prod_listener_blocked_even_with_allow_prod_but_no_token(self, tmp_path):
        asset = make_asset(environment="prod")
        result = run_migration(asset, str(tmp_path), "owner/repo", dry_run=True, allow_prod=True)
        assert result.status == "prod_blocked"

    def test_prod_listener_blocked_with_wrong_token(self, tmp_path):
        asset = make_asset(environment="prod")
        result = run_migration(
            asset, str(tmp_path), "owner/repo", dry_run=True,
            allow_prod=True, prod_token="wrong-token",
        )
        assert result.status == "prod_blocked"

    def test_prod_listener_proceeds_with_correct_token(self, tmp_path):
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(VALID_TF_CONTENT)
        asset = make_asset(environment="prod")
        result = run_migration(
            asset, str(tmp_path), "owner/repo", dry_run=True,
            allow_prod=True, prod_token=PROD_CONFIRMATION_TOKEN,
        )
        assert result.status == "dry_run"

    def test_token_is_case_sensitive(self, tmp_path):
        asset = make_asset(environment="prod")
        result = run_migration(
            asset, str(tmp_path), "owner/repo", dry_run=True,
            allow_prod=True, prod_token=PROD_CONFIRMATION_TOKEN.lower(),
        )
        assert result.status == "prod_blocked"

    def test_non_prod_environments_not_gated(self, tmp_path):
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(VALID_TF_CONTENT)
        for env in ["staging", "dev", "dmz", None, "PROD-LIKE"]:
            asset = make_asset(environment=env)
            result = run_migration(asset, str(tmp_path), "owner/repo", dry_run=True)
            assert result.status == "dry_run", f"environment={env} should not be gated"

    def test_prod_case_insensitive_match(self, tmp_path):
        for env_value in ["PROD", "Prod", "prod"]:
            asset = make_asset(environment=env_value)
            result = run_migration(asset, str(tmp_path), "owner/repo", dry_run=True)
            assert result.status == "prod_blocked", f"'{env_value}' should be gated"


class TestRunMigration:
    def test_already_pq_short_circuits_no_pr(self, tmp_path):
        asset = make_asset(is_post_quantum=True)
        result = run_migration(asset, str(tmp_path), "owner/repo", dry_run=False)
        assert result.status == "already_pq"

    def test_manual_review_required_propagates(self, tmp_path):
        asset = make_asset()
        result = run_migration(asset, str(tmp_path), "owner/repo", dry_run=True)
        assert result.status == "manual_review"
        assert result.reason

    def test_dry_run_does_not_call_github(self, tmp_path):
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(VALID_TF_CONTENT)
        asset = make_asset()
        with patch("tls_migration.run.open_migration_pr") as mock_pr:
            result = run_migration(asset, str(tmp_path), "owner/repo", dry_run=True)
            mock_pr.assert_not_called()
        assert result.status == "dry_run"
        assert result.pr_url is None
        assert result.diff is not None
        assert result.pr_body_preview is not None
        assert "Cryptiq will not merge" in result.pr_body_preview

    def test_live_run_calls_github_and_returns_pr_info(self, tmp_path):
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(VALID_TF_CONTENT)
        asset = make_asset()
        from tls_migration.github_pr import PRResult
        fake_pr = PRResult(
            pr_url="https://github.com/owner/repo/pull/42", pr_number=42,
            branch="cryptiq/migrate-demo-alb-443", repo="owner/repo",
        )
        with patch("tls_migration.run.open_migration_pr", return_value=fake_pr) as mock_pr:
            result = run_migration(asset, str(tmp_path), "owner/repo", dry_run=False)
            mock_pr.assert_called_once()
        assert result.status == "pr_opened"
        assert result.pr_url == "https://github.com/owner/repo/pull/42"
        assert result.pr_number == 42

    def test_pr_body_contains_required_disclosure(self, tmp_path):
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(VALID_TF_CONTENT)
        asset = make_asset()
        result = run_migration(asset, str(tmp_path), "owner/repo", dry_run=True)
        assert "will not merge" in result.pr_body_preview.lower()

    def test_pr_body_embeds_original_policy_metadata(self, tmp_path):
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(VALID_TF_CONTENT)
        asset = make_asset()
        result = run_migration(asset, str(tmp_path), "owner/repo", dry_run=True)
        assert "cryptiq-metadata" in result.pr_body_preview
        assert "original_policy=ELBSecurityPolicy-TLS13-1-2-2021-06" in result.pr_body_preview

    def test_branch_name_is_safe_and_bounded(self, tmp_path):
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(VALID_TF_CONTENT)
        asset = make_asset(lb_name="My_Weird-LB.Name", port=8443)
        result = run_migration(asset, str(tmp_path), "owner/repo", dry_run=True)
        assert len(result.pr_branch) <= 60
        assert result.pr_branch == result.pr_branch.lower()
        assert "_" not in result.pr_branch


class TestNeverMergesOrDeletes:
    """github_pr.py is the sole chokepoint for GitHub writes. The REAL
    implementation hard-enforces this via _ALLOWED_OPERATIONS + _assert_allowed,
    which raises PermissionError for anything outside
    {branch_create, commit, open_pr}."""

    def test_allowed_operations_excludes_merge(self):
        from tls_migration.github_pr import _ALLOWED_OPERATIONS
        assert "merge" not in _ALLOWED_OPERATIONS
        assert not any("merge" in op for op in _ALLOWED_OPERATIONS)

    def test_allowed_operations_excludes_delete(self):
        from tls_migration.github_pr import _ALLOWED_OPERATIONS
        assert "delete" not in _ALLOWED_OPERATIONS
        assert not any("delete" in op for op in _ALLOWED_OPERATIONS)

    def test_allowed_operations_excludes_force_push(self):
        from tls_migration.github_pr import _ALLOWED_OPERATIONS
        assert not any("force" in op for op in _ALLOWED_OPERATIONS)

    def test_assert_not_merge_raises_for_disallowed_operation(self):
        from tls_migration.github_pr import assert_not_merge
        with pytest.raises(PermissionError, match="not allowed"):
            assert_not_merge("merge_pull_request")

    def test_assert_not_merge_allows_open_pr(self):
        from tls_migration.github_pr import assert_not_merge
        assert_not_merge("open_pr")  # should not raise

    def test_module_has_no_merge_function(self):
        """assert_not_merge() is the safety GUARD itself -- its name
        contains "merge" as a deliberate naming choice (it asserts
        something is NOT a merge), so exclude it explicitly rather than
        flagging it as a violation."""
        import tls_migration.github_pr as gh
        public_names = [n for n in dir(gh) if not n.startswith("_")]
        merge_like = [n for n in public_names if "merge" in n.lower() and n != "assert_not_merge"]
        assert merge_like == [], f"Found merge-capable function(s): {merge_like}"

    def test_module_has_no_delete_function(self):
        import tls_migration.github_pr as gh
        public_names = [n for n in dir(gh) if not n.startswith("_")]
        delete_like = [n for n in public_names if "delete" in n.lower()]
        assert delete_like == [], f"Found delete-capable function(s): {delete_like}"

    @patch("tls_migration.github_pr.Github")
    def test_open_migration_pr_never_calls_merge(self, mock_github_cls):
        from tls_migration.github_pr import open_migration_pr
        mock_repo = MagicMock()
        mock_branch = MagicMock()
        mock_branch.commit.sha = "abc123"
        mock_repo.get_branch.return_value = mock_branch
        from github import GithubException
        fake_404 = GithubException(404, "not found", None)
        mock_repo.get_contents.side_effect = fake_404  # forces create_file path (real code catches GithubException with status==404)
        mock_pr = MagicMock()
        mock_pr.html_url = "https://github.com/owner/repo/pull/1"
        mock_pr.number = 1
        mock_repo.create_pull.return_value = mock_pr
        mock_github_cls.return_value.get_repo.return_value = mock_repo

        open_migration_pr(
            repo_full_name="owner/repo", base_branch="main", new_branch="cryptiq/x",
            file_path="main.tf", new_file_content="content",
            pr_title="title", pr_body="body", label=None, github_token="fake-token",
        )
        mock_pr.merge.assert_not_called()

    @patch("tls_migration.github_pr.Github")
    def test_open_migration_pr_raises_without_token(self, mock_github_cls, monkeypatch):
        from tls_migration.github_pr import open_migration_pr
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        with pytest.raises(EnvironmentError, match="GITHUB_TOKEN"):
            open_migration_pr(
                repo_full_name="owner/repo", base_branch="main", new_branch="x",
                file_path="f.tf", new_file_content="c", pr_title="t", pr_body="b",
                github_token=None,
            )

    @patch("tls_migration.github_pr.Github")
    def test_creates_branch_from_base_sha_only(self, mock_github_cls):
        from tls_migration.github_pr import open_migration_pr
        mock_repo = MagicMock()
        mock_branch = MagicMock()
        mock_branch.commit.sha = "base-sha-xyz"
        mock_repo.get_branch.return_value = mock_branch
        from github import GithubException
        mock_repo.get_contents.side_effect = GithubException(404, "not found", None)
        mock_pr = MagicMock(html_url="url", number=1)
        mock_repo.create_pull.return_value = mock_pr
        mock_github_cls.return_value.get_repo.return_value = mock_repo

        open_migration_pr(
            repo_full_name="owner/repo", base_branch="main", new_branch="cryptiq/x",
            file_path="main.tf", new_file_content="c", pr_title="t", pr_body="b",
            label=None, github_token="fake",
        )
        mock_repo.get_branch.assert_called_with("main")
        mock_repo.create_git_ref.assert_called_once_with(
            ref="refs/heads/cryptiq/x", sha="base-sha-xyz"
        )


class TestRollbackNeverGuesses:
    """Rollback must source the original ssl_policy from the migration PR's
    metadata block, never infer/guess a value. Uses the REAL
    extract_metadata_from_pr_body() / compute_rollback_diff() contracts."""

    def test_extracts_original_policy_from_valid_metadata(self):
        pr_body = (
            "Some PR text\n\n"
            "<!-- cryptiq-metadata\n"
            "original_policy=ELBSecurityPolicy-TLS13-1-2-2021-06\n"
            "listener_arn=arn:aws:x\n"
            "-->\n"
        )
        meta = extract_metadata_from_pr_body(pr_body)
        assert meta.get("original_policy") == "ELBSecurityPolicy-TLS13-1-2-2021-06"

    def test_missing_metadata_block_returns_empty_dict(self):
        assert extract_metadata_from_pr_body("just some regular PR text, no metadata") == {}

    def test_malformed_metadata_block_has_no_original_policy_key(self):
        pr_body = "<!-- cryptiq-metadata\nsomething_else=value\n-->"
        meta = extract_metadata_from_pr_body(pr_body)
        assert "original_policy" not in meta

    def test_run_rollback_errors_when_metadata_missing(self, tmp_path):
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(VALID_TF_CONTENT)
        asset = make_asset()
        result = run_rollback(
            asset=asset, migration_pr_body="no metadata here at all",
            migration_pr_number=42, tf_file=str(tf_file),
            gh_repo="owner/repo", dry_run=True,
        )
        assert result.status == "error"
        assert "original_policy" in result.reason or "metadata" in result.reason.lower()

    def test_run_rollback_dry_run_restores_correct_value(self, tmp_path):
        tf_content = VALID_TF_CONTENT.replace(
            "ELBSecurityPolicy-TLS13-1-2-2021-06", TARGET_PQ_POLICY
        )
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(tf_content)
        asset = make_asset(ssl_policy_name=TARGET_PQ_POLICY, is_post_quantum=True)
        pr_body = (
            "<!-- cryptiq-metadata\n"
            "original_policy=ELBSecurityPolicy-TLS13-1-2-2021-06\n"
            "-->\n"
        )
        result = run_rollback(
            asset=asset, migration_pr_body=pr_body, migration_pr_number=1,
            tf_file=str(tf_file), gh_repo="owner/repo", dry_run=True,
        )
        assert result.status == "dry_run"
        assert result.original_policy == "ELBSecurityPolicy-TLS13-1-2-2021-06"

    def test_run_rollback_current_policy_not_found_in_file(self, tmp_path):
        """compute_rollback_diff returns None if the asset's claimed
        current_policy string isn't actually present in the tf file --
        this must surface as an error, not a silent no-op."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(VALID_TF_CONTENT)  # has the CLASSICAL policy, not PQ
        asset = make_asset(ssl_policy_name=TARGET_PQ_POLICY)  # claims PQ is current -- mismatch
        pr_body = "<!-- cryptiq-metadata\noriginal_policy=SomeOtherPolicy\n-->"
        result = run_rollback(
            asset=asset, migration_pr_body=pr_body, migration_pr_number=1,
            tf_file=str(tf_file), gh_repo="owner/repo", dry_run=True,
        )
        assert result.status == "error"

    def test_compute_rollback_diff_returns_none_when_policy_absent(self, tmp_path):
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(VALID_TF_CONTENT)
        result = compute_rollback_diff(
            str(tf_file), current_policy="NonExistentPolicyName", original_policy="X"
        )
        assert result is None

    def test_migrate_then_rollback_round_trip_is_exact(self, tmp_path):
        """The single most important rollback test: file must be
        byte-identical to the original after migrate + rollback."""
        tf_file = tmp_path / "main.tf"
        original_content = VALID_TF_CONTENT
        tf_file.write_text(original_content)
        asset = make_asset()

        migration = compute_migration_diff(asset, str(tmp_path))
        assert migration.status == "ok"

        from tls_migration.alb_plan import _SSL_POLICY_RE
        migrated_content = _SSL_POLICY_RE.sub(
            lambda m: m.group(1) + TARGET_PQ_POLICY + m.group(2),
            original_content, count=1,
        )
        tf_file.write_text(migrated_content)
        assert TARGET_PQ_POLICY in tf_file.read_text()
        assert "ELBSecurityPolicy-TLS13-1-2-2021-06" not in tf_file.read_text()

        pr_body = f"<!-- cryptiq-metadata\noriginal_policy={migration.current_policy}\n-->"
        rollback_asset = make_asset(ssl_policy_name=TARGET_PQ_POLICY, is_post_quantum=True)
        rollback_result = run_rollback(
            asset=rollback_asset, migration_pr_body=pr_body, migration_pr_number=1,
            tf_file=str(tf_file), gh_repo="owner/repo", dry_run=True,
        )
        assert rollback_result.status == "dry_run"
        assert rollback_result.original_policy == "ELBSecurityPolicy-TLS13-1-2-2021-06"

        restored_content = _SSL_POLICY_RE.sub(
            lambda m: m.group(1) + rollback_result.original_policy + m.group(2),
            tf_file.read_text(), count=1,
        )
        assert restored_content == original_content


class TestAuditLog:
    def test_log_appends_jsonl_entry(self, tmp_path, monkeypatch):
        log_file = tmp_path / "audit" / "audit.log"
        monkeypatch.setenv("CRYPTIQ_AUDIT_LOG", str(log_file))
        audit.log(action="migrate", target="arn:x", outcome="dry_run")
        entries = audit.read_log()
        assert len(entries) == 1
        assert entries[0]["action"] == "migrate"
        assert entries[0]["outcome"] == "dry_run"
        assert "timestamp" in entries[0]
        assert "actor" in entries[0]

    def test_log_is_append_only_across_calls(self, tmp_path, monkeypatch):
        log_file = tmp_path / "audit" / "audit.log"
        monkeypatch.setenv("CRYPTIQ_AUDIT_LOG", str(log_file))
        audit.log(action="plan", target="arn:1", outcome="success")
        audit.log(action="migrate", target="arn:1", outcome="dry_run")
        audit.log(action="rollback", target="arn:1", outcome="pr_opened")
        entries = audit.read_log()
        assert len(entries) == 3
        assert [e["action"] for e in entries] == ["plan", "migrate", "rollback"]

    def test_read_log_respects_limit(self, tmp_path, monkeypatch):
        log_file = tmp_path / "audit" / "audit.log"
        monkeypatch.setenv("CRYPTIQ_AUDIT_LOG", str(log_file))
        for i in range(10):
            audit.log(action="test", target=f"arn:{i}", outcome="success")
        entries = audit.read_log(limit=3)
        assert len(entries) == 3
        assert entries[-1]["target"] == "arn:9"

    def test_read_log_missing_file_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CRYPTIQ_AUDIT_LOG", str(tmp_path / "nonexistent" / "audit.log"))
        assert audit.read_log() == []

    def test_full_migrate_and_rollback_cycle_is_audited(self, tmp_path, monkeypatch):
        log_file = tmp_path / "audit" / "audit.log"
        monkeypatch.setenv("CRYPTIQ_AUDIT_LOG", str(log_file))
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(VALID_TF_CONTENT)
        asset = make_asset()
        run_migration(asset, str(tmp_path), "owner/repo", dry_run=True)
        entries = audit.read_log()
        actions = [e["action"] for e in entries]
        assert "plan" in actions
        assert "migrate" in actions


class TestAlbCbom:
    def test_cbom_structure(self):
        assets = [make_asset()]
        cbom = convert_alb_to_cbom(assets)
        assert cbom["bomFormat"] == "CycloneDX"
        assert len(cbom["components"]) == 1

    def test_pq_asset_gets_level_1(self):
        """NOTE: the real alb_cbom.py maps is_post_quantum -> level 1
        (not level 3 like the TLS/AWS scanners use) -- a # VERIFY tag
        in the source notes this mapping needs confirming against the
        CycloneDX 1.6 spec. Documents actual behavior."""
        asset = make_asset(is_post_quantum=True)
        component = build_alb_component(asset)
        assert component["cryptoProperties"]["nistQuantumSecurityLevel"] == 1

    def test_vulnerable_asset_gets_level_0(self):
        asset = make_asset(is_post_quantum=False)
        component = build_alb_component(asset)
        assert component["cryptoProperties"]["nistQuantumSecurityLevel"] == 0

    def test_empty_asset_list(self):
        cbom = convert_alb_to_cbom([])
        assert cbom["components"] == []

    def test_component_includes_listener_arn_property(self):
        asset = make_asset()
        component = build_alb_component(asset)
        prop_names = [p["name"] for p in component["properties"]]
        assert "listener_arn" in prop_names
        assert "ssl_policy" in prop_names

    def test_component_has_bom_ref(self):
        asset = make_asset()
        component = build_alb_component(asset)
        assert component["bom-ref"] == asset.listener_arn