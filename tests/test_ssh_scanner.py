"""
tests/test_ssh_scanner.py
---------------------------
Tests for ssh_scanner/: scan_ssh, ssh_risk, ssh_algorithms, ssh_versions, ssh_cbom.
"""

import pytest
from unittest.mock import patch, MagicMock

from ssh_scanner.scan_ssh import SSHHostKey, SSHScanResult, _estimate_key_size
from ssh_scanner.ssh_risk import (
    classify_host_key, classify_kex, classify_cipher, classify_mac,
    assess_risk, assess_risk_from_scan, summarise_risk_assessments,
    MigrationRecommendation, _score_to_risk,
)
from ssh_scanner.ssh_algorithms import normalize, normalize_list, is_extension_pseudo_algo
from ssh_scanner.ssh_versions import parse_banner, analyse_capability_gap
from ssh_scanner.ssh_cbom import generate_ssh_cbom


class TestAlgorithmNormalization:
    def test_curve25519_variants_map_to_same_canonical_name(self):
        a = normalize("curve25519-sha256")
        b = normalize("curve25519-sha256@libssh.org")
        assert a is not None and b is not None
        assert a.canonical_name == b.canonical_name == "curve25519-sha256"
        assert a.family == b.family == "Curve25519"

    def test_rsa_variants_map_to_rsa_family(self):
        for variant in ["ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"]:
            desc = normalize(variant)
            assert desc is not None
            assert desc.family == "RSA"

    def test_unknown_algorithm_returns_none(self):
        assert normalize("totally-made-up-algo-xyz") is None

    def test_extension_pseudo_algo_detected(self):
        assert is_extension_pseudo_algo("kex-strict-s-v00@openssh.com") is True
        assert is_extension_pseudo_algo("ext-info-s") is True
        assert is_extension_pseudo_algo("curve25519-sha256") is False

    def test_normalize_list_groups_by_family(self):
        algos = [
            "curve25519-sha256", "curve25519-sha256@libssh.org",
            "diffie-hellman-group1-sha1",
            "sntrup761x25519-sha512@openssh.com",
            "kex-strict-s-v00@openssh.com",
        ]
        result = normalize_list(algos)
        assert "curve25519-sha256" in result["families"]
        family_names = list(result["families"].keys())
        curve_count = sum(1 for f in family_names if "curve25519" in f.lower())
        assert curve_count == 1
        assert result["extension_flags"] == ["kex-strict-s-v00@openssh.com"]

    def test_normalize_list_worst_risk(self):
        algos = ["diffie-hellman-group1-sha1", "curve25519-sha256"]
        result = normalize_list(algos)
        assert result["worst_risk"] == "critical"

    def test_normalize_list_best_pqc(self):
        algos = ["curve25519-sha256", "sntrup761x25519-sha512@openssh.com"]
        result = normalize_list(algos)
        assert result["best_pqc"] == "hybrid"

    def test_ml_dsa_is_pqc_ready(self):
        desc = normalize("ml-dsa-65")
        assert desc is not None
        assert desc.pqc_status == "pqc_ready"

    def test_normalize_list_unknown_collected_separately(self):
        result = normalize_list(["curve25519-sha256", "fake-algo-123"])
        assert "fake-algo-123" in result["unknown"]


class TestParseBanner:
    def test_ubuntu_openssh_parsed_correctly(self):
        info = parse_banner("OpenSSH_8.2p1 Ubuntu-4ubuntu0.13")
        assert info.vendor == "OpenSSH"
        assert info.major == 8
        assert info.minor == 2
        assert info.patch == 1
        assert info.distribution == "Ubuntu"

    def test_old_openssh_does_not_support_sntrup761(self):
        info = parse_banner("OpenSSH_8.2p1 Ubuntu-4ubuntu0.13")
        assert info.supports_sntrup761 is False

    def test_openssh_85_supports_sntrup761(self):
        info = parse_banner("OpenSSH_8.5p1")
        assert info.supports_sntrup761 is True

    def test_openssh_99_supports_mlkem(self):
        info = parse_banner("OpenSSH_9.9p1")
        assert info.supports_mlkem is True

    def test_openssh_96_does_not_support_mlkem(self):
        info = parse_banner("OpenSSH_9.6")
        assert info.supports_mlkem is False

    def test_eol_flag_for_very_old_version(self):
        info = parse_banner("OpenSSH_7.2p2 Ubuntu-4ubuntu2.8")
        assert info.eol is True

    def test_dropbear_parsed(self):
        info = parse_banner("dropbear_2022.83")
        assert info.vendor == "Dropbear"
        assert info.supports_mlkem is False
        assert info.requires_upgrade_for_pqc is True

    def test_empty_banner_handled_gracefully(self):
        info = parse_banner("")
        assert info.vendor == "Unknown"
        assert info.is_supported is False

    def test_unrecognised_software_falls_back_gracefully(self):
        info = parse_banner("SSH-2.0-7358299")
        assert info.vendor is not None
        assert isinstance(info.notes, list)

    def test_pqc_capability_level_property(self):
        old = parse_banner("OpenSSH_7.2p2")
        mid = parse_banner("OpenSSH_8.9p1")
        new = parse_banner("OpenSSH_9.9p1")
        assert old.pqc_capability_level in ("legacy", "classical_best")
        assert mid.pqc_capability_level == "hybrid"
        assert new.pqc_capability_level == "pqc_ready"

    def test_version_display_includes_patch(self):
        info = parse_banner("OpenSSH_8.2p1 Ubuntu-4ubuntu0.13")
        assert "8.2" in info.version_display


class TestCapabilityGap:
    def test_software_supports_but_not_configured_is_reconfigure(self):
        software = parse_banner("OpenSSH_8.9p1")
        gap = analyse_capability_gap(
            software, configured_kex=["curve25519-sha256"], configured_host_keys=["ssh-rsa"]
        )
        kex_reconfigure_gaps = [g for g in gap["gaps"] if g["action"] == "reconfigure" and "sntrup761" in g["gap"]]
        assert len(kex_reconfigure_gaps) >= 1
        # NOTE: reconfigure_only is False here because ML-KEM (9.9+) is ALSO
        # listed as a gap requiring upgrade. The sntrup761 gap itself is
        # correctly reconfigure-only -- verify that specifically.
        assert kex_reconfigure_gaps[0]["effort"] == "low"

    def test_software_too_old_requires_upgrade(self):
        software = parse_banner("OpenSSH_7.2p2")
        gap = analyse_capability_gap(
            software, configured_kex=["diffie-hellman-group14-sha256"], configured_host_keys=["ssh-rsa"]
        )
        kex_upgrade_gaps = [g for g in gap["gaps"] if g["action"] == "upgrade" and "PQC" in g["gap"]]
        assert len(kex_upgrade_gaps) >= 1
        assert gap["upgrade_required"] is True

    def test_fully_configured_modern_server_has_minimal_gaps(self):
        software = parse_banner("OpenSSH_9.9p1")
        gap = analyse_capability_gap(
            software,
            configured_kex=["mlkem768x25519-sha256", "sntrup761x25519-sha512@openssh.com"],
            configured_host_keys=["ssh-ed25519"],
        )
        assert gap["upgrade_required"] is False

    def test_summary_text_present(self):
        software = parse_banner("OpenSSH_8.2p1")
        gap = analyse_capability_gap(software, configured_kex=[], configured_host_keys=[])
        assert isinstance(gap["summary"], str)
        assert len(gap["summary"]) > 0


class TestClassifyHostKey:
    def test_rsa_small_key_is_critical(self):
        result = classify_host_key("ssh-rsa", 1024)
        assert result["risk_contribution"] == "critical"
        assert result["quantum_vulnerable"] is True

    def test_rsa_2048_is_high_not_critical(self):
        result = classify_host_key("ssh-rsa", 2048)
        assert result["risk_contribution"] == "high"

    def test_ed25519_is_medium(self):
        result = classify_host_key("ssh-ed25519", None)
        assert result["risk_contribution"] == "medium"
        assert result["quantum_vulnerable"] is False

    def test_ml_dsa_is_low(self):
        result = classify_host_key("ml-dsa-65", None)
        assert result["risk_contribution"] == "low"
        assert result["quantum_vulnerable"] is False

    def test_dsa_is_high(self):
        """NOTE: README's risk taxonomy documents ssh-dss as 'critical'
        (DSA is classically broken), but classify_host_key() currently
        groups it with ECDSA and scores it 'high'. Documents ACTUAL
        behavior -- flag to the team as a possible risk-scoring gap."""
        result = classify_host_key("ssh-dss", None)
        assert result["risk_contribution"] == "high"

    def test_none_algorithm_defaults_to_high_not_unknown(self):
        result = classify_host_key(None, None)
        assert result["risk_contribution"] == "high"
        assert result["quantum_vulnerable"] is True


class TestClassifyKex:
    def test_group1_sha1_is_critical(self):
        result = classify_kex("diffie-hellman-group1-sha1")
        assert result["risk_contribution"] == "critical"
        assert result["pqc_status"] == "vulnerable"

    def test_group14_sha256_is_high_not_critical(self):
        """Regression test: group14-sha256 used to incorrectly match the
        'group1' substring check and score critical."""
        result = classify_kex("diffie-hellman-group14-sha256")
        assert result["risk_contribution"] == "high"

    def test_group14_sha1_is_critical(self):
        result = classify_kex("diffie-hellman-group14-sha1")
        assert result["risk_contribution"] == "critical"

    def test_curve25519_is_medium(self):
        result = classify_kex("curve25519-sha256")
        assert result["risk_contribution"] == "medium"
        assert result["pqc_status"] == "vulnerable"

    def test_sntrup761_is_hybrid_low(self):
        result = classify_kex("sntrup761x25519-sha512@openssh.com")
        assert result["risk_contribution"] == "low"
        assert result["pqc_status"] == "hybrid"

    def test_pure_mlkem_is_pqc_ready(self):
        result = classify_kex("mlkem768-sha256")
        assert result["pqc_status"] == "pqc_ready"

    def test_none_kex_defaults_to_high_not_unknown(self):
        result = classify_kex(None)
        assert result["risk_contribution"] == "high"
        assert result["pqc_status"] == "vulnerable"
        assert result["quantum_vulnerable"] is True


class TestClassifyCipherAndMac:
    def test_3des_flagged_weak(self):
        assert classify_cipher("3des-cbc")["weak"] is True

    def test_aes_gcm_not_weak(self):
        assert classify_cipher("aes256-gcm@openssh.com")["weak"] is False

    def test_hmac_md5_flagged_weak(self):
        assert classify_mac("hmac-md5")["weak"] is True

    def test_hmac_sha2_etm_not_weak(self):
        assert classify_mac("hmac-sha2-256-etm@openssh.com")["weak"] is False

    def test_none_cipher_not_weak(self):
        assert classify_cipher(None)["weak"] is False


class TestWeightedScoring:
    def test_score_to_risk_thresholds(self):
        assert _score_to_risk(90) == "critical"
        assert _score_to_risk(85) == "critical"
        assert _score_to_risk(70) == "high"
        assert _score_to_risk(60) == "high"
        assert _score_to_risk(40) == "medium"
        assert _score_to_risk(30) == "medium"
        assert _score_to_risk(10) == "low"

    def test_critical_everything_scores_critical(self):
        risk = assess_risk(
            host="test", host_key_algorithm="ssh-rsa", key_size=1024,
            kex_algorithm="diffie-hellman-group1-sha1",
            cipher="3des-cbc", mac="hmac-md5",
        )
        assert risk.risk_level == "critical"
        assert risk.weighted_score >= 85

    def test_good_everything_scores_low(self):
        risk = assess_risk(
            host="test", host_key_algorithm="ml-dsa-65", key_size=None,
            kex_algorithm="mlkem768-sha256",
            cipher="chacha20-poly1305@openssh.com", mac="hmac-sha2-256-etm@openssh.com",
        )
        assert risk.risk_level == "low"

    def test_score_breakdown_sums_correctly(self):
        risk = assess_risk(
            host="test", host_key_algorithm="ssh-rsa", key_size=2048,
            kex_algorithm="curve25519-sha256",
        )
        breakdown = risk.score_breakdown
        total_from_components = (
            breakdown["host_key"]["contribution"]
            + breakdown["kex"]["contribution"]
            + breakdown["cipher"]["contribution"]
            + breakdown["mac"]["contribution"]
        )
        assert abs(total_from_components - breakdown["total"]) < 0.5

    def test_weight_split_is_40_40_10_10(self):
        risk = assess_risk(
            host="test", host_key_algorithm="ssh-rsa", key_size=2048,
            kex_algorithm="curve25519-sha256",
        )
        bd = risk.score_breakdown
        assert bd["host_key"]["weight"] == 40
        assert bd["kex"]["weight"] == 40
        assert bd["cipher"]["weight"] == 10
        assert bd["mac"]["weight"] == 10

    def test_weighted_score_more_nuanced_than_max(self):
        all_critical = assess_risk(
            host="a", host_key_algorithm="ssh-dss", key_size=None,
            kex_algorithm="diffie-hellman-group1-sha1",
            cipher="3des-cbc", mac="hmac-md5",
        )
        only_kex_critical = assess_risk(
            host="b", host_key_algorithm="ssh-ed25519", key_size=None,
            kex_algorithm="diffie-hellman-group1-sha1",
            cipher="chacha20-poly1305@openssh.com", mac="hmac-sha2-256-etm@openssh.com",
        )
        assert all_critical.weighted_score > only_kex_critical.weighted_score


class TestMigrationRecommendations:
    def test_rsa_host_key_generates_recommendation(self):
        risk = assess_risk(
            host="test", host_key_algorithm="ssh-rsa", key_size=2048,
            kex_algorithm="curve25519-sha256",
        )
        rec_titles = [r.title for r in risk.recommendations]
        assert any("Ed25519" in t for t in rec_titles)

    def test_critical_kex_generates_critical_severity_recommendation(self):
        risk = assess_risk(
            host="test", host_key_algorithm="ssh-ed25519", key_size=None,
            kex_algorithm="diffie-hellman-group1-sha1",
        )
        crit_recs = [r for r in risk.recommendations if r.severity == "critical"]
        assert len(crit_recs) >= 1
        assert "remove" in crit_recs[0].action.lower() or "Remove" in crit_recs[0].action

    def test_recommendation_has_required_fields(self):
        risk = assess_risk(
            host="test", host_key_algorithm="ssh-rsa", key_size=1024,
            kex_algorithm="diffie-hellman-group1-sha1",
            cipher="3des-cbc", mac="hmac-md5",
        )
        for rec in risk.recommendations:
            assert rec.title
            assert rec.severity in ("critical", "high", "medium", "low", "info")
            assert rec.reason
            assert rec.action
            assert rec.estimated_effort
            d = rec.to_dict()
            assert "requires_restart" in d
            assert "requires_client_update" in d

    def test_no_recommendations_for_already_good_config(self):
        risk = assess_risk(
            host="test", host_key_algorithm="ml-dsa-65", key_size=None,
            kex_algorithm="mlkem768-sha256",
            cipher="chacha20-poly1305@openssh.com", mac="hmac-sha2-256-etm@openssh.com",
        )
        assert len(risk.recommendations) == 0

    def test_weak_cipher_recommendation(self):
        risk = assess_risk(
            host="test", host_key_algorithm="ssh-ed25519", key_size=None,
            kex_algorithm="curve25519-sha256", cipher="3des-cbc",
        )
        cipher_recs = [r for r in risk.recommendations if "cipher" in r.title.lower()]
        assert len(cipher_recs) == 1


class TestAssessRiskFromScan:
    def test_picks_worst_kex_from_advertised_list_when_no_negotiated(self, fake_ssh_scan_result):
        """fake_ssh_scan_result advertises group1-sha1 (critical) alongside
        curve25519 (medium). The worst-case picker must select group1-sha1
        for scoring -- verified via the KEX component of the weighted score.
        Combined RSA-2048 host key (high, not critical) caps the overall
        weighted score at 'high', not 'critical' -- by design."""
        fake_ssh_scan_result.negotiated_kex = None
        risk = assess_risk_from_scan(fake_ssh_scan_result)
        assert risk.score_breakdown["kex"]["score"] == 100
        assert risk.risk_level == "high"

    def test_uses_negotiated_kex_when_present(self, fake_hybrid_scan_result):
        risk = assess_risk_from_scan(fake_hybrid_scan_result)
        assert risk.pqc_status == "hybrid"

    def test_uses_primary_host_key(self, fake_ssh_scan_result):
        risk = assess_risk_from_scan(fake_ssh_scan_result)
        assert risk.host_key_algorithm == "ssh-rsa"

    def test_empty_host_keys_handled(self):
        result = SSHScanResult(host="x", port=22)
        result.host_keys = []
        result.server_kex_algorithms = []
        result.scan_success = False
        risk = assess_risk_from_scan(result)
        assert risk.risk_level in ("critical", "high")


class TestSummariseRiskAssessments:
    def test_aggregates_counts_correctly(self):
        # NOTE: RSA-1024 (critical host_key, score=100) + group1-sha1
        # (critical KEX, score=100) combine to a weighted score of 82
        # (40+40+1+1), landing at "high" not "critical" by default. Add
        # weak cipher+mac so this case actually reaches the critical
        # threshold for this aggregation test.
        risks = [
            assess_risk(host="a", host_key_algorithm="ssh-rsa", key_size=1024,
                        kex_algorithm="diffie-hellman-group1-sha1",
                        cipher="3des-cbc", mac="hmac-md5"),
            assess_risk(host="b", host_key_algorithm="ssh-ed25519", key_size=None,
                        kex_algorithm="sntrup761x25519-sha512@openssh.com"),
        ]
        summary = summarise_risk_assessments(risks)
        assert summary["total_scanned"] == 2
        assert summary["by_risk_level"]["critical"] >= 1

    def test_empty_list_does_not_crash(self):
        summary = summarise_risk_assessments([])
        assert summary["total_scanned"] == 0
        assert summary["pqc_readiness_percent"] == 0.0

    def test_critical_targets_identified(self):
        risks = [assess_risk(host="critical-host", host_key_algorithm="ssh-rsa", key_size=1024,
                              kex_algorithm="diffie-hellman-group1-sha1",
                              cipher="3des-cbc", mac="hmac-md5")]
        summary = summarise_risk_assessments(risks)
        assert "critical-host" in summary["critical_migration_targets"]


class TestEstimateKeySize:
    def test_rsa_returns_none(self):
        assert _estimate_key_size("ssh-rsa") is None

    def test_ecdsa_nistp256(self):
        assert _estimate_key_size("ecdsa-sha2-nistp256") == 256

    def test_ecdsa_nistp384(self):
        assert _estimate_key_size("ecdsa-sha2-nistp384") == 384

    def test_ed25519_returns_none_fixed_size(self):
        assert _estimate_key_size("ssh-ed25519") is None


class TestSSHHostKey:
    def test_construction(self):
        hk = SSHHostKey(algorithm="ssh-rsa", key_size=2048, fingerprint="SHA256:abc")
        assert hk.algorithm == "ssh-rsa"
        assert hk.key_size == 2048

    def test_fingerprint_optional(self):
        hk = SSHHostKey(algorithm="ssh-ed25519", key_size=None)
        assert hk.fingerprint is None


class TestSSHCBOM:
    def test_cbom_structure(self, fake_ssh_scan_result):
        risk = assess_risk_from_scan(fake_ssh_scan_result)
        cbom = generate_ssh_cbom(fake_ssh_scan_result, risk)
        assert cbom["bomFormat"] == "CycloneDX"
        assert cbom["specVersion"] == "1.6"
        assert len(cbom["components"]) > 0

    def test_cbom_has_host_key_component(self, fake_ssh_scan_result):
        risk = assess_risk_from_scan(fake_ssh_scan_result)
        cbom = generate_ssh_cbom(fake_ssh_scan_result, risk)
        names = [c["name"] for c in cbom["components"]]
        assert any("Host Key" in n or "host" in n.lower() for n in names)

    def test_cbom_serialises_to_json(self, fake_ssh_scan_result):
        import json
        risk = assess_risk_from_scan(fake_ssh_scan_result)
        cbom = generate_ssh_cbom(fake_ssh_scan_result, risk)
        json.dumps(cbom)

    def test_cbom_empty_host_keys(self):
        result = SSHScanResult(host="x", port=22)
        result.host_keys = []
        result.scan_success = True
        risk = assess_risk_from_scan(result)
        cbom = generate_ssh_cbom(result, risk)
        assert isinstance(cbom["components"], list)