"""
Unit tests for src/policy_parser.py
"""
import sys
import os
from pathlib import Path

import pytest

# Allow running from repo root without installing the package
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.policy_parser import parse_policy, get_policy_metadata

FIXTURES = Path(__file__).parent / "fixtures"
BASELINE = str(FIXTURES / "baseline_policy.xml")
DRIFTED  = str(FIXTURES / "target_policy_drifted.xml")


class TestGetPolicyMetadata:
    def test_name(self):
        meta = get_policy_metadata(BASELINE)
        assert meta["name"] == "baseline_policy"

    def test_full_path(self):
        meta = get_policy_metadata(BASELINE)
        assert meta["fullPath"] == "/Common/baseline_policy"

    def test_description(self):
        meta = get_policy_metadata(BASELINE)
        assert "baseline" in meta["description"].lower()

    def test_missing_file(self):
        with pytest.raises(FileNotFoundError):
            get_policy_metadata("/nonexistent/path.xml")


class TestParseGeneral:
    def setup_method(self):
        self.policy = parse_policy(BASELINE)

    def test_enforcement_mode(self):
        assert self.policy["general"]["enforcementMode"] == "blocking"

    def test_signature_staging_false(self):
        assert self.policy["general"]["signatureStaging"] is False

    def test_mask_credit_card(self):
        assert self.policy["general"]["maskCreditCardNumbers"] is True

    def test_allowed_response_codes(self):
        codes = self.policy["general"]["allowedResponseCodes"]
        assert isinstance(codes, list)
        assert 200 in codes
        assert 404 in codes

    def test_enforcement_readiness_period(self):
        assert self.policy["general"]["enforcementReadinessPeriod"] == 7


class TestParseBlockingSettings:
    def setup_method(self):
        self.policy = parse_policy(BASELINE)
        self.bs = self.policy["blocking-settings"]

    def test_violations_parsed(self):
        assert len(self.bs["violations"]) == 3

    def test_violation_names(self):
        names = {v["name"] for v in self.bs["violations"]}
        assert "VIOL_ASM_COOKIE_MODIFIED" in names
        assert "VIOL_ATTACK_SIGNATURE" in names

    def test_violation_block_true(self):
        viol = next(v for v in self.bs["violations"] if v["name"] == "VIOL_ASM_COOKIE_MODIFIED")
        assert viol["block"] is True
        assert viol["alarm"] is True

    def test_evasions_parsed(self):
        assert len(self.bs["evasions"]) == 1
        assert self.bs["evasions"][0]["name"] == "Bad unescape"

    def test_http_protocols_parsed(self):
        assert len(self.bs["http-protocols"]) == 1


class TestParseAttackSignatures:
    def setup_method(self):
        self.policy = parse_policy(BASELINE)
        self.sigs = self.policy["attack-signatures"]

    def test_count(self):
        assert len(self.sigs) == 3

    def test_signature_id_is_int(self):
        for sig in self.sigs:
            assert isinstance(sig["signatureId"], int)

    def test_enabled_true(self):
        sig = next(s for s in self.sigs if s["signatureId"] == 200001470)
        assert sig["enabled"] is True

    def test_staging_false(self):
        sig = next(s for s in self.sigs if s["signatureId"] == 200001470)
        assert sig["performStaging"] is False


class TestParseSignatureSets:
    def setup_method(self):
        self.policy = parse_policy(BASELINE)
        self.sets = self.policy["signature-sets"]

    def test_count(self):
        assert len(self.sets) == 2

    def test_sql_injection_block(self):
        ss = next(s for s in self.sets if "SQL" in s["name"])
        assert ss["block"] is True


class TestParseURLs:
    def setup_method(self):
        self.policy = parse_policy(BASELINE)
        self.urls = self.policy["urls"]

    def test_count(self):
        assert len(self.urls) == 2

    def test_login_url(self):
        url = next(u for u in self.urls if u["name"] == "/login")
        assert url["isAllowed"] is True
        assert url["attackSignaturesCheck"] is True
        assert url["type"] == "explicit"

    def test_wildcard_url(self):
        url = next(u for u in self.urls if u["name"] == "/api/*")
        assert url["type"] == "wildcard"


class TestParseDataGuard:
    def setup_method(self):
        self.policy = parse_policy(BASELINE)
        self.dg = self.policy["data-guard"]

    def test_enabled(self):
        assert self.dg["enabled"] is True

    def test_credit_cards(self):
        assert self.dg["creditCardNumbers"] is True

    def test_ssn(self):
        assert self.dg["socialSecurityNumbers"] is True


class TestParseWhitelistIPs:
    def setup_method(self):
        self.policy = parse_policy(BASELINE)
        self.wl = self.policy["whitelist-ips"]

    def test_count(self):
        assert len(self.wl) == 1

    def test_ip_address(self):
        assert self.wl[0]["ipAddress"] == "10.0.0.1"

    def test_trusted(self):
        assert self.wl[0]["trustedByPolicyBuilder"] is True


class TestParseBotDefense:
    def setup_method(self):
        self.policy = parse_policy(BASELINE)

    def test_enabled(self):
        assert self.policy["bot-defense"]["enabled"] is True


class TestParseDriftedPolicy:
    """Ensure the drifted fixture parses correctly (wrong values expected)."""

    def setup_method(self):
        self.policy = parse_policy(DRIFTED)

    def test_enforcement_mode_transparent(self):
        assert self.policy["general"]["enforcementMode"] == "transparent"

    def test_viol_cookie_block_false(self):
        viol = next(
            v for v in self.policy["blocking-settings"]["violations"]
            if v["name"] == "VIOL_ASM_COOKIE_MODIFIED"
        )
        assert viol["block"] is False

    def test_sig_470_disabled(self):
        sig = next(
            s for s in self.policy["attack-signatures"]
            if s["signatureId"] == 200001470
        )
        assert sig["enabled"] is False

    def test_data_guard_disabled(self):
        assert self.policy["data-guard"]["enabled"] is False

    def test_bot_defense_disabled(self):
        assert self.policy["bot-defense"]["enabled"] is False


class TestParseBlockingSection:
    """Tests for the newer <blocking> section parser."""

    def setup_method(self):
        self.baseline = parse_policy(BASELINE)
        self.drifted  = parse_policy(DRIFTED)
        self.bl_base  = self.baseline["blocking"]
        self.bl_drift = self.drifted["blocking"]

    # ── Section-level attributes ──────────────────────────────────────────────

    def test_section_present_in_baseline(self):
        assert self.bl_base != {}

    def test_baseline_enforcement_mode_blocking(self):
        assert self.bl_base["enforcement_mode"] == "blocking"

    def test_baseline_passive_mode(self):
        assert self.bl_base["passive_mode"] == "disabled"

    def test_drifted_enforcement_mode_transparent(self):
        assert self.bl_drift["enforcement_mode"] == "transparent"

    # ── Violation count ───────────────────────────────────────────────────────

    def test_baseline_violation_count(self):
        assert len(self.bl_base["violations"]) == 56

    def test_drifted_violation_count(self):
        assert len(self.bl_drift["violations"]) == 56

    # ── id and name attributes ────────────────────────────────────────────────

    def test_violation_has_id(self):
        ids = {v["id"] for v in self.bl_base["violations"]}
        assert "ILLEGAL_SOAP_ATTACHMENT" in ids
        assert "RESPONSE_SCRUBBING" in ids
        assert "EVASION_DETECTED" in ids

    def test_violation_has_name(self):
        # name = canonical machine ID (used as comparator join key)
        viol = next(v for v in self.bl_base["violations"] if v["id"] == "VIRUS_DETECTED")
        assert viol["name"] == "VIRUS_DETECTED"

    def test_violation_has_description(self):
        # description = human-readable label for display
        viol = next(v for v in self.bl_base["violations"] if v["id"] == "VIRUS_DETECTED")
        assert viol["description"] == "Virus detected"

    # ── alarm / block / learn flags ───────────────────────────────────────────

    def test_response_scrubbing_baseline_block_true(self):
        viol = next(v for v in self.bl_base["violations"] if v["id"] == "RESPONSE_SCRUBBING")
        assert viol["block"] is True
        assert viol["alarm"] is True
        assert viol["learn"] is True

    def test_illegal_soap_all_false(self):
        viol = next(v for v in self.bl_base["violations"] if v["id"] == "ILLEGAL_SOAP_ATTACHMENT")
        assert viol["alarm"] is False
        assert viol["block"] is False
        assert viol["learn"] is False

    def test_virus_detected_baseline_block_true(self):
        viol = next(v for v in self.bl_base["violations"] if v["id"] == "VIRUS_DETECTED")
        assert viol["block"] is True

    # ── policyBuilderTracking ─────────────────────────────────────────────────

    def test_policy_builder_tracking_parsed(self):
        viol = next(v for v in self.bl_base["violations"] if v["id"] == "RESPONSE_SCRUBBING")
        assert viol["policyBuilderTracking"] is True

    # ── Drifted values ────────────────────────────────────────────────────────

    def test_drifted_response_scrubbing_block_false(self):
        viol = next(v for v in self.bl_drift["violations"] if v["id"] == "RESPONSE_SCRUBBING")
        assert viol["block"] is False

    def test_drifted_request_too_long_block_false(self):
        viol = next(v for v in self.bl_drift["violations"] if v["id"] == "REQUEST_TOO_LONG")
        assert viol["block"] is False
        assert viol["alarm"] is False

    def test_drifted_virus_detected_block_false(self):
        viol = next(v for v in self.bl_drift["violations"] if v["id"] == "VIRUS_DETECTED")
        assert viol["block"] is False
