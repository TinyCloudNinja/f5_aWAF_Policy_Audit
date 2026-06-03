"""
Tests for the Bot Defense posture scorer (src/bot_defense_scorer.py).

Covers:
- All three hard triggers (NO_VIRTUAL_SERVERS, BOT_TRANSPARENT_MODE, BOT_NO_TEETH)
- All standalone posture signals
- Drift detection (loosening only; tightening ignored)
- No-baseline path (no penalty, Monitor-level note surfaced)
- Score capping by hard trigger
- Contributing factors sorted largest deduction first
"""
from __future__ import annotations

from typing import Dict, List, Optional
import pytest

from src.bot_defense_comparator import _canonical_override_entry
from src.bot_defense_scorer import (
    score_bot_profile,
    _detect_no_teeth,
    _detect_browser_mitigation_weak,
    _detect_dos_anomaly_alarm_only,
    _detect_api_strict_off,
    _detect_staged_signatures,
    _detect_cross_domain_permissive,
    _detect_mobile_sdk_loose,
    _detect_template_relaxed,
    _detect_deviceid_weak,
    _detect_grace_period_extended,
    _detect_challenge_transparent_off,
    _is_loosening_bot_diff,
    _bot_drift_category,
    _HIGH_RISK_BOT_CLASSES,
    _BLOCKING_ACTIONS,
)
from src.policy_comparator import DiffItem, Severity
from src.utils import TIER_RED, TIER_AMBER, TIER_YELLOW, TIER_GREEN


# ---------------------------------------------------------------------------
# Test profile builder helpers
# ---------------------------------------------------------------------------

def _blocking_profile(**overrides) -> Dict:
    """Minimal healthy Bot Defense profile (blocking, no issues)."""
    base = {
        "fullPath": "/Common/test_bot",
        "name": "test_bot",
        "enforcementMode": "blocking",
        "template": "balanced",
        "browserMitigationAction": "block",
        "dosAttackStrictMitigation": True,
        "apiAccessStrictMitigation": True,
        "crossDomainRequests": "validate-origin",
        "deviceidMode": "generate-if-session-not-present",
        "performChallengeInTransparent": True,
        "gracePeriod": 300,
        "mobileDetection": {
            "allowJailbrokenDevices": False,
            "allowAndroidRootedDevice": False,
            "allowEmulators": False,
            "allowAnyAndroidPackage": False,
            "allowAnyIosPackage": False,
            "blockDebuggerEnabledDevice": True,
        },
        "classOverridesReference": {"items": []},
        "whitelistReference": {"items": []},
        "stagedSignaturesReference": {"items": []},
        "anomalyOverridesReference": {"items": []},
        "anomalyCategoryOverridesReference": {"items": []},
    }
    base.update(overrides)
    return base


def _meta(name: str = "test_bot", path: str = "/Common/test_bot") -> Dict:
    return {"name": name, "fullPath": path}


def _vs_list(attached: bool = True) -> List[Dict]:
    if attached:
        return [{"name": "vs_1", "fullPath": "/Common/vs_1"}]
    return []


def _class_overrides(*entries) -> Dict:
    """Build classOverridesReference with given (className, action) pairs."""
    items = [{"className": cls, "action": act} for cls, act in entries]
    return {"classOverridesReference": {"items": items}}


def _staged_sigs(count: int) -> Dict:
    return {"stagedSignaturesReference": {"items": [{"name": f"sig_{i}"} for i in range(count)]}}


# ---------------------------------------------------------------------------
# Hard trigger: NO_VIRTUAL_SERVERS
# ---------------------------------------------------------------------------

class TestHardTriggerNoVirtualServers:
    def test_fires_when_vs_list_empty(self):
        """Empty vs_list with vs_eval performed → Review Now."""
        target = _blocking_profile()
        result = score_bot_profile(
            target=target, vs_list=[], profile_meta=_meta()
        )
        assert result.has_hard_triggers is True
        assert result.score <= 39
        assert result.tier == TIER_RED
        assert any("virtual server" in lbl.lower() for lbl in result.circuit_breakers_triggered)

    def test_does_not_fire_when_vs_attached(self):
        """Non-empty vs_list → NO_VIRTUAL_SERVERS does not fire."""
        target = _blocking_profile()
        result = score_bot_profile(
            target=target, vs_list=_vs_list(attached=True), profile_meta=_meta()
        )
        assert "NO_VIRTUAL_SERVERS" not in result.circuit_breakers_triggered
        assert not any("not attached" in lbl.lower() for lbl in result.circuit_breakers_triggered)

    def test_does_not_fire_when_vs_eval_not_performed(self):
        """vs_list=None means VS enrichment was not attempted — trigger must not fire."""
        target = _blocking_profile()
        result = score_bot_profile(
            target=target, vs_list=None, profile_meta=_meta()
        )
        assert result.virtual_server_eval_performed is False
        assert not any("virtual server" in lbl.lower() for lbl in result.circuit_breakers_triggered)


# ---------------------------------------------------------------------------
# Hard trigger: BOT_TRANSPARENT_MODE
# ---------------------------------------------------------------------------

class TestHardTriggerTransparentMode:
    def test_fires_for_transparent(self):
        target = _blocking_profile(enforcementMode="transparent")
        result = score_bot_profile(
            target=target, vs_list=_vs_list(), profile_meta=_meta()
        )
        assert result.has_hard_triggers is True
        assert result.score <= 39
        assert result.tier == TIER_RED
        assert any("transparent" in lbl.lower() for lbl in result.circuit_breakers_triggered)

    def test_does_not_fire_for_blocking(self):
        target = _blocking_profile(enforcementMode="blocking")
        result = score_bot_profile(
            target=target, vs_list=_vs_list(), profile_meta=_meta()
        )
        assert not any("transparent" in lbl.lower() for lbl in result.circuit_breakers_triggered)

    def test_score_still_computed_when_triggered(self):
        """Score is computed normally even when a hard trigger fires; final_score is capped."""
        target = _blocking_profile(
            enforcementMode="transparent",
            browserMitigationAction="alarm",
            dosAttackStrictMitigation=False,
        )
        result = score_bot_profile(
            target=target, vs_list=_vs_list(), profile_meta=_meta()
        )
        assert result.raw_score <= 100
        assert result.score <= 39


# ---------------------------------------------------------------------------
# Hard trigger: BOT_NO_TEETH
# ---------------------------------------------------------------------------

class TestHardTriggerNoTeeth:
    def test_fires_when_all_high_risk_overrides_alarm(self):
        target = _blocking_profile(
            **_class_overrides(
                ("malicious-bot", "alarm"),
                ("dos-tool", "alarm"),
            )
        )
        result = score_bot_profile(
            target=target, vs_list=_vs_list(), profile_meta=_meta()
        )
        assert result.has_hard_triggers is True
        assert result.score <= 39
        assert any("no teeth" in lbl.lower() or "alarm" in lbl.lower()
                   for lbl in result.circuit_breakers_triggered)

    def test_fires_when_all_high_risk_overrides_none(self):
        target = _blocking_profile(**_class_overrides(("scanner", "none")))
        assert _detect_no_teeth(target) is True

    def test_does_not_fire_when_one_override_is_blocking(self):
        """One block action among high-risk overrides is enough — no trigger."""
        target = _blocking_profile(
            **_class_overrides(
                ("malicious-bot", "alarm"),
                ("scanner", "block"),
            )
        )
        assert _detect_no_teeth(target) is False

    def test_does_not_fire_when_no_class_overrides_configured(self):
        """No class overrides → template default applies; trigger must not fire."""
        target = _blocking_profile()
        assert _detect_no_teeth(target) is False

    def test_captcha_action_prevents_trigger(self):
        target = _blocking_profile(**_class_overrides(("malicious-bot", "captcha")))
        assert _detect_no_teeth(target) is False

    def test_rate_limit_action_prevents_trigger(self):
        target = _blocking_profile(**_class_overrides(("dos-tool", "rate-limit")))
        assert _detect_no_teeth(target) is False

    def test_does_not_fire_for_low_risk_class_only(self):
        """Override on a non-high-risk class (e.g. 'search-engine-bot') doesn't trigger."""
        target = _blocking_profile(
            **_class_overrides(("search-engine-bot", "alarm"))
        )
        assert _detect_no_teeth(target) is False


# ---------------------------------------------------------------------------
# Multiple hard triggers simultaneously
# ---------------------------------------------------------------------------

def test_multiple_hard_triggers_all_reported():
    """Transparent mode + no VS: both triggers reported, score ≤ 39."""
    target = _blocking_profile(enforcementMode="transparent")
    result = score_bot_profile(
        target=target, vs_list=[], profile_meta=_meta()
    )
    assert result.has_hard_triggers is True
    assert result.score <= 39
    assert len(result.circuit_breakers_triggered) >= 2


# ---------------------------------------------------------------------------
# Standalone signal: browser_mitigation_weak
# ---------------------------------------------------------------------------

class TestStandaloneBrowserMitigationWeak:
    def test_flags_alarm_action(self):
        target = _blocking_profile(browserMitigationAction="alarm")
        assert _detect_browser_mitigation_weak(target) is True

    def test_flags_none_action(self):
        target = _blocking_profile(browserMitigationAction="none")
        assert _detect_browser_mitigation_weak(target) is True

    def test_does_not_flag_block(self):
        target = _blocking_profile(browserMitigationAction="block")
        assert _detect_browser_mitigation_weak(target) is False

    def test_does_not_flag_captcha(self):
        target = _blocking_profile(browserMitigationAction="captcha")
        assert _detect_browser_mitigation_weak(target) is False

    def test_does_not_flag_absent_field(self):
        target = _blocking_profile()
        del target["browserMitigationAction"]
        assert _detect_browser_mitigation_weak(target) is False

    def test_deduction_appears_in_factors(self):
        target = _blocking_profile(
            browserMitigationAction="alarm", enforcementMode="blocking"
        )
        result = score_bot_profile(
            target=target, vs_list=_vs_list(), profile_meta=_meta()
        )
        categories = [f["category"] for f in result.contributing_factors]
        assert "browser_mitigation_weak" in categories
        deduction = next(
            f["deduction"] for f in result.contributing_factors
            if f["category"] == "browser_mitigation_weak"
        )
        assert deduction > 0


# ---------------------------------------------------------------------------
# Standalone signal: dos_anomaly_alarm_only
# ---------------------------------------------------------------------------

class TestStandaloneDoSAnomalyAlarmOnly:
    def test_flags_dos_strict_mitigation_false(self):
        target = _blocking_profile(dosAttackStrictMitigation=False)
        assert _detect_dos_anomaly_alarm_only(target) is True

    def test_does_not_flag_dos_strict_mitigation_true(self):
        target = _blocking_profile(dosAttackStrictMitigation=True)
        assert _detect_dos_anomaly_alarm_only(target) is False

    def test_flags_all_anomaly_overrides_detect_only(self):
        target = _blocking_profile()
        target["anomalyOverridesReference"] = {
            "items": [
                {"name": "anomaly_1", "action": "alarm"},
                {"name": "anomaly_2", "action": "none"},
            ]
        }
        assert _detect_dos_anomaly_alarm_only(target) is True

    def test_does_not_flag_when_one_anomaly_blocks(self):
        target = _blocking_profile()
        target["anomalyOverridesReference"] = {
            "items": [
                {"name": "anomaly_1", "action": "alarm"},
                {"name": "anomaly_2", "action": "block"},
            ]
        }
        assert _detect_dos_anomaly_alarm_only(target) is False


# ---------------------------------------------------------------------------
# Standalone signal: api_strict_mitigation_off
# ---------------------------------------------------------------------------

class TestStandaloneApiStrictOff:
    def test_flags_when_false(self):
        target = _blocking_profile(apiAccessStrictMitigation=False)
        assert _detect_api_strict_off(target) is True

    def test_does_not_flag_when_true(self):
        target = _blocking_profile(apiAccessStrictMitigation=True)
        assert _detect_api_strict_off(target) is False

    def test_does_not_flag_when_absent(self):
        target = _blocking_profile()
        del target["apiAccessStrictMitigation"]
        assert _detect_api_strict_off(target) is False


# ---------------------------------------------------------------------------
# Standalone signal: staged_signatures
# ---------------------------------------------------------------------------

class TestStandaloneStagedSignatures:
    def test_counts_staged_signatures(self):
        target = _blocking_profile(**_staged_sigs(5))
        assert _detect_staged_signatures(target) == 5

    def test_zero_when_none_staged(self):
        target = _blocking_profile()
        assert _detect_staged_signatures(target) == 0

    def test_deduction_capped_at_max(self):
        target = _blocking_profile(**_staged_sigs(50))
        result = score_bot_profile(
            target=target, vs_list=_vs_list(), profile_meta=_meta()
        )
        staged_factor = next(
            (f for f in result.contributing_factors if f["category"] == "staged_signatures"),
            None,
        )
        assert staged_factor is not None
        assert staged_factor["deduction"] <= 10  # max_deduction from config


# ---------------------------------------------------------------------------
# Standalone signal: cross_domain_permissive
# ---------------------------------------------------------------------------

class TestStandaloneCrossDomainPermissive:
    def test_flags_allow_all(self):
        target = _blocking_profile(crossDomainRequests="allow-all")
        assert _detect_cross_domain_permissive(target) is True

    def test_flags_allow_all_underscored(self):
        target = _blocking_profile(crossDomainRequests="allow_all")
        assert _detect_cross_domain_permissive(target) is True

    def test_does_not_flag_validate_origin(self):
        target = _blocking_profile(crossDomainRequests="validate-origin")
        assert _detect_cross_domain_permissive(target) is False


# ---------------------------------------------------------------------------
# Standalone signal: mobile_sdk_loose
# ---------------------------------------------------------------------------

class TestStandaloneMobileSdkLoose:
    def test_flags_jailbroken_allowed(self):
        target = _blocking_profile()
        target["mobileDetection"]["allowJailbrokenDevices"] = True
        flags = _detect_mobile_sdk_loose(target)
        assert any("jailbroken" in f.lower() for f in flags)

    def test_flags_emulators_allowed(self):
        target = _blocking_profile()
        target["mobileDetection"]["allowEmulators"] = True
        flags = _detect_mobile_sdk_loose(target)
        assert any("emulator" in f.lower() for f in flags)

    def test_flags_debugger_not_blocked(self):
        target = _blocking_profile()
        target["mobileDetection"]["blockDebuggerEnabledDevice"] = False
        flags = _detect_mobile_sdk_loose(target)
        assert any("debugger" in f.lower() for f in flags)

    def test_empty_when_all_secure(self):
        target = _blocking_profile()
        assert _detect_mobile_sdk_loose(target) == []

    def test_deduction_accumulates_per_flag(self):
        target = _blocking_profile()
        target["mobileDetection"]["allowJailbrokenDevices"] = True
        target["mobileDetection"]["allowEmulators"] = True
        result = score_bot_profile(
            target=target, vs_list=_vs_list(), profile_meta=_meta()
        )
        factor = next(
            (f for f in result.contributing_factors if f["category"] == "mobile_sdk_loose"),
            None,
        )
        assert factor is not None
        assert factor["deduction"] == 4  # 2 flags × 2 pts each


# ---------------------------------------------------------------------------
# Standalone signal: template_relaxed
# ---------------------------------------------------------------------------

class TestStandaloneTemplateRelaxed:
    def test_flags_relaxed_template(self):
        target = _blocking_profile(template="relaxed")
        assert _detect_template_relaxed(target) is True

    def test_does_not_flag_balanced(self):
        target = _blocking_profile(template="balanced")
        assert _detect_template_relaxed(target) is False

    def test_does_not_flag_strict(self):
        target = _blocking_profile(template="strict")
        assert _detect_template_relaxed(target) is False


# ---------------------------------------------------------------------------
# Standalone signal: deviceid_weak
# ---------------------------------------------------------------------------

class TestStandaloneDeviceidWeak:
    def test_flags_none_mode(self):
        target = _blocking_profile(deviceidMode="none")
        assert _detect_deviceid_weak(target) is True

    def test_flags_empty_mode(self):
        target = _blocking_profile(deviceidMode="")
        assert _detect_deviceid_weak(target) is True

    def test_flags_absent_mode(self):
        target = _blocking_profile()
        del target["deviceidMode"]
        assert _detect_deviceid_weak(target) is True

    def test_does_not_flag_generate_mode(self):
        target = _blocking_profile(deviceidMode="generate-if-session-not-present")
        assert _detect_deviceid_weak(target) is False


# ---------------------------------------------------------------------------
# Standalone signal: grace_period_extended
# ---------------------------------------------------------------------------

class TestStandaloneGracePeriodExtended:
    def test_flags_grace_period_over_threshold(self):
        target = _blocking_profile(gracePeriod=90_000)  # > 86_400 seconds
        assert _detect_grace_period_extended(target) is True

    def test_flags_enforcement_readiness_period_over_threshold(self):
        target = _blocking_profile(enforcementReadinessPeriod=100_000)
        assert _detect_grace_period_extended(target) is True

    def test_does_not_flag_short_grace_period(self):
        target = _blocking_profile(gracePeriod=300)
        assert _detect_grace_period_extended(target) is False

    def test_does_not_flag_when_fields_absent(self):
        target = _blocking_profile()
        assert _detect_grace_period_extended(target) is False


# ---------------------------------------------------------------------------
# Standalone signal: challenge_transparent_off
# ---------------------------------------------------------------------------

class TestStandaloneChallengeTransparentOff:
    def test_flags_when_false(self):
        target = _blocking_profile(performChallengeInTransparent=False)
        assert _detect_challenge_transparent_off(target) is True

    def test_does_not_flag_when_true(self):
        target = _blocking_profile(performChallengeInTransparent=True)
        assert _detect_challenge_transparent_off(target) is False

    def test_does_not_flag_when_absent(self):
        target = _blocking_profile()
        del target["performChallengeInTransparent"]
        assert _detect_challenge_transparent_off(target) is False


# ---------------------------------------------------------------------------
# Drift detection — loosening only
# ---------------------------------------------------------------------------

class TestDriftClassActionDowngrade:
    def _diff(self, baseline_action: str, target_action: str, section: str = "bot-defense.overrides.classOverrides") -> DiffItem:
        return DiffItem(
            section=section,
            section_category="overrides",
            element_name="malicious-bot",
            attribute="action",
            baseline_value=baseline_action,
            target_value=target_action,
            severity=Severity.CRITICAL.value,
            description="Class action changed.",
        )

    def test_block_to_alarm_is_loosening(self):
        diff = self._diff("block", "alarm")
        assert _is_loosening_bot_diff(diff) is True

    def test_block_to_none_is_loosening(self):
        diff = self._diff("block", "none")
        assert _is_loosening_bot_diff(diff) is True

    def test_alarm_to_block_is_tightening(self):
        diff = self._diff("alarm", "block")
        assert _is_loosening_bot_diff(diff) is False

    def test_captcha_to_alarm_is_loosening(self):
        diff = self._diff("captcha", "alarm")
        assert _is_loosening_bot_diff(diff) is True

    def test_class_override_maps_to_class_actions_category(self):
        diff = self._diff("block", "alarm")
        assert _bot_drift_category(diff) == "class_actions"

    def test_drift_with_baseline_deducts_score(self):
        healthy = _blocking_profile()
        drifted = dict(healthy)
        drifted["classOverridesReference"] = {
            "items": [{"className": "malicious-bot", "action": "alarm"}]
        }
        healthy["classOverridesReference"] = {
            "items": [{"className": "malicious-bot", "action": "block"}]
        }
        result = score_bot_profile(
            target=drifted,
            baseline=healthy,
            vs_list=_vs_list(),
            profile_meta=_meta(),
        )
        drift_factor = next(
            (f for f in result.contributing_factors if "class_actions" in f["category"]),
            None,
        )
        assert drift_factor is not None
        assert drift_factor["deduction"] > 0
        assert drift_factor["is_drift"] is True


class TestDriftWhitelistGrowth:
    def test_added_whitelist_entry_is_loosening(self):
        diff = DiffItem(
            section="bot-defense.whitelist",
            section_category="whitelist",
            element_name="10.0.0.1",
            attribute="present",
            baseline_value=False,
            target_value=True,
            severity=Severity.WARNING.value,
            description="Whitelist entry added.",
        )
        assert _is_loosening_bot_diff(diff) is True

    def test_removed_whitelist_entry_is_tightening(self):
        diff = DiffItem(
            section="bot-defense.whitelist",
            section_category="whitelist",
            element_name="10.0.0.1",
            attribute="present",
            baseline_value=True,
            target_value=False,
            severity=Severity.INFO.value,
            description="Whitelist entry removed.",
        )
        assert _is_loosening_bot_diff(diff) is False

    def test_whitelist_diff_maps_to_whitelist_category(self):
        diff = DiffItem(
            section="bot-defense.whitelist",
            section_category="whitelist",
            element_name="10.0.0.0",
            attribute="present",
            baseline_value=False,
            target_value=True,
            severity=Severity.WARNING.value,
            description="Whitelist entry added.",
        )
        assert _bot_drift_category(diff) == "whitelist"

    def test_whitelist_growth_deducts_with_baseline(self):
        healthy = _blocking_profile()
        drifted = dict(healthy)
        drifted["whitelistReference"] = {
            "items": [{"name": "bypass_entry", "ipAddress": "10.99.0.0", "ipMask": "255.0.0.0"}]
        }
        result = score_bot_profile(
            target=drifted,
            baseline=healthy,
            vs_list=_vs_list(),
            profile_meta=_meta(),
        )
        assert result.drift_summary["baselined"] is True
        whitelist_factor = next(
            (f for f in result.contributing_factors if "whitelist" in f["category"]),
            None,
        )
        assert whitelist_factor is not None
        assert whitelist_factor["deduction"] > 0


class TestDriftTighteningIgnored:
    def test_tightening_action_does_not_deduct(self):
        """alarm → block is tightening — score should not decrease."""
        healthy = _blocking_profile()
        drifted = dict(healthy)
        # Target is MORE restrictive: adds a class override that blocks
        drifted["classOverridesReference"] = {
            "items": [{"className": "malicious-bot", "action": "block"}]
        }
        healthy["classOverridesReference"] = {
            "items": [{"className": "malicious-bot", "action": "alarm"}]
        }
        result = score_bot_profile(
            target=drifted,
            baseline=healthy,
            vs_list=_vs_list(),
            profile_meta=_meta(),
        )
        assert result.drift_summary["baselined"] is True
        drift_factors = [f for f in result.contributing_factors if f.get("is_drift")]
        assert not drift_factors, "Tightening drift must not produce a deduction factor"


# ---------------------------------------------------------------------------
# No-baseline path
# ---------------------------------------------------------------------------

class TestNoBaseline:
    def test_no_penalty_when_no_baseline(self):
        """Standalone signals still apply; drift adds nothing when unbaselined."""
        target = _blocking_profile()
        result_with = score_bot_profile(
            target=target, baseline=target, vs_list=_vs_list(), profile_meta=_meta()
        )
        result_without = score_bot_profile(
            target=target, baseline=None, vs_list=_vs_list(), profile_meta=_meta()
        )
        assert result_without.score >= result_with.score

    def test_unbaselined_note_in_factors(self):
        target = _blocking_profile()
        result = score_bot_profile(
            target=target, baseline=None, vs_list=_vs_list(), profile_meta=_meta()
        )
        assert result.drift_baselined is False
        unbaselined = next(
            (f for f in result.contributing_factors if f["category"] == "drift_unbaselined"),
            None,
        )
        assert unbaselined is not None
        assert unbaselined["deduction"] == 0

    def test_note_does_not_use_failure_language(self):
        target = _blocking_profile()
        result = score_bot_profile(
            target=target, baseline=None, vs_list=_vs_list(), profile_meta=_meta()
        )
        unbaselined = next(
            f for f in result.contributing_factors if f["category"] == "drift_unbaselined"
        )
        combined = (unbaselined["label"] + unbaselined["description"] + unbaselined["remediation"]).lower()
        assert "fail" not in combined


# ---------------------------------------------------------------------------
# Score computation and band assignment
# ---------------------------------------------------------------------------

class TestScoreComputation:
    def test_healthy_profile_scores_near_100(self):
        target = _blocking_profile()
        result = score_bot_profile(
            target=target, vs_list=_vs_list(), profile_meta=_meta()
        )
        assert result.score >= 85
        assert result.tier == TIER_GREEN
        assert result.tier_label == "Aligned"

    def test_hard_trigger_caps_score_at_39(self):
        target = _blocking_profile(enforcementMode="transparent")
        result = score_bot_profile(
            target=target, vs_list=_vs_list(), profile_meta=_meta()
        )
        assert result.score <= 39
        assert result.tier == TIER_RED

    def test_hard_trigger_fires_even_when_raw_score_high(self):
        """raw_score may be high but final_score is capped by the hard trigger."""
        target = _blocking_profile(enforcementMode="transparent")
        result = score_bot_profile(
            target=target, vs_list=_vs_list(), profile_meta=_meta()
        )
        assert result.raw_score > result.score or result.raw_score <= 39

    def test_multiple_standalone_signals_accumulate(self):
        target = _blocking_profile(
            browserMitigationAction="alarm",
            dosAttackStrictMitigation=False,
            apiAccessStrictMitigation=False,
            template="relaxed",
        )
        result = score_bot_profile(
            target=target, vs_list=_vs_list(), profile_meta=_meta()
        )
        # 12 + 10 + 8 + 4 = 34 pts deduction → score = 66
        assert result.score < 85

    def test_review_soon_band(self):
        # Construct a profile that loses enough to land in AMBER without a trigger
        target = _blocking_profile(
            browserMitigationAction="alarm",     # −12
            dosAttackStrictMitigation=False,     # −10
            apiAccessStrictMitigation=False,     # −8
            template="relaxed",                  # −4
            crossDomainRequests="allow-all",     # −5
        )
        target["mobileDetection"]["allowJailbrokenDevices"] = True   # −2
        target["mobileDetection"]["allowEmulators"] = True           # −2
        target["mobileDetection"]["blockDebuggerEnabledDevice"] = False  # −2
        # Total standalone ≈ 45 → score ≈ 55 → Review Soon
        result = score_bot_profile(
            target=target, vs_list=_vs_list(), profile_meta=_meta()
        )
        assert 40 <= result.score <= 64
        assert result.tier == TIER_AMBER

    def test_drift_category_cap_limits_deduction(self):
        """Whitelist cap is 16; many whitelist diffs should not exceed it."""
        healthy = _blocking_profile()
        drifted = dict(healthy)
        drifted["whitelistReference"] = {
            "items": [{"name": f"entry_{i}", "ipAddress": f"10.{i}.0.0"} for i in range(30)]
        }
        result = score_bot_profile(
            target=drifted,
            baseline=healthy,
            vs_list=_vs_list(),
            profile_meta=_meta(),
        )
        total_whitelist_deduction = sum(
            f["deduction"] for f in result.contributing_factors
            if "whitelist" in f["category"] and f.get("is_drift")
        )
        assert total_whitelist_deduction <= 16


# ---------------------------------------------------------------------------
# Contributing factors ordering
# ---------------------------------------------------------------------------

class TestContributingFactors:
    def test_sorted_largest_deduction_first(self):
        target = _blocking_profile(
            browserMitigationAction="alarm",  # 12 pts
            template="relaxed",               # 4 pts
            crossDomainRequests="allow-all",  # 5 pts
        )
        result = score_bot_profile(
            target=target, vs_list=_vs_list(), profile_meta=_meta()
        )
        deductions = [f["deduction"] for f in result.contributing_factors]
        non_zero = [d for d in deductions if d > 0]
        assert non_zero == sorted(non_zero, reverse=True)

    def test_unbaselined_note_at_end(self):
        """Zero-deduction unbaselined note should come after all scoring factors."""
        target = _blocking_profile(browserMitigationAction="alarm")
        result = score_bot_profile(
            target=target, baseline=None, vs_list=_vs_list(), profile_meta=_meta()
        )
        last = result.contributing_factors[-1]
        assert last["category"] == "drift_unbaselined"
        assert last["deduction"] == 0

    def test_is_drift_flag_set_correctly(self):
        """Drift factors have is_drift=True; standalone factors have is_drift=False."""
        healthy = _blocking_profile()
        drifted = dict(healthy)
        drifted["classOverridesReference"] = {
            "items": [{"className": "malicious-bot", "action": "alarm"}]
        }
        healthy["classOverridesReference"] = {
            "items": [{"className": "malicious-bot", "action": "block"}]
        }
        drifted["browserMitigationAction"] = "alarm"

        result = score_bot_profile(
            target=drifted,
            baseline=healthy,
            vs_list=_vs_list(),
            profile_meta=_meta(),
        )
        drift_factors = [f for f in result.contributing_factors if f.get("is_drift")]
        standalone_factors = [
            f for f in result.contributing_factors
            if not f.get("is_drift") and f["category"] != "drift_unbaselined"
        ]
        assert drift_factors, "Expected at least one drift factor"
        assert standalone_factors, "Expected at least one standalone factor"


# ---------------------------------------------------------------------------
# "FAIL" language guard
# ---------------------------------------------------------------------------

def test_no_fail_language_anywhere():
    """The word 'fail' must not appear in any scorer output."""
    target = _blocking_profile(
        enforcementMode="transparent",
        browserMitigationAction="alarm",
    )
    result = score_bot_profile(
        target=target, baseline=None, vs_list=[], profile_meta=_meta()
    )

    all_text = " ".join([
        result.tier_label,
        " ".join(result.circuit_breakers_triggered),
        " ".join(
            f.get("label", "") + f.get("description", "") + f.get("remediation", "")
            for f in result.contributing_factors
        ),
        " ".join(result.drift_summary.get("loosening", [])),
    ])
    assert "fail" not in all_text.lower(), (
        f"'fail' found in scorer output: {all_text}"
    )


# ---------------------------------------------------------------------------
# Override entry noise-field stripping (regression: generation / selfLink
# false positives on semantically identical entries from different profiles)
# ---------------------------------------------------------------------------

class TestCanonicalOverrideEntry:
    """_canonical_override_entry strips API noise fields before comparison."""

    _WHITELIST_BASELINE = {
        "kind": "tm:security:bot-defense:profile:whitelist:whiteliststate",
        "name": "apple_touch_1",
        "fullPath": "apple_touch_1",
        "generation": 1002,
        "selfLink": "https://localhost/mgmt/tm/security/bot-defense/profile/~Common~BST_Bot_v1/whitelist/apple_touch_1?ver=17.5.1.5",
        "disableMitigation": "yes",
        "disableVerification": "yes",
        "matchOrder": 2,
        "sourceAddress": "::/32",
        "url": "/apple-touch-icon*.png",
    }
    _WHITELIST_TARGET = {
        "kind": "tm:security:bot-defense:profile:whitelist:whiteliststate",
        "name": "apple_touch_1",
        "fullPath": "apple_touch_1",
        "generation": 1022,
        "selfLink": "https://localhost/mgmt/tm/security/bot-defense/profile/~Common~app1.siterequest.com/whitelist/apple_touch_1?ver=17.5.1.5",
        "disableMitigation": "yes",
        "disableVerification": "yes",
        "matchOrder": 2,
        "sourceAddress": "::/32",
        "url": "/apple-touch-icon*.png",
    }

    def test_identical_semantic_content_compares_equal(self):
        """Entries that differ only in generation/selfLink must compare equal."""
        assert _canonical_override_entry(self._WHITELIST_BASELINE) == \
               _canonical_override_entry(self._WHITELIST_TARGET)

    def test_generation_stripped(self):
        assert "generation" not in _canonical_override_entry(self._WHITELIST_BASELINE)

    def test_selflink_stripped(self):
        assert "selfLink" not in _canonical_override_entry(self._WHITELIST_BASELINE)

    def test_kind_stripped(self):
        assert "kind" not in _canonical_override_entry(self._WHITELIST_BASELINE)

    def test_security_fields_preserved(self):
        canon = _canonical_override_entry(self._WHITELIST_BASELINE)
        assert canon["disableMitigation"] == "yes"
        assert canon["disableVerification"] == "yes"
        assert canon["sourceAddress"] == "::/32"
        assert canon["url"] == "/apple-touch-icon*.png"
        assert canon["name"] == "apple_touch_1"

    def test_no_false_positive_from_generation_drift(self):
        """Scoring two identical profiles must produce zero drift findings."""
        baseline = _blocking_profile()
        baseline["whitelistReference"] = {"items": [dict(self._WHITELIST_BASELINE)]}

        target = _blocking_profile()
        target["whitelistReference"] = {"items": [dict(self._WHITELIST_TARGET)]}

        result = score_bot_profile(
            target=target,
            baseline=baseline,
            vs_list=_vs_list(),
            profile_meta=_meta(),
        )
        drift_findings = [
            d for d in result.diffs
            if d.section == "bot-defense.overrides.whitelist"
            and d.attribute == "content"
        ]
        assert drift_findings == [], (
            "Whitelist entries identical except for generation/selfLink must "
            f"not produce drift findings. Got: {drift_findings}"
        )

    def test_real_content_change_still_detected(self):
        """A genuine field change (url differs) must still be reported."""
        baseline = _blocking_profile()
        baseline["whitelistReference"] = {"items": [dict(self._WHITELIST_BASELINE)]}

        changed = dict(self._WHITELIST_TARGET)
        changed["url"] = "/different-path.png"  # genuine change
        target = _blocking_profile()
        target["whitelistReference"] = {"items": [changed]}

        result = score_bot_profile(
            target=target,
            baseline=baseline,
            vs_list=_vs_list(),
            profile_meta=_meta(),
        )
        drift_findings = [
            d for d in result.diffs
            if d.section == "bot-defense.overrides.whitelist"
            and d.attribute == "content"
        ]
        assert drift_findings, "Changed url field must produce a drift finding"
