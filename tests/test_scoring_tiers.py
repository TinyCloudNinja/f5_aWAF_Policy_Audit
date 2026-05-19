"""
Pytest coverage for the tiered scoring model and circuit breaker logic.

Changelog: Added regression tests for the 4-tier compliance scoring, circuit
breaker capping, and deduction weights across WAF and Bot Defense comparators.
"""

from __future__ import annotations

from typing import Dict, Tuple

import pytest

from src.policy_comparator import compare_policies
from src.bot_defense_comparator import compare_bot_profiles
from src.utils import TIER_RED, TIER_AMBER, TIER_YELLOW, TIER_GREEN


def _make_policy_pair(
    *,
    baseline_enforcement: str = "blocking",
    target_enforcement: str = "blocking",
    sig_count: int = 0,
    disabled_sig_count: int = 0,
    target_blocking_enabled: bool = True,
    data_guard_baseline: bool = True,
    data_guard_target: bool = True,
    ipi_enabled_baseline: bool = True,
    ipi_enabled_target: bool = True,
) -> Tuple[Dict, Dict]:
    """Build baseline/target policy dicts for comparator tests.

    Keeps collections aligned to avoid incidental missing/extra diffs while
    allowing targeted drift (signatures disabled, blocking flags flipped, etc.).
    """

    disabled_ids = {i for i in range(1, disabled_sig_count + 1)}

    def _attack_sig(sig_id: int, enabled: bool) -> Dict:
        return {
            "signatureId": sig_id,
            "enabled": enabled,
            "performStaging": False,
        }

    baseline = {
        "general": {"enforcementMode": baseline_enforcement},
        "blocking-settings": {
            "violations": [
                {"name": "VIOL_HTTP", "alarm": True, "block": True, "learn": False},
            ],
            "evasions": [],
            "http-protocols": [],
        },
        "signature-sets": [
            {"name": "Default", "alarm": True, "block": True, "learn": False},
        ],
        "attack-signatures": [
            _attack_sig(sig_id, True) for sig_id in range(1, sig_count + 1)
        ],
        "data-guard": {
            "enabled": data_guard_baseline,
            "creditCardNumbers": True,
            "socialSecurityNumbers": True,
        },
        "ip-intelligence": {
            "enabled": ipi_enabled_baseline,
            "categories": [
                {"name": "Botnets", "alarm": True, "block": True},
            ],
        },
    }

    target = {
        "general": {"enforcementMode": target_enforcement},
        "blocking-settings": {
            "violations": [
                {"name": "VIOL_HTTP", "alarm": True, "block": target_blocking_enabled, "learn": False},
            ],
            "evasions": [],
            "http-protocols": [],
        },
        "signature-sets": [
            {"name": "Default", "alarm": True, "block": target_blocking_enabled, "learn": False},
        ],
        "attack-signatures": [
            _attack_sig(sig_id, sig_id not in disabled_ids)
            for sig_id in range(1, sig_count + 1)
        ],
        "data-guard": {
            "enabled": data_guard_target,
            "creditCardNumbers": True,
            "socialSecurityNumbers": True,
        },
        "ip-intelligence": {
            "enabled": ipi_enabled_target,
            "categories": [
                {"name": "Botnets", "alarm": True, "block": ipi_enabled_target},
            ],
        },
    }

    return baseline, target


def _make_bot_profile(*, enabled: bool = True) -> Tuple[Dict, Dict, Dict]:
    """Return (baseline, target, meta) bot profiles with aligned collections."""

    baseline = {
        "fullPath": "/Common/bot_profile",
        "name": "bot_profile",
        "enforcementMode": "blocking",
        "enabled": True,
        "signatures": [{"name": "CategoryA", "enabled": True, "action": "block"}],
        "browsers": [{"name": "BrowserA", "enabled": True}],
    }
    target = {
        "fullPath": "/Common/bot_profile",
        "name": "bot_profile",
        "enforcementMode": "blocking",
        "enabled": enabled,
        "signatures": [{"name": "CategoryA", "enabled": True, "action": "block"}],
        "browsers": [{"name": "BrowserA", "enabled": True}],
    }
    meta = {"fullPath": "/Common/bot_profile", "name": "bot_profile"}
    return baseline, target, meta


# ---------------------------------------------------------------------------
# WAF comparator scenarios
# ---------------------------------------------------------------------------


def test_blocking_no_findings_green_100():
    baseline, target = _make_policy_pair()
    result = compare_policies(baseline, target)
    assert result.score == 100.0
    assert result.tier == TIER_GREEN


def test_blocking_5_disabled_signatures_green_90():
    baseline, target = _make_policy_pair(sig_count=5, disabled_sig_count=5)
    result = compare_policies(baseline, target)
    assert result.score == 90.0
    assert result.tier == TIER_GREEN


def test_blocking_15_disabled_signatures_amber_70():
    baseline, target = _make_policy_pair(sig_count=15, disabled_sig_count=15)
    result = compare_policies(baseline, target)
    assert result.score == 70.0
    assert result.tier == TIER_AMBER


def test_blocking_data_guard_off_with_sig_changes_amber_72():
    baseline, target = _make_policy_pair(
        sig_count=10,
        disabled_sig_count=10,
        data_guard_baseline=True,
        data_guard_target=False,
    )
    result = compare_policies(baseline, target)
    assert result.score == 72.0
    assert result.tier == TIER_AMBER


def test_transparent_perfect_capped_red_49():
    baseline, target = _make_policy_pair(
        baseline_enforcement="transparent",
        target_enforcement="transparent",
        sig_count=0,
        disabled_sig_count=0,
    )
    result = compare_policies(baseline, target)
    assert result.is_hard_fail is True
    assert result.raw_score == 100.0
    assert result.score == 49.0
    assert result.tier == TIER_RED


def test_transparent_with_extra_findings_capped_below_49():
    baseline, target = _make_policy_pair(
        baseline_enforcement="transparent",
        target_enforcement="transparent",
        sig_count=20,
        disabled_sig_count=20,
        data_guard_target=False,
        ipi_enabled_target=False,
    )
    result = compare_policies(baseline, target)
    assert result.is_hard_fail is True
    assert result.raw_score < 49.0
    assert result.score == result.raw_score  # raw already below cap
    assert result.tier == TIER_RED


def test_blocking_all_blocking_flags_off_capped_red_49():
    baseline, target = _make_policy_pair(target_blocking_enabled=False)
    result = compare_policies(baseline, target)
    assert result.is_hard_fail is True
    assert result.score == 49.0
    assert result.tier == TIER_RED


def test_blocking_three_crit_five_warn_score_66_amber():
    baseline, target = _make_policy_pair(
        sig_count=5,
        disabled_sig_count=5,
        target_blocking_enabled=True,
    )

    # Inject three critical drifts without tripping circuit breakers:
    # 1-2) Data Guard sub-attributes weakened
    target["data-guard"]["creditCardNumbers"] = False
    target["data-guard"]["socialSecurityNumbers"] = False
    # 3) IP Intelligence category block disabled (feature still enabled)
    target["ip-intelligence"]["categories"][0]["block"] = False

    result = compare_policies(baseline, target)
    assert result.is_hard_fail is False
    assert result.score == 66.0
    assert result.tier == TIER_AMBER


def test_blocking_single_warning_score_98_green():
    baseline, target = _make_policy_pair(sig_count=1, disabled_sig_count=1)
    result = compare_policies(baseline, target)
    assert result.score == 98.0
    assert result.tier == TIER_GREEN


# ---------------------------------------------------------------------------
# Bot Defense comparator scenario
# ---------------------------------------------------------------------------


def test_bot_profile_disabled_capped_red_49():
    baseline, target, meta = _make_bot_profile(enabled=False)
    result = compare_bot_profiles(baseline, target, profile_meta=meta)
    assert result.is_hard_fail is True
    assert result.score == 49.0
    assert result.tier == TIER_RED


if __name__ == "__main__":
    pytest.main([__file__])