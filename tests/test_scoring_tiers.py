"""
Pytest coverage for the posture scoring model and hard-trigger logic.

Status ladder (new):
  Review Now  (TIER_RED)    0–39
  Review Soon (TIER_AMBER)  40–64
  Monitor     (TIER_YELLOW) 65–84
  Aligned     (TIER_GREEN)  85–100

Hard triggers (3) → force Review Now regardless of score:
  TRANSPARENT_MODE, NO_VIRTUAL_SERVERS, NO_SIGNATURE_SETS

ALL_BLOCKING_DISABLED and POLICY_DISABLED are high-weight standalone signals,
NOT hard triggers — they produce a deduction but do not force Review Now.
"""

from __future__ import annotations

from typing import Dict, Tuple

import pytest

from src.policy_comparator import compare_policies
from src.bot_defense_comparator import compare_bot_profiles
from src.utils import TIER_RED, TIER_AMBER, TIER_YELLOW, TIER_GREEN


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


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
    """Build baseline/target policy dicts for comparator tests."""

    disabled_ids = {i for i in range(1, disabled_sig_count + 1)}

    def _attack_sig(sig_id: int, enabled: bool) -> Dict:
        return {"signatureId": sig_id, "enabled": enabled, "performStaging": False}

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
            "categories": [{"name": "Botnets", "alarm": True, "block": True}],
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
            "categories": [{"name": "Botnets", "alarm": True, "block": ipi_enabled_target}],
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
# Aligned (TIER_GREEN) scenarios
# ---------------------------------------------------------------------------


def test_no_findings_aligned_100():
    """Perfect policy against itself — full score, Aligned."""
    baseline, target = _make_policy_pair()
    result = compare_policies(baseline, target)
    assert result.score == 100.0
    assert result.tier == TIER_GREEN
    assert result.tier_label == "Aligned"
    assert result.has_hard_triggers is False


def test_five_disabled_signatures_aligned_90():
    """5 disabled sigs × 2 pts = 10 deduction → score 90, still Aligned."""
    baseline, target = _make_policy_pair(sig_count=5, disabled_sig_count=5)
    result = compare_policies(baseline, target)
    assert result.score == 90.0
    assert result.tier == TIER_GREEN


def test_single_warning_aligned_98():
    """One disabled signature — 2-point deduction → score 98, Aligned."""
    baseline, target = _make_policy_pair(sig_count=1, disabled_sig_count=1)
    result = compare_policies(baseline, target)
    assert result.score == 98.0
    assert result.tier == TIER_GREEN


# ---------------------------------------------------------------------------
# Monitor (TIER_YELLOW) scenarios
# ---------------------------------------------------------------------------


def test_fifteen_disabled_signatures_monitor():
    """15 disabled sigs → 30 raw pts capped at 20 → score 80, Monitor.

    The signatures drift_category_cap of 20 prevents a single category from
    dominating the score (leniency principle).
    """
    baseline, target = _make_policy_pair(sig_count=15, disabled_sig_count=15)
    result = compare_policies(baseline, target)
    assert result.score == 80.0
    assert result.tier == TIER_YELLOW
    assert result.tier_label == "Monitor"


def test_data_guard_off_with_sig_changes_monitor():
    """10 disabled sigs (capped 20) + data-guard disabled (8) = 28 → score 72, Monitor."""
    baseline, target = _make_policy_pair(
        sig_count=10,
        disabled_sig_count=10,
        data_guard_baseline=True,
        data_guard_target=False,
    )
    result = compare_policies(baseline, target)
    assert result.score == 72.0
    assert result.tier == TIER_YELLOW


def test_three_critical_five_warn_monitor():
    """Mixed critical findings across categories — score 66, Monitor."""
    baseline, target = _make_policy_pair(sig_count=5, disabled_sig_count=5)
    # Data Guard sub-attributes weakened (data_guard category)
    target["data-guard"]["creditCardNumbers"] = False
    target["data-guard"]["socialSecurityNumbers"] = False
    # IP Intelligence category block disabled (ip_intelligence category)
    target["ip-intelligence"]["categories"][0]["block"] = False

    result = compare_policies(baseline, target)
    assert result.has_hard_triggers is False
    assert result.score == 66.0
    assert result.tier == TIER_YELLOW


# ---------------------------------------------------------------------------
# Hard triggers → Review Now (TIER_RED)
# ---------------------------------------------------------------------------


def test_transparent_mode_forces_review_now():
    """Transparent enforcement is a hard trigger — score capped at 39."""
    baseline, target = _make_policy_pair(
        baseline_enforcement="transparent",
        target_enforcement="transparent",
    )
    result = compare_policies(baseline, target)
    assert result.has_hard_triggers is True
    assert result.is_hard_fail is True          # backward-compat property
    assert result.raw_score == 100.0            # no other findings
    assert result.score == 39.0                 # hard_trigger_cap
    assert result.tier == TIER_RED
    assert result.tier_label == "Review Now"
    assert any("Transparent" in t for t in result.circuit_breakers_triggered)


def test_transparent_with_extra_findings_still_capped():
    """Hard trigger cap overrides even when raw score would be below cap."""
    baseline, target = _make_policy_pair(
        baseline_enforcement="transparent",
        target_enforcement="transparent",
        sig_count=20,
        disabled_sig_count=20,
        data_guard_target=False,
        ipi_enabled_target=False,
    )
    result = compare_policies(baseline, target)
    assert result.has_hard_triggers is True
    assert result.score <= 39.0
    assert result.tier == TIER_RED


def test_no_virtual_servers_forces_review_now():
    """Policy not attached to any VS is a hard trigger."""
    baseline, target = _make_policy_pair()
    result = compare_policies(
        baseline,
        target,
        virtual_servers=[],  # explicitly empty → eval performed with no VS
    )
    assert result.has_hard_triggers is True
    assert result.score <= 39.0
    assert result.tier == TIER_RED
    assert any("virtual server" in t.lower() for t in result.circuit_breakers_triggered)


def test_no_signature_sets_forces_review_now():
    """Removing all signature sets is a hard trigger."""
    baseline = {
        "general": {"enforcementMode": "blocking"},
        "blocking-settings": {"violations": [], "evasions": [], "http-protocols": []},
        "signature-sets": [{"name": "Default", "alarm": True, "block": True}],
        "attack-signatures": [],
        "data-guard": {"enabled": False},
        "ip-intelligence": {"enabled": False, "categories": []},
    }
    target = {
        "general": {"enforcementMode": "blocking"},
        "blocking-settings": {"violations": [], "evasions": [], "http-protocols": []},
        "signature-sets": [],   # removed all sets
        "attack-signatures": [],
        "data-guard": {"enabled": False},
        "ip-intelligence": {"enabled": False, "categories": []},
    }
    result = compare_policies(baseline, target)
    assert result.has_hard_triggers is True
    assert result.score <= 39.0
    assert result.tier == TIER_RED
    assert any("signature" in t.lower() for t in result.circuit_breakers_triggered)


# ---------------------------------------------------------------------------
# ALL_BLOCKING_DISABLED is a standalone signal, NOT a hard trigger
# ---------------------------------------------------------------------------


def test_all_blocking_disabled_is_signal_not_hard_trigger():
    """Disabling all blocking deducts points but does NOT force Review Now."""
    baseline, target = _make_policy_pair(target_blocking_enabled=False)
    result = compare_policies(baseline, target)
    # Should NOT trigger a hard trigger
    assert result.has_hard_triggers is False
    # Should NOT be Review Now purely because of blocking disabled
    assert result.tier != TIER_RED
    # The blocking_disabled standalone signal must appear in contributing factors
    blocking_factor = next(
        (f for f in result.contributing_factors if f["category"] == "blocking_disabled"),
        None,
    )
    assert blocking_factor is not None, "blocking_disabled should appear in contributing_factors"
    assert blocking_factor["deduction"] > 0


# ---------------------------------------------------------------------------
# Drift direction filtering
# ---------------------------------------------------------------------------


def test_tightening_drift_does_not_reduce_score():
    """Moving a violation from alarm-only to blocking is tightening — no deduction."""
    baseline = {
        "general": {"enforcementMode": "blocking"},
        "blocking-settings": {
            "violations": [{"name": "VIOL_HTTP", "alarm": True, "block": False, "learn": False}],
            "evasions": [],
            "http-protocols": [],
        },
        "signature-sets": [{"name": "Default", "alarm": True, "block": True}],
        "attack-signatures": [],
        "data-guard": {"enabled": False},
        "ip-intelligence": {"enabled": False, "categories": []},
    }
    target = {
        "general": {"enforcementMode": "blocking"},
        "blocking-settings": {
            # block changed from False → True (tightening)
            "violations": [{"name": "VIOL_HTTP", "alarm": True, "block": True, "learn": False}],
            "evasions": [],
            "http-protocols": [],
        },
        "signature-sets": [{"name": "Default", "alarm": True, "block": True}],
        "attack-signatures": [],
        "data-guard": {"enabled": False},
        "ip-intelligence": {"enabled": False, "categories": []},
    }
    result = compare_policies(baseline, target)
    assert result.score == 100.0, "Tightening change should not reduce Posture Score"
    assert result.tier == TIER_GREEN
    # Verify the change appears in drift_summary.tightening, not loosening
    assert result.drift_summary.get("baselined") is True
    assert len(result.drift_summary.get("loosening", [])) == 0
    assert len(result.drift_summary.get("tightening", [])) >= 1


def test_loosening_drift_counted_against_score():
    """Disabling a block flag (block True→False) is loosening and reduces the score."""
    baseline, target = _make_policy_pair(target_blocking_enabled=True)
    # Now disable blocking on the violation
    target["blocking-settings"]["violations"][0]["block"] = False
    result = compare_policies(baseline, target)
    assert result.score < 100.0
    loosening = result.drift_summary.get("loosening", [])
    assert len(loosening) >= 1


# ---------------------------------------------------------------------------
# Contributing factors structure
# ---------------------------------------------------------------------------


def test_contributing_factors_present_on_findings():
    """When findings exist, contributing_factors is non-empty and well-formed."""
    baseline, target = _make_policy_pair(sig_count=5, disabled_sig_count=5)
    result = compare_policies(baseline, target)
    assert isinstance(result.contributing_factors, list)
    assert len(result.contributing_factors) > 0
    first = result.contributing_factors[0]
    assert "category" in first
    assert "label" in first
    assert "description" in first
    assert "remediation" in first
    assert "deduction" in first
    assert isinstance(first["deduction"], (int, float))
    assert "is_drift" in first


def test_contributing_factors_sorted_descending():
    """Factors must be sorted largest-deduction-first."""
    baseline, target = _make_policy_pair(sig_count=15, disabled_sig_count=15)
    result = compare_policies(baseline, target)
    deductions = [f["deduction"] for f in result.contributing_factors]
    assert deductions == sorted(deductions, reverse=True), (
        "contributing_factors must be sorted by deduction descending"
    )


# ---------------------------------------------------------------------------
# Drift summary structure
# ---------------------------------------------------------------------------


def test_drift_summary_baselined_true_when_baseline_provided():
    baseline, target = _make_policy_pair()
    result = compare_policies(baseline, target)
    assert result.drift_baselined is True
    assert result.drift_summary.get("baselined") is True
    assert "loosening" in result.drift_summary
    assert "tightening" in result.drift_summary


def test_drift_summary_unbaselined_when_empty_baseline():
    """An empty baseline dict sets drift_baselined=False and adds a Monitor note."""
    result = compare_policies({}, {"general": {"enforcementMode": "blocking"}})
    assert result.drift_baselined is False
    assert result.drift_summary.get("baselined") is False
    unbaselined_factor = next(
        (f for f in result.contributing_factors if f["category"] == "drift_unbaselined"),
        None,
    )
    assert unbaselined_factor is not None, "Should surface a note about unbaselined drift"
    assert unbaselined_factor["deduction"] == 0, "Unbaselined note must not penalize the score"


# ---------------------------------------------------------------------------
# Per-category caps (leniency)
# ---------------------------------------------------------------------------


def test_signatures_category_capped():
    """Massive number of disabled sigs — deduction still capped at 20."""
    baseline, target = _make_policy_pair(sig_count=100, disabled_sig_count=100)
    result = compare_policies(baseline, target)
    # 100 sigs × 2 pts = 200 raw, but signatures cap is 20 → score = 80
    assert result.score == 80.0
    assert result.tier == TIER_YELLOW  # Monitor, not Review Soon or Review Now


# ---------------------------------------------------------------------------
# Tier labels
# ---------------------------------------------------------------------------


def test_tier_labels_match_new_ladder():
    """All four tier labels match the status ladder."""
    from src.utils import score_to_tier, TIER_RED, TIER_AMBER, TIER_YELLOW, TIER_GREEN

    assert score_to_tier(0.0).label == "Review Now"
    assert score_to_tier(39.0).label == "Review Now"
    assert score_to_tier(40.0).label == "Review Soon"
    assert score_to_tier(64.0).label == "Review Soon"
    assert score_to_tier(65.0).label == "Monitor"
    assert score_to_tier(84.0).label == "Monitor"
    assert score_to_tier(85.0).label == "Aligned"
    assert score_to_tier(100.0).label == "Aligned"


def test_tier_names_unchanged():
    """TIER_* constant names are preserved for backwards compat."""
    from src.utils import score_to_tier, TIER_RED, TIER_AMBER, TIER_YELLOW, TIER_GREEN

    assert score_to_tier(20.0).name == TIER_RED
    assert score_to_tier(50.0).name == TIER_AMBER
    assert score_to_tier(70.0).name == TIER_YELLOW
    assert score_to_tier(90.0).name == TIER_GREEN


# ---------------------------------------------------------------------------
# Backward-compat: is_hard_fail property
# ---------------------------------------------------------------------------


def test_is_hard_fail_property_reflects_has_hard_triggers():
    """is_hard_fail is a backward-compat alias for has_hard_triggers."""
    baseline, target = _make_policy_pair(target_enforcement="transparent")
    result = compare_policies(baseline, target)
    assert result.has_hard_triggers is True
    assert result.is_hard_fail is True          # property alias

    baseline2, target2 = _make_policy_pair()
    result2 = compare_policies(baseline2, target2)
    assert result2.has_hard_triggers is False
    assert result2.is_hard_fail is False


# ---------------------------------------------------------------------------
# Bot Defense comparator scenarios
# ---------------------------------------------------------------------------


def test_bot_profile_disabled_forces_review_now():
    """Bot profile disabled is a Bot hard trigger — score capped at 39."""
    baseline, target, meta = _make_bot_profile(enabled=False)
    result = compare_bot_profiles(baseline, target, profile_meta=meta)
    assert result.has_hard_triggers is True
    assert result.is_hard_fail is True
    assert result.score <= 39.0
    assert result.tier == TIER_RED


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
