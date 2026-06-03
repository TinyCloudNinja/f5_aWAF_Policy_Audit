"""
Bot Defense profile posture scorer.

Separate scorer for Bot Defense profiles (tm:security:bot-defense:profile).
Uses Bot Defense-specific hard triggers, standalone posture signals, and drift
logic. Shares the same status ladder (Review Now → Review Soon → Monitor →
Aligned), score direction (0-100 Posture Score, higher = healthier), hard-trigger
override pattern, and output contract (ComparisonResult) as the WAF scorer —
but uses its own config and rules.

Threat model: the Bot Defense analog of Policy Builder poisoning is allow-listing
and class-action downgrading. Whitelist growth and mitigation-action weakening
(block → alarm/none) are the primary drift signals.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from .bot_defense_comparator import (
    _cmp_browsers,
    _cmp_core,
    _cmp_mobile_detection,
    _cmp_overrides,
    _cmp_signature_categories,
    _cmp_whitelist,
    _get_reference_subcollection,
    _get_subcollection,
)
from .bot_defense_scoring_config import BOT_SCORING_CONFIG
from .policy_comparator import (
    ComparisonResult,
    DiffItem,
    Severity,
    _build_summary,
)
from .utils import get_logger, iso_timestamp, score_to_tier

_log = get_logger("bot_defense_scorer")

# ── Constants ──────────────────────────────────────────────────────────────────

# F5 bot class names considered high-risk / confirmed-malicious.
# Class override actions for these must be blocking/challenging; alarm or none
# means the profile detects them but takes no mitigating action ("no teeth").
_HIGH_RISK_BOT_CLASSES: frozenset = frozenset({
    "malicious-bot",
    "dos-tool",
    "web-scraper",
    "scanner",
    "vulnerability-scanner",
    "network-scanner",
    "denial-of-service",
})

# Actions that constitute actual mitigation (block, challenge, or rate-limit).
_BLOCKING_ACTIONS: frozenset = frozenset({"block", "captcha", "rate-limit"})

# Mobile SDK flag name → (value_that_is_risky, human_description).
# True-valued entries fire when the flag equals the risky value.
_MOBILE_SDK_FLAGS: List[Tuple[str, object, str]] = [
    ("allowJailbrokenDevices",    True,  "Jailbroken devices allowed"),
    ("allowAndroidRootedDevice",  True,  "Rooted Android devices allowed"),
    ("allowEmulators",            True,  "Emulators allowed"),
    ("allowAnyAndroidPackage",    True,  "Any Android package allowed"),
    ("allowAnyIosPackage",        True,  "Any iOS package allowed"),
    ("blockDebuggerEnabledDevice", False, "Debugger-enabled devices not blocked"),
]

# deviceidMode values that mean device fingerprinting is off or ineffective.
_WEAK_DEVICEID_MODES: frozenset = frozenset({"none", "never", "off", "disabled", ""})

# Grace period threshold in seconds above which we flag the profile.
_GRACE_PERIOD_WARN_SECONDS: int = 86_400  # 1 day

# Template protection ranking: higher rank = more restrictive.
_TEMPLATE_RANK: Dict[str, int] = {"relaxed": 0, "balanced": 1, "strict": 2}

# Per-severity deduction weights for drift findings.
_DEDUCT: Dict[str, float] = {
    Severity.CRITICAL.value: 8.0,
    Severity.HIGH.value:     4.0,
    Severity.WARNING.value:  2.0,
    Severity.INFO.value:     0.5,
}


# ── Public entry point ─────────────────────────────────────────────────────────


def score_bot_profile(
    target: Dict,
    baseline: Optional[Dict] = None,
    vs_list: Optional[List[Dict]] = None,
    profile_meta: Optional[Dict] = None,
    baseline_name: str = "baseline",
    device_hostname: str = "",
    device_mgmt_ip: str = "",
    green_threshold: float = 85.0,
) -> ComparisonResult:
    """Score a Bot Defense profile and return a ComparisonResult.

    Args:
        target: Full profile dict from the BIG-IP API (subcollections expanded).
        baseline: Optional baseline profile dict for drift analysis.
                  When None, drift detection is inactive; the score reflects
                  standalone signals only and a Monitor-level note is added.
        vs_list: Virtual server dicts attached to this profile. Pass an empty
                 list (not None) when VS enrichment was performed and no VS
                 was found — this enables the NO_VIRTUAL_SERVERS hard trigger.
                 Pass None when VS enrichment was not attempted.
        profile_meta: Profile metadata dict (fullPath, name, partition, …).
        baseline_name: Display name of the baseline snapshot.
        device_hostname: Source BIG-IP hostname.
        device_mgmt_ip: Source BIG-IP management IP.
        green_threshold: Minimum score for the Aligned band (default 85).

    Returns:
        ComparisonResult populated with score, tier, contributing_factors,
        drift_summary, and all required output fields.
    """
    meta = profile_meta or {}
    full_path = meta.get("fullPath") or target.get("fullPath", "unknown")
    partition = (
        full_path.strip("/").split("/")[0]
        if full_path and full_path != "unknown"
        else "Common"
    )
    name = meta.get("name") or target.get("name", "unknown")
    enforcement_mode = str(target.get("enforcementMode", "transparent")).lower()

    result = ComparisonResult(
        policy_name=name,
        policy_path=full_path,
        partition=partition,
        enforcement_mode=enforcement_mode,
        baseline_name=baseline_name,
        timestamp=iso_timestamp(),
        virtual_servers=vs_list if vs_list is not None else [],
        # vs_list=None means enrichment was not attempted (no trigger).
        # vs_list=[] means enrichment found no VS (trigger can fire).
        virtual_server_eval_performed=(vs_list is not None),
        device_hostname=device_hostname,
        device_mgmt_ip=device_mgmt_ip,
        profile_type="bot",
        drift_baselined=(baseline is not None),
    )

    # Generate drift DiffItems from baseline comparison (skipped when no baseline).
    if baseline is not None:
        _cmp_core(baseline, target, result)
        _cmp_mobile_detection(baseline, target, result)
        _cmp_signature_categories(baseline, target, result)
        _cmp_whitelist(baseline, target, result)
        _cmp_browsers(baseline, target, result)
        _cmp_overrides(baseline, target, result)

    _build_summary(result)
    _compute_bot_posture_score(result, target, green_threshold)
    return result


# ── Internal scoring engine ────────────────────────────────────────────────────


def _compute_bot_posture_score(
    result: ComparisonResult,
    target: Dict,
    green_threshold: float,
) -> None:
    """Compute the Bot Defense Posture Score and populate all scoring fields."""
    cfg = BOT_SCORING_CONFIG
    cats = cfg["categories"]
    drift_caps = cfg["drift_category_caps"]
    hard_trigger_cap = int(cfg["hard_trigger_cap"])

    # ── 1. Hard triggers ──────────────────────────────────────────────────────
    hard_trigger_keys: List[str] = []

    if result.virtual_server_eval_performed and not result.virtual_servers:
        hard_trigger_keys.append("NO_VIRTUAL_SERVERS")

    if result.enforcement_mode != "blocking":
        hard_trigger_keys.append("BOT_TRANSPARENT_MODE")

    if _detect_no_teeth(target):
        hard_trigger_keys.append("BOT_NO_TEETH")

    # ── 2. Drift deductions (loosening direction only) ─────────────────────────
    loosening_descs: List[str] = []
    tightening_descs: List[str] = []
    raw_by_cat: Dict[str, float] = {}

    for diff in result.diffs:
        is_loose = _is_loosening_bot_diff(diff)
        (loosening_descs if is_loose else tightening_descs).append(diff.description)

        if not result.drift_baselined or not is_loose:
            continue

        cat = _bot_drift_category(diff)
        raw_by_cat[cat] = raw_by_cat.get(cat, 0.0) + _DEDUCT.get(diff.severity, 0.0)

    # Apply per-category caps and build drift contributing factors.
    contributing: List[Dict] = []
    capped_drift_total = 0.0

    for cat, raw_ded in raw_by_cat.items():
        cap = float(drift_caps.get(cat, drift_caps["default"]))
        capped = min(raw_ded, cap)
        capped_drift_total += capped
        if capped > 0:
            label = cat.replace("_", " ")
            contributing.append({
                "category": f"drift_{cat}",
                "label": f"Loosening drift — {label} settings",
                "description": (
                    f"{max(1, int(raw_ded / 8))} loosening change(s) in "
                    f"'{label}' since baseline."
                    + (f" (capped at {cap:.0f} pts)" if raw_ded > cap else "")
                ),
                "remediation": (
                    "Review the drift findings below and restore baseline settings "
                    "where the change was unintended."
                ),
                "deduction": capped,
                "is_drift": True,
            })

    # ── 3. Standalone posture signals ─────────────────────────────────────────
    standalone_total = 0.0

    def _add_signal(cat_key: str, deduction: float, description: str) -> None:
        nonlocal standalone_total
        cat_cfg = cats[cat_key]
        standalone_total += deduction
        contributing.append({
            "category": cat_key,
            "label": cat_cfg["label"],
            "description": description or cat_cfg["description"],
            "remediation": cat_cfg["remediation"],
            "deduction": deduction,
            "is_drift": False,
        })

    # Browser mitigation action (high weight)
    if _detect_browser_mitigation_weak(target):
        _add_signal(
            "browser_mitigation_weak",
            float(cats["browser_mitigation_weak"]["flat"]),
            cats["browser_mitigation_weak"]["description"],
        )

    # DoS / anomaly alarm-only (high weight)
    if _detect_dos_anomaly_alarm_only(target):
        _add_signal(
            "dos_anomaly_alarm_only",
            float(cats["dos_anomaly_alarm_only"]["flat"]),
            cats["dos_anomaly_alarm_only"]["description"],
        )

    # API strict mitigation off (high weight)
    if _detect_api_strict_off(target):
        _add_signal(
            "api_strict_mitigation_off",
            float(cats["api_strict_mitigation_off"]["flat"]),
            cats["api_strict_mitigation_off"]["description"],
        )

    # Staged signatures count (high weight, per-item)
    staged_count = _detect_staged_signatures(target)
    if staged_count > 0:
        staged_ded = min(
            staged_count * int(cats["staged_signatures"]["per_item"]),
            int(cats["staged_signatures"]["max_deduction"]),
        )
        _add_signal(
            "staged_signatures",
            float(staged_ded),
            f"{staged_count} bot signature(s) are in staging (log-only) mode.",
        )

    # Mobile SDK loose flags (lower weight, per-flag)
    loose_flags = _detect_mobile_sdk_loose(target)
    if loose_flags:
        sdk_ded = min(
            len(loose_flags) * int(cats["mobile_sdk_loose"]["per_flag"]),
            int(cats["mobile_sdk_loose"]["max_deduction"]),
        )
        flag_list = "; ".join(loose_flags)
        _add_signal(
            "mobile_sdk_loose",
            float(sdk_ded),
            f"Mobile SDK permissive flags: {flag_list}.",
        )

    # Template relaxed (lower weight)
    if _detect_template_relaxed(target):
        _add_signal(
            "template_relaxed",
            float(cats["template_relaxed"]["flat"]),
            cats["template_relaxed"]["description"],
        )

    # Device ID weak (lower weight)
    if _detect_deviceid_weak(target):
        _add_signal(
            "deviceid_weak",
            float(cats["deviceid_weak"]["flat"]),
            cats["deviceid_weak"]["description"],
        )

    # Grace period extended (lower weight)
    if _detect_grace_period_extended(target):
        _add_signal(
            "grace_period_extended",
            float(cats["grace_period_extended"]["flat"]),
            cats["grace_period_extended"]["description"],
        )

    # performChallengeInTransparent disabled (lower weight — context signal)
    if _detect_challenge_transparent_off(target):
        _add_signal(
            "challenge_transparent_off",
            float(cats["challenge_transparent_off"]["flat"]),
            cats["challenge_transparent_off"]["description"],
        )

    # ── 4. Score computation ──────────────────────────────────────────────────
    total_deduction = capped_drift_total + standalone_total
    raw_score = max(0.0, round(100.0 - total_deduction, 1))
    final_score = (
        raw_score
        if not hard_trigger_keys
        else min(raw_score, float(hard_trigger_cap))
    )

    tier_info = score_to_tier(final_score, hard_trigger_keys, green_threshold=green_threshold)

    # ── 5. Contributing factors (largest deduction first) ─────────────────────
    contributing.sort(key=lambda x: x["deduction"], reverse=True)

    # Unbaselined note — zero deduction, Monitor-level informational.
    if not result.drift_baselined:
        contributing.append({
            "category": "drift_unbaselined",
            "label": "Drift tracking is unbaselined",
            "description": (
                "No baseline snapshot is available for this Bot Defense profile. "
                "The score reflects standalone posture signals only — "
                "drift detection is inactive."
            ),
            "remediation": (
                "Capture a baseline by designating a BST-prefixed profile on the "
                "device, or by running with --gitlab-update-source-truth."
            ),
            "deduction": 0,
            "is_drift": False,
        })

    # ── 6. Populate result ────────────────────────────────────────────────────
    trigger_cfg = cfg.get("hard_triggers", {})
    result.circuit_breakers_triggered = [
        trigger_cfg[k]["label"] if isinstance(trigger_cfg.get(k), dict) else k
        for k in hard_trigger_keys
    ]
    result.has_hard_triggers = bool(hard_trigger_keys)
    result.raw_score = raw_score
    result.score = final_score
    result.tier = tier_info.name
    result.tier_label = tier_info.label
    result.tier_color = tier_info.color
    result.contributing_factors = contributing
    result.drift_summary = {
        "loosening": loosening_descs,
        "tightening": tightening_descs,
        "baselined": result.drift_baselined,
    }


# ── Hard trigger detectors ─────────────────────────────────────────────────────


def _detect_no_teeth(target: Dict) -> bool:
    """True when ALL high-risk class overrides have non-blocking actions.

    Fires only when class overrides for known malicious bot categories are
    explicitly present AND every one of them uses alarm or none. If no
    high-risk class overrides are configured, the trigger does not fire
    (template default applies — scored as a lower-weight standalone signal).
    """
    class_overrides = _get_reference_subcollection(
        target, "classOverridesReference", "classOverrides"
    )
    malicious = [
        item for item in class_overrides
        if str(item.get("className", "")).lower() in _HIGH_RISK_BOT_CLASSES
    ]
    if not malicious:
        return False
    return all(
        str(item.get("action", "")).lower() not in _BLOCKING_ACTIONS
        for item in malicious
    )


# ── Standalone signal detectors ────────────────────────────────────────────────


def _detect_browser_mitigation_weak(target: Dict) -> bool:
    """True when browserMitigationAction is explicitly set to a non-blocking value."""
    bma = target.get("browserMitigationAction")
    if bma is None:
        return False
    return str(bma).lower() not in _BLOCKING_ACTIONS


def _detect_dos_anomaly_alarm_only(target: Dict) -> bool:
    """True when DoS strict mitigation is off or all anomaly overrides are detect-only."""
    if target.get("dosAttackStrictMitigation") is False:
        return True

    anomaly = _get_reference_subcollection(
        target, "anomalyOverridesReference", "anomalyOverrides"
    )
    anomaly_cat = _get_reference_subcollection(
        target, "anomalyCategoryOverridesReference", "anomalyCategoryOverrides"
    )
    all_overrides = [
        item for item in (anomaly + anomaly_cat) if item.get("action")
    ]
    if all_overrides and all(
        str(item["action"]).lower() not in _BLOCKING_ACTIONS for item in all_overrides
    ):
        return True
    return False


def _detect_api_strict_off(target: Dict) -> bool:
    """True when apiAccessStrictMitigation is explicitly set to False."""
    return target.get("apiAccessStrictMitigation") is False


def _detect_staged_signatures(target: Dict) -> int:
    """Return the number of bot signatures currently in staging mode."""
    staged = _get_reference_subcollection(
        target, "stagedSignaturesReference", "stagedSignatures"
    )
    return len(staged)


def _detect_mobile_sdk_loose(target: Dict) -> List[str]:
    """Return a list of human-readable descriptions for each loose mobile SDK flag."""
    mobile = target.get("mobileDetection") or {}
    if not isinstance(mobile, dict):
        return []
    return [
        desc
        for attr, risky_val, desc in _MOBILE_SDK_FLAGS
        if mobile.get(attr) == risky_val
    ]


def _detect_template_relaxed(target: Dict) -> bool:
    """True when the profile template is 'relaxed' (lowest protection level)."""
    return str(target.get("template", "")).lower() == "relaxed"


def _detect_deviceid_weak(target: Dict) -> bool:
    """True when deviceidMode is absent or set to a weak/disabled value."""
    mode = str(target.get("deviceidMode", "")).lower()
    return mode in _WEAK_DEVICEID_MODES


def _detect_grace_period_extended(target: Dict) -> bool:
    """True when gracePeriod or enforcementReadinessPeriod exceeds the threshold."""
    for field in ("gracePeriod", "enforcementReadinessPeriod"):
        val = target.get(field)
        if isinstance(val, (int, float)) and val > _GRACE_PERIOD_WARN_SECONDS:
            return True
    return False


def _detect_challenge_transparent_off(target: Dict) -> bool:
    """True when performChallengeInTransparent is explicitly disabled."""
    return target.get("performChallengeInTransparent") is False


# ── Drift helpers ──────────────────────────────────────────────────────────────


def _is_loosening_bot_diff(diff: DiffItem) -> bool:
    """True when a Bot Defense DiffItem represents a weakening of posture.

    Only loosening drift counts against the Posture Score. Tightening changes
    are tracked in the drift summary but do not reduce the score.
    """
    attr = diff.attribute
    b_val = diff.baseline_value
    t_val = diff.target_value
    section = diff.section or ""

    # Class or signature action downgraded to non-blocking
    if attr == "action":
        b_blocking = str(b_val).lower() in _BLOCKING_ACTIONS
        t_blocking = str(t_val).lower() in _BLOCKING_ACTIONS
        return b_blocking and not t_blocking

    # Feature or entry disabled
    if attr == "enabled":
        return b_val is True and t_val is False

    # Entry added to target that was not in baseline (whitelist growth)
    if attr == "present":
        return b_val is False and t_val is True

    # Enforcement mode relaxed
    if attr == "enforcementMode":
        return str(b_val).lower() == "blocking" and str(t_val).lower() != "blocking"

    # Template protection level reduced (strict → balanced → relaxed)
    if attr == "template":
        b_rank = _TEMPLATE_RANK.get(str(b_val).lower(), 1)
        t_rank = _TEMPLATE_RANK.get(str(t_val).lower(), 1)
        return t_rank < b_rank

    # Mobile SDK permissive flags turned on
    if attr in ("allowJailbrokenDevices", "allowAndroidRootedDevice",
                "allowEmulators", "allowAnyAndroidPackage", "allowAnyIosPackage"):
        return b_val is False and t_val is True
    if attr == "blockDebuggerEnabledDevice":
        return b_val is True and t_val is False

    # Strict mitigation flags turned off
    if attr in ("dosAttackStrictMitigation", "apiAccessStrictMitigation"):
        return b_val is True and t_val is False

    # Override collection content change (_cmp_overrides emits attribute="content"
    # with the full entry dict as values).  For class overrides, check whether the
    # action was downgraded from a blocking action to a non-blocking one.
    if attr == "content":
        if "classOverrides" in section:
            b_action = str(b_val.get("action", "") if isinstance(b_val, dict) else "").lower()
            t_action = str(t_val.get("action", "") if isinstance(t_val, dict) else "").lower()
            return b_action in _BLOCKING_ACTIONS and t_action not in _BLOCKING_ACTIONS
        # For other override collections, use severity-based heuristic.
        return diff.severity in (Severity.CRITICAL.value, Severity.WARNING.value)

    # Default: treat as loosening when severity is Warning or Critical
    # (conservative — better to flag than to miss).
    return diff.severity in (Severity.CRITICAL.value, Severity.WARNING.value)


def _bot_drift_category(diff: DiffItem) -> str:
    """Map a Bot Defense DiffItem to its scoring drift category for cap purposes.

    Uses the DiffItem section string to distinguish class-override downgrades
    (primary poisoning vector) from whitelist, mobile SDK, and other categories.
    """
    section = diff.section or ""
    base_cat = diff.section_category or "general"

    if "classOverrides" in section:
        return "class_actions"
    if "mobileDetection" in section or "mobile" in section.lower():
        return "mobile_sdk"
    if "whitelist" in section:
        return "whitelist"
    if "signatures" in section or "stagedSignatures" in section:
        return "signatures"
    # bot_defense, overrides, general, etc. — use base_cat as-is
    return base_cat
