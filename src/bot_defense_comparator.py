"""Bot Defense profile comparison engine (tiered scoring refactor).

Compares a target Bot Defense profile (BIG-IP /mgmt/tm/security/bot-defense/profile)
against a baseline profile and produces a ComparisonResult with 4-tier severities,
circuit breaker detection, weighted deductions, and tier metadata that aligns with
the WAF comparator model.

Changelog: Scoring refactor – implemented 4-tier severities, circuit breakers,
tiered compliance bands, weighted deductions, and enriched ComparisonResult fields.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from .policy_comparator import (
    ComparisonResult,
    DiffItem,
    Severity,
    _add,
    _build_summary,
    _apply_scoring_with_circuit_breakers,
    SEVERITY_CRITICAL,
    SEVERITY_WARNING,
    SEVERITY_INFO,
)
from .utils import get_logger, iso_timestamp

_log = get_logger("bot_defense_comparator")


# ── Helpers --------------------------------------------------------------------

_TEMPLATE_RANK: Dict[str, int] = {"relaxed": 0, "balanced": 1, "strict": 2}

_OVERRIDE_COLLECTIONS = [
    ("anomalyCategoryOverridesReference", "anomalyCategoryOverrides", "Anomaly Category Overrides"),
    ("anomalyOverridesReference", "anomalyOverrides", "Anomaly Overrides"),
    ("classOverridesReference", "classOverrides", "Class Overrides"),
    ("externalDomainsReference", "externalDomains", "External Domains"),
    ("microServicesReference", "microServices", "Micro Services"),
    ("signatureCategoryOverridesReference", "signatureCategoryOverrides", "Signature Category Overrides"),
    ("signatureOverridesReference", "signatureOverrides", "Signature Overrides"),
    ("siteDomainsReference", "siteDomains", "Site Domains"),
    ("stagedSignaturesReference", "stagedSignatures", "Staged Signatures"),
    ("whitelistReference", "whitelist", "Whitelist"),
]


# ── Main entry point ------------------------------------------------------------


def compare_bot_profiles(
    baseline: Dict,
    target: Dict,
    profile_meta: Optional[Dict] = None,
    baseline_name: str = "baseline",
    device_hostname: str = "",
    device_mgmt_ip: str = "",
    virtual_servers: Optional[List[Dict]] = None,
    green_threshold: float = 90.0,
) -> ComparisonResult:
    """Compare a target Bot Defense profile against a baseline using tiered scoring."""

    meta = profile_meta or {}
    full_path = meta.get("fullPath") or target.get("fullPath", "unknown")
    partition = full_path.strip("/").split("/")[0] if full_path and full_path != "unknown" else "Common"
    name = meta.get("name") or target.get("name", "unknown")

    result = ComparisonResult(
        policy_name=name,
        policy_path=full_path,
        partition=partition,
        enforcement_mode=target.get("enforcementMode", "transparent"),
        baseline_name=baseline_name,
        timestamp=iso_timestamp(),
        virtual_servers=virtual_servers or [],
        device_hostname=device_hostname,
        device_mgmt_ip=device_mgmt_ip,
        profile_type="bot",
    )

    _cmp_core(baseline, target, result)
    _cmp_mobile_detection(baseline, target, result)
    _cmp_signature_categories(baseline, target, result)
    _cmp_whitelist(baseline, target, result)
    _cmp_browsers(baseline, target, result)
    _cmp_overrides(baseline, target, result)

    _build_summary(result)
    _apply_scoring_with_circuit_breakers(
        result=result,
        target=target,
        policy_meta=profile_meta or {},
        green_threshold=green_threshold,
        extra_cb_func=_bot_circuit_breakers,
    )
    return result


# ── Circuit breakers ------------------------------------------------------------


def _bot_circuit_breakers(result: ComparisonResult, target: Dict, policy_meta: Dict) -> List[str]:
    """Detect Bot Defense circuit breakers (caps score at 49 when any fire)."""

    triggers: List[str] = []

    # Profile administratively disabled
    if target.get("enabled") is False:
        triggers.append("BOT_PROFILE_DISABLED")

    # All categories/actions non-blocking
    sigs = _get_subcollection(target, "signatures")
    if sigs:
        if all(str(sig.get("action", "")).lower() not in ("block", "alarm") for sig in sigs):
            triggers.append("BOT_ALL_CATEGORIES_ALLOW")

    # Browser verification absent or fully disabled
    browsers = _get_subcollection(target, "browsers")
    if not browsers or all(b.get("enabled") is False for b in browsers):
        triggers.append("BOT_NO_BROWSER_VERIFICATION")

    return triggers


# ── Comparators -----------------------------------------------------------------


def _cmp_core(baseline: Dict, target: Dict, result: ComparisonResult) -> None:
    b_mode = baseline.get("enforcementMode", "transparent")
    t_mode = target.get("enforcementMode", "transparent")
    if b_mode != t_mode:
        sev = Severity.CRITICAL.value if (b_mode == "blocking" and t_mode != "blocking") else Severity.WARNING.value
        _add(result, DiffItem(
            section="bot-defense",
            section_category="bot_defense",
            element_name="enforcementMode",
            attribute="enforcementMode",
            baseline_value=b_mode,
            target_value=t_mode,
            severity=sev,
            description=(
                f"Bot Defense enforcement mode differs. Baseline: '{b_mode}', Target: '{t_mode}'."
                + (" Bot threats will NOT be blocked." if sev == Severity.CRITICAL.value else "")
            ),
        ))

    b_tmpl = baseline.get("template")
    t_tmpl = target.get("template")
    if b_tmpl is not None and b_tmpl != t_tmpl:
        b_rank = _TEMPLATE_RANK.get(str(b_tmpl), 1)
        t_rank = _TEMPLATE_RANK.get(str(t_tmpl), 1)
        sev = Severity.CRITICAL.value if t_rank < b_rank else Severity.WARNING.value
        _add(result, DiffItem(
            section="bot-defense",
            section_category="bot_defense",
            element_name="template",
            attribute="template",
            baseline_value=b_tmpl,
            target_value=t_tmpl,
            severity=sev,
            description=(
                f"Bot Defense template changed from '{b_tmpl}' to '{t_tmpl}'."
                + (" Security posture has been weakened." if sev == Severity.CRITICAL.value else "")
            ),
        ))

    b_bma = baseline.get("browserMitigationAction")
    t_bma = target.get("browserMitigationAction")
    if b_bma is not None and b_bma != t_bma:
        sev = Severity.CRITICAL.value if (b_bma == "block" and t_bma != "block") else Severity.WARNING.value
        _add(result, DiffItem(
            section="bot-defense",
            section_category="bot_defense",
            element_name="browserMitigationAction",
            attribute="browserMitigationAction",
            baseline_value=b_bma,
            target_value=t_bma,
            severity=sev,
            description=(
                f"Browser mitigation action changed from '{b_bma}' to '{t_bma}'."
                + (" Suspicious browsers will NOT be blocked." if sev == Severity.CRITICAL.value else "")
            ),
        ))

    # Enabled/disabled drift (warnings)
    for attr, sev, desc in [
        ("allowBrowserAccess", Severity.WARNING.value, "Allow browser access setting differs from baseline."),
        ("apiAccessStrictMitigation", Severity.WARNING.value, "API access strict mitigation differs from baseline."),
        ("dosAttackStrictMitigation", Severity.WARNING.value, "DoS attack strict mitigation differs from baseline."),
        ("signatureStagingUponUpdate", Severity.WARNING.value, "Signature staging upon update differs."),
        ("crossDomainRequests", Severity.WARNING.value, "Cross-domain requests setting differs."),
    ]:
        b_val = baseline.get(attr)
        t_val = target.get(attr)
        if b_val is not None and b_val != t_val:
            _add(result, DiffItem(
                section="bot-defense",
                section_category="bot_defense",
                element_name=attr,
                attribute=attr,
                baseline_value=b_val,
                target_value=t_val,
                severity=sev,
                description=desc,
            ))

    for attr, sev, desc in [
        ("performChallengeInTransparent", Severity.INFO.value, "Perform challenge in transparent mode differs."),
        ("singlePageApplication", Severity.INFO.value, "Single page application setting differs."),
        ("deviceidMode", Severity.INFO.value, "Device ID mode differs."),
        ("gracePeriod", Severity.INFO.value, "Grace period differs."),
        ("enforcementReadinessPeriod", Severity.INFO.value, "Enforcement readiness period differs."),
    ]:
        b_val = baseline.get(attr)
        t_val = target.get(attr)
        if b_val is not None and b_val != t_val:
            _add(result, DiffItem(
                section="bot-defense",
                section_category="bot_defense",
                element_name=attr,
                attribute=attr,
                baseline_value=b_val,
                target_value=t_val,
                severity=sev,
                description=desc,
            ))

    tracked = [
        "enforcementMode", "template", "browserMitigationAction",
        "allowBrowserAccess", "apiAccessStrictMitigation", "dosAttackStrictMitigation",
        "signatureStagingUponUpdate", "crossDomainRequests",
        "performChallengeInTransparent", "singlePageApplication", "deviceidMode",
        "gracePeriod", "enforcementReadinessPeriod",
    ]
    result.bot_mitigation_target = {k: target.get(k) for k in tracked}
    result.bot_mitigation_baseline = {k: baseline.get(k) for k in tracked}


def _cmp_mobile_detection(baseline: Dict, target: Dict, result: ComparisonResult) -> None:
    b_md = baseline.get("mobileDetection", {})
    t_md = target.get("mobileDetection", {})
    if not b_md:
        return

    checks = [
        ("allowAndroidRootedDevice", "disabled", "Rooted Android devices allowed in target.", Severity.INFO.value, Severity.WARNING.value),
        ("allowEmulators", "disabled", "Emulators allowed in target.", Severity.CRITICAL.value, Severity.WARNING.value),
        ("allowJailbrokenDevices", "disabled", "Jailbroken devices allowed in target.", Severity.CRITICAL.value, Severity.WARNING.value),
        ("blockDebuggerEnabledDevice", "enabled", "Debugger-enabled devices not blocked.", Severity.CRITICAL.value, Severity.WARNING.value),
        ("allowAnyAndroidPackage", None, "Android package allowance differs.", Severity.WARNING.value, Severity.WARNING.value),
        ("allowAnyIosPackage", None, "iOS package allowance differs.", Severity.WARNING.value, Severity.WARNING.value),
        ("clientSideChallengeMode", None, "Client-side challenge mode differs.", Severity.WARNING.value, Severity.WARNING.value),
    ]

    for attr, secure_val, downgrade_desc, downgrade_sev, other_sev in checks:
        b_val = b_md.get(attr)
        t_val = t_md.get(attr)
        if b_val is None or b_val == t_val:
            continue
        if secure_val and b_val == secure_val:
            sev = downgrade_sev
            desc = downgrade_desc
        else:
            sev = other_sev
            desc = f"Mobile detection '{attr}' differs. Baseline: '{b_val}', Target: '{t_val}'."
        _add(result, DiffItem(
            section="bot-defense.mobileDetection",
            section_category="bot_defense",
            element_name=attr,
            attribute=attr,
            baseline_value=b_val,
            target_value=t_val,
            severity=sev,
            description=desc,
        ))


def _cmp_signature_categories(baseline: Dict, target: Dict, result: ComparisonResult) -> None:
    b_sigs = {s.get("name", ""): s for s in _get_subcollection(baseline, "signatures") if s.get("name")}
    t_sigs = {s.get("name", ""): s for s in _get_subcollection(target, "signatures") if s.get("name")}

    if not b_sigs and not t_sigs:
        return

    action_rank = {"detect": 0, "alarm": 0, "log": 0, "block": 1}

    for name in sorted(set(b_sigs) | set(t_sigs)):
        b_entry = b_sigs.get(name)
        t_entry = t_sigs.get(name)

        if b_entry is None:
            _add(result, DiffItem(
                section="bot-defense.signatures",
                section_category="signatures",
                element_name=name,
                attribute="present",
                baseline_value=False,
                target_value=True,
                severity=SEVERITY_INFO,
                description=f"Signature category '{name}' present in target but not baseline.",
            ))
            continue
        if t_entry is None:
            _add(result, DiffItem(
                section="bot-defense.signatures",
                section_category="signatures",
                element_name=name,
                attribute="present",
                baseline_value=True,
                target_value=False,
                severity=SEVERITY_WARNING,
                description=f"Signature category '{name}' missing from target.",
            ))
            continue

        b_enabled = b_entry.get("enabled")
        t_enabled = t_entry.get("enabled")
        if b_enabled != t_enabled:
            sev = SEVERITY_CRITICAL if b_enabled is True and t_enabled is False else SEVERITY_WARNING
            _add(result, DiffItem(
                section="bot-defense.signatures",
                section_category="signatures",
                element_name=name,
                attribute="enabled",
                baseline_value=b_enabled,
                target_value=t_enabled,
                severity=sev,
                description=(
                    f"Signature category '{name}' enabled state differs. Baseline: {b_enabled}, Target: {t_enabled}."
                    + (" Category will NOT be enforced." if sev == SEVERITY_CRITICAL else "")
                ),
            ))

        b_action = b_entry.get("action")
        t_action = t_entry.get("action")
        if b_action is not None and b_action != t_action:
            b_rank = action_rank.get(str(b_action).lower(), 0)
            t_rank = action_rank.get(str(t_action).lower(), 0)
            sev = SEVERITY_CRITICAL if t_rank < b_rank else SEVERITY_WARNING
            _add(result, DiffItem(
                section="bot-defense.signatures",
                section_category="signatures",
                element_name=name,
                attribute="action",
                baseline_value=b_action,
                target_value=t_action,
                severity=sev,
                description=(
                    f"Signature category '{name}' action changed from '{b_action}' to '{t_action}'."
                    + (" Enforcement has been weakened." if sev == SEVERITY_CRITICAL else "")
                ),
            ))


def _cmp_whitelist(baseline: Dict, target: Dict, result: ComparisonResult) -> None:
    def _key(e: Dict) -> str:
        return e.get("name") or e.get("ipAddress", "")

    b_map = {_key(e): e for e in _get_subcollection(baseline, "whitelist") if _key(e)}
    t_map = {_key(e): e for e in _get_subcollection(target, "whitelist") if _key(e)}

    attrs = ["ipAddress", "ipMask", "matchType", "enabled", "description"]

    for key, b_entry in b_map.items():
        if key not in t_map:
            _add(result, DiffItem(
                section="bot-defense.whitelist",
                section_category="whitelist",
                element_name=key,
                attribute="present",
                baseline_value=True,
                target_value=False,
                severity=SEVERITY_INFO,
                description=f"Whitelist entry '{key}' missing from target.",
            ))
            continue
        t_entry = t_map[key]
        for attr in attrs:
            b_val = b_entry.get(attr)
            t_val = t_entry.get(attr)
            if b_val is not None and b_val != t_val:
                sev = SEVERITY_CRITICAL if (attr == "enabled" and b_val is True and t_val is False) else SEVERITY_WARNING
                _add(result, DiffItem(
                    section="bot-defense.whitelist",
                    section_category="whitelist",
                    element_name=key,
                    attribute=attr,
                    baseline_value=b_val,
                    target_value=t_val,
                    severity=sev,
                    description=f"Whitelist entry '{key}' attribute '{attr}' differs.",
                ))

    for key in t_map:
        if key not in b_map:
            _add(result, DiffItem(
                section="bot-defense.whitelist",
                section_category="whitelist",
                element_name=key,
                attribute="present",
                baseline_value=False,
                target_value=True,
                severity=SEVERITY_WARNING,
                description=f"Whitelist entry '{key}' added in target (not in baseline).",
            ))


def _cmp_browsers(baseline: Dict, target: Dict, result: ComparisonResult) -> None:
    b_map = {e.get("name"): e for e in _get_subcollection(baseline, "browsers") if e.get("name")}
    t_map = {e.get("name"): e for e in _get_subcollection(target, "browsers") if e.get("name")}

    for name, b_entry in b_map.items():
        if name not in t_map:
            _add(result, DiffItem(
                section="bot-defense.browsers",
                section_category="bot_defense",
                element_name=name,
                attribute="present",
                baseline_value=True,
                target_value=False,
                severity=Severity.WARNING.value,
                description=f"Browser entry '{name}' missing from target.",
            ))
            continue
        t_entry = t_map[name]
        b_enabled = b_entry.get("enabled")
        t_enabled = t_entry.get("enabled")
        if b_enabled != t_enabled:
            sev = Severity.CRITICAL.value if b_enabled is True and t_enabled is False else Severity.WARNING.value
            _add(result, DiffItem(
                section="bot-defense.browsers",
                section_category="bot_defense",
                element_name=name,
                attribute="enabled",
                baseline_value=b_enabled,
                target_value=t_enabled,
                severity=sev,
                description=(
                    f"Browser '{name}' enabled state differs. Baseline: {b_enabled}, Target: {t_enabled}."
                    + (" Browser validation disabled." if sev == Severity.CRITICAL.value else "")
                ),
            ))

        for attr, b_val in b_entry.items():
            if attr in ("name", "kind", "selfLink", "generation", "lastUpdateMicros", "enabled"):
                continue
            t_val = t_entry.get(attr)
            if b_val != t_val:
                _add(result, DiffItem(
                    section="bot-defense.browsers",
                    section_category="bot_defense",
                    element_name=name,
                    attribute=attr,
                    baseline_value=b_val,
                    target_value=t_val,
                    severity=Severity.INFO.value,
                    description=f"Browser '{name}' attribute '{attr}' differs from baseline.",
                ))

    for name in t_map:
        if name not in b_map:
            _add(result, DiffItem(
                section="bot-defense.browsers",
                section_category="bot_defense",
                element_name=name,
                attribute="present",
                baseline_value=False,
                target_value=True,
                severity=Severity.INFO.value,
                description=f"Browser entry '{name}' present in target but not baseline.",
            ))


def _cmp_overrides(baseline: Dict, target: Dict, result: ComparisonResult) -> None:
    display_rows: List[Dict] = []

    for ref_key, inline_key, label in _OVERRIDE_COLLECTIONS:
        b_items = _get_reference_subcollection(baseline, ref_key, inline_key)
        t_items = _get_reference_subcollection(target, ref_key, inline_key)

        b_map = {_override_entry_key(e): e for e in b_items if isinstance(e, dict)}
        t_map = {_override_entry_key(e): e for e in t_items if isinstance(e, dict)}

        for key in sorted(set(b_map) | set(t_map)):
            b_entry = b_map.get(key)
            t_entry = t_map.get(key)

            if b_entry is None and t_entry is not None:
                display_rows.append({"collection": label, "name": key, "baseline_entry": None, "target_entry": t_entry, "baseline_match": "extra"})
                _add(result, DiffItem(
                    section=f"bot-defense.overrides.{inline_key}",
                    section_category="overrides",
                    element_name=key,
                    attribute="present",
                    baseline_value=False,
                    target_value=True,
                    severity=Severity.WARNING.value,
                    description=f"Override '{key}' added in '{label}' on target profile.",
                ))
                result.extra_in_target.append({"section": f"bot-defense.overrides.{inline_key}", "name": key})
                continue

            if t_entry is None and b_entry is not None:
                display_rows.append({"collection": label, "name": key, "baseline_entry": b_entry, "target_entry": None, "baseline_match": "missing"})
                _add(result, DiffItem(
                    section=f"bot-defense.overrides.{inline_key}",
                    section_category="overrides",
                    element_name=key,
                    attribute="present",
                    baseline_value=True,
                    target_value=False,
                    severity=Severity.INFO.value,
                    description=f"Override '{key}' from baseline '{label}' is missing on target.",
                ))
                result.missing_in_target.append({"section": f"bot-defense.overrides.{inline_key}", "name": key})
                continue

            if b_entry != t_entry:
                display_rows.append({"collection": label, "name": key, "baseline_entry": b_entry, "target_entry": t_entry, "baseline_match": "diff"})
                _add(result, DiffItem(
                    section=f"bot-defense.overrides.{inline_key}",
                    section_category="overrides",
                    element_name=key,
                    attribute="content",
                    baseline_value=b_entry,
                    target_value=t_entry,
                    severity=Severity.INFO.value,
                    description=f"Override '{key}' in '{label}' differs from baseline.",
                ))
            else:
                display_rows.append({"collection": label, "name": key, "baseline_entry": b_entry, "target_entry": t_entry, "baseline_match": "match"})

    result.bot_overrides = display_rows


# ── Collection helpers ---------------------------------------------------------


def _get_subcollection(profile: Dict, key: str) -> List[Dict]:
    ref = profile.get(f"{key}Reference", {})
    if isinstance(ref, dict) and isinstance(ref.get("items"), list):
        return ref.get("items", [])
    inline = profile.get(key, [])
    return inline if isinstance(inline, list) else []


def _get_reference_subcollection(profile: Dict, ref_key: str, inline_key: str) -> List[Dict]:
    ref = profile.get(ref_key, {})
    if isinstance(ref, dict) and isinstance(ref.get("items"), list):
        return ref.get("items", [])
    inline = profile.get(inline_key, [])
    return inline if isinstance(inline, list) else []


def _override_entry_key(entry: Dict) -> str:
    for k in ("id", "name", "fullPath", "signatureId", "signatureName", "category", "className", "serviceName", "domain", "host", "ipAddress", "ip", "value"):
        v = entry.get(k)
        if v not in (None, ""):
            return str(v)
    try:
        import json
        return json.dumps(entry, sort_keys=True)
    except Exception:
        return str(entry)
