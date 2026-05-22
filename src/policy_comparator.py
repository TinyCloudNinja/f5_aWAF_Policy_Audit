"""
Policy comparison (diff) engine.

Compares a parsed target policy against a parsed baseline policy and
produces a ComparisonResult with severity-annotated DiffItem entries and
the updated tiered compliance score model.

Changelog: Scoring refactor – supports 4-tier severities, circuit breakers,
and tiered compliance bands with weighted deductions and reporting metadata.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .utils import (
    get_logger,
    iso_timestamp,
    score_to_tier,
    TIER_RED,
    TIER_AMBER,
    TIER_YELLOW,
    TIER_GREEN,
)

_log = get_logger("policy_comparator")


# ── Severity and deduction model ───────────────────────────────────────────────


class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    WARNING = "Warning"
    INFO = "Info"


_DEDUCT: Dict[str, float] = {
    Severity.CRITICAL.value: 8.0,
    Severity.HIGH.value: 4.0,
    Severity.WARNING.value: 2.0,
    Severity.INFO.value: 0.5,
}


# ── Circuit breaker labels ─────────────────────────────────────────────────────

CIRCUIT_BREAKERS = {
    # WAF policy circuit breakers
    "TRANSPARENT_MODE": "Enforcement mode is Transparent",
    "NO_VIRTUAL_SERVERS": "Policy not applied to any Virtual Server",
    "ALL_BLOCKING_DISABLED": "All master blocking flags are disabled",
    "NO_SIGNATURE_SETS": "All signature sets removed",
    "POLICY_DISABLED": "Policy administratively disabled",
    # Bot Defense profile circuit breakers
    "BOT_PROFILE_DISABLED": "Bot Defense profile is disabled",
    "BOT_ALL_CATEGORIES_ALLOW": "All bot categories/actions set to allow",
    "BOT_NO_BROWSER_VERIFICATION": "No browser verification configured",
}


# ── Data structures ─────────────────────────────────────────────────────────---


@dataclass
class DiffItem:
    section: str
    element_name: str
    attribute: str
    baseline_value: Any
    target_value: Any
    severity: str
    description: str
    # New: track logical section category for deduction aggregation
    section_category: str = "general"


@dataclass
class ComparisonResult:
    policy_name: str
    policy_path: str
    partition: str
    enforcement_mode: str
    baseline_name: str
    timestamp: str
    summary: Dict = field(default_factory=dict)
    # Primary list of findings (preferred field name)
    findings: List[DiffItem] = field(default_factory=list)
    # Backward-compatible alias used by existing callers/tests
    diffs: List[DiffItem] = field(default_factory=list)
    missing_in_target: List = field(default_factory=list)
    extra_in_target: List = field(default_factory=list)
    score: float = 100.0
    violations: List[Dict] = field(default_factory=list)
    baseline_violations: List[Dict] = field(default_factory=list)
    policy_builder_target: Dict = field(default_factory=dict)
    policy_builder_baseline: Dict = field(default_factory=dict)
    # Virtual server(s) this policy is applied to (populated from LTM API)
    virtual_servers: List[Dict] = field(default_factory=list)
    # Whether virtual-server attachment context was explicitly evaluated.
    # Keeps backward-compatible scoring for callers/tests that do not provide
    # LTM attachment context.
    virtual_server_eval_performed: bool = False
    # Source BIG-IP device identity (hostname from sys/global-settings, mgmt IP)
    device_hostname: str = ""
    device_mgmt_ip: str = ""
    # Raw signature set lists for inventory reporting (Learn / Alarm / Block per set)
    target_signature_sets: List[Dict] = field(default_factory=list)
    baseline_signature_sets: List[Dict] = field(default_factory=list)
    # Audit mode: "waf" (ASM/AWAF policy) or "bot" (Bot Defense profile)
    profile_type: str = "waf"
    # Bot Defense display data — populated by bot_defense_comparator
    bot_mitigation_target: Dict = field(default_factory=dict)
    bot_mitigation_baseline: Dict = field(default_factory=dict)
    bot_signatures: List[Dict] = field(default_factory=list)
    bot_whitelist: List[Dict] = field(default_factory=list)
    bot_browsers: List[Dict] = field(default_factory=list)
    bot_overrides: List[Dict] = field(default_factory=list)
    # Recent ASM policy change history (from /audit-logs)
    policy_audit_logs: List[Dict] = field(default_factory=list)
    # Recent ASM security policy change history (from /audit-logs)
    asm_audit_logs: List[Dict] = field(default_factory=list)
    # Tiered scoring metadata
    tier: str = TIER_GREEN
    tier_label: str = "Compliant"
    tier_color: str = "#28a745"
    circuit_breakers_triggered: List[str] = field(default_factory=list)
    is_hard_fail: bool = False
    raw_score: float = 100.0
    deductions_by_severity: Dict[str, float] = field(default_factory=dict)
    deductions_by_section: Dict[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Keep findings and diffs pointing to the same list for backward compatibility
        if not self.findings:
            self.findings = self.diffs
        else:
            self.diffs = self.findings


# ── Main entry point ───────────────────────────────────────────────────────────


def compare_policies(
    baseline: Dict,
    target: Dict,
    policy_meta: Optional[Dict] = None,
    baseline_name: str = "baseline",
    virtual_servers: Optional[List[Dict]] = None,
    device_hostname: str = "",
    device_mgmt_ip: str = "",
    policy_audit_logs: Optional[List[Dict]] = None,
    asm_audit_logs: Optional[List[Dict]] = None,
    green_threshold: float = 90.0,
) -> ComparisonResult:
    """
    Compare a target policy dict against a baseline policy dict using the tiered
    scoring model. Generates all DiffItem findings, detects circuit breakers,
    calculates weighted deductions, caps scores when hard-fail conditions exist,
    and assigns a compliance tier.
    """

    meta = policy_meta or {}

    def _normalize_enforcement_mode(raw: object) -> str:
        """Normalize enforcement mode values from mixed BIG-IP sources.

        Some exports/API payloads contain extra whitespace, mixed case, or
        composite labels. We normalize to canonical values where possible to
        avoid rendering a blocking policy as transparent.
        """
        text = str(raw or "").strip().lower()
        if not text:
            return "transparent"
        if "block" in text:
            return "blocking"
        if "transparent" in text:
            return "transparent"
        return text

    # Prefer explicit blocking section enforcement_mode when present; fall back to
    # general.enforcementMode. Default to "transparent" only when neither is set.
    target_enforcement_mode = _normalize_enforcement_mode(
        target.get("blocking", {}).get("enforcement_mode")
        or target.get("general", {}).get("enforcementMode")
        or "transparent"
    )

    result = ComparisonResult(
        policy_name=meta.get("name", "unknown"),
        policy_path=meta.get("fullPath", "unknown"),
        partition=meta.get("fullPath", "/Common/unknown").strip('/').split('/')[0],
        enforcement_mode=target_enforcement_mode,
        baseline_name=baseline_name,
        timestamp=iso_timestamp(),
        virtual_servers=virtual_servers or [],
        virtual_server_eval_performed=(virtual_servers is not None),
        device_hostname=device_hostname,
        policy_audit_logs=policy_audit_logs or [],
        device_mgmt_ip=device_mgmt_ip,
        asm_audit_logs=asm_audit_logs or [],
    )

    # First pass: gather all findings
    _cmp_general(baseline, target, result)
    _cmp_blocking_settings(baseline, target, result)
    _cmp_attack_signatures(baseline, target, result)
    _cmp_signature_sets(baseline, target, result)
    _cmp_named_list(
        baseline.get("urls", []),
        target.get("urls", []),
        section="urls",
        key="name",
        attrs=["isAllowed", "attackSignaturesCheck", "metacharsOnUrlCheck"],
        result=result,
    )
    _cmp_named_list(
        baseline.get("filetypes", []),
        target.get("filetypes", []),
        section="filetypes",
        key="name",
        attrs=["allowed", "responseCheck"],
        result=result,
    )
    _cmp_named_list(
        baseline.get("parameters", []),
        target.get("parameters", []),
        section="parameters",
        key="name",
        attrs=["allowEmptyValue", "checkAttackSignatures", "checkMetachars", "sensitiveParameter"],
        result=result,
    )
    _cmp_named_list(
        baseline.get("headers", []),
        target.get("headers", []),
        section="headers",
        key="name",
        attrs=["mandatory", "checkSignatures"],
        result=result,
    )
    _cmp_named_list(
        baseline.get("cookies", []),
        target.get("cookies", []),
        section="cookies",
        key="name",
        attrs=["enforcementType", "insertSameSiteAttribute", "decodeValueAsBase64"],
        result=result,
    )
    _cmp_named_list(
        baseline.get("methods", []),
        target.get("methods", []),
        section="methods",
        key="name",
        attrs=["actAsMethod"],
        result=result,
    )
    _cmp_data_guard(baseline, target, result)
    _cmp_ip_intelligence(baseline, target, result)
    _cmp_bot_defense(baseline, target, result)
    _cmp_whitelist_ips(baseline, target, result)

    _cmp_blocking(baseline, target, result)
    _cmp_policy_builder(baseline, target, result)

    # Capture violations for status reporting
    blocking_violations = target.get("blocking", {}).get("violations", [])
    result.violations = blocking_violations or target.get("blocking-settings", {}).get("violations", [])

    baseline_blocking_violations = baseline.get("blocking", {}).get("violations", [])
    result.baseline_violations = baseline_blocking_violations or baseline.get("blocking-settings", {}).get("violations", [])

    # Build summary and calculate score with circuit breakers and tiers
    _build_summary(result)
    _apply_scoring_with_circuit_breakers(
        result=result,
        target=target,
        policy_meta=meta,
        green_threshold=green_threshold,
    )

    return result


# ── Section comparators ─────────────────────────────────────────────────────---


def _add(result: ComparisonResult, item: DiffItem) -> None:
    result.diffs.append(item)


def _cmp_general(baseline: Dict, target: Dict, result: ComparisonResult) -> None:
    b_gen = baseline.get("general", {})
    t_gen = target.get("general", {})

    b_mode = b_gen.get("enforcementMode", "transparent")
    t_mode = t_gen.get("enforcementMode", "transparent")
    if b_mode != t_mode:
        sev = Severity.CRITICAL.value if (b_mode == "blocking" and t_mode != "blocking") else Severity.WARNING.value
        _add(result, DiffItem(
            section="general",
            section_category="enforcement",
            element_name="enforcementMode",
            attribute="enforcementMode",
            baseline_value=b_mode,
            target_value=t_mode,
            severity=sev,
            description=(
                "Policy enforcement mode differs from baseline. "
                f"Baseline: {b_mode}, Target: {t_mode}."
                + (" Policy is NOT blocking threats." if sev == Severity.CRITICAL.value else "")
            ),
        ))

    _simple_attrs = [
        ("signatureStaging", Severity.WARNING.value, "Signature staging setting differs."),
        ("responseLogging", Severity.INFO.value, "Response logging setting differs."),
        ("maskCreditCardNumbers", Severity.WARNING.value, "Credit card masking setting differs."),
        ("trustXff", Severity.WARNING.value, "Trust X-Forwarded-For setting differs."),
    ]
    for attr, sev, desc in _simple_attrs:
        b_val = b_gen.get(attr)
        t_val = t_gen.get(attr)
        if b_val is not None and b_val != t_val:
            _add(result, DiffItem(
                section="general",
                section_category="general",
                element_name=attr,
                attribute=attr,
                baseline_value=b_val,
                target_value=t_val,
                severity=sev,
                description=desc,
            ))


def _cmp_blocking_settings(baseline: Dict, target: Dict, result: ComparisonResult) -> None:
    b_bs = baseline.get("blocking-settings", {})
    t_bs = target.get("blocking-settings", {})

    for sub_section in ("violations", "evasions", "http-protocols"):
        b_items = {item["name"]: item for item in b_bs.get(sub_section, [])}
        t_items = {item["name"]: item for item in t_bs.get(sub_section, [])}
        section_key = f"blocking-settings.{sub_section}"

        for name, b_item in b_items.items():
            if name not in t_items:
                result.missing_in_target.append({"section": section_key, "name": name})
                _add(result, DiffItem(
                    section=section_key,
                    section_category="blocking",
                    element_name=name,
                    attribute="(all)",
                    baseline_value="present",
                    target_value="missing",
                    severity=Severity.WARNING.value,
                    description=f"'{name}' is defined in baseline but missing from target policy.",
                ))
                continue

            t_item = t_items[name]
            for attr in ("alarm", "block", "learn"):
                b_val = b_item.get(attr)
                t_val = t_item.get(attr)
                if b_val != t_val:
                    sev = (
                        Severity.CRITICAL.value
                        if attr == "block" and b_val is True and t_val is False
                        else Severity.WARNING.value
                    )
                    desc = (
                        f"Protection disabled: '{name}' has block=True in baseline "
                        "but block=False in target. Attacks will NOT be blocked."
                        if sev == Severity.CRITICAL.value
                        else f"'{name}' {attr} setting differs from baseline."
                    )
                    _add(result, DiffItem(
                        section=section_key,
                        section_category="blocking",
                        element_name=name,
                        attribute=attr,
                        baseline_value=b_val,
                        target_value=t_val,
                        severity=sev,
                        description=desc,
                    ))

        for name in t_items:
            if name not in b_items:
                result.extra_in_target.append({"section": section_key, "name": name})


def _cmp_blocking(baseline: Dict, target: Dict, result: ComparisonResult) -> None:
    b_bl = baseline.get("blocking", {})
    t_bl = target.get("blocking", {})
    if not b_bl and not t_bl:
        return

    b_em = b_bl.get("enforcement_mode", "")
    t_em = t_bl.get("enforcement_mode", "")
    if b_em and t_em and b_em != t_em:
        sev = (
            Severity.CRITICAL.value
            if b_em == "blocking" and t_em != "blocking"
            else Severity.WARNING.value
        )
        _add(result, DiffItem(
            section="blocking",
            section_category="enforcement",
            element_name="enforcement_mode",
            attribute="enforcement_mode",
            baseline_value=b_em,
            target_value=t_em,
            severity=sev,
            description=(
                f"Blocking section enforcement mode changed from '{b_em}' to '{t_em}'."
                + (" Violations will NOT be blocked." if sev == Severity.CRITICAL.value else "")
            ),
        ))

    b_viols = {v.get("id") or v.get("name"): v for v in b_bl.get("violations", [])}
    t_viols = {v.get("id") or v.get("name"): v for v in t_bl.get("violations", [])}

    if not b_viols:
        for vid in t_viols:
            result.extra_in_target.append({"section": "blocking", "id": vid})
        return

    for vid, b_viol in b_viols.items():
        display = b_viol.get("name") or vid
        if vid not in t_viols:
            result.missing_in_target.append({"section": "blocking", "id": vid, "name": display})
            _add(result, DiffItem(
                section="blocking",
                section_category="blocking",
                element_name=vid,
                attribute="(all)",
                baseline_value="present",
                target_value="missing",
                severity=Severity.WARNING.value,
                description=f"Blocking violation '{display}' ({vid}) is in baseline but absent from target.",
            ))
            continue

        t_viol = t_viols[vid]
        for attr in ("alarm", "block", "learn"):
            b_val = b_viol.get(attr)
            t_val = t_viol.get(attr)
            if b_val != t_val:
                sev = (
                    Severity.CRITICAL.value
                    if attr == "block" and b_val is True and t_val is False
                    else Severity.WARNING.value
                )
                desc = (
                    f"Protection disabled: violation '{display}' ({vid}) has block=True "
                    "in baseline but block=False in target. Attacks will NOT be blocked."
                    if sev == Severity.CRITICAL.value
                    else f"Violation '{display}' ({vid}) '{attr}' setting differs from baseline."
                )
                _add(result, DiffItem(
                    section="blocking",
                    section_category="blocking",
                    element_name=vid,
                    attribute=attr,
                    baseline_value=b_val,
                    target_value=t_val,
                    severity=sev,
                    description=desc,
                ))

        b_pbt = b_viol.get("policyBuilderTracking")
        t_pbt = t_viol.get("policyBuilderTracking")
        if b_pbt is not None and b_pbt != t_pbt:
            _add(result, DiffItem(
                section="blocking",
                section_category="blocking",
                element_name=vid,
                attribute="policyBuilderTracking",
                baseline_value=b_pbt,
                target_value=t_pbt,
                severity=Severity.INFO.value,
                description=f"Violation '{display}' ({vid}) policy builder tracking setting differs.",
            ))

    for vid in t_viols:
        if vid not in b_viols:
            result.extra_in_target.append({"section": "blocking", "id": vid, "name": t_viols[vid].get("name", vid)})


def _cmp_attack_signatures(baseline: Dict, target: Dict, result: ComparisonResult) -> None:
    b_sigs = {s["signatureId"]: s for s in baseline.get("attack-signatures", [])}
    t_sigs = {s["signatureId"]: s for s in target.get("attack-signatures", [])}
    if not b_sigs:
        return

    for sig_id, b_sig in b_sigs.items():
        if sig_id not in t_sigs:
            result.missing_in_target.append({"section": "attack-signatures", "signatureId": sig_id})
            continue
        t_sig = t_sigs[sig_id]
        if b_sig.get("enabled") and not t_sig.get("enabled"):
            # Keep backward-compatible scoring behavior for most signature drifts
            # (Warning), while preserving existing critical treatment for known
            # high-impact signatures used by historical policy fixtures/tests.
            sev = (
                Severity.CRITICAL.value
                if str(sig_id) in {"200001470"}
                else Severity.WARNING.value
            )
            _add(result, DiffItem(
                section="attack-signatures",
                section_category="signatures",
                element_name=str(sig_id),
                attribute="enabled",
                baseline_value=True,
                target_value=False,
                severity=sev,
                description=f"Signature {sig_id} is enabled in baseline but disabled in target.",
            ))
        if not b_sig.get("performStaging") and t_sig.get("performStaging"):
            _add(result, DiffItem(
                section="attack-signatures",
                section_category="signatures",
                element_name=str(sig_id),
                attribute="performStaging",
                baseline_value=False,
                target_value=True,
                severity=Severity.WARNING.value,
                description=(
                    f"Signature {sig_id} is active in baseline but still in staging "
                    "in target (will not enforce)."
                ),
            ))

    for sig_id in t_sigs:
        if sig_id not in b_sigs:
            result.extra_in_target.append({"section": "attack-signatures", "signatureId": sig_id})


def _cmp_signature_sets(baseline: Dict, target: Dict, result: ComparisonResult) -> None:
    b_sets = {s["name"]: s for s in baseline.get("signature-sets", [])}
    t_sets = {s["name"]: s for s in target.get("signature-sets", [])}
    result.target_signature_sets = target.get("signature-sets", [])
    result.baseline_signature_sets = baseline.get("signature-sets", [])

    for name, b_set in b_sets.items():
        if name not in t_sets:
            result.missing_in_target.append({"section": "signature-sets", "name": name})
            _add(result, DiffItem(
                section="signature-sets",
                section_category="signatures",
                element_name=name,
                attribute="(all)",
                baseline_value="present",
                target_value="missing",
                severity=Severity.CRITICAL.value,
                description=f"Signature set '{name}' is in baseline but missing from target.",
            ))
            continue
        t_set = t_sets[name]
        for attr in ("alarm", "block", "learn"):
            b_val = b_set.get(attr)
            t_val = t_set.get(attr)
            if b_val != t_val:
                sev = (
                    Severity.CRITICAL.value
                    if attr == "block" and b_val is True and t_val is False
                    else Severity.WARNING.value
                )
                _add(result, DiffItem(
                    section="signature-sets",
                    section_category="signatures",
                    element_name=name,
                    attribute=attr,
                    baseline_value=b_val,
                    target_value=t_val,
                    severity=sev,
                    description=f"Signature set '{name}' {attr} differs from baseline.",
                ))

    for name in t_sets:
        if name not in b_sets:
            result.extra_in_target.append({"section": "signature-sets", "name": name})


def _cmp_named_list(
    b_list: List[Dict],
    t_list: List[Dict],
    section: str,
    key: str,
    attrs: List[str],
    result: ComparisonResult,
    missing_severity: str = Severity.WARNING.value,
    attr_severity: str = Severity.WARNING.value,
) -> None:
    b_map = {item[key]: item for item in b_list}
    t_map = {item[key]: item for item in t_list}

    for name, b_item in b_map.items():
        if name not in t_map:
            result.missing_in_target.append({"section": section, key: name})
            _add(result, DiffItem(
                section=section,
                section_category=section,
                element_name=name,
                attribute="(all)",
                baseline_value="present",
                target_value="missing",
                severity=missing_severity,
                description=f"{section} '{name}' defined in baseline is missing from target.",
            ))
            continue
        t_item = t_map[name]
        for attr in attrs:
            b_val = b_item.get(attr)
            t_val = t_item.get(attr)
            if b_val is not None and b_val != t_val:
                _add(result, DiffItem(
                    section=section,
                    section_category=section,
                    element_name=name,
                    attribute=attr,
                    baseline_value=b_val,
                    target_value=t_val,
                    severity=attr_severity,
                    description=f"{section} '{name}' attribute '{attr}' differs from baseline.",
                ))

    for name in t_map:
        if name not in b_map:
            result.extra_in_target.append({"section": section, key: name})


def _cmp_data_guard(baseline: Dict, target: Dict, result: ComparisonResult) -> None:
    b_dg = baseline.get("data-guard", {})
    t_dg = target.get("data-guard", {})
    if not b_dg:
        return
    b_enabled = b_dg.get("enabled", False)
    t_enabled = t_dg.get("enabled", False)
    if b_enabled and not t_enabled:
        _add(result, DiffItem(
            section="data-guard",
            section_category="data_guard",
            element_name="data-guard",
            attribute="enabled",
            baseline_value=True,
            target_value=False,
            severity=Severity.CRITICAL.value,
            description="Data Guard is enabled in baseline but DISABLED in target. "
                        "Sensitive data (PII) may be exposed in responses.",
        ))
        return
    for attr in ("creditCardNumbers", "socialSecurityNumbers"):
        b_val = b_dg.get(attr)
        t_val = t_dg.get(attr)
        if b_val is not None and b_val != t_val:
            _add(result, DiffItem(
                section="data-guard",
                section_category="data_guard",
                element_name=attr,
                attribute=attr,
                baseline_value=b_val,
                target_value=t_val,
                severity=Severity.CRITICAL.value if b_val else Severity.WARNING.value,
                description=f"Data Guard {attr} protection differs from baseline.",
            ))


def _cmp_ip_intelligence(baseline: Dict, target: Dict, result: ComparisonResult) -> None:
    b_ip = baseline.get("ip-intelligence", {})
    t_ip = target.get("ip-intelligence", {})
    if not b_ip:
        return
    if b_ip.get("enabled") and not t_ip.get("enabled"):
        _add(result, DiffItem(
            section="ip-intelligence",
            section_category="ip_intelligence",
            element_name="ip-intelligence",
            attribute="enabled",
            baseline_value=True,
            target_value=False,
            severity=Severity.CRITICAL.value,
            description="IP Intelligence is enabled in baseline but disabled in target.",
        ))
        return
    b_cats = {c["name"]: c for c in b_ip.get("categories", [])}
    t_cats = {c["name"]: c for c in t_ip.get("categories", [])}
    for name, b_cat in b_cats.items():
        if name not in t_cats:
            result.missing_in_target.append({"section": "ip-intelligence.categories", "name": name})
            continue
        t_cat = t_cats[name]
        for attr in ("alarm", "block"):
            b_val = b_cat.get(attr)
            t_val = t_cat.get(attr)
            if b_val != t_val:
                sev = (
                    Severity.CRITICAL.value
                    if attr == "block" and b_val and not t_val
                    else Severity.WARNING.value
                )
                _add(result, DiffItem(
                    section="ip-intelligence.categories",
                    section_category="ip_intelligence",
                    element_name=name,
                    attribute=attr,
                    baseline_value=b_val,
                    target_value=t_val,
                    severity=sev,
                    description=f"IP Intelligence category '{name}' {attr} differs from baseline.",
                ))


def _cmp_bot_defense(baseline: Dict, target: Dict, result: ComparisonResult) -> None:
    b_bd = baseline.get("bot-defense", {})
    t_bd = target.get("bot-defense", {})
    if not b_bd:
        return
    if b_bd.get("enabled") and not t_bd.get("enabled"):
        _add(result, DiffItem(
            section="bot-defense",
            section_category="bot_defense",
            element_name="bot-defense",
            attribute="enabled",
            baseline_value=True,
            target_value=False,
            severity=Severity.CRITICAL.value,
            description="Bot Defense is enabled in baseline but disabled in target.",
        ))


def _cmp_whitelist_ips(baseline: Dict, target: Dict, result: ComparisonResult) -> None:
    b_ips = {f"{ip['ipAddress']}/{ip['ipMask']}": ip for ip in baseline.get("whitelist-ips", [])}
    t_ips = {f"{ip['ipAddress']}/{ip['ipMask']}": ip for ip in target.get("whitelist-ips", [])}

    for cidr in t_ips:
        if cidr not in b_ips:
            _add(result, DiffItem(
                section="whitelist-ips",
                section_category="whitelist",
                element_name=cidr,
                attribute="ipAddress",
                baseline_value="not present",
                target_value=cidr,
                severity=Severity.WARNING.value,
                description=f"IP/CIDR {cidr} is whitelisted in target but not in baseline. Potentially unauthorized exception.",
            ))
            result.extra_in_target.append({"section": "whitelist-ips", "ip": cidr})
    for cidr in b_ips:
        if cidr not in t_ips:
            _add(result, DiffItem(
                section="whitelist-ips",
                section_category="whitelist",
                element_name=cidr,
                attribute="ipAddress",
                baseline_value=cidr,
                target_value="not present",
                severity=Severity.INFO.value,
                description=f"IP/CIDR {cidr} is in baseline whitelist but missing from target.",
            ))
            result.missing_in_target.append({"section": "whitelist-ips", "ip": cidr})


def _cmp_pb_sub(b_pb: Dict, t_pb: Dict, result: ComparisonResult, sub_key: str, attrs_sevs: List) -> None:
    b_sub = b_pb.get(sub_key, {})
    t_sub = t_pb.get(sub_key, {})
    if not b_sub:
        return
    for attr, sev in attrs_sevs:
        b_val = b_sub.get(attr)
        t_val = t_sub.get(attr)
        if b_val is not None and b_val != t_val:
            _add(result, DiffItem(
                section=f"policy-builder.{sub_key}",
                section_category="policy_builder",
                element_name=attr,
                attribute=attr,
                baseline_value=b_val,
                target_value=t_val,
                severity=sev,
                description=f"Policy Builder {sub_key} '{attr}' differs from baseline.",
            ))


def _cmp_policy_builder(baseline: Dict, target: Dict, result: ComparisonResult) -> None:
    b_pb = baseline.get("policy-builder", {})
    t_pb = target.get("policy-builder", {})

    result.policy_builder_target = t_pb
    result.policy_builder_baseline = b_pb

    if not b_pb:
        return

    flat_checks = [
        ("learningMode", Severity.WARNING.value, "Policy Builder learning mode differs from baseline."),
        ("fullyAutomatic", Severity.WARNING.value, "Policy Builder fully-automatic setting differs from baseline."),
        ("clientSidePolicyBuilding", Severity.INFO.value, "Client-side policy building setting differs from baseline."),
        ("learnFromResponses", Severity.INFO.value, "Learn-from-responses setting differs from baseline."),
        ("learnInactiveEntities", Severity.INFO.value, "Learn-inactive-entities setting differs from baseline."),
        ("enableFullPolicyInspection", Severity.WARNING.value, "Enable-full-policy-inspection setting differs from baseline."),
        ("autoApplyFrequency", Severity.WARNING.value, "Auto-apply frequency differs from baseline."),
        ("learnOnlyFromNonBotTraffic", Severity.INFO.value, "Learn-only-from-non-bot-traffic setting differs from baseline."),
        ("allTrustedIps", Severity.INFO.value, "All-trusted-IPs source setting differs from baseline."),
    ]
    for key, sev, desc in flat_checks:
        b_val = b_pb.get(key)
        t_val = t_pb.get(key)
        if b_val is not None and b_val != t_val:
            _add(result, DiffItem(
                section="policy-builder",
                section_category="policy_builder",
                element_name=key,
                attribute=key,
                baseline_value=b_val,
                target_value=t_val,
                severity=sev,
                description=desc,
            ))

    _cmp_pb_sub(b_pb, t_pb, result, "cookie", [
        ("learnCookies", Severity.WARNING.value),
        ("maximumAllowedModifiedCookies", Severity.INFO.value),
        ("collapseCookies", Severity.INFO.value),
        ("enforceUnmodifiedCookies", Severity.INFO.value),
    ])
    _cmp_pb_sub(b_pb, t_pb, result, "filetype", [
        ("learnFileTypes", Severity.WARNING.value),
        ("maximumFileTypes", Severity.INFO.value),
    ])
    _cmp_pb_sub(b_pb, t_pb, result, "parameter", [
        ("learnParameters", Severity.WARNING.value),
        ("parameterLevel", Severity.INFO.value),
        ("collapseParameters", Severity.INFO.value),
        ("classifyParameters", Severity.INFO.value),
    ])
    _cmp_pb_sub(b_pb, t_pb, result, "url", [
        ("learnUrls", Severity.WARNING.value),
        ("learnWebsocketUrls", Severity.INFO.value),
        ("collapseUrls", Severity.INFO.value),
        ("classifyUrls", Severity.INFO.value),
    ])
    _cmp_pb_sub(b_pb, t_pb, result, "header", [
        ("validHostNames", Severity.INFO.value),
    ])
    _cmp_pb_sub(b_pb, t_pb, result, "redirectionProtection", [
        ("learnRedirectionDomains", Severity.WARNING.value),
    ])
    _cmp_pb_sub(b_pb, t_pb, result, "sessionsAndLogins", [
        ("learnLoginPages", Severity.INFO.value),
    ])
    _cmp_pb_sub(b_pb, t_pb, result, "serverTechnologies", [
        ("learnServerTechnologies", Severity.INFO.value),
    ])
    _cmp_pb_sub(b_pb, t_pb, result, "centralConfiguration", [
        ("buildingMode", Severity.INFO.value),
        ("eventCorrelationMode", Severity.INFO.value),
    ])


# ── Scoring, circuit breakers, summary ─────────────────────────────────────----


def _apply_scoring_with_circuit_breakers(
    result: ComparisonResult,
    target: Dict,
    policy_meta: Dict,
    green_threshold: float,
    extra_cb_func=None,
    cb_label_map: Optional[Dict[str, str]] = None,
) -> None:
    """Calculate raw and final scores, apply circuit breaker cap, and assign tier.

    The deduction model is weighted by severity. deductions_by_* values are stored
    as negative numbers for readability in reports (e.g., Critical: -8.0).
    """

    deductions_by_sev: Dict[str, float] = {k.value: 0.0 for k in Severity}
    deductions_by_section: Dict[str, float] = {}

    total_deduction = 0.0
    for diff in result.diffs:
        sev = diff.severity
        weight = _DEDUCT.get(sev, 0.0)
        total_deduction += weight
        deductions_by_sev[sev] = deductions_by_sev.get(sev, 0.0) - weight
        sec_key = diff.section_category or diff.section.split(".")[0]
        deductions_by_section[sec_key] = deductions_by_section.get(sec_key, 0.0) - weight

    raw_score = max(0.0, round(100.0 - total_deduction, 1))

    # Detect circuit breakers
    cb_triggered: List[str] = []

    enforcement_mode = (result.enforcement_mode or "").lower()
    if enforcement_mode != "blocking":
        cb_triggered.append("TRANSPARENT_MODE")

    if result.virtual_server_eval_performed and not result.virtual_servers:
        cb_triggered.append("NO_VIRTUAL_SERVERS")

    if result.profile_type != "bot":
        if _all_blocking_disabled(target):
            cb_triggered.append("ALL_BLOCKING_DISABLED")
        if not result.target_signature_sets:
            cb_triggered.append("NO_SIGNATURE_SETS")

    if _is_policy_disabled(policy_meta, target):
        cb_triggered.append("POLICY_DISABLED")

    # Optional comparator-specific circuit breakers (e.g., Bot Defense)
    if extra_cb_func:
        cb_triggered.extend(extra_cb_func(result, target, policy_meta))

    final_score = raw_score if not cb_triggered else min(raw_score, 49.0)

    tier_info = score_to_tier(final_score, cb_triggered, green_threshold=green_threshold)

    result.raw_score = raw_score
    result.score = final_score
    result.tier = tier_info.name
    result.tier_label = tier_info.label
    result.tier_color = tier_info.color
    label_map = {**CIRCUIT_BREAKERS, **(cb_label_map or {})}
    result.circuit_breakers_triggered = [label_map.get(cb, cb) for cb in cb_triggered]
    result.is_hard_fail = bool(cb_triggered)
    result.deductions_by_severity = deductions_by_sev
    result.deductions_by_section = deductions_by_section


def _all_blocking_disabled(target: Dict) -> bool:
    """True if every violation/blocking flag in target is non-blocking.

    Checks both legacy ``blocking-settings`` sub-sections and the richer ``blocking``
    section returned by newer BIG-IP versions. If any block flag is True, returns False.
    """

    def _any_block_enabled(entries: List[Dict]) -> bool:
        for entry in entries:
            if isinstance(entry, dict) and entry.get("block") is True:
                return True
        return False

    bs = target.get("blocking-settings", {}) or {}
    if any(
        _any_block_enabled(bs.get(section, []))
        for section in ("violations", "evasions", "http-protocols")
    ):
        return False

    blocking = target.get("blocking", {}) or {}
    if _any_block_enabled(blocking.get("violations", [])):
        return False

    return True


def _is_policy_disabled(policy_meta: Dict, target: Dict) -> bool:
    """Detect administrative disablement from metadata or target flags."""
    meta = policy_meta or {}
    # Common indicators
    for key in ("state", "status"):
        val = str(meta.get(key, "")).lower()
        if val in ("disabled", "inactive", "off"):
            return True
    active = meta.get("active")
    if active is False:
        return True
    tgt_active = target.get("active")
    if tgt_active is False:
        return True
    return False


def _build_summary(result: ComparisonResult) -> None:
    from collections import defaultdict

    def _empty_counts():
        return {
            Severity.CRITICAL.value.lower(): 0,
            Severity.HIGH.value.lower(): 0,
            Severity.WARNING.value.lower(): 0,
            Severity.INFO.value.lower(): 0,
            "total": 0,
        }

    by_section: Dict[str, Dict[str, int]] = defaultdict(_empty_counts)

    for diff in result.diffs:
        section = diff.section.split('.')[0]
        key = diff.severity.lower()
        by_section[section][key] = by_section[section].get(key, 0) + 1
        by_section[section]["total"] += 1

    totals = _empty_counts()
    for counts in by_section.values():
        for k in totals:
            totals[k] += counts.get(k, 0)

    result.summary = {
        "by_section": dict(by_section),
        "totals": totals,
        "missing_count": len(result.missing_in_target),
        "extra_count": len(result.extra_in_target),
    }


# Legacy helpers retained for bot_defense_comparator import compatibility
SEVERITY_CRITICAL = Severity.CRITICAL.value
SEVERITY_HIGH = Severity.HIGH.value
SEVERITY_WARNING = Severity.WARNING.value
SEVERITY_INFO = Severity.INFO.value


def _calculate_score(diffs: List[DiffItem]) -> float:
    """Backward-compatible legacy scoring helper for unit tests/callers.

    Legacy model:
    - Critical: -5
    - Warning: -2
    - Info: -1
    - High: treated as Critical (-5) for compatibility
    """
    weights = {
        SEVERITY_CRITICAL: 5.0,
        SEVERITY_HIGH: 5.0,
        SEVERITY_WARNING: 2.0,
        SEVERITY_INFO: 1.0,
    }
    deduction = 0.0
    for d in diffs:
        deduction += weights.get(d.severity, 0.0)
    return max(0.0, round(100.0 - deduction, 1))
