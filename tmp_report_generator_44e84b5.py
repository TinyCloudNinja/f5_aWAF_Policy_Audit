"""
Report generation: Markdown and self-contained HTML output.
"""
from __future__ import annotations

import html as _html_module
import re
from pathlib import Path
from typing import List, Optional

from .policy_comparator import ComparisonResult, DiffItem, SEVERITY_CRITICAL, SEVERITY_WARNING
from .utils import get_logger, ensure_dir, human_bool

_log = get_logger("report_generator")

_PASS_THRESHOLD = 90.0

# ── Policy Builder display config ──────────────────────────────────────────────

# (section_label, display_name, flat_key)
_PB_FLAT_ROWS = [
    ("Core", "Learning Mode",                   "learningMode"),
    ("Core", "Fully Automatic",                 "fullyAutomatic"),
    ("Core", "Client-Side Policy Building",     "clientSidePolicyBuilding"),
    ("Core", "Learn From Responses",            "learnFromResponses"),
    ("Core", "Learn Inactive Entities",         "learnInactiveEntities"),
    ("Core", "Enable Full Policy Inspection",   "enableFullPolicyInspection"),
    ("Core", "Auto Apply Frequency",            "autoApplyFrequency"),
    ("Core", "Auto Apply Start Time",           "autoApplyStartTime"),
    ("Core", "Auto Apply End Time",             "autoApplyEndTime"),
    ("Core", "Apply on All Days",               "applyOnAllDays"),
    ("Core", "Apply at All Times",              "applyAtAllTimes"),
    ("Core", "Learn Only from Non-Bot Traffic", "learnOnlyFromNonBotTraffic"),
    ("Core", "All Trusted IPs Source",          "allTrustedIps"),
    ("Core", "Response Codes",                  "responseCodes"),
]

# (section_label, display_name, sub_key, field_key)
_PB_SUB_ROWS = [
    ("Cookie",                  "Learn Cookies",               "cookie",                   "learnCookies"),
    ("Cookie",                  "Max Modified Cookies",        "cookie",                   "maximumAllowedModifiedCookies"),
    ("Cookie",                  "Collapse Cookies",            "cookie",                   "collapseCookies"),
    ("Cookie",                  "Enforce Unmodified Cookies",  "cookie",                   "enforceUnmodifiedCookies"),
    ("File Type",               "Learn File Types",            "filetype",                 "learnFileTypes"),
    ("File Type",               "Maximum File Types",          "filetype",                 "maximumFileTypes"),
    ("Parameter",               "Learn Parameters",            "parameter",                "learnParameters"),
    ("Parameter",               "Maximum Parameters",          "parameter",                "maximumParameters"),
    ("Parameter",               "Parameter Level",             "parameter",                "parameterLevel"),
    ("Parameter",               "Collapse Parameters",         "parameter",                "collapseParameters"),
    ("Parameter",               "Classify Parameters",         "parameter",                "classifyParameters"),
    ("URL",                     "Learn URLs",                  "url",                      "learnUrls"),
    ("URL",                     "Learn WebSocket URLs",        "url",                      "learnWebsocketUrls"),
    ("URL",                     "Maximum URLs",                "url",                      "maximumUrls"),
    ("URL",                     "Collapse URLs",               "url",                      "collapseUrls"),
    ("URL",                     "Classify URLs",               "url",                      "classifyUrls"),
    ("Header",                  "Valid Host Names",            "header",                   "validHostNames"),
    ("Header",                  "Maximum Hosts",               "header",                   "maximumHosts"),
    ("Redirection Protection",  "Learn Redirection Domains",   "redirectionProtection",    "learnRedirectionDomains"),
    ("Redirection Protection",  "Max Redirection Domains",     "redirectionProtection",    "maximumRedirectionDomains"),
    ("Sessions & Logins",       "Learn Login Pages",           "sessionsAndLogins",        "learnLoginPages"),
    ("Server Technologies",     "Learn Server Technologies",   "serverTechnologies",       "learnServerTechnologies"),
    ("Central Configuration",   "Building Mode",               "centralConfiguration",     "buildingMode"),
    ("Central Configuration",   "Event Correlation Mode",      "centralConfiguration",     "eventCorrelationMode"),
]


# ── Markdown ───────────────────────────────────────────────────────────────────

def generate_markdown(result: ComparisonResult, output_dir: str) -> Path:
    """Write a Markdown audit report. Returns the file path."""
    reports_dir = ensure_dir(Path(output_dir) / "reports")
    safe_name = result.policy_name.replace('/', '_').replace(' ', '_')
    is_bot = getattr(result, "profile_type", "waf") == "bot"
    prefix = "BOT" if is_bot else "WAF"
    out_path = reports_dir / f"{prefix}_{safe_name}_audit_report.md"

    lines: List[str] = []
    _md_header(lines, result)
    if not is_bot:
        _md_signature_sets_table(lines, result)
        _md_policy_builder_status(lines, result)
        _md_violations_table(lines, result)
    else:
        _md_bot_mitigation_settings(lines, result)
        _md_bot_signature_enforcement(lines, result)
        _md_bot_whitelist(lines, result)
        _md_bot_browsers(lines, result)
        _md_bot_overrides(lines, result)
    _md_summary_table(lines, result)
    _md_findings(lines, result)
    if not is_bot:
        _md_blocking_comparison(lines, result)
    _md_extra_missing(lines, result)

    out_path.write_text('\n'.join(lines), encoding='utf-8')
    _log.info("Markdown report: %s", out_path)
    return out_path


def _md_header(lines: List[str], result: ComparisonResult) -> None:
    score = result.score
    status = "PASS" if score >= _PASS_THRESHOLD else "FAIL"
    is_bot = getattr(result, "profile_type", "waf") == "bot"

    # Device identity line — show hostname (mgmt-ip) when both are available,
    # otherwise fall back to whichever value is present.
    if result.device_hostname and result.device_mgmt_ip:
        device_line = f"`{result.device_hostname}` ({result.device_mgmt_ip})"
    elif result.device_hostname:
        device_line = f"`{result.device_hostname}`"
    elif result.device_mgmt_ip:
        device_line = result.device_mgmt_ip
    else:
        device_line = "*(unknown)*"

    report_kind = "Bot Defense Profile" if is_bot else "WAF Policy"
    subject_label = "Profile" if is_bot else "Policy"
    baseline_label = "Baseline Profile" if is_bot else "Baseline Policy"

    lines += [
        f"# {report_kind} Compliance Report for `{result.policy_path}` on {device_line}",
        "",
        f"**Source Device:** {device_line}",
        "",
        f"## {subject_label}: `{result.policy_path}`",
        "",
        f"- **Partition:** {result.partition}",
        f"- **Enforcement Mode:** {result.enforcement_mode}",
        f"- **{baseline_label}:** {result.baseline_name}",
        f"- **Audit Date:** {result.timestamp}",
        f"- **Compliance Score:** {score:.1f}% — **{status}** (threshold: {_PASS_THRESHOLD:.0f}%)",
        "",
    ]
    # Virtual server bindings
    vs_list = result.virtual_servers
    lines.append("### Virtual Server Bindings")
    lines.append("")
    if vs_list:
        lines.append("| Virtual Server | IP Address | Port | Association | Local Traffic Policies |")
        lines.append("|----------------|:----------:|:----:|:-----------:|------------------------|")
        for vs in vs_list:
            assoc = vs.get("association_type", "direct")
            ltm_names = ", ".join(
                f"`{p.get('fullPath', p.get('name', ''))}`"
                for p in vs.get("ltm_policies", [])
            ) or "*(none)*"
            lines.append(
                f"| `{vs.get('fullPath', vs.get('name', ''))}` "
                f"| {vs.get('ip', '—')} "
                f"| {vs.get('port', '—')} "
                f"| {assoc} "
                f"| {ltm_names} |"
            )
        lines.append("")

        # Per-VS LTM policy rule detail
        policy_col = "Bot Defense Profile" if is_bot else "WAF Security Policy"
        for vs in vs_list:
            for ltp in vs.get("ltm_policies", []):
                rules = ltp.get("rules", [])
                if not rules:
                    continue
                vs_path = vs.get('fullPath', vs.get('name', ''))
                ltp_path = ltp.get('fullPath', ltp.get('name', ''))
                lines += [
                    f"#### LTM Policy `{ltp_path}` on `{vs_path}`",
                    "",
                    f"| Rule | Host Condition(s) | {policy_col} |",
                    "|------|:-----------------:|---------------------|",
                ]
                for rule in rules:
                    hosts = ", ".join(
                        f"`{h}`" for h in rule.get("host_conditions", [])
                    ) or "*(any)*"
                    if is_bot:
                        sec_pol = f"`{rule['bot_profile']}`" if rule.get("bot_profile") else "*(none)*"
                    else:
                        sec_pol = f"`{rule['waf_policy']}`" if rule.get("waf_policy") else "*(none)*"
                    lines.append(
                        f"| `{rule.get('name', '')}` | {hosts} | {sec_pol} |"
                    )
                lines.append("")
    else:
        lines += [
            "*No virtual server bindings found for this policy.*",
            "",
        ]


def _md_signature_sets_table(lines: List[str], result: ComparisonResult) -> None:
    """Render a Markdown table of all Attack Signature Sets applied to this policy."""
    sig_sets = result.target_signature_sets
    if not sig_sets:
        return

    # Build a lookup for baseline values to flag differences
    baseline_map = {s["name"]: s for s in result.baseline_signature_sets}

    lines += [
        "## Attack Signature Sets",
        "",
        "All Attack Signature Sets applied to this policy and their Learn / Alarm / Block status.",
        "",
        "| Signature Set Name | Type | Learn | Alarm | Block | Baseline Match |",
        "|--------------------|------|:-----:|:-----:|:-----:|:--------------:|",
    ]

    for ss in sorted(sig_sets, key=lambda s: s.get("name", "")):
        name  = ss.get("name", "")
        stype = ss.get("signatureSetType", "filter-based")
        learn = human_bool(ss.get("learn", False))
        alarm = human_bool(ss.get("alarm", False))
        block = human_bool(ss.get("block", False))

        bss = baseline_map.get(name)
        if bss is None:
            match_cell = "— N/A"
        elif any(ss.get(a) != bss.get(a) for a in ("learn", "alarm", "block")):
            match_cell = "✗ Mismatch"
        else:
            match_cell = "✓ Match"

        lines.append(
            f"| {name} | {stype} | {learn} | {alarm} | {block} | {match_cell} |"
        )

    lines.append("")


def _md_policy_builder_status(lines: List[str], result: ComparisonResult) -> None:
    pb_t = result.policy_builder_target
    pb_b = result.policy_builder_baseline

    if not pb_t:
        return

    learning_mode = pb_t.get("learningMode", "unknown")
    bl_learning_mode = pb_b.get("learningMode", "") if pb_b else ""

    # Mode label + indicator
    mode_upper = learning_mode.upper()
    if learning_mode.lower() in ("automatic", "automatic-only"):
        mode_indicator = "✅ AUTOMATIC"
    elif learning_mode.lower() == "manual":
        mode_indicator = "⚠ MANUAL"
    elif learning_mode.lower() in ("disabled", ""):
        mode_indicator = "🔴 DISABLED"
    else:
        mode_indicator = f"ℹ {mode_upper}"

    differs = bl_learning_mode and bl_learning_mode.lower() != learning_mode.lower()
    baseline_note = f" *(Baseline: `{bl_learning_mode}`)*" if differs else ""

    lines += [
        "## Policy Builder Status",
        "",
        f"**Learning Mode:** `{learning_mode}` — **{mode_indicator}**{baseline_note}",
        "",
    ]

    # Full comparison table
    lines += [
        "### Policy Builder Settings",
        "",
        "| Section | Setting | Baseline | Target | Match |",
        "|---------|---------|----------|--------|-------|",
    ]

    def _fmt(val) -> str:
        if val is None or val == "":
            return "*(n/a)*"
        if isinstance(val, list):
            return ", ".join(str(v) for v in val) if val else "*(empty)*"
        return human_bool(val)

    def _match(b_val, t_val) -> str:
        if b_val is None or b_val == "":
            return "—"
        return "✓" if b_val == t_val else "⚠"

    for section, label, key in _PB_FLAT_ROWS:
        t_val = pb_t.get(key)
        b_val = pb_b.get(key) if pb_b else None
        lines.append(
            f"| {section} | {label} | {_fmt(b_val)} | {_fmt(t_val)} | {_match(b_val, t_val)} |"
        )

    for section, label, sub_key, field_key in _PB_SUB_ROWS:
        t_val = pb_t.get(sub_key, {}).get(field_key)
        b_val = pb_b.get(sub_key, {}).get(field_key) if pb_b else None
        lines.append(
            f"| {section} | {label} | {_fmt(b_val)} | {_fmt(t_val)} | {_match(b_val, t_val)} |"
        )

    lines.append("")


def _md_summary_table(lines: List[str], result: ComparisonResult) -> None:
    lines += [
        "## Executive Summary",
        "",
        "| Category | Critical | Warning | Info | Total |",
        "|----------|----------|---------|------|-------|",
    ]
    for section, counts in sorted(result.summary.get("by_section", {}).items()):
        lines.append(
            f"| {section} | {counts['critical']} | {counts['warning']} | {counts['info']} | {counts['total']} |"
        )
    totals = result.summary.get("totals", {})
    lines += [
        f"| **Totals** | **{totals.get('critical',0)}** | **{totals.get('warning',0)}** | **{totals.get('info',0)}** | **{totals.get('total',0)}** |",
        "",
        f"- **Missing elements (in baseline, absent in target):** {result.summary.get('missing_count', 0)}",
        f"- **Extra elements (in target, not in baseline):** {result.summary.get('extra_count', 0)}",
        "",
    ]


def _md_findings(lines: List[str], result: ComparisonResult) -> None:
    for sev_label, sev_key in [
        ("Critical Findings (Protections Disabled)", SEVERITY_CRITICAL),
        ("Warning Findings (Configuration Drift)",   SEVERITY_WARNING),
        ("Informational Findings",                   "info"),
    ]:
        items = [d for d in result.diffs if d.severity == sev_key]
        if not items:
            continue
        lines.append(f"## {sev_label}")
        lines.append("")
        for i, diff in enumerate(items, 1):
            lines += [
                f"### {i}. {diff.section}: {diff.element_name}",
                f"- **Attribute:** `{diff.attribute}`",
                f"- **Baseline:** {human_bool(diff.baseline_value)}",
                f"- **This Policy:** {human_bool(diff.target_value)}",
                f"- **Impact:** {diff.description}",
                "",
            ]


def _md_violations_table(lines: List[str], result: ComparisonResult) -> None:
    if not result.violations:
        return

    # Detect whether violations come from the richer <blocking> section (have 'id')
    has_id = any(v.get("id") for v in result.violations)

    # Build baseline lookup: keyed by id (falling back to name)
    baseline_map: dict = {}
    for bv in result.baseline_violations:
        key = bv.get("id") or bv.get("name", "")
        if key:
            baseline_map[key] = bv

    lines += ["## WAF Violations Status", ""]

    _MATCH = "✓ Match"
    _MISMATCH = "✗ Mismatch"
    _NO_BASELINE = "— N/A"

    def _baseline_match_md(v: dict, bv: dict | None) -> tuple[str, str]:
        """Return (match_cell, baseline_settings_cell) for markdown."""
        if bv is None:
            return _NO_BASELINE, "*(not in baseline)*"
        attrs = ["alarm", "block", "learn"]
        differs = any(v.get(a) != bv.get(a) for a in attrs)
        match_cell = _MISMATCH if differs else _MATCH
        bl_settings = (
            f"A:{human_bool(bv.get('alarm', False))} "
            f"B:{human_bool(bv.get('block', False))} "
            f"L:{human_bool(bv.get('learn', False))}"
        )
        return match_cell, bl_settings

    if has_id:
        lines += [
            "| ID | Violation Name | Alarm | Block | Learn | PB Tracking | Matches Baseline | Baseline (A/B/L) |",
            "|----|----------------|:-----:|:-----:|:-----:|:-----------:|:----------------:|:----------------:|",
        ]
        for v in sorted(result.violations, key=lambda x: x.get("id", x.get("name", ""))):
            vid = v.get("id") or v.get("name", "")
            bv = baseline_map.get(vid)
            match_cell, bl_settings = _baseline_match_md(v, bv)
            pb = human_bool(v.get("policyBuilderTracking", False))
            lines.append(
                f"| `{v.get('id', '')}` "
                f"| {v.get('name', '')} "
                f"| {human_bool(v.get('alarm', False))} "
                f"| {human_bool(v.get('block', False))} "
                f"| {human_bool(v.get('learn', False))} "
                f"| {pb} "
                f"| {match_cell} "
                f"| {bl_settings} |"
            )
    else:
        lines += [
            "| Violation | Alarm | Block | Learn | Matches Baseline | Baseline (A/B/L) |",
            "|-----------|:-----:|:-----:|:-----:|:----------------:|:----------------:|",
        ]
        for v in sorted(result.violations, key=lambda x: x.get("name", "")):
            vname = v.get("name", "")
            bv = baseline_map.get(vname)
            match_cell, bl_settings = _baseline_match_md(v, bv)
            lines.append(
                f"| {vname} "
                f"| {human_bool(v.get('alarm', False))} "
                f"| {human_bool(v.get('block', False))} "
                f"| {human_bool(v.get('learn', False))} "
                f"| {match_cell} "
                f"| {bl_settings} |"
            )

    lines.append("")


def _md_blocking_comparison(lines: List[str], result: ComparisonResult) -> None:
    """Render a side-by-side baseline-vs-target table for <blocking> violations."""
    blocking_diffs = [d for d in result.diffs if d.section == "blocking"]
    if not blocking_diffs and not result.violations:
        return

    # Build a map of violation id → list of diff attributes for quick lookup
    diff_by_id: dict = {}
    for d in blocking_diffs:
        if d.element_name not in ("enforcement_mode",):
            diff_by_id.setdefault(d.element_name, []).append(d)

    lines += [
        "## Blocking Section — Violations Comparison",
        "",
        "Compares each violation's Alarm / Block / Learn flags against the baseline.",
        "Cells marked with ⚠ differ from baseline; 🚨 indicates a critical security gap.",
        "",
        "| ID | Violation Name | Attr | Baseline | Target | Severity |",
        "|----|----------------|------|:--------:|:------:|----------|",
    ]

    if not blocking_diffs:
        lines += ["| — | *(no differences detected)* | — | — | — | — |", ""]
        return

    for d in blocking_diffs:
        icon = "🚨" if d.severity == SEVERITY_CRITICAL else "⚠"
        name = d.element_name
        # Try to resolve display name from violations list
        for v in result.violations:
            if (v.get("id") or v.get("name")) == d.element_name:
                name = v.get("name", d.element_name)
                break
        lines.append(
            f"| `{d.element_name}` "
            f"| {name} "
            f"| `{d.attribute}` "
            f"| {human_bool(d.baseline_value)} "
            f"| {human_bool(d.target_value)} "
            f"| {icon} {d.severity.upper()} |"
        )
    lines.append("")


def _md_extra_missing(lines: List[str], result: ComparisonResult) -> None:
    if result.extra_in_target:
        lines.append("## Extra Elements Not in Baseline")
        lines.append("")
        lines.append("Items present in this policy but not in the baseline:")
        lines.append("")
        for item in result.extra_in_target:
            lines.append(f"- `{item}`")
        lines.append("")

    if result.missing_in_target:
        lines.append("## Missing Elements From Baseline")
        lines.append("")
        lines.append("Items expected from baseline that are absent in this policy:")
        lines.append("")
        for item in result.missing_in_target:
            lines.append(f"- `{item}`")
        lines.append("")


# ── HTML ───────────────────────────────────────────────────────────────────────

_CSS = """
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Arial,Helvetica,sans-serif;background:#f5f6f8;color:#333;padding:20px}
h1{color:#1a1a2e;margin-bottom:8px}
h2{color:#16213e;margin:24px 0 8px;border-bottom:2px solid #e0e0e0;padding-bottom:4px}
h3{color:#0f3460;margin:14px 0 6px}
.meta{background:#fff;border-radius:6px;padding:16px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
.meta table{border-collapse:collapse;width:100%}
.meta td{padding:4px 10px;vertical-align:top}
.meta td:first-child{font-weight:bold;color:#555;width:220px}
.score-bar{height:24px;border-radius:4px;background:#e0e0e0;overflow:hidden;margin:6px 0}
.score-fill{height:100%;transition:width .4s}
.score-pass{background:#28a745}
.score-fail{background:#dc3545}
.badge{display:inline-block;padding:2px 10px;border-radius:10px;font-size:.8em;font-weight:bold;color:#fff}
.badge-critical{background:#dc3545}
.badge-warning{background:#fd7e14}
.badge-info{background:#17a2b8}
.badge-pass{background:#28a745}
.badge-fail{background:#dc3545}
.badge-manual{background:#fd7e14}
.badge-automatic{background:#28a745}
.badge-disabled{background:#dc3545}
.badge-unknown{background:#6c757d}
.pb-banner{border-radius:6px;padding:14px 18px;margin:16px 0;display:flex;align-items:center;gap:14px;font-size:1em}
.pb-banner-manual{background:#fff3cd;border:1px solid #ffc107}
.pb-banner-automatic{background:#d4edda;border:1px solid #28a745}
.pb-banner-disabled{background:#f8d7da;border:1px solid #dc3545}
.pb-banner-unknown{background:#e2e3e5;border:1px solid #adb5bd}
.pb-banner .pb-mode-label{font-size:1.1em;font-weight:bold}
.pb-banner .pb-baseline-note{font-size:.85em;color:#555;margin-left:6px}
table.findings{width:100%;border-collapse:collapse;margin:8px 0;font-size:.9em}
table.findings th{background:#1a1a2e;color:#fff;padding:8px 10px;text-align:left}
table.findings td{padding:7px 10px;border-bottom:1px solid #e0e0e0;vertical-align:top}
table.findings tr:nth-child(even){background:#f9f9f9}
table.findings tr:hover{background:#eef3ff}
table.findings td.match-ok{color:#28a745;font-weight:bold;text-align:center}
table.findings td.match-diff{color:#dc3545;font-weight:bold;text-align:center}
table.findings td.match-na{color:#aaa;text-align:center}
.summary-table{width:100%;border-collapse:collapse;margin:8px 0}
.summary-table th{background:#16213e;color:#fff;padding:8px 10px}
.summary-table td{padding:7px 10px;border-bottom:1px solid #e0e0e0;text-align:center}
.summary-table td:first-child{text-align:left}
details{background:#fff;border:1px solid #ddd;border-radius:6px;margin:10px 0;padding:0}
summary{padding:12px 16px;cursor:pointer;font-weight:bold;color:#16213e;list-style:none;display:flex;align-items:center;gap:8px}
summary::-webkit-details-marker{display:none}
summary::before{content:"▶";font-size:.8em;transition:transform .2s}
details[open] summary::before{transform:rotate(90deg)}
.details-body{padding:4px 16px 16px}
.list-items li{padding:3px 0;font-family:monospace;font-size:.85em}
@media print{
  .score-bar{-webkit-print-color-adjust:exact}
  .pb-banner{-webkit-print-color-adjust:exact}
  details{display:block}
  details summary::before{display:none}
}
</style>
"""

def _e(text) -> str:
    """HTML-escape a value."""
    return _html_module.escape(str(text))


def _build_policy_report_fragment(result: ComparisonResult, embedded: bool = False) -> str:
    """Build the HTML body fragment for one policy/profile report."""

    score = result.score
    is_bot = getattr(result, "profile_type", "waf") == "bot"
    pass_fail = "PASS" if score >= _PASS_THRESHOLD else "FAIL"
    score_class = "score-pass" if score >= _PASS_THRESHOLD else "score-fail"
    badge_pf = f'<span class="badge badge-{pass_fail.lower()}">{pass_fail}</span>'

    # Build virtual server rows for the meta table
    vs_list = result.virtual_servers
    if vs_list:
        vs_rows = []
        for vs in vs_list:
            vs_name = _e(vs.get('fullPath', vs.get('name', '')))
            vs_ip   = _e(vs.get('ip', '—'))
            vs_port = _e(vs.get('port', '—'))
            assoc   = _e(vs.get('association_type', 'direct'))
            ltm_policies = vs.get("ltm_policies", [])
            ltm_cell = (
                ", ".join(f"<code>{_e(p.get('fullPath', p.get('name','')))}</code>"
                          for p in ltm_policies)
                if ltm_policies else "<em>none</em>"
            )
            vs_rows.append(
                f"<tr>"
                f"<td style='padding-left:20px'>&#8627; <code>{vs_name}</code></td>"
                f"<td>{vs_ip}:{vs_port}</td>"
                f"<td>{assoc}</td>"
                f"<td>{ltm_cell}</td>"
                f"</tr>"
            )
        vs_html = (
            f"<tr><td>Virtual Server Bindings</td><td>"
            f"<table style='width:100%;border-collapse:collapse'>"
            f"<thead><tr>"
            f"<th style='text-align:left;font-weight:normal;color:#555'>Name</th>"
            f"<th style='text-align:left;font-weight:normal;color:#555'>IP:Port</th>"
            f"<th style='text-align:left;font-weight:normal;color:#555'>Association</th>"
            f"<th style='text-align:left;font-weight:normal;color:#555'>Local Traffic Policies</th>"
            f"</tr></thead><tbody>"
            + "".join(vs_rows) +
            f"</tbody></table></td></tr>"
        )
    else:
        vs_html = "<tr><td>Virtual Server Bindings</td><td><em>None found</em></td></tr>"

    # Device identity cell
    if result.device_hostname and result.device_mgmt_ip:
        device_cell = (
            f"<strong>{_e(result.device_hostname)}</strong>"
            f"&nbsp;<span style='color:#555;font-size:.9em'>({_e(result.device_mgmt_ip)})</span>"
        )
    elif result.device_hostname:
        device_cell = f"<strong>{_e(result.device_hostname)}</strong>"
    elif result.device_mgmt_ip:
        device_cell = _e(result.device_mgmt_ip)
    else:
        device_cell = "<em>unknown</em>"

    report_kind = "Bot Defense Profile" if is_bot else "WAF Policy"
    subject_label = "Profile" if is_bot else "Policy"
    baseline_label = "Baseline Profile" if is_bot else "Baseline Policy"

    parts = []
    if embedded:
        parts.append(
            f"<h2>{report_kind} Compliance Report for {_e(result.policy_path)}</h2>"
        )
    else:
        parts.append(
            f"<h1>{report_kind} Compliance Report for {_e(result.policy_path)} on {device_cell}</h1>"
        )

    parts += [
        "<div class='meta'>",
        "<table>",
        f"<tr><td>Source Device</td><td>{device_cell}</td></tr>",
        f"<tr><td>{subject_label}</td><td><code>{_e(result.policy_path)}</code></td></tr>",
        f"<tr><td>Partition</td><td>{_e(result.partition)}</td></tr>",
        f"<tr><td>Enforcement Mode</td><td>{_e(result.enforcement_mode)}</td></tr>",
    ]
    parts.append(vs_html)
    parts += [
        f"<tr><td>{baseline_label}</td><td>{_e(result.baseline_name)}</td></tr>",
        f"<tr><td>Audit Date</td><td>{_e(result.timestamp)}</td></tr>",
        f"<tr><td>Compliance Score</td><td><strong>{score:.1f}%</strong> {badge_pf}</td></tr>",
        "</table>",
        f"<div class='score-bar'><div class='{score_class} score-fill' style='width:{min(score,100):.1f}%'></div></div>",
        "</div>",
    ]

    # LTM policy rule detail (collapsible, after the meta block) — shown for
    # both WAF and Bot Defense profiles whenever LTM policy bindings exist.
    ltm_section = _html_ltm_policy_section(vs_list, is_bot=is_bot)
    if ltm_section:
        parts.append(ltm_section)

    if not is_bot:
        # Policy Builder status banner + settings table
        parts.append(_html_policy_builder_status(result))

        # Attack Signature Sets inventory — always shown, after Policy Builder
        parts.append(_html_signature_sets_table(result))

        # WAF Violations Status — collapsible, directly after Policy Builder
        if result.violations:
            parts.append(
                "<details><summary><h2 style='display:inline;font-size:1em'>"
                f"WAF Violations Status ({len(result.violations)})</h2></summary>"
                "<div class='details-body'>"
            )
            parts.append(_html_violations_table(result.violations, result.baseline_violations))
            parts.append("</div></details>")
    else:
        # Bot Defense sections: Mitigation Settings, Signature Enforcement, Whitelist, Browsers
        bot_mit = _html_bot_mitigation_table(result)
        if bot_mit:
            parts.append(bot_mit)
        bot_sig = _html_bot_signature_enforcement_table(result)
        if bot_sig:
            parts.append(bot_sig)
        bot_wl = _html_bot_whitelist_table(result)
        if bot_wl:
            parts.append(bot_wl)
        bot_br = _html_bot_browsers_table(result)
        if bot_br:
            parts.append(bot_br)

    # Executive summary
    parts.append("<h2>Executive Summary</h2>")
    parts.append(_html_summary_table(result))

    # Findings per severity
    for sev_label, sev_key, badge_cls in [
        ("Critical Findings", SEVERITY_CRITICAL, "critical"),
        ("Warning Findings",  SEVERITY_WARNING,  "warning"),
        ("Informational Findings", "info",        "info"),
    ]:
        items = [d for d in result.diffs if d.severity == sev_key]
        if not items:
            continue
        parts.append(
            f"<details open><summary>"
            f"<span class='badge badge-{badge_cls}'>{sev_label}</span>"
            f"&nbsp;({len(items)})</summary>"
            f"<div class='details-body'>"
        )
        parts.append(_html_findings_table(items))
        parts.append("</div></details>")

    # Blocking violations comparison — collapsible (WAF mode only)
    if not is_bot:
        blocking_diffs = [d for d in result.diffs if d.section == "blocking"]
        if blocking_diffs or result.violations:
            n = len(blocking_diffs)
            parts.append(
                f"<details><summary><h2 style='display:inline;font-size:1em'>"
                f"Blocking Section — Violations Comparison ({n} diff{'s' if n != 1 else ''})</h2>"
                f"</summary><div class='details-body'>"
                f"<p style='margin:8px 0'>Each violation's Alarm / Block / Learn flags compared against the baseline.</p>"
            )
            parts.append(_html_blocking_comparison_table(blocking_diffs, result.violations))
            parts.append("</div></details>")

    # Extra / missing
    if result.extra_in_target:
        parts.append("<details><summary>Extra Elements Not in Baseline "
                     f"({len(result.extra_in_target)})</summary>"
                     "<div class='details-body'><ul class='list-items'>")
        for item in result.extra_in_target:
            parts.append(f"<li>{_e(str(item))}</li>")
        parts.append("</ul></div></details>")

    if result.missing_in_target:
        parts.append("<details><summary>Missing Elements From Baseline "
                     f"({len(result.missing_in_target)})</summary>"
                     "<div class='details-body'><ul class='list-items'>")
        for item in result.missing_in_target:
            parts.append(f"<li>{_e(str(item))}</li>")
        parts.append("</ul></div></details>")

    return "\n".join(parts)


def generate_html(result: ComparisonResult, output_dir: str) -> Path:
    """Write a self-contained HTML audit report. Returns the file path."""
    reports_dir = ensure_dir(Path(output_dir) / "reports")
    safe_name = result.policy_name.replace('/', '_').replace(' ', '_')
    is_bot = getattr(result, "profile_type", "waf") == "bot"
    prefix = "BOT" if is_bot else "WAF"
    out_path = reports_dir / f"{prefix}_{safe_name}_audit_report.html"

    page_title = f"{'Bot Defense' if is_bot else 'WAF'} Audit: {_e(result.policy_path)}"
    content = (
        "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
        f"<title>{page_title}</title>"
        f"{_CSS}"
        "</head><body>"
        f"{_build_policy_report_fragment(result, embedded=False)}"
        "</body></html>"
    )

    out_path.write_text(content, encoding='utf-8')
    _log.info("HTML report: %s", out_path)
    return out_path


def _safe_dom_id(text: str, index: int) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_-]+", "-", text).strip("-").lower()
    if not cleaned:
        cleaned = "item"
    return f"report-{index}-{cleaned}"


def generate_html_dashboard(results: List[ComparisonResult], output_dir: str) -> Path:
    """
    Generate one interactive HTML report containing all audited policies/profiles.
    Layout: title pane, left navigation pane, and main report pane.
    """
    reports_dir = ensure_dir(Path(output_dir) / "reports")
    if not results:
        raise ValueError("No comparison results provided for HTML dashboard generation")

    is_bot = any(getattr(r, "profile_type", "waf") == "bot" for r in results)
    subject_label = "Profiles" if is_bot else "Policies"
    prefix = "BOT" if is_bot else "WAF"
    out_path = reports_dir / f"{prefix}_audit_dashboard.html"

    sorted_results = sorted(results, key=lambda r: r.policy_path.lower())

    first = sorted_results[0]
    if first.device_hostname and first.device_mgmt_ip:
        device_line = (
            f"<strong>{_e(first.device_hostname)}</strong>"
            f" <span style='color:#d7deff'>({_e(first.device_mgmt_ip)})</span>"
        )
    elif first.device_hostname:
        device_line = f"<strong>{_e(first.device_hostname)}</strong>"
    elif first.device_mgmt_ip:
        device_line = _e(first.device_mgmt_ip)
    else:
        device_line = "<em>unknown</em>"

    nav_items = []
    report_panels = []
    for idx, result in enumerate(sorted_results):
        dom_id = _safe_dom_id(result.policy_path, idx)
        status = "PASS" if result.score >= _PASS_THRESHOLD else "FAIL"
        nav_items.append(
            f"<button class='nav-item{' active' if idx == 0 else ''}' "
            f"data-target='{dom_id}' title='{_e(result.policy_path)}'>"
            f"<span class='nav-name'>{_e(result.policy_path)}</span>"
            f"<span class='badge badge-{'pass' if status == 'PASS' else 'fail'}'>{status}</span>"
            f"</button>"
        )
        report_panels.append(
            f"<section id='{dom_id}' class='report-panel{' active' if idx == 0 else ''}'>"
            f"{_build_policy_report_fragment(result, embedded=True)}"
            f"</section>"
        )

    dashboard_css = """
<style>
body{padding:0;margin:0;background:#eef1f6}
.dashboard-grid{display:grid;grid-template-columns:320px 1fr;grid-template-rows:82px calc(100vh - 82px);height:100vh}
.title-pane{grid-column:1 / 3;background:#16213e;color:#fff;padding:14px 18px;display:flex;flex-direction:column;justify-content:center;gap:6px;border-bottom:1px solid #22355f}
.title-pane h1{margin:0;color:#fff;font-size:1.2rem}
.title-sub{font-size:.9rem;color:#d7deff}
.nav-pane{background:#fff;border-right:1px solid #d7dce8;overflow:auto;padding:10px}
.nav-list{display:flex;flex-direction:column;gap:8px}
.nav-item{width:100%;border:1px solid #d8deea;background:#f8faff;border-radius:6px;padding:10px;display:flex;justify-content:space-between;align-items:center;gap:8px;cursor:pointer;text-align:left}
.nav-item:hover{background:#edf2ff}
.nav-item.active{border-color:#3f63b8;background:#e8efff;box-shadow:inset 0 0 0 1px #3f63b8}
.nav-name{display:block;font-family:monospace;font-size:.85rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.report-pane{overflow:auto;padding:16px}
.report-panel{display:none}
.report-panel.active{display:block}
.report-panel h2{margin-top:0}
</style>
"""

    content = (
        "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
        f"<title>{'Bot Defense' if is_bot else 'WAF'} Audit Dashboard</title>"
        f"{_CSS}{dashboard_css}"
        "</head><body>"
        "<div class='dashboard-grid'>"
        "<header class='title-pane'>"
        f"<h1>{'Bot Defense' if is_bot else 'WAF'} Audit Dashboard</h1>"
        f"<div class='title-sub'>Source Device: {device_line}</div>"
        f"<div class='title-sub'>{len(sorted_results)} audited {subject_label.lower()}</div>"
        "</header>"
        "<aside class='nav-pane'>"
        f"<h3 style='margin:4px 0 10px;color:#16213e'>{subject_label}</h3>"
        "<div class='nav-list'>"
        + "".join(nav_items) +
        "</div></aside>"
        "<main class='report-pane'>"
        + "".join(report_panels) +
        "</main></div>"
        "<script>"
        "(function(){"
        "const buttons=document.querySelectorAll('.nav-item');"
        "const panels=document.querySelectorAll('.report-panel');"
        "buttons.forEach(btn=>btn.addEventListener('click',()=>{"
        "const target=btn.getAttribute('data-target');"
        "buttons.forEach(b=>b.classList.remove('active'));"
        "panels.forEach(p=>p.classList.remove('active'));"
        "btn.classList.add('active');"
        "const panel=document.getElementById(target);"
        "if(panel){panel.classList.add('active');window.scrollTo({top:0,behavior:'smooth'});}"
        "}));"
        "})();"
        "</script>"
        "</body></html>"
    )

    out_path.write_text(content, encoding='utf-8')
    _log.info("HTML dashboard report: %s", out_path)
    return out_path


def _html_summary_table(result: ComparisonResult) -> str:
    rows = []
    for section, counts in sorted(result.summary.get("by_section", {}).items()):
        rows.append(
            f"<tr><td>{_e(section)}</td>"
            f"<td>{counts['critical']}</td>"
            f"<td>{counts['warning']}</td>"
            f"<td>{counts['info']}</td>"
            f"<td>{counts['total']}</td></tr>"
        )
    totals = result.summary.get("totals", {})
    rows.append(
        f"<tr style='font-weight:bold'><td>Totals</td>"
        f"<td>{totals.get('critical',0)}</td>"
        f"<td>{totals.get('warning',0)}</td>"
        f"<td>{totals.get('info',0)}</td>"
        f"<td>{totals.get('total',0)}</td></tr>"
    )
    return (
        "<table class='summary-table'>"
        "<thead><tr><th>Category</th><th>Critical</th><th>Warning</th><th>Info</th><th>Total</th></tr></thead>"
        "<tbody>" + "".join(rows) + "</tbody></table>"
    )


def _html_signature_sets_table(result: ComparisonResult) -> str:
    """Render a collapsible HTML table of all applied Attack Signature Sets."""
    sig_sets = result.target_signature_sets
    baseline_map = {s["name"]: s for s in result.baseline_signature_sets}

    rows = []
    for ss in sorted(sig_sets, key=lambda s: s.get("name", "")):
        name  = _e(ss.get("name", ""))
        stype = _e(ss.get("signatureSetType", "filter-based"))
        learn = human_bool(ss.get("learn", False))
        alarm = human_bool(ss.get("alarm", False))
        block = human_bool(ss.get("block", False))

        bss = baseline_map.get(ss.get("name", ""))
        if bss is None:
            match_td = "<td class='match-na'>— N/A</td>"
        elif any(ss.get(a) != bss.get(a) for a in ("learn", "alarm", "block")):
            match_td = "<td class='match-diff'>✗ Mismatch</td>"
        else:
            match_td = "<td class='match-ok'>✓ Match</td>"

        rows.append(
            f"<tr>"
            f"<td>{name}</td>"
            f"<td>{stype}</td>"
            f"<td style='text-align:center'>{_e(learn)}</td>"
            f"<td style='text-align:center'>{_e(alarm)}</td>"
            f"<td style='text-align:center'>{_e(block)}</td>"
            f"{match_td}"
            f"</tr>"
        )

    n = len(sig_sets)
    count_label = str(n) if n else "none"

    if not rows:
        body = (
            "<p style='margin:8px 0;color:#777'>"
            "<em>No Attack Signature Sets found in this policy export. "
            "Verify that the policy XML includes a &lt;signature-sets&gt; section.</em>"
            "</p>"
        )
    else:
        body = (
            f"<p style='margin:8px 0'>Attack Signature Sets applied to this policy "
            f"and their Learn / Alarm / Block status.</p>"
            f"<table class='findings'>"
            f"<thead><tr>"
            f"<th>Signature Set Name</th><th>Type</th>"
            f"<th style='text-align:center'>Learn</th>"
            f"<th style='text-align:center'>Alarm</th>"
            f"<th style='text-align:center'>Block</th>"
            f"<th style='text-align:center'>Baseline Match</th>"
            f"</tr></thead><tbody>"
            + "".join(rows) +
            "</tbody></table>"
        )

    return (
        f"<h2>Attack Signature Sets</h2>"
        f"<details open><summary>Signature Set Inventory ({count_label})</summary>"
        f"<div class='details-body'>{body}</div></details>"
    )


def _html_ltm_policy_section(vs_list: List[Dict], is_bot: bool = False) -> str:
    """
    Render a collapsible HTML section showing LTM policy rules for all
    virtual servers that have Local Traffic Policies attached.

    For WAF profiles each rule row shows: rule name | host condition(s) |
    WAF security policy.  For Bot Defense profiles the last column shows the
    Bot Defense profile referenced by the rule's botDefense action.
    Returns an empty string when there are no LTM policies to display.
    """
    # Collect (vs_path, ltp_path, [rules]) tuples that have content
    entries = []
    for vs in vs_list:
        for ltp in vs.get("ltm_policies", []):
            rules = ltp.get("rules", [])
            if rules:
                entries.append((
                    vs.get("fullPath", vs.get("name", "")),
                    ltp.get("fullPath", ltp.get("name", "")),
                    rules,
                ))

    if not entries:
        return ""

    total_rules = sum(len(e[2]) for e in entries)
    policy_col_header = "Bot Defense Profile" if is_bot else "WAF Security Policy"
    section_title = (
        f"Local Traffic Policy — Host-to-Bot-Defense Mappings ({total_rules} rule{'s' if total_rules != 1 else ''})"
        if is_bot else
        f"Local Traffic Policy — Host-to-WAF Mappings ({total_rules} rule{'s' if total_rules != 1 else ''})"
    )
    section_desc = (
        "Rules from LTM policies that map host conditions to Bot Defense profiles on each virtual server."
        if is_bot else
        "Rules from LTM policies that map host conditions to WAF security policies on each virtual server."
    )
    parts = [
        f"<details open><summary>"
        f"<h2 style='display:inline;font-size:1em'>"
        f"{section_title}"
        f"</h2></summary>"
        f"<div class='details-body'>"
        f"<p style='margin:8px 0'>{section_desc}</p>"
    ]

    for vs_path, ltp_path, rules in entries:
        rows = []
        for rule in rules:
            hosts = rule.get("host_conditions", [])
            host_cell = (
                " ".join(f"<code>{_e(h)}</code>" for h in hosts)
                if hosts else "<em>any</em>"
            )
            if is_bot:
                sec_pol = rule.get("bot_profile", "")
            else:
                sec_pol = rule.get("waf_policy", "")
            pol_cell = f"<code>{_e(sec_pol)}</code>" if sec_pol else "<em style='color:#999'>none</em>"
            rows.append(
                f"<tr>"
                f"<td><code>{_e(rule.get('name', ''))}</code></td>"
                f"<td>{host_cell}</td>"
                f"<td>{pol_cell}</td>"
                f"</tr>"
            )

        parts.append(
            f"<h3 style='margin:14px 0 4px'>"
            f"<code>{_e(ltp_path)}</code>"
            f" <span style='font-weight:normal;font-size:.85em;color:#555'>"
            f"on <code>{_e(vs_path)}</code></span></h3>"
            f"<table class='findings'>"
            f"<thead><tr>"
            f"<th>Rule</th><th>Host Condition(s)</th><th>{_e(policy_col_header)}</th>"
            f"</tr></thead><tbody>"
            + "".join(rows) +
            f"</tbody></table>"
        )

    parts.append("</div></details>")
    return "".join(parts)


def _html_policy_builder_status(result: ComparisonResult) -> str:
    pb_t = result.policy_builder_target
    pb_b = result.policy_builder_baseline

    if not pb_t:
        return ""

    learning_mode = pb_t.get("learningMode", "unknown")
    bl_learning_mode = pb_b.get("learningMode", "") if pb_b else ""
    mode_lc = learning_mode.lower()

    if mode_lc in ("automatic", "automatic-only"):
        banner_cls, badge_cls, icon = "pb-banner-automatic", "badge-automatic", "&#10003;"
    elif mode_lc == "manual":
        banner_cls, badge_cls, icon = "pb-banner-manual",    "badge-manual",    "&#9888;"
    elif mode_lc in ("disabled", ""):
        banner_cls, badge_cls, icon = "pb-banner-disabled",  "badge-disabled",  "&#10007;"
    else:
        banner_cls, badge_cls, icon = "pb-banner-unknown",   "badge-unknown",   "&#8505;"

    differs = bl_learning_mode and bl_learning_mode.lower() != mode_lc
    baseline_note = (
        f"<span class='pb-baseline-note'>(Baseline: <code>{_e(bl_learning_mode)}</code>)</span>"
        if differs else ""
    )

    banner = (
        f"<h2>Policy Builder Status</h2>"
        f"<div class='pb-banner {_e(banner_cls)}'>"
        f"<span class='badge {_e(badge_cls)}'>{icon} {_e(learning_mode.upper())}</span>"
        f"<span class='pb-mode-label'>Learning Mode: <strong>{_e(learning_mode)}</strong></span>"
        f"{baseline_note}"
        f"</div>"
    )

    # Settings comparison table
    def _fmt(val) -> str:
        if val is None or val == "":
            return "<em>n/a</em>"
        if isinstance(val, list):
            return _e(", ".join(str(v) for v in val)) if val else "<em>empty</em>"
        return _e(human_bool(val))

    rows = []
    last_section = None

    all_rows = (
        [(sec, label, pb_t.get(key), pb_b.get(key) if pb_b else None)
         for sec, label, key in _PB_FLAT_ROWS]
        +
        [(sec, label, pb_t.get(sub, {}).get(fld), pb_b.get(sub, {}).get(fld) if pb_b else None)
         for sec, label, sub, fld in _PB_SUB_ROWS]
    )

    for section, label, t_val, b_val in all_rows:
        if section != last_section:
            rows.append(
                f"<tr style='background:#e8ecf5'>"
                f"<td colspan='4' style='font-weight:bold;color:#16213e;padding:6px 10px'>"
                f"{_e(section)}</td></tr>"
            )
            last_section = section

        if b_val is None or b_val == "":
            match_td = "<td class='match-na'>—</td>"
        elif b_val == t_val:
            match_td = "<td class='match-ok'>&#10003;</td>"
        else:
            match_td = "<td class='match-diff'>&#9888;</td>"

        rows.append(
            f"<tr>"
            f"<td>{_e(label)}</td>"
            f"<td>{_fmt(b_val)}</td>"
            f"<td>{_fmt(t_val)}</td>"
            f"{match_td}"
            f"</tr>"
        )

    table = (
        "<details open><summary>Policy Builder Settings Comparison</summary>"
        "<div class='details-body'>"
        "<table class='findings'>"
        "<thead><tr>"
        "<th>Setting</th><th>Baseline</th><th>Target</th><th>Match</th>"
        "</tr></thead><tbody>"
        + "".join(rows) +
        "</tbody></table>"
        "</div></details>"
    )

    return banner + table


def _html_findings_table(diffs: List[DiffItem]) -> str:
    rows = []
    for diff in diffs:
        badge = f"<span class='badge badge-{_e(diff.severity)}'>{_e(diff.severity.upper())}</span>"
        rows.append(
            f"<tr>"
            f"<td>{_e(diff.section)}</td>"
            f"<td>{_e(diff.element_name)}</td>"
            f"<td><code>{_e(diff.attribute)}</code></td>"
            f"<td>{_e(human_bool(diff.baseline_value))}</td>"
            f"<td>{_e(human_bool(diff.target_value))}</td>"
            f"<td>{_e(diff.description)}</td>"
            f"<td>{badge}</td>"
            f"</tr>"
        )
    return (
        "<table class='findings'>"
        "<thead><tr>"
        "<th>Section</th><th>Element</th><th>Attribute</th>"
        "<th>Baseline</th><th>Target</th><th>Description</th><th>Severity</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


# ── Bot Defense dedicated display helpers ──────────────────────────────────────

# Settings shown in the Bot Mitigation Settings table, in display order.
# Tuples: (section_label, display_name, key)
_BD_MITIGATION_ROWS = [
    ("Core",         "Enforcement Mode",                 "enforcementMode"),
    ("Core",         "Template",                         "template"),
    ("Core",         "Browser Mitigation Action",        "browserMitigationAction"),
    ("Core",         "Allow Browser Access",             "allowBrowserAccess"),
    ("Core",         "API Access Strict Mitigation",     "apiAccessStrictMitigation"),
    ("Core",         "DoS Attack Strict Mitigation",     "dosAttackStrictMitigation"),
    ("Core",         "Signature Staging Upon Update",    "signatureStagingUponUpdate"),
    ("Core",         "Cross-Domain Requests",            "crossDomainRequests"),
    ("Advanced",     "Perform Challenge In Transparent", "performChallengeInTransparent"),
    ("Advanced",     "Single Page Application",          "singlePageApplication"),
    ("Advanced",     "Device ID Mode",                   "deviceidMode"),
    ("Advanced",     "Grace Period (seconds)",           "gracePeriod"),
    ("Advanced",     "Enforcement Readiness Period (days)", "enforcementReadinessPeriod"),
]


def _html_bot_mitigation_table(result: ComparisonResult) -> str:
    """Render a collapsible Bot Mitigation Settings comparison table (HTML)."""
    t_cfg = result.bot_mitigation_target
    b_cfg = result.bot_mitigation_baseline
    if not t_cfg:
        return ""

    def _fmt(val) -> str:
        if val is None or val == "":
            return "<em>n/a</em>"
        if isinstance(val, bool):
            return _e(human_bool(val))
        return _e(str(val))

    rows = []
    last_section = None
    for section, label, key in _BD_MITIGATION_ROWS:
        if section != last_section:
            rows.append(
                f"<tr style='background:#e8ecf5'>"
                f"<td colspan='4' style='font-weight:bold;color:#16213e;padding:6px 10px'>"
                f"{_e(section)}</td></tr>"
            )
            last_section = section

        t_val = t_cfg.get(key)
        b_val = b_cfg.get(key)

        if b_val is None or b_val == "":
            match_td = "<td class='match-na'>—</td>"
        elif b_val == t_val:
            match_td = "<td class='match-ok'>&#10003;</td>"
        else:
            match_td = "<td class='match-diff'>&#9888;</td>"

        rows.append(
            f"<tr>"
            f"<td>{_e(label)}</td>"
            f"<td>{_fmt(b_val)}</td>"
            f"<td>{_fmt(t_val)}</td>"
            f"{match_td}"
            f"</tr>"
        )

    table = (
        "<details open><summary>Bot Mitigation Settings Comparison</summary>"
        "<div class='details-body'>"
        "<table class='findings'>"
        "<thead><tr>"
        "<th>Setting</th><th>Baseline</th><th>Target</th><th>Match</th>"
        "</tr></thead><tbody>"
        + "".join(rows) +
        "</tbody></table>"
        "</div></details>"
    )
    return "<h2>Bot Mitigation Settings</h2>" + table


def _html_bot_signature_enforcement_table(result: ComparisonResult) -> str:
    """Render a collapsible Bot Signature Enforcement table (HTML)."""
    rows_data = result.bot_signatures
    if not rows_data:
        return ""

    rows = []
    for row in sorted(rows_data, key=lambda r: r.get("name", "")):
        name = _e(row.get("name", ""))
        b_enabled = row.get("baseline_enabled")
        t_enabled = row.get("target_enabled")
        b_action  = row.get("baseline_action")
        t_action  = row.get("target_action")
        bm        = row.get("baseline_match", "match")

        if bm == "extra":
            match_td = "<td class='match-na'>+ Extra</td>"
        elif bm == "missing":
            match_td = "<td class='match-diff'>&#9888; Missing</td>"
        elif bm == "diff":
            match_td = "<td class='match-diff'>&#9888; Differs</td>"
        else:
            match_td = "<td class='match-ok'>&#10003; Match</td>"

        rows.append(
            f"<tr>"
            f"<td>{name}</td>"
            f"<td style='text-align:center'>{_e(human_bool(b_enabled)) if b_enabled is not None else '<em>—</em>'}</td>"
            f"<td style='text-align:center'>{_e(human_bool(t_enabled)) if t_enabled is not None else '<em>—</em>'}</td>"
            f"<td style='text-align:center'>{_e(str(b_action)) if b_action is not None else '<em>—</em>'}</td>"
            f"<td style='text-align:center'>{_e(str(t_action)) if t_action is not None else '<em>—</em>'}</td>"
            f"{match_td}"
            f"</tr>"
        )

    n = len(rows_data)
    body = (
        f"<p style='margin:8px 0'>Bot signature categories and their enforcement status.</p>"
        f"<table class='findings'>"
        f"<thead><tr>"
        f"<th>Category Name</th>"
        f"<th style='text-align:center'>Baseline Enabled</th>"
        f"<th style='text-align:center'>Target Enabled</th>"
        f"<th style='text-align:center'>Baseline Action</th>"
        f"<th style='text-align:center'>Target Action</th>"
        f"<th style='text-align:center'>Baseline Match</th>"
        f"</tr></thead><tbody>"
        + "".join(rows) +
        "</tbody></table>"
    )
    return (
        f"<h2>Signature Enforcement</h2>"
        f"<details open><summary>Signature Category Inventory ({n})</summary>"
        f"<div class='details-body'>{body}</div></details>"
    )


def _html_bot_whitelist_table(result: ComparisonResult) -> str:
    """Render a collapsible Bot Defense Whitelist table (HTML)."""
    rows_data = result.bot_whitelist
    if not rows_data:
        return ""

    rows = []
    for row in sorted(rows_data, key=lambda r: r.get("name", "")):
        name = _e(row.get("name", ""))
        bm   = row.get("baseline_match", "match")
        t_e  = row.get("target_entry") or {}
        b_e  = row.get("baseline_entry") or {}

        match_type = _e(t_e.get("matchType") or b_e.get("matchType") or "—")
        ip_addr    = _e(t_e.get("ipAddress") or b_e.get("ipAddress") or "—")
        ip_mask    = _e(t_e.get("ipMask")    or b_e.get("ipMask")    or "—")
        enabled    = t_e.get("enabled") if t_e else b_e.get("enabled")
        desc_val   = _e(t_e.get("description") or b_e.get("description") or "")

        if bm == "extra":
            match_td = "<td class='match-na'>+ Added</td>"
        elif bm == "missing":
            match_td = "<td class='match-diff'>&#9888; Removed</td>"
        elif bm == "diff":
            match_td = "<td class='match-diff'>&#9888; Differs</td>"
        else:
            match_td = "<td class='match-ok'>&#10003; Match</td>"

        rows.append(
            f"<tr>"
            f"<td>{name}</td>"
            f"<td>{match_type}</td>"
            f"<td>{ip_addr}</td>"
            f"<td>{ip_mask}</td>"
            f"<td style='text-align:center'>{_e(human_bool(enabled)) if enabled is not None else '<em>—</em>'}</td>"
            f"<td>{desc_val}</td>"
            f"{match_td}"
            f"</tr>"
        )

    n = len(rows_data)
    body = (
        f"<p style='margin:8px 0'>Whitelist (trusted source) entries and their comparison to the baseline.</p>"
        f"<table class='findings'>"
        f"<thead><tr>"
        f"<th>Name</th><th>Match Type</th><th>IP Address</th><th>IP Mask</th>"
        f"<th style='text-align:center'>Enabled</th><th>Description</th>"
        f"<th style='text-align:center'>Baseline Match</th>"
        f"</tr></thead><tbody>"
        + "".join(rows) +
        "</tbody></table>"
    )
    return (
        f"<h2>Whitelist (Trusted Sources)</h2>"
        f"<details open><summary>Whitelist Entry Inventory ({n})</summary>"
        f"<div class='details-body'>{body}</div></details>"
    )


def _html_bot_browsers_table(result: ComparisonResult) -> str:
    """Render a collapsible Bot Defense Browsers table (HTML)."""
    rows_data = result.bot_browsers
    if not rows_data:
        return ""

    rows = []
    for row in sorted(rows_data, key=lambda r: r.get("name", "")):
        name = _e(row.get("name", ""))
        bm   = row.get("baseline_match", "match")
        t_e  = row.get("target_entry") or {}
        b_e  = row.get("baseline_entry") or {}

        t_enabled = t_e.get("enabled")
        b_enabled = b_e.get("enabled")

        if bm == "extra":
            match_td = "<td class='match-na'>+ Added</td>"
        elif bm == "missing":
            match_td = "<td class='match-diff'>&#9888; Removed</td>"
        elif bm == "diff":
            match_td = "<td class='match-diff'>&#9888; Differs</td>"
        else:
            match_td = "<td class='match-ok'>&#10003; Match</td>"

        rows.append(
            f"<tr>"
            f"<td>{name}</td>"
            f"<td style='text-align:center'>{_e(human_bool(b_enabled)) if b_enabled is not None else '<em>—</em>'}</td>"
            f"<td style='text-align:center'>{_e(human_bool(t_enabled)) if t_enabled is not None else '<em>—</em>'}</td>"
            f"{match_td}"
            f"</tr>"
        )

    n = len(rows_data)
    body = (
        f"<p style='margin:8px 0'>Browser validation entries and their comparison to the baseline.</p>"
        f"<table class='findings'>"
        f"<thead><tr>"
        f"<th>Browser Name</th>"
        f"<th style='text-align:center'>Baseline Enabled</th>"
        f"<th style='text-align:center'>Target Enabled</th>"
        f"<th style='text-align:center'>Baseline Match</th>"
        f"</tr></thead><tbody>"
        + "".join(rows) +
        "</tbody></table>"
    )
    return (
        f"<h2>Browsers</h2>"
        f"<details open><summary>Browser Entry Inventory ({n})</summary>"
        f"<div class='details-body'>{body}</div></details>"
    )


def _html_bot_overrides_table(result: ComparisonResult) -> str:
    """Render a collapsible Bot Defense Overrides table (HTML)."""
    rows_data = result.bot_overrides
    if not rows_data:
        return ""

    rows = []
    for row in sorted(rows_data, key=lambda r: (r.get("collection", ""), r.get("name", ""))):
        collection = _e(row.get("collection", ""))
        name = _e(row.get("name", ""))
        bm = row.get("baseline_match", "match")

        if bm == "extra":
            match_td = "<td class='match-diff'>&#9888; Added Override</td>"
        elif bm == "missing":
            match_td = "<td class='match-na'>Removed</td>"
        elif bm == "diff":
            match_td = "<td class='match-diff'>&#9888; Differs</td>"
        else:
            match_td = "<td class='match-ok'>&#10003; Match</td>"

        rows.append(
            f"<tr>"
            f"<td>{collection}</td>"
            f"<td><code>{name}</code></td>"
            f"{match_td}"
            f"</tr>"
        )

    n = len(rows_data)
    body = (
        "<p style='margin:8px 0'>"
        "Override collections found in the target Bot Defense profile compared to baseline."
        "</p>"
        "<table class='findings'>"
        "<thead><tr>"
        "<th>Collection</th><th>Entry</th><th style='text-align:center'>Baseline Match</th>"
        "</tr></thead><tbody>"
        + "".join(rows) +
        "</tbody></table>"
    )
    return (
        f"<h2>Bot Defense Overrides</h2>"
        f"<details open><summary>Override Entry Inventory ({n})</summary>"
        f"<div class='details-body'>{body}</div></details>"
    )


# ── Markdown Bot Defense helpers ────────────────────────────────────────────────

def _md_bot_mitigation_settings(lines: List[str], result: ComparisonResult) -> None:
    """Render Bot Mitigation Settings comparison table (Markdown)."""
    t_cfg = result.bot_mitigation_target
    b_cfg = result.bot_mitigation_baseline
    if not t_cfg:
        return

    def _fmt(val) -> str:
        if val is None or val == "":
            return "*(n/a)*"
        return human_bool(val)

    def _match(b_val, t_val) -> str:
        if b_val is None or b_val == "":
            return "—"
        return "✓" if b_val == t_val else "✗"

    lines += [
        "## Bot Mitigation Settings",
        "",
        "| Section | Setting | Baseline | Target | Match |",
        "|---------|---------|----------|--------|-------|",
    ]
    for section, label, key in _BD_MITIGATION_ROWS:
        t_val = t_cfg.get(key)
        b_val = b_cfg.get(key)
        lines.append(
            f"| {section} | {label} | {_fmt(b_val)} | {_fmt(t_val)} | {_match(b_val, t_val)} |"
        )
    lines.append("")


def _md_bot_signature_enforcement(lines: List[str], result: ComparisonResult) -> None:
    """Render Bot Signature Enforcement table (Markdown)."""
    rows_data = result.bot_signatures
    if not rows_data:
        return

    lines += [
        "## Signature Enforcement",
        "",
        "Bot signature categories and their enforcement status.",
        "",
        "| Category Name | Baseline Enabled | Target Enabled | Baseline Action | Target Action | Baseline Match |",
        "|---------------|:----------------:|:--------------:|:---------------:|:-------------:|:--------------:|",
    ]
    for row in sorted(rows_data, key=lambda r: r.get("name", "")):
        bm = row.get("baseline_match", "match")
        match_cell = {"extra": "+ Extra", "missing": "⚠ Missing", "diff": "✗ Differs"}.get(bm, "✓ Match")
        b_en = human_bool(row.get("baseline_enabled")) if row.get("baseline_enabled") is not None else "—"
        t_en = human_bool(row.get("target_enabled")) if row.get("target_enabled") is not None else "—"
        b_ac = str(row.get("baseline_action") or "—")
        t_ac = str(row.get("target_action") or "—")
        lines.append(
            f"| {row.get('name', '')} | {b_en} | {t_en} | {b_ac} | {t_ac} | {match_cell} |"
        )
    lines.append("")


def _md_bot_whitelist(lines: List[str], result: ComparisonResult) -> None:
    """Render Bot Defense Whitelist table (Markdown)."""
    rows_data = result.bot_whitelist
    if not rows_data:
        return

    lines += [
        "## Whitelist (Trusted Sources)",
        "",
        "Whitelist entries and their comparison to the baseline.",
        "",
        "| Name | Match Type | IP Address | IP Mask | Enabled | Baseline Match |",
        "|------|:----------:|:----------:|:-------:|:-------:|:--------------:|",
    ]
    for row in sorted(rows_data, key=lambda r: r.get("name", "")):
        bm  = row.get("baseline_match", "match")
        t_e = row.get("target_entry") or {}
        b_e = row.get("baseline_entry") or {}
        match_cell = {"extra": "+ Added", "missing": "⚠ Removed", "diff": "✗ Differs"}.get(bm, "✓ Match")
        mt   = t_e.get("matchType") or b_e.get("matchType") or "—"
        ip   = t_e.get("ipAddress") or b_e.get("ipAddress") or "—"
        mask = t_e.get("ipMask")    or b_e.get("ipMask")    or "—"
        en   = t_e.get("enabled") if t_e else b_e.get("enabled")
        en_s = human_bool(en) if en is not None else "—"
        lines.append(f"| {row.get('name', '')} | {mt} | {ip} | {mask} | {en_s} | {match_cell} |")
    lines.append("")


def _md_bot_browsers(lines: List[str], result: ComparisonResult) -> None:
    """Render Bot Defense Browsers table (Markdown)."""
    rows_data = result.bot_browsers
    if not rows_data:
        return

    lines += [
        "## Browsers",
        "",
        "Browser validation entries and their comparison to the baseline.",
        "",
        "| Browser Name | Baseline Enabled | Target Enabled | Baseline Match |",
        "|-------------|:----------------:|:--------------:|:--------------:|",
    ]
    for row in sorted(rows_data, key=lambda r: r.get("name", "")):
        bm  = row.get("baseline_match", "match")
        t_e = row.get("target_entry") or {}
        b_e = row.get("baseline_entry") or {}
        match_cell = {"extra": "+ Added", "missing": "⚠ Removed", "diff": "✗ Differs"}.get(bm, "✓ Match")
        b_en = human_bool(b_e.get("enabled")) if b_e.get("enabled") is not None else "—"
        t_en = human_bool(t_e.get("enabled")) if t_e.get("enabled") is not None else "—"
        lines.append(f"| {row.get('name', '')} | {b_en} | {t_en} | {match_cell} |")
    lines.append("")


def _md_bot_overrides(lines: List[str], result: ComparisonResult) -> None:
    """Render Bot Defense Overrides table (Markdown)."""
    rows_data = result.bot_overrides
    if not rows_data:
        return

    lines += [
        "## Bot Defense Overrides",
        "",
        "Override collections found in the target profile and their comparison to baseline.",
        "",
        "| Collection | Entry | Baseline Match |",
        "|------------|-------|----------------|",
    ]
    for row in sorted(rows_data, key=lambda r: (r.get("collection", ""), r.get("name", ""))):
        bm = row.get("baseline_match", "match")
        match_cell = {"extra": "⚠ Added Override", "missing": "Removed", "diff": "✗ Differs"}.get(bm, "✓ Match")
        lines.append(f"| {row.get('collection', '')} | `{row.get('name', '')}` | {match_cell} |")
    lines.append("")


def _html_blocking_comparison_table(diffs: List[DiffItem], violations: List[dict]) -> str:
    """
    Render a side-by-side baseline-vs-target HTML table for <blocking> violations.
    Each row shows a single attribute difference for a specific violation id.
    """
    # Build id → display name lookup from violations list
    id_to_name = {}
    for v in violations:
        vid = v.get("id") or v.get("name", "")
        id_to_name[vid] = v.get("name", vid)

    if not diffs:
        return "<p><em>No differences detected in the blocking violations section.</em></p>"

    rows = []
    for d in diffs:
        sev_cls = d.severity
        badge = f"<span class='badge badge-{_e(sev_cls)}'>{_e(d.severity.upper())}</span>"
        display_name = id_to_name.get(d.element_name, d.element_name)
        rows.append(
            f"<tr>"
            f"<td><code>{_e(d.element_name)}</code></td>"
            f"<td>{_e(display_name)}</td>"
            f"<td><code>{_e(d.attribute)}</code></td>"
            f"<td>{_e(human_bool(d.baseline_value))}</td>"
            f"<td>{_e(human_bool(d.target_value))}</td>"
            f"<td>{_e(d.description)}</td>"
            f"<td>{badge}</td>"
            f"</tr>"
        )
    return (
        "<table class='findings'>"
        "<thead><tr>"
        "<th>Violation ID</th><th>Name</th><th>Attribute</th>"
        "<th>Baseline</th><th>Target</th><th>Description</th><th>Severity</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def _html_violations_table(violations: List[dict], baseline_violations: List[dict] | None = None) -> str:
    has_id = any(v.get("id") for v in violations)
    rows = []

    # Build baseline lookup
    baseline_map: dict = {}
    for bv in (baseline_violations or []):
        key = bv.get("id") or bv.get("name", "")
        if key:
            baseline_map[key] = bv

    def _flag_badge(val: bool) -> str:
        cls = "pass" if val else "fail"
        label = "Yes" if val else "No"
        return f"<span class='badge badge-{cls}'>{label}</span>"

    def _match_badge(v: dict, bv: dict | None) -> str:
        if bv is None:
            return "<span class='badge badge-info'>N/A</span>"
        attrs = ["alarm", "block", "learn"]
        differs = any(v.get(a) != bv.get(a) for a in attrs)
        if differs:
            return "<span class='badge badge-fail'>Mismatch</span>"
        return "<span class='badge badge-pass'>Match</span>"

    def _baseline_settings(bv: dict | None) -> str:
        if bv is None:
            return "<em>not in baseline</em>"
        return (
            f"A:{_flag_badge(bv.get('alarm', False))} "
            f"B:{_flag_badge(bv.get('block', False))} "
            f"L:{_flag_badge(bv.get('learn', False))}"
        )

    if has_id:
        for v in sorted(violations, key=lambda x: x.get("id", x.get("name", ""))):
            vid = v.get("id") or v.get("name", "")
            bv = baseline_map.get(vid)
            rows.append(
                f"<tr>"
                f"<td><code>{_e(v.get('id', ''))}</code></td>"
                f"<td>{_e(v.get('name', ''))}</td>"
                f"<td>{_flag_badge(v.get('alarm', False))}</td>"
                f"<td>{_flag_badge(v.get('block', False))}</td>"
                f"<td>{_flag_badge(v.get('learn', False))}</td>"
                f"<td>{_flag_badge(v.get('policyBuilderTracking', False))}</td>"
                f"<td>{_match_badge(v, bv)}</td>"
                f"<td>{_baseline_settings(bv)}</td>"
                f"</tr>"
            )
        return (
            "<table class='findings'>"
            "<thead><tr>"
            "<th>ID</th><th>Violation Name</th>"
            "<th>Alarm</th><th>Block</th><th>Learn</th><th>PB Tracking</th>"
            "<th>Matches Baseline</th><th>Baseline (A/B/L)</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        )
    else:
        for v in sorted(violations, key=lambda x: x.get("name", "")):
            vname = v.get("name", "")
            bv = baseline_map.get(vname)
            rows.append(
                f"<tr>"
                f"<td>{_e(vname)}</td>"
                f"<td>{_flag_badge(v.get('alarm', False))}</td>"
                f"<td>{_flag_badge(v.get('block', False))}</td>"
                f"<td>{_flag_badge(v.get('learn', False))}</td>"
                f"<td>{_match_badge(v, bv)}</td>"
                f"<td>{_baseline_settings(bv)}</td>"
                f"</tr>"
            )
        return (
            "<table class='findings'>"
            "<thead><tr>"
            "<th>Violation</th><th>Alarm</th><th>Block</th><th>Learn</th>"
            "<th>Matches Baseline</th><th>Baseline (A/B/L)</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        )


def _build_policy_report_fragment(result: ComparisonResult, embedded: bool = False) -> str:
    """Build the inner report HTML for a single policy/profile (no <html>/<body>)."""
    score = result.score
    pass_fail = "PASS" if score >= _PASS_THRESHOLD else "FAIL"
    score_class = "score-pass" if score >= _PASS_THRESHOLD else "score-fail"
    badge_pf = f'<span class="badge badge-{pass_fail.lower()}">{pass_fail}</span>'

    is_bot = getattr(result, "profile_type", "waf") == "bot"

    # Build virtual server rows for the meta table
    vs_list = result.virtual_servers
    if vs_list:
        vs_rows = []
        for vs in vs_list:
            vs_name = _e(vs.get('fullPath', vs.get('name', '')))
            vs_ip   = _e(vs.get('ip', '—'))
            vs_port = _e(vs.get('port', '—'))
            assoc   = _e(vs.get('association_type', 'direct'))
            ltm_policies = vs.get("ltm_policies", [])
            ltm_cell = (
                ", ".join(f"<code>{_e(p.get('fullPath', p.get('name','')))}</code>"
                          for p in ltm_policies)
                if ltm_policies else "<em>none</em>"
            )
            vs_rows.append(
                f"<tr>"
                f"<td style='padding-left:20px'>&#8627; <code>{vs_name}</code></td>"
                f"<td>{vs_ip}:{vs_port}</td>"
                f"<td>{assoc}</td>"
                f"<td>{ltm_cell}</td>"
                f"</tr>"
            )
        vs_html = (
            f"<tr><td>Virtual Server Bindings</td><td>"
            f"<table style='width:100%;border-collapse:collapse'>"
            f"<thead><tr>"
            f"<th style='text-align:left;font-weight:normal;color:#555'>Name</th>"
            f"<th style='text-align:left;font-weight:normal;color:#555'>IP:Port</th>"
            f"<th style='text-align:left;font-weight:normal;color:#555'>Association</th>"
            f"<th style='text-align:left;font-weight:normal;color:#555'>Local Traffic Policies</th>"
            f"</tr></thead><tbody>"
            + "".join(vs_rows) +
            f"</tbody></table></td></tr>"
        )
    else:
        vs_html = "<tr><td>Virtual Server Bindings</td><td><em>None found</em></td></tr>"

    # Device identity cell
    if result.device_hostname and result.device_mgmt_ip:
        device_cell = (
            f"<strong>{_e(result.device_hostname)}</strong>"
            f"&nbsp;<span style='color:#555;font-size:.9em'>({_e(result.device_mgmt_ip)})</span>"
        )
    elif result.device_hostname:
        device_cell = f"<strong>{_e(result.device_hostname)}</strong>"
    elif result.device_mgmt_ip:
        device_cell = _e(result.device_mgmt_ip)
    else:
        device_cell = "<em>unknown</em>"

    report_kind = "Bot Defense Profile" if is_bot else "WAF Policy"
    subject_label = "Profile" if is_bot else "Policy"
    baseline_label = "Baseline Profile" if is_bot else "Baseline Policy"

    title_html = (
        f"<h2>{report_kind} Compliance Report for {_e(result.policy_path)}</h2>"
        if embedded else
        f"<h1>{report_kind} Compliance Report for {_e(result.policy_path)} on {device_cell}</h1>"
    )

    parts = [
        title_html,
        "<div class='meta'>",
        "<table>",
        f"<tr><td>Source Device</td><td>{device_cell}</td></tr>",
        f"<tr><td>{subject_label}</td><td><code>{_e(result.policy_path)}</code></td></tr>",
        f"<tr><td>Partition</td><td>{_e(result.partition)}</td></tr>",
        f"<tr><td>Enforcement Mode</td><td>{_e(result.enforcement_mode)}</td></tr>",
    ]
    parts.append(vs_html)
    parts += [
        f"<tr><td>{baseline_label}</td><td>{_e(result.baseline_name)}</td></tr>",
        f"<tr><td>Audit Date</td><td>{_e(result.timestamp)}</td></tr>",
        f"<tr><td>Compliance Score</td><td><strong>{score:.1f}%</strong> {badge_pf}</td></tr>",
        "</table>",
        f"<div class='score-bar'><div class='{score_class} score-fill' style='width:{min(score,100):.1f}%'></div></div>",
        "</div>",
    ]

    ltm_section = _html_ltm_policy_section(vs_list, is_bot=is_bot)
    if ltm_section:
        parts.append(ltm_section)

    if not is_bot:
        parts.append(_html_policy_builder_status(result))
        parts.append(_html_signature_sets_table(result))

        if result.violations:
            parts.append(
                "<details><summary><h2 style='display:inline;font-size:1em'>"
                f"WAF Violations Status ({len(result.violations)})</h2></summary>"
                "<div class='details-body'>"
            )
            parts.append(_html_violations_table(result.violations, result.baseline_violations))
        # Bot Defense sections: Mitigation Settings, Signature Enforcement, Whitelist, Browsers, Overrides
    else:
        bot_mit = _html_bot_mitigation_table(result)
        if bot_mit:
            parts.append(bot_mit)
        bot_sig = _html_bot_signature_enforcement_table(result)
        if bot_sig:
            parts.append(bot_sig)
        bot_wl = _html_bot_whitelist_table(result)
        if bot_wl:
            parts.append(bot_wl)
        bot_br = _html_bot_browsers_table(result)
        if bot_br:
            parts.append(bot_br)
        bot_ov = _html_bot_overrides_table(result)
        if bot_ov:
            parts.append(bot_ov)

    parts.append("<h2>Executive Summary</h2>")
    parts.append(_html_summary_table(result))

    for sev_label, sev_key, badge_cls in [
        ("Critical Findings", SEVERITY_CRITICAL, "critical"),
        ("Warning Findings",  SEVERITY_WARNING,  "warning"),
        ("Informational Findings", "info",      "info"),
    ]:
        items = [d for d in result.diffs if d.severity == sev_key]
        if not items:
            continue
        parts.append(
            f"<details open><summary>"
            f"<span class='badge badge-{badge_cls}'>{sev_label}</span>"
            f"&nbsp;({len(items)})</summary>"
            f"<div class='details-body'>"
        )
        parts.append(_html_findings_table(items))
        parts.append("</div></details>")

    if not is_bot:
        blocking_diffs = [d for d in result.diffs if d.section == "blocking"]
        if blocking_diffs or result.violations:
            n = len(blocking_diffs)
            parts.append(
                f"<details><summary><h2 style='display:inline;font-size:1em'>"
                f"Blocking Section — Violations Comparison ({n} diff{'s' if n != 1 else ''})</h2>"
                f"</summary><div class='details-body'>"
                f"<p style='margin:8px 0'>Each violation's Alarm / Block / Learn flags compared against the baseline.</p>"
            )
            parts.append(_html_blocking_comparison_table(blocking_diffs, result.violations))
            parts.append("</div></details>")

    if result.extra_in_target:
        parts.append("<details><summary>Extra Elements Not in Baseline "
                     f"({len(result.extra_in_target)})</summary>"
                     "<div class='details-body'><ul class='list-items'>")
        for item in result.extra_in_target:
            parts.append(f"<li>{_e(str(item))}</li>")
        parts.append("</ul></div></details>")

    if result.missing_in_target:
        parts.append("<details><summary>Missing Elements From Baseline "
                     f"({len(result.missing_in_target)})</summary>"
                     "<div class='details-body'><ul class='list-items'>")
        for item in result.missing_in_target:
            parts.append(f"<li>{_e(str(item))}</li>")
        parts.append("</ul></div></details>")

    return ''.join(parts)


def generate_html_dashboard(results: List[ComparisonResult], output_dir: str) -> Path:
    """
    Write a single interactive HTML dashboard containing all policy/profile reports.

    Layout:
      - Title pane (top): BIG-IP device info
      - Navigation pane (left): selectable list of policies/profiles
      - Main pane (right): selected policy/profile report
    """
    reports_dir = ensure_dir(Path(output_dir) / "reports")
    sorted_results = sorted(results, key=lambda r: r.policy_path.lower())
    is_bot = any(getattr(r, "profile_type", "waf") == "bot" for r in sorted_results)
    prefix = "BOT" if is_bot else "WAF"
    out_path = reports_dir / f"{prefix}_audit_dashboard.html"

    dev_hostname = sorted_results[0].device_hostname if sorted_results else ""
    dev_mgmt_ip = sorted_results[0].device_mgmt_ip if sorted_results else ""
    if dev_hostname and dev_mgmt_ip:
        device_line = f"<strong>{_e(dev_hostname)}</strong> <span style='color:#555'>({_e(dev_mgmt_ip)})</span>"
    elif dev_hostname:
        device_line = f"<strong>{_e(dev_hostname)}</strong>"
    elif dev_mgmt_ip:
        device_line = _e(dev_mgmt_ip)
    else:
        device_line = "<em>unknown</em>"

    nav_items = []
    panels = []
    subject_label = "Profile" if is_bot else "Policy"
    nav_title = "Bot Defense Profiles" if is_bot else "ASM Policies"

    for idx, r in enumerate(sorted_results):
        panel_id = f"report-{idx}"
        status = "PASS" if r.score >= _PASS_THRESHOLD else "FAIL"
        status_cls = "pass" if status == "PASS" else "fail"
        nav_items.append(
            f"<button class='nav-item{' active' if idx == 0 else ''}' data-target='{panel_id}'>"
            f"<div class='nav-name'><code>{_e(r.policy_path)}</code></div>"
            f"<div class='nav-meta'>{r.score:.1f}% <span class='badge badge-{status_cls}'>{status}</span></div>"
            f"</button>"
        )
        panels.append(
            f"<section id='{panel_id}' class='report-panel{' active' if idx == 0 else ''}'>"
            f"{_build_policy_report_fragment(r)}"
            f"</section>"
        )

    dashboard_css = """
<style>
body.dashboard{padding:0;margin:0;height:100vh;display:grid;grid-template-rows:auto 1fr;overflow:hidden}
.title-pane{background:#16213e;color:#fff;padding:14px 18px;border-bottom:1px solid #0f3460}
.title-pane h1{color:#fff;margin:0 0 6px;font-size:1.2rem}
.title-meta{font-size:.9rem;display:flex;gap:24px;flex-wrap:wrap}
.dashboard-body{min-height:0;display:grid;grid-template-columns:300px 1fr}
.nav-pane{background:#fff;border-right:1px solid #d9dde5;padding:12px;overflow:auto}
.nav-pane h2{margin:0 0 10px;border:0;padding:0;font-size:1rem}
.nav-list{display:flex;flex-direction:column;gap:8px}
.nav-item{width:100%;text-align:left;background:#f6f8fb;border:1px solid #dbe2ef;border-radius:6px;padding:10px;cursor:pointer}
.nav-item:hover{background:#eef3ff}
.nav-item.active{border-color:#1f4d99;background:#e8f0ff}
.nav-item .nav-name{font-size:.86rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.nav-item .nav-meta{margin-top:6px;font-size:.84rem;color:#444;display:flex;justify-content:space-between;align-items:center}
.main-pane{overflow:auto;padding:18px}
.report-panel{display:none}
.report-panel.active{display:block}
.report-panel h1{font-size:1.3rem}
</style>
"""

    dashboard_js = """
<script>
(function(){
  const buttons = Array.from(document.querySelectorAll('.nav-item'));
  const panels = Array.from(document.querySelectorAll('.report-panel'));
  function activate(targetId){
    buttons.forEach(b => b.classList.toggle('active', b.dataset.target === targetId));
    panels.forEach(p => p.classList.toggle('active', p.id === targetId));
  }
  buttons.forEach(btn => btn.addEventListener('click', () => activate(btn.dataset.target)));
})();
</script>
"""

    report_title = "Bot Defense Audit Dashboard" if is_bot else "WAF Policy Audit Dashboard"
    generated_ts = _e(sorted_results[0].timestamp) if sorted_results else ""

    html_doc = (
        "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
        f"<title>{_e(report_title)}</title>"
        + _CSS + dashboard_css +
        "</head><body class='dashboard'>"
        "<header class='title-pane'>"
        f"<h1>{_e(report_title)}</h1>"
        "<div class='title-meta'>"
        f"<div><strong>Source BIG-IP:</strong> {device_line}</div>"
        f"<div><strong>Total {subject_label}s:</strong> {len(sorted_results)}</div>"
        f"<div><strong>Generated:</strong> {generated_ts}</div>"
        "</div></header>"
        "<div class='dashboard-body'>"
        "<aside class='nav-pane'>"
        f"<h2>{_e(nav_title)}</h2>"
        f"<div class='nav-list'>{''.join(nav_items)}</div>"
        "</aside>"
        f"<main class='main-pane'>{''.join(panels)}</main>"
        "</div>"
        + dashboard_js +
        "</body></html>"
    )

    out_path.write_text(html_doc, encoding='utf-8')
    _log.info("HTML dashboard report: %s", out_path)
    return out_path


# ── Summary report ─────────────────────────────────────────────────────────────

def generate_summary_reports(
    results: List[ComparisonResult],
    output_dir: str,
    formats: List[str],
) -> None:
    """
    Generate a cross-policy summary report sorted by compliance score (worst first).
    """
    sorted_results = sorted(results, key=lambda r: r.score)
    reports_dir = ensure_dir(Path(output_dir) / "reports")

    if "markdown" in formats:
        _write_summary_md(sorted_results, reports_dir)
    if "html" in formats:
        _write_summary_html(sorted_results, reports_dir)


def _write_summary_md(results: List[ComparisonResult], reports_dir: Path) -> None:
    # All results come from the same device — use the first one
    dev_hostname = results[0].device_hostname if results else ""
    dev_mgmt_ip  = results[0].device_mgmt_ip  if results else ""
    is_bot = any(getattr(r, "profile_type", "waf") == "bot" for r in results)

    if dev_hostname and dev_mgmt_ip:
        device_line = f"**Source Device:** `{dev_hostname}` ({dev_mgmt_ip})"
    elif dev_hostname:
        device_line = f"**Source Device:** `{dev_hostname}`"
    elif dev_mgmt_ip:
        device_line = f"**Source Device:** {dev_mgmt_ip}"
    else:
        device_line = ""

    report_title = (
        "# Bot Defense Profile Audit — Summary Report"
        if is_bot else
        "# WAF Policy Audit — Summary Report"
    )
    subject_label = "Profile" if is_bot else "Policy"

    lines = [report_title, ""]
    if device_line:
        lines += [device_line, ""]

    if is_bot:
        lines += [
            f"{subject_label}s sorted by compliance score (lowest first).",
            "",
            f"| {subject_label} | Partition | Enforcement | Template | Virtual Servers | Score | Status | Critical | Warning | Info |",
            f"|--------|-----------|-------------|----------|-----------------|-------|--------|----------|---------|------|",
        ]
        for r in results:
            status = "PASS" if r.score >= _PASS_THRESHOLD else "FAIL"
            totals = r.summary.get("totals", {})
            if r.virtual_servers:
                vs_cell = "<br>".join(
                    f"`{vs.get('fullPath', vs.get('name', ''))}` ({vs.get('ip', '?')}:{vs.get('port', '?')}) [{vs.get('association_type', 'direct')}]"
                    for vs in r.virtual_servers
                )
            else:
                vs_cell = "*(none)*"
            lines.append(
                f"| `{r.policy_path}` | {r.partition} | {r.enforcement_mode} "
                f"| — "
                f"| {vs_cell} "
                f"| {r.score:.1f}% | {status} "
                f"| {totals.get('critical',0)} | {totals.get('warning',0)} | {totals.get('info',0)} |"
            )
    else:
        lines += [
            "Policies sorted by compliance score (lowest first).",
            "",
            "| Policy | Partition | Enforcement | Virtual Servers | Score | Status | Critical | Warning | Info |",
            "|--------|-----------|-------------|-----------------|-------|--------|----------|---------|------|",
        ]
        for r in results:
            status = "PASS" if r.score >= _PASS_THRESHOLD else "FAIL"
            totals = r.summary.get("totals", {})
            if r.virtual_servers:
                vs_cell = "<br>".join(
                    f"`{vs.get('fullPath', vs.get('name', ''))}` ({vs.get('ip', '?')}:{vs.get('port', '?')}) [{vs.get('association_type', 'direct')}]"
                    for vs in r.virtual_servers
                )
            else:
                vs_cell = "*(none)*"
            lines.append(
                f"| `{r.policy_path}` | {r.partition} | {r.enforcement_mode} "
                f"| {vs_cell} "
                f"| {r.score:.1f}% | {status} "
                f"| {totals.get('critical',0)} | {totals.get('warning',0)} | {totals.get('info',0)} |"
            )

    prefix = "BOT" if is_bot else "WAF"
    out = reports_dir / f"{prefix}_summary_audit_report.md"
    out.write_text('\n'.join(lines), encoding='utf-8')
    _log.info("Summary Markdown: %s", out)


def _write_summary_html(results: List[ComparisonResult], reports_dir: Path) -> None:
    is_bot = any(getattr(r, "profile_type", "waf") == "bot" for r in results)
    subject_label = "Profile" if is_bot else "Policy"
    report_title = (
        "Bot Defense Profile Audit — Summary Report"
        if is_bot else
        "WAF Policy Audit — Summary Report"
    )

    rows = []
    for r in results:
        status = "PASS" if r.score >= _PASS_THRESHOLD else "FAIL"
        badge_cls = "pass" if status == "PASS" else "fail"
        totals = r.summary.get("totals", {})
        score_class = "score-pass" if r.score >= _PASS_THRESHOLD else "score-fail"

        if r.virtual_servers:
            vs_items = "".join(
                f"<div style='white-space:nowrap'>"
                f"<code>{_e(vs.get('fullPath', vs.get('name', '')))}</code>"
                f"&nbsp;<span style='color:#555;font-size:.85em'>"
                f"{_e(vs.get('ip', '?'))}:{_e(vs.get('port', '?'))}"
                f"&nbsp;[{_e(vs.get('association_type', 'direct'))}]"
                f"</span></div>"
                for vs in r.virtual_servers
            )
            extra_cell = f"<td>{vs_items}</td>"
        else:
            extra_cell = "<td><em style='color:#999'>none</em></td>"

        rows.append(
            f"<tr>"
            f"<td><code>{_e(r.policy_path)}</code></td>"
            f"<td>{_e(r.partition)}</td>"
            f"<td>{_e(r.enforcement_mode)}</td>"
            + extra_cell +
            f"<td>"
            f"  <div class='score-bar'><div class='{score_class} score-fill' style='width:{min(r.score,100):.1f}%'></div></div>"
            f"  {r.score:.1f}%"
            f"</td>"
            f"<td><span class='badge badge-{badge_cls}'>{status}</span></td>"
            f"<td>{totals.get('critical',0)}</td>"
            f"<td>{totals.get('warning',0)}</td>"
            f"<td>{totals.get('info',0)}</td>"
            f"</tr>"
        )

    dev_hostname = results[0].device_hostname if results else ""
    dev_mgmt_ip  = results[0].device_mgmt_ip  if results else ""
    if dev_hostname and dev_mgmt_ip:
        device_html = (
            f"<p style='margin:0 0 12px'><strong>Source Device:</strong> "
            f"<strong>{_e(dev_hostname)}</strong>"
            f"&nbsp;<span style='color:#555'>({_e(dev_mgmt_ip)})</span></p>"
        )
    elif dev_hostname:
        device_html = (
            f"<p style='margin:0 0 12px'><strong>Source Device:</strong> "
            f"<strong>{_e(dev_hostname)}</strong></p>"
        )
    elif dev_mgmt_ip:
        device_html = (
            f"<p style='margin:0 0 12px'><strong>Source Device:</strong> "
            f"{_e(dev_mgmt_ip)}</p>"
        )
    else:
        device_html = ""

    extra_th = "<th>Virtual Servers</th>"
    content = (
        "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
        f"<title>{_e(report_title)}</title>"
        + _CSS +
        f"</head><body>"
        f"<h1>{_e(report_title)}</h1>"
        + device_html +
        f"<p>{subject_label}s sorted by compliance score (lowest first).</p>"
        "<table class='summary-table findings'>"
        "<thead><tr>"
        f"<th>{subject_label}</th><th>Partition</th><th>Enforcement</th>"
        + extra_th +
        "<th>Score</th><th>Status</th><th>Critical</th><th>Warning</th><th>Info</th>"
        "</tr></thead><tbody>"
        + "".join(rows) +
        "</tbody></table></body></html>"
    )
    prefix = "BOT" if is_bot else "WAF"
    out = reports_dir / f"{prefix}_summary_audit_report.html"
    out.write_text(content, encoding='utf-8')
    _log.info("Summary HTML: %s", out)
