"""
Report generation for WAF and Bot Defense audits (tiered scoring model).

Changelog: Implemented 4-tier compliance rendering with circuit breaker
disclosure, raw vs capped scores, deduction breakdowns, and color-coded
dashboards replacing legacy binary status wording.
"""
from __future__ import annotations

import html
import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .policy_comparator import (
    ComparisonResult,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_WARNING,
    SEVERITY_INFO,
)
from .utils import (
    ensure_dir,
    get_logger,
    human_bool,
    TIER_RED,
    TIER_AMBER,
    TIER_YELLOW,
    TIER_GREEN,
)

from .virtual_server_inventory import VirtualServerRecord


_log = get_logger("report_generator")

_TIER_EMOJI = {
    TIER_RED: "🔴",
    TIER_AMBER: "🟠",
    TIER_YELLOW: "🟡",
    TIER_GREEN: "🟢",
}

_TIER_CLASS = {
    TIER_RED: "tier-red",
    TIER_AMBER: "tier-amber",
    TIER_YELLOW: "tier-yellow",
    TIER_GREEN: "tier-green",
}


# ----------------------------------------------------------------------------
# Markdown reports
# ----------------------------------------------------------------------------


def generate_markdown(result: ComparisonResult, output_dir: str) -> Path:
    """Write a Markdown audit report and return its path."""

    reports_dir = ensure_dir(Path(output_dir) / "reports")
    safe_name = result.policy_name.replace('/', '_').replace(' ', '_')
    prefix = "BOT" if getattr(result, "profile_type", "waf") == "bot" else "WAF"
    out_path = reports_dir / f"{prefix}_{safe_name}_audit_report.md"

    lines: List[str] = []
    _md_header(lines, result)
    _md_circuit_breakers(lines, result)
    _md_deductions(lines, result)
    _md_waf_violations(lines, result)
    _md_findings(lines, result)

    out_path.write_text("\n".join(lines), encoding="utf-8")
    _log.info("Markdown report: %s", out_path)
    return out_path


def _md_header(lines: List[str], result: ComparisonResult) -> None:
    """Render the report header.

    Enforcement mode should reflect the **target (device)** policy so that
    the report always shows the current device state, not the baseline. The
    comparator injects the target enforcement mode into ``result.enforcement_mode``.
    """

    tier_badge = f"{_TIER_EMOJI.get(result.tier, '')} {result.tier_label}"
    if result.is_hard_fail:
        score_line = f"{result.score:.1f}% (capped from raw {result.raw_score:.1f}%)"
    else:
        score_line = f"{result.score:.1f}%"

    lines += [
        f"# Compliance Report for `{result.policy_path}`",
        "",
        f"- **Compliance Score:** {score_line}",
        f"- **Tier:** **{tier_badge}**",
        f"- **Partition:** {result.partition}",
        f"- **Current Enforcement Mode (device):** {result.enforcement_mode}",
        f"- **Baseline:** {result.baseline_name}",
        f"- **Audit Date:** {result.timestamp}",
        "",
    ]


def _md_circuit_breakers(lines: List[str], result: ComparisonResult) -> None:
    if not result.circuit_breakers_triggered:
        lines += ["## Circuit Breakers", "", "*None triggered.*", ""]
        return

    lines += ["## Circuit Breakers", ""]
    lines.append(
        "The following circuit-breaker conditions cap the score at 49 regardless of other deductions:"
    )
    lines.append("")
    for cb in result.circuit_breakers_triggered:
        lines.append(f"- `{cb}`")
    lines.append("")


def _md_waf_violations(lines: List[str], result: ComparisonResult) -> None:
    """Render per-violation learn/alarm/block comparison against baseline."""
    if getattr(result, "profile_type", "waf") != "waf":
        return

    lines += ["## WAF Violations vs Baseline", ""]
    comparison_rows = _waf_violation_comparison_rows(result)
    if not comparison_rows:
        lines += ["*No WAF violation settings were available for comparison.*", ""]
        return

    lines.append(
        "| Violation | Baseline Learn | Policy Learn | Learn Match | "
        "Baseline Alarm | Policy Alarm | Alarm Match | "
        "Baseline Block | Policy Block | Block Match | Overall |"
    )
    lines.append(
        "|-----------|----------------|-------------|-------------|"
        "----------------|--------------|-------------|"
        "----------------|--------------|-------------|---------|"
    )
    for row in comparison_rows:
        lines.append(
            "| "
            f"`{row['violation']}` | {row['baseline_learn']} | {row['target_learn']} | {row['learn_match']} | "
            f"{row['baseline_alarm']} | {row['target_alarm']} | {row['alarm_match']} | "
            f"{row['baseline_block']} | {row['target_block']} | {row['block_match']} | {row['overall']} |"
        )
    lines.append("")


def _md_deductions(lines: List[str], result: ComparisonResult) -> None:
    lines += ["## Deduction Breakdown", ""]
    lines.append("### By Severity")
    lines.append("")
    lines.append("| Severity | Total Deduction |")
    lines.append("|----------|-----------------|")
    for sev in (SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_WARNING, SEVERITY_INFO):
        val = result.deductions_by_severity.get(sev, 0.0)
        lines.append(f"| {sev} | {val:.1f} |")
    lines.append("")

    lines.append("### By Section")
    lines.append("")
    lines.append("| Section | Total Deduction |")
    lines.append("|---------|-----------------|")
    for section, val in sorted(result.deductions_by_section.items()):
        lines.append(f"| {section} | {val:.1f} |")
    lines.append("")


def _md_findings(lines: List[str], result: ComparisonResult) -> None:
    severities = [
        ("Critical", SEVERITY_CRITICAL),
        ("High", SEVERITY_HIGH),
        ("Warning", SEVERITY_WARNING),
        ("Info", SEVERITY_INFO),
    ]
    for title, sev in severities:
        items = [d for d in result.findings if d.severity == sev]
        if not items:
            continue
        lines += [f"## {title} Findings ({len(items)})", ""]
        for i, diff in enumerate(items, 1):
            lines += [
                f"### {i}. {diff.section} — {diff.element_name}",
                f"- **Attribute:** `{diff.attribute}`",
                f"- **Baseline:** {human_bool(diff.baseline_value)}",
                f"- **Target:** {human_bool(diff.target_value)}",
                f"- **Section:** `{diff.section_category}`",
                f"- **Severity:** {diff.severity}",
                f"- **Description:** {diff.description}",
                "",
            ]


# ----------------------------------------------------------------------------
# HTML dashboard
# ----------------------------------------------------------------------------


def generate_html_dashboard(
    results: List[ComparisonResult],
    output_dir: str,
    virtual_server_inventory: Optional[List[VirtualServerRecord]] = None,
    virtual_server_inventory_error: Optional[str] = None,
) -> Path:
    """Generate an interactive dashboard with three-pane shell layout."""

    reports_dir = ensure_dir(Path(output_dir) / "reports")
    if not results:
        raise ValueError("No comparison results provided")

    # Sort worst-first
    ordered = sorted(results, key=lambda r: r.score)

    # Tier counts for summary bar
    counts = {TIER_RED: 0, TIER_AMBER: 0, TIER_YELLOW: 0, TIER_GREEN: 0}
    for r in ordered:
        counts[r.tier] = counts.get(r.tier, 0) + 1

    is_bot = any(getattr(r, "profile_type", "waf") == "bot" for r in ordered)
    prefix = "BOT" if is_bot else "WAF"
    out_path = reports_dir / f"{prefix}_audit_dashboard.html"

    hostnames = {
        str(getattr(r, "device_hostname", "")).strip()
        for r in ordered
        if str(getattr(r, "device_hostname", "")).strip()
    }
    mgmt_ips = {
        str(getattr(r, "device_mgmt_ip", "")).strip()
        for r in ordered
        if str(getattr(r, "device_mgmt_ip", "")).strip()
    }
    timestamps = [
        str(getattr(r, "timestamp", "")).strip()
        for r in ordered
        if str(getattr(r, "timestamp", "")).strip()
    ]

    device_hostname = next(iter(hostnames)) if len(hostnames) == 1 else ("Multiple devices" if hostnames else "Unknown")
    device_mgmt_ip = next(iter(mgmt_ips)) if len(mgmt_ips) == 1 else ("Multiple IPs" if mgmt_ips else "Unknown")
    audit_timestamp = max(timestamps) if timestamps else "Unknown"

    rows: List[str] = []
    nav_items = [
        "<button type='button' class='nav-item active' data-view='summary-view'>Summary</button>",
        "<div class='nav-group-title'>Policies</div>",
    ]
    policy_templates: List[str] = []
    policy_path_to_id: Dict[str, str] = {}
    for idx, r in enumerate(ordered, 1):
        policy_id = f"policy-{idx}"
        tier_cls = _TIER_CLASS.get(r.tier, "")
        cb_col = ", ".join(r.circuit_breakers_triggered) if r.circuit_breakers_triggered else "—"
        raw_col = f"{r.raw_score:.1f}" if r.is_hard_fail else "—"

        mode_text = (r.enforcement_mode or "transparent").strip().lower()
        mode_is_blocking = "block" in mode_text
        mode_label = "Blocking" if mode_is_blocking else "Transparent"
        mode_cls = "mode-blocking" if mode_is_blocking else "mode-transparent"
        status_label = r.tier_label

        compliance_label = "Compliant" if r.score >= 90.0 else "Needs Review"
        compliance_cls = "status-compliant" if compliance_label == "Compliant" else "status-review"
        ports = sorted({str(v.get("port", "")).strip() for v in (r.virtual_servers or []) if str(v.get("port", "")).strip()})
        ports_label = ", ".join(ports) if ports else "None"

        nav_items.append(
            f"<button type='button' class='nav-item nav-policy {tier_cls}' data-view='{policy_id}'>"
            f"<span class='nav-policy-path'>{_esc(r.policy_path)}</span>"
            f"<span class='nav-policy-meta'>{r.score:.1f}% • {_esc(status_label)} • {_esc(mode_label)}</span>"
            "</button>"
        )
        policy_path_to_id[str(r.policy_path)] = policy_id

        rows.append(
            "<tr class='" + tier_cls + "'>"
            f"<td>{_esc(r.policy_path)}</td>"
            f"<td>{_TIER_EMOJI.get(r.tier, '')} {r.tier_label}</td>"
            f"<td>{r.score:.1f}</td>"
            f"<td>{raw_col}</td>"
            f"<td>{cb_col}</td>"
            f"<td>{len([d for d in r.findings if d.severity==SEVERITY_CRITICAL])}</td>"
            f"<td>{len([d for d in r.findings if d.severity==SEVERITY_HIGH])}</td>"
            f"<td>{len([d for d in r.findings if d.severity==SEVERITY_WARNING])}</td>"
            f"<td>{len([d for d in r.findings if d.severity==SEVERITY_INFO])}</td>"
            "</tr>"
        )
        policy_templates.append(
            f"<template id='tpl-{policy_id}'>"
            f"{_build_legacy_policy_section(r, section_id=policy_id)}"
            "</template>"
        )

    nav_items.append("<button type='button' class='nav-item' data-view='run-info-view'>Run Info</button>")

    summary_bar = (
        f"<div class='summary-bar'>"
        f"<span class='tier-red'>🔴 Red: {counts[TIER_RED]}</span>"
        f"<span class='tier-amber'>🟠 Amber: {counts[TIER_AMBER]}</span>"
        f"<span class='tier-yellow'>🟡 Yellow: {counts[TIER_YELLOW]}</span>"
        f"<span class='tier-green'>🟢 Green: {counts[TIER_GREEN]}</span>"
        "</div>"
    )

    pass_count = sum(1 for r in ordered if r.score >= 90.0)
    fail_count = len(ordered) - pass_count

    summary_content = (
        "<section id='summary-view' class='view active' role='region' aria-label='Summary'>"
        + (
            _build_virtual_server_summary_section(
                virtual_server_inventory=virtual_server_inventory or [],
                inventory_error=virtual_server_inventory_error,
                policy_path_to_id=policy_path_to_id,
                policy_score_map={str(r.policy_path): r for r in ordered},
                tier_counts=counts,
            )
            if not is_bot
            else (
                f"{summary_bar}"
                "<table class='results'>"
                "<thead><tr>"
                "<th>Policy/Profile</th><th>Tier</th><th>Score</th><th>Raw Score</th><th>Circuit Breakers</th>"
                "<th>Critical</th><th>High</th><th>Warning</th><th>Info</th>"
                "</tr></thead><tbody>"
                + "".join(rows)
                + "</tbody></table>"
            )
        )
        + "</section>"
    )

    run_info_content = (
        "<section id='run-info-view' class='view' role='region' aria-label='Run information'>"
        "<h2>Run Info</h2>"
        "<table class='results run-info-table'><tbody>"
        f"<tr><th>Device Hostname</th><td>{_esc(device_hostname)}</td></tr>"
        f"<tr><th>Management IP</th><td>{_esc(device_mgmt_ip)}</td></tr>"
        f"<tr><th>Audit Mode</th><td>{'BOT' if is_bot else 'WAF'}</td></tr>"
        f"<tr><th>Run Timestamp</th><td>{_esc(audit_timestamp)}</td></tr>"
        f"<tr><th>Total Objects Audited</th><td>{len(ordered)}</td></tr>"
        f"<tr><th>Pass Count (&ge;90%)</th><td>{pass_count}</td></tr>"
        f"<tr><th>Fail Count (&lt;90%)</th><td>{fail_count}</td></tr>"
        "</tbody></table>"
        "</section>"
    )

    css = _DASHBOARD_CSS
    detail_templates = "".join(policy_templates)
    mode_label = "BOT" if is_bot else "WAF"
    title_label = "Bot Defense Audit Dashboard" if is_bot else "WAF Audit Dashboard"
    sidebar_heading = "Bot Defense Profiles" if is_bot else "Navigation"

    html_doc = (
        "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
        f"<title>{title_label}</title>"
        f"<style>{css}</style>"
        "</head><body>"
        "<div class='app'>"
        "<header class='title-pane' role='banner'>"
        f"<h1>{title_label}</h1>"
        "<div class='title-meta'>"
        f"<div><strong>Device:</strong> {_esc(device_hostname)} ({_esc(device_mgmt_ip)})</div>"
        f"<div><strong>Mode:</strong> {mode_label}</div>"
        f"<div><strong>Generated:</strong> {_esc(audit_timestamp)}</div>"
        f"<div><strong>Pass/Fail:</strong> {pass_count}/{fail_count}</div>"
        "</div>"
        "</header>"
        "<div class='body-grid'>"
        "<nav class='sidebar' role='navigation' aria-label='Audit navigation'>"
        f"<h2>{sidebar_heading}</h2>"
        f"<div class='nav-list'>{''.join(nav_items)}</div>"
        "</nav>"
        "<main class='main' role='main'>"
        f"{summary_content}"
        f"{run_info_content}"
        "<section id='detail-view' class='view detail-view' role='region' aria-label='Policy details'></section>"
        f"{detail_templates}"
        "</main>"
        "</div>"
        "</div>"
        f"<script id='policy-path-map' type='application/json'>{_esc(json.dumps(policy_path_to_id))}</script>"
        "<script>"
        "(function(){"
        "var navItems=document.querySelectorAll('.nav-item');"
        "var views=document.querySelectorAll('.view');"
        "var detail=document.getElementById('detail-view');"
        "var rawMap=document.getElementById('policy-path-map');"
        "var policyPathMap={};"
        "if(rawMap){try{policyPathMap=JSON.parse(rawMap.textContent||'{}')}catch(e){policyPathMap={}}}"
        "function setActive(viewId){"
        "navItems.forEach(function(item){item.classList.toggle('active',item.getAttribute('data-view')===viewId);});"
        "views.forEach(function(view){view.classList.toggle('active',view.id===viewId);});"
        "}"
        "function showView(viewId){"
        "if(viewId==='summary-view'||viewId==='run-info-view'){detail.innerHTML='';setActive(viewId);"
        "var m=document.querySelector('.main');if(m)m.scrollTop=0;window.location.hash=viewId;return;}"
        "var tpl=document.getElementById('tpl-'+viewId);"
        "if(!tpl){return;}"
        "detail.innerHTML=tpl.innerHTML;"
        "bindDisclose(detail);"
        "setActive('detail-view');"
        "window.location.hash=viewId;"
        "var m=document.querySelector('.main');if(m)m.scrollTop=0;"
        "}"
        "function bindDisclose(root){"
        "(root||document).querySelectorAll('.disclose-sum').forEach(function(sum){"
        "sum.addEventListener('click',function(){sum.closest('.disclose').classList.toggle('open');});"
        "});"
        "}"
        "bindDisclose(document);"
        "navItems.forEach(function(card){"
        "card.addEventListener('click', function(){"
        "var target=card.getAttribute('data-view');"
        "showView(target);"
        "});"
        "});"
        "document.addEventListener('click', function(ev){"
        "var jump=ev.target.closest('.policy-jump');"
        "if(!jump){return;}"
        "ev.preventDefault();"
        "var path=jump.getAttribute('data-policy-path')||'';"
        "var viewId=policyPathMap[path];"
        "if(viewId){showView(viewId);}"
        "});"
        "var filterInput=document.getElementById('vs-filter');"
        "if(filterInput){filterInput.addEventListener('input',function(){"
        "var q=(filterInput.value||'').toLowerCase();"
        "document.querySelectorAll('#vs-summary-body tr.vs-row').forEach(function(row){"
        "var show=(row.getAttribute('data-search')||'').toLowerCase().indexOf(q)!==-1;"
        "row.style.display=show?'':'none';"
        "});"
        "});}"
        "document.querySelectorAll('.sort-btn').forEach(function(btn){btn.addEventListener('click',function(){"
        "var col=btn.getAttribute('data-col');"
        "var body=document.getElementById('vs-summary-body');if(!body){return;}"
        "var rows=Array.prototype.slice.call(body.querySelectorAll('tr.vs-row'));"
        "var asc=btn.getAttribute('data-asc')!=='true';"
        "btn.setAttribute('data-asc',asc?'true':'false');"
        "rows.sort(function(a,b){"
        "var av=(a.getAttribute('data-'+col)||'').toLowerCase();"
        "var bv=(b.getAttribute('data-'+col)||'').toLowerCase();"
        "if(col==='score'||col==='tier'){var an=parseInt(av||'-1',10),bn=parseInt(bv||'-1',10);return asc?an-bn:bn-an;}"
        "return asc?av.localeCompare(bv):bv.localeCompare(av);"
        "});"
        "rows.forEach(function(r){body.appendChild(r);});"
        "});});"
        "function exportMappingCSV(){"
        "var table=document.getElementById('vs-summary-table');if(!table){return;}"
        "var rows=Array.prototype.slice.call(table.querySelectorAll('tr'));"
        "var csv=rows.map(function(row){"
        "var cells=Array.prototype.slice.call(row.querySelectorAll('th,td'));"
        "return cells.map(function(cell){"
        "var t=(cell.textContent||'').replace(/\\s+/g,' ').trim();"
        "return '\\x22'+t.split('\\x22').join('\\x22\\x22')+'\\x22';"
        "}).join(',');"
        "}).join('\\n');"
        "var blob=new Blob([csv],{type:'text/csv'});"
        "var url=URL.createObjectURL(blob);"
        "var a=document.createElement('a');"
        "a.href=url;a.download='waf_policy_mapping.csv';"
        "document.body.appendChild(a);a.click();document.body.removeChild(a);"
        "URL.revokeObjectURL(url);"
        "}"
        "function copyMappingToClipboard(){"
        "var table=document.getElementById('vs-summary-table');if(!table){return;}"
        "var rows=Array.prototype.slice.call(table.querySelectorAll('tr'));"
        "var tsv=rows.map(function(row){"
        "var cells=Array.prototype.slice.call(row.querySelectorAll('th,td'));"
        "return cells.map(function(cell){"
        "return (cell.textContent||'').replace(/\\s+/g,' ').trim().replace(/\\t/g,' ');"
        "}).join('\\t');"
        "}).join('\\n');"
        "var copyBtn=document.getElementById('copy-table-btn');"
        "function setCopyDone(){if(copyBtn){copyBtn.textContent='\\u2713 Copied!';setTimeout(function(){copyBtn.textContent='Copy to Clipboard';},2000);}}"
        "if(navigator.clipboard&&navigator.clipboard.writeText){"
        "navigator.clipboard.writeText(tsv).then(setCopyDone).catch(function(){"
        "var ta=document.createElement('textarea');ta.value=tsv;"
        "document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta);"
        "setCopyDone();"
        "});"
        "}else{"
        "var ta=document.createElement('textarea');ta.value=tsv;"
        "document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta);"
        "setCopyDone();"
        "}"
        "}"
        "showView('summary-view');"
        "})();"
        "</script>"
        "</body></html>"
    )

    out_path.write_text(html_doc, encoding="utf-8")
    _log.info("HTML dashboard: %s", out_path)
    return out_path


def _build_virtual_server_summary_section(
    virtual_server_inventory: List[VirtualServerRecord],
    inventory_error: Optional[str],
    policy_path_to_id: Dict[str, str],
    policy_score_map: Optional[Dict[str, Any]] = None,
    tier_counts: Optional[Dict[str, int]] = None,
) -> str:
    def _status_meta(status: str) -> tuple[str, str]:
        if status == "enabled":
            return ("WAF Enabled", "status-enabled")
        if status == "capable":
            return ("WAF Capable", "status-capable")
        return ("Not Applicable", "status-na")

    if inventory_error:
        return (
            "<div class='pb-banner pb-disabled' role='alert'>"
            "<span class='g'>&#9888;</span>"
            "<span>Virtual server inventory was unavailable for this run. "
            f"Details: {_esc(inventory_error)}</span>"
            "</div>"
        )

    score_map = policy_score_map or {}
    records = virtual_server_inventory or []
    html_rows: List[str] = []
    _TIER_ORDER = {TIER_RED: 0, TIER_AMBER: 1, TIER_YELLOW: 2, TIER_GREEN: 3}

    for rec in records:
        source: Any = asdict(rec) if is_dataclass(rec) else rec
        if not isinstance(source, dict):
            continue

        name = str(source.get("name") or "")
        partition = str(source.get("partition") or "")
        destination = str(source.get("destination") or "—")
        http_profile = str(source.get("http_profile") or "—")
        status_raw = str(source.get("waf_status") or "not_applicable")
        direct = list(source.get("directly_attached_waf_policies") or [])
        ltm_policies_src = list(source.get("ltm_policies") or [])
        status_label, status_cls = _status_meta(status_raw)

        # Build flat list of (attach_type, ltm_name, rule_name, hosts_str, waf_policy)
        attachments: List[tuple] = []
        for pol_path in direct:
            attachments.append(("Direct", "—", "—", "—", str(pol_path)))
        for ltm_pol in ltm_policies_src:
            if not isinstance(ltm_pol, dict):
                continue
            ltm_name = str(ltm_pol.get("full_path") or ltm_pol.get("name") or "(unresolved)")
            for rule in (ltm_pol.get("rules") or []):
                if not isinstance(rule, dict):
                    continue
                rule_name = str(rule.get("rule_name") or "(unnamed rule)")
                waf_policy = str(rule.get("waf_policy") or "(unresolved)")
                hosts = rule.get("host_conditions") or ["(any)"]
                hosts_str = ", ".join(str(h) for h in hosts)
                attachments.append(("LTM", ltm_name, rule_name, hosts_str, waf_policy))

        if not attachments:
            attachments.append((None, "—", "—", "—", "—"))

        for (attach_type, ltm_name, rule_name, hosts_str, waf_policy) in attachments:
            result = score_map.get(waf_policy) if (waf_policy and waf_policy != "—") else None
            tier_label = result.tier_label if result else "—"
            tier_cls = _TIER_CLASS.get(result.tier, "") if result else ""
            tier_emoji = _TIER_EMOJI.get(result.tier, "") if result else ""
            score_str = f"{result.score:.1f}" if result else "—"
            score_num = str(int(result.score * 10)) if result else "-1"
            tier_order = str(_TIER_ORDER.get(result.tier, 4)) if result else "5"

            if attach_type is None:
                attach_display = "—"
                attach_sort = ""
            elif attach_type == "Direct":
                attach_display = "<span class='attach-direct'>Direct</span>"
                attach_sort = "direct"
            else:
                attach_display = (
                    f"<span class='attach-ltm' title='{_esc(ltm_name)}'>{_esc(ltm_name)}</span>"
                )
                attach_sort = ltm_name.lower()

            if waf_policy != "—" and waf_policy in policy_path_to_id:
                policy_display = (
                    f"<a href='#' class='policy-jump' data-policy-path='{_esc(waf_policy)}'>{_esc(waf_policy)}</a>"
                )
            else:
                policy_display = _esc(waf_policy)

            tier_badge = (
                f"<span class='tier-badge {tier_cls}'>{tier_emoji} {_esc(tier_label)}</span>"
                if result else "<span class='tier-badge'>—</span>"
            )

            rule_cell = (
                f"{_esc(rule_name)}<br><small class='muted'>{_esc(hosts_str)}</small>"
                if (attach_type == "LTM" and rule_name not in ("—", ""))
                else "—"
            )

            search_blob = " ".join([
                name, partition, destination, http_profile,
                status_label, waf_policy, ltm_name, tier_label,
            ])

            html_rows.append(
                "<tr class='vs-row'"
                f" data-search='{_esc(search_blob)}'"
                f" data-name='{_esc(name)}'"
                f" data-partition='{_esc(partition)}'"
                f" data-destination='{_esc(destination)}'"
                f" data-http_profile='{_esc(http_profile)}'"
                f" data-status='{_esc(status_label)}'"
                f" data-attachment='{_esc(attach_sort)}'"
                f" data-policy='{_esc(waf_policy)}'"
                f" data-tier='{tier_order}'"
                f" data-score='{score_num}'>"
                f"<td>{_esc(name)}</td>"
                f"<td>{_esc(partition)}</td>"
                f"<td>{_esc(destination)}</td>"
                f"<td>{_esc(http_profile)}</td>"
                f"<td><span class='status-badge {status_cls}'>{_esc(status_label)}</span></td>"
                f"<td>{attach_display}</td>"
                f"<td>{rule_cell}</td>"
                f"<td>{policy_display}</td>"
                f"<td>{tier_badge}</td>"
                f"<td class='score-cell'>{_esc(score_str)}</td>"
                "</tr>"
            )

    tc = tier_counts or {}
    tier_bar_html = (
        "<div class='summary-bar'>"
        f"<span class='tier-red'>&#128308; Red: {tc.get(TIER_RED, 0)}</span>"
        f"<span class='tier-amber'>&#128992; Amber: {tc.get(TIER_AMBER, 0)}</span>"
        f"<span class='tier-yellow'>&#128993; Yellow: {tc.get(TIER_YELLOW, 0)}</span>"
        f"<span class='tier-green'>&#128994; Green: {tc.get(TIER_GREEN, 0)}</span>"
        "</div>"
    ) if tc else ""

    return (
        "<h1>WAF Audit Summary</h1>"
        + tier_bar_html
        + "<h2 class='sec-h2'>Virtual Server &#8212; WAF Policy Mapping</h2>"
        "<div class='pb-banner pb-manual'>"
        "<span class='g'>&#9888;</span>"
        "<span>Virtual Server inventory reflects ASM/AWAF applicability at audit time. "
        "Each row is one WAF policy attachment per virtual server. "
        "Use <strong>Export CSV</strong> or <strong>Copy to Clipboard</strong> to paste into a spreadsheet.</span>"
        "</div>"
        "<div class='vs-controls'>"
        "<label for='vs-filter'>Filter:</label>"
        "<input id='vs-filter' type='text' placeholder='Search virtual servers, policies, partitions&#8230;'>"
        "<button type='button' class='export-btn' onclick='exportMappingCSV()'>&#11015; Export CSV</button>"
        "<button type='button' class='export-btn export-btn-secondary' id='copy-table-btn' "
        "onclick='copyMappingToClipboard()'>Copy to Clipboard</button>"
        "</div>"
        "<table id='vs-summary-table' class='results' aria-label='Virtual Server WAF Policy Mapping'>"
        "<thead><tr>"
        "<th><button type='button' class='sort-btn' data-col='name'>Virtual Server</button></th>"
        "<th><button type='button' class='sort-btn' data-col='partition'>Partition</button></th>"
        "<th><button type='button' class='sort-btn' data-col='destination'>Destination</button></th>"
        "<th><button type='button' class='sort-btn' data-col='http_profile'>HTTP Profile</button></th>"
        "<th><button type='button' class='sort-btn' data-col='status'>WAF Status</button></th>"
        "<th><button type='button' class='sort-btn' data-col='attachment'>Attachment</button></th>"
        "<th>Rule / Host Conditions</th>"
        "<th><button type='button' class='sort-btn' data-col='policy'>ASM Policy</button></th>"
        "<th><button type='button' class='sort-btn' data-col='tier'>Tier</button></th>"
        "<th><button type='button' class='sort-btn' data-col='score'>Score %</button></th>"
        "</tr></thead>"
        "<tbody id='vs-summary-body'>"
        f"{''.join(html_rows) if html_rows else '<tr><td colspan=10>No virtual servers found.</td></tr>'}"
        "</tbody>"
        "</table>"
    )


def generate_virtual_server_summary_markdown(
    virtual_server_inventory: Optional[List[VirtualServerRecord]],
    output_dir: str,
    inventory_error: Optional[str] = None,
) -> Path:
    """Write WAF virtual server summary markdown report."""
    reports_dir = ensure_dir(Path(output_dir) / "reports")
    out_path = reports_dir / "WAF_virtual_server_summary.md"

    lines: List[str] = ["# WAF Virtual Server Summary", ""]
    if inventory_error:
        lines.extend(["## Inventory Unavailable", "", f"- Error: `{inventory_error}`", ""])
    else:
        lines.append("| Virtual Server | Partition | Destination | HTTP Profile | WAF Status | Attached WAF Policies |")
        lines.append("|----------------|-----------|-------------|--------------|------------|-----------------------|")
        for rec in virtual_server_inventory or []:
            source: Any = asdict(rec) if is_dataclass(rec) else rec
            if not isinstance(source, dict):
                continue
            status = str(source.get("waf_status") or "not_applicable")
            status_label = {
                "enabled": "WAF Enabled",
                "capable": "WAF Capable",
                "not_applicable": "Not Applicable",
            }.get(status, status)
            attached_count = len(source.get("directly_attached_waf_policies") or []) + sum(
                len((p or {}).get("rules") or []) for p in (source.get("ltm_policies") or []) if isinstance(p, dict)
            )
            lines.append(
                f"| `{source.get('name','')}` | {source.get('partition','')} | {source.get('destination','—')} | "
                f"{source.get('http_profile') or '—'} | {status_label} | {attached_count if attached_count else '—'} |"
            )

    out_path.write_text("\n".join(lines), encoding="utf-8")
    _log.info("Virtual server summary Markdown: %s", out_path)
    return out_path


def _esc(val) -> str:
    return html.escape(str(val))


def _build_legacy_policy_section(result: ComparisonResult, section_id: str = "") -> str:
    """Render a per-policy detail block — always expanded, no collapsible elements."""
    sev_order = [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_WARNING, SEVERITY_INFO]
    sev_labels = {
        SEVERITY_CRITICAL: "Critical",
        SEVERITY_HIGH: "High",
        SEVERITY_WARNING: "Warning",
        SEVERITY_INFO: "Informational",
    }

    raw_score = f"{result.raw_score:.1f}%" if result.is_hard_fail else "—"
    cb_text = ", ".join(result.circuit_breakers_triggered) if result.circuit_breakers_triggered else "None"

    mode_text = (result.enforcement_mode or "transparent").strip().lower()
    mode_is_blocking = "block" in mode_text
    mode_label = "Blocking" if mode_is_blocking else "Transparent"
    mode_cls = "mode-blocking" if mode_is_blocking else "mode-transparent"
    enforcement_badge = f"<span class='pill {mode_cls}'>{mode_label}</span>"
    learning_badge = _learning_mode_badge(getattr(result, "learning_mode", ""))
    pass_flag = result.score >= 90.0
    score_badge = f"<span class='badge badge-{'pass' if pass_flag else 'fail'}'>{'PASS' if pass_flag else 'FAIL'}</span>"
    compliance_label = "Compliant" if pass_flag else "Needs Review"
    compliance_cls = "status-compliant" if pass_flag else "status-review"

    # Meta card with score bar
    meta_card = "".join([
        "<div class='meta-card'><table><tbody>",
        f"<tr><td>Partition</td><td>{_esc(result.partition)}</td>",
        f"<td>Enforcement Mode</td><td>{enforcement_badge}</td></tr>",
        f"<tr><td>Baseline</td><td>{_esc(result.baseline_name)}</td>",
        f"<td>Audit Date</td><td>{_esc(result.timestamp)}</td></tr>",
        f"<tr><td>Learning Mode</td><td>{learning_badge}</td>",
        f"<td>Raw Score</td><td>{raw_score}</td></tr>",
        f"<tr><td>Circuit Breakers</td><td>{_esc(cb_text)}</td>",
        f"<td>Compliance Score</td><td><strong>{result.score:.1f}%</strong> {score_badge}</td></tr>",
        f"<tr><td>Status</td><td><span class='pill {compliance_cls}'>{compliance_label}</span></td><td></td><td></td></tr>",
        "</tbody></table>",
        f"<div class='score-bar'><div class='score-fill {'score-pass' if pass_flag else 'score-fail'}' style='width:{result.score:.1f}%'></div></div>",
        "</div>",
    ])

    # Findings summary count table
    summary_rows = ""
    for sev in sev_order:
        count = len([d for d in result.findings if d.severity == sev])
        summary_rows += f"<tr><td>{sev_labels[sev]}</td><td>{count}</td></tr>"

    _sev_badge_cls = {
        SEVERITY_CRITICAL: "critical",
        SEVERITY_HIGH: "critical",
        SEVERITY_WARNING: "warning",
        SEVERITY_INFO: "info",
    }

    # Individual finding sections wrapped in disclose collapsibles
    finding_sections: List[str] = []
    for sev in sev_order:
        items = [d for d in result.findings if d.severity == sev]
        if not items:
            continue
        badge_cls = _sev_badge_cls.get(sev, "info")
        rows = []
        for diff in items:
            rows.append(
                "<tr>"
                f"<td><code>{_esc(diff.section)}</code></td>"
                f"<td>{_esc(diff.element_name)}</td>"
                f"<td><code>{_esc(diff.attribute)}</code></td>"
                f"<td>{_esc(human_bool(diff.baseline_value))}</td>"
                f"<td>{_esc(human_bool(diff.target_value))}</td>"
                f"<td>{_esc(diff.description)}</td>"
                f"<td><span class='badge badge-{badge_cls}'>{sev_labels[sev].upper()}</span></td>"
                "</tr>"
            )
        finding_sections.append(
            "<div class='disclose open'>"
            "<div class='disclose-sum'>"
            f"<span class='caret'>&#9654;</span>"
            f"<span class='badge badge-{badge_cls}'>{sev_labels[sev]} Findings</span>&nbsp;({len(items)})"
            "</div>"
            "<div class='disclose-body'>"
            "<table class='findings'>"
            "<thead><tr>"
            "<th>Section</th><th>Element</th><th>Attribute</th><th>Baseline</th><th>Target</th><th>Description</th><th>Severity</th>"
            "</tr></thead><tbody>"
            + "".join(rows) +
            "</tbody></table>"
            "</div></div>"
        )

    id_attr = f" id='{_esc(section_id)}'" if section_id else ""
    is_waf = getattr(result, "profile_type", "waf") == "waf"

    parts: List[str] = [
        f"<div class='legacy-policy-panel'{id_attr}>",
        meta_card,
    ]

    if is_waf:
        parts += [
            "<h2 class='sec-h2'>WAF Violations — Learn / Alarm / Block</h2>",
            _build_waf_violations_grouped_html(result),
            "<h2 class='sec-h2'>WAF Violations vs Baseline</h2>",
            _build_waf_violation_table_html(result),
            "<h2 class='sec-h2'>Applied Attack Signature Sets</h2>",
            _build_signature_sets_html(result),
        ]

    parts += [
        "<h2 class='sec-h2'>Audit Log (Last 10 Changes)</h2>",
        _build_audit_log_html(result),
        "<h2 class='sec-h2'>Findings by Severity</h2>",
        "<table class='results legacy-summary'><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>",
        summary_rows,
        "</tbody></table>",
        "".join(finding_sections),
        "</div>",
    ]

    return "".join(parts)


def _normalize_violations_map(violations: List[Dict]) -> Dict[str, Dict]:
    mapped: Dict[str, Dict] = {}
    for item in violations or []:
        vid = str(item.get("id") or item.get("name") or "").strip()
        if not vid:
            continue
        mapped[vid] = item
    return mapped


def _format_violation_name(item: Dict, fallback_key: str) -> str:
    name = str(item.get("name") or "").strip()
    vid = str(item.get("id") or fallback_key).strip()
    return f"{name} ({vid})" if name and name != vid else vid


def _fmt_setting(value) -> str:
    if value is None:
        return "Not Set"
    return human_bool(value)


def _match_text(baseline_val, target_val) -> str:
    return "Match ✅" if baseline_val == target_val else "Different ⚠️"


def _waf_violation_comparison_rows(result: ComparisonResult) -> List[Dict[str, str]]:
    baseline_map = _normalize_violations_map(result.baseline_violations)
    target_map = _normalize_violations_map(result.violations)
    all_ids = sorted(set(baseline_map) | set(target_map))

    rows: List[Dict[str, str]] = []
    for vid in all_ids:
        base = baseline_map.get(vid, {})
        targ = target_map.get(vid, {})
        b_learn, t_learn = base.get("learn"), targ.get("learn")
        b_alarm, t_alarm = base.get("alarm"), targ.get("alarm")
        b_block, t_block = base.get("block"), targ.get("block")

        learn_match = _match_text(b_learn, t_learn)
        alarm_match = _match_text(b_alarm, t_alarm)
        block_match = _match_text(b_block, t_block)
        overall_match = "All Match ✅" if (b_learn == t_learn and b_alarm == t_alarm and b_block == t_block) else "Differences Found ⚠️"

        rows.append({
            "violation": _format_violation_name(base or targ, vid),
            "baseline_learn": _fmt_setting(b_learn),
            "target_learn": _fmt_setting(t_learn),
            "learn_match": learn_match,
            "baseline_alarm": _fmt_setting(b_alarm),
            "target_alarm": _fmt_setting(t_alarm),
            "alarm_match": alarm_match,
            "baseline_block": _fmt_setting(b_block),
            "target_block": _fmt_setting(t_block),
            "block_match": block_match,
            "overall": overall_match,
        })

    return rows


def _build_waf_violation_table_html(result: ComparisonResult) -> str:
    if getattr(result, "profile_type", "waf") != "waf":
        return ""

    rows = _waf_violation_comparison_rows(result)
    if not rows:
        return "<p class='muted'>No WAF violation settings were available for comparison.</p>"

    body_rows = []
    for row in rows:
        body_rows.append(
            "<tr>"
            f"<td>{_esc(row['violation'])}</td>"
            f"<td>{_esc(row['baseline_learn'])}</td>"
            f"<td>{_esc(row['target_learn'])}</td>"
            f"<td>{_esc(row['learn_match'])}</td>"
            f"<td>{_esc(row['baseline_alarm'])}</td>"
            f"<td>{_esc(row['target_alarm'])}</td>"
            f"<td>{_esc(row['alarm_match'])}</td>"
            f"<td>{_esc(row['baseline_block'])}</td>"
            f"<td>{_esc(row['target_block'])}</td>"
            f"<td>{_esc(row['block_match'])}</td>"
            f"<td>{_esc(row['overall'])}</td>"
            "</tr>"
        )

    return (
        "<table class='results violation-compare'>"
        "<thead><tr>"
        "<th>Violation</th><th>Baseline Learn</th><th>Policy Learn</th><th>Learn Match</th>"
        "<th>Baseline Alarm</th><th>Policy Alarm</th><th>Alarm Match</th>"
        "<th>Baseline Block</th><th>Policy Block</th><th>Block Match</th><th>Overall</th>"
        "</tr></thead><tbody>"
        + "".join(body_rows) +
        "</tbody></table>"
    )


def _learning_mode_badge(mode: str) -> str:
    m = (mode or "").strip().lower()
    if m == "automatic":
        return "<span class='policy-mode' style='background:#d4edda;color:#155724'>Automatic</span>"
    if m == "manual":
        return "<span class='policy-mode' style='background:#cce5ff;color:#004085'>Manual</span>"
    return "<span class='policy-mode' style='background:#e9ecef;color:#495057'>Off</span>"


def _build_waf_violations_grouped_html(result: ComparisonResult) -> str:
    if getattr(result, "profile_type", "waf") != "waf":
        return ""

    violations = result.violations or []

    def _viol_name(v: Dict) -> str:
        name = str(v.get("name") or "").strip()
        return name if name else str(v.get("id") or "")

    def _ul(items: List[Dict]) -> str:
        if not items:
            return "<ul><li class='muted'>None</li></ul>"
        return "<ul>" + "".join(f"<li>{_esc(_viol_name(v))}</li>" for v in items) + "</ul>"

    learn_items = [v for v in violations if v.get("learn")]
    alarm_items = [v for v in violations if v.get("alarm")]
    block_items = [v for v in violations if v.get("block")]

    cards = (
        "<div class='vcard'>"
        "<div class='vcard-title learn'>Learn</div>"
        + _ul(learn_items) +
        "</div>"
        "<div class='vcard'>"
        "<div class='vcard-title alarm'>Alarm</div>"
        + _ul(alarm_items) +
        "</div>"
        "<div class='vcard'>"
        "<div class='vcard-title block'>Block</div>"
        + _ul(block_items) +
        "</div>"
    )
    return "<div class='violation-cards'>" + cards + "</div>"


def _build_signature_sets_html(result: ComparisonResult) -> str:
    sets = result.target_signature_sets or []
    if not sets:
        return "<p class='muted'>No signature sets applied.</p>"

    body_rows = []
    for s in sets:
        name = _esc(str(s.get("name") or ""))
        learn = "✅" if s.get("learn") else "—"
        alarm = "✅" if s.get("alarm") else "—"
        block = "✅" if s.get("block") else "—"
        body_rows.append(f"<tr><td>{name}</td><td>{learn}</td><td>{alarm}</td><td>{block}</td></tr>")

    return (
        "<table class='results sig-sets-table'>"
        "<thead><tr><th>Signature Set</th><th>Learn</th><th>Alarm</th><th>Block</th></tr></thead>"
        "<tbody>" + "".join(body_rows) + "</tbody>"
        "</table>"
    )


def _build_audit_log_html(result: ComparisonResult) -> str:
    logs = (result.policy_audit_logs or [])[:10]
    if not logs:
        return "<p class='muted'>No audit log entries available.</p>"

    body_rows = []
    for entry in logs:
        action = _esc(str(entry.get("action") or ""))
        username = _esc(str(entry.get("username") or ""))
        timestamp = _esc(str(entry.get("timestamp") or ""))
        body_rows.append(f"<tr><td>{action}</td><td>{username}</td><td>{timestamp}</td></tr>")

    return (
        "<table class='results'>"
        "<thead><tr><th>Change / Action</th><th>User</th><th>Date / Time</th></tr></thead>"
        "<tbody>" + "".join(body_rows) + "</tbody>"
        "</table>"
    )


_DASHBOARD_CSS = """
*{box-sizing:border-box}
html,body{height:100%;margin:0;scroll-behavior:smooth}
body{font-family:Arial,Helvetica,sans-serif;background:#f7f7fb;color:#222}
/* ---- App shell ---------------------------------------------------------- */
.app{height:100vh;display:grid;grid-template-rows:auto 1fr;overflow:hidden}
/* ---- Title pane --------------------------------------------------------- */
.title-pane{background:#16213e;color:#fff;padding:12px 18px;border-bottom:1px solid #0f3460;display:flex;align-items:center;gap:18px;flex-wrap:wrap}
.title-pane h1{color:#fff;margin:0;font-size:1.2rem;font-weight:700}
.title-meta{font-size:.86rem;display:flex;gap:22px;flex-wrap:wrap;color:#cdd6e8}
.title-meta strong{color:#fff;font-weight:700}
/* ---- Body grid ---------------------------------------------------------- */
.body-grid{min-height:0;display:grid;grid-template-columns:300px 1fr}
.sidebar{background:#fff;border-right:1px solid #d9dde5;padding:12px;overflow-y:auto}
.sidebar h2{margin:0 0 10px;font-size:1rem;color:#16213e;font-weight:700}
.main{overflow:auto;padding:18px}
/* ---- View visibility ---------------------------------------------------- */
.view{display:none}
.view.active{display:block}
/* ---- Nav items ---------------------------------------------------------- */
.nav-list{display:flex;flex-direction:column;gap:6px}
.policy-nav{display:flex;flex-direction:column;gap:6px}
.nav-group-title{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#7a8fa6;font-weight:700;padding:8px 4px 2px;margin-top:2px}
.nav-item{display:block;width:100%;text-align:left;padding:9px 10px;border:1px solid #d8deeb;border-radius:6px;background:#f8fafe;cursor:pointer;font:inherit;font-size:13px;color:#1f2b3d;transition:border-color .15s,box-shadow .15s,background .15s;appearance:none;-webkit-appearance:none;box-sizing:border-box}
.nav-item:hover{border-color:#5b77ad;box-shadow:0 0 0 2px rgba(15,52,96,.12)}
.nav-item.active{border-color:#0f3460;background:#e6edf7;box-shadow:0 0 0 2px rgba(15,52,96,.2);font-weight:700}
.nav-policy{display:flex;flex-direction:column;gap:3px}
.nav-policy-path{font-weight:600;word-break:break-all;font-size:13px}
.nav-policy-meta{font-size:11px;color:#5f6570;display:flex;justify-content:space-between;align-items:center;gap:8px}
.nav-item.active .nav-policy-meta{color:#2a4a7f}
/* ---- Badges ------------------------------------------------------------- */
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:.78em;font-weight:700;color:#fff;white-space:nowrap}
.badge-critical{background:#dc3545}
.badge-warning{background:#fd7e14}
.badge-info{background:#17a2b8}
.badge-pass{background:#28a745}
.badge-fail{background:#dc3545}
.badge-unknown{background:#6c757d}
/* ---- Pills -------------------------------------------------------------- */
.pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:700;white-space:nowrap}
.status-compliant{background:#d4edda;color:#155724}
.status-review{background:#ffe8a1;color:#7a5a00}
.status-enabled{background:#d4edda;color:#155724}
.status-capable{background:#cce5ff;color:#004085}
.status-na{background:#e9ecef;color:#495057}
.mode-blocking{background:#d4edda;color:#155724}
.mode-transparent{background:#ffe9a8;color:#7a5a00}
/* legacy compat */
.policy-mode{display:inline-block;padding:2px 8px;border-radius:999px;font-weight:700;width:fit-content}
.status-badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:700}
/* ---- Meta card + score bar ---------------------------------------------- */
.meta-card{background:#fff;border:1px solid #e6e9f0;border-radius:6px;padding:16px;margin-bottom:18px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
.meta-card table{border-collapse:collapse;width:100%}
.meta-card td{padding:4px 10px;vertical-align:top;font-size:13px}
.meta-card td:first-child{font-weight:700;color:#555;width:180px}
.score-bar{height:24px;border-radius:4px;background:#e0e0e0;overflow:hidden;margin:10px 0 0}
.score-fill{height:100%;transition:width .5s ease}
.score-pass{background:#28a745}
.score-fail{background:#dc3545}
/* ---- Headings ----------------------------------------------------------- */
h1{font-size:1.3rem;color:#1a1a2e;margin:0 0 12px}
h2{margin:16px 0 8px}
.sec-h2{color:#16213e;margin:24px 0 8px;border-bottom:2px solid #e0e0e0;padding-bottom:4px;font-size:1.12rem}
.sec-h3{color:#0f3460;margin:14px 0 6px;font-size:1rem}
.section-heading{margin:18px 0 8px;padding-bottom:4px;border-bottom:2px solid #d9dfea;color:#0f3460}
/* ---- Tables ------------------------------------------------------------- */
table.results{border-collapse:collapse;width:100%;background:#fff;border:1px solid #ddd;font-size:13px}
table.results th,table.results td{padding:9px 10px;border-bottom:1px solid #eee;text-align:left}
table.results th{background:#0f3460;color:#fff}
table.results.nested th{background:#2a5a8c}
table.results tr.vs-row:hover{background:#f3f6fc}
table.findings{width:100%;border-collapse:collapse;margin:8px 0;font-size:.9em}
table.findings th{background:#1a1a2e;color:#fff;padding:8px 10px;text-align:left}
table.findings td{padding:7px 10px;border-bottom:1px solid #e0e0e0;vertical-align:top}
table.findings tr:nth-child(even){background:#f9f9f9}
table.findings tr:hover{background:#eef3ff}
tr.tier-red{background:#dc3545;color:#fff}
tr.tier-amber{background:#fd7e14;color:#fff}
tr.tier-yellow{background:#ffc107;color:#000}
tr.tier-green{background:#28a745;color:#fff}
tr.tier-yellow td{border-color:#f5d86a}
tr.tier-red a,tr.tier-amber a,tr.tier-green a{color:#fff;font-weight:bold}
tr.band td{background:#e8ecf5;font-weight:700;color:#16213e;padding:6px 10px}
.legacy-meta th{width:180px;background:#f8fafe;color:#22314f}
.legacy-summary{max-width:420px;margin-bottom:10px}
.legacy-findings th,.legacy-findings td{font-size:13px}
.violation-compare th,.violation-compare td{font-size:12px}
/* ---- VS table controls -------------------------------------------------- */
.expand-col{width:34px}
.vs-toggle{background:none;border:1px solid #b0b8cb;border-radius:4px;width:22px;height:22px;cursor:pointer;font-weight:700;font-size:14px;line-height:1;padding:0;color:#0f3460}
.vs-toggle:hover{background:#e6edf7}
.vs-detail-row>td{background:#f3f6fc;border-top:2px solid #d9dfea;padding:0}
.vs-detail-panel{padding:10px 14px}
.vs-controls{margin:6px 0 10px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.vs-controls label{font-size:13px;font-weight:600;color:#444;white-space:nowrap}
.vs-controls input{padding:7px 10px;border:1px solid #d9dfea;border-radius:4px;font-size:13px;flex:1;min-width:180px;max-width:360px;font-family:inherit}
.sort-btn{background:none;border:none;cursor:pointer;font-weight:700;color:#fff;padding:0;font:inherit;font-size:inherit}
.sort-btn:hover{text-decoration:underline}
/* ---- Collapsible sections ----------------------------------------------- */
.disclose{background:#fff;border:1px solid #ddd;border-radius:6px;margin:10px 0}
.disclose-sum{padding:12px 16px;cursor:pointer;font-weight:700;color:#16213e;display:flex;align-items:center;gap:8px;user-select:none}
.disclose-sum .caret{font-size:.8em;transition:transform .2s;color:#0f3460}
.disclose.open .disclose-sum .caret{transform:rotate(90deg)}
.disclose-body{padding:4px 16px 16px}
.disclose:not(.open) .disclose-body{display:none}
/* ---- Banners ------------------------------------------------------------ */
.pb-banner{border-radius:6px;padding:12px 16px;margin:14px 0;display:flex;align-items:center;gap:12px;font-size:14px}
.pb-banner .g{font-size:18px;line-height:1}
.pb-manual{background:#fff3cd;border:1px solid #ffc107;color:#7a5a00}
.pb-automatic{background:#d4edda;border:1px solid #28a745}
.pb-disabled{background:#f8d7da;border:1px solid #dc3545;color:#721c24}
.pb-unknown{background:#e2e3e5;border:1px solid #adb5bd}
.inventory-banner{background:#fff3cd;border:1px solid #ffc107;border-radius:6px;padding:12px 16px;color:#7a5a00;margin-bottom:12px}
/* ---- Summary bar -------------------------------------------------------- */
.summary-bar{display:flex;gap:12px;margin:12px 0;font-weight:bold}
.summary-bar span{padding:6px 10px;border-radius:4px;color:#fff}
.summary-bar .tier-red{background:#dc3545}
.summary-bar .tier-amber{background:#fd7e14}
.summary-bar .tier-yellow{background:#ffc107;color:#000}
.summary-bar .tier-green{background:#28a745}
/* ---- Policy detail panel ------------------------------------------------ */
.legacy-policy-panel{margin-top:10px;border:1px solid #d9dfea;border-radius:6px;background:#fff;padding:12px 16px}
/* ---- Violation cards ---------------------------------------------------- */
.violation-cards{display:flex;gap:16px;flex-wrap:wrap}
.vcard{flex:1;min-width:200px;border:1px solid #d9dfea;border-radius:6px;padding:10px;background:#f8fafe}
.vcard-title{font-weight:700;margin-bottom:6px;font-size:14px}
.vcard-title.learn{color:#0f3460}
.vcard-title.alarm{color:#fd7e14}
.vcard-title.block{color:#dc3545}
/* ---- Misc --------------------------------------------------------------- */
.muted{color:#5f6570}
code{font-family:ui-monospace,Menlo,Consolas,monospace}
.policy-jump{color:#0f3460;cursor:pointer;text-decoration:underline}
.summary-card{background:#eef5ff}
/* ---- Export buttons ----------------------------------------------------- */
.export-btn{padding:6px 14px;background:#0f3460;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:13px;font-weight:600;transition:background .15s;white-space:nowrap}
.export-btn:hover{background:#1a4f8a}
.export-btn-secondary{background:#fff;color:#0f3460;border:1px solid #0f3460}
.export-btn-secondary:hover{background:#e6edf7}
/* ---- Tier badge (inline, for table cells) -------------------------------- */
.tier-badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:700;white-space:nowrap}
.tier-badge.tier-red{background:#dc3545;color:#fff}
.tier-badge.tier-amber{background:#fd7e14;color:#fff}
.tier-badge.tier-yellow{background:#ffc107;color:#000}
.tier-badge.tier-green{background:#28a745;color:#fff}
.tier-badge:not(.tier-red):not(.tier-amber):not(.tier-yellow):not(.tier-green){background:#e9ecef;color:#495057}
/* ---- Attachment type tags ------------------------------------------------ */
.attach-direct{display:inline-block;padding:1px 7px;background:#d4edda;color:#155724;border-radius:4px;font-size:12px;font-weight:600}
.attach-ltm{display:inline-block;padding:1px 7px;background:#cce5ff;color:#004085;border-radius:4px;font-size:12px;font-weight:600;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:bottom}
/* ---- Score cell ---------------------------------------------------------- */
.score-cell{font-weight:700;font-variant-numeric:tabular-nums;text-align:right}
"""


# ----------------------------------------------------------------------------
# Summary reports (Markdown + HTML)
# ----------------------------------------------------------------------------


def generate_summary_reports(results: List[ComparisonResult], output_dir: str, formats: List[str]) -> None:
    """Write summary reports sorted worst-first."""

    ordered = sorted(results, key=lambda r: r.score)
    reports_dir = ensure_dir(Path(output_dir) / "reports")

    if "markdown" in formats:
        _write_summary_md(ordered, reports_dir)
    if "html" in formats:
        _write_summary_html(ordered, reports_dir)


def _write_summary_md(results: List[ComparisonResult], reports_dir: Path) -> None:
    is_bot = any(getattr(r, "profile_type", "waf") == "bot" for r in results)
    title = "# Bot Defense Profile Audit — Summary" if is_bot else "# WAF Policy Audit — Summary"
    lines = [title, "", "Policies sorted by score (lowest first).", ""]
    lines.append("| Policy/Profile | Tier | Score | Raw Score | Circuit Breakers | Critical | High | Warning | Info |")
    lines.append("|----------------|------|-------|-----------|------------------|---------|------|---------|------|")
    for r in results:
        cb = ", ".join(r.circuit_breakers_triggered) if r.circuit_breakers_triggered else "—"
        raw = f"{r.raw_score:.1f}" if r.is_hard_fail else "—"
        lines.append(
            f"| `{r.policy_path}` | {_TIER_EMOJI.get(r.tier, '')} {r.tier_label} "
            f"| {r.score:.1f} | {raw} | {cb} | "
            f"{len([d for d in r.findings if d.severity==SEVERITY_CRITICAL])} | "
            f"{len([d for d in r.findings if d.severity==SEVERITY_HIGH])} | "
            f"{len([d for d in r.findings if d.severity==SEVERITY_WARNING])} | "
            f"{len([d for d in r.findings if d.severity==SEVERITY_INFO])} |"
        )

    prefix = "BOT" if is_bot else "WAF"
    out = reports_dir / f"{prefix}_summary_audit_report.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    _log.info("Summary Markdown: %s", out)


def _write_summary_html(results: List[ComparisonResult], reports_dir: Path) -> None:
    is_bot = any(getattr(r, "profile_type", "waf") == "bot" for r in results)
    prefix = "BOT" if is_bot else "WAF"
    title = "Bot Defense Profile Audit — Summary" if is_bot else "WAF Policy Audit — Summary"

    rows = []
    for r in results:
        tier_cls = _TIER_CLASS.get(r.tier, "")
        cb = ", ".join(r.circuit_breakers_triggered) if r.circuit_breakers_triggered else "—"
        raw = f"{r.raw_score:.1f}" if r.is_hard_fail else "—"
        rows.append(
            f"<tr class='{tier_cls}'>"
            f"<td><code>{_esc(r.policy_path)}</code></td>"
            f"<td>{_TIER_EMOJI.get(r.tier,'')} {r.tier_label}</td>"
            f"<td>{r.score:.1f}</td>"
            f"<td>{raw}</td>"
            f"<td>{_esc(cb)}</td>"
            f"<td>{len([d for d in r.findings if d.severity==SEVERITY_CRITICAL])}</td>"
            f"<td>{len([d for d in r.findings if d.severity==SEVERITY_HIGH])}</td>"
            f"<td>{len([d for d in r.findings if d.severity==SEVERITY_WARNING])}</td>"
            f"<td>{len([d for d in r.findings if d.severity==SEVERITY_INFO])}</td>"
            "</tr>"
        )

    html_doc = (
        "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
        f"<title>{title}</title>"
        f"<style>{_DASHBOARD_CSS}</style>"
        "</head><body>"
        f"<h1>{title}</h1>"
        "<table class='results'>"
        "<thead><tr>"
        "<th>Policy/Profile</th><th>Tier</th><th>Score</th><th>Raw Score</th><th>Circuit Breakers</th>"
        "<th>Critical</th><th>High</th><th>Warning</th><th>Info</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        "</body></html>"
    )

    out = reports_dir / f"{prefix}_summary_audit_report.html"
    out.write_text(html_doc, encoding="utf-8")
    _log.info("Summary HTML: %s", out)


__all__ = [
    "generate_markdown",
    "generate_html_dashboard",
    "generate_summary_reports",
]
