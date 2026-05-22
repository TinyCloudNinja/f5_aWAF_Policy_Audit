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

    html_doc = (
        "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
        f"<title>{'Bot Defense' if is_bot else 'WAF'} Audit Dashboard</title>"
        f"<style>{css}</style>"
        "</head><body>"
        "<header class='topbar' role='banner'>"
        f"<div class='top-title'>{'Bot Defense' if is_bot else 'WAF'} Audit Dashboard</div>"
        "<div class='top-meta'>"
        f"<span><strong>Device:</strong> {_esc(device_hostname)} ({_esc(device_mgmt_ip)})</span>"
        f"<span><strong>Mode:</strong> {'BOT' if is_bot else 'WAF'}</span>"
        f"<span><strong>Timestamp:</strong> {_esc(audit_timestamp)}</span>"
        f"<span><strong>Pass/Fail:</strong> {pass_count}/{fail_count}</span>"
        "</div>"
        "</header>"
        "<div class='shell'>"
        "<nav class='sidebar' role='navigation' aria-label='Audit navigation'>"
        f"<div class='policy-nav'>{''.join(nav_items)}</div>"
        "</nav>"
        "<main class='main' role='main'>"
        f"{summary_content}"
        f"{run_info_content}"
        "<section id='detail-view' class='view detail-view' role='region' aria-label='Policy details'></section>"
        f"{detail_templates}"
        "</main>"
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
        "if(viewId==='summary-view'||viewId==='run-info-view'){detail.innerHTML='';setActive(viewId);window.location.hash=viewId;return;}"
        "var tpl=document.getElementById('tpl-'+viewId);"
        "if(!tpl){return;}"
        "detail.innerHTML=tpl.innerHTML;"
        "setActive('detail-view');"
        "window.location.hash=viewId;"
        "window.scrollTo({top:0,behavior:'smooth'});"
        "}"
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
        "document.addEventListener('click', function(ev){"
        "var btn=ev.target.closest('.vs-toggle');"
        "if(!btn){return;}"
        "var rowId=btn.getAttribute('data-row-id');"
        "var detailRow=document.getElementById('vs-detail-'+rowId);"
        "if(!detailRow){return;}"
        "var expanded=btn.getAttribute('aria-expanded')==='true';"
        "btn.setAttribute('aria-expanded', expanded?'false':'true');"
        "btn.textContent=expanded?'+':'−';"
        "detailRow.hidden=expanded;"
        "});"
        "var filterInput=document.getElementById('vs-filter');"
        "if(filterInput){filterInput.addEventListener('input', function(){"
        "var q=(filterInput.value||'').toLowerCase();"
        "document.querySelectorAll('#vs-summary-body tr.vs-row').forEach(function(row){"
        "var show=(row.getAttribute('data-search')||'').toLowerCase().indexOf(q)!==-1;"
        "row.style.display=show?'':'none';"
        "var rid=row.getAttribute('data-row-id');"
        "var dr=document.getElementById('vs-detail-'+rid);"
        "if(dr&&!show){dr.hidden=true;}"
        "});"
        "});}"
        "document.querySelectorAll('.sort-btn').forEach(function(btn){btn.addEventListener('click', function(){"
        "var col=btn.getAttribute('data-col');"
        "var body=document.getElementById('vs-summary-body'); if(!body){return;}"
        "var rows=Array.prototype.slice.call(body.querySelectorAll('tr.vs-row'));"
        "var asc=btn.getAttribute('data-asc')!=='true';"
        "btn.setAttribute('data-asc',asc?'true':'false');"
        "rows.sort(function(a,b){"
        "var av=(a.getAttribute('data-'+col)||'').toLowerCase();"
        "var bv=(b.getAttribute('data-'+col)||'').toLowerCase();"
        "if(col==='attached'){var an=parseInt(av||'0',10),bn=parseInt(bv||'0',10); return asc?an-bn:bn-an;}"
        "return asc?av.localeCompare(bv):bv.localeCompare(av);"
        "});"
        "rows.forEach(function(r){body.appendChild(r); var rid=r.getAttribute('data-row-id'); var dr=document.getElementById('vs-detail-'+rid); if(dr){body.appendChild(dr);}});"
        "});});"
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
) -> str:
    def _status_meta(status: str) -> tuple[str, str]:
        if status == "enabled":
            return ("WAF Enabled", "status-enabled")
        if status == "capable":
            return ("WAF Capable", "status-capable")
        return ("Not Applicable", "status-na")

    if inventory_error:
        return (
            "<div class='inventory-banner' role='alert'>"
            "Virtual server inventory was unavailable for this run. "
            f"Details: {_esc(inventory_error)}"
            "</div>"
        )

    records = virtual_server_inventory or []
    rows: List[str] = []
    for idx, rec in enumerate(records):
        source: Any = asdict(rec) if is_dataclass(rec) else rec
        if not isinstance(source, dict):
            continue

        name = str(source.get("name") or "")
        partition = str(source.get("partition") or "")
        destination = str(source.get("destination") or "—")
        http_profile = str(source.get("http_profile") or "—")
        direct = list(source.get("directly_attached_waf_policies") or [])
        ltm_policies = list(source.get("ltm_policies") or [])
        ltm_rule_count = sum(len((p or {}).get("rules") or []) for p in ltm_policies if isinstance(p, dict))
        total_policies = len(direct) + ltm_rule_count
        status_raw = str(source.get("waf_status") or "not_applicable")
        status_label, status_cls = _status_meta(status_raw)
        has_expand = status_raw == "enabled" and total_policies > 0

        search_blob = " ".join([name, partition, destination, http_profile, status_label] + [str(p) for p in direct])
        attached_label = str(total_policies) if total_policies else "—"

        toggle_html = (
            f"<button type='button' class='vs-toggle' aria-expanded='false' data-row-id='{idx}' title='Toggle details'>+</button>"
            if has_expand else ""
        )

        rows.append(
            "<tr class='vs-row'"
            f" data-row-id='{idx}'"
            f" data-search='{_esc(search_blob)}'"
            f" data-name='{_esc(name)}'"
            f" data-partition='{_esc(partition)}'"
            f" data-destination='{_esc(destination)}'"
            f" data-http_profile='{_esc(http_profile)}'"
            f" data-status='{_esc(status_label)}'"
            f" data-attached='{total_policies}'>"
            f"<td class='expand-col'>{toggle_html}</td>"
            f"<td>{_esc(name)}</td>"
            f"<td>{_esc(partition)}</td>"
            f"<td>{_esc(destination)}</td>"
            f"<td>{_esc(http_profile)}</td>"
            f"<td><span class='status-badge {status_cls}'>{_esc(status_label)}</span></td>"
            f"<td>{_esc(attached_label)}</td>"
            "</tr>"
        )

        if has_expand:
            direct_lines = []
            for pol in direct:
                p = str(pol)
                if p in policy_path_to_id:
                    direct_lines.append(f"<li><a href='#' class='policy-jump' data-policy-path='{_esc(p)}'>{_esc(p)}</a></li>")
                else:
                    direct_lines.append(f"<li>{_esc(p)}</li>")
            direct_html = "<ul>" + ("".join(direct_lines) if direct_lines else "<li>None</li>") + "</ul>"

            routed_rows: List[str] = []
            for policy in ltm_policies:
                if not isinstance(policy, dict):
                    continue
                ltm_name = str(policy.get("full_path") or policy.get("name") or "(unresolved)")
                for rule in (policy.get("rules") or []):
                    if not isinstance(rule, dict):
                        continue
                    waf_policy = str(rule.get("waf_policy") or "(unresolved)")
                    if waf_policy in policy_path_to_id:
                        waf_cell = f"<a href='#' class='policy-jump' data-policy-path='{_esc(waf_policy)}'>{_esc(waf_policy)}</a>"
                    else:
                        waf_cell = _esc(waf_policy)
                    host_conditions = rule.get("host_conditions") or ["(any)"]
                    for host in host_conditions:
                        routed_rows.append(
                            "<tr>"
                            f"<td>{_esc(host)}</td>"
                            f"<td>{_esc(ltm_name)}</td>"
                            f"<td>{_esc(rule.get('rule_name') or '(unnamed rule)')}</td>"
                            f"<td>{waf_cell}</td>"
                            "</tr>"
                        )

            routed_html = (
                "<table class='results nested'>"
                "<thead><tr><th>Host (FQDN)</th><th>LTM Policy</th><th>Rule</th><th>WAF Policy</th></tr></thead>"
                f"<tbody>{''.join(routed_rows) if routed_rows else '<tr><td colspan=4>None</td></tr>'}</tbody>"
                "</table>"
            )

            rows.append(
                f"<tr id='vs-detail-{idx}' class='vs-detail-row' hidden>"
                "<td colspan='7'>"
                "<div class='vs-detail-panel'>"
                "<h4>Direct attachments</h4>"
                f"{direct_html}"
                "<h4>LTM-Policy-routed attachments</h4>"
                f"{routed_html}"
                "</div>"
                "</td></tr>"
            )

    return (
        "<h2>Virtual Server Summary</h2>"
        "<div class='vs-controls'>"
        "<label for='vs-filter'>Filter:</label>"
        "<input id='vs-filter' type='text' placeholder='Search virtual servers, partitions, destination, or policy'>"
        "</div>"
        "<table id='vs-summary-table' class='results' aria-label='Virtual Server Summary'>"
        "<thead><tr>"
        "<th></th>"
        "<th><button type='button' class='sort-btn' data-col='name'>Virtual Server</button></th>"
        "<th><button type='button' class='sort-btn' data-col='partition'>Partition</button></th>"
        "<th><button type='button' class='sort-btn' data-col='destination'>Destination</button></th>"
        "<th><button type='button' class='sort-btn' data-col='http_profile'>HTTP Profile</button></th>"
        "<th><button type='button' class='sort-btn' data-col='status'>WAF Status</button></th>"
        "<th><button type='button' class='sort-btn' data-col='attached'>Attached WAF Policies</button></th>"
        "</tr></thead>"
        f"<tbody id='vs-summary-body'>{''.join(rows) if rows else '<tr><td colspan=7>No virtual servers found.</td></tr>'}</tbody>"
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
    """Render a legacy-style per-policy combined detail block."""
    sev_order = [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_WARNING, SEVERITY_INFO]
    sev_labels = {
        SEVERITY_CRITICAL: "Critical",
        SEVERITY_HIGH: "High",
        SEVERITY_WARNING: "Warning",
        SEVERITY_INFO: "Informational",
    }

    summary_rows = ""
    for sev in sev_order:
        count = len([d for d in result.findings if d.severity == sev])
        summary_rows += f"<tr><td>{sev_labels[sev]}</td><td>{count}</td></tr>"

    finding_sections: List[str] = []
    for sev in sev_order:
        items = [d for d in result.findings if d.severity == sev]
        if not items:
            continue
        rows = []
        for diff in items:
            rows.append(
                "<tr>"
                f"<td>{_esc(diff.section)}</td>"
                f"<td>{_esc(diff.element_name)}</td>"
                f"<td><code>{_esc(diff.attribute)}</code></td>"
                f"<td>{_esc(human_bool(diff.baseline_value))}</td>"
                f"<td>{_esc(human_bool(diff.target_value))}</td>"
                f"<td>{_esc(diff.description)}</td>"
                "</tr>"
            )

        finding_sections.append(
            "<details>"
            f"<summary>{sev_labels[sev]} Findings ({len(items)})</summary>"
            "<div class='details-body'>"
            "<table class='results legacy-findings'>"
            "<thead><tr>"
            "<th>Section</th><th>Element</th><th>Attribute</th><th>Baseline</th><th>Target</th><th>Description</th>"
            "</tr></thead><tbody>"
            + "".join(rows) +
            "</tbody></table></div></details>"
        )

    violation_section = _build_waf_violation_table_html(result)

    raw_score = f"{result.raw_score:.1f}%" if result.is_hard_fail else "—"
    cb_text = ", ".join(result.circuit_breakers_triggered) if result.circuit_breakers_triggered else "None"
    section_id_attr = f" id='{_esc(section_id)}'" if section_id else ""
    return "".join([
        f"<details class='legacy-policy'{section_id_attr}>",
        f"<summary><strong>{_esc(result.policy_path)}</strong> — {_TIER_EMOJI.get(result.tier,'')} {_esc(result.tier_label)} ({result.score:.1f}%)</summary>",
        "<div class='details-body'>",
        "<table class='results legacy-meta'><tbody>",
        f"<tr><th>Partition</th><td>{_esc(result.partition)}</td><th>Enforcement Mode</th><td>{_esc(result.enforcement_mode)}</td></tr>",
        f"<tr><th>Baseline</th><td>{_esc(result.baseline_name)}</td><th>Audit Date</th><td>{_esc(result.timestamp)}</td></tr>",
        f"<tr><th>Score</th><td>{result.score:.1f}%</td><th>Raw Score</th><td>{raw_score}</td></tr>",
        f"<tr><th>Circuit Breakers</th><td colspan='3'>{_esc(cb_text)}</td></tr>",
        "</tbody></table>",
        "<h3>Executive Summary</h3>",
        "<table class='results legacy-summary'><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>",
        f"{summary_rows}</tbody></table>",
        violation_section,
        "".join(finding_sections),
        "</div></details>",
    ])


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
        return "<h3>WAF Violations vs Baseline</h3><p class='muted'>No WAF violation settings were available for comparison.</p>"

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
        "<h3>WAF Violations vs Baseline</h3>"
        "<table class='results violation-compare'>"
        "<thead><tr>"
        "<th>Violation</th><th>Baseline Learn</th><th>Policy Learn</th><th>Learn Match</th>"
        "<th>Baseline Alarm</th><th>Policy Alarm</th><th>Alarm Match</th>"
        "<th>Baseline Block</th><th>Policy Block</th><th>Block Match</th><th>Overall</th>"
        "</tr></thead><tbody>"
        + "".join(body_rows) +
        "</tbody></table>"
    )


_DASHBOARD_CSS = """
html{scroll-behavior:smooth}
body{font-family:Arial,Helvetica,sans-serif;background:#f7f7fb;color:#222;margin:0;padding:0}
h1{margin-top:0;margin-bottom:12px}
h2{margin:16px 0 8px}
.topbar{background:linear-gradient(135deg,#0f3460,#1f4f85);color:#fff;padding:12px 20px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px}
.top-title{font-size:18px;font-weight:700;letter-spacing:.3px}
.top-meta{display:flex;gap:16px;font-size:13px;flex-wrap:wrap;align-items:center}
.top-meta span{display:flex;align-items:center;gap:4px}
.shell{display:flex;gap:18px;align-items:flex-start;padding:16px 20px}
.sidebar{width:260px;flex-shrink:0;position:sticky;top:16px;max-height:calc(100vh - 80px);overflow:auto;background:#fff;border:1px solid #d9dfea;border-radius:8px;padding:12px}
.main{flex:1;min-width:0}
.policy-nav{display:flex;flex-direction:column;gap:3px}
.nav-group-title{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:#6b7a99;padding:8px 8px 2px;margin-top:4px}
.nav-item{display:flex;flex-direction:column;text-align:left;border:1px solid transparent;border-radius:6px;background:none;padding:8px 10px;cursor:pointer;font:inherit;color:#1f2b3d;width:100%;transition:background .12s,border-color .12s;-webkit-appearance:none;appearance:none}
.nav-item:hover{background:#f0f4ff;border-color:#c5cfe8}
.nav-item.active{background:#e8eeff;border-color:#0f3460;font-weight:700;color:#0f3460}
.nav-policy-path{font-weight:600;word-break:break-word;font-size:13px}
.nav-policy-meta{font-size:11px;color:#6b7a99;margin-top:2px}
.nav-item.active .nav-policy-meta{color:#3a5a99}
.view{display:none}
.view.active{display:block}
.device-banner{background:linear-gradient(135deg,#0f3460,#1f4f85);color:#fff;border-radius:10px;padding:14px 16px;margin:0 0 14px;border:1px solid #0b2a4f}
.device-banner-title{font-size:15px;font-weight:700;margin-bottom:8px;text-transform:uppercase;letter-spacing:.4px;opacity:.95}
.device-banner-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px}
.device-banner-grid .label{display:block;font-size:11px;opacity:.85;text-transform:uppercase;letter-spacing:.35px;margin-bottom:2px}
.device-banner-grid strong{font-size:15px}
.policy-card{display:block;text-decoration:none;color:#1f2b3d;border:1px solid #d8deeb;border-radius:8px;background:#f8fafe;padding:10px;transition:border-color .15s,box-shadow .15s;cursor:pointer;font:inherit;text-align:left;width:100%;appearance:none;-webkit-appearance:none}
.policy-card:hover{border-color:#5b77ad;box-shadow:0 0 0 2px rgba(15,52,96,.15)}
.policy-card.active{border-color:#0f3460;box-shadow:0 0 0 2px rgba(15,52,96,.25)}
.policy-card-title{font-weight:700;margin-bottom:6px;word-break:break-word}
.policy-card-meta{display:grid;gap:4px;font-size:12px}
.policy-card-badges{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:6px}
.policy-mode{display:inline-block;padding:2px 8px;border-radius:999px;font-weight:700;width:fit-content}
.policy-status{display:inline-block;padding:2px 8px;border-radius:999px;font-weight:700;width:fit-content}
.status-compliant{background:#d4edda;color:#155724}
.status-review{background:#ffe8a1;color:#7a5a00}
.mode-blocking{background:#d4edda;color:#155724}
.mode-transparent{background:#ffe9a8;color:#7a5a00}
.summary-card{background:#eef5ff}
table.results{border-collapse:collapse;width:100%;background:#fff;border:1px solid #ddd}
table.results th,table.results td{padding:10px;border-bottom:1px solid #eee;text-align:left}
table.results th{background:#0f3460;color:#fff}
tr.tier-red{background:#dc3545;color:#fff}
tr.tier-amber{background:#fd7e14;color:#fff}
tr.tier-yellow{background:#ffc107;color:#000}
tr.tier-green{background:#28a745;color:#fff}
tr.tier-yellow td{border-color:#f5d86a}
tr.tier-red a, tr.tier-amber a, tr.tier-green a{color:#fff;font-weight:bold}
.summary-bar{display:flex;gap:12px;margin:12px 0;font-weight:bold}
.summary-bar span{padding:6px 10px;border-radius:4px;color:#fff}
.summary-bar .tier-red{background:#dc3545}
.summary-bar .tier-amber{background:#fd7e14}
.summary-bar .tier-yellow{background:#ffc107;color:#000}
.summary-bar .tier-green{background:#28a745}
.muted{color:#5f6570}
.legacy-policy{margin-top:10px;border:1px solid #d9dfea;border-radius:6px;background:#fff}
.legacy-policy>summary{cursor:pointer;padding:10px 12px;font-weight:bold;background:#f3f6fc}
.details-body{padding:10px 12px}
.legacy-meta th{width:180px;background:#f8fafe;color:#22314f}
.legacy-summary{max-width:420px;margin-bottom:10px}
.legacy-findings th,.legacy-findings td{font-size:13px}
.violation-compare th,.violation-compare td{font-size:12px}
.vs-controls{display:flex;align-items:center;gap:8px;margin-bottom:10px}
.vs-controls input{padding:6px 10px;border:1px solid #c5cfe8;border-radius:4px;font-size:13px;width:280px}
.expand-col{width:36px;text-align:center}
.vs-toggle{background:none;border:1px solid #c5cfe8;border-radius:4px;cursor:pointer;font:inherit;font-size:14px;font-weight:700;color:#0f3460;width:24px;height:24px;padding:0;line-height:1}
.vs-toggle:hover{background:#e8eeff}
.vs-detail-row td{padding:0}
.vs-detail-panel{padding:12px 16px;background:#f8fafe;border-top:1px solid #e0e8f5}
.vs-detail-panel h4{margin:8px 0 4px;font-size:13px;color:#0f3460}
.vs-detail-panel ul{margin:4px 0 10px 16px;padding:0;font-size:13px}
.status-badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600}
.status-enabled{background:#d4edda;color:#155724}
.status-capable{background:#cce5ff;color:#004085}
.status-na{background:#e2e3e5;color:#383d41}
.inventory-banner{background:#fff3cd;border:1px solid #ffc107;border-radius:6px;padding:10px 14px;margin-bottom:12px;color:#856404}
table.results.nested{margin-top:6px;font-size:13px}
.sort-btn{background:none;border:none;color:#fff;font:inherit;font-weight:700;cursor:pointer;padding:0;text-decoration:underline dotted}
.sort-btn:hover{text-decoration:underline}
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
