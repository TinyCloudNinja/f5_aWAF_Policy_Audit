"""
Report generation for WAF and Bot Defense audits (tiered scoring model).

Changelog: Implemented 4-tier compliance rendering with circuit breaker
disclosure, raw vs capped scores, deduction breakdowns, and color-coded
dashboards replacing legacy PASS/FAIL views.
"""
from __future__ import annotations

import html
from pathlib import Path
from typing import Dict, List

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
        "The following hard-fail conditions cap the score at 49 regardless of other deductions:" 
    )
    lines.append("")
    for cb in result.circuit_breakers_triggered:
        lines.append(f"- `{cb}`")
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


def generate_html_dashboard(results: List[ComparisonResult], output_dir: str) -> Path:
    """Generate a multi-policy HTML dashboard sorted worst-first."""

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

    rows = []
    for r in ordered:
        tier_cls = _TIER_CLASS.get(r.tier, "")
        cb_col = ", ".join(r.circuit_breakers_triggered) if r.circuit_breakers_triggered else "—"
        raw_col = f"{r.raw_score:.1f}" if r.is_hard_fail else "—"
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

    summary_bar = (
        f"<div class='summary-bar'>"
        f"<span class='tier-red'>🔴 Red: {counts[TIER_RED]}</span>"
        f"<span class='tier-amber'>🟠 Amber: {counts[TIER_AMBER]}</span>"
        f"<span class='tier-yellow'>🟡 Yellow: {counts[TIER_YELLOW]}</span>"
        f"<span class='tier-green'>🟢 Green: {counts[TIER_GREEN]}</span>"
        "</div>"
    )

    css = _DASHBOARD_CSS
    legacy_sections = "".join(_build_legacy_policy_section(r) for r in ordered)

    html_doc = (
        "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
        f"<title>{'Bot Defense' if is_bot else 'WAF'} Audit Dashboard</title>"
        f"<style>{css}</style>"
        "</head><body>"
        f"<h1>{'Bot Defense' if is_bot else 'WAF'} Audit Dashboard</h1>"
        f"{summary_bar}"
        "<table class='results'>"
        "<thead><tr>"
        "<th>Policy/Profile</th><th>Tier</th><th>Score</th><th>Raw Score</th><th>Circuit Breakers</th>"
        "<th>Critical</th><th>High</th><th>Warning</th><th>Info</th>"
        "</tr></thead><tbody>"
        + "".join(rows) +
        "</tbody></table>"
        "<h2 style='margin-top:24px'>Detailed Combined Report</h2>"
        "<p class='muted'>Legacy per-policy report content is included below for full audit detail.</p>"
        f"{legacy_sections}"
        "</body></html>"
    )

    out_path.write_text(html_doc, encoding="utf-8")
    _log.info("HTML dashboard: %s", out_path)
    return out_path


def _esc(val) -> str:
    return html.escape(str(val))


def _build_legacy_policy_section(result: ComparisonResult) -> str:
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

    raw_score = f"{result.raw_score:.1f}%" if result.is_hard_fail else "—"
    cb_text = ", ".join(result.circuit_breakers_triggered) if result.circuit_breakers_triggered else "None"
    return (
        "<details class='legacy-policy'>"
        f"<summary><strong>{_esc(result.policy_path)}</strong> — {_TIER_EMOJI.get(result.tier,'')} {_esc(result.tier_label)} ({result.score:.1f}%)</summary>"
        "<div class='details-body'>"
        "<table class='results legacy-meta'><tbody>"
        f"<tr><th>Partition</th><td>{_esc(result.partition)}</td><th>Enforcement Mode</th><td>{_esc(result.enforcement_mode)}</td></tr>"
        f"<tr><th>Baseline</th><td>{_esc(result.baseline_name)}</td><th>Audit Date</th><td>{_esc(result.timestamp)}</td></tr>"
        f"<tr><th>Score</th><td>{result.score:.1f}%</td><th>Raw Score</th><td>{raw_score}</td></tr>"
        f"<tr><th>Circuit Breakers</th><td colspan='3'>{_esc(cb_text)}</td></tr>"
        "</tbody></table>"
        "<h3>Executive Summary</h3>"
        "<table class='results legacy-summary'><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>"
        f"{summary_rows}</tbody></table>"
        + "".join(finding_sections) +
        "</div></details>"
    )


_DASHBOARD_CSS = """
body{font-family:Arial,Helvetica,sans-serif;background:#f7f7fb;color:#222;padding:20px}
h1{margin-top:0;margin-bottom:12px}
h2{margin:16px 0 8px}
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
