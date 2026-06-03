"""Tests for WAF/Bot enforcement summary table rendering in HTML dashboard.

VS / destination data is sourced from ComparisonResult.virtual_servers,
which is populated by PolicyExporter.enrich_with_virtual_servers() via the
ASM API (virtualServers + manualVirtualServers fields).
"""

import re
from typing import List, Optional

from src.policy_comparator import ComparisonResult
from src.report_generator import generate_html_dashboard
from src.virtual_server_inventory import (
    LtmPolicyAttachment,
    LtmPolicyRuleAttachment,
    VirtualServerRecord,
)


def _vs(full_path: str, destination: str, assoc_type: str = "direct") -> dict:
    """Minimal VS detail dict matching PolicyExporter._get_vs_destination output."""
    name = full_path.split("/")[-1]
    return {
        "name": name,
        "fullPath": full_path,
        "destination": destination,
        "ip": destination.split(":")[-2].lstrip("/").split("/")[-1] if ":" in destination else "",
        "port": destination.split(":")[-1] if ":" in destination else "",
        "association_type": assoc_type,
        "ltm_policies": [],
    }


def _make_result(
    policy_path: str,
    score: float = 95.0,
    virtual_servers: Optional[List[dict]] = None,
) -> ComparisonResult:
    return ComparisonResult(
        policy_name=policy_path.split("/")[-1],
        policy_path=policy_path,
        partition="Common",
        enforcement_mode="blocking",
        baseline_name="baseline.xml",
        timestamp="2026-05-22T12:00:00Z",
        score=score,
        tier_label="Compliant" if score >= 90 else "Needs Review",
        device_hostname="bigip1.example.local",
        device_mgmt_ip="10.0.0.1",
        virtual_servers=virtual_servers or [],
        virtual_server_eval_performed=(virtual_servers is not None),
    )


def test_generate_html_dashboard_includes_three_pane_landmarks_and_vs_summary(tmp_path):
    results = [
        _make_result(
            "/Common/api_waf",
            96.0,
            virtual_servers=[_vs("/Common/vs_ltm", "/Common/10.0.0.12:443", "manual")],
        ),
        _make_result(
            "/Common/direct_waf",
            88.0,
            virtual_servers=[_vs("/Common/vs_direct", "/Common/10.0.0.11:443", "direct")],
        ),
    ]

    # Inventory is still accepted (for backward compat) but no longer drives the table.
    inventory = [
        VirtualServerRecord(
            name="vs_no_http",
            partition="Common",
            full_path="/Common/vs_no_http",
            destination="/Common/10.0.0.10:80",
            http_profile=None,
            directly_attached_waf_policies=[],
            ltm_policies=[],
            waf_status="not_applicable",
        ),
        VirtualServerRecord(
            name="vs_direct",
            partition="Common",
            full_path="/Common/vs_direct",
            destination="/Common/10.0.0.11:443",
            http_profile="/Common/http",
            directly_attached_waf_policies=["/Common/direct_waf"],
            ltm_policies=[],
            waf_status="enabled",
        ),
        VirtualServerRecord(
            name="vs_ltm",
            partition="Common",
            full_path="/Common/vs_ltm",
            destination="/Common/10.0.0.12:443",
            http_profile="/Common/http",
            directly_attached_waf_policies=[],
            ltm_policies=[
                LtmPolicyAttachment(
                    name="ltm_host_policy",
                    full_path="/Common/ltm_host_policy",
                    rules=[
                        LtmPolicyRuleAttachment(
                            rule_name="route_api",
                            host_conditions=["api.example.gov"],
                            waf_policy="/Common/api_waf",
                        )
                    ],
                )
            ],
            waf_status="enabled",
        ),
        VirtualServerRecord(
            name="vs_capable",
            partition="Common",
            full_path="/Common/vs_capable",
            destination="/Common/10.0.0.13:443",
            http_profile="/Common/http",
            directly_attached_waf_policies=[],
            ltm_policies=[],
            waf_status="capable",
        ),
    ]

    out = generate_html_dashboard(results, str(tmp_path), virtual_server_inventory=inventory)
    html = out.read_text(encoding="utf-8")

    # Three-pane shell landmarks preserved
    assert re.search(r"<header[^>]*role='banner'", html)
    assert re.search(r"<nav[^>]*role='navigation'", html)
    assert re.search(r"<main[^>]*role='main'", html)

    # Summary view and enforcement table present
    assert "id='summary-view'" in html
    assert "id='vs-summary-table'" in html

    # New column headers
    assert "Policy Name" in html
    assert "Enforcement Mode" in html
    assert "Virtual Server" in html
    assert "Tier Status" in html
    assert "Destination IP" in html

    # Removed columns are gone from the summary table header
    assert "data-col='partition'" not in html
    assert "data-col='http_profile'" not in html
    assert "data-col='status'" not in html
    assert "data-col='attached'" not in html

    # Critical/High/Warning/Info count columns are gone from Summary tab
    assert "<th>Critical</th>" not in html
    assert "<th>High</th>" not in html
    assert "<th>Warning</th>" not in html
    assert "<th>Info</th>" not in html

    # Summary bar (tier count pills) is gone
    assert "class='summary-bar'" not in html

    # Policy rows driven by ComparisonResult.virtual_servers — direct attachment
    assert "/Common/direct_waf" in html
    assert "/Common/vs_direct" in html
    assert "/Common/10.0.0.11:443" in html

    # Policy rows — LTM/manual attachment
    assert "/Common/api_waf" in html
    assert "/Common/vs_ltm" in html
    assert "/Common/10.0.0.12:443" in html

    # VSes that appear only in inventory (not in any result.virtual_servers) are absent
    assert "vs_no_http" not in html
    assert "vs_capable" not in html

    # Enforcement mode badge rendered
    assert "mode-blocking" in html

    # Policy click-through links preserved
    assert "data-policy-path='/Common/api_waf'" in html
    assert "data-policy-path='/Common/direct_waf'" in html

    # Sortable columns wired up
    assert "data-col='policy'" in html
    assert "data-col='mode'" in html
    assert "data-col='vs'" in html
    assert "data-col='tier'" in html
    assert "data-col='destination'" in html


def test_policy_without_vs_shows_not_applied(tmp_path):
    """Policies whose virtual_servers list is empty get a 'Not applied' row."""
    results = [_make_result("/Common/orphan_policy", 70.0, virtual_servers=[])]
    out = generate_html_dashboard(results, str(tmp_path), virtual_server_inventory=[])
    html = out.read_text(encoding="utf-8")

    assert "/Common/orphan_policy" in html
    assert "Not applied" in html


def test_inventory_error_does_not_block_table(tmp_path):
    """An inventory_error no longer blocks the table; the result's VS data still renders."""
    results = [
        _make_result(
            "/Common/some_policy",
            80.0,
            virtual_servers=[_vs("/Common/vs_one", "/Common/192.0.2.1:443")],
        )
    ]
    out = generate_html_dashboard(
        results,
        str(tmp_path),
        virtual_server_inventory=None,
        virtual_server_inventory_error="Connection timed out",
    )
    html = out.read_text(encoding="utf-8")
    # Table still renders with VS data from ComparisonResult
    assert "/Common/vs_one" in html
    assert "/Common/192.0.2.1:443" in html


def test_multiple_vs_per_policy_each_get_row(tmp_path):
    """A policy attached to two VSes emits two rows, one per VS."""
    results = [
        _make_result(
            "/Common/shared_waf",
            95.0,
            virtual_servers=[
                _vs("/Common/vs_a", "/Common/10.0.0.30:443"),
                _vs("/Common/vs_b", "/Common/10.0.0.31:443"),
            ],
        )
    ]
    out = generate_html_dashboard(results, str(tmp_path), virtual_server_inventory=[])
    html = out.read_text(encoding="utf-8")

    assert "/Common/vs_a" in html
    assert "/Common/vs_b" in html
    assert html.count("/Common/shared_waf") >= 2


def test_multiple_policies_same_vs_each_get_row(tmp_path):
    """Two policies attached to the same VS each appear as their own row."""
    results = [
        _make_result(
            "/Common/waf_a",
            95.0,
            virtual_servers=[_vs("/Common/vs_multi", "/Common/10.0.0.20:443")],
        ),
        _make_result(
            "/Common/waf_b",
            85.0,
            virtual_servers=[_vs("/Common/vs_multi", "/Common/10.0.0.20:443")],
        ),
    ]
    out = generate_html_dashboard(results, str(tmp_path), virtual_server_inventory=[])
    html = out.read_text(encoding="utf-8")

    assert "/Common/waf_a" in html
    assert "/Common/waf_b" in html
    assert html.count("/Common/vs_multi") >= 2
    assert html.count("/Common/10.0.0.20:443") >= 2
