"""Tests for WAF virtual server summary rendering in HTML dashboard."""

import re

from src.policy_comparator import ComparisonResult
from src.report_generator import generate_html_dashboard
from src.virtual_server_inventory import (
    LtmPolicyAttachment,
    LtmPolicyRuleAttachment,
    VirtualServerRecord,
)


def _make_result(policy_path: str, score: float = 95.0) -> ComparisonResult:
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
    )


def test_generate_html_dashboard_includes_three_pane_landmarks_and_vs_summary(tmp_path):
    results = [_make_result("/Common/api_waf", 96.0), _make_result("/Common/direct_waf", 88.0)]

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

    assert re.search(r"<header[^>]*role='banner'", html)
    assert re.search(r"<nav[^>]*role='navigation'", html)
    assert re.search(r"<main[^>]*role='main'", html)

    assert "id='summary-view'" in html
    assert "id='vs-summary-table'" in html

    assert "vs_no_http" in html
    assert "class='status-badge status-na'>Not Applicable</span>" in html
    assert "class='status-badge status-enabled'>WAF Enabled</span>" in html
    assert "class='status-badge status-capable'>WAF Capable</span>" in html

    assert "class='vs-toggle'" in html
    assert "aria-expanded='false'" in html
    assert "class='vs-detail-row' hidden" in html

    assert "Host (FQDN)" in html
    assert "api.example.gov" in html
    assert "data-policy-path='/Common/api_waf'" in html
