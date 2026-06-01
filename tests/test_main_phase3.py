"""
Phase 3 integration tests for _run_waf_audit() PolicyFetcher integration.

Tests:
  - One target policy fetch fails → remaining targets still audited
  - Baseline fetch raises → function returns 1
  - KeyboardInterrupt inside _run_waf_audit → main() returns 130
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.main import _run_waf_audit, main


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _make_policy(name: str, full_path: str, policy_id: str = "id1") -> dict:
    return {
        "id": policy_id,
        "name": name,
        "fullPath": full_path,
        "enforcementMode": "blocking",
        "active": True,
        "virtual_servers": [],
    }


def _make_cmp_result(path: str = "/Common/P1", score: float = 95.0) -> MagicMock:
    r = MagicMock()
    r.score = score
    r.tier = "GREEN"
    r.tier_label = "GREEN"
    r.diffs = []
    r.policy_path = path
    r.summary = {"totals": {"critical": 0, "high": 0, "warning": 0, "info": 0}}
    return r


def _make_exporter(policies: list) -> MagicMock:
    exporter = MagicMock()
    exporter.discover_policies.return_value = policies
    exporter.enrich_with_virtual_servers.return_value = None
    exporter._raw_asm_payload = {}
    return exporter


def _baseline_data(name: str = "BST_Base", full_path: str = "/Common/BST_Base") -> dict:
    return {
        "name": name,
        "fullPath": full_path,
        "id": "id0",
        "enforcementMode": "blocking",
        "general": {"enforcementMode": "blocking"},
        "blocking": {},
        "blocking-settings": {"violations": [], "evasions": [], "http-protocols": []},
        "signature-sets": [],
        "attack-signatures": [],
        "urls": [],
        "filetypes": [],
        "parameters": [],
        "headers": [],
        "cookies": [],
        "methods": [],
        "whitelist-ips": [],
        "login-pages": [],
        "brute-force": [],
        "data-guard": {},
        "ip-intelligence": {},
        "policy-builder": {"learningMode": "disabled"},
        "bot-defense": {},
    }


def _target_data(name: str, full_path: str) -> dict:
    d = _baseline_data(name, full_path)
    d["id"] = f"id-{name}"
    return d


# ── Test: one target fetch fails, others continue ──────────────────────────────

class TestOneFetchFailsContinues:
    """When one target policy fetch raises, the rest are still audited."""

    def test_remaining_targets_audited(self, tmp_path):
        baseline = _make_policy("BST_Base", "/Common/BST_Base", "id0")
        p1 = _make_policy("P1", "/Common/P1", "id1")
        p2 = _make_policy("P2", "/Common/P2", "id2")

        exporter = _make_exporter([baseline, p1, p2])
        client = MagicMock()

        cmp_ok = _make_cmp_result("/Common/P2")

        fetch_results = [
            _baseline_data(),           # baseline succeeds
            Exception("timeout"),       # p1 fetch fails
            _target_data("P2", "/Common/P2"),  # p2 succeeds
        ]

        def side_effect_fetch(policy):
            result = fetch_results.pop(0)
            if isinstance(result, Exception):
                raise result
            return result

        with patch("src.main.collect_run_parameters") as mock_params, \
             patch("src.main.PolicyFetcher") as MockFetcher, \
             patch("src.main.compare_policies", return_value=cmp_ok), \
             patch("src.main.generate_markdown"), \
             patch("src.main.generate_html_dashboard", return_value=str(tmp_path / "dash.html")), \
             patch("src.main.generate_summary_reports"), \
             patch("src.main.generate_virtual_server_summary_markdown"), \
             patch("src.main.collect_virtual_server_inventory", return_value=[]):

            mock_params.return_value = {"baseline": baseline, "target_policies": [p1, p2]}
            mock_fetcher = MagicMock()
            mock_fetcher.fetch_waf_policy.side_effect = side_effect_fetch
            MockFetcher.return_value = mock_fetcher

            rc = _run_waf_audit(
                client=client,
                exporter=exporter,
                all_partitions=["Common"],
                baseline_policy_arg=None,
                output_dir=str(tmp_path),
                formats=["html", "markdown"],
                device_hostname="bigip1",
                device_mgmt_ip="10.0.0.1",
                gitlab_state=None,
                gitlab_update_source_truth=False,
                logger=MagicMock(),
                fail_on_tier="RED",
                pass_threshold=90.0,
            )

        # Not exit 2 (not all failed) — p2 was audited successfully
        assert rc != 2
        # baseline + p1 + p2 = 3 fetch calls
        assert mock_fetcher.fetch_waf_policy.call_count == 3
        # compare_policies called once (only p2 succeeded)
        import src.main as main_mod
        # The return code reflects the successful p2 result (GREEN → 0)
        assert rc == 0

    def test_all_targets_fail_returns_2(self, tmp_path):
        baseline = _make_policy("BST_Base", "/Common/BST_Base", "id0")
        p1 = _make_policy("P1", "/Common/P1", "id1")

        exporter = _make_exporter([baseline, p1])
        client = MagicMock()

        fetch_results = [
            _baseline_data(),       # baseline OK
            Exception("refused"),   # p1 fails
        ]

        def side_effect_fetch(policy):
            result = fetch_results.pop(0)
            if isinstance(result, Exception):
                raise result
            return result

        with patch("src.main.collect_run_parameters") as mock_params, \
             patch("src.main.PolicyFetcher") as MockFetcher, \
             patch("src.main.collect_virtual_server_inventory", return_value=[]):

            mock_params.return_value = {"baseline": baseline, "target_policies": [p1]}
            mock_fetcher = MagicMock()
            mock_fetcher.fetch_waf_policy.side_effect = side_effect_fetch
            MockFetcher.return_value = mock_fetcher

            rc = _run_waf_audit(
                client=client,
                exporter=exporter,
                all_partitions=["Common"],
                baseline_policy_arg=None,
                output_dir=str(tmp_path),
                formats=["html"],
                device_hostname="bigip1",
                device_mgmt_ip="10.0.0.1",
                gitlab_state=None,
                gitlab_update_source_truth=False,
                logger=MagicMock(),
                fail_on_tier="RED",
                pass_threshold=90.0,
            )

        assert rc == 2


# ── Test: baseline fetch raises → exit 1 ──────────────────────────────────────

class TestBaselineFetchFails:
    """Baseline policy fetch failure aborts with exit code 1."""

    def test_baseline_exception_returns_1(self, tmp_path):
        baseline = _make_policy("BST_Base", "/Common/BST_Base", "id0")
        p1 = _make_policy("P1", "/Common/P1", "id1")

        exporter = _make_exporter([baseline, p1])
        client = MagicMock()

        with patch("src.main.collect_run_parameters") as mock_params, \
             patch("src.main.PolicyFetcher") as MockFetcher, \
             patch("src.main.collect_virtual_server_inventory", return_value=[]):

            mock_params.return_value = {"baseline": baseline, "target_policies": [p1]}
            mock_fetcher = MagicMock()
            mock_fetcher.fetch_waf_policy.side_effect = Exception("404 Not Found")
            MockFetcher.return_value = mock_fetcher

            rc = _run_waf_audit(
                client=client,
                exporter=exporter,
                all_partitions=["Common"],
                baseline_policy_arg=None,
                output_dir=str(tmp_path),
                formats=["html"],
                device_hostname="bigip1",
                device_mgmt_ip="10.0.0.1",
                gitlab_state=None,
                gitlab_update_source_truth=False,
                logger=MagicMock(),
                fail_on_tier="RED",
                pass_threshold=90.0,
            )

        assert rc == 1
        # client.close() must be called on abort
        client.close.assert_called()

    def test_baseline_timeout_returns_1(self, tmp_path):
        import requests
        baseline = _make_policy("BST_Base", "/Common/BST_Base", "id0")
        p1 = _make_policy("P1", "/Common/P1", "id1")

        exporter = _make_exporter([baseline, p1])
        client = MagicMock()

        with patch("src.main.collect_run_parameters") as mock_params, \
             patch("src.main.PolicyFetcher") as MockFetcher, \
             patch("src.main.collect_virtual_server_inventory", return_value=[]):

            mock_params.return_value = {"baseline": baseline, "target_policies": [p1]}
            mock_fetcher = MagicMock()
            mock_fetcher.fetch_waf_policy.side_effect = requests.Timeout("timed out")
            MockFetcher.return_value = mock_fetcher

            rc = _run_waf_audit(
                client=client,
                exporter=exporter,
                all_partitions=["Common"],
                baseline_policy_arg=None,
                output_dir=str(tmp_path),
                formats=["html"],
                device_hostname="bigip1",
                device_mgmt_ip="10.0.0.1",
                gitlab_state=None,
                gitlab_update_source_truth=False,
                logger=MagicMock(),
                fail_on_tier="RED",
                pass_threshold=90.0,
            )

        assert rc == 1


# ── Test: KeyboardInterrupt → exit 130 ────────────────────────────────────────

class TestKeyboardInterrupt:
    """KeyboardInterrupt raised inside _run_waf_audit is caught in main() returning 130."""

    def test_keyboard_interrupt_returns_130(self, tmp_path):
        argv = [
            "--host", "10.0.0.1",
            "--username", "admin",
            "--password", "testpass",
            "--mode", "WAF",
            "--baseline-policy", "/Common/BST_Base",
            "--output-dir", str(tmp_path),
            "--format", "html",
        ]
        with patch("src.main.BigIPClient") as MockClient, \
             patch("src.main.PolicyExporter") as MockExporter, \
             patch("src.main.get_device_version", return_value="BIG-IP 17.1.0"), \
             patch("src.main._run_waf_audit", side_effect=KeyboardInterrupt):

            mock_client = MagicMock()
            MockClient.return_value = mock_client

            mock_exporter = MagicMock()
            mock_exporter.fetch_device_info.return_value = {
                "hostname": "bigip1", "mgmt_ip": "10.0.0.1"
            }
            mock_exporter.discover_partitions.return_value = ["Common"]
            MockExporter.return_value = mock_exporter

            rc = main(argv)

        assert rc == 130

    def test_keyboard_interrupt_during_password_prompt_returns_130(self, tmp_path):
        """KeyboardInterrupt at the password prompt returns 130."""
        argv = [
            "--host", "10.0.0.1",
            "--username", "admin",
            "--mode", "WAF",
            "--output-dir", str(tmp_path),
        ]
        with patch("src.main.sys") as mock_sys, \
             patch("src.main.prompt_password", side_effect=KeyboardInterrupt):
            mock_sys.stdin.isatty.return_value = True
            mock_sys.stderr = sys.stderr
            mock_sys.stdout = sys.stdout

            # Re-import to ensure patched sys is used
            from src.main import main as main_fn
            rc = main_fn(argv)

        assert rc == 130
