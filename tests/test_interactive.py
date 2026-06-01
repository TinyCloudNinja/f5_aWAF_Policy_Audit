"""
Unit tests for src/interactive.py.

All questionary calls and sys.stdin.isatty() are mocked — no TTY required.
"""
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.interactive import (
    BASELINE_PREFIX,
    filter_baselines,
    lookup_by_full_path,
    collect_run_parameters,
    prompt_password,
    prompt_mode,
    prompt_baseline,
    prompt_policies,
)


# ── filter_baselines ───────────────────────────────────────────────────────────

class TestFilterBaselines:
    def _items(self):
        return [
            {"name": "BST_Corporate",    "fullPath": "/Common/BST_Corporate"},
            {"name": "APP_CustomerPortal","fullPath": "/Common/APP_CustomerPortal"},
            {"name": "bst_nipr",         "fullPath": "/Common/bst_nipr"},
            {"name": "BST_DoD",          "fullPath": "/Tenant/BST_DoD"},
        ]

    def test_keeps_bst_prefix(self):
        result = filter_baselines(self._items())
        names = [r["name"] for r in result]
        assert "BST_Corporate" in names
        assert "bst_nipr" in names
        assert "BST_DoD" in names

    def test_excludes_non_bst(self):
        result = filter_baselines(self._items())
        names = [r["name"] for r in result]
        assert "APP_CustomerPortal" not in names

    def test_case_insensitive(self):
        items = [{"name": "bst_lower", "fullPath": "/Common/bst_lower"}]
        result = filter_baselines(items)
        assert len(result) == 1

    def test_sorted_by_full_path(self):
        result = filter_baselines(self._items())
        fps = [r["fullPath"] for r in result]
        assert fps == sorted(fps)

    def test_empty_list(self):
        assert filter_baselines([]) == []

    def test_no_bst_policies(self):
        items = [{"name": "APP_Foo", "fullPath": "/Common/APP_Foo"}]
        assert filter_baselines(items) == []

    def test_baseline_prefix_constant_is_bst(self):
        assert BASELINE_PREFIX == "BST"


# ── lookup_by_full_path ────────────────────────────────────────────────────────

class TestLookupByFullPath:
    def _items(self):
        return [
            {"name": "A", "fullPath": "/Common/PolicyA"},
            {"name": "B", "fullPath": "/Tenant/PolicyB"},
        ]

    def test_exact_match(self):
        result = lookup_by_full_path(self._items(), "/Common/PolicyA")
        assert result is not None
        assert result["name"] == "A"

    def test_tilde_normalization(self):
        result = lookup_by_full_path(self._items(), "~Common~PolicyA")
        assert result is not None
        assert result["name"] == "A"

    def test_not_found_returns_none(self):
        assert lookup_by_full_path(self._items(), "/Common/NonExistent") is None

    def test_empty_list(self):
        assert lookup_by_full_path([], "/Common/PolicyA") is None


# ── collect_run_parameters (non-interactive bypass) ───────────────────────────

class TestCollectRunParametersNonInteractive:
    def _items(self):
        return [
            {"name": "BST_Corporate", "fullPath": "/Common/BST_Corporate"},
            {"name": "APP_Portal",    "fullPath": "/Common/APP_Portal"},
            {"name": "APP_API",       "fullPath": "/Common/APP_API"},
        ]

    def test_bypasses_prompts_when_baseline_provided(self):
        """No questionary calls should be made when baseline_policy is supplied."""
        with patch("src.interactive.questionary") as mock_q:
            result = collect_run_parameters(
                all_items=self._items(),
                output_dir="/tmp/out",
                mode="WAF",
                baseline_policy="/Common/BST_Corporate",
            )
        mock_q.select.assert_not_called()
        mock_q.checkbox.assert_not_called()
        mock_q.confirm.assert_not_called()

    def test_correct_baseline_selected(self):
        result = collect_run_parameters(
            all_items=self._items(),
            output_dir="/tmp/out",
            mode="WAF",
            baseline_policy="/Common/BST_Corporate",
        )
        assert result["baseline"]["fullPath"] == "/Common/BST_Corporate"

    def test_all_others_become_targets(self):
        result = collect_run_parameters(
            all_items=self._items(),
            output_dir="/tmp/out",
            mode="WAF",
            baseline_policy="/Common/BST_Corporate",
        )
        fps = [p["fullPath"] for p in result["target_policies"]]
        assert "/Common/APP_Portal" in fps
        assert "/Common/APP_API" in fps
        assert "/Common/BST_Corporate" not in fps

    def test_baseline_not_found_raises(self):
        with pytest.raises(RuntimeError, match="not found"):
            collect_run_parameters(
                all_items=self._items(),
                output_dir="/tmp/out",
                mode="WAF",
                baseline_policy="/Common/DOES_NOT_EXIST",
            )

    def test_mode_preserved_in_result(self):
        result = collect_run_parameters(
            all_items=self._items(),
            output_dir="/tmp/out",
            mode="BOT",
            baseline_policy="/Common/BST_Corporate",
        )
        assert result["mode"] == "BOT"

    def test_tilde_encoded_path_works(self):
        result = collect_run_parameters(
            all_items=self._items(),
            output_dir="/tmp/out",
            mode="WAF",
            baseline_policy="~Common~BST_Corporate",
        )
        assert result["baseline"]["name"] == "BST_Corporate"


# ── Non-TTY guard ──────────────────────────────────────────────────────────────

class TestNonTtyGuard:
    def test_prompt_password_raises_outside_tty(self):
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = False
            with pytest.raises(RuntimeError, match="TTY"):
                prompt_password("admin", "10.1.1.4")

    def test_prompt_mode_raises_outside_tty(self):
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = False
            with pytest.raises(RuntimeError, match="TTY"):
                prompt_mode()

    def test_prompt_baseline_raises_outside_tty(self):
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = False
            with pytest.raises(RuntimeError, match="TTY"):
                prompt_baseline([{"name": "BST_X", "fullPath": "/Common/BST_X"}])

    def test_prompt_policies_raises_outside_tty(self):
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = False
            with pytest.raises(RuntimeError, match="TTY"):
                prompt_policies([{"name": "A", "fullPath": "/Common/A"}], "/Common/BST_X")
