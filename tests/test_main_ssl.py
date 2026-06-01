"""
Tests for the SSL string-to-bool conversion and baseline-path guard in src/main.py.

SSL: "true"/"1"/"yes" → True (verification enabled), "false"/"0"/"no" → False.
Baseline path guard: stale config.yaml filesystem paths are detected and discarded
so the interactive selector takes over instead of failing with "policy not found".
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.main import _resolve


def _ssl_from_string(raw: str) -> bool:
    """Reproduce the exact SSL resolution logic from main.py."""
    _raw_ssl = _resolve(None, "UNUSED_ENV_VAR_FOR_TEST", None, raw)
    if isinstance(_raw_ssl, str):
        return _raw_ssl.lower() in ("1", "true", "yes")
    return bool(_raw_ssl)


class TestSslStringConversion:
    @pytest.mark.parametrize("raw,expected", [
        ("true",  True),
        ("True",  True),
        ("TRUE",  True),
        ("1",     True),
        ("yes",   True),
        ("YES",   True),
        ("false", False),
        ("False", False),
        ("FALSE", False),
        ("0",     False),
        ("no",    False),
        ("NO",    False),
    ])
    def test_string_values(self, raw, expected):
        assert _ssl_from_string(raw) == expected

    def test_bool_true_unchanged(self):
        """Non-string True stays True."""
        _raw_ssl = _resolve(None, "UNUSED", None, True)
        assert not isinstance(_raw_ssl, str)
        assert bool(_raw_ssl) is True

    def test_bool_false_unchanged(self):
        """Non-string False stays False."""
        _raw_ssl = _resolve(None, "UNUSED", None, False)
        assert not isinstance(_raw_ssl, str)
        assert bool(_raw_ssl) is False


# ── Baseline filesystem-path guard ────────────────────────────────────────────

def _is_filesystem_path(value: str) -> bool:
    """Reproduce the path-detection logic from main.py."""
    from pathlib import Path
    ext = Path(value).suffix.lower()
    return ext in (".xml", ".json", ".yaml", ".yml") or value.startswith(("./", "../"))


class TestBaselinePathGuard:
    """The guard in main.py must discard stale file paths from config.yaml."""

    @pytest.mark.parametrize("path", [
        "./baseline/corporate_baseline.xml",
        "../baselines/stig.xml",
        "./baseline/bot_baseline.json",
        "relative/path/policy.xml",
        "/absolute/path/to/baseline.xml",
        "policy_export.json",
        "baseline.yaml",
    ])
    def test_filesystem_paths_detected(self, path):
        assert _is_filesystem_path(path), f"Expected {path!r} to be detected as filesystem path"

    @pytest.mark.parametrize("full_path", [
        "~Common~BST_Corporate_Baseline",
        "/Common/BST_Corporate_Baseline",
        "~Tenant1~BST_PCI_Strict",
        "/Common/my_policy",
        "~Common~some_policy",
    ])
    def test_device_fullpaths_not_detected(self, full_path):
        assert not _is_filesystem_path(full_path), (
            f"Expected {full_path!r} to be accepted as a valid device fullPath"
        )

    def test_main_discards_xml_path_from_config(self, tmp_path):
        """main() must discard a stale .xml baseline_policy so interactive/error
        takes over rather than failing with 'policy not found on device'."""
        from unittest.mock import MagicMock, patch

        argv = [
            "--host", "10.0.0.1",
            "--username", "admin",
            "--password", "pass",
            "--mode", "WAF",
            "--output-dir", str(tmp_path),
        ]
        # Simulate a config with the old filesystem-path baseline value
        stale_config = {
            "bigip": {},
            "audit": {"baseline_policy": "./baseline/corporate_baseline.xml"},
            "gitlab": {},
        }
        # One mock policy so discover_policies is non-empty and we reach collect_run_parameters
        mock_policy = {"id": "id1", "name": "App1", "fullPath": "/Common/App1",
                       "enforcementMode": "blocking", "active": True}

        with patch("src.main.BigIPClient") as MockClient, \
             patch("src.main.PolicyExporter") as MockExporter, \
             patch("src.main.get_device_version", return_value="BIG-IP 17.1.0"), \
             patch("src.main._load_config", return_value=stale_config), \
             patch("src.main.collect_run_parameters") as mock_params, \
             patch("src.main.collect_virtual_server_inventory", return_value=[]), \
             patch("src.main.PolicyFetcher"):

            mock_client = MagicMock()
            MockClient.return_value = mock_client

            mock_exporter = MagicMock()
            mock_exporter.fetch_device_info.return_value = {"hostname": "bigip1", "mgmt_ip": "10.0.0.1"}
            mock_exporter.discover_partitions.return_value = ["Common"]
            mock_exporter.discover_policies.return_value = [mock_policy]
            mock_exporter._raw_asm_payload = {}
            MockExporter.return_value = mock_exporter

            # collect_run_parameters raises (e.g. no BST policy) — we just want to
            # confirm it was called with baseline_policy=None (path guard cleared it)
            mock_params.side_effect = RuntimeError("no BST policies found")

            from src.main import main
            main(argv)

        # Guard must have cleared the stale path — collect_run_parameters called with None
        assert mock_params.call_args is not None
        passed_baseline = mock_params.call_args.kwargs.get("baseline_policy")
        assert passed_baseline is None, (
            f"Expected baseline_policy=None after guard, got {passed_baseline!r}"
        )
