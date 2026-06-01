"""
Unit tests for src/policy_fetcher.py.

All BigIPClient calls are mocked — no network required.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, call
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.policy_fetcher import (
    PolicyFetcher,
    _normalize_violations,
    _normalize_bool_items,
    _normalize_signature_sets,
    _normalize_whitelist_ips,
    _normalize_data_guard,
    _normalize_ip_intelligence,
    _derive_name,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_client(get_returns=None, get_all_returns=None):
    client = MagicMock()
    if get_returns is not None:
        client.get.side_effect = get_returns if callable(get_returns) else (
            lambda path, **kwargs: get_returns.get(path, {})
        )
    if get_all_returns is not None:
        client.get_all.side_effect = get_all_returns if callable(get_all_returns) else (
            lambda path, **kwargs: get_all_returns.get(path, [])
        )
    return client


def _make_policy(policy_id="pid1", name="TestPolicy", full_path="/Common/TestPolicy"):
    return {"id": policy_id, "name": name, "fullPath": full_path, "enforcementMode": "blocking"}


# ── get_all() pagination ───────────────────────────────────────────────────────

class TestGetAll:
    """Tests for BigIPClient.get_all() (exercised indirectly via PolicyFetcher)."""

    def test_single_page_under_total(self):
        """When items < totalItems, get_all must fetch more pages."""
        from src.bigip_client import BigIPClient
        client = MagicMock(spec=BigIPClient)

        # Page 0: 500 items; Page 1: 250 items — totalItems = 750
        def fake_get(path, params=None):
            skip = int((params or {}).get("$skip", 0))
            if skip == 0:
                return {"items": list(range(500)), "totalItems": 750}
            return {"items": list(range(250)), "totalItems": 750}

        client.get.side_effect = fake_get
        # Instantiate a real BigIPClient method via unbound call
        from src.bigip_client import BigIPClient
        result = BigIPClient.get_all(client, "/some/path")
        assert len(result) == 750
        assert client.get.call_count == 2

    def test_empty_collection(self):
        from src.bigip_client import BigIPClient
        client = MagicMock(spec=BigIPClient)
        client.get.return_value = {"items": [], "totalItems": 0}
        result = BigIPClient.get_all(client, "/some/path")
        assert result == []

    def test_single_page_exact_total(self):
        from src.bigip_client import BigIPClient
        client = MagicMock(spec=BigIPClient)
        client.get.return_value = {"items": [1, 2, 3], "totalItems": 3}
        result = BigIPClient.get_all(client, "/some/path")
        assert result == [1, 2, 3]
        assert client.get.call_count == 1

    def test_safety_break_on_empty_page(self):
        """If totalItems is large but API returns empty items[], stop looping."""
        from src.bigip_client import BigIPClient
        client = MagicMock(spec=BigIPClient)
        client.get.return_value = {"items": [], "totalItems": 9999}
        result = BigIPClient.get_all(client, "/some/path")
        assert result == []


# ── Normalization helpers ──────────────────────────────────────────────────────

class TestNormalizeViolations:
    def test_flags_preserved(self):
        items = [{"name": "VIRUS_DETECTED", "alarm": True, "block": True, "learn": False,
                  "description": "Virus detected"}]
        result = _normalize_violations(items)
        assert len(result) == 1
        assert result[0]["block"] is True
        assert result[0]["alarm"] is True
        assert result[0]["learn"] is False

    def test_items_without_name_skipped(self):
        items = [{"description": "no name", "alarm": True, "block": False, "learn": False}]
        result = _normalize_violations(items)
        assert result == []

    def test_all_false_violations_included(self):
        """Default-state (all-False) violations must be kept — not silently dropped."""
        items = [{"name": "RESPONSE_SCRUBBING", "alarm": False, "block": False, "learn": False,
                  "description": "Response scrubbing"}]
        result = _normalize_violations(items)
        assert len(result) == 1
        assert result[0]["block"] is False


class TestNormalizeBoolItems:
    def test_name_derived_from_description(self):
        items = [{"description": "Multiple decoding", "enabled": True}]
        result = _normalize_bool_items(items)
        assert len(result) == 1
        assert result[0]["name"] == "MULTIPLE_DECODING"

    def test_enabled_false_preserved(self):
        items = [{"description": "Directory traversal", "enabled": False}]
        result = _normalize_bool_items(items)
        assert result[0]["alarm"] is False
        assert result[0]["block"] is False

    def test_items_without_name_or_description_skipped(self):
        items = [{"enabled": True}]
        result = _normalize_bool_items(items)
        assert result == []


class TestNormalizeSignatureSets:
    def test_basic_fields(self):
        items = [{"name": "Generic Detection Signatures", "alarm": True, "block": True, "learn": False}]
        result = _normalize_signature_sets(items)
        assert result[0]["name"] == "Generic Detection Signatures"
        assert result[0]["block"] is True

    def test_name_from_reference_link(self):
        items = [{"signatureSetReference": {"link": "/mgmt/tm/asm/signature-sets/All_Signatures"}}]
        result = _normalize_signature_sets(items)
        assert result[0]["name"] == "All_Signatures"


class TestNormalizeWhitelistIps:
    def test_basic_fields(self):
        items = [{"ipAddress": "10.0.0.1", "ipMask": "255.255.255.0",
                  "trustedByPolicyBuilder": True, "ignoreAnomalies": False,
                  "blockRequests": "never"}]
        result = _normalize_whitelist_ips(items)
        assert result[0]["ipAddress"] == "10.0.0.1"
        assert result[0]["trustedByPolicyBuilder"] is True

    def test_items_without_ip_skipped(self):
        items = [{"ipMask": "255.255.255.0"}]
        result = _normalize_whitelist_ips(items)
        assert result == []


class TestNormalizeDataGuard:
    def test_fields(self):
        data = {"enabled": True, "creditCardNumbers": True,
                "usSocialSecurityNumbers": False}
        result = _normalize_data_guard(data)
        assert result["enabled"] is True
        assert result["creditCardNumbers"] is True

    def test_empty_returns_empty_dict(self):
        assert _normalize_data_guard({}) == {}


class TestNormalizeIpIntelligence:
    def test_categories_extracted(self):
        data = {
            "enabled": True,
            "defaultAction": "accept",
            "ipIntelligenceCategories": [
                {"category": "Spam Sources", "alarm": True, "block": False, "defaultAction": "alarm"},
            ],
        }
        result = _normalize_ip_intelligence(data)
        assert result["enabled"] is True
        assert len(result["categories"]) == 1
        assert result["categories"][0]["name"] == "Spam Sources"


# ── PolicyFetcher.list_waf_policies ───────────────────────────────────────────

class TestListWafPolicies:
    def test_returns_items(self):
        client = MagicMock()
        client.get_all.return_value = [
            {"name": "P1", "fullPath": "/Common/P1", "id": "id1", "partition": "Common"},
        ]
        fetcher = PolicyFetcher(client)
        result = fetcher.list_waf_policies()
        assert len(result) == 1
        assert result[0]["name"] == "P1"

    def test_partition_filter(self):
        client = MagicMock()
        client.get_all.return_value = [
            {"name": "P1", "partition": "Common"},
            {"name": "P2", "partition": "Tenant"},
        ]
        fetcher = PolicyFetcher(client)
        result = fetcher.list_waf_policies(partitions=["Common"])
        assert len(result) == 1
        assert result[0]["name"] == "P1"


# ── PolicyFetcher.list_bot_profiles ───────────────────────────────────────────

class TestListBotProfiles:
    def test_returns_items(self):
        import requests as req
        client = MagicMock()
        client.get_all.return_value = [{"name": "BP1", "fullPath": "/Common/BP1"}]
        fetcher = PolicyFetcher(client)
        result = fetcher.list_bot_profiles()
        assert result[0]["name"] == "BP1"

    def test_404_returns_empty(self):
        import requests as req
        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 404
        client.get_all.side_effect = req.HTTPError(response=resp)
        fetcher = PolicyFetcher(client)
        result = fetcher.list_bot_profiles()
        assert result == []


# ── PolicyFetcher.fetch_waf_policy ────────────────────────────────────────────

class TestFetchWafPolicy:
    def _make_fetcher_with_mock(self):
        client = MagicMock()
        # general data
        client.get.return_value = {
            "enforcementMode": "blocking",
            "applicationLanguage": "utf-8",
            "active": True,
            "policyBuilder": {"learningMode": "automatic"},
        }
        # all paginated sub-resources return empty list
        client.get_all.return_value = []
        return PolicyFetcher(client), client

    def test_enforcement_mode_propagated(self):
        fetcher, _ = self._make_fetcher_with_mock()
        result = fetcher.fetch_waf_policy(_make_policy())
        assert result["general"]["enforcementMode"] == "blocking"
        assert result["enforcementMode"] == "blocking"

    def test_blocking_section_empty(self):
        fetcher, _ = self._make_fetcher_with_mock()
        result = fetcher.fetch_waf_policy(_make_policy())
        assert result["blocking"] == {}

    def test_required_keys_present(self):
        fetcher, _ = self._make_fetcher_with_mock()
        result = fetcher.fetch_waf_policy(_make_policy())
        for key in (
            "name", "fullPath", "id", "general", "blocking", "blocking-settings",
            "signature-sets", "attack-signatures", "urls", "filetypes", "parameters",
            "headers", "cookies", "methods", "whitelist-ips", "login-pages",
            "brute-force", "data-guard", "ip-intelligence", "policy-builder", "bot-defense",
        ):
            assert key in result, f"Missing key: {key}"

    def test_violations_normalized(self):
        client = MagicMock()
        client.get.return_value = {"enforcementMode": "blocking", "policyBuilder": {}}

        violations = [
            {"name": "VIRUS_DETECTED", "alarm": True, "block": True, "learn": False,
             "description": "Virus detected"},
        ]

        def fake_get_all(path, params=None):
            if "blocking-settings/violations" in path:
                return violations
            return []

        client.get_all.side_effect = fake_get_all
        fetcher = PolicyFetcher(client)
        result = fetcher.fetch_waf_policy(_make_policy())
        viols = result["blocking-settings"]["violations"]
        assert len(viols) == 1
        assert viols[0]["name"] == "VIRUS_DETECTED"
        assert viols[0]["block"] is True

    def test_learning_mode_from_policy_builder(self):
        client = MagicMock()
        client.get.return_value = {
            "enforcementMode": "transparent",
            "policyBuilder": {"learningMode": "automatic"},
        }
        client.get_all.return_value = []
        fetcher = PolicyFetcher(client)
        result = fetcher.fetch_waf_policy(_make_policy())
        assert result["policy-builder"]["learningMode"] == "automatic"
