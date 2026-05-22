"""
Unit tests for src/policy_inspector.py
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.policy_inspector import (
    PolicyInspector,
    _normalize_learning_mode,
    _format_audit_entry,
    print_inspection_table,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_POLICY = {
    "id":        "abc123",
    "name":      "my_waf",
    "fullPath":  "/Common/my_waf",
    "partition": "Common",
}

_CORE_RESP = {
    "enforcementMode": "blocking",
    "policyBuilder":   {"learningMode": "automatic"},
}

_VIOLATIONS_RESP = {
    "items": [
        {"name": "VIOL_ATTACK_SIGNATURE",  "description": "Attack signature detected", "learn": True,  "alarm": True,  "block": True},
        {"name": "VIOL_COOKIE_NOT_BASE64", "description": "Cookie is not base64",       "learn": True,  "alarm": True,  "block": False},
        {"name": "VIOL_FILETYPE",          "description": "Illegal file type",           "learn": False, "alarm": True,  "block": True},
        {"name": "VIOL_PARAMETER_VALUE",   "description": "Illegal parameter value",     "learn": False, "alarm": False, "block": False},
    ]
}

_SIG_SETS_RESP = {
    "items": [
        {"name": "Generic Detection Signatures", "alarm": True,  "block": True,  "learn": False},
        {"name": "SQL Injection Signatures",      "alarm": True,  "block": False, "learn": True},
    ]
}

_AUDIT_RESP = {
    "items": [
        {"action": "modify", "username": "admin", "lastUpdateMicros": "1716214331000000", "entityName": "my_waf", "entityType": "security"},
        {"action": "create", "username": "bob",   "lastUpdateMicros": "1716200000000000", "entityName": "my_waf", "entityType": "policy"},
    ]
}


def _make_client(responses: dict) -> MagicMock:
    """Return a mock BigIPClient whose .get() dispatches on the longest matching path prefix."""
    client = MagicMock()
    # Sort by descending prefix length so more-specific paths win over shorter ones.
    sorted_prefixes = sorted(responses.keys(), key=len, reverse=True)

    def _get(path, params=None):
        for prefix in sorted_prefixes:
            if path.startswith(prefix):
                resp = responses[prefix]
                if callable(resp):
                    return resp(path, params)
                return resp
        raise AssertionError(f"Unexpected GET {path}")

    client.get.side_effect = _get
    return client


def _default_client() -> MagicMock:
    return _make_client({
        "/mgmt/tm/asm/policies/abc123":                   _CORE_RESP,
        "/mgmt/tm/asm/policies/abc123/blocking-settings": _VIOLATIONS_RESP,
        "/mgmt/tm/asm/policies/abc123/signature-sets":    _SIG_SETS_RESP,
        "/mgmt/tm/asm/audit":                             _AUDIT_RESP,
    })


# ---------------------------------------------------------------------------
# _normalize_learning_mode
# ---------------------------------------------------------------------------

class TestNormalizeLearningMode:
    def test_automatic(self):
        assert _normalize_learning_mode("automatic") == "automatic"

    def test_manual(self):
        assert _normalize_learning_mode("manual") == "manual"

    def test_disabled(self):
        assert _normalize_learning_mode("disabled") == "disabled"

    def test_off_maps_to_disabled(self):
        assert _normalize_learning_mode("off") == "disabled"

    def test_empty_string_maps_to_disabled(self):
        assert _normalize_learning_mode("") == "disabled"

    def test_none_maps_to_disabled(self):
        assert _normalize_learning_mode(None) == "disabled"

    def test_unknown_maps_to_disabled(self):
        assert _normalize_learning_mode("whatever") == "disabled"

    def test_case_insensitive(self):
        assert _normalize_learning_mode("AUTOMATIC") == "automatic"
        assert _normalize_learning_mode("Manual") == "manual"


# ---------------------------------------------------------------------------
# _format_audit_entry
# ---------------------------------------------------------------------------

class TestFormatAuditEntry:
    def test_timestamp_conversion(self):
        entry = _format_audit_entry({
            "action": "modify",
            "username": "admin",
            "lastUpdateMicros": "1716214331000000",
        })
        assert entry["timestamp"] == "2024-05-20T14:12:11Z"

    def test_zero_micros(self):
        entry = _format_audit_entry({"action": "x", "username": "y", "lastUpdateMicros": 0})
        assert entry["timestamp"] == "1970-01-01T00:00:00Z"

    def test_invalid_micros_returns_empty_string(self):
        entry = _format_audit_entry({"lastUpdateMicros": "not-a-number"})
        assert entry["timestamp"] == ""

    def test_action_and_username_preserved(self):
        entry = _format_audit_entry({
            "action": "create",
            "username": "alice",
            "lastUpdateMicros": 1_000_000,
        })
        assert entry["action"] == "create"
        assert entry["username"] == "alice"


# ---------------------------------------------------------------------------
# PolicyInspector._fetch_core
# ---------------------------------------------------------------------------

class TestFetchCore:
    def test_returns_enforcement_and_learning(self):
        inspector = PolicyInspector(_default_client())
        data, errors = inspector._fetch_core("abc123")
        assert data["enforcementMode"] == "blocking"
        assert data["learningMode"] == "automatic"
        assert errors == []

    def test_missing_policy_builder_yields_disabled(self):
        client = _make_client({
            "/mgmt/tm/asm/policies/abc123": {"enforcementMode": "transparent"},
        })
        inspector = PolicyInspector(client)
        data, errors = inspector._fetch_core("abc123")
        assert data["learningMode"] == "disabled"
        assert errors == []

    def test_dashed_variant_normalized(self):
        """BIG-IP 13.x may return policy-builder.learning-mode."""
        client = _make_client({
            "/mgmt/tm/asm/policies/abc123": {
                "enforcementMode": "blocking",
                "policy-builder": {"learning-mode": "manual"},
            },
        })
        inspector = PolicyInspector(client)
        data, errors = inspector._fetch_core("abc123")
        assert data["learningMode"] == "manual"

    def test_api_failure_returns_error(self):
        client = MagicMock()
        client.get.side_effect = Exception("timeout")
        inspector = PolicyInspector(client)
        data, errors = inspector._fetch_core("abc123")
        assert data == {}
        assert len(errors) == 1
        assert "core:" in errors[0]


# ---------------------------------------------------------------------------
# PolicyInspector._fetch_violations
# ---------------------------------------------------------------------------

class TestFetchViolations:
    def _inspector(self):
        return PolicyInspector(_default_client())

    def test_learn_group(self):
        inspector = self._inspector()
        result, errors = inspector._fetch_violations("abc123")
        learn_names = {v["name"] for v in result["learn"]}
        assert "VIOL_ATTACK_SIGNATURE" in learn_names
        assert "VIOL_COOKIE_NOT_BASE64" in learn_names
        assert "VIOL_FILETYPE" not in learn_names

    def test_alarm_group(self):
        inspector = self._inspector()
        result, errors = inspector._fetch_violations("abc123")
        alarm_names = {v["name"] for v in result["alarm"]}
        assert "VIOL_ATTACK_SIGNATURE" in alarm_names
        assert "VIOL_COOKIE_NOT_BASE64" in alarm_names
        assert "VIOL_FILETYPE" in alarm_names
        assert "VIOL_PARAMETER_VALUE" not in alarm_names

    def test_block_group(self):
        inspector = self._inspector()
        result, errors = inspector._fetch_violations("abc123")
        block_names = {v["name"] for v in result["block"]}
        assert "VIOL_ATTACK_SIGNATURE" in block_names
        assert "VIOL_FILETYPE" in block_names
        assert "VIOL_COOKIE_NOT_BASE64" not in block_names

    def test_violation_can_appear_in_multiple_groups(self):
        inspector = self._inspector()
        result, errors = inspector._fetch_violations("abc123")
        learn_names = {v["name"] for v in result["learn"]}
        alarm_names = {v["name"] for v in result["alarm"]}
        block_names = {v["name"] for v in result["block"]}
        assert "VIOL_ATTACK_SIGNATURE" in learn_names & alarm_names & block_names

    def test_violation_with_no_flags_not_in_any_group(self):
        inspector = self._inspector()
        result, errors = inspector._fetch_violations("abc123")
        all_names = (
            {v["name"] for v in result["learn"]}
            | {v["name"] for v in result["alarm"]}
            | {v["name"] for v in result["block"]}
        )
        assert "VIOL_PARAMETER_VALUE" not in all_names

    def test_api_failure_returns_empty_groups_and_error(self):
        client = MagicMock()
        client.get.side_effect = Exception("connection refused")
        inspector = PolicyInspector(client)
        result, errors = inspector._fetch_violations("abc123")
        assert result == {"learn": [], "alarm": [], "block": []}
        assert len(errors) == 1
        assert "violations:" in errors[0]

    def test_entry_has_name_and_description(self):
        inspector = self._inspector()
        result, errors = inspector._fetch_violations("abc123")
        entry = next(v for v in result["learn"] if v["name"] == "VIOL_ATTACK_SIGNATURE")
        assert entry["description"] == "Attack signature detected"


# ---------------------------------------------------------------------------
# PolicyInspector._fetch_signature_sets
# ---------------------------------------------------------------------------

class TestFetchSignatureSets:
    def test_sets_returned(self):
        inspector = PolicyInspector(_default_client())
        sets, errors = inspector._fetch_signature_sets("abc123")
        assert len(sets) == 2
        names = {s["name"] for s in sets}
        assert "Generic Detection Signatures" in names
        assert "SQL Injection Signatures" in names

    def test_boolean_fields(self):
        inspector = PolicyInspector(_default_client())
        sets, errors = inspector._fetch_signature_sets("abc123")
        generic = next(s for s in sets if s["name"] == "Generic Detection Signatures")
        assert generic["alarm"] is True
        assert generic["block"] is True
        assert generic["learn"] is False

    def test_name_resolved_from_reference_when_missing(self):
        client = _make_client({
            "/mgmt/tm/asm/policies/abc123/signature-sets": {
                "items": [
                    {
                        "name": "",
                        "alarm": True,
                        "block": True,
                        "learn": False,
                        "signatureSetReference": {
                            "link": "https://localhost/mgmt/tm/asm/signature-sets/generic-detection"
                        },
                    }
                ]
            },
        })
        inspector = PolicyInspector(client)
        sets, errors = inspector._fetch_signature_sets("abc123")
        assert sets[0]["name"] == "generic-detection"

    def test_api_failure_returns_empty_list_and_error(self):
        client = MagicMock()
        client.get.side_effect = Exception("forbidden")
        inspector = PolicyInspector(client)
        sets, errors = inspector._fetch_signature_sets("abc123")
        assert sets == []
        assert len(errors) == 1
        assert "signature-sets:" in errors[0]


# ---------------------------------------------------------------------------
# PolicyInspector._fetch_audit — filter path and fallback path
# ---------------------------------------------------------------------------

class TestFetchAudit:
    def test_primary_filter_path_returns_entries(self):
        inspector = PolicyInspector(_default_client())
        entries, errors = inspector._fetch_audit("my_waf")
        assert len(entries) == 2
        assert errors == []

    def test_timestamp_converted_in_entries(self):
        inspector = PolicyInspector(_default_client())
        entries, errors = inspector._fetch_audit("my_waf")
        assert entries[0]["timestamp"] == "2024-05-20T14:12:11Z"

    def test_fallback_path_when_filter_rejected(self):
        """When the $filter-based call raises, the fallback must be used."""
        call_count = 0

        def _get(path, params=None):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First call (with $filter) — simulate rejection
                raise Exception("400 Bad Request: unsupported filter")
            # Second call (fallback, no filter)
            return {
                "items": [
                    {
                        "action":             "modify",
                        "username":           "admin",
                        "lastUpdateMicros":   "1716214331000000",
                        "entityName":         "my_waf",
                        "entityType":         "security",
                    },
                    {
                        "action":             "create",
                        "username":           "other",
                        "lastUpdateMicros":   "1716200000000000",
                        "entityName":         "other_policy",
                        "entityType":         "security",
                    },
                ]
            }

        client = MagicMock()
        client.get.side_effect = _get
        inspector = PolicyInspector(client)
        entries, errors = inspector._fetch_audit("my_waf")

        # Client-side filter should keep only the my_waf entry
        assert len(entries) == 1
        assert entries[0]["username"] == "admin"
        assert errors == []

    def test_fallback_filters_by_entity_name(self):
        """Fallback must drop entries whose entityName != policy_name."""
        def _get(path, params=None):
            if params and "$filter" in params:
                raise Exception("not supported")
            return {
                "items": [
                    {"action": "x", "username": "u", "lastUpdateMicros": "1000000",
                     "entityName": "other", "entityType": "security"},
                    {"action": "y", "username": "v", "lastUpdateMicros": "2000000",
                     "entityName": "my_waf", "entityType": "policy"},
                ]
            }

        client = MagicMock()
        client.get.side_effect = _get
        inspector = PolicyInspector(client, audit_limit=10)
        entries, errors = inspector._fetch_audit("my_waf")
        assert len(entries) == 1
        assert entries[0]["username"] == "v"

    def test_both_paths_fail_yields_error(self):
        client = MagicMock()
        client.get.side_effect = Exception("network down")
        inspector = PolicyInspector(client)
        entries, errors = inspector._fetch_audit("my_waf")
        assert entries == []
        assert len(errors) == 1
        assert "audit:" in errors[0]

    def test_audit_limit_respected(self):
        many_items = [
            {
                "action": "modify", "username": "u",
                "lastUpdateMicros": str(i * 1_000_000),
                "entityName": "my_waf", "entityType": "security",
            }
            for i in range(20)
        ]
        client = _make_client({"/mgmt/tm/asm/audit": {"items": many_items}})
        inspector = PolicyInspector(client, audit_limit=5)
        entries, errors = inspector._fetch_audit("my_waf")
        assert len(entries) == 5


# ---------------------------------------------------------------------------
# PolicyInspector.inspect_one — integration of all sub-calls
# ---------------------------------------------------------------------------

class TestInspectOne:
    def test_full_happy_path(self):
        inspector = PolicyInspector(_default_client())
        result = inspector.inspect_one(_POLICY)

        assert result["name"] == "my_waf"
        assert result["fullPath"] == "/Common/my_waf"
        assert result["partition"] == "Common"
        assert result["enforcementMode"] == "blocking"
        assert result["learningMode"] == "automatic"
        assert isinstance(result["violations"]["learn"], list)
        assert isinstance(result["signatureSets"], list)
        assert isinstance(result["auditLog"], list)
        assert result["errors"] == []

    def test_partial_failure_recorded_in_errors(self):
        """One endpoint failing must not prevent the others from succeeding."""
        call_count = 0

        def _get(path, params=None):
            nonlocal call_count
            call_count += 1
            if "blocking-settings" in path:
                raise Exception("503 Service Unavailable")
            if path.startswith("/mgmt/tm/asm/policies/abc123") and "signature" not in path:
                return _CORE_RESP
            if "signature-sets" in path:
                return _SIG_SETS_RESP
            if "/mgmt/tm/asm/audit" in path:
                return _AUDIT_RESP
            raise AssertionError(f"Unexpected GET {path}")

        client = MagicMock()
        client.get.side_effect = _get
        inspector = PolicyInspector(client)
        result = inspector.inspect_one(_POLICY)

        assert len(result["errors"]) == 1
        assert "violations:" in result["errors"][0]
        # Other fields still populated
        assert result["enforcementMode"] == "blocking"
        assert len(result["signatureSets"]) == 2

    def test_schema_keys_always_present(self):
        """Even if all sub-calls fail, result must have all required keys."""
        client = MagicMock()
        client.get.side_effect = Exception("down")
        inspector = PolicyInspector(client)
        result = inspector.inspect_one(_POLICY)

        for key in ("name", "fullPath", "partition", "enforcementMode",
                    "learningMode", "violations", "signatureSets", "auditLog", "errors"):
            assert key in result


# ---------------------------------------------------------------------------
# PolicyInspector.inspect_all — concurrency + error isolation
# ---------------------------------------------------------------------------

class TestInspectAll:
    def test_returns_one_result_per_policy(self):
        policies = [
            {**_POLICY, "id": "p1", "name": "waf1", "fullPath": "/Common/waf1"},
            {**_POLICY, "id": "p2", "name": "waf2", "fullPath": "/Common/waf2"},
        ]
        # All GETs return empty/default responses
        client = _make_client({
            "/mgmt/tm/asm/policies/p1": _CORE_RESP,
            "/mgmt/tm/asm/policies/p2": _CORE_RESP,
            "/mgmt/tm/asm/audit": {"items": []},
        })

        def _get(path, params=None):
            for prefix, resp in {
                "/mgmt/tm/asm/policies/p1": _CORE_RESP,
                "/mgmt/tm/asm/policies/p2": _CORE_RESP,
            }.items():
                if path.startswith(prefix):
                    if "blocking-settings" in path or "signature-sets" in path:
                        return {"items": []}
                    return resp
            return {"items": []}

        client = MagicMock()
        client.get.side_effect = _get
        inspector = PolicyInspector(client, concurrent=2)
        results = inspector.inspect_all(policies)
        assert len(results) == 2

    def test_one_broken_policy_does_not_abort_run(self):
        """inspect_all must not raise even if inspect_one raises for one policy."""
        good_policy = {**_POLICY, "id": "good", "name": "good_waf", "fullPath": "/Common/good"}
        bad_policy  = {**_POLICY, "id": "bad",  "name": "bad_waf",  "fullPath": "/Common/bad"}

        original_inspect_one = PolicyInspector.inspect_one

        def _patched(self, policy):
            if policy["id"] == "bad":
                raise RuntimeError("catastrophic failure")
            return original_inspect_one(self, policy)

        with patch.object(PolicyInspector, "inspect_one", _patched):
            client = MagicMock()
            client.get.side_effect = lambda path, params=None: (
                _CORE_RESP if path.startswith("/mgmt/tm/asm/policies/good")
                else {"items": []}
            )
            inspector = PolicyInspector(client, concurrent=2)
            results = inspector.inspect_all([good_policy, bad_policy])

        assert len(results) == 2
        bad_result = next(r for r in results if r["fullPath"] == "/Common/bad")
        assert len(bad_result["errors"]) > 0
        assert "inspect_one raised:" in bad_result["errors"][0]
