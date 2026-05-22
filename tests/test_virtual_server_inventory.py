"""Tests for src.virtual_server_inventory."""

import json
from pathlib import Path

from src.virtual_server_inventory import collect_virtual_server_inventory


FIXTURES_DIR = Path(__file__).parent / "fixtures" / "virtual_servers"


class _FakeBigIPClient:
    def __init__(self, payload_map):
        self.payload_map = payload_map
        self.calls = []

    def get(self, path, params=None):
        self.calls.append((path, params))
        try:
            return self.payload_map[path]
        except KeyError as exc:
            raise AssertionError(f"Unexpected GET path in test: {path}") from exc


def _load_json(name: str):
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def test_collect_virtual_server_inventory_statuses_and_host_mappings():
    client = _FakeBigIPClient(
        {
            "/mgmt/tm/ltm/virtual": _load_json("ltm_virtuals_expand.json"),
            "/mgmt/tm/ltm/profile/http": _load_json("http_profiles.json"),
            "/mgmt/tm/ltm/policy": _load_json("ltm_policy_expand.json"),
            "/mgmt/tm/asm/policies": _load_json("asm_policies.json"),
        }
    )

    records = collect_virtual_server_inventory(client, partitions=["Common"])

    by_name = {r.name: r for r in records}

    assert by_name["vs_no_http"].waf_status == "not_applicable"
    assert by_name["vs_no_http"].http_profile is None

    assert by_name["vs_http_capable"].waf_status == "capable"
    assert by_name["vs_http_capable"].http_profile == "/Common/http"
    assert by_name["vs_http_capable"].directly_attached_waf_policies == []

    assert by_name["vs_direct_waf"].waf_status == "enabled"
    assert by_name["vs_direct_waf"].directly_attached_waf_policies == ["/Common/direct_waf"]

    host_vs = by_name["vs_ltm_host"]
    assert host_vs.waf_status == "enabled"
    assert host_vs.ltm_policies
    host_rule = host_vs.ltm_policies[0].rules[0]
    assert host_rule.rule_name == "route_api"
    assert host_rule.host_conditions == ["api.example.gov"]
    assert host_rule.waf_policy == "/Common/api_waf"

    any_vs = by_name["vs_ltm_any"]
    assert any_vs.waf_status == "enabled"
    any_rule = any_vs.ltm_policies[0].rules[0]
    assert any_rule.host_conditions == ["(any)"]
    assert any_rule.waf_policy == "/Common/any_waf"

    called_paths = [c[0] for c in client.calls]
    assert called_paths == [
        "/mgmt/tm/ltm/virtual",
        "/mgmt/tm/ltm/profile/http",
        "/mgmt/tm/ltm/policy",
        "/mgmt/tm/asm/policies",
    ]
