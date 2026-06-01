"""
Virtual server inventory collection for WAF summary reporting.

Read-only guarantee:
This module performs GET requests only. It does not create, modify, or delete
BIG-IP configuration objects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Literal, Optional

from .bigip_client import BigIPClient
from .utils import get_logger, normalize_full_path, retry


@dataclass
class LtmPolicyRuleAttachment:
    rule_name: str
    host_conditions: List[str] = field(default_factory=list)
    waf_policy: Optional[str] = None


@dataclass
class LtmPolicyAttachment:
    name: str
    full_path: str
    rules: List[LtmPolicyRuleAttachment] = field(default_factory=list)


@dataclass
class VirtualServerRecord:
    name: str
    partition: str
    full_path: str
    destination: str
    http_profile: Optional[str]
    directly_attached_waf_policies: List[str] = field(default_factory=list)
    ltm_policies: List[LtmPolicyAttachment] = field(default_factory=list)
    waf_status: Literal["not_applicable", "capable", "enabled"] = "capable"


_LOG = get_logger("virtual_server_inventory")


def _partition_from_full_path(full_path: str) -> str:
    cleaned = str(full_path or "").strip().strip("/")
    if not cleaned:
        return "Common"
    return cleaned.split("/", 1)[0]


def _normalize_ref_to_full_path(ref: Any, default_partition: str = "Common") -> str:
    if isinstance(ref, dict):
        if ref.get("fullPath"):
            return normalize_full_path(str(ref.get("fullPath")), partition=default_partition)
        name = str(ref.get("name") or "").strip()
        part = str(ref.get("partition") or default_partition).strip() or default_partition
        if name:
            return normalize_full_path(name, partition=part)
        if ref.get("policy"):
            return _normalize_ref_to_full_path(ref.get("policy"), default_partition=default_partition)
        if ref.get("wamPolicy"):
            return _normalize_ref_to_full_path(ref.get("wamPolicy"), default_partition=default_partition)
        if ref.get("link"):
            return _normalize_ref_to_full_path(ref.get("link"), default_partition=default_partition)
        if ref.get("selfLink"):
            return _normalize_ref_to_full_path(ref.get("selfLink"), default_partition=default_partition)
        return ""

    text = str(ref or "").strip()
    if not text:
        return ""
    if text.startswith("~"):
        # ~Common~object -> /Common/object
        return "/" + text.strip("~").replace("~", "/")
    if text.startswith("/") and "/" in text.strip("/"):
        return text
    if "/mgmt/tm/" in text:
        # Keep unresolved links as-is so caller can still display raw values.
        return text
    return normalize_full_path(text, partition=default_partition)


def _extract_host_conditions(rule: Dict[str, Any]) -> List[str]:
    hosts: List[str] = []
    for cond in rule.get("conditionsReference", {}).get("items", []) or []:
        ctype = str(cond.get("type") or "").lower()
        if ctype == "httpheader" and str(cond.get("name") or "").lower() == "host":
            hosts.extend([str(v) for v in (cond.get("values") or []) if str(v).strip()])
        elif ctype == "httpuri" and cond.get("host"):
            hosts.extend([str(v) for v in (cond.get("values") or []) if str(v).strip()])
        elif ctype == "httphost":
            hosts.extend([str(v) for v in (cond.get("values") or []) if str(v).strip()])

    unique: List[str] = []
    seen = set()
    for h in hosts:
        if h not in seen:
            seen.add(h)
            unique.append(h)
    return unique


def _extract_direct_waf_reference_candidates(vs_item: Dict[str, Any]) -> List[Any]:
    """
    Collect potential direct ASM/AWAF policy references from a VS payload.

    BIG-IP versions expose these references in different keys/shapes. We collect
    broadly and resolve/refine in later normalization.
    """
    candidates: List[Any] = []
    for key in (
        "asmPolicy",
        "applicationSecurityPolicy",
        "securityPolicy",
        "securityPolicyReference",
        "policy",
        "policyReference",
    ):
        if key in vs_item:
            candidates.append(vs_item.get(key))

    return candidates


def _iter_nested_values(value: Any) -> Iterable[Any]:
    if value is None:
        return
    if isinstance(value, (str, int, float, bool)):
        yield value
        return
    if isinstance(value, list):
        for item in value:
            yield from _iter_nested_values(item)
        return
    if isinstance(value, dict):
        for k in ("fullPath", "name", "policy", "wamPolicy", "link", "selfLink", "id"):
            if k in value and value.get(k) not in (None, ""):
                yield value.get(k)
        for v in value.values():
            yield from _iter_nested_values(v)


def _build_asm_lookup(asm_payload: Dict[str, Any]) -> tuple[Dict[str, str], Dict[str, str]]:
    by_id: Dict[str, str] = {}
    by_self_link: Dict[str, str] = {}

    for item in asm_payload.get("items", []) or []:
        partition = str(item.get("partition") or "Common")
        name = str(item.get("name") or "").strip()
        full_path = str(item.get("fullPath") or "").strip()
        if not full_path and name:
            full_path = f"/{partition}/{name}"
        full_path = normalize_full_path(full_path, partition=partition) if full_path else ""
        if not full_path:
            continue

        policy_id = str(item.get("id") or "").strip()
        if policy_id:
            by_id[policy_id] = full_path

        self_link = str(item.get("selfLink") or "").strip()
        if self_link:
            by_self_link[self_link.split("?")[0]] = full_path

    return by_id, by_self_link


def _resolve_asm_reference(value: Any, asm_by_id: Dict[str, str], asm_by_self_link: Dict[str, str], default_partition: str = "Common") -> str:
    if isinstance(value, dict):
        if value.get("id") and str(value.get("id")) in asm_by_id:
            return asm_by_id[str(value.get("id"))]
        if value.get("selfLink"):
            sl = str(value.get("selfLink")).split("?")[0]
            if sl in asm_by_self_link:
                return asm_by_self_link[sl]
        return _normalize_ref_to_full_path(value, default_partition=default_partition)

    text = str(value or "").strip()
    if not text:
        return ""

    if text in asm_by_id:
        return asm_by_id[text]

    stripped_link = text.split("?")[0]
    if stripped_link in asm_by_self_link:
        return asm_by_self_link[stripped_link]

    if "/mgmt/tm/asm/policies/" in text:
        tail = text.split("/mgmt/tm/asm/policies/", 1)[1].split("?", 1)[0].strip("/")
        if tail in asm_by_id:
            return asm_by_id[tail]
        return text

    return _normalize_ref_to_full_path(text, default_partition=default_partition)


def _is_http_profile(profile_item: Dict[str, Any], http_profiles: set[str], vs_partition: str) -> Optional[str]:
    p_full = _normalize_ref_to_full_path(
        profile_item.get("fullPath") or {
            "name": profile_item.get("name"),
            "partition": profile_item.get("partition") or vs_partition,
        },
        default_partition=vs_partition,
    )
    if p_full and p_full in http_profiles:
        return p_full

    if str(profile_item.get("name") or "").strip().lower() == "http":
        return p_full or f"/{vs_partition}/http"

    p_type = str(profile_item.get("type") or "").lower()
    if p_type == "http":
        return p_full

    return None


@retry(max_attempts=3, base_delay=1.5)
def _collect_virtual_server_inventory_impl(
    bigip_client: BigIPClient,
    partitions: Optional[List[str]] = None,
    asm_policies_payload: Optional[Dict[str, Any]] = None,
) -> List[VirtualServerRecord]:
    partition_filter = {p.strip() for p in (partitions or []) if str(p).strip()}

    # GET-only iControl REST calls (read-only data collection).
    virtual_payload = bigip_client.get("/mgmt/tm/ltm/virtual", params={"expandSubcollections": "true"})
    http_profiles_payload = bigip_client.get("/mgmt/tm/ltm/profile/http")
    ltm_policies_payload = bigip_client.get("/mgmt/tm/ltm/policy", params={"expandSubcollections": "true"})
    # Reuse pre-fetched ASM payload from discover_policies() when available so
    # we avoid a duplicate call to /mgmt/tm/asm/policies.
    if asm_policies_payload is None:
        asm_policies_payload = bigip_client.get("/mgmt/tm/asm/policies")

    http_profile_paths: set[str] = set()
    for item in http_profiles_payload.get("items", []) or []:
        part = str(item.get("partition") or "Common")
        fp = _normalize_ref_to_full_path(item.get("fullPath") or {"name": item.get("name"), "partition": part}, default_partition=part)
        if fp:
            http_profile_paths.add(fp)

    asm_by_id, asm_by_self_link = _build_asm_lookup(asm_policies_payload)

    ltm_policy_map: Dict[str, Dict[str, Any]] = {}
    for item in ltm_policies_payload.get("items", []) or []:
        part = str(item.get("partition") or "Common")
        fp = _normalize_ref_to_full_path(item.get("fullPath") or {"name": item.get("name"), "partition": part}, default_partition=part)
        if fp:
            ltm_policy_map[fp] = item

    records: List[VirtualServerRecord] = []
    for vs in virtual_payload.get("items", []) or []:
        vs_name = str(vs.get("name") or "").strip()
        vs_partition = str(vs.get("partition") or "").strip()
        vs_full = str(vs.get("fullPath") or "").strip()

        if not vs_full and vs_name:
            vs_full = _normalize_ref_to_full_path({"name": vs_name, "partition": vs_partition or "Common"})
        vs_partition = vs_partition or _partition_from_full_path(vs_full)
        if partition_filter and vs_partition not in partition_filter:
            continue

        profiles = (vs.get("profilesReference") or {}).get("items", []) or []
        http_profile = None
        for profile in profiles:
            maybe_http = _is_http_profile(profile, http_profile_paths, vs_partition)
            if maybe_http:
                http_profile = maybe_http
                break

        direct_refs: List[str] = []
        for candidate in _extract_direct_waf_reference_candidates(vs):
            for nested in _iter_nested_values(candidate):
                resolved = _resolve_asm_reference(nested, asm_by_id, asm_by_self_link, default_partition=vs_partition)
                if not resolved:
                    continue
                if resolved.startswith("/mgmt/tm/ltm/"):
                    continue
                if "/mgmt/tm/asm/policies/" in resolved or resolved.startswith("/"):
                    direct_refs.append(resolved)

        # De-duplicate while preserving order.
        seen_direct = set()
        direct_policies: List[str] = []
        for ref in direct_refs:
            if ref not in seen_direct:
                seen_direct.add(ref)
                direct_policies.append(ref)

        ltm_attachments: List[LtmPolicyAttachment] = []
        for pref in ((vs.get("policiesReference") or {}).get("items", []) or []):
            ltm_ref = _normalize_ref_to_full_path(
                pref.get("fullPath") or {"name": pref.get("name"), "partition": pref.get("partition") or vs_partition},
                default_partition=vs_partition,
            )
            if not ltm_ref:
                continue
            ltm_pol = ltm_policy_map.get(ltm_ref)
            if not ltm_pol:
                continue

            rules: List[LtmPolicyRuleAttachment] = []
            for rule in (ltm_pol.get("rulesReference") or {}).get("items", []) or []:
                rule_name = str(rule.get("name") or "").strip() or "(unnamed rule)"
                waf_policy_ref: Optional[str] = None

                for action in (rule.get("actionsReference") or {}).get("items", []) or []:
                    atype = str(action.get("type") or "").lower()
                    if atype not in ("asm", "wam"):
                        continue
                    if not action.get("enable"):
                        continue
                    raw_pol = action.get("policy") or action.get("wamPolicy") or action.get("policyReference")
                    waf_policy_ref = _resolve_asm_reference(raw_pol, asm_by_id, asm_by_self_link, default_partition=vs_partition)
                    break

                if waf_policy_ref is None:
                    continue

                hosts = _extract_host_conditions(rule)
                if not hosts:
                    hosts = ["(any)"]

                rules.append(
                    LtmPolicyRuleAttachment(
                        rule_name=rule_name,
                        host_conditions=hosts,
                        waf_policy=waf_policy_ref,
                    )
                )

            if rules:
                ltm_attachments.append(
                    LtmPolicyAttachment(
                        name=str(ltm_pol.get("name") or ltm_ref.split("/")[-1]),
                        full_path=ltm_ref,
                        rules=rules,
                    )
                )

        if not http_profile:
            status: Literal["not_applicable", "capable", "enabled"] = "not_applicable"
        elif direct_policies or any(a.rules for a in ltm_attachments):
            status = "enabled"
        else:
            status = "capable"

        records.append(
            VirtualServerRecord(
                name=vs_name,
                partition=vs_partition,
                full_path=vs_full,
                destination=str(vs.get("destination") or "").strip() or "—",
                http_profile=http_profile,
                directly_attached_waf_policies=direct_policies,
                ltm_policies=ltm_attachments,
                waf_status=status,
            )
        )

    return sorted(records, key=lambda r: (r.partition.lower(), r.name.lower()))


def collect_virtual_server_inventory(
    bigip_client: BigIPClient,
    partitions: Optional[List[str]] = None,
    asm_policies_payload: Optional[Dict[str, Any]] = None,
) -> List[VirtualServerRecord]:
    """Collect inventory records for virtual servers and WAF association context.

    Pass ``asm_policies_payload`` (the raw response from a previous
    /mgmt/tm/asm/policies GET) to avoid a duplicate API call when the caller
    has already fetched that data (e.g. from PolicyExporter.discover_policies).

    This function is intentionally read-only and issues GET requests only.
    """
    _LOG.info("Collecting read-only virtual server inventory from BIG-IP")
    return _collect_virtual_server_inventory_impl(
        bigip_client=bigip_client,
        partitions=partitions,
        asm_policies_payload=asm_policies_payload,
    )


__all__ = [
    "LtmPolicyRuleAttachment",
    "LtmPolicyAttachment",
    "VirtualServerRecord",
    "collect_virtual_server_inventory",
]
