"""
Full API-driven WAF policy and Bot Defense profile fetcher.

Replaces XML-export-based data collection with targeted iControl REST calls.
All sub-resources are fetched via paginated GET requests; no export tasks,
no file downloads.

Read-only guarantee: this module issues GET requests only.
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

import requests

from .bigip_client import BigIPClient
from .bot_defense_auditor import BotDefenseAuditor
from .utils import get_logger

_LOG = get_logger("policy_fetcher")

# Sub-resources fetched for every WAF policy.
# Each entry: (relative path suffix, $select fields)
# NOTE: blocking-settings/violations is fetched separately via client.get()
# because F5 ASM does not support OData $top/$skip/$select params on that
# bounded ~180-item collection — passing them returns a 400 error.
_WAF_SUB_RESOURCES: List[Tuple[str, Optional[str]]] = [
    ("blocking-settings/evasions",
     "description,enabled"),
    ("blocking-settings/http-protocols",
     "description,enabled"),
    ("blocking-settings/web-services-securities",
     "description,enabled"),
    ("signature-sets",
     "name,alarm,block,learn,signatureSetReference"),
    ("signatures",
     "enabled,performStaging,alarmState,signatureReference"),
    ("urls",
     "name,method,type,attackSignaturesCheck,performStaging,isAllowed"),
    ("filetypes",
     "name,type,queryStringLength,requestLength,responseCheck,attackSignaturesCheck"),
    ("parameters",
     "name,type,sensitiveParameter,attackSignaturesCheck,performStaging,valueType"),
    ("headers",
     "name,checkSignatures,mandatory,allowRepeatedOccurrences"),
    ("cookies",
     "name,enforcementType,attackSignaturesCheck,performStaging"),
    ("methods",
     "name,actAsMethod"),
    ("whitelist-ips",
     "ipAddress,ipMask,blockRequests,trustedByPolicyBuilder,ignoreAnomalies"),
    ("login-pages",
     "url,authenticationType,usernameParameterName"),
    ("brute-force-attack-preventions",
     "url,maximumLoginAttempts,preventionDuration"),
]

# Non-paginated endpoints (single-object or sub-resource collections too
# small to require pagination).
_WAF_SINGLE_ENDPOINTS = [
    "data-guard",
    "ip-intelligence",
    "session-tracking",
]


def _derive_name(item: Dict) -> str:
    """Return a stable machine-ID-style name for items that lack a 'name' field.

    Evasions and http-protocols expose a 'description' instead.  We upper-case
    and underscore-replace so the comparator's dict-key join works correctly.
    """
    name = str(item.get("name") or "").strip()
    if name:
        return name
    desc = str(item.get("description") or "").strip()
    return desc.upper().replace(" ", "_") if desc else ""


def _normalize_violations(items: List[Dict]) -> List[Dict]:
    """Normalize ASM blocking-settings/violations items.

    The canonical join key is ``name`` (machine ID, e.g. VIRUS_DETECTED).
    Some BIG-IP versions / $select projections return an empty ``name``; in
    that case we derive a stable key from ``description`` (upper-snake-cased)
    rather than dropping the violation — mirroring policy_inspector so that
    default-state violations are not silently lost.  Items with neither a
    name nor a description are skipped.
    """
    result: List[Dict] = []
    for v in items:
        name = str(v.get("name") or "").strip()
        desc = str(v.get("description") or "").strip()
        if not name and desc:
            name = desc.upper().replace(" ", "_")
        if not name:
            continue
        result.append({
            "name":        name,
            "description": desc or name,
            "alarm":       bool(v.get("alarm", False)),
            "block":       bool(v.get("block", False)),
            "learn":       bool(v.get("learn", False)),
        })
    return result


def _normalize_bool_items(items: List[Dict]) -> List[Dict]:
    """Normalize evasions / http-protocols / web-services-securities.

    These use 'description' as their identifier and 'enabled' as the flag.
    We add a 'name' field derived from 'description' so _cmp_blocking_settings
    can use it as the join key.
    """
    result = []
    for item in items:
        name = _derive_name(item)
        if not name:
            continue
        result.append({
            "name":        name,
            "description": str(item.get("description") or ""),
            "enabled":     bool(item.get("enabled", False)),
            # Mirror enabled→alarm/block/learn so the flag comparator works.
            "alarm":       bool(item.get("enabled", False)),
            "block":       bool(item.get("enabled", False)),
            "learn":       False,
        })
    return result


def _normalize_signature_sets(
    items: List[Dict],
    name_lookup: Optional[Dict[str, str]] = None,
) -> List[Dict]:
    """Normalize policy signature-set items.

    The policy sub-collection does not embed the human-readable set name; it
    only carries a ``signatureSetReference.link`` pointing to the global
    catalog entry.  When ``name_lookup`` (id→name from the global endpoint) is
    provided, we resolve the real name from there.  Without it we fall back to
    the bare hash ID from the link (better than nothing, but not readable).
    """
    result = []
    for item in items:
        name = str(item.get("name") or "").strip()
        if not name:
            ref = item.get("signatureSetReference") or {}
            link = ref.get("link", "") if isinstance(ref, dict) else ""
            if link:
                # Strip trailing slash, take last path segment, drop ?ver=... param
                raw = link.rstrip("/").split("/")[-1]
                sig_id = raw.split("?")[0]
                if name_lookup:
                    name = name_lookup.get(sig_id, "")
                if not name:
                    name = sig_id  # fallback to ID when lookup unavailable
        if not name:
            continue
        result.append({
            "name":  name,
            "alarm": bool(item.get("alarm", False)),
            "block": bool(item.get("block", False)),
            "learn": bool(item.get("learn", False)),
        })
    return result


def _normalize_attack_signatures(items: List[Dict]) -> List[Dict]:
    result = []
    for item in items:
        ref = item.get("signatureReference") or {}
        sig_name = ref.get("name", "") if isinstance(ref, dict) else ""
        sig_id = str(item.get("signatureId") or ref.get("signatureId") or "").strip()
        if not sig_id and not sig_name:
            continue
        result.append({
            "signatureId":     sig_id,
            "name":            sig_name,
            "enabled":         bool(item.get("enabled", True)),
            "performStaging":  bool(item.get("performStaging", False)),
            "alarmState":      str(item.get("alarmState") or ""),
        })
    return result


def _normalize_data_guard(data: Dict) -> Dict:
    if not data:
        return {}
    return {
        "enabled":              bool(data.get("enabled", False)),
        "creditCardNumbers":    bool(data.get("creditCardNumbers", False)),
        "usSocialSecurityNumbers": bool(data.get("usSocialSecurityNumbers", False)),
        "customPatterns":       data.get("customPatterns", []),
        "exceptionPatterns":    data.get("exceptionPatterns", []),
    }


def _normalize_ip_intelligence(data: Dict) -> Dict:
    if not data:
        return {}
    categories: List[Dict] = []
    for cat in data.get("ipIntelligenceCategories", []) or []:
        name = str(cat.get("category") or cat.get("name") or "").strip()
        if not name:
            continue
        categories.append({
            "name":          name,
            "defaultAction": str(cat.get("defaultAction") or ""),
            "alarm":         bool(cat.get("alarm", False)),
            "block":         bool(cat.get("block", False)),
        })
    return {
        "enabled":       bool(data.get("enabled", False)),
        "defaultAction": str(data.get("defaultAction") or ""),
        "categories":    categories,
    }


def _normalize_whitelist_ips(items: List[Dict]) -> List[Dict]:
    result = []
    for item in items:
        ip = str(item.get("ipAddress") or "").strip()
        mask = str(item.get("ipMask") or "").strip()
        if not ip:
            continue
        result.append({
            "ipAddress":            ip,
            "ipMask":               mask,
            "blockRequests":        str(item.get("blockRequests") or "never"),
            "trustedByPolicyBuilder": bool(item.get("trustedByPolicyBuilder", False)),
            "ignoreAnomalies":      bool(item.get("ignoreAnomalies", False)),
        })
    return result


class PolicyFetcher:
    """Full API-driven WAF policy and Bot Defense profile fetcher.

    Each ``fetch_waf_policy()`` call issues concurrent sub-resource GETs for
    one policy.  ``fetch_all_waf()`` fans out across policies using a thread
    pool (same pattern as PolicyInspector).
    """

    def __init__(self, client: BigIPClient, concurrent: int = 5):
        self.client = client
        self.concurrent = concurrent
        self.log = get_logger("policy_fetcher")
        # Lazily populated by _get_sig_set_names(); shared across all policy
        # fetches so the global catalog is only downloaded once per run.
        self._sig_set_name_cache: Optional[Dict[str, str]] = None
        self._sig_set_cache_lock = threading.Lock()

    def _get_sig_set_names(self) -> Dict[str, str]:
        """Return a {sig_set_id: human_name} dict, fetched once and cached.

        Thread-safe via double-checked locking — multiple concurrent
        fetch_waf_policy() calls share a single cached lookup.
        """
        if self._sig_set_name_cache is not None:
            return self._sig_set_name_cache
        with self._sig_set_cache_lock:
            if self._sig_set_name_cache is None:
                try:
                    items = self.client.get_all(
                        "/mgmt/tm/asm/signature-sets",
                        params={"$select": "id,name"},
                    )
                    self._sig_set_name_cache = {
                        item["id"]: item["name"]
                        for item in items
                        if item.get("id") and item.get("name")
                    }
                    self.log.debug(
                        "Cached %d global signature-set name(s)",
                        len(self._sig_set_name_cache),
                    )
                except Exception as exc:
                    self.log.warning(
                        "Could not fetch global signature-set names: %s", exc
                    )
                    self._sig_set_name_cache = {}
        return self._sig_set_name_cache

    # ── Discovery ──────────────────────────────────────────────────────────────

    def list_waf_policies(self, partitions: Optional[List[str]] = None) -> List[Dict]:
        """Return lightweight policy metadata: name, fullPath, id, enforcementMode, active."""
        items = self.client.get_all(
            "/mgmt/tm/asm/policies",
            params={"$select": "name,fullPath,id,enforcementMode,active,partition"},
        )
        if partitions:
            pset = {p.strip() for p in partitions}
            items = [i for i in items if i.get("partition", "Common") in pset]
        return items

    def list_bot_profiles(self, partitions: Optional[List[str]] = None) -> List[Dict]:
        """Return bot-defense profile metadata.  Returns [] if not licensed (404)."""
        try:
            items = self.client.get_all(
                "/mgmt/tm/security/bot-defense/profile",
                params={"$select": "name,fullPath,partition"},
            )
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                self.log.info(
                    "Bot Defense module not licensed or not provisioned (404). "
                    "Skipping bot profile discovery."
                )
                return []
            raise
        if partitions:
            pset = {p.strip() for p in partitions}
            items = [i for i in items if i.get("partition", "Common") in pset]
        return items

    # ── Full WAF policy fetch ──────────────────────────────────────────────────

    def fetch_waf_policy(self, policy: Dict) -> Dict:
        """Fetch all comparable WAF policy data and return a normalized dict.

        Parameters
        ----------
        policy:
            Metadata dict with at least ``id``, ``name``, and ``fullPath``.

        Returns
        -------
        Normalized dict compatible with ``policy_comparator.compare_policies()``.
        """
        policy_id = policy.get("id", "")
        base = f"/mgmt/tm/asm/policies/{policy_id}"

        # ── Fetch general policy fields ────────────────────────────────────────
        try:
            general_data = self.client.get(
                base,
                params={
                    "$select": (
                        "name,fullPath,enforcementMode,applicationLanguage,"
                        "active,signatureStaging,trustXff,responseLogging,"
                        "maskCreditCardNumbers,placeSignaturesInStaging"
                    )
                },
            )
        except Exception as exc:
            self.log.error("Failed to fetch general fields for %s: %s", policy_id, exc)
            general_data = {}

        enforcement_mode = str(
            general_data.get("enforcementMode") or policy.get("enforcementMode") or "transparent"
        )

        # ── Fetch paged sub-resources concurrently ────────────────────────────
        sub_data: Dict[str, Any] = {}
        with ThreadPoolExecutor(max_workers=self.concurrent) as pool:
            future_to_key = {
                pool.submit(
                    self.client.get_all,
                    f"{base}/{suffix}",
                    {"$select": fields} if fields else None,
                ): suffix
                for suffix, fields in _WAF_SUB_RESOURCES
            }
            for future in as_completed(future_to_key):
                key = future_to_key[future]
                try:
                    sub_data[key] = future.result()
                except Exception as exc:
                    self.log.warning("Sub-resource fetch failed (%s/%s): %s", policy_id, key, exc)
                    sub_data[key] = []

        # ── Fetch violations directly (F5 ASM doesn't support OData params here) ─
        # The blocking-settings/violations collection is a bounded ~180-item set.
        # Using get_all() with $top/$skip/$select causes a 400; use a plain GET.
        try:
            _viols_resp = self.client.get(f"{base}/blocking-settings/violations")
            violations_raw: List[Dict] = (
                _viols_resp.get("items", [])
                if isinstance(_viols_resp, dict)
                else []
            )
            self.log.debug(
                "Fetched %d raw violation(s) for %s", len(violations_raw), policy_id
            )
        except Exception as exc:
            self.log.warning("violations fetch failed (%s): %s", policy_id, exc)
            violations_raw = []

        # ── Fetch non-paginated single-object endpoints ────────────────────────
        single_data: Dict[str, Any] = {}
        with ThreadPoolExecutor(max_workers=self.concurrent) as pool:
            future_to_ep = {
                pool.submit(self.client.get, f"{base}/{ep}"): ep
                for ep in _WAF_SINGLE_ENDPOINTS
            }
            for future in as_completed(future_to_ep):
                ep = future_to_ep[future]
                try:
                    single_data[ep] = future.result()
                except Exception as exc:
                    self.log.debug("Single endpoint fetch skipped (%s/%s): %s", policy_id, ep, exc)
                    single_data[ep] = {}

        # ── Fetch policy-builder (learningMode) ───────────────────────────────
        try:
            pb_data = self.client.get(
                base,
                params={"$select": "policyBuilder"},
            )
            pb = pb_data.get("policyBuilder") or pb_data.get("policy-builder") or {}
            learning_mode = str(
                pb.get("learningMode") or pb.get("learning-mode") or "disabled"
            )
        except Exception:
            learning_mode = "disabled"

        # ── Resolve signature-set names from global catalog ───────────────────
        # The policy's /signature-sets sub-collection carries only a hash ID
        # in signatureSetReference.link; the human-readable name lives in the
        # global /mgmt/tm/asm/signature-sets endpoint.
        sig_set_names = self._get_sig_set_names()

        # ── Normalize and return ───────────────────────────────────────────────
        return {
            # Top-level metadata
            "name":                  str(general_data.get("name") or policy.get("name") or ""),
            "fullPath":              str(general_data.get("fullPath") or policy.get("fullPath") or ""),
            "id":                    policy_id,
            "enforcementMode":       enforcement_mode,
            "applicationLanguage":   str(general_data.get("applicationLanguage") or ""),
            "active":                bool(general_data.get("active", policy.get("active", False))),
            "signatureStaging":      bool(general_data.get("signatureStaging", False)),
            "trustXff":              bool(general_data.get("trustXff", False)),
            "responseLogging":       str(general_data.get("responseLogging") or ""),
            "maskCreditCardNumbers": bool(general_data.get("maskCreditCardNumbers", False)),
            # Comparator-facing sections
            "general": {
                "enforcementMode":   enforcement_mode,
                "applicationLanguage": str(general_data.get("applicationLanguage") or ""),
                "signatureStaging":  bool(general_data.get("signatureStaging", False)),
            },
            "blocking": {},  # left empty; comparator skips when both sides empty
            "blocking-settings": {
                "violations":               _normalize_violations(violations_raw),
                "evasions":                 _normalize_bool_items(
                    sub_data.get("blocking-settings/evasions", [])
                ),
                "http-protocols":           _normalize_bool_items(
                    sub_data.get("blocking-settings/http-protocols", [])
                ),
                "web-services-securities":  _normalize_bool_items(
                    sub_data.get("blocking-settings/web-services-securities", [])
                ),
            },
            "signature-sets":   _normalize_signature_sets(
                sub_data.get("signature-sets", []),
                name_lookup=sig_set_names,
            ),
            "attack-signatures": _normalize_attack_signatures(
                sub_data.get("signatures", [])
            ),
            "urls":       sub_data.get("urls", []),
            "filetypes":  sub_data.get("filetypes", []),
            "parameters": sub_data.get("parameters", []),
            "headers":    sub_data.get("headers", []),
            "cookies":    sub_data.get("cookies", []),
            "methods":    sub_data.get("methods", []),
            "whitelist-ips": _normalize_whitelist_ips(
                sub_data.get("whitelist-ips", [])
            ),
            "login-pages": sub_data.get("login-pages", []),
            "brute-force": sub_data.get("brute-force-attack-preventions", []),
            "data-guard":  _normalize_data_guard(single_data.get("data-guard", {})),
            "ip-intelligence": _normalize_ip_intelligence(
                single_data.get("ip-intelligence", {})
            ),
            "policy-builder": {"learningMode": learning_mode},
            "bot-defense":    {},  # WAF policies don't embed bot-defense settings
        }

    def fetch_all_waf(
        self, policies: List[Dict]
    ) -> Tuple[List[Tuple[Dict, Dict]], List[Tuple[Dict, str]]]:
        """Fan-out fetch_waf_policy across all policies using a thread pool.

        Returns
        -------
        (successes, failures)
            successes: list of (policy_meta, policy_data) tuples
            failures:  list of (policy_meta, error_message) tuples
        """
        successes: List[Tuple[Dict, Dict]] = []
        failures: List[Tuple[Dict, str]] = []
        total = len(policies)
        self.log.info("Fetching %d WAF policies (concurrency=%d) …", total, self.concurrent)

        with ThreadPoolExecutor(max_workers=self.concurrent) as pool:
            future_to_policy = {
                pool.submit(self.fetch_waf_policy, policy): policy
                for policy in policies
            }
            for future in as_completed(future_to_policy):
                policy = future_to_policy[future]
                try:
                    successes.append((policy, future.result()))
                except Exception as exc:
                    self.log.error(
                        "Fetch FAILED for %s: %s", policy.get("fullPath"), exc
                    )
                    failures.append((policy, str(exc)))

        return successes, failures

    # ── Bot Defense fetch ──────────────────────────────────────────────────────

    def fetch_bot_profile(self, profile: Dict) -> Dict:
        """Fetch a Bot Defense profile and return its normalized data dict.

        Delegates to ``BotDefenseAuditor.fetch_profile()`` which already
        implements the full reference-expansion logic.
        """
        auditor = BotDefenseAuditor(client=self.client, output_dir="/tmp", partitions=None)
        return auditor.fetch_profile(profile)


__all__ = ["PolicyFetcher"]
