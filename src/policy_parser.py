"""
XML ASM/AWAF policy parser and normalizer.

Converts an F5 BIG-IP ASM XML export into a normalized Python dictionary
suitable for comparison.  Handles both namespaced and non-namespaced XML.
"""
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from lxml import etree as ET
    _LXML = True
except ImportError:
    import xml.etree.ElementTree as ET  # type: ignore
    _LXML = False

from .utils import get_logger

_log = get_logger("policy_parser")


# ── Namespace helpers ──────────────────────────────────────────────────────────

def _strip_ns(tag: str) -> str:
    """Remove XML namespace from a tag, e.g. '{http://...}name' → 'name'."""
    return re.sub(r'\{[^}]+\}', '', tag)


def _find(element, tag: str):
    """Find a child element ignoring XML namespaces."""
    # Direct match first
    child = element.find(tag)
    if child is not None:
        return child
    # Namespace-agnostic search
    for child in element:
        if _strip_ns(child.tag) == tag:
            return child
    return None


def _findall(element, tag: str) -> List:
    """Find all children with a given tag, ignoring XML namespaces."""
    results = element.findall(tag)
    if results:
        return results
    return [c for c in element if _strip_ns(c.tag) == tag]


def _text(element, tag: str, default: str = "") -> str:
    child = _find(element, tag)
    if child is not None and child.text:
        return child.text.strip()
    return default


def _bool(value: str) -> bool:
    return value.strip().lower() in ("true", "1", "yes", "enabled")


def _int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def _norm_bool(element, tag: str, default: bool = False) -> bool:
    child = _find(element, tag)
    if child is not None and child.text:
        return _bool(child.text)
    return default


def _item_as_bool(el, attr: str) -> bool:
    val = el.get(attr, "") or _text(el, attr)
    return _bool(val)


# ── Top-level parsers ──────────────────────────────────────────────────────────

def _parse_general(root) -> Dict:
    gen = _find(root, "general")
    if gen is None:
        return {}

    # F5 exports are inconsistent between dashed and underscored element names.
    # The general section typically uses <enforcement-mode>, but some exports
    # emit <enforcement_mode>. Read both and only fall back to "transparent"
    # when neither is present. This prevents masking a blocking policy as
    # transparent in reports.
    em_raw = _text(gen, "enforcement-mode") or _text(gen, "enforcement_mode")
    # Note: some exports spell this as <enforcement_mode> while others use
    # <enforcement-mode>. Capture both to avoid silently defaulting to
    # "transparent" when the underscore variant is present.
    enforcement_mode = (
        _text(gen, "enforcement-mode")
        or _text(gen, "enforcement_mode")
        or "transparent"
    )
    return {
        "enforcementMode":          enforcement_mode,
        "signatureStaging":         _norm_bool(gen, "signature-staging"),
        "placeholderSignatures":    _norm_bool(gen, "placeholder-signatures"),
        "responseLogging":          _text(gen, "response-logging", "none"),
        "trustXff":                 _norm_bool(gen, "trust-xff"),
        "allowedResponseCodes":     [
            _int(c.text)
            for c in _findall(gen, "allowed-response-code")
            if c.text
        ],
        "maskCreditCardNumbers":    _norm_bool(gen, "mask-credit-card-numbers"),
        "customXffHeaders":         [
            c.text.strip()
            for c in _findall(gen, "custom-xff-header")
            if c.text
        ],
        "enforcementReadinessPeriod": _int(_text(gen, "enforcement-readiness-period"), 7),
    }


def _parse_blocking_item(el) -> Dict:
    # enabled: check XML attribute first, then child element; default True if absent
    enabled_raw = el.get("enabled") or _text(el, "enabled")
    return {
        "name":    el.get("name") or _text(el, "name"),
        "enabled": _bool(enabled_raw) if enabled_raw else True,
        "alarm":   _item_as_bool(el, "alarm"),
        "block":   _item_as_bool(el, "block"),
        "learn":   _item_as_bool(el, "learn"),
    }


def _parse_blocking_settings(root) -> Dict:
    bs = _find(root, "blocking-settings")
    if bs is None:
        return {"violations": [], "evasions": [], "http-protocols": []}
    return {
        "violations":      [_parse_blocking_item(v) for v in _findall(bs, "violation")],
        "evasions":        [_parse_blocking_item(e) for e in _findall(bs, "evasion")],
        "http-protocols":  [_parse_blocking_item(h) for h in _findall(bs, "http-protocol")],
    }


def _parse_blocking_violation(el) -> Dict:
    """
    Parse a <violation> element from the newer <blocking> section format.

    In this format violations carry both a human-readable 'name' attribute and a
    machine-readable 'id' attribute (e.g. id="ILLEGAL_SOAP_ATTACHMENT").  The 'id'
    is the stable key used for comparison; 'name' is kept for display purposes.
    """
    pb_raw = _text(el, "policy_builder_tracking") or _text(el, "policy-builder-tracking")
    return {
        "id":                     el.get("id", ""),
        "name":                   el.get("name", "") or _text(el, "name"),
        "alarm":                  _item_as_bool(el, "alarm"),
        "block":                  _item_as_bool(el, "block"),
        "learn":                  _item_as_bool(el, "learn"),
        "policyBuilderTracking":  _bool(pb_raw) if pb_raw else False,
    }


def _parse_blocking(root) -> Dict:
    """
    Parse the newer <blocking> section exported by some F5 AWAF versions.

    Schema (abridged)::

        <blocking>
          <enforcement_mode>transparent|blocking</enforcement_mode>
          <passive_mode>enabled|disabled</passive_mode>
          <violation name="Human Name" id="MACHINE_ID">
            <alarm>true|false</alarm>
            <block>true|false</block>
            <learn>true|false</learn>
            <policy_builder_tracking>enabled|disabled</policy_builder_tracking>
          </violation>
          ...
        </blocking>

    Returns a dict with keys: enforcement_mode, passive_mode, violations (list).
    Returns an empty dict when the section is absent.
    """
    bl = _find(root, "blocking")
    if bl is None:
        return {}

    em_raw  = _text(bl, "enforcement_mode") or _text(bl, "enforcement-mode")
    pm_raw  = _text(bl, "passive_mode") or _text(bl, "passive-mode")

    return {
        "enforcement_mode": em_raw or "transparent",
        "passive_mode":     pm_raw or "disabled",
        "violations": [
            _parse_blocking_violation(v) for v in _findall(bl, "violation")
        ],
    }


def _parse_attack_signatures(root) -> List[Dict]:
    sigs_el = _find(root, "attack-signatures")
    if sigs_el is None:
        return []
    results = []
    for sig in _findall(sigs_el, "signature"):
        results.append({
            "signatureId":    _int(_text(sig, "signature-id") or sig.get("signature-id", "0")),
            "enabled":        _norm_bool(sig, "enabled", True),
            "performStaging": _norm_bool(sig, "perform-staging"),
            "inPolicy":       _norm_bool(sig, "in-policy", True),
        })
    return results


def _parse_signature_sets(root) -> List[Dict]:
    # Format 1 (iControl REST XML export): <signature-sets><signature-set>...
    sets_el = _find(root, "signature-sets")
    if sets_el is not None:
        results = []
        for ss in _findall(sets_el, "signature-set"):
            results.append({
                "name":             _text(ss, "name") or ss.get("name", ""),
                "alarm":            _norm_bool(ss, "alarm"),
                "block":            _norm_bool(ss, "block"),
                "learn":            _norm_bool(ss, "learn"),
                "signatureSetType": _text(ss, "type", "filter-based"),
            })
        return results

    # Format 2 (BIG-IP GUI / older XML export): <attack_signatures><signature_set>...
    # The set name lives in a <set name="..."> child attribute, not a <name> element.
    atk_el = _find(root, "attack_signatures")
    if atk_el is None:
        return []
    results = []
    for ss in _findall(atk_el, "signature_set"):
        set_el = _find(ss, "set")
        if set_el is None:
            continue
        name = set_el.get("name", "") or _text(set_el, "set_name", "")
        if not name:
            continue
        results.append({
            "name":             name,
            "alarm":            _norm_bool(ss, "alarm"),
            "block":            _norm_bool(ss, "block"),
            "learn":            _norm_bool(ss, "learn"),
            "signatureSetType": "filter-based",
        })
    return results


def _parse_urls(root) -> List[Dict]:
    urls_el = _find(root, "urls")
    if urls_el is None:
        return []
    results = []
    for url in _findall(urls_el, "url"):
        method_overrides = []
        mo_el = _find(url, "method-overrides")
        if mo_el is not None:
            for mo in _findall(mo_el, "method-override"):
                method_overrides.append({
                    "method":  _text(mo, "method"),
                    "allowed": _norm_bool(mo, "allowed"),
                })
        results.append({
            "name":                  _text(url, "name") or url.get("name", ""),
            "protocol":              _text(url, "protocol", "http"),
            "type":                  _text(url, "type", "explicit"),
            "isAllowed":             _norm_bool(url, "is-allowed", True),
            "attackSignaturesCheck": _norm_bool(url, "attack-signatures-check", True),
            "metacharsOnUrlCheck":   _norm_bool(url, "metachars-on-url-check", True),
            "methodOverrides":       method_overrides,
        })
    return results


def _parse_filetypes(root) -> List[Dict]:
    ft_el = _find(root, "filetypes")
    if ft_el is None:
        return []
    results = []
    for ft in _findall(ft_el, "filetype"):
        results.append({
            "name":           _text(ft, "name") or ft.get("name", ""),
            "allowed":        _norm_bool(ft, "allowed", True),
            "responseCheck":  _norm_bool(ft, "response-check"),
            "type":           _text(ft, "type", "explicit"),
        })
    return results


def _parse_parameters(root) -> List[Dict]:
    params_el = _find(root, "parameters")
    if params_el is None:
        return []
    results = []
    for param in _findall(params_el, "parameter"):
        results.append({
            "name":                  _text(param, "name") or param.get("name", ""),
            "type":                  _text(param, "type", "explicit"),
            "level":                 _text(param, "level", "global"),
            "parameterLocation":     _text(param, "parameter-location", "query"),
            "valueType":             _text(param, "value-type", "user-input"),
            "allowEmptyValue":       _norm_bool(param, "allow-empty-value"),
            "checkAttackSignatures": _norm_bool(param, "attack-signatures-check", True),
            "checkMetachars":        _norm_bool(param, "check-metachars", True),
            "sensitiveParameter":    _norm_bool(param, "sensitive"),
        })
    return results


def _parse_headers(root) -> List[Dict]:
    hdrs_el = _find(root, "headers")
    if hdrs_el is None:
        return []
    results = []
    for hdr in _findall(hdrs_el, "header"):
        results.append({
            "name":            _text(hdr, "name") or hdr.get("name", ""),
            "type":            _text(hdr, "type", "explicit"),
            "mandatory":       _norm_bool(hdr, "mandatory"),
            "checkSignatures": _norm_bool(hdr, "check-signatures", True),
        })
    return results


def _parse_cookies(root) -> List[Dict]:
    cookies_el = _find(root, "cookies")
    if cookies_el is None:
        return []
    results = []
    for ck in _findall(cookies_el, "cookie"):
        results.append({
            "name":                  _text(ck, "name") or ck.get("name", ""),
            "type":                  _text(ck, "type", "explicit"),
            "enforcementType":       _text(ck, "enforcement-type", "allow"),
            "insertSameSiteAttribute": _text(ck, "insert-same-site-attribute", "none"),
            "decodeValueAsBase64":   _text(ck, "decode-value-as-base64", "disabled"),
        })
    return results


def _parse_methods(root) -> List[Dict]:
    methods_el = _find(root, "methods")
    if methods_el is None:
        return []
    results = []
    for m in _findall(methods_el, "method"):
        results.append({
            "name":        _text(m, "name") or m.get("name", ""),
            "actAsMethod": _text(m, "act-as-method", ""),
        })
    return results


def _parse_http_protocols(root) -> List[Dict]:
    hp_el = _find(root, "http-protocols")
    if hp_el is None:
        return []
    results = []
    for hp in _findall(hp_el, "http-protocol"):
        results.append({
            "description": _text(hp, "description") or hp.get("description", ""),
            "enabled":     _norm_bool(hp, "enabled", True),
            "maxHeaders":  _int(_text(hp, "max-headers"), 0),
            "maxParams":   _int(_text(hp, "max-params"), 0),
        })
    return results


def _parse_evasions(root) -> List[Dict]:
    evasions_el = _find(root, "evasions")
    if evasions_el is None:
        return []
    results = []
    for ev in _findall(evasions_el, "evasion"):
        results.append({
            "description": _text(ev, "description") or ev.get("description", ""),
            "enabled":     _norm_bool(ev, "enabled", True),
        })
    return results


def _parse_data_guard(root) -> Dict:
    dg = _find(root, "data-guard")
    if dg is None:
        return {"enabled": False}
    patterns = [
        p.text.strip() for p in _findall(dg, "custom-pattern") if p.text
    ]
    enforcement_urls = [
        u.text.strip() for u in _findall(dg, "enforcement-url") if u.text
    ]
    return {
        "enabled":               _norm_bool(dg, "enabled"),
        "creditCardNumbers":     _norm_bool(dg, "credit-card-numbers"),
        "socialSecurityNumbers": _norm_bool(dg, "us-social-security-numbers"),
        "customPatterns":        patterns,
        "enforcementMode":       _text(dg, "enforcement-mode", "ignore-urls-in-list"),
        "enforcementUrls":       enforcement_urls,
    }


def _parse_brute_force(root) -> List[Dict]:
    bf_el = _find(root, "brute-force-attack-preventions")
    if bf_el is None:
        return []
    results = []
    for entry in _findall(bf_el, "brute-force-attack-prevention"):
        settings = {}
        settings_el = _find(entry, "brute-force-protection-settings")
        if settings_el is not None:
            for child in settings_el:
                settings[_strip_ns(child.tag)] = child.text.strip() if child.text else ""
        results.append({
            "urlName":          _text(entry, "url-name"),
            "maxLoginAttempts": _int(_text(entry, "max-login-attempts"), 0),
            "settings":         settings,
        })
    return results


def _parse_ip_intelligence(root) -> Dict:
    ip_el = _find(root, "ip-intelligence")
    if ip_el is None:
        return {"enabled": False, "categories": []}
    categories = []
    cats_el = _find(ip_el, "ip-intelligence-categories")
    if cats_el is not None:
        for cat in _findall(cats_el, "ip-intelligence-category"):
            categories.append({
                "name":  _text(cat, "category"),
                "alarm": _norm_bool(cat, "alarm"),
                "block": _norm_bool(cat, "block"),
            })
    return {
        "enabled":    _norm_bool(ip_el, "enabled"),
        "categories": categories,
    }


def _parse_bot_defense(root) -> Dict:
    bd = _find(root, "bot-defense")
    if bd is None:
        return {"enabled": False}
    result: Dict[str, Any] = {"enabled": _norm_bool(bd, "enabled")}
    ms_el = _find(bd, "mitigation-settings")
    if ms_el is not None:
        result["mitigationSettings"] = {
            _strip_ns(c.tag): c.text.strip() if c.text else ""
            for c in ms_el
        }
    bv_el = _find(bd, "browser-verification")
    if bv_el is not None:
        result["browserVerification"] = bv_el.text.strip() if bv_el.text else ""
    return result


def _parse_login_pages(root) -> List[Dict]:
    lp_el = _find(root, "login-pages")
    if lp_el is None:
        return []
    results = []
    for lp in _findall(lp_el, "login-page"):
        settings = {
            _strip_ns(c.tag): c.text.strip() if c.text else ""
            for c in lp
            if _strip_ns(c.tag) not in ("url", "authentication-type")
        }
        results.append({
            "url":                _text(lp, "url"),
            "authenticationType": _text(lp, "authentication-type", "none"),
            "settings":           settings,
        })
    return results


def _parse_pb_traffic_sources(el) -> Dict:
    """Parse untrusted/trusted sub-elements of track_site_changes or loosen_rule."""
    result: Dict[str, Any] = {}
    for src in ("untrusted", "trusted"):
        src_el = _find(el, src)
        if src_el is None:
            continue
        def _st(t, _e=src_el): return _text(_e, t) or _text(_e, t.replace("_", "-"))
        result[src] = {
            "enabled":         _norm_bool(src_el, "enabled", True),
            "distinctSources": _int(_st("distinct_sources"), 0),
            "minimumInterval": _int(_st("minimum_interval"), 0),
            "maximumInterval": _int(_st("maximum_interval"), 0),
        }
    return result


def _parse_pb_subsections(root) -> Dict:
    """Parse policy_builder_* sibling sections at the root level."""
    result: Dict[str, Any] = {}

    def _try(tag):
        el = _find(root, tag)
        return el if el is not None else _find(root, tag.replace("_", "-"))

    def _ut(el, tag):
        return _text(el, tag) or _text(el, tag.replace("_", "-"))

    def _ub(el, tag, default=False):
        ch = _find(el, tag)
        if ch is None:
            ch = _find(el, tag.replace("_", "-"))
        return _bool(ch.text) if ch is not None and ch.text else default

    pbc = _try("policy_builder_cookie")
    if pbc is not None:
        result["cookie"] = {
            "learnCookies":                  _ut(pbc, "learn_cookies"),
            "maximumAllowedModifiedCookies": _int(_ut(pbc, "maximum_allowed_modified_cookies"), 0),
            "collapseCookies":               _ub(pbc, "collapse_cookies"),
            "collapseCookiesOccurrences":    _int(_ut(pbc, "collapse_cookies_occurrences"), 0),
            "enforceUnmodifiedCookies":      _ub(pbc, "flg_enforce_unmodified_cookies"),
        }

    pbft = _try("policy_builder_filetype")
    if pbft is not None:
        result["filetype"] = {
            "learnFileTypes":  _ut(pbft, "learn_file_types"),
            "maximumFileTypes": _int(_ut(pbft, "maximum_file_types"), 0),
        }

    pbp = _try("policy_builder_parameter")
    if pbp is not None:
        result["parameter"] = {
            "learnParameters":               _ut(pbp, "learn_parameters"),
            "maximumParameters":             _int(_ut(pbp, "maximum_parameters"), 0),
            "parameterLevel":                _ut(pbp, "parameter_level"),
            "collapseParameters":            _ub(pbp, "collapse_parameters"),
            "collapseParametersOccurrences": _int(_ut(pbp, "collapse_parameters_occurrences"), 0),
            "classifyParameters":            _ub(pbp, "classify_parameters"),
        }

    pbu = _try("policy_builder_url")
    if pbu is not None:
        result["url"] = {
            "learnUrls":          _ut(pbu, "learn_urls"),
            "learnWebsocketUrls": _ut(pbu, "learn_websocket_urls"),
            "maximumUrls":        _int(_ut(pbu, "maximum_urls"), 0),
            "collapseUrls":       _ub(pbu, "collapse_urls"),
            "classifyUrls":       _ub(pbu, "classify_urls"),
        }

    pbh = _try("policy_builder_header")
    if pbh is not None:
        result["header"] = {
            "validHostNames": _ub(pbh, "valid_host_names"),
            "maximumHosts":   _int(_ut(pbh, "maximum_hosts"), 0),
        }

    pbrp = _try("policy_builder_redirection_protection")
    if pbrp is not None:
        result["redirectionProtection"] = {
            "learnRedirectionDomains":   _ut(pbrp, "learn_redirection_domains"),
            "maximumRedirectionDomains": _int(_ut(pbrp, "maximum_redirection_domains"), 0),
        }

    pbsl = _try("policy_builder_sessions_and_logins")
    if pbsl is not None:
        result["sessionsAndLogins"] = {
            "learnLoginPages": _ub(pbsl, "flg_learn_login_pages"),
        }

    pbst = _try("policy_builder_server_technologies")
    if pbst is not None:
        result["serverTechnologies"] = {
            "learnServerTechnologies": _ub(pbst, "learn_server_technologies"),
        }

    pbcc = _try("policy_builder_central_configuration")
    if pbcc is not None:
        result["centralConfiguration"] = {
            "buildingMode":         _ut(pbcc, "building_mode"),
            "eventCorrelationMode": _ut(pbcc, "event_correlation_mode"),
        }

    return result


def _parse_policy_builder(root) -> Dict:
    pb = _find(root, "policy_builder")
    if pb is None:
        pb = _find(root, "policy-builder")
    if pb is None:
        return {}

    def _u(tag: str, default: str = "") -> str:
        val = _text(pb, tag, "")
        return val if val else _text(pb, tag.replace("_", "-"), default)

    def _ub(tag: str, default: bool = False) -> bool:
        ch = _find(pb, tag)
        if ch is None:
            ch = _find(pb, tag.replace("_", "-"))
        return _bool(ch.text) if ch is not None and ch.text else default

    result: Dict[str, Any] = {
        "learningMode":                     _u("learning_mode", "disabled"),
        "clientSidePolicyBuilding":         _ub("client_side_policy_building"),
        "learnFromResponses":               _ub("learn_from_responses"),
        "learnInactiveEntities":            _ub("learn_inactive_entities"),
        "inactiveEntityInactivityDuration": _int(_u("inactive_entity_inactivity_duration_in_seconds"), 0),
        "enableFullPolicyInspection":       _ub("enable_full_policy_inspection"),
        "autoApplyFrequency":               _u("auto_apply_frequency"),
        "autoApplyStartTime":               _u("auto_apply_start_time"),
        "autoApplyEndTime":                 _u("auto_apply_end_time"),
        "applyOnAllDays":                   _ub("apply_on_all_days"),
        "applyAtAllTimes":                  _ub("apply_at_all_times"),
        "learnOnlyFromNonBotTraffic":       _ub("learn_only_from_non_bot_traffic"),
        "fullyAutomatic":                   _ub("fully_automatic"),
        "allTrustedIps":                    _u("all_trusted_ips"),
        "responseCodes": [
            c.text.strip()
            for c in pb
            if _strip_ns(c.tag) in ("response_code", "response-code") and c.text
        ],
    }

    tsc = _find(pb, "track_site_changes")
    if tsc is None:
        tsc = _find(pb, "track-site-changes")
    if tsc is not None:
        result["trackSiteChanges"] = _parse_pb_traffic_sources(tsc)

    lr = _find(pb, "loosen_rule")
    if lr is None:
        lr = _find(pb, "loosen-rule")
    if lr is not None:
        result["loosenRule"] = _parse_pb_traffic_sources(lr)

    tr = _find(pb, "tighten_rule")
    if tr is None:
        tr = _find(pb, "tighten-rule")
    if tr is not None:
        def _tu(t): return _text(tr, t) or _text(tr, t.replace("_", "-"))
        result["tightenRule"] = {
            "totalRequests":                  _int(_tu("total_requests"), 0),
            "minimumInterval":                _int(_tu("minimum_interval"), 0),
            "maxModificationSuggestionScore": _int(_tu("max_modification_suggestion_score"), 0),
        }

    result.update(_parse_pb_subsections(root))
    return result


def _parse_whitelist_ips(root) -> List[Dict]:
    wl_el = _find(root, "whitelist-ips")
    if wl_el is None:
        return []
    results = []
    for ip_el in _findall(wl_el, "whitelist-ip"):
        results.append({
            "ipAddress":            _text(ip_el, "ip-address") or ip_el.get("ip-address", ""),
            "ipMask":               _text(ip_el, "ip-mask") or ip_el.get("ip-mask", "255.255.255.255"),
            "trustedByPolicyBuilder": _norm_bool(ip_el, "trusted-by-policy-builder"),
            "ignoreAnomalies":      _norm_bool(ip_el, "ignore-anomalies"),
            "ignoreIpReputation":   _norm_bool(ip_el, "ignore-ip-reputation"),
        })
    return results


# ── Public API ─────────────────────────────────────────────────────────────────

def get_policy_metadata(xml_path: str) -> Dict:
    """Extract high-level metadata from the policy XML header."""
    path = Path(xml_path)
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {xml_path}")

    tree = _parse_tree(xml_path)
    root = tree.getroot()
    # Strip namespace from root tag if present
    if _strip_ns(root.tag) != "policy":
        # Some exports wrap in a <policies> element
        for child in root:
            if _strip_ns(child.tag) == "policy":
                root = child
                break

    return {
        "name":        _text(root, "name") or root.get("name", ""),
        "fullPath":    _text(root, "full-path") or root.get("fullPath", ""),
        "description": _text(root, "description"),
        "version":     root.get("version", ""),
        "createdAt":   _text(root, "created-at"),
        "updatedAt":   _text(root, "updated-at"),
    }


def parse_policy(xml_path: str) -> Dict:
    """
    Parse an F5 ASM XML policy export into a normalized Python dict.

    Returns a nested dictionary with keys matching each policy section.
    """
    _log.debug("Parsing policy XML: %s", xml_path)
    tree = _parse_tree(xml_path)
    root = tree.getroot()

    # Handle wrapping <policies> element
    if _strip_ns(root.tag) != "policy":
        for child in root:
            if _strip_ns(child.tag) == "policy":
                root = child
                break

    return {
        "general":             _parse_general(root),
        "blocking-settings":   _parse_blocking_settings(root),
        "blocking":            _parse_blocking(root),
        "attack-signatures":   _parse_attack_signatures(root),
        "signature-sets":      _parse_signature_sets(root),
        "urls":                _parse_urls(root),
        "filetypes":           _parse_filetypes(root),
        "parameters":          _parse_parameters(root),
        "headers":             _parse_headers(root),
        "cookies":             _parse_cookies(root),
        "methods":             _parse_methods(root),
        "http-protocols":      _parse_http_protocols(root),
        "evasions":            _parse_evasions(root),
        "data-guard":          _parse_data_guard(root),
        "brute-force":         _parse_brute_force(root),
        "ip-intelligence":     _parse_ip_intelligence(root),
        "bot-defense":         _parse_bot_defense(root),
        "login-pages":         _parse_login_pages(root),
        "policy-builder":      _parse_policy_builder(root),
        "whitelist-ips":       _parse_whitelist_ips(root),
    }


def _parse_tree(xml_path: str):
    """Parse XML file, handling encoding declarations robustly.

    Entity resolution and network access are explicitly disabled to prevent
    XML External Entity (XXE) attacks regardless of the lxml/stdlib backend.
    """
    path = Path(xml_path)
    if _LXML:
        # resolve_entities=False and no_network=True prevent XXE; recover=True
        # tolerates minor malformedness in F5 exports without expanding entities.
        parser = ET.XMLParser(
            recover=True,
            resolve_entities=False,
            no_network=True,
            encoding="utf-8",
        )
        try:
            return ET.parse(str(path), parser)
        except Exception:
            # Retry without the encoding hint (some exports declare their own)
            parser = ET.XMLParser(
                recover=True,
                resolve_entities=False,
                no_network=True,
            )
            return ET.parse(str(path), parser)
    else:
        # stdlib ElementTree does not process external entities by default.
        return ET.parse(str(path))
