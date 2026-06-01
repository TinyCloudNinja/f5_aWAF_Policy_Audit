"""
Policy discovery and virtual server enrichment.

All operations are read-only against the BIG-IP device.
"""
from typing import Dict, List, Optional, Tuple

from .bigip_client import BigIPClient
from .utils import get_logger


def _parse_destination(destination: str) -> Tuple[str, str]:
    """
    Parse an F5 LTM virtual server destination string into (ip, port).

    F5 formats:
      /Common/10.1.1.1:80       →  ("10.1.1.1", "80")
      /Common/10.1.1.1:443      →  ("10.1.1.1", "443")
      /Common/2001:db8::1.443   →  ("2001:db8::1", "443")  IPv6 uses dot for port
      10.1.1.1:8080             →  ("10.1.1.1", "8080")
    """
    raw = destination
    # Strip leading partition component: /Common/10.0.0.1:80  →  10.0.0.1:80
    if raw.startswith('/'):
        stripped = raw.strip('/')
        parts = stripped.split('/', 1)
        raw = parts[1] if len(parts) == 2 else parts[0]

    # IPv6: multiple colons — F5 uses a trailing dot before the port
    if raw.count(':') > 1 and '.' in raw:
        last_dot = raw.rfind('.')
        return raw[:last_dot], raw[last_dot + 1:]

    # IPv4 / named address: single colon separates IP and port
    if ':' in raw:
        ip, _, port = raw.rpartition(':')
        return ip, port

    return raw, ""


def _extract_host_conditions(rule: Dict) -> List[str]:
    """
    Extract host-name values from an LTM policy rule's conditions.

    F5 BIG-IP uses several condition types to match the HTTP Host header:
      - httpHeader with name == "host"  (most common, all versions)
      - httpUri   with host == true     (URI component matching)
      - httpHost                        (dedicated type in newer BIG-IP versions)

    Returns a deduplicated, ordered list of host strings.
    """
    hosts: List[str] = []
    for cond in rule.get("conditionsReference", {}).get("items", []):
        ctype = cond.get("type", "").lower()
        if ctype == "httpheader" and cond.get("name", "").lower() == "host":
            hosts.extend(cond.get("values", []))
        elif ctype == "httpuri" and cond.get("host"):
            hosts.extend(cond.get("values", []))
        elif ctype == "httphost":
            hosts.extend(cond.get("values", []))
    # Deduplicate while preserving order
    seen: set = set()
    unique: List[str] = []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            unique.append(h)
    return unique


def _extract_waf_policy_action(rule: Dict) -> str:
    """
    Extract the WAF/ASM security policy path from an LTM policy rule's actions.

    F5 uses two action types for WAF association:
      - type "asm"  with a "policy" field        (BIG-IP 12.1+)
      - type "wam"  with a "wamPolicy" / "policy" field  (older versions)

    Returns the full path of the ASM policy (e.g. "/Common/my_waf") or "".
    """
    for action in rule.get("actionsReference", {}).get("items", []):
        atype = action.get("type", "").lower()
        if atype == "asm" and action.get("enable"):
            return action.get("policy", "")
        if atype == "wam" and action.get("enable"):
            return action.get("wamPolicy", "") or action.get("policy", "")
    return ""


class ExportError(Exception):
    pass


class PolicyExporter:
    """
    Discovers all ASM/AWAF policies across partitions and resolves their
    virtual server associations via direct iControl REST calls.
    """

    _PARTITION_EP  = "/mgmt/tm/auth/partition"
    # Single fetch covers both audit metadata and VS binding fields, eliminating
    # a previously separate call to /mgmt/tm/asm/policies?$select=…virtualServers….
    _POLICY_EP     = (
        "/mgmt/tm/asm/policies"
        "?$select=id,name,fullPath,active,enforcementMode,type,"
        "versionDatetime,hasParent,protocolIndependent,"
        "virtualServers,manualVirtualServers,selfLink"
    )
    _VIRTUAL_EP    = "/mgmt/tm/ltm/virtual"
    _LTM_POLICY_EP = "/mgmt/tm/ltm/policy"
    _SYS_GLOBAL_EP = "/mgmt/tm/sys/global-settings"

    def __init__(
        self,
        client: BigIPClient,
        partitions: Optional[List[str]] = None,
    ):
        self.client = client
        self.filter_partitions = [p.strip() for p in partitions] if partitions else []
        self.log = get_logger("policy_exporter")
        # Raw unfiltered API response stored after discover_policies() so that
        # virtual_server_inventory can reuse it without a duplicate fetch.
        self._raw_asm_payload: Optional[Dict] = None

    # ── Device information ──────────────────────────────────────────────────────

    def fetch_device_info(self) -> Dict:
        """
        Return basic identity information about the BIG-IP device.

        Queries ``/mgmt/tm/sys/global-settings`` for the configured hostname
        (the FQDN the administrator gave the device).  The management address
        is the ``host`` value already used to open the HTTPS connection —
        it may be an IP address or a DNS name depending on how the tool was
        invoked.

        Returns a dict with keys:
          hostname   — BIG-IP system hostname (from global-settings), or ""
          mgmt_ip    — the host/IP used to connect (from the client base URL)

        Failures are non-fatal: the hostname will be an empty string and the
        mgmt_ip will still be populated from the connection target.
        """
        mgmt_ip = self.client.base_url[len("https://"):] if self.client.base_url.startswith("https://") else self.client.base_url
        hostname = ""
        try:
            data = self.client.get(
                self._SYS_GLOBAL_EP,
                params={"$select": "hostname"},
            )
            hostname = data.get("hostname", "")
        except Exception as exc:
            self.log.debug("Could not fetch device hostname: %s", exc)
        return {"hostname": hostname, "mgmt_ip": mgmt_ip}

    # ── Discovery ──────────────────────────────────────────────────────────────

    def discover_partitions(self) -> List[str]:
        """Return all user partition names (always including 'Common')."""
        self.log.info("Discovering partitions …")
        try:
            data = self.client.get(self._PARTITION_EP)
            names = [item["name"] for item in data.get("items", [])]
        except Exception as exc:
            self.log.warning("Could not enumerate partitions (%s); defaulting to Common.", exc)
            names = []
        if "Common" not in names:
            names.insert(0, "Common")
        self.log.info("Found partitions: %s", names)
        return names

    def discover_policies(self, partitions: List[str]) -> List[Dict]:
        """Return a list of policy metadata dicts filtered by partition list.

        A single GET to _POLICY_EP fetches both the policy metadata and the
        virtualServers / manualVirtualServers binding fields, replacing what
        was previously two separate API calls.  The raw response is stored in
        ``self._raw_asm_payload`` so callers (e.g. virtual_server_inventory)
        can reuse it without issuing a duplicate request.

        Each returned dict includes private ``_virtualServers`` and
        ``_manualVirtualServers`` keys consumed by enrich_with_virtual_servers().
        """
        self.log.info("Enumerating ASM/AWAF policies …")
        try:
            data = self.client.get(self._POLICY_EP)
        except Exception as exc:
            raise ExportError(f"Failed to enumerate policies: {exc}") from exc

        # Store for sharing with virtual_server_inventory
        self._raw_asm_payload = data

        policies = []
        for item in data.get("items", []):
            full_path = item.get("fullPath", "")
            # Normalize path to always have /partition/name form
            if not full_path.startswith('/'):
                full_path = f"/Common/{full_path}"
                item["fullPath"] = full_path

            # Extract partition from fullPath
            parts = full_path.strip('/').split('/', 1)
            partition = parts[0] if len(parts) == 2 else "Common"
            item["partition"] = partition

            # Apply partition filter
            if self.filter_partitions and partition not in self.filter_partitions:
                continue

            if partition not in partitions:
                continue

            policies.append({
                "id":                    item.get("id", ""),
                "name":                  item.get("name", ""),
                "fullPath":              full_path,
                "partition":             partition,
                "active":                bool(item.get("active", False)),
                "enforcementMode":       item.get("enforcementMode", "transparent"),
                "type":                  item.get("type", "security"),
                "versionDatetime":       item.get("versionDatetime", ""),
                "selfLink":              item.get("selfLink", ""),
                # VS binding refs consumed by enrich_with_virtual_servers()
                "_virtualServers":       item.get("virtualServers", []),
                "_manualVirtualServers": item.get("manualVirtualServers", []),
            })

        self.log.info("Discovered %d ASM/AWAF policies.", len(policies))
        return policies

    def print_discovery_table(self, policies: List[Dict]) -> None:
        """Print a summary table of all discovered policies to stdout."""
        if not policies:
            print("No ASM/AWAF policies found.")
            return
        col_widths = {
            "fullPath":        max(len("Policy Full Path"),
                                   max(len(p["fullPath"]) for p in policies)),
            "partition":       max(len("Partition"),
                                   max(len(p["partition"]) for p in policies)),
            "enforcementMode": max(len("Enforcement"),
                                   max(len(p["enforcementMode"]) for p in policies)),
            "type":            max(len("Type"),
                                   max(len(p["type"]) for p in policies)),
        }
        sep = "-" * (
            col_widths["fullPath"] + col_widths["partition"] +
            col_widths["enforcementMode"] + col_widths["type"] + 24
        )
        fmt = (
            f"{{:<{col_widths['fullPath']+2}}}"
            f"{{:<{col_widths['partition']+2}}}"
            f"{{:<{col_widths['enforcementMode']+2}}}"
            f"{{:<{col_widths['type']+2}}}"
            f"{{:<8}}"
        )
        print("\n" + sep)
        print(fmt.format("Policy Full Path", "Partition", "Enforcement", "Type", "Active"))
        print(sep)
        for p in policies:
            print(fmt.format(
                p["fullPath"],
                p["partition"],
                p["enforcementMode"],
                p["type"],
                "Yes" if p["active"] else "No",
            ))
        print(sep)
        print(f"Total: {len(policies)} policies\n")

    # ── Virtual server enrichment ──────────────────────────────────────────────

    def enrich_with_virtual_servers(self, policies: List[Dict]) -> None:
        """
        Enrich each policy dict in-place with a ``virtual_servers`` list.

        VS binding references (``_virtualServers`` / ``_manualVirtualServers``)
        were fetched as part of discover_policies() in the same API call, so
        no additional policy-level API request is needed here.  Each reference
        is then resolved to a full VS detail dict via targeted GET calls.

        Each entry in ``virtual_servers`` is a dict with keys:
          name, fullPath, destination, ip, port, association_type, ltm_policies

        ``association_type`` is ``"direct"`` for ``virtualServers`` entries and
        ``"manual"`` for ``manualVirtualServers`` entries.
        """
        self.log.info("Resolving virtual server bindings for %d policies …", len(policies))
        for policy in policies:
            direct_refs = policy.pop("_virtualServers", [])
            manual_refs = policy.pop("_manualVirtualServers", [])
            policy["virtual_servers"] = self._resolve_vs_refs(
                direct_refs,
                manual_refs,
                policy.get("fullPath", ""),
            )

    def _resolve_vs_refs(
        self,
        direct_refs: List,
        manual_refs: List,
        policy_path: str,
    ) -> List[Dict]:
        """
        Resolve VS path references from ``virtualServers`` and
        ``manualVirtualServers`` to full VS detail dicts.

        Each ref may be a plain string path or a dict with a ``fullPath`` /
        ``name`` key — both formats appear across BIG-IP versions.

        Returns a deduplicated list of VS detail dicts, each extended with:
          association_type – ``"direct"``  (from ``virtualServers``)
                          – ``"manual"``  (from ``manualVirtualServers``)
        """
        results: List[Dict] = []
        seen: set = set()

        def _add(refs: List, assoc_type: str) -> None:
            for ref in refs:
                vs_path = (
                    ref if isinstance(ref, str)
                    else ref.get("fullPath") or ref.get("name", "")
                )
                if not vs_path or vs_path in seen:
                    continue
                seen.add(vs_path)
                vs_info = self._get_vs_destination(vs_path)
                if vs_info:
                    vs_info["association_type"] = assoc_type
                    results.append(vs_info)

        _add(direct_refs, "direct")
        _add(manual_refs, "manual")
        return results

    def _get_vs_destination(self, vs_full_path: str) -> Optional[Dict]:
        """
        GET a single LTM virtual server and return its name, fullPath,
        destination, ip, port, and any attached Local Traffic Policies.

        The path is tilde-encoded for the REST URL:
          /Common/my_vs  →  /mgmt/tm/ltm/virtual/~Common~my_vs
        """
        encoded = vs_full_path.strip("/").replace("/", "~")
        api_path = f"{self._VIRTUAL_EP}/~{encoded}"

        try:
            data = self.client.get(
                api_path,
                params={"$select": "name,fullPath,destination,partition"},
            )
        except Exception as exc:
            self.log.debug("Could not fetch VS %s: %s", vs_full_path, exc)
            return None

        destination = data.get("destination", "")
        ip, port = _parse_destination(destination)

        return {
            "name":        data.get("name", ""),
            "fullPath":    data.get("fullPath", vs_full_path),
            "destination": destination,
            "ip":          ip,
            "port":        port,
            "ltm_policies": self._get_vs_ltm_policies(api_path),
        }

    def _get_vs_ltm_policies(self, vs_api_path: str) -> List[Dict]:
        """
        Return the Local Traffic Policies attached to a virtual server.

        Calls GET {vs_api_path}/policies, then for each attached LTM policy
        fetches the full rule/condition/action tree so we can surface
        host-header → WAF-policy mappings.

        Returns a list of dicts, each with:
          name, fullPath, rules
        where each rule has:
          name, host_conditions (list of str), waf_policy (str or "")
        """
        try:
            data = self.client.get(f"{vs_api_path}/policies")
        except Exception as exc:
            self.log.debug("Could not fetch LTM policies for VS %s: %s", vs_api_path, exc)
            return []

        results = []
        for item in data.get("items", []):
            name = item.get("name", "")
            partition = item.get("partition", "Common")
            full_path = item.get("fullPath", f"/{partition}/{name}")
            rules = self._get_ltm_policy_rules(full_path)
            results.append({
                "name":     name,
                "fullPath": full_path,
                "rules":    rules,
            })

        return results

    def _get_ltm_policy_rules(self, policy_full_path: str) -> List[Dict]:
        """
        Fetch an LTM (Local Traffic Policy) with its rules, conditions, and
        actions expanded in a single API call.

        Parses each rule to extract:
          - host_conditions: host names matched by httpHeader/httpUri/httpHost
            conditions (the "selector" for which web application this rule applies to)
          - waf_policy: the ASM/WAF security policy path applied by the rule's
            action (empty string if no ASM action is present)

        Only rules that have at least one host condition or a WAF policy action
        are included in the returned list.

        Returns a list of dicts: {name, host_conditions, waf_policy}
        """
        encoded  = policy_full_path.strip("/").replace("/", "~")
        api_path = f"{self._LTM_POLICY_EP}/~{encoded}"

        try:
            data = self.client.get(api_path, params={"expandSubcollections": "true"})
        except Exception as exc:
            self.log.debug("Could not fetch LTM policy %s: %s", policy_full_path, exc)
            return []

        rules = []
        for rule in data.get("rulesReference", {}).get("items", []):
            host_conditions = _extract_host_conditions(rule)
            waf_policy      = _extract_waf_policy_action(rule)
            if host_conditions or waf_policy:
                rules.append({
                    "name":            rule.get("name", ""),
                    "host_conditions": host_conditions,
                    "waf_policy":      waf_policy,
                })

        return rules
