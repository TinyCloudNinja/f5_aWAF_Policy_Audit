"""
Targeted REST-based ASM/AWAF policy inspector.

Fetches only what the reporting use-case needs (violations, learning mode,
signature sets, audit log, enforcement mode) via direct GET calls — no
export task, no XML download, no polling.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Tuple

from .bigip_client import BigIPClient
from .utils import get_logger


class PolicyInspector:
    """
    Inspect ASM/AWAF policies via targeted iControl REST calls.

    Each inspect_one() call issues four GETs concurrently-safe (no shared
    state mutated during a call).  inspect_all() fans out across policies
    using a ThreadPoolExecutor, mirroring PolicyExporter.export_all().
    """

    def __init__(
        self,
        client: BigIPClient,
        concurrent: int = 5,
        audit_limit: int = 10,
    ):
        self.client = client
        self.concurrent = concurrent
        self.audit_limit = audit_limit
        self.log = get_logger("policy_inspector")

    # ── Public API ─────────────────────────────────────────────────────────────

    def inspect_one(self, policy: Dict) -> Dict:
        """Return the inspection summary dict for a single policy.

        Never raises; any sub-call failure is recorded in result['errors'].
        """
        policy_id = policy.get("id", "")
        name      = policy.get("name", "")
        full_path = policy.get("fullPath", "")
        partition = policy.get("partition", "Common")

        result: Dict = {
            "name":            name,
            "fullPath":        full_path,
            "partition":       partition,
            "enforcementMode": "transparent",
            "learningMode":    "disabled",
            "violations":      {"learn": [], "alarm": [], "block": []},
            "signatureSets":   [],
            "auditLog":        [],
            "errors":          [],
        }

        core, errs = self._fetch_core(policy_id)
        result.update(core)
        result["errors"].extend(errs)

        violations, errs = self._fetch_violations(policy_id)
        result["violations"] = violations
        result["errors"].extend(errs)

        sig_sets, errs = self._fetch_signature_sets(policy_id)
        result["signatureSets"] = sig_sets
        result["errors"].extend(errs)

        audit, errs = self._fetch_audit(name)
        result["auditLog"] = audit
        result["errors"].extend(errs)

        return result

    def inspect_all(self, policies: List[Dict]) -> List[Dict]:
        """Thread-pool over inspect_one.

        A single broken policy never aborts the run; its result dict will
        have a non-empty 'errors' list.
        """
        results: List[Dict] = []
        total = len(policies)
        self.log.info("Inspecting %d policies (concurrency=%d) …", total, self.concurrent)

        with ThreadPoolExecutor(max_workers=self.concurrent) as pool:
            future_to_policy = {
                pool.submit(self.inspect_one, policy): policy
                for policy in policies
            }
            for future in as_completed(future_to_policy):
                policy = future_to_policy[future]
                try:
                    results.append(future.result())
                except Exception as exc:
                    self.log.error(
                        "Inspection FAILED for %s: %s", policy.get("fullPath"), exc
                    )
                    results.append({
                        "name":            policy.get("name", ""),
                        "fullPath":        policy.get("fullPath", ""),
                        "partition":       policy.get("partition", "Common"),
                        "enforcementMode": "transparent",
                        "learningMode":    "disabled",
                        "violations":      {"learn": [], "alarm": [], "block": []},
                        "signatureSets":   [],
                        "auditLog":        [],
                        "errors":          [f"inspect_one raised: {exc}"],
                    })

        return results

    # ── Private fetch helpers ──────────────────────────────────────────────────

    def _fetch_core(self, policy_id: str) -> Tuple[Dict, List[str]]:
        """GET core policy fields: enforcementMode + learningMode."""
        try:
            data = self.client.get(
                f"/mgmt/tm/asm/policies/{policy_id}",
                params={"$select": "name,fullPath,enforcementMode,policyBuilder"},
            )
        except Exception as exc:
            return {}, [f"core: {exc}"]

        enforcement = data.get("enforcementMode", "transparent")

        # Handle dashed vs camelCase field names across BIG-IP 13.x–17.x
        pb = (
            data.get("policyBuilder")
            or data.get("policy-builder")
            or {}
        )
        raw_mode = (
            pb.get("learningMode")
            or pb.get("learning-mode")
            or "disabled"
        )
        learning = _normalize_learning_mode(raw_mode)

        return {"enforcementMode": enforcement, "learningMode": learning}, []

    def _fetch_violations(self, policy_id: str) -> Tuple[Dict, List[str]]:
        """GET blocking-settings/violations and group by learn/alarm/block."""
        try:
            data = self.client.get(
                f"/mgmt/tm/asm/policies/{policy_id}/blocking-settings/violations",
                params={
                    "$select": "name,description,alarm,block,learn,sectionReference",
                    "$top":    "500",
                },
            )
        except Exception as exc:
            return {"learn": [], "alarm": [], "block": []}, [f"violations: {exc}"]

        learn: List[Dict] = []
        alarm: List[Dict] = []
        block: List[Dict] = []

        for item in data.get("items", []):
            # `name` is the canonical violation identifier (VIOL_*).
            # Fall back to the description if name is absent (older BIG-IP).
            viol_name = item.get("name", "")
            desc      = item.get("description", viol_name)
            entry     = {"description": desc, "name": viol_name or desc}

            if item.get("learn"):
                learn.append(entry)
            if item.get("alarm"):
                alarm.append(entry)
            if item.get("block"):
                block.append(entry)

        return {"learn": learn, "alarm": alarm, "block": block}, []

    def _fetch_signature_sets(self, policy_id: str) -> Tuple[List, List[str]]:
        """GET signature-sets applied to the policy."""
        try:
            data = self.client.get(
                f"/mgmt/tm/asm/policies/{policy_id}/signature-sets",
                params={"$select": "name,alarm,block,learn,signatureSetReference"},
            )
        except Exception as exc:
            return [], [f"signature-sets: {exc}"]

        sets: List[Dict] = []
        for item in data.get("items", []):
            name = item.get("name", "")
            # Some BIG-IP versions omit the name and put it in the reference link
            if not name:
                ref  = item.get("signatureSetReference") or {}
                link = ref.get("link", "") if isinstance(ref, dict) else ""
                name = link.rstrip("/").split("/")[-1] if link else ""

            sets.append({
                "name":  name,
                "alarm": bool(item.get("alarm", False)),
                "block": bool(item.get("block", False)),
                "learn": bool(item.get("learn", False)),
            })

        return sets, []

    def _fetch_audit(self, policy_name: str) -> Tuple[List, List[str]]:
        """GET audit-log entries for the policy, newest-first.

        Tries the server-side $filter first; falls back to client-side
        filtering on older BIG-IP versions that reject the $filter syntax.
        """
        items, error = self._audit_with_filter(policy_name)

        if error is not None:
            # Primary call failed — try the fallback
            self.log.debug(
                "Audit $filter rejected for '%s' (%s), falling back to client-side filter",
                policy_name, error,
            )
            items, fallback_error = self._audit_fallback(policy_name)
            if fallback_error is not None:
                return [], [f"audit: {fallback_error}"]

        return [_format_audit_entry(i) for i in items], []

    # ── Audit sub-helpers ──────────────────────────────────────────────────────

    def _audit_with_filter(
        self, policy_name: str
    ) -> Tuple[List, object]:
        """Return (items, None) on success or ([], error_string) on failure."""
        try:
            data = self.client.get(
                "/mgmt/tm/asm/audit",
                params={
                    "$filter":  f"entityName eq '{policy_name}'",
                    "$orderby": "lastUpdateMicros desc",
                    "$top":     str(self.audit_limit),
                    "$select":  "action,username,lastUpdateMicros,entityName,entityType",
                },
            )
            return data.get("items", [])[: self.audit_limit], None
        except Exception as exc:
            return [], str(exc)

    def _audit_fallback(
        self, policy_name: str
    ) -> Tuple[List, object]:
        """Client-side filter: fetch top-100, keep matching policy entries."""
        try:
            data = self.client.get(
                "/mgmt/tm/asm/audit",
                params={
                    "$orderby": "lastUpdateMicros desc",
                    "$top":     "100",
                    "$select":  "action,username,lastUpdateMicros,entityName,entityType",
                },
            )
        except Exception as exc:
            return [], str(exc)

        filtered = [
            i for i in data.get("items", [])
            if i.get("entityName") == policy_name
            and i.get("entityType", "").lower() in ("security", "policy", "security_policy")
        ]
        return filtered[: self.audit_limit], None


# ── Module-level helpers ───────────────────────────────────────────────────────

def _normalize_learning_mode(raw: str) -> str:
    """Normalize any BIG-IP learning-mode variant to automatic/manual/disabled."""
    if not raw:
        return "disabled"
    normalized = raw.strip().lower()
    if normalized in ("automatic", "manual", "disabled"):
        return normalized
    # BIG-IP 13.x may return "off" for disabled
    if normalized == "off":
        return "disabled"
    return "disabled"


def _format_audit_entry(item: Dict) -> Dict:
    """Convert a raw audit item to the output schema shape."""
    micros = item.get("lastUpdateMicros", 0)
    try:
        ts = datetime.utcfromtimestamp(int(micros) / 1_000_000).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    except (ValueError, TypeError, OSError):
        ts = ""
    return {
        "action":    item.get("action", ""),
        "username":  item.get("username", ""),
        "timestamp": ts,
    }


def print_inspection_table(results: List[Dict]) -> None:
    """Print a summary table of inspection results to stdout."""
    if not results:
        print("No policies inspected.")
        return

    def _vcount(r: Dict) -> str:
        v = r.get("violations", {})
        l = len(v.get("learn", []))
        a = len(v.get("alarm", []))
        b = len(v.get("block", []))
        return f"L:{l} A:{a} B:{b}"

    rows = [
        (
            r["fullPath"],
            r["partition"],
            r["enforcementMode"],
            r["learningMode"],
            _vcount(r),
            str(len(r.get("errors", []))),
        )
        for r in results
    ]

    headers = ("Policy Full Path", "Partition", "Enforcement", "Learning", "Violations", "Errors")
    widths = [
        max(len(headers[i]), max(len(row[i]) for row in rows))
        for i in range(len(headers))
    ]
    sep = "-" * (sum(widths) + len(widths) * 2 + 2)
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)

    print("\n" + sep)
    print(fmt.format(*headers))
    print(sep)
    for row in rows:
        print(fmt.format(*row))
    print(sep)
    print(f"Total: {len(results)} policies\n")
