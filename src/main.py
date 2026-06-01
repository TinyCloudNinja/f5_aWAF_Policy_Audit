"""
CLI entry point for the F5 BIG-IP ASM/AWAF Security Policy Auditor.

Changelog: Updated CLI for tiered compliance model with fail-on-tier exit codes,
backward-compatible --pass-threshold (Green boundary), and tier-aware summary output.
"""

import argparse
import getpass
import json
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from .utils import (
    setup_logging,
    get_logger,
    ensure_dir,
    iso_timestamp,
    TIER_RED,
    TIER_AMBER,
    TIER_YELLOW,
    TIER_GREEN,
)
from .bigip_client import BigIPClient, AuthenticationError
from .policy_exporter import PolicyExporter, ExportError
from .policy_inspector import PolicyInspector, print_inspection_table
from .policy_parser import parse_policy
from .policy_comparator import compare_policies
from .bot_defense_auditor import BotDefenseAuditor
from .bot_defense_comparator import compare_bot_profiles
from .report_generator import (
    generate_html_dashboard,
    generate_markdown,
    generate_summary_reports,
    generate_virtual_server_summary_markdown,
)
from .gitlab_state import GitLabStateManager
from .virtual_server_inventory import collect_virtual_server_inventory

import urllib3


_DEFAULT_PASS_THRESHOLD = 90.0  # Green lower bound for backward compatibility
_DEFAULT_FAIL_ON_TIER = TIER_RED
_REPO_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_OUTPUT_DIR = str((_REPO_ROOT.parent / f"{_REPO_ROOT.name}_output").resolve())
_DEFAULT_GITLAB_LOCAL_DIR = str((_REPO_ROOT.parent / f"{_REPO_ROOT.name}_policy_state_repo").resolve())

_TIER_RANK = {
    TIER_RED: 0,
    TIER_AMBER: 1,
    TIER_YELLOW: 2,
    TIER_GREEN: 3,
}

_TIER_EMOJI = {
    TIER_RED: "🔴",
    TIER_AMBER: "🟠",
    TIER_YELLOW: "🟡",
    TIER_GREEN: "🟢",
}


# ── Config loading ─────────────────────────────────────────────────────────────

def _load_config(path: Optional[str]) -> dict:
    if path and Path(path).exists():
        with open(path, encoding='utf-8') as fh:
            if Path(path).suffix == ".yaml":
                return yaml.safe_load(fh) or {}
            elif Path(path).suffix == ".json":
                return json.load(fh) or {}
    return {}


def _resolve(cli_val, env_var: str, config_val, default=None):
    """Precedence: CLI → env → config → default."""
    if cli_val is not None:
        return cli_val
    env_val = os.environ.get(env_var)
    if env_val is not None:
        return env_val
    if config_val is not None:
        return config_val
    return default


# ── Argument parsing ───────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="f5-awaf-auditor",
        description=(
            "F5 BIG-IP Security Auditor — Read-only compliance audit of WAF policies "
            "or Bot Defense profiles against a baseline.\n\n"
            "Audit modes (mutually exclusive):\n"
            "  --WAF   Audit ASM/AWAF security policies against an XML baseline (default)\n"
            "  --BOT   Audit Bot Defense profiles against a JSON baseline"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Audit mode selection
    mode_group = p.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--WAF", dest="audit_mode", action="store_const", const="waf",
        help="Audit ASM/AWAF security policies (default mode)",
    )
    mode_group.add_argument(
        "--BOT", dest="audit_mode", action="store_const", const="bot",
        help="Audit Bot Defense profiles against a JSON baseline",
    )
    mode_group.add_argument(
        "--INSPECT", dest="audit_mode", action="store_const", const="inspect",
        help=(
            "Inspect ASM/AWAF policies via targeted REST calls (no export task). "
            "Emits <output-dir>/inspection.json. Does not require --baseline."
        ),
    )

    # Tiered scoring controls
    p.add_argument(
        "--pass-threshold",
        dest="pass_threshold",
        type=float,
        default=None,
        metavar="N",
        help=(
            "Backward-compatible Green lower bound (default: 90). "
            "Only shifts the Yellow/Green boundary; other bands remain fixed."
        ),
    )
    p.add_argument(
        "--fail-on-tier",
        dest="fail_on_tier",
        choices=["RED", "AMBER", "YELLOW", "GREEN", "red", "amber", "yellow", "green"],
        default=None,
        help=(
            "Tier that triggers a non-zero exit code. "
            "RED (default) fails on any Red policy; AMBER fails on Amber or worse, etc."
        ),
    )

    p.add_argument("--config", metavar="FILE",
                   help="Path to YAML config file (default: config.yaml)")
    p.add_argument("--host", metavar="HOST",
                   help="BIG-IP management IP or FQDN [env: BIGIP_HOST]")
    p.add_argument("--username", metavar="USER",
                   help="Admin username [env: BIGIP_USER]")
    # NOTE: --password is intentionally absent. Supply credentials via the
    # BIGIP_PASS environment variable or the interactive prompt to avoid
    # exposing the password in the process table (ps aux).
    p.add_argument("--baseline", metavar="FILE",
                   help=(
                       "Path to baseline file. "
                       "XML for --WAF mode; JSON for --BOT mode."
                   ))
    p.add_argument("--output-dir", metavar="DIR", default=None,
                   help=f"Output directory for exports and reports (default: {_DEFAULT_OUTPUT_DIR})")
    p.add_argument("--format", dest="report_format",
                   choices=["html", "markdown", "both"], default=None,
                   help="Report format (default: both)")
    p.add_argument("--partitions", metavar="P1,P2",
                   help="Comma-separated partition names to audit (default: all)")
    p.add_argument("--verify-ssl", dest="verify_ssl", action="store_true",
                   default=None, help="Enable TLS certificate verification (default)")
    p.add_argument("--no-verify-ssl", dest="verify_ssl", action="store_false",
                   help="Disable TLS certificate verification (for self-signed certs)")
    p.add_argument("--login-provider", dest="login_provider", metavar="PROVIDER",
                   default=None,
                   help="BIG-IP login provider name [env: BIGIP_LOGIN_PROVIDER] (default: tmos)")
    p.add_argument("--concurrent-exports", dest="concurrent_exports",
                   type=int, default=None, metavar="N",
                   help="Max parallel inspection workers, 1–20 (default: 3)")
    p.add_argument("--gitlab-repo-url", dest="gitlab_repo_url", metavar="URL",
                   default=None,
                   help="GitLab repo URL used as source-of-truth + run archive")
    p.add_argument("--gitlab-local-dir", dest="gitlab_local_dir", metavar="DIR",
                   default=None,
                   help="Local clone path for the GitLab policy-state repository")
    p.add_argument("--gitlab-branch", dest="gitlab_branch", metavar="BRANCH",
                   default=None,
                   help="Git branch for the policy-state repository (default: main)")
    p.add_argument("--gitlab-auto-push", dest="gitlab_auto_push", action="store_true",
                   default=None,
                   help="Push policy-state commits to remote automatically")
    p.add_argument("--no-gitlab-auto-push", dest="gitlab_auto_push", action="store_false",
                   help="Do not push commits to remote automatically")
    p.add_argument("--gitlab-update-source-truth", dest="gitlab_update_source_truth", action="store_true",
                   default=None,
                   help="Update source_of_truth files in the GitLab repo from current device exports")
    p.add_argument("--no-gitlab-update-source-truth", dest="gitlab_update_source_truth", action="store_false",
                   help="Do not update source_of_truth files from current exports")
    p.add_argument("-v", "--verbose", action="store_true", default=False,
                   help="Enable debug logging")
    return p


# ── Validation helpers ─────────────────────────────────────────────────────────

def _validate_xml(path: str) -> None:
    """Abort with a clear message if the file is not valid XML."""
    try:
        ET.parse(path)
    except ET.ParseError as exc:
        sys.exit(f"ERROR: Baseline policy '{path}' is not valid XML: {exc}")


def _load_json_baseline(path: str) -> Optional[dict]:
    """
    Load and return a JSON baseline file.

    Returns the parsed dict on success, or None (with an error printed to
    stderr) if the file cannot be read or is not valid JSON.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        print(f"ERROR: Baseline file '{path}' is not valid JSON: {exc}", file=sys.stderr)
        return None
    except OSError as exc:
        print(f"ERROR: Cannot read baseline file '{path}': {exc}", file=sys.stderr)
        return None


def _inspector_to_target_dict(inspection: Dict) -> Dict:
    """Convert PolicyInspector results to the dict format expected by compare_policies.

    Only sections coverable via targeted REST calls (enforcement mode, violations,
    signature sets, learning mode) are populated.  All other sections are set to
    empty values so the comparator does not generate false-positive findings for
    data that was never fetched.
    """
    # Merge per-flag violation lists back into a single list with boolean flags.
    # The inspector groups violations as learn/alarm/block; the comparator expects
    # each violation once with all three flags set appropriately.
    merged_violations: Dict[str, Dict] = {}
    for flag in ("learn", "alarm", "block"):
        for item in inspection.get("violations", {}).get(flag, []):
            name = item.get("name", "")
            if not name:
                continue
            if name not in merged_violations:
                merged_violations[name] = {
                    "name":        name,
                    "description": item.get("description", ""),
                    "alarm":       False,
                    "block":       False,
                    "learn":       False,
                }
            merged_violations[name][flag] = True

    return {
        "general":           {"enforcementMode": inspection.get("enforcementMode", "transparent")},
        "blocking-settings": {
            "violations":     list(merged_violations.values()),
            "evasions":       [],
            "http-protocols": [],
        },
        "signature-sets": [
            {
                "name":  s.get("name", ""),
                "alarm": bool(s.get("alarm")),
                "block": bool(s.get("block")),
                "learn": bool(s.get("learn")),
            }
            for s in inspection.get("signatureSets", [])
        ],
        "policy-builder":   {"learningMode": inspection.get("learningMode", "disabled")},
        # Sections not reachable via inspector REST calls — kept empty to suppress
        # false-positive diffs against the baseline.
        "blocking":          {},
        "attack-signatures": [],
        "urls":              [],
        "filetypes":         [],
        "parameters":        [],
        "headers":           [],
        "cookies":           [],
        "methods":           [],
        "http-protocols":    [],
        "evasions":          [],
        "data-guard":        {},
        "brute-force":       [],
        "ip-intelligence":   {},
        "bot-defense":       {},
        "login-pages":       [],
        "whitelist-ips":     [],
    }


def _reduce_baseline_for_inspector(baseline_data: Dict) -> Dict:
    """Return a baseline dict limited to sections that the inspector can fetch.

    Sections the inspector does not cover are set to empty values so that the
    comparator only diffs what both sides actually have, preventing false-positive
    findings for things like custom URLs, parameters, and data-guard settings.
    """
    return {
        "general":           {"enforcementMode": baseline_data.get("general", {}).get("enforcementMode", "transparent")},
        "blocking-settings": {
            "violations":     baseline_data.get("blocking-settings", {}).get("violations", []),
            "evasions":       [],
            "http-protocols": [],
        },
        "signature-sets":    baseline_data.get("signature-sets", []),
        "policy-builder":    {"learningMode": baseline_data.get("policy-builder", {}).get("learningMode", "disabled")},
        "blocking":          {},
        "attack-signatures": [],
        "urls":              [],
        "filetypes":         [],
        "parameters":        [],
        "headers":           [],
        "cookies":           [],
        "methods":           [],
        "http-protocols":    [],
        "evasions":          [],
        "data-guard":        {},
        "brute-force":       [],
        "ip-intelligence":   {},
        "bot-defense":       {},
        "login-pages":       [],
        "whitelist-ips":     [],
    }


# ── Main workflow ──────────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Audit mode: waf (default) or bot
    audit_mode: str = args.audit_mode or "waf"

    # Load config file
    config_path = args.config or "config.yaml"
    raw_cfg = _load_config(config_path)
    bigip_cfg = raw_cfg.get("bigip", {})
    audit_cfg = raw_cfg.get("audit", {})
    gitlab_cfg = raw_cfg.get("gitlab", {})

    # Resolve parameters
    host     = _resolve(args.host,     "BIGIP_HOST", bigip_cfg.get("host"))
    username = _resolve(args.username, "BIGIP_USER", bigip_cfg.get("username"))
    # Password must come from the environment or an interactive prompt.
    # Accepting it from the config file would encourage storing plaintext
    # credentials on disk.  BIGIP_PASS env var is still permitted (e.g. CI).
    if bigip_cfg.get("password"):
        print(
            "ERROR: 'password' in the config file is not supported. "
            "Use the BIGIP_PASS environment variable or the interactive prompt.",
            file=sys.stderr,
        )
        return 2
    password = os.environ.get("BIGIP_PASS")
    login_provider = _resolve(
        args.login_provider, "BIGIP_LOGIN_PROVIDER",
        bigip_cfg.get("login_provider"), "tmos"
    )
    baseline = _resolve(args.baseline, "BASELINE_POLICY", audit_cfg.get("baseline_policy"))
    output_dir = _resolve(args.output_dir, "OUTPUT_DIR",
                          audit_cfg.get("output_dir"), _DEFAULT_OUTPUT_DIR)
    report_format = _resolve(args.report_format, "REPORT_FORMAT",
                             audit_cfg.get("report_format"), "both")

    # SSL verification defaults to False; This alleviates issues when the BIG-IPs use self-signed certificates
    _raw_ssl = _resolve(args.verify_ssl, "VERIFY_SSL", bigip_cfg.get("verify_ssl"), False)
    if isinstance(_raw_ssl, str):
        verify_ssl = _raw_ssl.lower() in ("0", "false", "no")
    else:
        verify_ssl = bool(_raw_ssl)
    concurrent = _resolve(args.concurrent_exports, "CONCURRENT_EXPORTS",
                          audit_cfg.get("concurrent_exports"), 3)
    partitions_str = _resolve(args.partitions, "PARTITIONS",
                              None, "")
    if partitions_str:
        partitions = [p.strip() for p in partitions_str.split(',') if p.strip()]
    else:
        partitions = audit_cfg.get("partitions") or []

    verbose = args.verbose

    # Tier thresholds
    pass_threshold = _resolve(
        args.pass_threshold, "PASS_THRESHOLD", audit_cfg.get("pass_threshold"), _DEFAULT_PASS_THRESHOLD
    )
    fail_on_tier = _resolve(
        args.fail_on_tier, "FAIL_ON_TIER", audit_cfg.get("fail_on_tier"), _DEFAULT_FAIL_ON_TIER
    )
    try:
        pass_threshold = float(pass_threshold)
    except (TypeError, ValueError):
        print("ERROR: --pass-threshold must be a number.")
        return 2
    fail_on_tier = str(fail_on_tier).upper()
    if fail_on_tier not in _TIER_RANK:
        print("ERROR: --fail-on-tier must be one of RED, AMBER, YELLOW, GREEN.")
        return 2

    # GitLab-backed policy state settings
    gitlab_repo_url = _resolve(
        args.gitlab_repo_url,
        "GITLAB_REPO_URL",
        gitlab_cfg.get("repo_url"),
    )
    gitlab_local_dir = _resolve(
        args.gitlab_local_dir,
        "GITLAB_LOCAL_DIR",
        gitlab_cfg.get("local_dir"),
        _DEFAULT_GITLAB_LOCAL_DIR,
    )
    gitlab_branch = _resolve(
        args.gitlab_branch,
        "GITLAB_BRANCH",
        gitlab_cfg.get("branch"),
        "main",
    )
    _raw_gitlab_auto_push = _resolve(
        args.gitlab_auto_push,
        "GITLAB_AUTO_PUSH",
        gitlab_cfg.get("auto_push"),
        False,
    )
    _raw_gitlab_update_sot = _resolve(
        args.gitlab_update_source_truth,
        "GITLAB_UPDATE_SOURCE_TRUTH",
        gitlab_cfg.get("update_source_truth"),
        False,
    )
    if isinstance(_raw_gitlab_auto_push, str):
        gitlab_auto_push = _raw_gitlab_auto_push.lower() in ("1", "true", "yes")
    else:
        gitlab_auto_push = bool(_raw_gitlab_auto_push)
    if isinstance(_raw_gitlab_update_sot, str):
        gitlab_update_source_truth = _raw_gitlab_update_sot.lower() in ("1", "true", "yes")
    else:
        gitlab_update_source_truth = bool(_raw_gitlab_update_sot)

    # Setup logging first
    ensure_dir(output_dir)
    log = setup_logging(verbose, output_dir, audit_mode)
    logger = get_logger("main")

    # Validate required arguments (--baseline not required for --INSPECT)
    missing = []
    if not host:
        missing.append("--host / BIGIP_HOST")
    if not username:
        missing.append("--username / BIGIP_USER")
    if audit_mode != "inspect" and not baseline:
        missing.append("--baseline")
    if missing:
        parser.print_usage()
        print(f"\nERROR: Missing required arguments: {', '.join(missing)}")
        return 2

    logger.info("Audit mode: %s", audit_mode.upper())

    # Optional GitLab state manager
    gitlab_state: Optional[GitLabStateManager] = None
    if gitlab_repo_url:
        gitlab_state = GitLabStateManager(
            repo_url=gitlab_repo_url,
            local_dir=str(Path(gitlab_local_dir).resolve()),
            branch=gitlab_branch,
            auto_push=gitlab_auto_push,
        )
        synced = gitlab_state.sync_from_remote()
        if synced:
            logger.info(
                "GitLab policy state enabled (branch=%s, local_dir=%s)",
                gitlab_branch,
                Path(gitlab_local_dir).resolve(),
            )
        else:
            logger.warning("GitLab policy state repo unavailable; continuing without source-of-truth sync.")
            gitlab_state = None

    # Validate concurrent_exports range
    try:
        concurrent = int(concurrent)
    except (TypeError, ValueError):
        print("ERROR: --concurrent-exports must be an integer between 1 and 20.")
        return 2
    if not 1 <= concurrent <= 20:
        print(f"ERROR: --concurrent-exports must be between 1 and 20 (got {concurrent}).")
        return 2

    # Password prompt if needed
    if not password:
        try:
            print(f"Please provide the password for device: {host}.")
            password = getpass.getpass(f"Password for user '{username}': ")
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            return 2

    # Validate baseline
    baseline = str(Path(baseline).resolve())
    if not Path(baseline).exists():
        logger.error("Baseline file not found: %s", baseline)
        return 2

    if audit_mode == "bot":
        logger.info("Validating baseline JSON …")
        baseline_data = _load_json_baseline(baseline)
        if baseline_data is None:
            return 1
        baseline_name = Path(baseline).name
    else:
        logger.info("Validating baseline XML …")
        _validate_xml(baseline)

    # SSL warning — loud enough to be noticed when the user opts out of verification
    if not verify_ssl:
        logger.warning(
            "SSL verification is DISABLED (--no-verify-ssl). "
            "Only use this for self-signed certificates in trusted environments. "
            "Remove --no-verify-ssl and supply a valid CA bundle in production."
        )
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Determine report formats
    formats: List[str] = []
    if report_format == "both":
        formats = ["html", "markdown"]
    else:
        formats = [report_format]

    # ── Connect & authenticate ─────────────────────────────────────────────────
    logger.info("Connecting to BIG-IP at %s …", host)
    client = BigIPClient(
        host=host,
        username=username,
        password=password,
        verify_ssl=verify_ssl,
        verbose=verbose,
        login_provider=login_provider,
    )
    try:
        client.authenticate()
    except AuthenticationError as exc:
        logger.error("Authentication failed: %s", exc)
        return 2
    except Exception as exc:
        logger.error("Cannot connect to BIG-IP: %s", exc)
        return 2
    logger.info("Authenticated successfully.")

    # ── Fetch device identity ─────────────────────────────────────────────────
    exporter = PolicyExporter(
        client=client,
        partitions=partitions if partitions else None,
    )
    device_info = exporter.fetch_device_info()
    device_hostname = device_info["hostname"]
    device_mgmt_ip  = device_info["mgmt_ip"]
    logger.info(
        "Device: hostname=%s  mgmt=%s",
        device_hostname or "(unknown)", device_mgmt_ip,
    )

    # ── Discover partitions ───────────────────────────────────────────────────
    try:
        all_partitions = exporter.discover_partitions()
    except Exception as exc:
        logger.error("Partition discovery failed: %s", exc)
        client.close()
        return 2

    # ── Branch: inspect / WAF audit / Bot Defense audit ──────────────────────
    if audit_mode == "inspect":
        return _run_inspect_audit(
            client=client,
            exporter=exporter,
            all_partitions=all_partitions,
            output_dir=output_dir,
            concurrent=concurrent,
            device_hostname=device_hostname,
            device_mgmt_ip=device_mgmt_ip,
            logger=logger,
        )
    elif audit_mode == "bot":
        return _run_bot_audit(
            client=client,
            all_partitions=all_partitions,
            baseline_data=baseline_data,
            baseline_name=baseline_name,
            output_dir=output_dir,
            formats=formats,
            partitions=partitions,
            device_hostname=device_hostname,
            device_mgmt_ip=device_mgmt_ip,
            gitlab_state=gitlab_state,
            gitlab_update_source_truth=gitlab_update_source_truth,
            logger=logger,
            fail_on_tier=fail_on_tier,
            pass_threshold=pass_threshold,
        )
    else:
        return _run_waf_audit(
            client=client,
            exporter=exporter,
            all_partitions=all_partitions,
            baseline=baseline,
            output_dir=output_dir,
            formats=formats,
            device_hostname=device_hostname,
            device_mgmt_ip=device_mgmt_ip,
            gitlab_state=gitlab_state,
            gitlab_update_source_truth=gitlab_update_source_truth,
            logger=logger,
            fail_on_tier=fail_on_tier,
            pass_threshold=pass_threshold,
            concurrent=concurrent,
        )


# ── Inspect workflow ───────────────────────────────────────────────────────────

def _run_inspect_audit(
    client, exporter, all_partitions, output_dir, concurrent,
    device_hostname, device_mgmt_ip, logger,
) -> int:
    """Run the fast REST-based policy inspection (no export task)."""
    try:
        policies = exporter.discover_policies(all_partitions)
    except ExportError as exc:
        logger.error("Policy discovery failed: %s", exc)
        client.close()
        return 2

    if not policies:
        logger.warning("No ASM/AWAF policies found. Exiting.")
        client.close()
        return 0

    exporter.print_discovery_table(policies)

    inspector = PolicyInspector(client=client, concurrent=concurrent)
    results = inspector.inspect_all(policies)

    # Write JSON output
    out_dir = ensure_dir(output_dir)
    out_path = out_dir / "inspection.json"
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    logger.info("Inspection results written to %s", out_path)

    client.close()

    print_inspection_table(results)

    errors_total = sum(len(r.get("errors", [])) for r in results)
    if errors_total:
        logger.warning(
            "%d sub-call error(s) across %d policies — see inspection.json for details.",
            errors_total, len(results),
        )

    print(f"Inspection JSON: {out_path}")
    return 0


# ── WAF audit workflow ─────────────────────────────────────────────────────────

def _run_waf_audit(
    client, exporter, all_partitions, baseline, output_dir, formats,
    device_hostname, device_mgmt_ip, gitlab_state, gitlab_update_source_truth, logger,
    fail_on_tier: str,
    pass_threshold: float,
    concurrent: int = 3,
) -> int:
    """Run the ASM/AWAF policy audit using targeted REST inspection.

    Policy state is collected via iControl REST API calls (enforcement mode,
    violations, signature sets, learning mode, audit log) rather than a full
    policy export/download.  This eliminates the async export task, polling
    loop, and chunked file download that were previously required.
    """
    virtual_server_inventory = []
    virtual_server_inventory_error: Optional[str] = None

    try:
        policies = exporter.discover_policies(all_partitions)
    except ExportError as exc:
        logger.error("Policy discovery failed: %s", exc)
        client.close()
        return 2

    if not policies:
        logger.warning("No ASM/AWAF policies found. Exiting.")
        client.close()
        return 0

    exporter.print_discovery_table(policies)

    # Enrich with virtual server bindings (uses VS refs already in policy dicts
    # from discover_policies — no additional API call to /asm/policies).
    exporter.enrich_with_virtual_servers(policies)

    # Collect VS inventory, reusing the ASM policies payload already fetched by
    # discover_policies to avoid a duplicate /mgmt/tm/asm/policies request.
    try:
        logger.info(
            "Collecting virtual server inventory across %d partition(s)...",
            len(all_partitions),
        )
        virtual_server_inventory = collect_virtual_server_inventory(
            bigip_client=client,
            partitions=all_partitions,
            asm_policies_payload=exporter._raw_asm_payload,
        )
    except Exception as exc:
        virtual_server_inventory_error = str(exc)
        logger.error(
            "Virtual server inventory collection failed; continuing with policy audit: %s",
            exc,
        )

    # Inspect all policies via targeted REST calls (no export task or download).
    inspector = PolicyInspector(client=client, concurrent=concurrent, audit_limit=10)
    logger.info("Inspecting %d policies via REST …", len(policies))
    inspections = inspector.inspect_all(policies)
    inspection_map = {r["fullPath"]: r for r in inspections}

    # Parse baseline XML — still used for comparison; only sections the inspector
    # can reach are compared to avoid false-positive diffs.
    logger.info("Parsing baseline policy: %s", baseline)
    try:
        raw_baseline = parse_policy(baseline)
    except Exception as exc:
        logger.error("Failed to parse baseline policy: %s", exc)
        return 2
    baseline_name = Path(baseline).name
    reduced_baseline = _reduce_baseline_for_inspector(raw_baseline)

    # Compare and report
    all_results = []
    sot_results = []
    total = len(policies)

    for idx, policy in enumerate(policies, 1):
        full_path = policy["fullPath"]
        inspection = inspection_map.get(full_path)
        if not inspection:
            logger.error("No inspection result for %s — skipping", full_path)
            continue

        if inspection.get("errors"):
            logger.warning(
                "Inspection errors for %s: %s", full_path, inspection["errors"]
            )

        logger.info("Auditing policy %d/%d: %s", idx, total, full_path)

        target_data = _inspector_to_target_dict(inspection)
        meta = {
            "name":     policy["name"],
            "fullPath": policy["fullPath"],
            "active":   policy.get("active", False),
        }

        cmp_result = compare_policies(
            baseline=reduced_baseline,
            target=target_data,
            policy_meta=meta,
            baseline_name=baseline_name,
            virtual_servers=policy.get("virtual_servers", []),
            device_hostname=device_hostname,
            device_mgmt_ip=device_mgmt_ip,
            asm_audit_logs=inspection.get("auditLog", []),
            asm_audit_log_total=inspection.get("auditLogTotal", 0),
            asm_audit_log_error=inspection.get("auditLogError"),
            green_threshold=pass_threshold,
        )
        all_results.append(cmp_result)

        if gitlab_state is not None:
            sot_baseline, sot_name = gitlab_state.load_waf_source_of_truth(full_path)
            if sot_baseline is not None:
                try:
                    sot_cmp_result = compare_policies(
                        baseline=_reduce_baseline_for_inspector(sot_baseline),
                        target=target_data,
                        policy_meta=meta,
                        baseline_name=sot_name,
                        virtual_servers=policy.get("virtual_servers", []),
                        device_hostname=device_hostname,
                        device_mgmt_ip=device_mgmt_ip,
                        asm_audit_logs=inspection.get("auditLog", []),
                        asm_audit_log_total=inspection.get("auditLogTotal", 0),
                        asm_audit_log_error=inspection.get("auditLogError"),
                        green_threshold=pass_threshold,
                    )
                    sot_results.append(sot_cmp_result)
                except Exception as exc:
                    logger.warning(
                        "Source-of-truth comparison failed for %s: %s",
                        full_path,
                        exc,
                    )

        if "markdown" in formats:
            generate_markdown(cmp_result, output_dir)
        # HTML is generated once as an interactive multi-policy dashboard.

    if all_results:
        if "html" in formats:
            generate_html_dashboard(
                all_results,
                output_dir,
                virtual_server_inventory=virtual_server_inventory,
                virtual_server_inventory_error=virtual_server_inventory_error,
            )

        summary_formats = [f for f in formats if f != "html"]
        if summary_formats:
            generate_summary_reports(all_results, output_dir, summary_formats)
        if "markdown" in formats:
            generate_virtual_server_summary_markdown(
                virtual_server_inventory=virtual_server_inventory,
                output_dir=output_dir,
                inventory_error=virtual_server_inventory_error,
            )

    if sot_results:
        sot_output_dir = str(Path(output_dir) / "source_of_truth")
        for r in sot_results:
            if "markdown" in formats:
                generate_markdown(r, sot_output_dir)
        if "html" in formats:
            generate_html_dashboard(
                sot_results,
                sot_output_dir,
                virtual_server_inventory=virtual_server_inventory,
                virtual_server_inventory_error=virtual_server_inventory_error,
            )
        summary_formats = [f for f in formats if f != "html"]
        if summary_formats:
            generate_summary_reports(sot_results, sot_output_dir, summary_formats)
        if "markdown" in formats:
            generate_virtual_server_summary_markdown(
                virtual_server_inventory=virtual_server_inventory,
                output_dir=sot_output_dir,
                inventory_error=virtual_server_inventory_error,
            )
        logger.info(
            "Generated %d source-of-truth comparison report(s) under %s",
            len(sot_results),
            Path(output_dir) / "source_of_truth" / "reports",
        )

    if gitlab_state is not None:
        gitlab_state.archive_run(
            mode="waf",
            output_dir=output_dir,
            baseline_path=baseline,
            device_hostname=device_hostname,
            device_mgmt_ip=device_mgmt_ip,
            audited_count=len(all_results),
            failure_count=0,
        )
        gitlab_state.commit_and_push(
            commit_message=(
                f"WAF audit sync for {device_hostname or device_mgmt_ip} "
                f"({len(all_results)} audited)"
            )
        )

    client.close()
    return _print_summary(
        all_results=all_results,
        failures=[],
        device_hostname=device_hostname,
        device_mgmt_ip=device_mgmt_ip,
        output_dir=output_dir,
        subject_label="Policy",
        failure_label="policy inspection(s)",
        pass_threshold=pass_threshold,
        fail_on_tier=fail_on_tier,
    )


# ── Bot Defense audit workflow ─────────────────────────────────────────────────

def _run_bot_audit(
    client, all_partitions, baseline_data, baseline_name, output_dir, formats,
    partitions, device_hostname, device_mgmt_ip, gitlab_state,
    gitlab_update_source_truth, logger,
    fail_on_tier: str,
    pass_threshold: float,
) -> int:
    """Run the Bot Defense profile audit."""
    auditor = BotDefenseAuditor(
        client=client,
        output_dir=output_dir,
        partitions=partitions if partitions else None,
    )

    try:
        profiles = auditor.discover_profiles(all_partitions)
    except RuntimeError as exc:
        logger.error("Bot Defense profile discovery failed: %s", exc)
        client.close()
        return 2

    if not profiles:
        logger.warning("No Bot Defense profiles found. Exiting.")
        client.close()
        return 0

    auditor.print_discovery_table(profiles)

    # Enrich profiles with Virtual Server bindings (direct and via LTM policy)
    auditor.enrich_with_virtual_servers(profiles)

    successes, failures = auditor.fetch_all(profiles)
    if failures:
        logger.warning(
            "%d Bot Defense profile fetch(es) failed:", len(failures)
        )
        for profile, err in failures:
            logger.warning("  %s: %s", profile["fullPath"], err)

    if not successes:
        logger.error("All profile fetches failed. No profiles to audit.")
        client.close()
        return 2

    client.close()

    # Compare and report
    all_results = []
    sot_results = []
    total = len(successes)
    iterable = successes

    for idx, (profile_meta, profile_data) in enumerate(successes, 1):
        logger.info(
            "Auditing Bot Defense profile %d/%d: %s",
            idx, total, profile_meta["fullPath"],
        )
        try:
            cmp_result = compare_bot_profiles(
                baseline=baseline_data,
                target=profile_data,
                profile_meta=profile_meta,
                baseline_name=baseline_name,
                device_hostname=device_hostname,
                device_mgmt_ip=device_mgmt_ip,
                virtual_servers=profile_meta.get("virtual_servers", []),
                green_threshold=pass_threshold,
            )
        except Exception as exc:
            logger.error(
                "Failed to compare Bot Defense profile %s: %s",
                profile_meta["fullPath"], exc,
            )
            continue

        all_results.append(cmp_result)

        if gitlab_state is not None:
            sot_baseline, sot_name = gitlab_state.load_bot_source_of_truth(profile_meta["fullPath"])
            if sot_baseline is not None:
                try:
                    sot_cmp_result = compare_bot_profiles(
                        baseline=sot_baseline,
                        target=profile_data,
                        profile_meta=profile_meta,
                        baseline_name=sot_name,
                        device_hostname=device_hostname,
                        device_mgmt_ip=device_mgmt_ip,
                        virtual_servers=profile_meta.get("virtual_servers", []),
                        green_threshold=pass_threshold,
                    )
                    sot_results.append(sot_cmp_result)
                except Exception as exc:
                    logger.warning(
                        "Source-of-truth comparison failed for %s: %s",
                        profile_meta["fullPath"],
                        exc,
                    )

        if "markdown" in formats:
            generate_markdown(cmp_result, output_dir)
        # HTML is generated once as an interactive multi-profile dashboard.

    if all_results:
        if "html" in formats:
            generate_html_dashboard(all_results, output_dir)

        summary_formats = [f for f in formats if f != "html"]
        if summary_formats:
            generate_summary_reports(all_results, output_dir, summary_formats)

    if sot_results:
        sot_output_dir = str(Path(output_dir) / "source_of_truth")
        for r in sot_results:
            if "markdown" in formats:
                generate_markdown(r, sot_output_dir)
        if "html" in formats:
            generate_html_dashboard(sot_results, sot_output_dir)
        summary_formats = [f for f in formats if f != "html"]
        if summary_formats:
            generate_summary_reports(sot_results, sot_output_dir, summary_formats)
        logger.info(
            "Generated %d source-of-truth comparison report(s) under %s",
            len(sot_results),
            Path(output_dir) / "source_of_truth" / "reports",
        )

    if gitlab_state is not None:
        gitlab_state.archive_run(
            mode="bot",
            output_dir=output_dir,
            baseline_path=baseline_name,
            device_hostname=device_hostname,
            device_mgmt_ip=device_mgmt_ip,
            audited_count=len(all_results),
            failure_count=len(failures),
        )
        if gitlab_update_source_truth:
            gitlab_state.update_bot_source_of_truth(successes)
        gitlab_state.commit_and_push(
            commit_message=(
                f"Bot Defense audit sync for {device_hostname or device_mgmt_ip} "
                f"({len(all_results)} audited, {len(failures)} failed fetches)"
            )
        )

    return _print_summary(
        all_results=all_results,
        failures=failures,
        device_hostname=device_hostname,
        device_mgmt_ip=device_mgmt_ip,
        output_dir=output_dir,
        subject_label="Profile",
        failure_label="profile fetch(es)",
        pass_threshold=pass_threshold,
        fail_on_tier=fail_on_tier,
    )


# ── Shared summary output ──────────────────────────────────────────────────────

def _print_summary(
    all_results, failures, device_hostname, device_mgmt_ip, output_dir,
    subject_label="Policy", failure_label="policy export(s)",
    pass_threshold=_DEFAULT_PASS_THRESHOLD,
    fail_on_tier=_DEFAULT_FAIL_ON_TIER,
) -> int:
    """Print the final stdout summary table and return the exit code.

    Exit codes:
      0 = All subjects scored at or above the --fail-on-tier threshold.
      1 = One or more subjects at/below the fail-on-tier threshold (non-compliant).
      2 = Runtime/setup error (handled earlier).
    """
    audit_label = (
        "BOT DEFENSE PROFILE AUDIT SUMMARY"
        if any(getattr(r, "profile_type", "waf") == "bot" for r in all_results)
        else "POLICY AUDIT SUMMARY"
    )
    print("\n" + "=" * 72)
    print(f"{audit_label:^72}")
    print("=" * 72)
    if device_hostname:
        print(f"Device : {device_hostname}  ({device_mgmt_ip})")
    else:
        print(f"Device : {device_mgmt_ip}")
    print("-" * 72)
    header = (
        f"{subject_label:<40} {'Score':>7}  {'Tier':<15}  {'Critical':>8}  {'High':>5}  {'Warn':>5}  {'Info':>5}"
    )
    print(header)
    print("-" * 72)

    threshold_rank = _TIER_RANK[fail_on_tier]
    any_fail = False
    for r in sorted(all_results, key=lambda x: x.score):
        tier_rank = _TIER_RANK.get(r.tier, _TIER_RANK[TIER_RED])
        if tier_rank <= threshold_rank:
            any_fail = True
        totals = r.summary.get("totals", {})
        crit = totals.get("critical", 0)
        high = totals.get("high", 0)
        warn = totals.get("warning", 0)
        info = totals.get("info", 0)
        name = r.policy_path
        if len(name) > 38:
            name = "…" + name[-37:]
        print(
            f"{name:<40} {r.score:>6.1f}%  "
            f"{_TIER_EMOJI.get(r.tier,'')} {r.tier_label:<13}  "
            f"{crit:>8}  {high:>5}  {warn:>5}  {info:>5}"
        )

    print("=" * 72)

    if failures:
        print(f"\nWARNING: {len(failures)} {failure_label} failed and were not audited.")

    reports_dir = Path(output_dir) / "reports"
    print(f"\nReports written to: {reports_dir}")
    print(f"Log file:           {Path(output_dir)}/audit_*.log")

    exit_code = 1 if any_fail else 0
    if any_fail:
        print(
            f"\nRESULT: NON-COMPLIANT — one or more {failure_label.split('(')[0].strip()}s are "
            f"{fail_on_tier.title()} tier or worse."
        )
    else:
        print(
            f"\nRESULT: COMPLIANT — all {failure_label.split('(')[0].strip()}s are above "
            f"the {fail_on_tier.title()} threshold."
        )

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
