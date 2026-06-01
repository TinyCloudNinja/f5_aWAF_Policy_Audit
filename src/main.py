"""
CLI entry point for the F5 BIG-IP ASM/AWAF Security Policy Auditor.

Changelog: Phase 1 refactor — interactive mode selection, device-side baseline
selection, questionary prompts, and SSL verification bug fix.
"""

import argparse
import json
import os
import sys
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
from .policy_fetcher import PolicyFetcher
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
from .interactive import (
    collect_run_parameters,
    prompt_password,
    prompt_mode,
    get_device_version,
)

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
            "or Bot Defense profiles against a baseline selected from the device.\n\n"
            "Audit modes (via --mode or interactive menu):\n"
            "  WAF      Audit ASM/AWAF security policies\n"
            "  BOT      Audit Bot Defense profiles\n"
            "  INSPECT  Fast targeted REST inspection (no baseline required)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument(
        "--mode",
        dest="mode",
        choices=["WAF", "BOT", "INSPECT", "waf", "bot", "inspect"],
        default=None,
        help="Audit mode. If omitted and stdin is a TTY, an interactive menu is shown.",
    )
    p.add_argument(
        "--baseline-policy",
        dest="baseline_policy",
        metavar="FULLPATH",
        default=None,
        help=(
            "Full path of the BST-prefixed baseline policy/profile on the device "
            "(e.g. '~Common~BST_Corporate_Baseline'). "
            "If omitted and stdin is a TTY, an interactive menu is shown."
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
            "Green lower bound (default: 90). "
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
            "RED (default) fails on any Red policy."
        ),
    )

    p.add_argument("--config", metavar="FILE",
                   help="Path to YAML config file (default: config.yaml)")
    p.add_argument("--host", metavar="HOST",
                   help="BIG-IP management IP or FQDN [env: BIGIP_HOST]")
    p.add_argument("--username", metavar="USER",
                   help="Admin username [env: BIGIP_USER]")
    p.add_argument(
        "--password",
        metavar="PASS",
        default=None,
        help=(
            "BIG-IP password. Prefer BIGIP_PASS env var or the interactive prompt "
            "to avoid exposing the password in the process table."
        ),
    )
    p.add_argument("--output-dir", metavar="DIR", default=None,
                   help=f"Output directory (default: {_DEFAULT_OUTPUT_DIR})")
    p.add_argument("--format", dest="report_format",
                   choices=["html", "markdown", "both"], default=None,
                   help="Report format (default: both)")
    p.add_argument("--verify-ssl", dest="verify_ssl", action="store_true",
                   default=None, help="Enable TLS certificate verification")
    p.add_argument("--no-verify-ssl", dest="verify_ssl", action="store_false",
                   help="Disable TLS certificate verification (default; for self-signed certs)")
    p.add_argument("--login-provider", dest="login_provider", metavar="PROVIDER",
                   default=None,
                   help="BIG-IP login provider name [env: BIGIP_LOGIN_PROVIDER] (default: tmos)")
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
    p.add_argument("--gitlab-update-source-truth", dest="gitlab_update_source_truth",
                   action="store_true", default=None,
                   help="Update source_of_truth files in the GitLab repo from current device state")
    p.add_argument("--no-gitlab-update-source-truth", dest="gitlab_update_source_truth",
                   action="store_false",
                   help="Do not update source_of_truth files")
    p.add_argument("-v", "--verbose", action="store_true", default=False,
                   help="Enable debug logging")
    return p


def _inspector_to_target_dict(inspection: Dict) -> Dict:
    """Convert PolicyInspector results to the dict format expected by compare_policies.

    Only sections coverable via targeted REST calls (enforcement mode, violations,
    signature sets, learning mode) are populated.  All other sections are set to
    empty values so the comparator does not generate false-positive findings for
    data that was never fetched.
    """
    # Build a single violations dict with all three flag values per violation.
    # Prefer the "all" list (added in inspector v2) which includes violations
    # whose flags are all False — those would otherwise be silently dropped and
    # misreported as "missing from target" by the comparator.
    violations_data = inspection.get("violations", {})
    all_viols = violations_data.get("all", [])
    if all_viols:
        merged_violations: Dict[str, Dict] = {
            v["name"]: {
                "name":        v["name"],
                "description": v.get("description", ""),
                "alarm":       bool(v.get("alarm", False)),
                "block":       bool(v.get("block", False)),
                "learn":       bool(v.get("learn", False)),
            }
            for v in all_viols if v.get("name")
        }
    else:
        # Backward-compat: reconstruct from per-flag lists (pre-"all" inspector).
        # Violations with all flags False are absent here — acceptable for old data.
        merged_violations = {}
        for flag in ("learn", "alarm", "block"):
            for item in violations_data.get(flag, []):
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
    # Enforcement mode: prefer the <blocking> section's enforcement_mode, which is
    # the authoritative policy mode in full exports.  Many exports carry only a
    # placeholder <general> section that defaults to "transparent" even when the
    # policy is blocking; preferring <blocking> (as compare_policies already does
    # for the target) prevents a false "transparent vs blocking" drift against the
    # live policy, whose mode comes from the REST enforcementMode field.
    enforcement_mode = (
        baseline_data.get("blocking", {}).get("enforcement_mode")
        or baseline_data.get("general", {}).get("enforcementMode")
        or "transparent"
    )
    return {
        "general":           {"enforcementMode": enforcement_mode},
        "blocking-settings": {
            # Fall back to <blocking> section for XML exports that use that format
            "violations":     (
                baseline_data.get("blocking-settings", {}).get("violations", [])
                or baseline_data.get("blocking", {}).get("violations", [])
            ),
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

    # Load config file
    config_path = args.config or "config.yaml"
    raw_cfg = _load_config(config_path)
    bigip_cfg = raw_cfg.get("bigip", {})
    audit_cfg = raw_cfg.get("audit", {})
    gitlab_cfg = raw_cfg.get("gitlab", {})

    # Resolve parameters
    host         = _resolve(args.host,     "BIGIP_HOST", bigip_cfg.get("host"))
    username     = _resolve(args.username, "BIGIP_USER", bigip_cfg.get("username"))
    login_provider = _resolve(
        args.login_provider, "BIGIP_LOGIN_PROVIDER",
        bigip_cfg.get("login_provider"), "tmos"
    )
    output_dir   = _resolve(args.output_dir, "OUTPUT_DIR",
                            audit_cfg.get("output_dir"), _DEFAULT_OUTPUT_DIR)
    report_format = _resolve(args.report_format, "REPORT_FORMAT",
                             audit_cfg.get("report_format"), "both")

    # SSL verification — default False for self-signed lab certs.
    # Fix: string "true"/"1"/"yes" must map to True (was inverted in prior version).
    _raw_ssl = _resolve(args.verify_ssl, "VERIFY_SSL", bigip_cfg.get("verify_ssl"), False)
    if isinstance(_raw_ssl, str):
        verify_ssl = _raw_ssl.lower() in ("1", "true", "yes")
    else:
        verify_ssl = bool(_raw_ssl)

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
        args.gitlab_repo_url, "GITLAB_REPO_URL", gitlab_cfg.get("repo_url"),
    )
    gitlab_local_dir = _resolve(
        args.gitlab_local_dir, "GITLAB_LOCAL_DIR",
        gitlab_cfg.get("local_dir"), _DEFAULT_GITLAB_LOCAL_DIR,
    )
    gitlab_branch = _resolve(
        args.gitlab_branch, "GITLAB_BRANCH", gitlab_cfg.get("branch"), "main",
    )
    _raw_gitlab_auto_push = _resolve(
        args.gitlab_auto_push, "GITLAB_AUTO_PUSH", gitlab_cfg.get("auto_push"), False,
    )
    _raw_gitlab_update_sot = _resolve(
        args.gitlab_update_source_truth, "GITLAB_UPDATE_SOURCE_TRUTH",
        gitlab_cfg.get("update_source_truth"), False,
    )
    if isinstance(_raw_gitlab_auto_push, str):
        gitlab_auto_push = _raw_gitlab_auto_push.lower() in ("1", "true", "yes")
    else:
        gitlab_auto_push = bool(_raw_gitlab_auto_push)
    if isinstance(_raw_gitlab_update_sot, str):
        gitlab_update_source_truth = _raw_gitlab_update_sot.lower() in ("1", "true", "yes")
    else:
        gitlab_update_source_truth = bool(_raw_gitlab_update_sot)

    # Setup logging
    ensure_dir(output_dir)
    log = setup_logging(verbose, output_dir, "waf")
    logger = get_logger("main")

    # Validate required connection arguments
    missing = []
    if not host:
        missing.append("--host / BIGIP_HOST")
    if not username:
        missing.append("--username / BIGIP_USER")
    if missing:
        parser.print_usage()
        print(f"\nERROR: Missing required arguments: {', '.join(missing)}")
        return 2

    # ── Determine audit mode ───────────────────────────────────────────────────
    _mode_raw = _resolve(args.mode, "AUDIT_MODE", audit_cfg.get("mode"))
    if _mode_raw:
        audit_mode = str(_mode_raw).lower()
    elif sys.stdin.isatty():
        try:
            audit_mode = prompt_mode().lower()
        except KeyboardInterrupt:
            print("\nAborted.")
            return 130
    else:
        print(
            "ERROR: --mode is required in non-interactive mode. "
            "Use --mode WAF, --mode BOT, or --mode INSPECT.",
            file=sys.stderr,
        )
        return 2

    # Re-setup logging with correct mode prefix
    log = setup_logging(verbose, output_dir, audit_mode)
    logger = get_logger("main")

    # ── Resolve password ───────────────────────────────────────────────────────
    if bigip_cfg.get("password"):
        print(
            "ERROR: 'password' in the config file is not supported. "
            "Use the BIGIP_PASS environment variable or the interactive prompt.",
            file=sys.stderr,
        )
        return 2

    password = args.password or os.environ.get("BIGIP_PASS")
    if not password:
        if sys.stdin.isatty():
            try:
                password = prompt_password(username, host)
            except KeyboardInterrupt:
                print("\nAborted.")
                return 130
        else:
            print(
                "ERROR: No password provided. Set BIGIP_PASS env var or use --password.",
                file=sys.stderr,
            )
            return 2

    # SSL warning
    if not verify_ssl:
        logger.warning(
            "SSL verification is DISABLED. "
            "Only use this for self-signed certificates in trusted environments."
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

    # Print connection banner
    version_str = get_device_version(client)
    print(f"Connected to BIG-IP {host}  ({version_str})")
    logger.info("Authenticated successfully.")

    # ── GitLab state manager ───────────────────────────────────────────────────
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
            logger.info("GitLab policy state enabled (branch=%s)", gitlab_branch)
        else:
            logger.warning("GitLab policy state repo unavailable; continuing without it.")
            gitlab_state = None

    # ── Fetch device identity ──────────────────────────────────────────────────
    exporter = PolicyExporter(client=client)
    device_info = exporter.fetch_device_info()
    device_hostname = device_info["hostname"]
    device_mgmt_ip  = device_info["mgmt_ip"]
    logger.info(
        "Device: hostname=%s  mgmt=%s",
        device_hostname or "(unknown)", device_mgmt_ip,
    )

    # ── Discover partitions ────────────────────────────────────────────────────
    try:
        all_partitions = exporter.discover_partitions()
    except Exception as exc:
        logger.error("Partition discovery failed: %s", exc)
        client.close()
        return 2

    # ── Resolve --baseline-policy ──────────────────────────────────────────────
    baseline_policy_arg = _resolve(
        args.baseline_policy, "BASELINE_POLICY", audit_cfg.get("baseline_policy")
    )

    # Guard against stale config.yaml entries that still point to a local file
    # (e.g. baseline_policy: "./baseline/corporate_baseline.xml").  Device
    # fullPaths look like '/Common/Name' or '~Common~Name' — never have a file
    # extension.  Silently dropping the value lets the interactive menu take over
    # rather than producing a confusing "policy not found on device" error.
    if baseline_policy_arg:
        _bp_ext = Path(str(baseline_policy_arg)).suffix.lower()
        _bp_str = str(baseline_policy_arg)
        if _bp_ext in (".xml", ".json", ".yaml", ".yml") or _bp_str.startswith(("./", "../")):
            logger.warning(
                "Ignoring baseline_policy value %r — looks like a local file path, "
                "not a device fullPath.  Use --baseline-policy with a device fullPath "
                "(e.g. '~Common~BST_Baseline') or remove 'baseline_policy' from your "
                "config file to use the interactive selector.",
                baseline_policy_arg,
            )
            baseline_policy_arg = None

    # ── Dispatch ───────────────────────────────────────────────────────────────
    try:
        if audit_mode == "inspect":
            return _run_inspect_audit(
                client=client,
                exporter=exporter,
                all_partitions=all_partitions,
                output_dir=output_dir,
                concurrent=5,
                device_hostname=device_hostname,
                device_mgmt_ip=device_mgmt_ip,
                logger=logger,
            )
        elif audit_mode == "bot":
            return _run_bot_audit(
                client=client,
                exporter=exporter,
                all_partitions=all_partitions,
                baseline_policy_arg=baseline_policy_arg,
                output_dir=output_dir,
                formats=formats,
                device_hostname=device_hostname,
                device_mgmt_ip=device_mgmt_ip,
                gitlab_state=gitlab_state,
                gitlab_update_source_truth=gitlab_update_source_truth,
                logger=logger,
                fail_on_tier=fail_on_tier,
                pass_threshold=pass_threshold,
            )
        else:  # waf
            return _run_waf_audit(
                client=client,
                exporter=exporter,
                all_partitions=all_partitions,
                baseline_policy_arg=baseline_policy_arg,
                output_dir=output_dir,
                formats=formats,
                device_hostname=device_hostname,
                device_mgmt_ip=device_mgmt_ip,
                gitlab_state=gitlab_state,
                gitlab_update_source_truth=gitlab_update_source_truth,
                logger=logger,
                fail_on_tier=fail_on_tier,
                pass_threshold=pass_threshold,
            )
    except KeyboardInterrupt:
        print("\nAborted.")
        return 130


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
    client,
    exporter,
    all_partitions,
    baseline_policy_arg: Optional[str],
    output_dir,
    formats,
    device_hostname,
    device_mgmt_ip,
    gitlab_state,
    gitlab_update_source_truth,
    logger,
    fail_on_tier: str,
    pass_threshold: float,
) -> int:
    """Run the ASM/AWAF policy audit (Phase 3: PolicyFetcher for full API-driven data)."""
    virtual_server_inventory: list = []
    virtual_server_inventory_error: Optional[str] = None

    # ── Discover all policies (with VS binding refs) ───────────────────────────
    try:
        all_policies = exporter.discover_policies(all_partitions)
    except ExportError as exc:
        logger.error("Policy discovery failed: %s", exc)
        client.close()
        return 2

    if not all_policies:
        logger.warning("No ASM/AWAF policies found. Exiting.")
        client.close()
        return 0

    exporter.enrich_with_virtual_servers(all_policies)

    try:
        logger.info("Collecting virtual server inventory …")
        virtual_server_inventory = collect_virtual_server_inventory(
            bigip_client=client,
            partitions=all_partitions,
            asm_policies_payload=exporter._raw_asm_payload,
        )
    except Exception as exc:
        virtual_server_inventory_error = str(exc)
        logger.error("Virtual server inventory collection failed; continuing: %s", exc)

    # ── Interactive or non-interactive policy selection ────────────────────────
    try:
        run_params = collect_run_parameters(
            all_items=all_policies,
            output_dir=output_dir,
            mode="WAF",
            baseline_policy=baseline_policy_arg,
        )
    except RuntimeError as exc:
        logger.error("%s", exc)
        client.close()
        return 1

    baseline_policy = run_params["baseline"]
    target_policies = run_params["target_policies"]
    baseline_name   = baseline_policy.get("fullPath", "baseline")

    if not target_policies:
        logger.warning("No target policies selected. Exiting.")
        client.close()
        return 0

    exporter.print_discovery_table(target_policies)

    # ── Fetch baseline via full API-driven fetcher ─────────────────────────────
    fetcher = PolicyFetcher(client=client, concurrent=5)
    logger.info("Fetching baseline policy: %s", baseline_name)
    try:
        baseline_data = fetcher.fetch_waf_policy(baseline_policy)
    except Exception as exc:
        logger.error("Baseline fetch failed for %s: %s", baseline_name, exc)
        client.close()
        return 1

    n_viols   = len(baseline_data.get("blocking-settings", {}).get("violations", []))
    n_sigsets = len(baseline_data.get("signature-sets", []))
    print(f"✓ Baseline fetched: {baseline_name}  ({n_viols} violations, {n_sigsets} sig sets)")

    # ── Fetch, compare, and report each target policy ──────────────────────────
    all_results: list = []
    sot_results: list = []
    fetch_failures = 0
    total = len(target_policies)

    for idx, policy in enumerate(target_policies, 1):
        full_path = policy["fullPath"]
        logger.info("Fetching policy %d/%d: %s", idx, total, full_path)

        try:
            target_data = fetcher.fetch_waf_policy(policy)
        except Exception as exc:
            logger.error("Fetch failed for %s: %s", full_path, exc)
            fetch_failures += 1
            short = full_path if len(full_path) <= 50 else "…" + full_path[-49:]
            print(f"  [{idx}/{total}] {short}  FETCH FAILED")
            continue

        meta = {
            "name":     policy["name"],
            "fullPath": policy["fullPath"],
            "active":   policy.get("active", False),
        }

        cmp_result = compare_policies(
            baseline=baseline_data,
            target=target_data,
            policy_meta=meta,
            baseline_name=baseline_name,
            virtual_servers=policy.get("virtual_servers", []),
            device_hostname=device_hostname,
            device_mgmt_ip=device_mgmt_ip,
            asm_audit_logs=[],
            asm_audit_log_total=0,
            asm_audit_log_error=None,
            green_threshold=pass_threshold,
        )
        all_results.append(cmp_result)

        short = full_path if len(full_path) <= 47 else "…" + full_path[-46:]
        print(
            f"  [{idx}/{total}] {short:<49}  "
            f"{cmp_result.score:>6.1f}%  "
            f"{_TIER_EMOJI.get(cmp_result.tier, '')} {cmp_result.tier_label:<13}  "
            f"{len(cmp_result.diffs)} diffs"
        )

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
                        asm_audit_logs=[],
                        asm_audit_log_total=0,
                        asm_audit_log_error=None,
                        green_threshold=pass_threshold,
                    )
                    sot_results.append(sot_cmp_result)
                except Exception as exc:
                    logger.warning("SoT comparison failed for %s: %s", full_path, exc)

        if "markdown" in formats:
            generate_markdown(cmp_result, output_dir)

    if fetch_failures == total:
        logger.error("All %d policy fetch(es) failed. No results to report.", total)
        client.close()
        return 2

    if all_results:
        if "html" in formats:
            dashboard_path = generate_html_dashboard(
                all_results,
                output_dir,
                virtual_server_inventory=virtual_server_inventory,
                virtual_server_inventory_error=virtual_server_inventory_error,
            )
            print(f"✓ Dashboard → {dashboard_path}")
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
                sot_results, sot_output_dir,
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

    if gitlab_state is not None:
        gitlab_state.archive_run(
            mode="waf",
            output_dir=output_dir,
            baseline_path=baseline_name,
            device_hostname=device_hostname,
            device_mgmt_ip=device_mgmt_ip,
            audited_count=len(all_results),
            failure_count=fetch_failures,
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
        failure_label="policy fetch(es)",
        pass_threshold=pass_threshold,
        fail_on_tier=fail_on_tier,
    )


# ── Bot Defense audit workflow ─────────────────────────────────────────────────

def _run_bot_audit(
    client,
    exporter,
    all_partitions,
    baseline_policy_arg: Optional[str],
    output_dir,
    formats,
    device_hostname,
    device_mgmt_ip,
    gitlab_state,
    gitlab_update_source_truth,
    logger,
    fail_on_tier: str,
    pass_threshold: float,
) -> int:
    """Run the Bot Defense profile audit (Phase 1: baseline selected from BIG-IP)."""
    auditor = BotDefenseAuditor(
        client=client,
        output_dir=output_dir,
        partitions=None,
    )

    # ── Discover all profiles ──────────────────────────────────────────────────
    try:
        all_profiles = auditor.discover_profiles(all_partitions)
    except RuntimeError as exc:
        logger.error("Bot Defense profile discovery failed: %s", exc)
        client.close()
        return 2

    if not all_profiles:
        logger.warning("No Bot Defense profiles found. Exiting.")
        client.close()
        return 0

    auditor.enrich_with_virtual_servers(all_profiles)

    # ── Interactive or non-interactive selection ───────────────────────────────
    try:
        run_params = collect_run_parameters(
            all_items=all_profiles,
            output_dir=output_dir,
            mode="BOT",
            baseline_policy=baseline_policy_arg,
        )
    except RuntimeError as exc:
        logger.error("%s", exc)
        client.close()
        return 1

    baseline_profile = run_params["baseline"]
    target_profiles  = run_params["target_policies"]
    baseline_name    = baseline_profile.get("fullPath", "baseline")

    if not target_profiles:
        logger.warning("No target profiles selected. Exiting.")
        client.close()
        return 0

    auditor.print_discovery_table(target_profiles)

    # ── Fetch baseline profile data ────────────────────────────────────────────
    logger.info("Fetching baseline Bot Defense profile: %s", baseline_name)
    try:
        baseline_data = auditor.fetch_profile(baseline_profile)
    except Exception as exc:
        logger.error("Failed to fetch baseline profile %s: %s", baseline_name, exc)
        client.close()
        return 1

    print(f"✓ Baseline fetched: {baseline_name}")

    # ── Fetch target profiles ──────────────────────────────────────────────────
    successes, failures = auditor.fetch_all(target_profiles)
    if failures:
        logger.warning("%d Bot Defense profile fetch(es) failed:", len(failures))
        for profile, err in failures:
            logger.warning("  %s: %s", profile["fullPath"], err)

    if not successes:
        logger.error("All profile fetches failed. No profiles to audit.")
        client.close()
        return 2

    client.close()

    # ── Compare and report ─────────────────────────────────────────────────────
    all_results: list = []
    sot_results: list = []
    total = len(successes)

    for idx, (profile_meta, profile_data) in enumerate(successes, 1):
        full_path = profile_meta.get("fullPath", "")
        logger.info("Auditing Bot Defense profile %d/%d: %s", idx, total, full_path)
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
            logger.error("Failed to compare Bot Defense profile %s: %s", full_path, exc)
            short = full_path if len(full_path) <= 47 else "…" + full_path[-46:]
            print(f"  [{idx}/{total}] {short}  COMPARE FAILED")
            continue

        all_results.append(cmp_result)

        short = full_path if len(full_path) <= 47 else "…" + full_path[-46:]
        print(
            f"  [{idx}/{total}] {short:<49}  "
            f"{cmp_result.score:>6.1f}%  "
            f"{_TIER_EMOJI.get(cmp_result.tier, '')} {cmp_result.tier_label:<13}  "
            f"{len(cmp_result.diffs)} diffs"
        )

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
                        "SoT comparison failed for %s: %s",
                        profile_meta["fullPath"], exc,
                    )

        if "markdown" in formats:
            generate_markdown(cmp_result, output_dir)

    if all_results:
        if "html" in formats:
            dashboard_path = generate_html_dashboard(all_results, output_dir)
            print(f"✓ Dashboard → {dashboard_path}")
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
