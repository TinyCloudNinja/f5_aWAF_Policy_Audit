"""
Interactive terminal UI for f5-awaf-auditor.

Uses questionary for arrow-key menus, checkbox multi-select, and hidden
password input.  The module is safe to import without a TTY — all prompt
functions guard via _require_tty() and raise RuntimeError when called from
a non-interactive context.
"""
from __future__ import annotations

import sys
from typing import Dict, List, Optional

import questionary

# ── Constants ──────────────────────────────────────────────────────────────────

BASELINE_PREFIX: str = "BST"

_SYS_VERSION_EP = "/mgmt/tm/sys/version"


# ── TTY guard ──────────────────────────────────────────────────────────────────

def _require_tty() -> None:
    """Raise RuntimeError when not in an interactive terminal."""
    if not sys.stdin.isatty():
        raise RuntimeError(
            "Interactive prompts require a TTY. "
            "Provide --mode, --baseline-policy, and --password (or BIGIP_PASS) "
            "for non-interactive / CI use."
        )


# ── Helpers ────────────────────────────────────────────────────────────────────

def get_device_version(client) -> str:
    """Return a short BIG-IP version string, e.g. 'BIG-IP Advanced WAF 17.1.2 Build 0.0.5'."""
    try:
        data = client.get(_SYS_VERSION_EP)
        for _key, val in data.get("entries", {}).items():
            nested = val.get("nestedStats", {}).get("entries", {})
            product = nested.get("Product", {}).get("description", "")
            version = nested.get("Version", {}).get("description", "")
            build   = nested.get("Build",   {}).get("description", "")
            if product:
                return f"{product} {version} Build {build}".strip()
    except Exception:
        pass
    return "BIG-IP (version unknown)"


def filter_baselines(items: List[Dict], prefix: str = BASELINE_PREFIX) -> List[Dict]:
    """Return items whose name begins with *prefix* (case-insensitive), sorted by fullPath."""
    up = prefix.upper()
    return sorted(
        [i for i in items if i.get("name", "").upper().startswith(up)],
        key=lambda i: i.get("fullPath", ""),
    )


def lookup_by_full_path(items: List[Dict], full_path: str) -> Optional[Dict]:
    """Return the item whose fullPath matches, normalising tilde ↔ slash."""
    def _norm(p: str) -> str:
        p = p.replace("~", "/")
        return p if p.startswith("/") else "/" + p

    target = _norm(full_path)
    for item in items:
        if _norm(item.get("fullPath", "")) == target:
            return item
    return None


# ── Prompt functions ───────────────────────────────────────────────────────────

def prompt_password(username: str, host: str) -> str:
    """Hidden password prompt. Raises RuntimeError outside a TTY."""
    _require_tty()
    result = questionary.password(f"Password for {username}@{host}:").ask()
    if result is None:
        raise KeyboardInterrupt
    return result


def prompt_mode() -> str:
    """Arrow-key mode selector. Returns 'WAF' or 'BOT'."""
    _require_tty()
    result = questionary.select(
        "Select report type:",
        choices=[
            questionary.Choice("WAF / Advanced WAF Policies", value="WAF"),
            questionary.Choice("Bot Defense Profiles",         value="BOT"),
        ],
    ).ask()
    if result is None:
        raise KeyboardInterrupt
    return result


def prompt_baseline(items: List[Dict]) -> Dict:
    """
    Arrow-key baseline selector filtered by BASELINE_PREFIX.

    Raises RuntimeError if no BST-prefixed items are found.
    Raises KeyboardInterrupt on Ctrl-C / Esc.
    """
    _require_tty()
    candidates = filter_baselines(items)
    if not candidates:
        raise RuntimeError(
            f"No policies with '{BASELINE_PREFIX}' prefix found on this device. "
            "A BST-prefixed policy is required as the compliance baseline."
        )
    choices = [questionary.Choice(i["fullPath"], value=i) for i in candidates]
    result = questionary.select(
        f"Select BASELINE policy ({BASELINE_PREFIX} prefix, sorted):",
        choices=choices,
    ).ask()
    if result is None:
        raise KeyboardInterrupt
    return result


def prompt_policies(items: List[Dict], baseline_full_path: str) -> List[Dict]:
    """
    Checkbox multi-select for comparison policies, excluding the baseline.

    All candidates are pre-checked. Raises RuntimeError if none remain.
    Raises KeyboardInterrupt on Ctrl-C / Esc.
    """
    _require_tty()
    candidates = [i for i in items if i.get("fullPath") != baseline_full_path]
    if not candidates:
        raise RuntimeError(
            "No comparison policies available — only the baseline policy was found."
        )
    choices = [
        questionary.Choice(i["fullPath"], value=i, checked=True)
        for i in candidates
    ]
    result = questionary.checkbox(
        "Select policies to audit (Space=toggle, a=all, Enter=confirm):",
        choices=choices,
    ).ask()
    if result is None:
        raise KeyboardInterrupt
    if not result:
        raise RuntimeError("No policies selected. At least one policy must be selected.")
    return result


def prompt_confirm(
    mode: str,
    baseline: Dict,
    target_policies: List[Dict],
    output_dir: str,
) -> bool:
    """Confirmation screen before starting the audit. Returns True to proceed."""
    _require_tty()
    print()
    print(f"  Mode:      {mode}")
    print(f"  Baseline:  {baseline.get('fullPath', '?')}")
    print(f"  Policies:  {len(target_policies)} selected")
    print(f"  Output:    {output_dir}")
    print()
    result = questionary.confirm("Proceed?", default=True).ask()
    if result is None:
        raise KeyboardInterrupt
    return bool(result)


# ── Orchestration ──────────────────────────────────────────────────────────────

def collect_run_parameters(
    all_items: List[Dict],
    output_dir: str,
    mode: str,
    baseline_policy: Optional[str] = None,
) -> Dict:
    """
    Collect audit parameters interactively or non-interactively.

    Parameters
    ----------
    all_items:
        Pre-fetched list of policy / profile metadata dicts (from PolicyExporter
        or BotDefenseAuditor). Each dict must have at least ``name`` and
        ``fullPath`` keys.
    output_dir:
        Output directory shown on the confirm screen.
    mode:
        Audit mode string — ``"WAF"`` or ``"BOT"``.
    baseline_policy:
        If provided (fullPath or tilde-encoded path), the function runs in
        non-interactive mode: it looks up the baseline in ``all_items`` and
        sets all remaining items as targets without prompting.

    Returns
    -------
    dict with keys ``mode`` (str), ``baseline`` (dict), ``target_policies`` (list[dict]).

    Raises
    ------
    RuntimeError
        No BST policies found, baseline not found, or no target policies.
    KeyboardInterrupt
        User aborted an interactive prompt.
    """
    # ── Non-interactive bypass ────────────────────────────────────────────────
    if baseline_policy:
        baseline = lookup_by_full_path(all_items, baseline_policy)
        if baseline is None:
            raise RuntimeError(
                f"Baseline policy '{baseline_policy}' not found on device. "
                "Check the --baseline-policy value and try again."
            )
        target_policies = [
            i for i in all_items if i.get("fullPath") != baseline.get("fullPath")
        ]
        return {"mode": mode, "baseline": baseline, "target_policies": target_policies}

    # ── Interactive flow ──────────────────────────────────────────────────────
    while True:
        baseline = prompt_baseline(all_items)
        target_policies = prompt_policies(all_items, baseline["fullPath"])
        if prompt_confirm(mode, baseline, target_policies, output_dir):
            break
        # User said "no" — loop back to baseline selection

    return {"mode": mode, "baseline": baseline, "target_policies": target_policies}
