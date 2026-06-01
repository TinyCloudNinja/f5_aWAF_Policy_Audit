# Implementation Plan — Interactive Mode + Git-Driven Policy Lifecycle

This plan assumes `REVIEW.md` findings are accepted as-is. Phase 0 bug fixes are
bundled into Step 1.1 of Phase 1 so each step can be reviewed as a unit.

---

## Phase 1 — Interactive TUI & Config Management

### Step 1.1 — Bug fixes from REVIEW.md (no new features)

**Files touched:** `src/main.py`, `src/bigip_client.py`, `src/utils.py`,
`src/report_generator.py`, `src/policy_exporter.py`

**Changes:**
- `main.py:273-276` — Fix inverted `verify_ssl` string-to-bool conversion
  (`in ("0","false","no")` → `in ("1","true","yes")`).
- `main.py:37` — Remove duplicate import line; keep line 39 only.
- `main.py:545,719` — Remove unused `iterable = successes` assignments.
- `main.py:1-18` — Fix garbled module docstring.
- `bigip_client.py:110` — Do NOT clear `self._password` in `authenticate()`;
  add a comment explaining the deliberate trade-off. Only zero it out in `close()`.
- `bigip_client.py:284-297` — Remove dead `_parse_content_range_total` helper.
- `utils.py:26-38` — Add regex pattern to `_MaskFilter` covering HTTPS credential
  URLs: `(https?://[^:@/\s]+:)[^@/\s]+(@)` → `\g<1>***MASKED***\g<2>`.
- `report_generator.py:623-807` — Remove dead first copy of `_build_policy_report_fragment`.
- `report_generator.py:838-945` — Remove dead first copy of `generate_html_dashboard`.
- `policy_exporter.py:561` — URL-encode `reported_filename` with
  `urllib.parse.quote(reported_filename, safe="")` before constructing `dl_path`.

**Tests:** Existing test suite must stay green. Add:
- `tests/test_utils.py` — Assert `_MaskFilter` masks a log record containing
  `https://user:secret@host/repo.git`.
- `tests/test_main_ssl.py` — Parameterised: `"true"` → `verify_ssl=True`,
  `"false"` → `verify_ssl=False`, `"1"` → `True`, `"0"` → `False`.

---

### Step 1.2 — `src/config_manager.py` — new module

**Files created:** `src/config_manager.py`

**Responsibilities:**
- `load_config(path: Optional[str]) -> AppConfig` — read YAML/JSON; migrate legacy
  flat `bigip:` block to `devices: [{name: "default", ...}]` automatically.
- `save_config(config: AppConfig, path: str) -> None` — write with `open(…, "w")`
  then `os.chmod(path, 0o600)`; raise `ValueError` if any device dict contains
  a `password` key (reject passwords on disk).
- `DeviceConfig`, `AuditConfig`, `GitConfig`, `BaselineConfig` typed dataclasses.
- `validate_config(config: AppConfig) -> List[str]` — returns list of error strings
  (empty = valid). Checks: required fields present, host is non-empty, no device has
  `password`, `concurrent_exports` in 1-20, etc.
- Backwards compat: if config contains `gitlab:` block but not `git:`, copy it to
  `git:` and emit a `DeprecationWarning` log line.
- Deprecation: `--gitlab-*` CLI flags continue to work; `main.py` emits a
  `DeprecationWarning("--gitlab-* flags are deprecated; use --git-* equivalents")`
  when they are used (but still honours them).

**Config schema changes:** Extend `config.yaml.example` with the new multi-device
and `git:` / `baselines:` blocks as specified in the task description.

**Tests:** `tests/test_config_manager.py`
- Legacy schema migration: flat `bigip:` block → `devices[0]` round-trip.
- Round-trip read/write: load example, mutate a field, save, reload, assert equality.
- Permission bits: after `save_config`, `stat(path).st_mode & 0o777 == 0o600`.
- Password rejection: `save_config` raises `ValueError` if any device has `password`.
- Deprecation warning: loading a `gitlab:` block emits a `DeprecationWarning`.
- `validate_config` returns an error for an empty host; returns empty list for valid config.

---

### Step 1.3 — Refactor `main.py` to source config through `config_manager`

**Files touched:** `src/main.py`

**Changes:**
- Replace `_load_config()` + ad-hoc `bigip_cfg.get(…)` calls with
  `config_manager.load_config(path)` returning a typed `AppConfig`.
- `_resolve()` stays but operates on typed fields, not raw dict lookups.
- Hoist `_PASS_THRESHOLD` into `AppConfig.audit.pass_threshold` with a 90.0 default;
  propagate it into `_print_summary()` and `report_generator` call sites.
- Per-device password env-var convention:
  `BIGIP_PASS__<NAME_UPPER_UNDERSCORE>` is tried first; `BIGIP_PASS` is the fallback.
- Add `--interactive` flag (bool, default `False`). If `--interactive` is present
  OR if no positional audit flags are given AND stdin is a TTY, enter interactive mode.

**No new tests** beyond checking the config integration path; existing tests cover CLI.

---

### Step 1.4 — `src/interactive.py` — new module

**Files created:** `src/interactive.py`

**Dependencies added to `requirements.txt`:** `questionary>=2.0`

**Architecture:** simple state machine — each screen is a function returning the
next screen name (`str`) or `None` to exit. A top-level `run_interactive(config_path)`
dispatches on the returned name.

**Screens / functions:**

| Function | Responsibility |
|---|---|
| `screen_main_menu()` | Top-level 7-option menu |
| `screen_run_audit()` | Device multi-select → mode → baseline source → partitions → format → confirm+run |
| `screen_manage_devices()` | Sub-menu: list / add / edit / remove / test |
| `screen_list_devices()` | Print table; return to parent |
| `screen_add_device()` | Guided form; optional reachability check; write config |
| `screen_edit_device()` | Pick one → field-by-field questionary prompts |
| `screen_remove_device()` | confirm(default=False) → write config |
| `screen_test_connection()` | Pick device → authenticate → fetch hostname → close |
| `screen_manage_git()` | Sub-menu: show / set URL+branch+dir / toggle auto-push / sync / status / author |
| `screen_git_sync()` | Call `GitLabStateManager.sync_from_remote()`; print result |
| `screen_review_pending()` | Phase 2 stub — prints "not yet implemented" |
| `screen_manage_baselines()` | Set `baselines.waf_fallback` and `baselines.bot_fallback` |
| `screen_view_last_run()` | Glob `output_dir/reports/` for dashboards; print table + offer browser open |

**Key implementation notes:**
- Non-TTY guard at module entry: `if not sys.stdin.isatty(): return` + hint.
- `questionary.password()` for prompts that touch credentials; result is never
  passed to `config_manager.save_config()`.
- "Run an audit" re-uses `_run_waf_audit()` / `_run_bot_audit()` from `main.py`
  unchanged; the interactive layer only assembles parameters.
- After an audit completes, offer `webbrowser.open(dashboard_path)`.
- Destructive operations (remove device, overwrite source-of-truth) use
  `questionary.confirm("Are you sure?", default=False)`.

**Tests:** `tests/test_interactive.py`
- Non-TTY short-circuit: with `sys.stdin` replaced by a non-TTY `StringIO`, calling
  `run_interactive()` returns immediately without prompting.
- `screen_test_connection` closes the `BigIPClient` after success and failure.
- Destructive operations do not proceed when `questionary.confirm` returns `False`
  (mock `questionary` to return `False`).

---

### Step 1.5 — Update `main.py` entry point

**Files touched:** `src/main.py`

**Changes:**
- At the top of `main()`: if interactive mode is selected (no audit flags + TTY, or
  `--interactive`), call `interactive.run_interactive(config_path)` and return its
  exit code.
- All existing flag paths unchanged; no flag removal.
- Add deprecation warnings for `--gitlab-*` flags (log, not hard error).

**No new tests** beyond the existing integration tests.

---

### Step 1.6 — `README.md` update for Phase 1

**Files touched:** `README.md`

**Content:** interactive-mode invocation, transcript-style screenshot of the main menu
and the "Run an audit" flow, config schema reference for the new `devices:` and `git:` blocks.

---

## Phase 2 — Git as Source of Truth & Change Acceptance Workflow

### Step 2.1 — `src/change_workflow.py` — new module

**Files created:** `src/change_workflow.py`

**Public API:**

```python
@dataclass
class PendingChange:
    change_id:      str          # SHA-256 of device|fullPath|normalised_target_content
    mode:           str          # "waf" | "bot"
    policy_path:    str
    device_hostname: str
    device_mgmt_ip:  str
    status:         str          # "NEW" | "CLEAN" | "DRIFTED"
    exported_file:  Path
    sot_file:       Optional[Path]
    score:          float
    summary:        Dict[str, int]   # critical/warning/info counts
    report_md:      Optional[Path]
    report_html:    Optional[Path]
    run_id:         str

@dataclass
class CommitResult:
    success: bool
    sha:     str
    message: str
    error:   str

def build_pending_manifest(
    results: List[ComparisonResult],
    exported_policies: List[Dict],      # enriched with local_path, fullPath
    output_dir: str,
    repo_dir: str,
    run_id: str,
    device_hostname: str,
    device_mgmt_ip: str,
) -> Path: ...

def load_pending_changes(repo_dir: str) -> List[PendingChange]: ...

def accept_change(
    change: PendingChange,
    commit_message: str,
    sign: bool = False,
    author_name: str = "",
    author_email: str = "",
) -> CommitResult: ...

def reject_change(change: PendingChange, reason: str) -> None: ...

def diff_change(change: PendingChange) -> str: ...

def canonicalize_xml(path: Path) -> str: ...

def canonicalize_json(path: Path) -> str: ...
```

**`change_id` computation:**
```
SHA-256( f"{device_hostname}|{policy_path}|{canonicalize_xml/json(exported_file)}" )
```
Stable across re-runs as long as device, policy path, and normalised content are
identical.

**Canonicalization:**
- `canonicalize_xml`: parse with `policy_parser._parse_tree`; serialize with
  `lxml.etree.tostring(sort_keys=False)` after sorting attributes; or with stdlib
  using `xml.etree.ElementTree.indent` + sorted attribute dicts. Falls back to
  stdlib if lxml absent.
- `canonicalize_json`: `json.dumps(json.load(fh), sort_keys=True, indent=2)`.

**Diff output:** `difflib.unified_diff` over canonicalized lines, context=5.

**`.auditor-state.json`** (gitignored, at repo root): tracks resolved change IDs.

```json
{
  "resolved": {
    "a3f…": {
      "action": "accepted" | "rejected",
      "at": "2026-04-24T14:30:00Z",
      "reason": "…",
      "commit": "abc123"
    }
  }
}
```

**Files touched:** also `src/gitlab_state.py` (add 3 methods):
- `commit_specific_paths(paths: List[str], message: str, sign: bool) -> str` (returns SHA)
- `has_uncommitted_at(path: str) -> bool`
- `current_branch() -> str`

**Tests:** `tests/test_change_workflow.py`
- `canonicalize_xml`: two semantically identical XMLs with reordered attributes
  produce identical output; whitespace-only reorder produces zero diff.
- `canonicalize_json`: sort_keys normalisation; nested dicts.
- `change_id` stability: same inputs → same ID; changing any field → different ID.
- `build_pending_manifest` on a synthetic result list writes a parseable JSON file.
- Classification: policy with no SoT file → `NEW`; matching export → `CLEAN`;
  differing export → `DRIFTED`.
- `accept_change` (git-init temp dir fixture, no network):
  writes exported file over SoT path; makes exactly one commit touching exactly
  that path; updates `.auditor-state.json`.
- `reject_change`: working tree clean afterwards; `.auditor-state.json` updated.
- XML/JSON diff: known drift produces non-empty diff; identical files produce empty diff.

---

### Step 2.2 — Integrate change classification into the WAF/BOT audit workflows

**Files touched:** `src/main.py`, `src/gitlab_state.py`

**Changes:**

1. In `_run_waf_audit()` and `_run_bot_audit()`, after the per-policy comparison loop:
   - If `gitlab_state is not None`, classify each policy as `NEW` / `CLEAN` / `DRIFTED`
     by calling `change_workflow.classify_result(cmp_result, sot_file_path)`.
   - Call `change_workflow.build_pending_manifest(…)` to write
     `runs/<mode>/<run_id>/pending_changes.json`.
   - Do **not** auto-commit SoT files (except when `--gitlab-update-source-truth` is
     passed, which keeps CI/batch behaviour intact with the existing flag).

2. `gitlab_state.archive_run()` already copies reports; extend it to also copy
   `pending_changes.json` if present.

3. `sync_from_remote()` change: after `pull --ff-only`, if the pull fails because the
   branch has diverged, log an error and return `False` (abort, don't merge). Existing
   behaviour is `check=False` on the pull, which silently ignores divergence.

**Tests:** integration test in `tests/test_main_integration.py` (temp-dir fixture,
mocked `BigIPClient`):
- With SoT absent: manifest contains `"status": "NEW"`.
- With matching SoT: manifest contains `"status": "CLEAN"`.
- With differing SoT: manifest contains `"status": "DRIFTED"` and non-zero summary counts.

---

### Step 2.3 — "Review pending changes" interactive screen

**Files touched:** `src/interactive.py`

**Replaces** the Phase 1 stub `screen_review_pending()`.

**Flow:**
1. Load all unresolved `PendingChange` items via `change_workflow.load_pending_changes(repo_dir)`.
2. For each change (sorted: DRIFTED first, then NEW, then CLEAN), display a summary line.
3. Present an action menu: Accept / Reject / View report / Diff / Skip / Quit.
4. **Accept:** `questionary.text()` pre-filled with the default commit message;
   offer `questionary.confirm("Open $EDITOR for a longer message?")`;
   call `change_workflow.accept_change(…)`;
   if `auto_push` is off, print the `git push` command.
5. **Reject:** `questionary.text("Reason:")` → `change_workflow.reject_change(…)`.
6. **View report:** `webbrowser.open(str(change.report_html))`.
7. **Diff:** call `change_workflow.diff_change(change)` → print paginated with
   Python's `pydoc.pager`.
8. **Skip:** advance to the next item.
9. Batch actions at the end of the list:
   - "Accept all NEW (first-run import)" — behind `questionary.confirm(default=False)`.
   - "Accept all DRIFTED from this device" — behind confirm.

---

### Step 2.4 — CLI non-interactive equivalents

**Files touched:** `src/main.py`

**New flags:**

| Flag | Behaviour |
|---|---|
| `--review-pending` | Load and print pending list; exit 2 if any unresolved changes exist |
| `--accept-change <change_id>` | Accept a single change; requires `--message "…"` |
| `--accept-all-clean` | Accept all NEW imports; requires `--yes` |
| `--yes` | Suppress confirmation prompts (CI use) |

These flags are mutually exclusive with the existing `--WAF` / `--BOT` audit triggers
(checked in `_build_parser()`).

**Tests:** `tests/test_cli_phase2.py`
- `--review-pending` with no pending changes → exit 0.
- `--review-pending` with one DRIFTED change → exit 2.
- `--accept-change <id> --message "msg"` → calls `accept_change` exactly once.
- `--accept-all-clean` without `--yes` → error message, no action.

---

### Step 2.5 — `README.md` update for Phase 2

**Files touched:** `README.md`

**Content:** explain the NEW / CLEAN / DRIFTED run lifecycle; transcript of the
review-pending TUI flow (Accept, Reject, Diff); the CLI non-interactive equivalents;
`.auditor-state.json` schema reference; the `pending_changes.json` manifest schema.

---

## Cross-phase constraints (checklist for every PR)

- [ ] No new `Any` return types on public functions.
- [ ] All new public functions have full type hints.
- [ ] `get_logger(…)` used for every new log line; no bare `print()` in library code.
- [ ] `_MaskFilter` coverage: any new log line that formats a dict potentially
      containing credentials has a targeted test.
- [ ] `ensure_dir()` used for every new output directory; no bare `os.makedirs`.
- [ ] No password stored or written to disk (tested in `test_config_manager.py`).
- [ ] `questionary` is the only new dependency; no Textual, Rich, Typer, Click.
- [ ] `lxml` optional: new canonicalization helpers work with the stdlib fallback.
- [ ] Existing CLI flags unchanged and tested end-to-end with the existing fixture set.
- [ ] `--gitlab-*` flags emit a `DeprecationWarning` but remain functional.

---

# New Refactor: API-Driven Data Collection + Interactive TUI

> **Scope:** Eliminate the on-disk XML baseline dependency; replace partial
> `PolicyInspector` data collection with full API-driven `PolicyFetcher`;
> introduce a `questionary`-based interactive TUI. Phases below are sequential;
> stop after Phase 0 for review.

---

## Module Changes Summary

| Module | Change | Reason |
|---|---|---|
| `src/main.py` | **Modified** | New CLI contract, interactive dispatch, updated run loop, error handling |
| `src/bigip_client.py` | **Modified** | Add `get_all()` pagination helper |
| `src/policy_exporter.py` | **Retained** | Policy discovery + VS enrichment unchanged |
| `src/policy_parser.py` | **Deprecated** → `src/_deprecated/policy_parser.py` | Replaced by API fetcher; kept for `gitlab_state.py` compat during transition |
| `src/policy_inspector.py` | **Retained (for `--INSPECT` mode)** | Superseded for WAF/BOT audit by `policy_fetcher.py`; keep for targeted inspection |
| `src/policy_comparator.py` | **Modified** | Field-access alignment with new API dict schema; no logic changes |
| `src/bot_defense_auditor.py` | **Retained / Wrapped** | `list_bot_profiles()` extracted to `policy_fetcher.py`; full fetch logic reused |
| `src/bot_defense_comparator.py` | **Retained** | No changes; comparison logic is data-format-agnostic |
| `src/report_generator.py` | **Retained** | No changes; `_XML_VIOL_ID_ALIASES` import moved to `utils.py` in Phase 4 |
| `src/gitlab_state.py` | **Modified** | `load_waf_source_of_truth()` uses JSON fallback; XML parse kept as legacy fallback |
| `src/utils.py` | **Retained** | Minor: HTTPS URL masking regex (if not already fixed) |
| `src/virtual_server_inventory.py` | **Retained** | No changes |
| `src/interactive.py` | **New** | `questionary`-based interactive menus; importable without a TTY |
| `src/policy_fetcher.py` | **New** | Full API-driven WAF + Bot data collection pipeline |

---

## Phase 0 — Audit & Plan (Complete — No Code Changes)

**Deliverables:** Updated `REVIEW.md` (Sections A–E) and this `PLAN.md` section.

**Test status:** 164/164 pass. Zero failures recorded.

**Key findings:**
- No XML export task (`/mgmt/tm/asm/tasks/export-policy`) exists in current code — it was removed in a prior refactor. `bigip_client.download_file()` and `upload_file()` exist but are uncalled.
- The remaining XML dependency is solely the on-disk `--baseline` file parsed by `policy_parser.parse_policy()`.
- `policy_parser.py` is also used by `gitlab_state.load_waf_source_of_truth()` for XML SoT files.
- `report_generator.py` imports `_XML_VIOL_ID_ALIASES` from `policy_parser`; this must be moved to `utils.py` in Phase 4.
- `questionary>=2.0` is the selected interactive library (see REVIEW.md Section D).
- SSL inversion bug (`main.py:405–409`) and token refresh credential-clearing bug (`bigip_client.py:110`) remain unresolved from prior REVIEW.md.

---

## Phase 1 — Interactive Entry Point

### 1.1 CLI Contract Change

**Files:** `src/main.py`

**New minimum invocation:**
```bash
python -m src.main --host 10.1.1.4 --username admin
```

**Full non-interactive (CI) invocation:**
```bash
python -m src.main \
  --host 10.1.1.4 --username admin \
  --password 'S3cret!' \
  --mode WAF \
  --baseline-policy "~Common~BST_Corporate_Baseline_v2" \
  --output-dir ./audit_results \
  --no-verify-ssl
```

**Flags removed:**
- `--baseline` (filesystem path) — replaced by `--baseline-policy` (API name)
- `--partitions` — auto-discovered
- `--concurrent-exports` — no longer relevant
- `--WAF` / `--BOT` / `--INSPECT` — replaced by `--mode {WAF,BOT,INSPECT}`
- `--export-format` — removed entirely

**Flags preserved:**
- `--output-dir`, `--no-verify-ssl` / `--verify-ssl`, `--verbose` / `-v`, `--format`

**Flags added:**
- `--mode {WAF,BOT,INSPECT}` — non-interactive mode selection
- `--baseline-policy` — non-interactive baseline policy fullPath/name
- `--password` — non-interactive password (still optional; interactive fallback)

**Non-interactive bypass rule:** If `--mode`, `--baseline-policy`, and
`--password` are ALL provided, skip all `questionary` prompts.

**Fix bundled into Phase 1:**
- SSL inversion bug (`main.py:405–409`): `in ("0", "false", "no")` → `in ("1", "true", "yes")`

### 1.2 New module: `src/interactive.py`

**Dependencies added:** `questionary>=2.0` → `requirements.txt`

**Public API:**

```python
BASELINE_PREFIX = "BST"   # top-level constant — configurable, never hardcoded

def run_interactive(
    host: str,
    username: str,
    output_dir: str,
    verify_ssl: bool,
    report_format: str,
    verbose: bool,
) -> int:
    """Top-level interactive flow. Returns exit code."""

def prompt_password(username: str, host: str) -> str: ...
def prompt_mode() -> str:              # "WAF" | "BOT"
def prompt_baseline(
    client: BigIPClient, mode: str
) -> dict:                             # selected policy/profile metadata dict
def prompt_policies(
    client: BigIPClient, mode: str, baseline_full_path: str
) -> list[dict]:                       # selected policy/profile metadata dicts
def prompt_confirm(
    mode: str, baseline: dict, policies: list[dict], output_dir: str
) -> bool: ...
```

**Interactive flow:**

1. Password prompt (`questionary.password()`) if `--password` not supplied.
2. Connect & authenticate; print `✓ Connected to BIG-IP {host} ({version})`.
3. Mode menu (`questionary.select()`): WAF / Bot Defense.
4. Baseline candidates: `GET /mgmt/tm/asm/policies?$select=name,fullPath,id&$top=500`
   filtered to `name.upper().startswith(BASELINE_PREFIX)`, sorted alphabetically.
   Display as arrow-key list. Exit 1 if no BST policies found.
5. Comparison policy candidates: same endpoint, exclude baseline, display as
   `questionary.checkbox()` multi-select. Space=toggle, `a`=all.
6. Confirm screen: print Mode/Baseline/Policies/Output. `questionary.confirm("Proceed?")`.
   If No, loop back to step 3.

**Non-TTY guard:** `if not sys.stdin.isatty(): raise RuntimeError("not a TTY")`
at module entry; call sites catch and fall through to non-interactive path.

**Tests:** `tests/test_interactive.py`
- Mock `questionary.select`, `questionary.checkbox`, `questionary.password`.
- Assert BST filter excludes non-BST policies (case-insensitive).
- Assert non-interactive mode (all flags provided) calls none of the prompts.
- Assert `BASELINE_PREFIX` constant is "BST" and is used by the filter function.
- Assert non-TTY raises gracefully.

---

## Phase 2 — API-Driven Data Collection

### 2.1 New module: `src/policy_fetcher.py`

**Public API:**

```python
class PolicyFetcher:
    def __init__(self, client: BigIPClient): ...

    def list_waf_policies(self) -> list[dict]:
        """[{name, fullPath, id, enforcementMode, active}]"""

    def list_bot_profiles(self) -> list[dict]:
        """[{name, fullPath}]"""

    def fetch_waf_policy(self, policy_id: str) -> dict:
        """Fetch all comparable WAF policy data. Returns normalized dict."""

    def fetch_bot_profile(self, profile_full_path: str) -> dict:
        """Fetch all comparable Bot Defense profile data. Returns normalized dict."""
```

**WAF policy fetch — all sub-resources (paginated):**

| Sub-resource path | Key fields |
|---|---|
| `/general` | `enforcementMode`, `applicationLanguage`, `trustXff`, `responseLogging`, `signatureStaging`, `maskCreditCardNumbers`, `placeSignaturesInStaging` |
| `/blocking-settings/violations` | `name`, `description`, `alarm`, `block`, `learn` |
| `/blocking-settings/evasions` | `description`, `enabled` |
| `/blocking-settings/http-protocols` | `description`, `enabled` |
| `/blocking-settings/web-services-securities` | `description`, `enabled` |
| `/signature-sets` | `name`, `alarm`, `block`, `learn`, `signatureSet.name` |
| `/signatures` | `signatureReference.name`, `enabled`, `performStaging`, `alarmState` |
| `/urls` | `name`, `method`, `type`, `attackSignaturesCheck`, `performStaging`, `isAllowed` |
| `/filetypes` | `name`, `type`, `queryStringLength`, `requestLength`, `responseCheck`, `attackSignaturesCheck` |
| `/parameters` | `name`, `type`, `sensitiveParameter`, `attackSignaturesCheck`, `performStaging`, `valueType` |
| `/headers` | `name`, `checkSignatures`, `mandatory`, `allowRepeatedOccurrences` |
| `/cookies` | `name`, `enforcementType`, `attackSignaturesCheck`, `performStaging` |
| `/methods` | `name`, `actAsMethod` |
| `/data-guard` | `enabled`, `creditCardNumbers`, `usSocialSecurityNumbers`, `customPatterns`, `exceptionPatterns` |
| `/ip-intelligence` | `enabled`, `defaultAction`, categories |
| `/whitelist-ips` | `blockRequests`, `trustedByPolicyBuilder`, `ignoreAnomalies`, `ipAddress`, `ipMask` |
| `/login-pages` | `url`, `authenticationType`, `usernameParameterName` |
| `/brute-force-attack-preventions` | `url`, `maximumLoginAttempts`, `preventionDuration` |
| `/json-profiles` | `name`, defenseAttributes |
| `/xml-profiles` | `name`, defenseAttributes |
| `/plain-text-profiles` | `name`, defenseAttributes |
| `/session-tracking` | `sessionTrackingConfiguration` |

**Normalized WAF dict schema** (must be compatible with `policy_comparator.compare_policies()`):

```python
{
    # Top-level metadata
    "name": str, "fullPath": str, "id": str,
    "enforcementMode": str,        # "blocking" | "transparent"
    "applicationLanguage": str,
    "active": bool,
    "signatureStaging": bool,
    "trustXff": bool,
    "responseLogging": str,
    "maskCreditCardNumbers": bool,
    # Comparator-facing sections (keyed to match policy_parser output)
    "general": {"enforcementMode": str, "signatureStaging": bool, ...},
    "blocking-settings": {
        "violations": [{"name": str, "description": str, "alarm": bool, "block": bool, "learn": bool}],
        "evasions":   [{"description": str, "enabled": bool}],
        "http-protocols": [{"description": str, "enabled": bool}],
    },
    "blocking": {},               # left empty; comparator skips if empty
    "signature-sets": [{"name": str, "alarm": bool, "block": bool, "learn": bool}],
    "attack-signatures": [],      # policy-level overrides only
    "urls": [...], "filetypes": [...], "parameters": [...],
    "headers": [...], "cookies": [...], "methods": [...],
    "data-guard": {...}, "ip-intelligence": {...},
    "whitelist-ips": [...], "login-pages": [...],
    "brute-force": [...], "policy-builder": {},
    "bot-defense": {},
}
```

**Field alignment note:** `policy_comparator._cmp_blocking()` checks
`baseline.get("blocking", {})`. Since the new dict leaves `"blocking"` empty,
that comparator branch silently skips — correct behavior. All violations come
through `"blocking-settings".violations` which `_cmp_blocking_settings()`
already handles. No logic changes needed in the comparator; only verify that
`"blocking-settings"` key is present with the correct structure.

### 2.2 `get_all()` pagination helper — `src/bigip_client.py`

Add as a public method:

```python
def get_all(self, path: str, params: dict | None = None) -> list:
    """Fetch all pages from a paged iControl REST collection.
    Uses $top=500 and $skip pagination. Raises on HTTP errors."""
    params = dict(params or {})
    params.setdefault("$top", 500)
    items: list = []
    skip = 0
    while True:
        params["$skip"] = skip
        data = self.get(path, params=params)
        page = data.get("items", [])
        items.extend(page)
        total = data.get("totalItems", len(items))
        if len(items) >= total:
            break
        skip += len(page)
        if not page:
            break          # safety: prevent infinite loop on empty page
    return items
```

### 2.3 Deprecate `src/policy_parser.py`

Move to `src/_deprecated/policy_parser.py`. Add at the top of the file:

```python
import warnings
warnings.warn(
    "policy_parser is deprecated. Use PolicyFetcher.fetch_waf_policy() instead.",
    DeprecationWarning, stacklevel=2,
)
```

Update `src/gitlab_state.py` to import from `src._deprecated.policy_parser`
and add a comment marking the import as transitional.

`report_generator.py` imports `_XML_VIOL_ID_ALIASES` — this dict is small and
pure data; copy it into `utils.py` and update the import in Phase 4.

### 2.4 `gitlab_state.load_waf_source_of_truth()` update

After Phase 2, new SoT files are JSON (the normalized API dict). Existing SoT
files may be XML. Update `load_waf_source_of_truth()` to:

1. Try reading `<path>.json` first.
2. Fall back to `<path>.xml` + `parse_policy()` if JSON not found.
3. Log a migration hint when XML fallback is used.

**Tests:**
- `tests/test_policy_fetcher.py`: mock `BigIPClient.get()`; test pagination
  (mock `totalItems=700` → 2 calls); test empty items; test WAF and Bot
  normalization round-trip.
- All 164 existing tests must continue to pass after schema alignment.

---

## Phase 3 — Progress Display & Orchestration

### 3.1 Updated run loop in `main.py`

```
1. Fetch baseline policy data via PolicyFetcher.
   Print: "✓ Baseline fetched: <fullPath> (N violations, M sig sets)"

2. For each selected comparison policy (with [N/M] counter):
   a. PolicyFetcher.fetch_waf_policy() or fetch_bot_profile()
   b. compare_policies() / compare_bot_profiles()
   c. generate_markdown() if format includes markdown
   Print per-policy: "  [1/3] <fullPath>  87.4%  ⚠  14 diffs"

3. generate_html_dashboard() once for all results.
   Print: "✓ Dashboard → <output_dir>/WAF_audit_dashboard.html"

4. generate_summary_reports()
5. Print final summary table to stdout.
6. Exit 0 if all scores ≥ threshold, else exit 1.
```

### 3.2 Error handling

| Condition | Behavior |
|---|---|
| Baseline fetch fails (404, timeout) | Abort, exit 1, clear message |
| Policy fetch fails | Log error, mark `status: "fetch_failed"`, continue |
| All policies fail | Exit 2 |
| `KeyboardInterrupt` | Print `\nAborted.`, exit 130 |

**Tests:** `tests/test_main_phase3.py`
- Mock one policy fetch to raise — assert others still run.
- Baseline fetch raises → exit 1.
- KeyboardInterrupt at top-level loop → exit 130.

---

## Phase 4 — Cleanup & Testing

### 4.1 Remove dead code

| Item | Action |
|---|---|
| `src/_deprecated/policy_parser.py` | Delete after `gitlab_state.py` JSON migration complete |
| `bigip_client.upload_file()` | Delete (unused) |
| `bigip_client.download_file()` | Delete (unused) |
| `bigip_client._parse_content_range_total()` | Delete (dead code, noted in REVIEW.md) |
| `--concurrent-exports` CLI flag | Remove |
| `import xml.etree.ElementTree as ET` in `main.py` | Remove once `_validate_xml()` deleted |
| `_validate_xml()` in `main.py` | Remove |
| `_load_json_baseline()` in `main.py` | Remove (BOT baseline is now API-driven) |

### 4.2 Update tests

- Update all test fixtures that used XML-parsed dicts to use API-normalized dicts
  (structure is identical after Phase 2 schema alignment; only source changes).
- Add Bot Defense comparison unit tests:
  - `enforcement` diff: baseline=`blocking`, target=`transparent` → CRITICAL.
  - Bot class action diff: baseline blocks, target allows → CRITICAL.
  - Whitelist entry in target not in baseline → WARNING.
- Run full suite; confirm 164+ green.

### 4.3 Update documentation

- `README.md`: new invocation pattern, interactive session transcript.
- `APP_REVIEW_FOR_AI.md`: updated module list with `policy_fetcher.py` and `interactive.py`.
- `CHANGELOG.md`: entry for this refactor.

---

## Non-Negotiable Constraints (Checklist)

- [ ] **Read-only:** After refactor, all BIG-IP HTTP is GET only.
- [ ] **No credentials on disk:** Password only from `--password`, `BIGIP_PASS` env, or interactive prompt.
- [ ] **SSL default = False** with visible warning; `--verify-ssl` enables. Fix inversion bug in Phase 1.
- [ ] **Token auth preserved;** fix credential-clearing bug (keep `self._password` until `close()`).
- [ ] **`get_all()` pages until `totalItems` exhausted.** Never assume single page.
- [ ] **`BASELINE_PREFIX = "BST"`** constant in `interactive.py`; case-insensitive; configurable.
- [ ] **BOT_DEFENSE_LICENSED guard:** catch 404, print clear message, exit 1 cleanly.
- [ ] **Python 3.10+.** No `match/case` unless already in codebase (currently not used).
- [ ] **Approved new deps:** `questionary>=2.0`, `tqdm` (optional progress bar). No others.
- [ ] **Stop after Phase 0** — do not proceed to Phase 1 without review confirmation.
