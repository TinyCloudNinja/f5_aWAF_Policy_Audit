# Changelog

All notable changes to the F5 BIG-IP ASM/AWAF Security Policy Auditor are
documented here. Entries are ordered newest-first within each version.

---

## [Unreleased] — Full API-Driven Interactive Mode Refactor

### Added

- **`src/interactive.py`** — `questionary`-based interactive TUI for TTY sessions.
  Presents arrow-key menus for mode selection, baseline selection (BST-prefixed
  policies from the device), and checkbox multi-select for target policies.
  `BASELINE_PREFIX = "BST"` constant at top of file; case-insensitive prefix match.
  Non-TTY guard raises `RuntimeError` cleanly so non-interactive callers can proceed.

- **`src/policy_fetcher.py`** — Full API-driven WAF policy and Bot Defense profile
  data collection. Replaces the XML export workflow with targeted iControl REST calls.
  `fetch_waf_policy()` fetches 15+ sub-resources concurrently via `ThreadPoolExecutor`.
  `fetch_all_waf()` fans out across all policies. `list_waf_policies()` and
  `list_bot_profiles()` support partition filtering. `list_bot_profiles()` guards
  against 404 (module not licensed).

- **`BigIPClient.get_all()`** — OData `$top`/`$skip` pagination helper. Pages until
  `totalItems` is exhausted; safety break on empty-page response.

- **`--mode {WAF,BOT,INSPECT}`** — Replaces the old `--WAF`, `--BOT`, `--INSPECT`
  boolean flags with a single mode flag. Prompted interactively on a TTY when omitted.

- **`--baseline-policy FULLPATH`** — Replaces the old `--baseline` filesystem path.
  Baseline is now selected live from the device by its `fullPath`. Prompted
  interactively on a TTY when omitted.

- **`--password`** — Optional CLI flag for non-interactive/CI use. Still accepts
  `BIGIP_PASS` env var and interactive prompt as preferred alternatives.

- **`--pass-threshold N`** — Green tier lower bound (default 90.0). Shifts only the
  Yellow/Green boundary; other tier bands remain fixed.

- **`--fail-on-tier {RED,AMBER,YELLOW,GREEN}`** — Tier that triggers a non-zero exit
  code (default RED). Enables AMBER-fail or YELLOW-fail CI policies.

- **4-tier compliance model**: RED (0–49), AMBER (50–74), YELLOW (75–89), GREEN (90–100).
  Per-policy progress line prints tier emoji + label + diff count.

- **Per-policy/profile progress display**: `[N/M] <fullPath>  score%  emoji tier  diffs`
  printed for each target as it is fetched and compared.

- **Baseline fetch confirmation**: `✓ Baseline fetched: <path>  (N violations, M sig sets)`.

- **Dashboard path confirmation**: `✓ Dashboard → <path>` after HTML generation.

- **`src/_deprecated/policy_parser.py`** — Original XML parser moved here with
  `DeprecationWarning` at import. Retained solely for `gitlab_state.py` XML SoT
  fallback. Not used by the main audit workflow.

- **`src/_deprecated/__init__.py`** — Makes `_deprecated` a proper package.

- **`_XML_VIOL_ID_ALIASES`** in `src/utils.py` — Violation ID rename table (moved
  from the deprecated parser module; now the canonical location).

- **JSON-first SoT lookup** in `gitlab_state.load_waf_source_of_truth()` — tries
  `<path>.json` before falling back to `<path>.xml` with a migration hint.

- **`tests/test_interactive.py`** — 21 tests covering BST filter, case-insensitivity,
  `collect_run_parameters()` non-interactive bypass, non-TTY guard.

- **`tests/test_main_ssl.py`** — 14 parametrized tests for the SSL string-to-bool fix.

- **`tests/test_policy_fetcher.py`** — 26 tests covering pagination (two-page,
  empty, safety break), normalization helpers, `list_waf_policies`, `list_bot_profiles`
  (404 guard), and `fetch_waf_policy`.

- **`tests/test_main_phase3.py`** — 6 tests covering one-fetch-fails-continues,
  all-fail→exit-2, baseline-exception→exit-1, baseline-timeout→exit-1,
  `KeyboardInterrupt`→exit-130.

- **`questionary>=2.0`** added to `requirements.txt`.

### Changed

- **`src/main.py`** — Major refactor across Phases 1–3:
  - Replaced `--WAF`/`--BOT`/`--INSPECT` with `--mode`.
  - Replaced `--baseline` (filesystem path) with `--baseline-policy` (API fullPath).
  - Removed `--partitions`, `--concurrent-exports`, `--export-format`.
  - `_run_waf_audit()` rewritten to use `PolicyFetcher` for full API-driven collection.
  - `_run_bot_audit()` updated with per-profile progress display and dashboard path print.
  - `_run_inspect_audit()` retained unchanged.
  - `_inspector_to_target_dict()` and `_reduce_baseline_for_inspector()` retained for SoT comparison compatibility.
  - Interactive password/mode prompts via `interactive.py` when TTY and flags absent.
  - `KeyboardInterrupt` at dispatch level → exit 130.

- **`src/bigip_client.py`** — Phase 1 + Phase 4:
  - Fixed credential-clearing bug: `self._password = ""` moved from `authenticate()` to `close()`.
  - Added `get_all()` pagination method (Phase 2).
  - Removed `upload_file()`, `download_file()`, `_parse_content_range_total()`, `_CHUNK_SIZE`, `_MAX_DOWNLOAD`, `_TRANSFER_TIMEOUT` (Phase 4 cleanup).

- **`src/policy_parser.py`** — Replaced with backward-compat stub in Phase 2; deleted entirely in Phase 4. Callers now import from `src._deprecated.policy_parser` directly.

- **`src/report_generator.py`** — Updated `_XML_VIOL_ID_ALIASES` import source from `.policy_parser` to `.utils`.

- **`src/gitlab_state.py`** — Updated import from `._deprecated.policy_parser`; updated `load_waf_source_of_truth()` to try JSON before XML.

- **`tests/test_policy_parser.py`** and **`tests/test_policy_comparator.py`** — Updated imports to use `src._deprecated.policy_parser` directly.

- **`src/utils.py`** — Added `Dict` to typing imports; added `_XML_VIOL_ID_ALIASES`.

### Fixed

- **SSL inversion bug** (`main.py`): `in ("0","false","no")` (truthy for "true") was
  reversed. Fixed to `in ("1","true","yes")`. `VERIFY_SSL=true` now correctly enables
  verification.

- **Token refresh credential-clearing bug** (`bigip_client.py`): `self._password = ""`
  was called in `authenticate()`, wiping the password before the first token refresh
  could reuse it. Moved to `close()`.

### Removed

- `--WAF`, `--BOT`, `--INSPECT` boolean flags (use `--mode WAF/BOT/INSPECT`).
- `--baseline` filesystem path flag (use `--baseline-policy` with device fullPath).
- `--partitions` flag (partitions are auto-discovered).
- `--concurrent-exports` flag (no longer relevant; no export tasks).
- `--export-format` flag (no longer relevant; no XML exports).
- `bigip_client.upload_file()`, `download_file()`, `_parse_content_range_total()` (unused dead code).
- `src/policy_parser.py` public stub (moved implementation to `_deprecated/`).

---

## Previous state (pre-refactor baseline)

- XML-export-based WAF audit workflow using `policy_exporter.py` export tasks and
  `policy_parser.py` XML parsing.
- On-disk `--baseline` XML file required for WAF audits; `--baseline` JSON for BOT.
- `PolicyInspector`-based data collection (partial: enforcement mode + violations + sig sets only).
- `--WAF`, `--BOT`, `--INSPECT` mode flags; `--partitions`, `--concurrent-exports`.
- 231 tests passing at refactor baseline.
