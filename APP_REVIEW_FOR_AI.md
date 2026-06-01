# Application Review for AI Systems

## 1) What this app is

**Name:** F5 BIG-IP ASM/AWAF Security Policy Auditor
**Type:** Python CLI security-audit tool
**Primary goal:** Read-only compliance/drift auditing of F5 BIG-IP configurations against approved baselines, fully API-driven with no on-disk baseline files required.

The app supports three audit modes:

- **WAF mode (`--mode WAF`)**: discovers ASM/AWAF security policies, fetches each
  policy's full configuration via the REST API (no XML export), compares to a
  BST-prefixed baseline policy selected from the device, and scores drift.
- **Bot Defense mode (`--mode BOT`)**: discovers Bot Defense profiles, fetches and
  expands profile JSON, compares to a BST-prefixed baseline profile selected from
  the device, and scores drift.
- **Inspect mode (`--mode INSPECT`)**: fast targeted REST inspection; no baseline
  required. Produces a JSON snapshot of key settings for every policy.

It can optionally integrate with a Git-backed policy-state repository to:

- load per-policy/profile source-of-truth JSON files,
- archive run artifacts (reports + run manifest),
- optionally update source-of-truth files from current device state.

---

## 2) Core behavior and guarantees

- **100% read-only on BIG-IP**: every request after the initial login POST is a
  GET. No export tasks, no file uploads, no POST/PUT/PATCH/DELETE.
- **No on-disk baseline files**: baselines are fetched live from the device.
  Baseline selection uses a naming convention (`BST` prefix, configurable).
- **Produces evidence artifacts**: per-policy/profile markdown reports and one
  interactive HTML dashboard per run.
- **Scoring model** starts at 100 and deducts by severity
  (`Critical`, `High`, `Warning`, `Info`).
- **4-tier compliance model**: RED (0–49), AMBER (50–74), YELLOW (75–89), GREEN (90–100).

---

## 3) High-level architecture (src)

- `src/main.py`
  - CLI entrypoint, argument parsing, CLI/env/config-file precedence, mode dispatch.
  - Orchestrates end-to-end workflows for WAF, BOT, and INSPECT audits.
  - Interactive mode: if `--mode`, `--baseline-policy`, and `--password` are all
    absent and stdin is a TTY, delegates to `interactive.collect_run_parameters()`.

- `src/bigip_client.py`
  - BIG-IP iControl REST client wrapper.
  - Handles token-based auth, proactive refresh at 80% of token lifetime,
    request/retry with exponential backoff.
  - `get_all()` — OData `$top`/`$skip` pagination helper used by all collection endpoints.
  - No file transfer methods (upload/download removed in Phase 4 cleanup).

- `src/interactive.py`
  - `questionary`-based interactive TUI (TTY-only; raises `RuntimeError` on non-TTY).
  - `BASELINE_PREFIX = "BST"` constant — controls which policies appear as baseline candidates.
  - `collect_run_parameters()` — main entry point; handles both interactive and
    non-interactive (all-flags-provided) code paths.
  - `filter_baselines()`, `lookup_by_full_path()`, `prompt_baseline()`,
    `prompt_policies()`, `prompt_confirm()`.

- `src/policy_fetcher.py`
  - Full API-driven WAF policy and Bot Defense profile data collection.
  - `fetch_waf_policy(policy)` — fetches 15+ sub-resources concurrently via
    `ThreadPoolExecutor`; returns a normalized dict compatible with
    `policy_comparator.compare_policies()`.
  - `fetch_all_waf(policies)` — thread-pool fan-out across all target policies.
  - `list_waf_policies()`, `list_bot_profiles()` — discovery with partition filtering.
  - Normalization helpers: `_normalize_violations()`, `_normalize_bool_items()`,
    `_normalize_signature_sets()`, `_normalize_whitelist_ips()`,
    `_normalize_data_guard()`, `_normalize_ip_intelligence()`.

- `src/policy_exporter.py`
  - WAF policy discovery (`discover_policies()`), partition discovery, device info fetch.
  - Enriches policy metadata with virtual server / LTM rule context.
  - No longer exports XML files; retained for discovery and VS enrichment.

- `src/policy_inspector.py`
  - Fast targeted REST inspection for `--mode INSPECT`.
  - Retained as-is; superseded by `policy_fetcher.py` for WAF/BOT audit modes.

- `src/policy_comparator.py`
  - WAF diff engine.
  - Produces `ComparisonResult` + `DiffItem` findings, summary counts, and score.
  - Consumes the normalized dict schema produced by `policy_fetcher.fetch_waf_policy()`.

- `src/bot_defense_auditor.py`
  - Bot Defense profile discovery, fetch, and sub-collection expansion.
  - `fetch_all()` — thread-pool fan-out for batch profile fetching.

- `src/bot_defense_comparator.py`
  - Bot Defense diff engine.

- `src/report_generator.py`
  - Generates per-policy/profile Markdown reports, summary Markdown, and one
    interactive multi-policy HTML dashboard per run.

- `src/gitlab_state.py`
  - Git-backed state manager (named GitLab but implemented via git CLI).
  - `load_waf_source_of_truth()` — tries JSON first (API-normalized), falls back
    to XML (legacy SoT files) with a migration hint.
  - Sync, source-of-truth load/update, run archival, optional commit/push.

- `src/virtual_server_inventory.py`
  - Read-only VS + LTM policy / host-condition mapping.

- `src/utils.py`
  - Logging with credential masking (`_MaskFilter`), retry decorator, filesystem
    helpers, compliance tier constants (`TIER_RED/AMBER/YELLOW/GREEN`),
    `score_to_tier()`, and `_XML_VIOL_ID_ALIASES` (violation ID rename table
    used by XML SoT fallback).

- `src/_deprecated/policy_parser.py`
  - XML ASM policy parser — retained **only** for `gitlab_state.py`'s XML
    source-of-truth fallback (legacy SoT files).
  - Emits a `DeprecationWarning` at import time.
  - Not used by the main audit workflow; new audit data comes via `policy_fetcher.py`.

---

## 4) Main execution flows

### WAF flow (current)

1. Resolve runtime settings from CLI > environment > config file.
2. Authenticate to BIG-IP (token-based; refresh at 80% lifetime).
3. Discover policies across partitions via `PolicyExporter.discover_policies()`.
4. Enrich policies with VS/LTM context.
5. Select baseline and target policies:
   - Interactive: `interactive.collect_run_parameters()` via `questionary` menus.
   - Non-interactive: look up `--baseline-policy` by `fullPath`, use all others as targets.
6. Fetch baseline via `PolicyFetcher.fetch_waf_policy()`.
7. For each target policy: fetch via `PolicyFetcher`, compare via `policy_comparator`,
   print `[N/M] <path>  score%  tier  diffs`.
8. Generate markdown and/or HTML outputs; print final summary table.
9. Optionally compare against Git source-of-truth and archive run data.

### BOT flow (current)

1. Resolve settings and authenticate.
2. Discover Bot Defense profiles via `BotDefenseAuditor.discover_profiles()`.
3. Select baseline and target profiles (interactive or non-interactive).
4. Fetch baseline profile via `BotDefenseAuditor.fetch_profile()`.
5. Fetch all target profiles via `BotDefenseAuditor.fetch_all()`.
6. Compare each via `bot_defense_comparator`; print per-profile progress.
7. Generate outputs; optionally archive Git state.

### INSPECT flow

1. Authenticate and discover all policies.
2. `PolicyInspector.inspect_all()` — concurrent targeted REST calls per policy.
3. Write `inspection.json`; print inspection table to stdout.

---

## 5) Inputs, outputs, and interfaces

### Inputs

- BIG-IP connection/auth settings (`--host`, `--username`, `BIGIP_PASS` or prompt, SSL options).
- Baseline selection: `--baseline-policy FULLPATH` (device-side) or interactive menu.
  No local baseline files required.
- Optional config file (`config.yaml` style).
- Optional Git repo settings (`--gitlab-*` flags / config block).

### Output artifacts

- Log file (`WAF_audit_<timestamp>.log` / `BOT_audit_<timestamp>.log`)
- Reports:
  - Dashboard HTML: `reports/WAF_audit_dashboard.html` or `reports/BOT_audit_dashboard.html`
  - Per-object markdown reports + summary markdown
- `inspection.json` (Inspect mode only)

---

## 6) Scoring and compliance model

- Baseline score: **100.0**
- Deduction model:
  - **Critical:** −5.0
  - **High:** −3.0
  - **Warning:** −2.0
  - **Info:** −0.5
- Floor: 0.0
- Default pass threshold (Green lower bound): **90.0** (adjustable via `--pass-threshold`)
- Default fail-on-tier: **RED** (adjustable via `--fail-on-tier`)
- 4-tier model: RED (0–49), AMBER (50–74), YELLOW (75–89), GREEN (90–100)

---

## 7) Security posture and operational constraints

### Positive controls

- Password accepted via `BIGIP_PASS` env var or interactive prompt; optional `--password` flag available for CI use.
- Credential masking in all log output (`_MaskFilter`).
- Token-based API session; zeroed on `close()`.
- 100% GET-only against BIG-IP after initial login.
- SSL verification disabled by default (with visible warning); `--verify-ssl` enables.

### Known issues / technical debt

The issues listed in `REVIEW.md` have been resolved:

- ~~SSL verify string parsing inversion~~ — **Fixed** (Phase 1)
- ~~Token refresh credential-clearing bug~~ — **Fixed** (Phase 1)
- ~~Duplicate/dead function definitions in report_generator.py~~ — **Fixed** (earlier cleanup)
- ~~bigip_client upload/download dead code~~ — **Removed** (Phase 4)
- ~~policy_parser.py public module~~ — **Moved to `_deprecated/`** (Phase 2/4)

Remaining known limitation:
- `src/_deprecated/policy_parser.py` is retained for XML SoT fallback in
  `gitlab_state.py`. It can be removed once all SoT files are migrated to JSON
  (run a WAF audit with `--gitlab-update-source-truth` to migrate).

---

## 8) Roadmap context (from `PLAN.md`)

Planned future phases:

1. **`config_manager.py`** — typed `AppConfig`/`DeviceConfig` dataclasses, multi-device
   YAML schema, password-on-disk rejection, `--gitlab-*` → `--git-*` migration.
2. **`change_workflow.py`** — NEW/CLEAN/DRIFTED policy classification, `change_id`
   (SHA-256 of device+path+content), `accept_change`/`reject_change`/`diff_change`,
   `pending_changes.json` manifest, interactive "Review pending changes" screen.

---

## 9) Practical mental model for an AI agent

Think of this repository as four layers:

1. **Acquisition layer** — `bigip_client.py` + `policy_fetcher.py` + `policy_exporter.py` + `bot_defense_auditor.py`
2. **Normalization layer** — `policy_fetcher.py` normalization helpers (REST → comparable dict)
3. **Comparison layer** — `policy_comparator.py` + `bot_defense_comparator.py`
4. **Presentation/state layer** — `report_generator.py` + `gitlab_state.py`

`main.py` composes these layers into WAF, BOT, or INSPECT runtime pipelines.
`interactive.py` sits above `main.py` and assembles run parameters from questionary prompts.

---

## 10) Copy/paste AI context block

```text
Project: F5 BIG-IP ASM/AWAF Security Policy Auditor (Python CLI)

Purpose:
- Perform read-only compliance/drift audits of BIG-IP WAF policies and Bot Defense profiles.
- Compare running device state to a baseline selected live from the device (BST-prefix convention).
- Generate markdown and HTML compliance reports with 4-tier scoring (RED/AMBER/YELLOW/GREEN).

Audit modes:
1) WAF mode (--mode WAF):
   - Discover ASM/AWAF policies via REST
   - Fetch full policy data via PolicyFetcher (concurrent sub-resource GETs, no XML export)
   - Compare baseline vs target via policy_comparator
2) BOT mode (--mode BOT):
   - Discover Bot Defense profiles via REST
   - Fetch profile JSON + expanded sub-collections
   - Compare baseline vs target via bot_defense_comparator
3) INSPECT mode (--mode INSPECT):
   - Fast targeted REST inspection; produces inspection.json; no baseline needed

Key modules:
- src/main.py: CLI orchestration and workflow dispatch
- src/bigip_client.py: BIG-IP REST auth/client + get_all() pagination
- src/interactive.py: questionary-based interactive TUI (TTY-only)
- src/policy_fetcher.py: full API-driven WAF + Bot data collection
- src/policy_exporter.py: WAF policy/partition discovery + VS enrichment
- src/policy_comparator.py: WAF diff/scoring engine
- src/bot_defense_auditor.py: Bot profile acquisition
- src/bot_defense_comparator.py: Bot diff/scoring engine
- src/report_generator.py: markdown + dashboard outputs
- src/gitlab_state.py: git-backed source-of-truth/archive management
- src/utils.py: logging/masking, retry, tier helpers, _XML_VIOL_ID_ALIASES
- src/_deprecated/policy_parser.py: XML parser (legacy SoT fallback only; deprecated)

Inputs:
- BIG-IP host/user/password (password via BIGIP_PASS env or interactive prompt)
- Baseline: --baseline-policy FULLPATH (device-side; BST prefix required)
- Optional config.yaml and optional git repo settings (--gitlab-* flags)

Outputs:
- Log file, per-policy/profile markdown reports, summary markdown,
  and one HTML dashboard per run.
- No policy export files (pure API-driven, no file downloads).

Scoring:
- Start 100.0, deduct Critical(-5)/High(-3)/Warning(-2)/Info(-0.5)
- 4 tiers: RED 0-49, AMBER 50-74, YELLOW 75-89, GREEN 90-100
- Default fail-on-tier: RED; default pass-threshold: 90.0

Constraints:
- 100% GET-only against BIG-IP (after initial login POST)
- Python 3.10+
- SSL verification off by default (visible warning); --verify-ssl enables
- BASELINE_PREFIX = "BST" in src/interactive.py (case-insensitive, configurable)
```
