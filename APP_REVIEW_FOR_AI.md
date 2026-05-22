# Application Review for AI Systems

## 1) What this app is

**Name:** F5 BIG-IP ASM/AWAF Security Policy Auditor  
**Type:** Python CLI security-audit tool  
**Primary goal:** Read-only compliance/drift auditing of F5 BIG-IP configurations against approved baselines.

The app supports two audit domains:

- **WAF mode (`--WAF`)**: discovers ASM/AWAF security policies, exports each policy, parses normalized structure, compares to XML baseline, and scores drift.
- **Bot Defense mode (`--BOT`)**: discovers Bot Defense profiles, fetches and expands profile JSON, compares to JSON baseline, and scores drift.

It can optionally integrate with a Git-backed policy-state repository to:

- load per-policy/profile source-of-truth files,
- archive run artifacts,
- optionally update source-of-truth files from current device state.

---

## 2) Core behavior and guarantees

- **Read-only intent on BIG-IP**: the tool performs GET-heavy audit flows and WAF export-task initiation used for data retrieval.
- **No policy apply/modify/delete workflow** in normal operation.
- **Produces evidence artifacts**: exported policy/profile files, markdown reports, and HTML dashboard.
- **Scoring model** starts at 100 and deducts by severity (`Critical`, `Warning`, `Info`).

---

## 3) High-level architecture (src)

- `src/main.py`
  - CLI entrypoint, argument parsing, config/env/CLI precedence, mode dispatch.
  - Orchestrates end-to-end workflows for WAF and BOT audits.

- `src/bigip_client.py`
  - BIG-IP iControl REST client wrapper.
  - Handles auth, token lifecycle, request/retry patterns, upload/download helpers.

- `src/policy_exporter.py`
  - WAF policy discovery and export-task workflow.
  - Enriches policies with virtual server/LTM rule context when available.

- `src/policy_parser.py`
  - Parses WAF XML exports into normalized Python dicts.
  - Extracts comparable sections (general, blocking, signatures, policy builder, etc.).

- `src/policy_comparator.py`
  - WAF diff engine.
  - Produces `ComparisonResult` + `DiffItem` findings, summary counts, and score.

- `src/bot_defense_auditor.py`
  - Bot profile discovery/fetch and subcollection expansion.

- `src/bot_defense_comparator.py`
  - Bot profile diff engine.

- `src/report_generator.py`
  - Generates markdown per-policy reports and interactive HTML dashboard summaries.

- `src/gitlab_state.py`
  - Git-backed state manager (named GitLab but implemented via git CLI operations).
  - Sync, source-of-truth load/update, run archival, optional commit/push.

- `src/utils.py`
  - Logging/masking, retry helper, filesystem/path utility functions.

---

## 4) Main execution flows

### WAF flow

1. Resolve runtime settings from CLI > environment > config file.
2. Authenticate to BIG-IP.
3. Discover policies across partitions.
4. Export policies (concurrently) to XML/JSON artifact files.
5. Parse each export + parse baseline XML.
6. Compare baseline vs target using `policy_comparator`.
7. Build markdown and/or HTML outputs; produce summary.
8. Optionally compare against Git source-of-truth and archive run data.

### BOT flow

1. Resolve runtime settings and authenticate.
2. Discover Bot Defense profiles.
3. Fetch full profile JSON + referenced subcollections.
4. Compare baseline profile JSON vs target via `bot_defense_comparator`.
5. Generate markdown and/or HTML outputs.
6. Optionally archive/update Git-based source-of-truth artifacts.

---

## 5) Inputs, outputs, and interfaces

### Inputs

- BIG-IP connection/auth settings (`--host`, `--username`, `BIGIP_PASS`, SSL options).
- Baseline file:
  - WAF: XML
  - BOT: JSON
- Optional config file (`config.yaml` style).
- Optional Git repo settings (`--gitlab-*` flags / config block).

### Output artifacts

- Log file (`audit_<timestamp>.log`)
- Exported evidence files
  - WAF: `exports/*.xml` (or JSON export format)
  - BOT: `bot-defense/*.json`
- Reports
  - Dashboard HTML: `reports/WAF_audit_dashboard.html` or `reports/BOT_audit_dashboard.html`
  - Per-object markdown reports + summary markdown

---

## 6) Scoring and compliance model

- Baseline score: **100.0**
- Deduction model:
  - **Critical:** -5.0
  - **Warning:** -2.0
  - **Info:** -0.5
- Floor: 0.0
- Typical pass threshold: **90.0**
- Exit behavior generally reflects whether any policy/profile is below threshold or export failures occurred.

Comparators evaluate security posture regressions by section (e.g., enforcement mode, blocking flags, signatures, data guard/IP intelligence, bot mitigations).

---

## 7) Security posture and operational constraints

### Positive controls

- Password not accepted as normal CLI argument.
- Credential masking in logs.
- Token-based API session use.
- Clear separation between audit logic and report generation.

### Known issues / technical debt (from `REVIEW.md`)

Important current findings include:

- **SSL verify string parsing inversion** in `main.py` (`"true"/"false"` handling bug).
- **Token refresh failure risk** due to credential lifecycle in `bigip_client.py`.
- **Potential credential exposure** via git HTTPS URL forms not fully masked.
- **Duplicate/dead function definitions** in `report_generator.py` causing maintainability risk.
- A few dead-code and hygiene issues (unused imports/assignments, stale helper).

Treat these as active caveats when using results for strict compliance decisions until remediated.

---

## 8) Roadmap context (from `PLAN.md`)

Planned evolution is in two broad phases:

1. **Phase 1:** bug fixes + interactive mode + stronger typed config management.
2. **Phase 2:** richer Git-based change acceptance workflow (`NEW/CLEAN/DRIFTED`, pending-change review/accept/reject lifecycle).

This means architecture is stable today for current CLI audits, but expected to expand into interactive and governance workflows.

---

## 9) Practical mental model for an AI agent

Think of this repository as four layers:

1. **Acquisition layer** — BIG-IP API client + exporters/auditors
2. **Normalization layer** — parsers converting exports into comparable structured dicts
3. **Comparison layer** — diff engines computing findings/severity/score
4. **Presentation/state layer** — report generation + optional Git-backed historical/source-of-truth state

`main.py` composes these layers into WAF or BOT runtime pipelines.

---

## 10) Copy/paste AI context block

Use the following block directly in another AI tool:

```text
Project: F5 BIG-IP ASM/AWAF Security Policy Auditor (Python CLI)

Purpose:
- Perform read-only compliance/drift audits of BIG-IP WAF policies and Bot Defense profiles.
- Compare running device state to approved baseline files.
- Generate markdown and HTML compliance reports with scoring.

Modes:
1) WAF mode:
   - Discover ASM/AWAF policies
   - Export policy artifacts (typically XML)
   - Parse to normalized structure
   - Compare baseline vs target via policy comparator
2) BOT mode:
   - Discover Bot Defense profiles
   - Fetch profile JSON + expanded subcollections
   - Compare baseline vs target via bot comparator

Important modules:
- src/main.py: CLI orchestration and workflow dispatch
- src/bigip_client.py: BIG-IP REST auth/client utilities
- src/policy_exporter.py: WAF discovery/export pipeline
- src/policy_parser.py: XML parsing into normalized dicts
- src/policy_comparator.py: WAF diff/scoring engine
- src/bot_defense_auditor.py: Bot profile acquisition
- src/bot_defense_comparator.py: Bot diff/scoring engine
- src/report_generator.py: markdown + dashboard outputs
- src/gitlab_state.py: git-backed source-of-truth/archive management

Inputs:
- BIG-IP host/user/password (password via env/prompt)
- Baseline file (XML for WAF, JSON for BOT)
- Optional config.yaml and optional git repo settings

Outputs:
- Logs, exported artifacts, per-policy/profile markdown reports, summary markdown,
  and one HTML dashboard per run.

Scoring:
- Start 100.0, deduct by finding severity (Critical/Warning/Info), pass threshold ~90.

Current caveats:
- Review technical debt in REVIEW.md before major refactors:
  SSL bool parsing bug, token refresh credential handling, incomplete log masking,
  duplicate/dead report functions, and related cleanup items.

Roadmap:
- PLAN.md defines near-term bug-fix and interactive mode work (Phase 1), then
  Git-driven pending-change acceptance workflows (Phase 2).
```
