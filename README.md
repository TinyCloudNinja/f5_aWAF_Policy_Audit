# F5 BIG-IP ASM/AWAF Security Policy Auditor

A Python CLI application that connects to an F5 BIG-IP device via the iControl
REST API and performs **read-only** compliance audits in three modes:

- **WAF mode** — Discovers all ASM/Advanced WAF security policies across every
  partition, fetches each policy's full configuration via the REST API, compares
  it against a baseline policy selected from the device, and generates a
  detailed compliance/drift report per policy.
- **Bot Defense mode** — Discovers all Bot Defense profiles, fetches each
  profile via the REST API, compares it against a baseline profile selected from
  the device, and generates a per-profile compliance report.
- **Inspect mode** — Fast targeted REST inspection of all policies; no baseline
  required. Produces a JSON snapshot of enforcement mode, violations, signature
  sets, and learning mode for every policy.

The tool can optionally sync a **Git-backed policy-state repository** used as:

- Source-of-truth policy/profile files (JSON, per app/policy path)
- Historical run archive (reports and run manifest)
- Optional update target for promoting current device state into source-of-truth

> **Read-Only Guarantee** — This tool issues GET requests only. It never
> creates, modifies, deletes, or applies any configuration on the BIG-IP device.
> No export tasks, no file downloads, no POST/PUT/PATCH/DELETE.

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| Python | 3.10 or later |
| BIG-IP version | 12.1+ (ASM/AWAF module licensed and provisioned) |
| BIG-IP credentials | Account with **Resource Administrator** or **Application Security Administrator** role |
| Network access | HTTPS (port 443) to the BIG-IP management interface |

---

## Installation

```bash
git clone <repo-url> f5-awaf-policy-auditor
cd f5-awaf-policy-auditor
pip install -r requirements.txt
```

---

## Quick Start

### Interactive mode (recommended for ad-hoc audits)

```bash
python -m src.main --host 10.1.1.4 --username admin
```

When all three flags (`--mode`, `--baseline-policy`, `--password`) are omitted
and stdin is a TTY, the tool enters interactive mode:

1. Prompts for password (hidden input).
2. Connects and displays the BIG-IP version.
3. Presents a mode menu: **WAF** / **Bot Defense**.
4. Shows a list of BST-prefixed baseline policies/profiles from the device.
5. Presents a checkbox list of target policies to audit.
6. Confirms the selection, then runs the audit.

A baseline policy/profile must be named with the prefix **`BST`**
(e.g. `BST_Corporate_Baseline`, `BST_PCI_Strict`). The prefix is
case-insensitive and configurable via `BASELINE_PREFIX` in `src/interactive.py`.

### Non-interactive / CI mode

```bash
python -m src.main \
  --host 10.1.1.4 \
  --username admin \
  --password 'S3cret!' \
  --mode WAF \
  --baseline-policy "~Common~BST_Corporate_Baseline" \
  --output-dir ./audit_results \
  --format both \
  --no-verify-ssl
```

When `--mode`, `--baseline-policy`, and `--password` are all supplied, no
interactive prompts appear. Suitable for CI pipelines.

### Using environment variables

```bash
export BIGIP_HOST=10.1.1.4
export BIGIP_USER=admin
export BIGIP_PASS='S3cret!'
export AUDIT_MODE=WAF
export BASELINE_POLICY='~Common~BST_Corporate_Baseline'
python -m src.main
```

### Using a config file

```bash
cp config.yaml.example config.yaml
# Edit config.yaml with your settings
python -m src.main --config ./config.yaml
```

---

## Audit Modes

### WAF Mode

Audits ASM/Advanced WAF security policies using full API-driven data collection.

- Discovers all policies across partitions via `GET /mgmt/tm/asm/policies`
- Fetches 15+ sub-resources per policy concurrently (violations, evasions,
  signature sets, URLs, filetypes, parameters, headers, cookies, data-guard,
  IP intelligence, and more)
- Selects a baseline from BST-prefixed policies on the device itself — no local
  XML file required
- Maps policies to Virtual Servers via LTM policy inspection
- Renders a three-pane HTML dashboard (Summary view default, policy deep-links)

### Bot Defense Mode

Audits Bot Defense profiles. Requires the BIG-IP Advanced WAF or Bot Defense
module to be licensed and provisioned.

- Discovers all Bot Defense profiles via `GET /mgmt/tm/security/bot-defense/profile`
- Fetches the full profile JSON for each discovered profile
- Expands referenced sub-collections (signatures, whitelist, overrides) for
  richer comparison coverage
- Compares the fetched profile against a baseline profile selected from the device

### Inspect Mode

Fast targeted REST inspection; no baseline required.

```bash
python -m src.main --host 10.1.1.4 --username admin --mode INSPECT
```

Produces `inspection.json` with enforcement mode, violations, signature sets,
and learning mode for every policy. Useful for quick device state snapshots.

---

## CLI Reference

### Mode

| Flag | Description |
|------|-------------|
| `--mode {WAF,BOT,INSPECT}` | Audit mode. Prompted interactively if omitted on a TTY. |
| `--baseline-policy FULLPATH` | Full path of the BST-prefixed baseline on the device (e.g. `~Common~BST_Base`). Prompted interactively if omitted on a TTY. |

### Connection & Authentication

| Argument | Env Var | Default | Description |
|----------|---------|---------|-------------|
| `--host` | `BIGIP_HOST` | required | BIG-IP management IP or FQDN |
| `--username` | `BIGIP_USER` | required | Admin username |
| `--password` | `BIGIP_PASS` | (prompt) | Password. Prefer `BIGIP_PASS` env var or interactive prompt over CLI to avoid shell history exposure. |
| `--login-provider` | `BIGIP_LOGIN_PROVIDER` | `tmos` | BIG-IP login provider (RADIUS/LDAP users may need to change this) |
| `--verify-ssl` / `--no-verify-ssl` | `VERIFY_SSL` | `false` | TLS certificate verification. Disabled by default for self-signed lab certs; always enable in production. |

### Audit Options

| Argument | Env Var | Default | Description |
|----------|---------|---------|-------------|
| `--output-dir` | `OUTPUT_DIR` | `../<repo_name>_output` | Output directory for reports and logs |
| `--format` | `REPORT_FORMAT` | `both` | `html` = interactive dashboard only, `markdown` = per-policy reports + summary, `both` = dashboard + markdown |
| `--pass-threshold` | `PASS_THRESHOLD` | `85.0` | Aligned (Green) band lower bound. Only shifts the Monitor/Aligned boundary; other bands remain fixed. |
| `--fail-on-tier` | `FAIL_ON_TIER` | `RED` | Tier that triggers a non-zero exit code (RED/AMBER/YELLOW/GREEN = Review Now / Review Soon / Monitor / Aligned). |
| `-v` / `--verbose` | — | `false` | Enable debug logging |
| `--config` | — | `config.yaml` | Path to YAML config file |

### Git Policy-State Options (Optional)

| Argument | Env Var | Default | Description |
|----------|---------|---------|-------------|
| `--gitlab-repo-url` | `GITLAB_REPO_URL` | (disabled) | Git repo URL that stores source-of-truth + historical runs |
| `--gitlab-local-dir` | `GITLAB_LOCAL_DIR` | `../<repo_name>_policy_state_repo` | Local clone path |
| `--gitlab-branch` | `GITLAB_BRANCH` | `main` | Git branch to pull/commit against |
| `--gitlab-auto-push` / `--no-gitlab-auto-push` | `GITLAB_AUTO_PUSH` | `false` | Whether commits are pushed automatically after each run |
| `--gitlab-update-source-truth` / `--no-gitlab-update-source-truth` | `GITLAB_UPDATE_SOURCE_TRUTH` | `false` | Whether current policy data overwrites `source_of_truth/` files |

When `--gitlab-repo-url` is supplied, the tool will:

1. Clone/pull the configured branch to the local repo directory.
2. Compare running policies against the selected device baseline (existing behavior).
3. Additionally compare running policies against `source_of_truth/` files from Git (if present).
4. Archive run artifacts into `runs/<mode>/<timestamp>/` inside the repo.
5. Optionally refresh `source_of_truth/` with the latest fetched data, then commit (and optionally push).

---

## Output Files

After a run, the `--output-dir` will contain:

**WAF mode:**

```
<output-dir>/
├── WAF_audit_20260303T143012.log      # Full debug log
└── reports/
    ├── WAF_audit_dashboard.html        # Interactive HTML dashboard
    ├── WAF_Common_app1_audit_report.md # Per-policy Markdown report
    ├── WAF_Common_app2_audit_report.md
    ├── WAF_summary_audit_report.md     # Cross-policy summary (Markdown)
    └── WAF_virtual_server_summary.md   # VS ↔ WAF policy mapping
```

**Bot Defense mode:**

```
<output-dir>/
├── BOT_audit_20260303T143012.log
└── reports/
    ├── BOT_audit_dashboard.html
    ├── BOT_Common_my_bot_profile_audit_report.md
    └── BOT_summary_audit_report.md
```

**Inspect mode:**

```
<output-dir>/
├── INSPECT_audit_20260303T143012.log
└── inspection.json                    # Full policy snapshot
```

If Git source-of-truth comparison is enabled and source files exist, additional
reports are written under `<output-dir>/source_of_truth/reports/`.

---

## Git Policy-State Repository Layout

```
policy-state-repo/
├── source_of_truth/
│   ├── waf/
│   │   └── <partition>/<policy>.json   # API-normalized JSON (preferred)
│   │   └── <partition>/<policy>.xml    # Legacy XML (read-only fallback)
│   └── bot/
│       └── <partition>/<profile>.json
└── runs/
    ├── waf/
    │   └── <timestamp>/
    │       ├── reports/
    │       ├── source_of_truth_reports/
    │       └── manifest.json
    └── bot/
        └── <timestamp>/
            ├── reports/
            ├── source_of_truth_reports/
            └── manifest.json
```

New source-of-truth files are stored as **JSON** (the API-normalized format).
Legacy XML files are still read as a fallback; re-run with
`--gitlab-update-source-truth` to migrate them to JSON.

---

## Posture Scoring

WAF mode and Bot Defense mode share one scoring framework — the **Posture
Score** — but each mode has its own rules, weights, and detectors:

- **WAF**: `src/scoring_config.py` (config) + `_compute_posture_score()` in
  `src/policy_comparator.py` (engine)
- **Bot Defense**: `src/bot_defense_scoring_config.py` (config) +
  `src/bot_defense_scorer.py` (engine)

All weights, caps, and thresholds live in the two config files, so scoring can
be tuned without touching logic code.

### The Algorithm (both modes)

Every policy/profile starts at **100.0** and the engine works through four
stages:

1. **Hard triggers** — a small set of conditions so severe that they override
   the numeric score entirely. If *any* hard trigger fires, the final score is
   capped at **39**, pinning the item into the 🔴 **Review Now** band no matter
   how clean the rest of the configuration is.
2. **Drift deductions** — DiffItems from the baseline comparison are classified
   as *loosening* (security got weaker) or *tightening* (security got stronger).
   **Only loosening drift deducts points**; tightening changes are listed in the
   drift summary but cost nothing. Each loosening diff deducts by severity, and
   each drift *category* has a maximum cap so one noisy category (e.g. hundreds
   of signature diffs) cannot single-handedly zero the score.
3. **Standalone posture signals** — risk indicators computed directly from the
   target configuration with **no baseline required** (e.g. signatures stuck in
   staging, permissive mobile SDK flags). Each signal has its own independent
   cap.
4. **Final score** —
   `raw_score = max(0, 100 − (capped drift total + standalone total))`,
   then `final_score = min(raw_score, 39)` if any hard trigger fired.
   The raw (pre-cap) score is retained and shown alongside the final score.

Every deduction is recorded as a **contributing factor** (ranked
largest-first in the reports) with a label, description, and remediation text
taken from the scoring config.

**Severity weights for loosening drift (both modes):**

| Severity | Deduction per finding |
|----------|----------------------|
| Critical | −8.0 |
| High | −4.0 |
| Warning | −2.0 |
| Info | −0.5 |

### Triage Bands

Both modes map the final score onto the same four-band status ladder
(internal tier names `RED`/`AMBER`/`YELLOW`/`GREEN` are kept for CLI/exit-code
compatibility):

| Band | Internal Tier | Score Range | Meaning |
|------|---------------|-------------|---------|
| 🔴 **Review Now** | RED | 0 – 39 | Hard trigger fired or severe posture gaps — act immediately |
| 🟠 **Review Soon** | AMBER | 40 – 64 | Material drift or weak posture — schedule review |
| 🟡 **Monitor** | YELLOW | 65 – 84 | Minor drift; keep an eye on it |
| 🟢 **Aligned** | GREEN | 85 – 100 | Within acceptable deviation from baseline |

The Aligned lower bound defaults to **85** and can be moved with
`--pass-threshold`; only the Monitor/Aligned boundary shifts — the Review
Now/Review Soon boundaries stay fixed at 39/64. Use `--fail-on-tier` to choose
which tier produces a non-zero exit code (default: `RED`).

### WAF Scoring Details

**Hard triggers** (any one pins the policy to Review Now):

| Trigger | Condition |
|---------|-----------|
| `TRANSPARENT_MODE` | Enforcement mode is not `blocking` — the policy logs violations but blocks nothing |
| `NO_VIRTUAL_SERVERS` | VS mapping was evaluated and the policy is not bound to any virtual server — it enforces nothing |
| `NO_SIGNATURE_SETS` | No attack signature sets are applied — no pattern-matching coverage at all |

**Drift category caps** (maximum deduction per category of loosening diffs):

| Category | Cap | Typical findings |
|----------|-----|------------------|
| `signatures` | 20 | Signatures disabled, sets removed or un-blocked |
| `blocking` | 20 | Violation block → alarm downgrades |
| `data_guard` | 16 | Data Guard features disabled |
| `ip_intelligence` | 12 | IP intelligence disabled / categories relaxed |
| `bot_defense` | 12 | Embedded bot defense settings disabled |
| `policy_builder` | 10 | Policy Builder loosened vs baseline |
| `whitelist` | 8 | Unauthorized IP whitelist additions |
| `general` | 8 | General settings |
| `enforcement` | 0 | Mode change is already a hard trigger — no double-count |
| *(default)* | 6 | Any unlisted category |

A diff counts as *loosening* when, for example: a `block` flag goes
`true → false`, a signature gains `performStaging`, an `enabled` flag goes
`true → false`, enforcement goes `blocking → transparent`, or an entity/set
present in the baseline is missing from the target.

**Standalone posture signals** (no baseline needed):

| Signal | Deduction | What it detects |
|--------|-----------|-----------------|
| Staging ratio | tiered, max −20 | Share of attack signatures in staging (log-only): ≥75% → −20, ≥50% → −14, ≥25% → −8, ≥10% → −3 |
| All blocking disabled | flat −15 | Policy is in blocking mode but every violation/signature block flag is off |
| Policy Builder fully automatic | flat −10 | Auto-learning can be poisoned: shaped traffic can train the WAF to accept real attacks |
| Accepted learning widened policy | −3/item, max −12 | Accepted Policy Builder suggestions in the ASM audit log that staged/disabled signatures, relaxed violations, or widened entities |
| Loose wildcard entities | −2/item, max −8 | Wildcard URLs/parameters (`*`, `/*`, …) with attack-signature checks disabled |

### Bot Defense Scoring Details

The Bot Defense threat model differs from WAF: the analog of Policy Builder
poisoning is **allow-listing and class-action downgrading** — whitelist growth
and mitigation actions weakened from block → alarm/none are the primary drift
signals. "Blocking actions" for bot scoring are `block`, `captcha`, and
`rate-limit`; `alarm` and `none` are detection-only.

**Hard triggers** (any one pins the profile to Review Now):

| Trigger | Condition |
|---------|-----------|
| `NO_VIRTUAL_SERVERS` | VS mapping was evaluated and the profile is attached to no virtual server |
| `BOT_TRANSPARENT_MODE` | `enforcementMode` is not `blocking` — bots are logged, never blocked or challenged |
| `BOT_NO_TEETH` | Class overrides exist for high-risk bot classes (`malicious-bot`, `dos-tool`, `web-scraper`, `scanner`, `vulnerability-scanner`, `network-scanner`, `denial-of-service`) and **every one** of them uses a non-blocking action — the profile detects malicious bots but mitigates none of them |

**Drift category caps:**

| Category | Cap | Typical findings |
|----------|-----|------------------|
| `class_actions` | 20 | Class override action downgrades — the primary poisoning vector |
| `whitelist` | 16 | Whitelist entries added / IP ranges broadened |
| `bot_defense` | 12 | Core enforcement/mode/mitigation settings |
| `mobile_sdk` | 8 | Mobile SDK posture loosened vs baseline |
| `signatures` | 8 | Signatures moved to staging / actions weakened |
| `general` | 6 | Other settings |
| *(default)* | 4 | Any unlisted category |

A bot diff counts as *loosening* when, for example: an override `action` goes
from a blocking action to a non-blocking one, a whitelist entry appears that
wasn't in the baseline, the template drops down the
`strict > balanced > relaxed` ladder, a permissive mobile SDK flag turns on, or
`dosAttackStrictMitigation`/`apiAccessStrictMitigation` turns off.

**Standalone posture signals:**

| Signal | Deduction | What it detects |
|--------|-----------|-----------------|
| Browser mitigation weak | flat −12 | `browserMitigationAction` set to a non-blocking value — untrusted browsers logged but never challenged |
| DoS/anomaly alarm-only | flat −10 | `dosAttackStrictMitigation` disabled, or every configured anomaly override is detect-only |
| API strict mitigation off | flat −8 | `apiAccessStrictMitigation` explicitly disabled |
| Staged bot signatures | −1/signature, max −10 | Bot signatures accumulating in staging (log-only) |
| Mobile SDK loose | −2/flag, max −8 | Jailbroken/rooted devices allowed, emulators allowed, any Android/iOS package allowed, debugger-enabled devices not blocked |
| Relaxed template | flat −4 | Profile uses the `relaxed` template (least restrictive) |
| Weak device ID | flat −4 | `deviceidMode` disabled/weak — no persistent device fingerprinting |
| Extended grace period | flat −3 | `gracePeriod` or `enforcementReadinessPeriod` > 86 400 s (1 day) |
| Challenge-in-transparent off | flat −2 | `performChallengeInTransparent` disabled — reduces detection fidelity |

### Scoring Without a Baseline

When no baseline is available (no BST-prefixed policy/profile selected and no
Git source-of-truth file), **drift deductions are suppressed entirely** — the
score reflects standalone posture signals only. The report adds a
zero-deduction *"Drift tracking is unbaselined"* note so the gap is visible
rather than silently inflating the score.

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All policies/profiles at or above `--fail-on-tier` |
| `1` | One or more policies/profiles at/below `--fail-on-tier` |
| `2` | Runtime error (auth failure, discovery failure, all fetches failed) |
| `130` | Interrupted (`Ctrl+C`) |

---

## Architecture

```
src/
├── main.py                     # CLI entry point, mode dispatch, audit orchestration
├── bigip_client.py             # iControl REST client (token auth, retry, pagination)
├── interactive.py              # questionary-based interactive TUI (TTY-only)
├── policy_fetcher.py           # Full API-driven WAF + Bot data collection pipeline
├── policy_exporter.py          # WAF policy discovery + VS/LTM enrichment
├── policy_inspector.py         # Fast targeted REST inspection (INSPECT mode)
├── policy_comparator.py        # WAF diff engine → ComparisonResult + DiffItem
├── bot_defense_auditor.py      # Bot Defense profile discovery + fetch
├── bot_defense_comparator.py   # Bot Defense diff engine
├── report_generator.py         # Markdown reports + interactive HTML dashboard
├── gitlab_state.py             # Git-backed SoT load/update, run archival
├── virtual_server_inventory.py # VS + LTM policy/host mapping (read-only)
└── utils.py                    # Logging, masking, retry decorator, tier helpers
```

**Key design decisions:**

- **100% GET-only** — no export tasks, no file uploads, no config mutations
- **Concurrent sub-resource fetches** — `ThreadPoolExecutor` per policy for speed
- **OData `$top`/`$skip` pagination** — `get_all()` pages until `totalItems` exhausted
- **Proactive token refresh** at 80% of token lifetime — avoids mid-run 401s
- **lxml with stdlib fallback** — used only for legacy XML SoT files
- **Credential masking** — passwords and tokens masked in all log output
- **SSL off by default** — visible warning shown; `--verify-ssl` enables

---

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

Tests use XML fixtures in `tests/fixtures/` for the XML parser unit tests, plus
mock-based unit tests for all REST-API-facing modules.

---

## Troubleshooting

### Authentication Failures

```
ERROR: Authentication failed for user 'admin'.
```

- Verify credentials with `curl -sk -X POST https://BIGIP/mgmt/shared/authn/login -d '{"username":"admin","password":"...", "loginProviderName":"tmos"}'`
- Ensure the account is not locked out
- RADIUS/LDAP users may need `--login-provider` changed from `tmos`

### SSL Certificate Errors

```
requests.exceptions.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED]
```

- Use `--no-verify-ssl` for self-signed certs (default; warning is printed)
- To use a CA bundle: set `verify_ssl: /path/to/ca-bundle.pem` in config

### No BST Baseline Found

```
RuntimeError: No BST-prefixed policies found on the device.
```

- At least one policy must be named with the `BST` prefix (e.g. `BST_Corporate`)
- The prefix is case-insensitive (`bst_`, `Bst_` also match)
- The constant `BASELINE_PREFIX` in `src/interactive.py` can be changed if needed

### Bot Defense Module Not Licensed

```
INFO: Bot Defense module not licensed or not provisioned (404). Skipping bot profile discovery.
```

- The `--mode BOT` workflow requires BIG-IP Advanced WAF or the Bot Defense add-on module

### Insufficient Privileges

The minimum required BIG-IP role is **Application Security Administrator**
(or Resource Administrator). To verify:

```bash
tmsh list auth user admin | grep role
```

---

## Security Considerations

1. **Credential Handling** — Passwords are never written to log files (masked as `***MASKED***`). Use `BIGIP_PASS` or the interactive prompt rather than `--password` to avoid credentials appearing in shell history.

2. **Read-Only Operation** — The tool issues GET requests only. No POST/PUT/PATCH/DELETE are issued to BIG-IP after the initial login POST.

3. **SSL Verification** — SSL verification is disabled by default for lab/self-signed environments. A warning is printed. Always use `--verify-ssl` in production.

4. **Token Storage** — Auth tokens are held in memory only and are never written to disk. Tokens are zeroed on `close()`.

5. **Output Directory** — Reports may contain policy configuration details. Treat the output directory as sensitive and apply appropriate filesystem permissions.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

---

## Contributing

Issues and pull requests are welcome. Please ensure all tests pass before
submitting:

```bash
python -m pytest tests/ -v
```
