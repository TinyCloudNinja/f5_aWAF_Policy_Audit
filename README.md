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
| `--pass-threshold` | `PASS_THRESHOLD` | `90.0` | Green tier lower bound. Only shifts the Yellow/Green boundary; other bands remain fixed. |
| `--fail-on-tier` | `FAIL_ON_TIER` | `RED` | Tier that triggers a non-zero exit code (RED/AMBER/YELLOW/GREEN). |
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

## Compliance Scoring

Each policy starts at a score of **100.0**. Findings deduct points by severity:

| Severity | Deduction | Condition |
|----------|-----------|-----------|
| **Critical** | −5.0 | Protection **enabled in baseline** is **disabled in target** |
| **High** | −3.0 | Notable security posture regression not reaching Critical threshold |
| **Warning** | −2.0 | Configuration drift that reduces security posture |
| **Info** | −0.5 | Informational differences (e.g., baseline whitelist IPs absent in target) |

Score is floored at **0.0** and displayed with one decimal place.

### Compliance Tiers

| Tier | Score Range | Meaning |
|------|-------------|---------|
| 🔴 **RED** | 0 – 49 | Non-Compliant — significant security gaps |
| 🟠 **AMBER** | 50 – 74 | Review Required — material drift identified |
| 🟡 **YELLOW** | 75 – 89 | Monitor — minor drift; schedule remediation |
| 🟢 **GREEN** | 90 – 100 | Compliant — within acceptable deviation |

The Green lower bound defaults to 90 and can be adjusted with `--pass-threshold`.
Use `--fail-on-tier` to set the tier that triggers a non-zero exit code (default: RED).

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
