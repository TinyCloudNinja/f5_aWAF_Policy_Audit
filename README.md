# F5 BIG-IP ASM/AWAF Security Policy Auditor

A Python CLI application that connects to an F5 BIG-IP device via the iControl
REST API and performs read-only compliance audits in two modes:

- **WAF mode (`--WAF`)** — Discovers all ASM/Advanced WAF security policies
  across every user partition, exports each policy as XML, compares it against
  a provided baseline XML policy, and generates a detailed compliance/drift
  report per policy.
- **Bot Defense mode (`--BOT`)** — Discovers all Bot Defense profiles across
  every user partition, fetches each profile via the REST API, compares it
  against a provided baseline JSON profile, and generates a per-profile
  compliance report.

It can also optionally sync a **GitLab-backed policy-state repository** used as:

- Source-of-truth policy/profile files (per app/policy path)
- Historical run archive (exports, reports, and run manifest)
- Optional update target for promoting current device state into source-of-truth

> **Read-Only Guarantee** — This tool never creates, modifies, deletes, or
> applies any configuration on the BIG-IP device. It performs only GET requests
> (plus the POST to initiate a WAF export task, which is a read operation) and
> downloads exported policy files.

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| Python | 3.9 or later |
| BIG-IP version | 12.1+ (ASM/AWAF module licensed and provisioned) |
| BIG-IP credentials | Account with **Resource Administrator** or **Application Security Administrator** role |
| Network access | HTTPS (port 443) to the BIG-IP management interface |

---

## Installation

```bash
# Clone or download the repository
git clone <repo-url> f5-awaf-policy-auditor
cd f5-awaf-policy-auditor

# Install Python dependencies
pip install -r requirements.txt
```

---

## Audit Modes

### WAF Mode (`--WAF`)

Audits ASM/Advanced WAF security policies. This is the **default** mode if
neither `--WAF` nor `--BOT` is specified.

- Discovers all policies across partitions via the iControl REST API
- Exports each policy as XML using the BIG-IP export task workflow
- Parses and compares the exported XML against a baseline XML policy
- Collects a read-only Virtual Server inventory (per partition scope) and maps
  HTTP Host/FQDN routing to attached ASM/AWAF policies when LTM Policies invoke ASM
- Renders a three-pane HTML dashboard where **Summary** is the default landing view
  (Virtual Servers + WAF applicability/enabled status), with policy deep-links
- Baseline file must be a valid F5 policy XML export

### Bot Defense Mode (`--BOT`)

Audits Bot Defense profiles. Requires the BIG-IP Advanced WAF or Bot Defense
module to be licensed and provisioned.

- Discovers all Bot Defense profiles via `GET /mgmt/tm/security/bot-defense/profile`
- Fetches the full profile JSON for each discovered profile
- Expands referenced sub-collections (signatures, whitelist, overrides, etc.) for richer comparison coverage
- Saves each profile JSON to `<output-dir>/bot-defense/` for the audit trail
- Compares the fetched profile against a baseline JSON file
- Baseline file must be a JSON export of a Bot Defense profile (see below)

#### Obtaining a Bot Defense Baseline

Export a "gold standard" Bot Defense profile from the BIG-IP REST API:

```bash
curl -sk -u admin:password \
  https://bigip/mgmt/tm/security/bot-defense/profile/~Common~my_bot_profile \
  -o ./baseline/bot_baseline.json
```

Or via the BIG-IP GUI: **Security > Bot Defense > Bot Defense Profiles**, select
the profile, and use the API URL shown in your browser's developer tools.

---

## Quick Start

### 1. Obtain a Baseline Policy

Export your "gold standard" policy from the BIG-IP GUI:

1. Go to **Security > Application Security > Security Policies**.
2. Select the policy to use as the baseline.
3. Click **Export** and choose **XML** format.
4. Save the file to `./baseline/corporate_baseline.xml`.

Or via the API directly:

```bash
# Trigger export
curl -sk -u admin:password \
  -X POST https://bigip/mgmt/tm/asm/tasks/export-policy \
  -H "Content-Type: application/json" \
  -d '{"filename":"baseline.xml","format":"xml","minimal":false,"policyReference":{"link":"https://localhost/mgmt/tm/asm/policies/<POLICY_ID>"}}'

# Download after task completes
curl -sk -u admin:password \
  -H "Content-Range: 0-1048575/*" \
  https://bigip/mgmt/tm/asm/file-transfer/downloads/baseline.xml \
  -o ./baseline/corporate_baseline.xml
```

### 2. Run the Audit

**WAF audit** (will prompt for password):

```bash
python -m src.main --WAF \
  --host 192.168.1.245 \
  --username admin \
  --baseline ./baseline/corporate_baseline.xml
```

**Bot Defense audit**:

```bash
python -m src.main --BOT \
  --host 192.168.1.245 \
  --username admin \
  --baseline ./baseline/bot_baseline.json
```

**Full options (WAF)**:

```bash
python -m src.main --WAF \
  --host 10.1.1.4 \
  --username admin \
  --baseline ./baseline/disa_stig_baseline.xml \
  --output-dir ./audit_results \
  --format both \
  --partitions Common,App1,App2 \
  --concurrent-exports 5 \
  --no-verify-ssl \
  -v
```

**Using a config file**:

```bash
cp config.yaml.example config.yaml
# Edit config.yaml with your settings
python -m src.main --config ./config.yaml
```

**Using environment variables**:

```bash
export BIGIP_HOST=192.168.1.245
export BIGIP_USER=admin
export BIGIP_PASS='S3cret!'
python -m src.main --baseline ./baseline/corporate_baseline.xml
```

---

## CLI Reference

### Audit Mode Flags

These flags are mutually exclusive. If neither is supplied, `--WAF` is the default.

| Flag | Description |
|------|-------------|
| `--WAF` | Audit ASM/AWAF security policies against an XML baseline |
| `--BOT` | Audit Bot Defense profiles against a JSON baseline |

### Connection & Authentication

| Argument | Env Var | Default | Description |
|----------|---------|---------|-------------|
| `--host` | `BIGIP_HOST` | required | BIG-IP management IP or FQDN |
| `--username` | `BIGIP_USER` | required | Admin username |
| `--login-provider` | `BIGIP_LOGIN_PROVIDER` | `tmos` | BIG-IP login provider (RADIUS/LDAP users may need to change this) |
| `--verify-ssl` / `--no-verify-ssl` | `VERIFY_SSL` | `true` | TLS certificate verification |

> Password input is intentionally **not** exposed as a CLI argument. Use `BIGIP_PASS`
> or the interactive prompt.

### Audit Options

| Argument | Env Var | Default | Description |
|----------|---------|---------|-------------|
| `--baseline` | `BASELINE_POLICY` | required | Path to baseline file (XML for `--WAF`, JSON for `--BOT`) |
| `--output-dir` | `OUTPUT_DIR` | `../<repo_name>_output` | Output directory for exports and reports |
| `--format` | `REPORT_FORMAT` | `both` | `html` = single interactive dashboard, `markdown` = per-policy/profile reports + summary, `both` = dashboard + markdown reports |
| `--partitions` | `PARTITIONS` | (all) | Comma-separated partition list to audit |
| `--export-format` | `EXPORT_FORMAT` | `xml` | WAF policy export format: `xml` or `json` |
| `--concurrent-exports` | `CONCURRENT_EXPORTS` | `3` | Max parallel WAF export tasks (1–20) |
| `-v` / `--verbose` | — | `false` | Enable debug logging |
| `--config` | — | `config.yaml` | Path to YAML config file |

### GitLab Policy-State Options (Optional)

| Argument | Env Var | Default | Description |
|----------|---------|---------|-------------|
| `--gitlab-repo-url` | `GITLAB_REPO_URL` | (disabled) | GitLab repo URL that stores source-of-truth + historical runs |
| `--gitlab-local-dir` | `GITLAB_LOCAL_DIR` | `../<repo_name>_policy_state_repo` | Local clone path used for sync/compare/archive |
| `--gitlab-branch` | `GITLAB_BRANCH` | `main` | Git branch to pull/commit against |
| `--gitlab-auto-push` / `--no-gitlab-auto-push` | `GITLAB_AUTO_PUSH` | `false` | Whether commits are pushed automatically after each run |
| `--gitlab-update-source-truth` / `--no-gitlab-update-source-truth` | `GITLAB_UPDATE_SOURCE_TRUTH` | `false` | Whether current exports overwrite `source_of_truth/` files |

When `--gitlab-repo-url` is supplied, the tool will:

1. Clone/pull the configured branch to the local repo directory.
2. Compare running policies against your provided baseline (existing behavior).
3. Additionally compare running policies against `source_of_truth/` files from GitLab (if present).
4. Archive run artifacts into `runs/<mode>/<timestamp>/` inside the repo.
5. Optionally refresh `source_of_truth/` with the latest exports, then commit (and optionally push).

Config file values are overridden by environment variables, which are overridden
by CLI arguments.

---

## Output Files

After a run, the `--output-dir` (default: sibling folder outside the repo, `../<repo_name>_output`) will contain:

**WAF mode:**

```
<output-dir>/
├── audit_20260303T143012.log          # Full debug log
├── exports/
│   ├── Common_app1_waf_20260303T1430.xml
│   └── Common_app2_waf_20260303T1431.xml
└── reports/
    ├── WAF_audit_dashboard.html        # Three-pane HTML dashboard (Summary + Policies)
    ├── WAF_app1_waf_audit_report.md    # Per-policy Markdown report
    ├── WAF_app2_waf_audit_report.md
    ├── WAF_summary_audit_report.md     # Cross-policy summary (Markdown)
    └── WAF_virtual_server_summary.md   # Virtual Server WAF applicability/enabled summary
```

**Bot Defense mode:**

```
<output-dir>/
├── audit_20260303T143012.log
├── bot-defense/
│   ├── Common_my_bot_profile.json     # Raw profile JSON (audit trail)
│   └── App1_strict_bot.json
└── reports/
    ├── BOT_audit_dashboard.html        # Single interactive multi-profile HTML dashboard
    ├── BOT_my_bot_profile_audit_report.md
    ├── BOT_strict_bot_audit_report.md
    └── BOT_summary_audit_report.md
```

Notes:
- HTML output is generated as one interactive dashboard file per run (`WAF_audit_dashboard.html` or `BOT_audit_dashboard.html`).
- In WAF mode, the dashboard defaults to a **Summary** view with all discovered Virtual Servers,
  WAF status badges (`Not Applicable`, `WAF Capable`, `WAF Enabled`), and expandable
  FQDN/Host-to-policy mappings for ASM-enabled LTM policy rules.
- Markdown output is generated per policy/profile, plus summary report(s). WAF markdown now
  also includes `WAF_virtual_server_summary.md`.
- If GitLab source-of-truth comparison is enabled and source files exist, additional reports are written under `<output-dir>/source_of_truth/reports/`.

## GitLab Policy-State Repository Layout

Recommended structure in your GitLab repo:

```
policy-state-repo/
├── source_of_truth/
│   ├── waf/
│   │   └── <partition>/<policy>.xml
│   └── bot/
│       └── <partition>/<profile>.json
└── runs/
    ├── waf/
    │   └── <timestamp>/
    │       ├── exports/
    │       ├── reports/
    │       ├── source_of_truth_reports/
    │       └── manifest.json
    └── bot/
        └── <timestamp>/
            ├── bot-defense/
            ├── reports/
            ├── source_of_truth_reports/
            └── manifest.json
```

This model supports multiple BIG-IP devices for the same applications while
keeping one GitLab source-of-truth. Each run compares the active device config
to baseline + GitLab source-of-truth and stores the full evidence trail in Git.

---

## Compliance Scoring Methodology

Each policy starts at a score of **100.0**.

| Finding Severity | Deduction per Finding | Condition |
|------------------|-----------------------|-----------|
| **Critical**     | −5.0 points | Protection that is **enabled in baseline** is **disabled in target** |
| **Warning**      | −2.0 points | Configuration drift that reduces security posture |
| **Info**         | −0.5 points | Informational differences (e.g., baseline whitelist IPs absent in target) |

Score is floored at **0.0** and displayed with one decimal place.

A policy **passes** if its score is ≥ **90.0%**.

The CLI exits with:
- **Code 0** — all policies scored ≥ 90%
- **Code 1** — one or more policies scored < 90%, or export errors occurred

### What triggers Critical findings — WAF mode

| Section | Trigger |
|---------|---------|
| General Settings | `enforcementMode` is `blocking` in baseline but `transparent` in target |
| Blocking Settings | Any violation/evasion/HTTP-protocol with `block=true` in baseline but `block=false` in target |
| Attack Signatures | A signature `enabled=true` in baseline is `enabled=false` in target |
| Signature Sets | A set with `block=true` in baseline has `block=false` in target |
| Data Guard | `enabled=true` in baseline, `enabled=false` in target |
| IP Intelligence | `enabled=true` in baseline, `enabled=false` in target |
| Bot Defense | `enabled=true` in baseline, `enabled=false` in target |
| Data Guard sub-controls | Credit card / SSN protection disabled in target |

### What triggers Critical findings — Bot Defense mode

| Section | Field | Trigger |
|---------|-------|---------|
| Core | `enforcementMode` | Baseline is `blocking`, target is not `blocking` — bot threats will not be blocked |
| Core | `template` | Template downgraded (e.g. `strict` → `balanced` or `relaxed`) — security posture weakened |
| Core | `browserMitigationAction` | Baseline is `block`, target is not `block` — suspicious browsers will not be blocked |
| Mobile Detection | `allowAndroidRootedDevice` | Baseline disables rooted Android devices, target allows them |
| Mobile Detection | `allowEmulators` | Baseline blocks emulators, target allows them |
| Mobile Detection | `allowJailbrokenDevices` | Baseline blocks jailbroken iOS devices, target allows them |
| Mobile Detection | `blockDebuggerEnabledDevice` | Baseline blocks debugger-enabled devices, target does not |

### What triggers Warning findings — Bot Defense mode

| Section | Field | Trigger |
|---------|-------|---------|
| Core | `enforcementMode` | Any other enforcement mode mismatch not covered by Critical |
| Core | `template` | Template upgraded or changed laterally |
| Core | `allowBrowserAccess` | Setting differs from baseline |
| Core | `apiAccessStrictMitigation` | API access strict mitigation differs from baseline |
| Core | `dosAttackStrictMitigation` | DoS attack strict mitigation differs from baseline |
| Core | `signatureStagingUponUpdate` | Signature staging upon update differs from baseline |
| Core | `crossDomainRequests` | Cross-domain requests setting differs from baseline |
| Mobile Detection | `allowAnyAndroidPackage` | Differs from baseline |
| Mobile Detection | `allowAnyIosPackage` | Differs from baseline |
| Mobile Detection | `clientSideChallengeMode` | Differs from baseline |

### What triggers Info findings — Bot Defense mode

| Section | Field | Trigger |
|---------|-------|---------|
| Core | `performChallengeInTransparent` | Differs from baseline |
| Core | `singlePageApplication` | Differs from baseline |
| Core | `deviceidMode` | Device ID mode differs from baseline |
| Core | `gracePeriod` | Grace period value differs from baseline |
| Core | `enforcementReadinessPeriod` | Enforcement readiness period differs from baseline |

---

## Architecture

```
src/
├── main.py                  # CLI entry point (argparse, audit mode dispatch)
├── bigip_client.py          # iControl REST client (token auth, chunked transfers)
├── policy_exporter.py       # WAF policy discovery + async export workflow
├── virtual_server_inventory.py # WAF virtual server + LTM policy/host mapping inventory (read-only)
├── policy_parser.py         # XML → normalized Python dict (lxml / stdlib fallback)
├── policy_comparator.py     # WAF diff engine → ComparisonResult + DiffItem dataclasses
├── bot_defense_auditor.py   # Bot Defense profile discovery + REST fetch workflow
├── bot_defense_comparator.py # Bot Defense diff engine (JSON profile comparison)
├── report_generator.py      # Markdown reports + interactive HTML dashboard + summary reports
└── utils.py                 # Logging, retry decorator, filename helpers
```

**Key design decisions:**

- **ThreadPoolExecutor** with configurable concurrency for parallel exports
- **O(1) signature lookups** using dict keyed by `signatureId`
- **Proactive token refresh** at 80% of token lifetime — avoids mid-run 401s
- **1 MiB chunk download loop** — required by F5 file-transfer endpoint limit
- **lxml with stdlib fallback** — `lxml` is faster and more tolerant; stdlib used if unavailable
- **Credential masking** — passwords and tokens are masked in all log output

---

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

Tests use XML fixtures in `tests/fixtures/`:
- `baseline_policy.xml` — reference policy with known settings
- `target_policy_drifted.xml` — deliberately modified policy with documented drifts

---

## Troubleshooting

### Authentication Failures

```
ERROR: Authentication failed for user 'admin'. Check credentials and that the
account has the Resource Administrator or Application Security Administrator role.
```

- Verify credentials with: `curl -sk -X POST https://BIGIP/mgmt/shared/authn/login -d '{"username":"admin","password":"...", "loginProviderName":"tmos"}'`
- Ensure the account is not locked out
- RADIUS/LDAP users may need `loginProviderName` changed from `tmos`

### SSL Certificate Errors

```
requests.exceptions.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED]
```

- Add `--no-verify-ssl` (or set `verify_ssl: false` in config) for self-signed certs
- To use a CA bundle: modify `bigip_client.py` to pass `verify="/path/to/ca-bundle.pem"`

### Large Policy Downloads Truncated

The tool automatically handles the F5 1 MiB download chunk limit via `Content-Range`
headers. If a downloaded file is smaller than expected, check:
- Network interruptions (retry logic will handle transient failures)
- BIG-IP disk space on the `/var/ts/` partition

### Policy Export Timeout

```
ExportError: Export task ... timed out after 120s
```

- Large policies (hundreds of signatures) can take longer — currently not configurable
- Check BIG-IP CPU/memory under `tmsh show sys performance` during export

### Insufficient Privileges

The minimum required BIG-IP role is **Application Security Administrator**
(or Resource Administrator). To verify:

```bash
tmsh list auth user admin | grep role
```

---

## Security Considerations

1. **Credential Handling** — Passwords are never written to log files (masked as `***MASKED***`). Use environment variables or interactive prompt rather than CLI `--password` to avoid credentials appearing in shell history.

2. **Read-Only Operation** — The tool only performs read operations and export task initiation. It never calls `apply-policy`, `create`, `modify`, or `delete` endpoints. All state changes are limited to exporting a file to BIG-IP's local `/var/ts/` transfer directory.

3. **SSL Verification** — `--no-verify-ssl` is convenient but disables MITM protection. Use only on isolated management networks. Always use `--verify-ssl` in production.

4. **Token Storage** — Auth tokens are held in memory only and are never written to disk.

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
