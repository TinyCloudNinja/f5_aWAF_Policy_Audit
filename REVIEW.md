# Code Review — F5 aWAF Policy Auditor

Findings grouped by category. Severity tags: `SEC-HIGH`, `SEC-MED`, `BUG`, `NIT`.

---

## 1. Security Concerns

### SEC-HIGH — SSL verify_ssl string-parsing is inverted (`main.py:273-276`)

```python
_raw_ssl = _resolve(args.verify_ssl, "VERIFY_SSL", bigip_cfg.get("verify_ssl"), False)
if isinstance(_raw_ssl, str):
    verify_ssl = _raw_ssl.lower() in ("0", "false", "no")   # ← inverted
```

When the env-var or config supplies a string, the membership-test maps `"false"` → `True`
(verification **enabled**) and `"true"` → `False` (verification **disabled**). Every
string value from `VERIFY_SSL` produces the opposite of its stated meaning. The default
path (non-string `False`) is unaffected, but any operator who sets `VERIFY_SSL=true`
expecting to turn on verification will silently run with an unverified TLS channel.

Fix: replace `in ("0", "false", "no")` with `in ("1", "true", "yes")`.

This is simultaneously a **correctness bug** and a **security bug**.

---

### SEC-HIGH — Token refresh fails after first authenticate() (`bigip_client.py:110, 121`)

`authenticate()` deliberately clears the credential with `self._password = ""` (line 110)
to limit its in-memory lifetime. `_ensure_token()` (line 121) re-calls `authenticate()`
when the token nears expiry (80% of lifetime = ~16 minutes for a 1200-second token).
Because `self._password` is now `""`, the second authentication attempt POSTs an empty
password to BIG-IP, receives a 401, and raises `AuthenticationError`.

Under `ThreadPoolExecutor` in `policy_exporter.export_all()`, the error propagates
through each worker's `_request()` → `_ensure_token()` chain. Long audit runs that
cross the 16-minute mark will have all in-flight exports fail silently. The tool
exits with code 1, but the log message says "token expired, re-authenticating" without
making it obvious that all subsequent operations are broken.

Fix options: (a) store the credential securely and clear it only in `close()`;
(b) accept a credential-renewal callback so the caller can inject a fresh password;
(c) document that runs are expected to complete in under 16 minutes.

---

### SEC-MED — `_MaskFilter` does not cover git HTTPS credential URLs (`utils.py:26-38`, `gitlab_state.py:255-257`)

`_run()` in `gitlab_state.py` logs failed commands with:

```python
raise RuntimeError(stderr or stdout or f"Command failed ({proc.returncode}): {' '.join(cmd)}")
```

and:

```python
self.log.debug("Command failed (ignored): %s :: %s", " ".join(cmd), stderr or stdout)
```

Both paths may include `self.repo_url` if the `git clone` command fails. If the URL is
`https://user:password@gitlab.example.com/repo.git`, the embedded password appears in
the log record. None of the six `_MaskFilter` regex patterns (`"password":`, `password:`,
`X-F5-Auth-Token:`, `password=`, `Bearer `) match the `https://user:PASSWORD@host`
URL form. Git also echoes the URL in some error messages on stderr, which doubles the
exposure.

Fix: add a pattern such as `(https?://[^:@/]+:)[^@/]+(@)` → `\g<1>***MASKED***\g<2>`.

---

### SEC-MED — `_parse_content_range_total` is dead code (`bigip_client.py:284-297`)

This helper is defined but never called anywhere in the codebase. Its presence implies
it may have been intended to be used in `download_file()` to know when to stop looping,
but the current loop uses chunk size and `expected_size` instead. No direct security
impact, but dead code increases the attack surface analysis burden.

---

### SEC-MED — XXE stdlib fallback lacks explicit hardening notice (`policy_parser.py:752-754`)

```python
else:
    # stdlib ElementTree does not process external entities by default.
    return ET.parse(str(path))
```

The comment is accurate for CPython's current ElementTree (external general entities
are not resolved), but the defusedxml project documents that system entities
(`<!ENTITY foo SYSTEM "file:///etc/passwd">`) were not fully blocked until Python 3.8.
Since the policy is to use local BIG-IP exports (not attacker-supplied XML), the
practical risk is low, but the hardening guarantee should be version-conditioned or
`defusedxml` should be added as a dependency.

No immediate fix required; document the assumption in a comment.

---

### SEC-MED — Server-supplied filename used without URL encoding in download path (`policy_exporter.py:558-561`)

```python
raw_filename = result.get("filename", filename)
reported_filename = Path(raw_filename).name or filename          # filesystem traversal prevented
dl_path = f"{self._DOWNLOAD_BASE_EP}/{reported_filename}"       # URL not encoded
```

`Path(...).name` correctly prevents filesystem path traversal. However,
`reported_filename` is then concatenated directly into a URL without percent-encoding.
If BIG-IP returns a filename containing URL metacharacters (e.g., `?`, `#`, `%2F`),
the `GET` request path could be malformed or redirect to a different resource. Since
BIG-IP fully controls the task result, this is a trust-boundary issue rather than an
injection opportunity, but it should be encoded with `urllib.parse.quote(reported_filename, safe="")`.

---

## 2. Correctness Bugs

### BUG — Duplicate import of `generate_markdown` and `generate_summary_reports` in `main.py` (`main.py:37-39`)

```python
from .report_generator import generate_html, generate_markdown, generate_summary_reports
from .report_generator import generate_html_dashboard, generate_markdown, generate_summary_reports
```

Line 37 imports `generate_html` (unused in `main.py` — the dashboard is used instead)
plus two names that are immediately re-imported on line 39. `generate_html` is dead
code from `main.py`'s perspective. The first import line should be removed; the second
is correct.

---

### BUG — Module docstring contains garbled text (`main.py:1-18`)

The phrase "Monthly CSM Sync" appears twice inside the usage example, interleaved with
the command strings, breaking the copy-paste examples in the module-level docstring.
Appears to be a merge/edit artifact.

---

### BUG — `_build_policy_report_fragment` defined twice in `report_generator.py` (lines 623 and 1828)

Python's module loader processes top-to-bottom: the definition at line 1828 silently
overwrites the one at line 623. The line-623 copy is therefore permanently dead. Both
functions share the same signature. The live copy (line 1828) is the more complete
implementation (handles Bot Defense tables, blocking comparison, the full collapsible
section set). The line-623 version should be removed.

---

### BUG — `generate_html_dashboard` defined twice in `report_generator.py` (lines 838 and 2004)

Same overwrite mechanism: the line-2004 definition is live; the line-838 definition
is dead. The two implementations produce significantly different HTML structures.
Any caller between lines 838 and 2004 in the module that references
`generate_html_dashboard` would be using the line-838 version at parse time but
the line-2004 version at call time — not a real problem because no intra-module call
exists in that range, but it increases confusion considerably. The line-838 copy
should be removed.

---

### BUG — `generate_html` is imported but never called from `main.py` (`main.py:37`, `report_generator.py:808`)

`generate_html` (per-policy single-report writer) was superseded by the multi-policy
`generate_html_dashboard`. `main.py` no longer calls it in either the WAF or BOT path.
It is a valid public API function and calls the correct (live) `_build_policy_report_fragment`.
Decision required: keep as a supported single-report utility (document it) or remove
and add it back when a caller exists.

---

### BUG — `iterable = successes` assigned but never used (`main.py:545`, `main.py:719`)

In both `_run_waf_audit()` and `_run_bot_audit()`, the assignment `iterable = successes`
is made but `iterable` is never referenced — the for-loop on the very next line
iterates directly over `successes`. Dead assignment; remove both.

---

### BUG — Token refresh will always fail for runs exceeding ~16 minutes

See SEC-HIGH item above. Classified here also because it is a functional correctness
failure independent of any adversarial scenario.

---

### BUG — SSL verify_ssl string-parsing inversion

See SEC-HIGH item above.

---

## 3. Design Observations (not bugs; relevant for Phase 1/2)

### NIT — `bot_defense_auditor._fetch_all_vs` requests `partition` but derives it from `fullPath`

`params={"$select": "name,fullPath,destination,partition"}` at `bot_defense_auditor.py:227`
fetches `partition` from the API, but the immediately following loop re-derives the
partition from `fullPath` (line 236-237) and does not use the returned `partition`
field. The `$select` could drop `partition` without changing behavior, or the code
could use the returned field directly instead of re-parsing `fullPath`.

---

### NIT — `_parse_content_range_total` defined but never called (`bigip_client.py:284`)

See SEC-MED item above. Can be removed.

---

### Design — `gitlab_state.py` is already provider-agnostic

The module name says "GitLab" but there is no GitLab-specific API call — every
operation goes through plain `git` subprocess commands. Renaming to `git_state.py`
and the config block from `gitlab:` to `git:` in Phase 1 is straightforward and
accurate. The existing `--gitlab-*` CLI flags can be kept for one release with a
deprecation warning.

---

### Design — Baseline is currently a single shared file; Phase 2 makes it per-policy

The current architecture compares every policy against the same baseline XML. Phase 2
introduces per-policy source-of-truth files under `source_of_truth/<mode>/<partition>/<name>`.
`gitlab_state.py` already builds and resolves these paths via `_sot_file_path()` and
`load_waf_source_of_truth()` / `load_bot_source_of_truth()`. The comparison loop in
`_run_waf_audit()` already does a source-of-truth comparison when `gitlab_state is not None`.
Phase 2 will make this the primary flow rather than an optional secondary path.

---

### Design — Single-device, single-run architecture

All connection and credential state is flat (one `BigIPClient`, one `PolicyExporter`,
one auth session per invocation). Phase 1's multi-device config schema will require
iterating over devices with separate client instances. The current architecture
composes cleanly: `main()` can loop over a device list and call `_run_waf_audit()` /
`_run_bot_audit()` once per device, provided each call gets its own `BigIPClient`.

---

### Design — `_PASS_THRESHOLD` is a module-level constant in `main.py`

`_PASS_THRESHOLD = 90.0` is defined in `main.py` and duplicated implicitly by usage in
`report_generator.py` (which also references it). Phase 1 hoists it into
`config.yaml` under `audit.pass_threshold` and should centralise it into
`config_manager.py` so that `report_generator.py` receives it as a parameter rather
than importing from `main.py` or maintaining its own copy.

---

### Design — `shutil.copy2` in `update_waf/bot_source_of_truth` preserves source permissions

If the exported XML/JSON file was created with permissive umask bits (e.g., `0o644`),
`shutil.copy2` will carry those bits into the repo. The repo directory is created with
`ensure_dir()` (`0o700`), which provides OS-level protection, but the file permissions
themselves are inconsistent with the stated security stance. Using `shutil.copy` (no
metadata copy) followed by `os.chmod(dst, 0o600)` would be more explicit.

---

## Phase 0 — Audit Findings: API-Driven Refactor + Interactive TUI

> **Test baseline (recorded before any Phase 0+ code changes):**
> `python -m pytest tests/ -v` — **164 passed, 0 failed** (Python 3.11.15, pytest 9.0.3)

---

### A. XML / Baseline Dependency Map

**Important context:** A prior refactor already removed the
`/mgmt/tm/asm/tasks/export-policy` export-task workflow. The WAF target
data is now collected via `PolicyInspector` (targeted REST GET calls). The
remaining XML dependency is the **on-disk baseline file** supplied via
`--baseline`. The new refactor eliminates that file dependency by selecting
the baseline policy directly from the BIG-IP via API + interactive menu.

#### Locations where `policy_parser.parse_policy()` is called

| Location | Function | Purpose |
|---|---|---|
| `src/main.py:32` | module import | `from .policy_parser import parse_policy` |
| `src/main.py:769` | `_run_waf_audit()` | `raw_baseline = parse_policy(baseline)` — parses on-disk XML baseline |
| `src/gitlab_state.py:23` | module import | `from .policy_parser import parse_policy` |
| `src/gitlab_state.py:93` | `load_waf_source_of_truth()` | `return parse_policy(str(path)), ...` — parses XML SoT files from Git repo |

#### Locations where `policy_parser` symbols are imported elsewhere

| Location | Symbol | Purpose |
|---|---|---|
| `src/report_generator.py:16` | `_XML_VIOL_ID_ALIASES` | Used in HTML report rendering for violation name normalization |

#### `--baseline` filesystem-path CLI argument

| Location | Note |
|---|---|
| `src/main.py:158–162` | `--baseline` argument definition (accepts XML or JSON path) |
| `src/main.py:398` | `baseline = _resolve(args.baseline, "BASELINE_POLICY", ...)` |
| `src/main.py:482–489` | Required for non-inspect modes; missing → early exit |
| `src/main.py:537–550` | File existence check + `_validate_xml()` call (WAF mode) |
| `src/main.py:765–774` | `parse_policy(baseline)` → `raw_baseline` |
| `src/main.py:773` | `baseline_name = Path(baseline).name` |

#### XML validation

| Location | Function | Note |
|---|---|---|
| `src/main.py:13` | module-level | `import xml.etree.ElementTree as ET` (used only by `_validate_xml`) |
| `src/main.py:206–211` | `_validate_xml(path)` | `ET.parse(path)` — aborts with clear error if not valid XML |
| `src/main.py:549–550` | `_run_waf_audit()` dispatch | `_validate_xml(baseline)` called before authentication |

#### Confirmed NOT present in current codebase

- **No calls to `/mgmt/tm/asm/tasks/export-policy`** — the async export task was removed in a prior refactor.
- **No XML file download** — `bigip_client.download_file()` (`bigip_client.py:212`) exists but is not called from any current code path.
- **No upload calls** — `bigip_client.upload_file()` (`bigip_client.py:183`) exists but is unused.
- `src/policy_exporter.py` is misleadingly named: it performs policy **discovery** and VS enrichment only; it has no export-task or file-download logic.

#### What the refactor must change

1. Remove `--baseline` (filesystem path) from CLI.
2. Replace `parse_policy()` baseline call in `_run_waf_audit()` with `PolicyFetcher.fetch_waf_policy(baseline_policy_id)`.
3. Update `gitlab_state.load_waf_source_of_truth()` to deserialize JSON instead of XML (new SoT files will be serialized API dicts; keep XML fallback for existing files during Phase 4 transition).
4. Remove or deprecate `policy_parser.py` (keep `_XML_VIOL_ID_ALIASES` accessible elsewhere if still needed by `report_generator.py`).
5. Remove `import xml.etree.ElementTree as ET` from `main.py` once `_validate_xml` is deleted.

---

### B. Blocking-Settings API Parity Audit

#### Current `PolicyInspector` approach (partial data)

`PolicyInspector._fetch_violations()` (`policy_inspector.py:156`) fetches
violations via:

```
GET /mgmt/tm/asm/policies/{id}/blocking-settings/violations
    ?$filter=alarm+eq+true+or+block+eq+true+or+learn+eq+true
    &$top=25&$skip=N
```

The filter means **only violations where at least one flag is `true` are
returned**. Violations at all-`false` default state are absent from the
response. The inspector builds an "all" list that reconstructs missing
violations from the per-flag lists, but this is still incomplete relative
to the full device policy state. This is the core motivation for the Phase 2
`PolicyFetcher` rewrite.

**Current inspector does NOT fetch:** evasions, HTTP-protocol checks, or
web-services-security settings.

#### New `PolicyFetcher` approach (full data, paginated)

Fetch all four blocking-settings sub-resources without a filter flag:

| Endpoint | Typical item count | Key fields |
|---|---|---|
| `.../blocking-settings/violations` | 180–220 | `name`, `description`, `alarm`, `block`, `learn`, `sectionReference` |
| `.../blocking-settings/evasions` | 8–12 | `description`, `enabled` |
| `.../blocking-settings/http-protocols` | 15–25 | `description`, `enabled` |
| `.../blocking-settings/web-services-securities` | 6–10 | `description`, `enabled` |

**Total items across all four sub-resources:** typically 210–270. A single
page of `$top=500` covers all items with no pagination needed in practice.
Pagination should still be implemented defensively using the `totalItems`
field in the response envelope.

#### Pagination pattern

```
GET /mgmt/tm/asm/policies/{id}/blocking-settings/violations?$top=500&$skip=0
→ {"totalItems": N, "items": [...]}

# If len(items) < totalItems, repeat with $skip += len(items) until exhausted.
```

The `get_all()` helper in `bigip_client.py` should implement this loop.
`totalItems` is always present for `/asm/policies/{id}/*` sub-resources
(confirmed behavior across BIG-IP 13.x–17.x).

#### Field name normalization note

The REST API returns violations with `name` as the machine ID
(e.g., `VIOL_ASM_COOKIE_MODIFIED`) and `description` as the human-readable
label. This is the inverse of what `policy_parser._parse_blocking_item()`
returns for the `<blocking-settings>` XML section format, where `name` is
the human-readable string. The `policy_comparator.py` joins violations on
`name`; the normalized dict from `PolicyFetcher` must use the machine ID as
`name` (consistent with the `<blocking>` XML section's machine ID format
already handled by the comparator).

---

### C. Bot Defense API Surface Map

The existing `BotDefenseAuditor` (`bot_defense_auditor.py`) already fetches
full Bot Defense profile data via `_expand_references()`. The `PolicyFetcher`
Bot mode will follow the same pattern.

| Endpoint | Key fields returned |
|---|---|
| `GET /mgmt/tm/security/bot-defense/profile` | `name`, `fullPath`, `template`, `enforcementMode`, `selfLink`, plus `*Reference` keys |
| `GET /mgmt/tm/security/bot-defense/profile/{name}` | All top-level fields: `enforcementMode`, `template`, `browserMitigationAction`, `allowBrowserAccess`, `apiAccessStrictMitigation`, `dosAttackStrictMitigation`, `mobileDetection{}`, plus inline/reference sub-collections |
| `*Reference` subcollections | Expanded via `GET <selfLink>` for each reference key in `_BD_OVERRIDE_REF_KEYS` |

**Sub-collection reference keys** (expanded by current `BotDefenseAuditor._expand_references()`):
`anomalyCategoryOverridesReference`, `anomalyOverridesReference`,
`classOverridesReference`, `externalDomainsReference`,
`microServicesReference`, `signatureCategoryOverridesReference`,
`signatureOverridesReference`, `siteDomainsReference`,
`stagedSignaturesReference`, `whitelistReference`

**Baseline selection (BOT mode):** Filter the profile list for
`name.lower().startswith("bst")` — the same `BASELINE_PREFIX` constant used
for WAF mode.

**If Bot Defense module is not licensed:** `GET /mgmt/tm/security/bot-defense/profile`
returns a `404` with a message like `"01020036:3: The requested object does not exist"`.
The `PolicyFetcher` must catch this and raise a user-friendly error:
`"Bot Defense module not licensed or not enabled on this device."` then exit
cleanly (code 1). Do not crash with an unhandled exception.

---

### D. questionary vs simple-term-menu Decision

**Recommendation: `questionary>=2.0`**

| Criterion | questionary | simple-term-menu |
|---|---|---|
| Arrow-key select | Yes (prompt_toolkit) | Yes (pure ANSI) |
| Multi-select (checkbox) | Yes (`questionary.checkbox`) | Yes |
| Password input | Yes (`questionary.password`) | **No** |
| Confirm prompt | Yes | No |
| SSH / tmux compatibility | Excellent (prompt_toolkit detects terminal caps) | Good |
| Windows Terminal compat | Good | Fair |
| Maintenance status | Active (2024 release) | Moderate |
| Dependency weight | prompt_toolkit (~500 KB) | Minimal |

**Decision rationale:**

1. `questionary.password()` is a hard requirement — the interactive password
   prompt must hide input. `simple-term-menu` has no equivalent.
2. The existing `PLAN.md` (Step 1.4) already specifies `questionary>=2.0`;
   consistency avoids rework.
3. Federal lab / BIG-IP SSH tunnel environments typically run xterm or
   xterm-256color terminals over OpenSSH. `prompt_toolkit` detects
   `$TERM` and `$COLORTERM` and degrades gracefully to dumb-terminal mode
   when needed, making it more robust than raw ANSI escape sequences across
   diverse terminal emulators.
4. `questionary` on tmux works correctly provided the tmux outer terminal
   reports `$TERM=xterm-256color` (standard default).

**CI/CD bypass:** When `--mode`, `--baseline-policy`, and `--password` are
all provided on the command line, no `questionary` call is made. The
dependency is present but dormant in non-interactive runs.

---

### E. Test Baseline (Pre-Refactor)

Recorded before any Phase 0+ code changes:

```
platform linux -- Python 3.11.15, pytest-9.0.3
164 passed in 1.50s
```

**Zero pre-existing failures.** All subsequent phases must preserve this
green baseline throughout.
