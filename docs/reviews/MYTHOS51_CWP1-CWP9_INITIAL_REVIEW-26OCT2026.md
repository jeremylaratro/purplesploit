# PurpleSploit CWP1–CWP9 Initial Capability Review (Mythos 5.1, review 1 of 2)

**Date:** 26 October 2026
**Baseline:** `main` at `c962994` plus the uncommitted working tree (workflow, auto-enum, credential-spray changes and their tests)
**Mode:** read-only; unit tests executed locally; no live tools, no targets
**Binding direction:** capability first. Everything in S19–S23 (authorization, ROE, permission contracts, spray budgets, secret/evidence integrity, containment, plugin trust, AI privacy, app security, supply chain, licensing, release certification) stays there. Where this review names a prerequisite it is a *technical capability dependency*, labelled as such.

---

## 1. Executive verdict

**The CWP1 restoration batch is real but partial. It fixed the crash class the review reported; it did not yet make the advertised automation truthful or useful end to end. Continue, but do not close gate C0 and do not start CWP2 technique breadth until the five items in §1.2 land, because every later package builds on the same observation/execution contract that is still missing.**

### 1.1 What is verified as fixed (code, not prose)

| Claim in roadmap §7 | Verified against code |
|---|---|
| Workflows use live instances, not metadata | Yes. `workflow.py:839` uses `use_module`; validation at `workflow.py:659-695` checks module + exact operation name before execution. |
| Step failure propagates to workflow state | Yes. `_update_result_summary` (`workflow.py:562-625`) rebuilds counts from persisted step state; `success` is true only on `COMPLETED`. |
| Unknown conditions fail closed; `forms_found` implemented | Yes. `workflow.py:697-715` rejects at validation, `workflow.py:771-775` rejects at evaluation; `forms_found` at `workflow.py:756-758`. |
| Template SMB operation names corrected | Yes. `Spider Only (No Download)` matches `nxc_smb.py:109`. |
| Auto-enum selects real Nmap operations and skips Nmap in passive scope | Yes. `auto_enum.py:399-408` maps to the seven real operations in `nmap.py:158-201`; passive returns at `auto_enum.py:378-380`. |
| Auto-enum forces synchronous Nmap | Yes, for `recon/nmap` only (`auto_enum.py:930-931`). |
| Auto-enum retains host/port/protocol identity | Yes. `_normalize_endpoint` / `discovered_endpoints` (`auto_enum.py:759-810, 1070-1102`). |
| All default-rule operation names exist on registered modules | Yes. Independently re-checked against `nxc_smb.py:88-137`, `nxc_ldap.py:80-94`, `nxc_rdp.py:46-49`, `dns.py:68`, `nuclei.py:132`, `kerbrute.py:105`; and `test_auto_enum_contract.py:135-146` enforces it with a real `Framework`. |
| Spray maps only protocols with a real auth operation | Yes. `credential_spray.py:195-201` (SMB, WinRM, SSH, RDP, MSSQL); `Test Authentication` exists on each. |
| Spray runs through `Framework.run_operation` | Yes. `credential_spray.py:567`. |
| Spray distinguishes process success from credential success | Yes. `_interpret_auth_result` (`credential_spray.py:580-647`). |
| Tests pass | 262 targeted tests pass here (`test_workflow*.py`, `test_auto_enum*.py`, `test_credential_spray.py`). Full-suite numbers: see §7.4 (this environment lacks `prompt_toolkit` and `pytest-benchmark`, so UI and benchmark tests error on collection; that is an environment limitation, not a product regression). |

### 1.2 Why C0 must stay open (ordered by impact)

1. **The built-in `quick_recon` and `full_network_assessment` templates still report success on a scan that has not finished.** Step 1 is `recon/nmap_fast` with no operation, so `WorkflowEngine` calls `run_module` (`workflow.py:878`); `NmapFastModule` inherits `BACKGROUND="true"` (`nmap.py:131-136`), returns `{"success": True, "background": True}` immediately (`nmap.py:604-621`, `module.py:594-600`), and the step is marked `SUCCESS` (`workflow.py:890-891`). No services are extracted, the `service_found` step is skipped, and the workflow finishes `COMPLETED` with `success: true`. The synchronous override exists only in auto-enum and only for `recon/nmap` (`auto_enum.py:930`). The S0 exit criterion "quick recon completes or fails truthfully" is therefore not met for the real template.
2. **No module emits the observations the engines gate on.** `_extract_workflow_data` (`workflow.py:943-979`) and auto-enum (`auto_enum.py:1001-1003`) read top-level `services`, `users`, `credentials`, `forms`, `findings`. Across `modules/` only `recon/nuclei` emits `findings` (`nuclei.py:330-332`) and `osint/shodan` emits `services` (`shodan.py:292-304`); Nmap nests under `parsed` (`module.py:661`, `nmap.py:495-519`); nothing emits `users`, `credentials`, `forms`, or `is_admin`. Consequently these template steps can never execute: `web_application_test`/sqlmap, `ad_assessment`/AS-REP + Kerberoast, `full_network_assessment`/secretsdump, `credential_harvest`/AS-REP + Kerberoast; and every `requires_auth` auto-enum rule is dead (§2.2 A3). Fail-closed is correct; the templates are hollow until producers exist. This is the `Observation` contract the roadmap lists as open, and it is the single technical dependency for CWP2–CWP6.
3. **Auto-enum writes host IPs into `DOMAIN` for kerbrute and dns** (`auto_enum.py:653-655`; `kerbrute.py:45-47`, `dns.py:44-47`), so two default rules dispatch invalid commands by construction.
4. **No background job model.** `workflow run`, `auto`, and `spray` block the CLI thread (`commands.py:3447, 4155, 4895`); `workflow pause` can only be typed after the run has already finished, so `pause_workflow` always returns false from the operator surface. Pause/resume is only reachable from tests that mutate status inside a callback.
5. **Parallel auto-enum is not thread-safe** (`auto_enum.py:491-506` runs `_run_enumeration_phase` in threads; `use_module` mutates `session.current_module`/`module_history` (`session.py:52-64`); `store_results` mutates an unsynchronized dict (`session.py:81-93`); `self._lock` at `auto_enum.py:272` is never used).

### 1.3 Readiness to continue

Continue with the *remaining* CWP1 items (ExecutionRequest/Result/Observation, the five fixes above, real-framework template runs). The code quality of the batch is good: contracts are enforced at validation, tests use a real `Framework` with only the process boundary faked, and the operation-name mismatches are gone. The gap is that the batch repaired the engines without repairing the producers they consume.

---

## 2. Concrete findings in the current diff

Severity: **H** blocks a CWP exit criterion; **M** produces wrong or misleading results; **L** quality/consolidation.

### 2.1 `python/purplesploit/core/workflow.py`

| # | Sev | Finding | Evidence |
|---|---|---|---|
| W1 | H | Background Nmap wrappers are marked SUCCESS before the scan runs (see §1.2.1). Also `run_module` never applies a timeout: `module.py:657` calls `execute_command(command)` with `timeout=None`, so a synchronous `-p-` scan can block the engine indefinitely. | `workflow.py:878`, `nmap.py:131-136, 604-621` |
| W2 | H | `service_found` falls back to a **global** service query: `framework.database.get_services()` with no target (`workflow.py:797`). Any service recorded for any host in any prior session satisfies the condition. `get_services(target)` exists (`database.py:686`). | `workflow.py:795-806` |
| W3 | H | Condition producers missing (see §1.2.2). `has_user_list`, `has_valid_creds`, `has_admin_creds`, `forms_found` have no producer in any module. | `workflow.py:743-758, 943-979` |
| W4 | M | DAG fields are dead API: `on_success` is never read; `on_failure` is used as a boolean "continue" flag (`workflow.py:498`), its step IDs are never dispatched; `timeout` and `retry_count` are never used. Execution is strictly linear. | `workflow.py:44-47, 498` |
| W5 | M | Pause/resume unreachable from the CLI (see §1.2.4); `resume_workflow` re-enters `run_workflow`, which is fine, but nothing can set `PAUSED` while the loop holds the thread. | `workflow.py:539-560`, `commands.py:3447, 3490-3502` |
| W6 | M | Persistence: `create_workflow` does not save; `list_workflows` is memory-only; the CLI `workflow list` never calls `load_workflow`, so workflows in `~/.purplesploit/workflows` are invisible after restart and cannot be resumed. `storage_path` is created in `__init__` even under tests. | `workflow.py:354-399, 981-996`, `commands.py:3317-3321` |
| W7 | M | Validation has side effects: `_validate_workflow` calls `use_module` for each pending step with an operation (`workflow.py:675`), which replaces `session.current_module` and appends to `module_history` (`session.py:59-64`). `dry_run=True` does the same. | `workflow.py:673-686` |
| W8 | M | Target injection sets `RHOST` and `TARGET` from `variables["target"]` and `URL` only when a scheme is present (`workflow.py:855-862`). The web template with an IP target fails `sqlmap`/`feroxbuster` validation ("Required option not set: URL", `sqlmap.py:42-45`). Truthful, but the template cannot work until httpx observations synthesize URLs (CWP3 dependency). | `workflow.py:855-862` |
| W9 | L | Two operation resolvers with different semantics: `_find_operation` is exact-match (`workflow.py:914-926`); auto-enum `_resolve_operation` adds a casefold fallback (`auto_enum.py:613-625`); spray does its own casefold match (`credential_spray.py:550-559`). Should be one `Framework.find_operation`. | |
| W10 | L | Step option names are validated only at execution (`workflow.py:849-852`); `_validate_workflow` could reject them during `dry_run`. `use_module` returning `None` sets FAILED then raises `RuntimeError` that is immediately caught (`workflow.py:840-844, 901-904`): harmless redundancy. | |
| W11 | H | Two templates reference an **interactive** operation. `Spider Only (No Download)` calls `input()` twice (`nxc_smb.py:299-300`). `full_network_assessment` step 4 and `credential_harvest` step 1 therefore block on stdin in the CLI and raise `EOFError` (step FAILED) under the API, an agent, or tests. 17 of the 42 `nxc_smb` handlers prompt (`nxc_smb.py:195-368`); the operation catalog has no flag that says so, so neither validation nor the contract test can detect it. | |

### 2.2 `python/purplesploit/core/auto_enum.py`

| # | Sev | Finding | Evidence |
|---|---|---|---|
| A1 | H | `_set_module_target` picks the first *required* option among URL/TARGET/RHOST/DOMAIN. For `ad/kerbrute` (DOMAIN required, DC optional) and `recon/dns` (DOMAIN required) the host IP becomes the domain name, so the kerberos and dns rules issue `kerbrute userenum -d <ip>` and AXFR for zone `<ip>`. The DC option (`kerbrute.py:51`) and `NAMESERVER` (`dns.py:50`) should receive the IP; the domain must come from an observation (SMB/LDAP banner, DNS SOA). The roadmap acknowledges dns only. | `auto_enum.py:627-674` |
| A2 | H | Port identity is dropped for TARGET-style modules: `PORTS` is written only when `"PORTS" in options` (`auto_enum.py:673-674`), so httpx gets the port but nuclei (TARGET only, no PORTS) scans the bare IP; an https service on 8443 is never scanned on 8443. `_build_service_url` (`auto_enum.py:677-690`) exists and should feed TARGET for URL-capable tools. Rule mismatch: the nuclei rule is `service="http", ports=[80, 443]` (`auto_enum.py:189-196`) but 443 is normalized to `https` (`auto_enum.py:103-104`), so nuclei never runs on 443 and no https rule exists for nuclei or feroxbuster. | |
| A3 | H | Authenticated rules are dead: `requires_auth` gates on `_has_credentials()` → `discovered_credentials`, which is fed only by result `credentials` keys that no module emits; session credentials (`framework.session.credentials`) are never consulted. The exploitation phase (`auto_enum.py:508-542`) has no rules in `EnumPhase.EXPLOITATION` and iterates the original CIDR targets rather than discovered hosts. | `auto_enum.py:455-457, 1001, 1104-1106` |
| A4 | H | Parallel mode is unsafe (§1.2.5). | `auto_enum.py:272, 491-506` |
| A5 | M | Summary is not truthful: `"success": len(failed) == 0 or len(successful) > 0` is true if any single module succeeded; `targets_scanned` counts hosts with services, not targets scanned; failures from A1 are silently absorbed. | `auto_enum.py:1143-1147` |
| A6 | M | Artifacts and importers: Nmap writes `-oA nmap_<target>` relative to the process CWD (`nmap.py:374-386, 597-602`) and auto-enum re-reads the same CWD-relative file (`auto_enum.py:851-866`). Three importers run for one scan: `NmapModule.process_discovered_hosts` (session + core DB + models DB), the auto-enum XML re-parse, and the session-delta heuristic (`auto_enum.py:887-903`) that attributes any concurrent session change to this scan. No run directory / artifact root exists. | |
| A7 | M | No timeout on synchronous discovery (`module.py:657`), and `HOST_TIMEOUT` is never set; the NORMAL scope runs `-p- -sCV --min-rate 3900` per target. A /24 with `Default Scan` can block the pipeline for hours. | `auto_enum.py:405, 959` |
| A8 | M | The pipeline cannot start from existing knowledge: `_run_enumeration_phase` reads only `self.discovered_services` (`auto_enum.py:438-441`); running `phases=[ENUMERATION]` after an operator `parse <nmap.xml>` (`commands.py:2350-2372`) finds "No services discovered". Session (`session.py:575-585`) and DB (`database.py:686`) service indexes are ignored on entry. | |
| A9 | L | `EnumResult.discovered_services` now carries endpoint dicts but `discovered_users`/`findings` remain untyped; `_resolve_operation` duplicates workflow `_find_operation` (W9). `self._lock` unused. | |
| A10 | L | A second, unrelated auto-enum exists as a module (`modules/recon/auto_enum.py`, see §6). | |
| A11 | H | **CIDR scans register the CIDR itself as an enumeration host.** `ExternalToolModule.run` always attaches `parsed = parse_output(stdout)` (`module.py:660-661`); `NmapModule.parse_output` merges every host's open ports into one `services` dict keyed `port/proto` with no host (`nmap.py:495-519`); `_extract_discovered_services` turns those into endpoints with `target=default_target`, i.e. the CIDR string (`auto_enum.py:700-704, 759-777`). `enumeration_targets = list(self.discovered_services)` (`auto_enum.py:342`) then includes `192.0.2.0/24` with the union of all services, and every rule fires once more against the CIDR. The contract test that asserts the CIDR is absent (`test_auto_enum_contract.py:76-121`) passes only because its fake result omits `parsed.services`; the real module always includes it. | |
| A12 | H | **`Fast Scan` is a full-port scan.** `op_fast_scan` sets `PORTS` to `None` (`nmap.py:220`); `get_option` returns the default `"-"` when the value is `None` (`module.py:273-276`), so `build_command` emits `-p -` and ignores `TOP_PORTS` (`nmap.py:332-335`). The LIGHT scope therefore runs `-p- -sV --min-rate 5000` per target. `UDP Scan` has the same defect (`nmap.py:282`). The `nmap_fast` wrapper is unaffected because it changes the default (`nmap_fast.py:33-34`). The contract test checks that `Fast Scan` is *selected* (`test_auto_enum_contract.py:61`), not what it executes. | |

### 2.3 `python/purplesploit/core/credential_spray.py`

| # | Sev | Finding | Evidence |
|---|---|---|---|
| S1 | H | Session-context bleed into sprayed credentials. `Framework.run_operation` calls `module.auto_set_from_context()` (`framework.py:343`), which fills any unset `DOMAIN`/`HASH`/`DCIP`/`DNS` from the session's current credential (`module.py:424-439`). For `nxc_rdp`, `nxc_winrm`, `nxc_mssql` (all register `HASH`, e.g. `nxc_rdp.py:41`) a current credential that carries a hash makes every spray attempt authenticate with `-H <session hash>` instead of `-p <sprayed password>` (precedence in `_build_auth`-style helpers, e.g. `nxc_smb.py:153-156`), and the result is attributed to the sprayed password. `DOMAIN` is likewise inherited when `--domain` is omitted. Clearing with `set_option("HASH", None)` does not help because `auto_set_from_context` only checks `not get_option(...)`. The spray path needs a way to pin explicit options (see §5.1 `ExecutionRequest.options_locked`). | |
| S2 | M | Skipped attempts are invisible: `_can_attempt_user` returns false silently (`credential_spray.py:387-388`); with the default `LockoutPolicy.conservative()` (`safe_attempts=1`) a breadth-first spray tries only the first password per user within 30 minutes, reports a smaller `total_attempts`, and `on_progress` never reaches `total`. Recording a `skipped_budget` outcome is a capability/observability fix; the policy values themselves remain S21. | `credential_spray.py:217-229, 387-388` |
| S3 | M | Unsupported protocols are not rejected before the loop: every user/password pair is recorded as a failed attempt with "Unsupported protocol" (`credential_spray.py:514-516, 490-491`). The CLI help still advertises `--protocol ldap` (`commands.py:4701`). | |
| S4 | M | No outcome vocabulary: `SprayAttempt` has only `success`/`locked_out`/`error`. Simulated results (no framework, `credential_spray.py:492-495`), "tool ran, output ambiguous", unsupported, and skipped are indistinguishable from an observed failure. | |
| S5 | M | Per-attempt `use_module` creates a new instance, appends to `session.module_history`, logs "Loaded module", and `_record_module_results` inserts one `module_history` row and one `session.workspace` entry per attempt (`framework.py:286, 375-396`). Functionally fine; at 1,500 attempts it floods logs and the audit table with near-duplicate rows. One instance per spray plus one execution record per attempt via the execution contract is the right shape. | |
| S6 | M | Marker heuristics need golden fixtures per protocol: `[-]` anywhere forces failure even when `[+]` is present (`credential_spray.py:622-636`); SSH/MSSQL/RDP output formats differ from SMB. The regression tests only use hand-written SMB lines (`test_credential_spray.py`, `FakeAuthenticationModule`). | |
| S7 | L | LDAP and Kerberos spraying were removed rather than implemented: `nxc_ldap` lacks a `Test Authentication` operation (`nxc_ldap.py:80-94`), and `kerbrute` already has `Password Spray` (`kerbrute.py:110`) that could back `SprayProtocol.KERBEROS`. Cheap CWP2 wins. | |
| S8 | L | Side-finding for CWP2: `nxc_smb` `Pass-the-Hash` is broken. `HASH` is not a registered option (profiles `smb_auth/smb_shares/smb_execution`, `parameters.py:492-509`), so `set_option("HASH", ...)` at `nxc_smb.py:207` returns false and `_build_auth` falls through to `-p ''`. | |

### 2.4 Tests added in the diff

- `test_auto_enum_contract.py` is the right *shape* (real `Framework`, real discovery) but it replaces `Framework.run_operation` wholesale (`:51, :110, :159`), not the process boundary. The real `op_*` handlers, `validate_options`, `execute_command`, XML parsing, redaction and recording are never exercised, which is why A11 and A12 are invisible to it. The rule check (`:135-146`) only covers rules with an `operations` entry; httpx/feroxbuster/ftp rules and `rule.modules` existence are unchecked.
- `test_workflow_extended.py::TestRealFrameworkContract` uses a synthetic `ContractWorkflowModule`, not a built-in template; the template check (`:151-184`) verifies operation *names* against hard-coded classes, not that a template runs, and skips steps with no operation (`recon/nmap_fast`, `web/httpx`, `smb/enumeration`, `impacket/*`). No test runs `quick_recon` or any template end to end with real modules and a faked `subprocess.run`; that is the test that would have caught W1 and W11.
- `FakeAuthenticationModule` in `test_credential_spray.py` registers `DOMAIN` but not `HASH`, so S1 is not exercised; no spray test touches a real `nxc_*` module.
- The roadmap's "261/224/4,050 passed" figures are consistent with what runs here: 262 targeted tests pass; the full suite in this environment is 2,894 passed, 23 skipped, 143 failed, 439 errors, with every failure/error traced to missing `prompt_toolkit`, `fastapi`, or `pytest-benchmark` (UI, web, main, benchmark files). No core, module, parser, or integration test fails.

---

## 3. Dependency-ordered capability backlog (CWP1–CWP9)

Each item lists what it depends on. Items with no dependency can start now and in parallel. "Deps" reference other backlog IDs. Nothing below moves S19–S23 work earlier; where a persistence change is needed for a feature to function it is marked *(capability-scoped persistence)* and kept additive so S19 can migrate it.

### CWP1 — close gate C0 (S0–S2 remainder)

| ID | Deliverable | Deps | Closes |
|---|---|---|---|
| B1.1 | **Execution contract.** `ExecutionRequest` (argv, cwd/run_dir, env allow-list, timeout, background flag, stdin policy) and `ExecutionResult` (exit code, stdout/stderr refs, started/finished, tool, tool_version, pid, timed_out, cancelled) produced by `ExternalToolModule.execute_command` and embedded in every module result as `result["execution"]` while keeping today's `success/stdout/stderr/returncode` keys. `Framework.run_module`/`run_operation` attach the execution record to `module_history`. | — | W1 (timeout), A6/A7, S5 |
| B1.2 | **Observation contract + first producers.** `result["observations"]` as a list of typed records (§5.3). Producers in priority order: Nmap XML (host, service with protocol), `nxc_smb` List Shares/Enumerate Users/Password Policy, `nxc_ldap` Enumerate Users/Computers/Trusts, `kerbrute` User Enumeration (users), `httpx` (http endpoints as URLs), `nuclei` (findings), spray (credential observations). Engines read observations, not ad-hoc keys. | B1.1 | W3, A3, §1.2.2 |
| B1.3 | **Operation catalog metadata.** Extend `get_operations()` entries with `interactive`, `background`, `requires` (option names), `emits` (observation kinds), `risk_hint` (informational only). Validation rejects `interactive` operations in workflow/auto-enum/API; a contract test asserts that every handler containing `input(` is flagged. | — | W11 |
| B1.4 | **Sync/background policy in the engine, not per module.** Orchestrated runs pass `background=False` and a timeout through the request; the `BACKGROUND` option applies only to interactive `run`. Remove the `recon/nmap` special case at `auto_enum.py:930`. | B1.1 | W1, A7 |
| B1.5 | **One target binder.** `core/binding.py: bind_endpoint(module, endpoint)` maps an endpoint (host, port, protocol, service, url?) to RHOST/TARGET/URL/PORTS/RPORT/DC/DC_IP/NAMESERVER; DOMAIN is only ever bound from a domain observation; URL-capable TARGET tools receive a URL built by `_build_service_url`. Workflow (`workflow.py:855-862`) and auto-enum (`auto_enum.py:627-674`) both call it. | B1.2 | A1, A2, W8 |
| B1.6 | **Nmap repair.** Fix `Fast Scan`/`UDP Scan` ports (A12); return parsed hosts in the result (observations), stop merging stdout services under the scan target (A11); write `-oA` into a run directory from the execution request (A6); carry protocol into the service index and the services table (additive column, *capability-scoped persistence*); make `NmapModule.parse_xml_output` the only importer used by `parse`, `/api/nmap/upload`, and auto-enum. | B1.1, B1.2 | A11, A12, A6 |
| B1.7 | **Auto-enum repair.** Seed from session/DB services when DISCOVERY is skipped (A8); treat session credentials as available for `requires_auth` and bind them per attempt (A3); truthful summary with per-rule outcomes (A5); add https rules for nuclei/feroxbuster and fix the 443 mismatch (A2); make parallel mode safe by giving each worker its own module instance via a non-mutating `Framework.instantiate_module` and serializing `_record_module_results` (A4); delete the exploitation phase or give it rules. | B1.2, B1.5 | A2–A5, A8 |
| B1.8 | **Workflow repair.** `service_found` scoped to the workflow target via `get_services(target)` and observations (W2); persist on create and load on list/status (W6); validation and `dry_run` without `use_module` side effects, using `instantiate_module` (W7); honor step `timeout`; implement `on_failure` branching or remove the DAG fields (W4); rewrite `quick_recon`/`full_network_assessment`/`credential_harvest` so no step references an interactive operation (W11) and `web_application_test` binds URLs from httpx observations. | B1.1–B1.5 | W2, W4, W6–W8, W11 |
| B1.9 | **Spray repair.** `SprayOutcome` enum on `SprayAttempt` (S4); reject unsupported protocols before the loop and expose `supported_protocols()` to the CLI (S3); record `skipped_budget` attempts (S2); pin explicit options so `auto_set_from_context` cannot overwrite them (S1, via `ExecutionRequest.options_locked` or a module flag); one module instance per spray and one execution record per attempt (S5); per-protocol golden NXC fixtures (S6); add `Test Authentication` to `nxc_ldap` and back `KERBEROS` with `kerbrute` Password Spray (S7). | B1.1 | S1–S7 |
| B1.10 | **Minimal job runner.** `core/jobs.py`: run a workflow/auto-enum/spray on a worker thread with status, progress, pause/stop flags checked at step boundaries, and a result handle. CLI `workflow run --background`, `auto`, `spray` register jobs; `workflow pause/resume/status`, `auto status/stop`, `spray status/stop` act on jobs. This is the capability dependency for UI parity (CWP8) and agents (CWP9). | B1.1 | W5 |
| B1.11 | **Real-template tests.** For each of the six templates: real `Framework`, real discovery, `subprocess.run` replaced by a fixture-driven fake keyed on argv[0]; assert the step sequence, observations, and final state. Same for auto-enum (nmap XML fixture → rule dispatch → nxc fixtures) and spray (real `nxc_smb`/`nxc_rdp`/`nxc_ssh` modules). | B1.6–B1.9 | §2.4 |
| B1.12 | **C0 lab demonstration.** Owned lab run of `quick_recon`, `auto` NORMAL scope, and SMB/SSH spray with recorded fixtures checked in (§7). | B1.11 | roadmap §7 open items |

### CWP2 — Network, Windows, AD, SMB (S3–S4)

| ID | Deliverable | Deps |
|---|---|---|
| B2.1 | Nmap profiles replace the six wrapper modules (`recon/nmap_*`); keep the old registry paths as aliases so templates and docs keep working; delete `recon/nmap_parser` as a module and move its searchsploit step into an importer option. Add IPv6, UDP top-ports, segmented target lists, script profiles, `HOST_TIMEOUT` defaults. | B1.6 |
| B2.2 | NetExec parsers → observations for every non-interactive `nxc_smb`/`nxc_ldap`/`nxc_winrm`/`nxc_rdp`/`nxc_ssh`/`nxc_mssql` operation (shares with permissions, users, groups, sessions, logged-on users, password policy, signing/NLA status, vuln-check verdicts, trusts, computers, ADCS). Replace every `input()` with options (B1.3). Register `HASH` on `nxc_smb` (S8). Quote all interpolated arguments. | B1.2, B1.3 |
| B2.3 | Delete `modules/smb/*` (six-file copy of `nxc_smb`, §6). | B2.2 |
| B2.4 | Impacket: argv-safe commands, `parsed` → observations (SAM/LSA/NTDS hashes as credential observations with `secret_ref` placeholders, SPNs, AS-REP-able accounts), `DC_IP` bound by B1.5, and `smbclient` flag correctness against the supported version. | B1.2, B1.5 |
| B2.5 | AD relationship model on the existing graph: identity, group, computer, session, local-admin, share-access, trust, credential-use edges populated automatically from observations; `graph auto <target>` implemented (today advertised but absent, `commands.py:4397`). Fix the alphabetical status-upgrade bug (`attack_graph.py:193-247`) and the never-populated `attack_paths`. | B1.2, B2.2 |
| B2.6 | BloodHound: import BloodHound CE/legacy JSON into the graph; export graph edges as BloodHound-compatible JSON and a generic edge CSV. `nxc_ldap` collection operations already exist and are reused. | B2.5 |
| B2.7 | Owned Windows/AD lab (§7.4) and golden fixtures for every CWP2 operation. | B1.12 |

### CWP3 — Web and API (S5–S6)

| ID | Deliverable | Deps |
|---|---|---|
| B3.1 | HTTP observation kinds (endpoint, request/response pair, form, parameter, technology, path) and producers: `httpx` (endpoints, technologies), `feroxbuster` (paths; rename `parsed_results` → `parsed`; remove the `/dev/tty` menu), `wfuzz` (non-interactive operations, honor `TARGET`), `sqlmap` (parameters/injection findings), `wpscan` (users/plugins/themes; stop calling the nonexistent `session.add_finding`). A form/parameter producer is required for `forms_found` (a light HTML form parser over httpx-discovered URLs or a crawler adapter). | B1.2, B1.3 |
| B3.2 | Web templates rebuilt on observations and URL binding (B1.5); `web_application_test` runs end to end against a fixture site. | B3.1, B1.8 |
| B3.3 | Nuclei: version-matrix the `-json`/`-jsonl` flag, import existing Nuclei output files, findings into the single findings store (B6.2) instead of the ad-hoc `framework.report_generator` attribute. | B1.2 |
| B3.4 | OpenAPI/Swagger ingestion → endpoint observations; authenticated collection + replay via an internal HTTP client producing request/response observations. | B3.1 |
| B3.5 | GraphQL introspection, gRPC reflection, WebSocket endpoint inventory adapters. | B3.4 |
| B3.6 | Manual request/response notes and evidence attachment reuse `core/findings.Evidence`; REST authorization test scaffolding (role × endpoint matrix) over B3.4. | B3.4, B6.3 |
| B3.7 | WSTG/ASVS/API Top 10 identifiers on operation manifests (`standards` field) and on manual procedures. | B1.3 |

### CWP4 — Identity and cloud (S7–S8)

| ID | Deliverable | Deps |
|---|---|---|
| B4.1 | OIDC discovery, JWKS, token-claim inspection, redirect/scope inventory as pure-Python adapters producing identity observations. | B1.2 |
| B4.2 | SAML metadata/assertion inspection; MFA/session capture notes via B3.6. | B4.1 |
| B4.3 | Entra ID inventory via imported `az`/Graph JSON (tenant, apps, service principals, roles, consents). | B4.5 |
| B4.4 | AWS/Azure/GCP inventory via imported CLI JSON (`aws`, `az`, `gcloud`) and optional SDK adapters; public exposure and privilege relationships. | B4.5 |
| B4.5 | Graph extensions: node types identity, role, policy, resource, tenant; edge types assumes, has_permission, exposed_to, federates_with. | B2.5 |
| B4.6 | Import paths for common native assessment outputs (Prowler/ScoutSuite JSON) — scope-cut candidate (§8). | B7.6 |

### CWP5 — Containers, Kubernetes, Linux, databases (S9–S10)

| ID | Deliverable | Deps |
|---|---|---|
| B5.1 | Kubernetes inventory via `kubectl ... -o json` import (contexts, namespaces, workloads, services, ingress, RBAC, network policies, secret references). | B1.2, B7.6 |
| B5.2 | Container image/runtime inventory (`docker`/`crictl` JSON) and scanner-output import (Trivy/Grype JSON). | B7.6 |
| B5.3 | Linux host observations: collectors over `nxc_ssh` Execute Command (non-interactive) for packages, services, permissions, cron/systemd timers, credential artifacts; linpeas output importer. | B2.2 |
| B5.4 | Database adapters chosen by lab availability: `nxc_mssql` exists; PostgreSQL, MySQL/MariaDB, Redis, MongoDB, Elasticsearch via Python clients, each emitting service/identity/data observations. | B1.2 |
| B5.5 | Correlation rules: exposed service → identity → role → data/resource edges. | B4.5, B5.1–B5.4 |

### CWP6 — Assessment lifecycle (S11–S12)

| ID | Deliverable | Deps |
|---|---|---|
| B6.1 | Minimal `Engagement` record (*capability-scoped persistence*: id, name, created, targets, phases) and an `engagement_id` on new observation/execution/finding rows so manual UX and comparisons can function. Additive, migrated properly in S19. | B1.1 |
| B6.2 | **One finding model.** Keep `core/findings.Finding` (richest), make `reporting` consume it directly, delete `reporting/models.Finding` and the hand-built conversion in `commands.py:3547-3596`, drop the unused core `findings` table or map it, fix `accepted_risk`. | — |
| B6.3 | Test plan/checklists, manual observations, notes, hypotheses, peer-review states, remediation, retest entities with CLI commands. | B6.1, B6.2 |
| B6.4 | Versioned methodology profiles (NIST SP 800-115, PTES, WSTG/ASVS/API Top 10, ATT&CK) as data files; tested/not-tested/not-applicable/automated/manual/imported coverage states computed from executions and manual entries. | B1.3, B3.7, B6.3 |
| B6.5 | Operator-defined workflow templates and assessment profiles as YAML/JSON (reuse `WorkflowEngine.import_workflow`). | B1.8 |
| B6.6 | Baseline/current/remediation/retest comparison views. | B6.3, B7.1 |

### CWP7 — Interoperability and reporting (S13–S14)

| ID | Deliverable | Deps |
|---|---|---|
| B7.1 | Canonical interchange JSON with `schema_version` and a published JSON Schema covering engagement, assets, services, identities, executions, observations, findings, evidence; generated from the B1/B6 dataclasses. | B1.1, B1.2, B6.1, B6.2 |
| B7.2 | Reports consume the canonical model; remove field loss; `ReportGenerator._build_report_data` reads findings from the store. | B7.1 |
| B7.3 | CSV, SARIF 2.1, DefectDojo Generic Findings import/export with round-trip fixtures and consumer-schema validation. | B7.1 |
| B7.4 | ATT&CK Navigator layer and STIX 2.1 export from technique mappings on findings/operations. | B7.1, B3.7 |
| B7.5 | Graph exports: BloodHound-compatible JSON, generic node/edge CSV/JSON (shares B2.6). | B2.5 |
| B7.6 | One `Importer` interface (`detect(path)`, `parse(path) -> observations`) with importers for Nmap XML, Nuclei JSONL, NetExec logs, BloodHound JSON, cloud/K8s/container JSON. | B1.2 |

### CWP8 — Visualization and UX (S15–S16)

| ID | Deliverable | Deps |
|---|---|---|
| B8.1 | Application services layer (`purplesploit/services/`): engagement, target, execution, workflow, auto-enum, spray, finding, report, graph, job. CLI, API and web call services; business logic leaves `ui/commands.py`. Delete `ui/command_mixins/` (unused duplicate). | B1.10 |
| B8.2 | One browser surface: keep the FastAPI app + static portal, retire the Jinja dashboard on port 8000 (its deletes are undone by `_load_persisted_data`); add API endpoints for workflow, auto-enum, spray, findings, reports, graph, jobs, importers. | B8.1 |
| B8.3 | Job progress over WebSocket; CLI and browser show the same job state. | B1.10, B8.2 |
| B8.4 | Views: asset/service topology, identity relationships, attack paths with evidence, methodology/ATT&CK coverage, finding trends, remediation/retest, data quality; built on Cytoscape export and the canonical store. | B7.1, B7.5 |
| B8.5 | Evidence and raw-output drill-down from finding → observation → execution record → stdout/stderr artifact. | B1.1, B7.1 |
| B8.6 | Capability/operation reference generated from manifests (B1.3). | B1.3 |

### CWP9 — Ecosystem (S17–S18)

| ID | Deliverable | Deps |
|---|---|---|
| B9.1 | Plugins: implement `load_plugin_modules` (import `manifest.module_path`, register with `Framework`), plugin-dir discovery at startup, runtime enable/disable, transactional uninstall, fix the local repository archive path mismatch (`repository.py:322-404`); ship a sample plugin. | B1.3 |
| B9.2 | Distributed: define the protocol around `distributed/task.py`; implement `/api/v1/health|agents/register|agents/heartbeat|tasks/request|tasks/result|findings/sync` and `/ws/agent`; add `Agent` and `Coordinator`; fix `extra_headers` → `additional_headers`; task leases, cancel, result/artifact transfer, reconnect. Agents execute `ExecutionRequest`s and return `ExecutionResult`s + observations. | B1.1, B1.10, B8.2 |
| B9.3 | Integrations: fix config reload (duplicate `name` TypeError, `manager.py:213`), persist what is needed to function (file-mode-protected like credentials today; secret-provider migration stays S20), `send_finding` takes a `Finding`, remote-ID mapping for idempotent sync, delivery log, CLI/API commands (none exist). | B6.2, B8.1 |
| B9.4 | AI advisory: recommendations grounded in the live module/operation inventory (replace hard-coded paths such as `utility/hashcat`, `ad/bloodhound`, `post/*_privesc`), structured output schema validated against the inventory, provider adapters with correct default models per provider, `op_analyze`/`op_automate` implemented over typed observations or removed, workflow proposal emitted as a draft workflow (never executed by the AI path). | B1.3, B7.1, B1.8 |

---

## 4. Definitions of done and demonstration evidence

| CWP | Definition of done | Demonstration evidence (checked in) |
|---|---|---|
| **CWP1** | All six built-in templates validate and run under a real `Framework` with fixture-faked processes; `quick_recon` either completes with services and a nuclei run on the discovered URL, or fails with the step error. Auto-enum NORMAL on a /24 fixture produces per-host endpoints (no CIDR host), dispatches only valid, non-interactive operations with correct DOMAIN/DC/URL binding, and runs authenticated rules when session credentials exist. SMB/RDP/WinRM/SSH/MSSQL spray reaches `Test Authentication` with the sprayed secret only; every attempt has an outcome. Pause/stop work from the CLI via jobs. | `tests/contract/test_templates_real.py` (6 templates), `tests/contract/test_auto_enum_real.py`, `tests/contract/test_spray_real.py`; fixtures `tests/fixtures/{nmap,nxc,nuclei}/`; a lab transcript under `docs/evidence/C0-<date>/` with the nmap XML, nxc logs, and the resulting canonical JSON. |
| **CWP2** | From a subnet, an operator reaches host→service→share/user/group/session/trust observations and graph edges with no manual reconciliation; Impacket outputs are observations; `nxc_smb` PTH works; `smb/*` and `nmap_*` wrappers are gone with no lost operation. | Lab run against the owned AD lab: canonical JSON + Cytoscape/BloodHound export + screenshots of `graph` output; golden fixtures per operation; CI contract tests over the fixtures. |
| **CWP3** | A web target yields endpoint/parameter/technology/path/form observations, a generated test plan, and findings from automated plus manual steps; `web_application_test` runs through sqlmap when a form is observed. | Fixture site (DVWA/Juice Shop) run with recorded tool outputs; OpenAPI ingestion fixture; WSTG coverage listing generated from manifests. |
| **CWP4** | OIDC/SAML/Entra/AWS/Azure/GCP observations produce one identity/resource graph; at least one review workflow consumes it. | Imported sanitized inventories under `tests/fixtures/cloud/`; graph export; coverage of identity relationships in the contract tests. |
| **CWP5** | K8s, container, Linux, and at least two database adapters produce observations in the same model and correlate to identities/data. | `kind` cluster fixture export, container inventory fixture, Linux collector fixture, DB enumerations against docker-compose lab. |
| **CWP6** | An operator records a full lifecycle (engagement, plan, manual observations, review states, remediation, retest) in the CLI with coverage states computed. | Scripted CLI session transcript producing a canonical JSON engagement with coverage states. |
| **CWP7** | Every export validates against its consumer schema; imports round-trip; reports lose no fields. | Round-trip tests for JSON/CSV/SARIF/DefectDojo/Navigator/STIX; golden report snapshots. |
| **CWP8** | CLI and browser perform the same operations through the same services; dashboards drill down to evidence; `ui/commands.py` contains no business logic; one web app. | API contract tests; browser screenshots per view; parity matrix test (every service method has a CLI and API path). |
| **CWP9** | Sample plugin installs/registers/executes/uninstalls; a remote agent runs a task and returns results; a finding syncs to a ticket; an AI proposal references only real operations and lands as a draft workflow. | End-to-end lab scripts for each, with recorded request/response logs; §9 checklist signed. |

---

## 5. Cross-cutting technical contracts (no policy)

### 5.1 `ExecutionRequest`
`module_path`, `operation_name?`, `options: dict`, `options_locked: set[str]` (never overwritten by context auto-population), `argv: list[str]` (built by the module, never re-split from a string), `cwd/run_dir`, `env: dict`, `timeout_s`, `background: bool`, `stdin: "none"|"inherit"`, `engagement_id?`, `job_id?`, `correlation_id`.

### 5.2 `ExecutionResult`
`request_id`, `argv_display` (redacted), `exit_code | None`, `timed_out`, `cancelled`, `started_at`, `finished_at`, `stdout_ref`, `stderr_ref` (artifact paths under `run_dir`), `tool`, `tool_version`, `pid`, `success` (= exit_code == 0 and not timed_out/cancelled; modules may *lower* this, never raise it), `observations: list[Observation]`, `artifacts: list[path]`, `error?`. Background runs return a `handle` with `status()`/`wait()`/`cancel()`; they are not `success` until completion.

### 5.3 `Observation`
`kind ∈ {host, service, http_endpoint, http_request, form, parameter, technology, path, user, group, computer, domain, session, share, credential, identity, role, policy, resource, finding, note}`, `target` (host/ip/url), `port?`, `protocol?`, `service?`, `version?`, `attributes: dict`, `source_execution_id`, `module_path`, `operation_name?`, `observed_at`, `confidence ∈ {observed, inferred}`, `engagement_id?`. Credentials carry `secret_ref` placeholders now (string value allowed in the capability phase, swapped for provider refs in S20).

### 5.4 Operation manifest (adapter manifest)
Per operation: `name` (stable), `id` (slug, stable; display name may change), `handler`, `description`, `interactive: bool`, `background: bool`, `requires: [option]`, `optional: [option]`, `emits: [Observation.kind]`, `tool`, `supported_tool_versions`, `standards: [WSTG/ASVS/ATT&CK ids]`, `subcategory`. Per module: `path`, `name`, `category`, `tool`, `options schema`. CI validates manifests without executing tools.

### 5.5 Importer/Exporter
`Importer.detect(path) -> bool`, `Importer.parse(path, engagement_id?) -> list[Observation]` with `source_file` provenance. `Exporter.export(canonical_doc, path)` with `schema_version`. Canonical document = engagement + assets + services + identities + executions + observations + findings + evidence.

### 5.6 Graph
Nodes/edges derived from observations with `source_observation_ids`; node identity from `(kind, canonical identifier)`; status ordering numeric; attack paths persisted; exports: Cytoscape, DOT, BloodHound JSON, edge CSV.

### 5.7 UI parity
Every operator capability is a method on a service class; CLI commands and API routes are thin adapters; one job model exposes progress/pause/stop identically; a parity test enumerates service methods against CLI/API registrations.

### 5.8 Plugin
Manifest declares `module_path`, `main_class`, framework version range, required tools; loader imports and calls `Framework.register_module(path, cls)`; registry paths namespaced `plugin/<name>/<module>`.

### 5.9 Agent
Agent executes `ExecutionRequest`s, streams `ExecutionResult`s and observations; messages: register, heartbeat, task_request, task_result, cancel; task identity from `distributed/task.py`; transport headers per installed `websockets` API.

### 5.10 Integration
`send_finding(Finding) -> RemoteRef`; `RemoteRef` persisted for idempotent updates; delivery log with status; configuration persists every field the adapter needs to function.

### 5.11 AI grounding
Prompts receive the manifest inventory (5.4) and canonical observations (5.3); outputs are JSON validated against a schema whose `module_path`/`operation_id` values must exist in the registry; proposals become draft `Workflow` objects, never executions.

---

## 6. Reuse, consolidate, replace, delete

| Action | Target | Reason |
|---|---|---|
| **Reuse** | `core/findings.Finding/Evidence/FindingsManager` | Richest finding model; make reporting consume it (B6.2). |
| **Reuse** | `core/attack_graph` node/edge types and exports | Good base for CWP2/4/7 graph work; fix status comparison and path persistence. |
| **Reuse** | `NmapModule.parse_xml_output`, `WorkflowEngine` import/export, `distributed/task.py`, `integrations/*` clients, `plugins/manager` extraction | Sound pieces; wire them to contracts instead of rewriting. |
| **Reuse** | `test_auto_enum_contract.py` fixture shape; `FakeAuthenticationModule` pattern | Template for real-framework contract tests, after moving the fake to `subprocess.run`. |
| **Consolidate** | Six `recon/nmap_*` wrappers → Nmap profiles with path aliases | Inherited `BACKGROUND`, duplicated `--traceroute`, divergent defaults. |
| **Consolidate** | `_find_operation` (workflow), `_resolve_operation` (auto-enum), spray's inline match → `Framework.find_operation` | One semantics for operation lookup. |
| **Consolidate** | Three Nmap importers (module, `nmap_parser` module, auto-enum re-parse/session delta) → one importer | Different service-name mappings write different names to the DB today. |
| **Consolidate** | Two web apps (API+static on 5000, Jinja dashboard on 8000) → API+static | Dashboard deletes are undone by framework startup sync. |
| **Replace** | Ad-hoc result keys (`services`, `users`, `credentials`, `forms`, `parsed`, `parsed_results`, `findings`) → `observations` | Engines currently gate on keys nobody emits. |
| **Replace** | `input()` prompts inside operation handlers → options + `interactive` flag | Blocks orchestration and API execution. |
| **Replace** | Hard-coded module paths in `ai/attack_paths.py`, `ai/nlp.py`, `modules/ai/methodology.py` → registry lookups | Seven referenced modules do not exist. |
| **Delete** | `modules/smb/*` (six files, 959 lines) | Verbatim copy of `nxc_smb` operations with no shared code. |
| **Delete** | `modules/recon/auto_enum.py` | Shells out directly, writes `./enum_output/`, always reports success, shares nothing with `core/auto_enum.py`. Keep only a scope-level option list if any tool it drives (rustscan, gospider, dirsearch) is wanted as a real adapter. |
| **Delete** | `ui/command_mixins/*` and their tests | Unused duplicate of `commands.py`. |
| **Delete** | `reporting/models.Finding` after B6.2; core `findings` table if unused after B6.2 | Two of three finding models go. |
| **Delete** | `WorkflowStep.on_success/on_failure/retry_count` unless B1.8 implements them | Dead API surface misleads template authors. |
| **Delete** | `modules/ai/methodology.py` (unregistered, wrong port map, nonexistent module) once B9.4 lands | Misleading. |
| **Delete** | `python/build/`, `python/dist/`, stale `python/graph.*`, root `my_sessions.json` from the working tree (not history) | Stale copies confuse grep and diff; history rewrite remains S23. |

---

## 7. Test and owned-lab strategy

### 7.1 Principles
1. Fake only `subprocess.run`/`subprocess.Popen` (via `ExternalToolModule.execute_command`) and network clients; never patch `Framework.run_operation`, `run_module`, `use_module`, or module handlers in contract tests.
2. Every orchestration test builds a real `Framework`, runs real discovery, and uses real module classes; fakes are keyed by `argv[0]` and return recorded stdout/stderr/exit codes and write recorded output files (nmap XML, nuclei JSONL, feroxbuster log) into the run directory.
3. Fixtures are files, versioned by tool: `tests/fixtures/<tool>/<version>/<scenario>.{txt,xml,jsonl}` plus a `manifest.yaml` with the exact command that produced them. Today there are zero file fixtures; all samples are inline strings.
4. Manifest and template validation run without tools: every template step, rule module, operation id, option name, `interactive=false`, and `emits` claim is checked by one test.

### 7.2 Test tiers
| Tier | Scope | Runs |
|---|---|---|
| Unit | dataclasses, parsers, binders, interpreters (`_interpret_auth_result` per protocol fixture) | CI, every push |
| Contract | real Framework + fake process; all templates, auto-enum scopes, spray protocols, importers, exporters round-trips, API routes with `TestClient` | CI, every push |
| Lab | owned docker-compose/VM lab (§7.4), real tools, recorded into new fixtures | nightly / per-sprint gate |
| Parity | service ↔ CLI ↔ API enumeration | CI from CWP8 |

### 7.3 Specific tests to add first (CWP1)
- `quick_recon` real run: `nmap_fast` fake returns the /24 XML fixture → services observed → httpx fake → nuclei fake with URL; assert the nuclei argv contains the https URL with port.
- `credential_harvest`/`full_network_assessment` validation fails until W11 is fixed, then passes with the non-interactive spider operation.
- Auto-enum: CIDR fixture → no CIDR key in `discovered_services`; kerberos rule binds `DC`, not `DOMAIN`; https on 8443 → nuclei URL; LIGHT scope argv contains `--top-ports 100`, not `-p -`.
- Spray: real `nxc_rdp` with a session credential carrying a hash → argv contains `-p <sprayed>` and no `-H`; unsupported protocol rejected before any attempt; skipped-budget outcomes present.
- Environment: pin `[dev]` extras so UI/API tests collect (`prompt_toolkit`, `fastapi`, `pytest-benchmark`); today 9 files fail collection outside a full install, which hides 582 tests.

### 7.4 Owned lab
- **Internal/AD:** one Samba AD DC + one Windows member (eval VM) or a GOAD-style minimal set; services: SMB, LDAP/S, Kerberos, WinRM, RDP, MSSQL (Linux container), SSH. Resettable snapshots; fixture capture scripts that run each operation and store outputs under `tests/fixtures/`.
- **Web/API:** DVWA + Juice Shop + a small OpenAPI/GraphQL/gRPC sample service in compose.
- **Cloud/identity:** no live cloud in CI; sanitized exported JSON inventories only; optional opt-in live run with the operator's own tenant later.
- **K8s/containers/DB:** `kind` cluster, local registry, Postgres/MySQL/Redis/Mongo/Elasticsearch containers.
- **Version matrix:** record `nmap`, `nxc`, `nuclei`, `feroxbuster`, `sqlmap`, `kerbrute`, impacket versions in `manifest.yaml`; contract tests select fixtures by supported version.

### 7.5 This review's measurements
262 targeted tests pass; full suite in this environment 2,894 passed / 23 skipped / 143 failed / 439 errors, all failures and errors attributable to missing `prompt_toolkit`, `fastapi`, `pytest-benchmark`. CI (`.github/workflows/ci.yml`) gates on the full suite for Python 3.10–3.13 with `pip install -e ".[dev]"`, so CI sees the green run the roadmap reports; lint/format/type/Bandit remain advisory (S23).

---

## 8. Risks, hidden blockers, scope cuts

### 8.1 Risks and hidden blockers
1. **Producer work is larger than the roadmap implies.** CWP1 "restoration" is mostly engine-side; the observation producers (B1.2, B2.2, B3.1) are parser work across ~40 operations with tool-version drift. Budget S1–S3 for it or CWP2–CWP6 will repeat the "engine works, templates hollow" pattern.
2. **Interactive handlers are systemic** (17 in `nxc_smb`, plus mssql/winrm/ssh/rdp/feroxbuster/wfuzz/nuclei/osint). Until B1.3/B2.2 land, any orchestrated path can block on stdin.
3. **Shared mutable `Session`** (`current_module`, `module_history`, `workspace`, service index) is touched by every execution. Parallel auto-enum, jobs, agents, and the API all need `instantiate_module` and a per-run context; retrofitting later is harder than doing it in B1.7/B1.10.
4. **Two persistence layers with different service-name mappings** (`nmap.py` vs `nmap_parser.py`) and no protocol column will corrupt endpoint identity for UDP/TCP collisions until B1.6. Keep schema changes additive so S19 can migrate.
5. **Tool flag drift:** nuclei `-json` vs `-jsonl`, impacket `smbclient` flags, wpscan non-zero exit on findings, dig exit 0 on refused AXFR. Each needs a version-matrix fixture before its adapter can be called done.
6. **Nmap default scopes are aggressive** (`-p- -sCV --min-rate 3900` per host in NORMAL). Not a policy item here, but it is a *usability* blocker for lab demos; LIGHT must actually be light (A12).
7. **Distributed and plugins are green-field** (no Agent/Coordinator, no endpoints, loader never called). CWP9 estimates should assume new implementation, not repair.
8. **Finding-model consolidation (B6.2) is on the critical path for CWP7 and CWP9**; if it slips, exports and integrations build on a model that will be replaced.
9. **AI inventory grounding depends on manifests (B1.3)**; without stable operation ids, proposals cannot be validated.

### 8.2 Scope cuts that preserve the highest-value capability
- **Cut from CWP2:** `smb/*` package (delete, not port); `nmap_parser` searchsploit auto-run (make it an importer option).
- **Cut from CWP3:** gRPC reflection and WebSocket testing to "inventory only"; defer REST authorization matrix UX to CWP6 manual steps.
- **Cut from CWP4:** live SDK adapters; ship import-only for AWS/Azure/GCP/Entra in S8, live calls later. Drop B4.6 (third-party scanner import) unless a consumer asks.
- **Cut from CWP5:** Oracle and Elasticsearch adapters unless a lab exists; ship PostgreSQL, MySQL, Redis, MongoDB.
- **Cut from CWP7:** STIX 2.1 to "after Navigator layer validates"; Tier-3 formats stay out.
- **Cut from CWP8:** one browser surface only; no second dashboard; views limited to topology, attack path, coverage, findings until evidence drill-down works.
- **Cut from CWP9:** distributed scope to HTTP transport + one agent + cancel/heartbeat; WebSocket transport second; AI "Automate Workflow" becomes "Propose Workflow" (draft only).

---

## 9. CWP9 completion checklist (gate C4)

Tick every line with a checked-in artifact or test name.

- [ ] All six built-in templates and every operator-defined template pass `tests/contract/test_templates_real.py` against real modules with fixture-faked processes; no template references an `interactive` operation.
- [ ] Auto-enum on a CIDR fixture yields per-host endpoints only, binds DOMAIN/DC/URL correctly, runs authenticated rules from session credentials, and reports per-rule outcomes.
- [ ] Spray: every supported protocol has golden NXC fixtures; every attempt has an outcome; explicit options cannot be overwritten by context; LDAP/Kerberos supported or removed from the CLI help.
- [ ] `ExecutionRequest`/`ExecutionResult`/`Observation` dataclasses exist, are emitted by every registered external-tool module, and are persisted with `module_history`.
- [ ] Operation manifests validated in CI; `interactive`, `emits`, `requires`, and `standards` populated for every operation; generated reference docs match runtime.
- [ ] Nmap profiles replace wrappers; one importer; services carry protocol; `Fast Scan` runs top ports.
- [ ] `modules/smb/*`, `modules/recon/auto_enum.py`, `ui/command_mixins/*`, `reporting/models.Finding` are deleted or demonstrably unused by anything but their own tests.
- [ ] AD lab run produces users/groups/sessions/shares/trusts/local-admin edges and a BloodHound-compatible export; BloodHound JSON imports.
- [ ] Web lab run produces endpoint/parameter/technology/form observations; `web_application_test` reaches sqlmap on an observed form.
- [ ] Identity/cloud/K8s/container/Linux/DB importers each have a fixture round-trip test and populate the same graph.
- [ ] Engagement, test plan, manual observation, review state, remediation, retest entities exist with CLI commands and coverage states.
- [ ] Canonical JSON validates against the published schema; CSV/SARIF/DefectDojo/Navigator/STIX exports validate against consumer schemas; imports round-trip.
- [ ] Reports consume the single finding model with zero field loss (golden snapshot test).
- [ ] One web surface; API routes exist for workflow, auto-enum, spray, findings, reports, graph, jobs, importers; parity test passes.
- [ ] Job runner: `pause/resume/stop/status` work from CLI and API for workflow, auto-enum, spray.
- [ ] Sample plugin installs, registers with `Framework`, executes an operation, disables, uninstalls; local repository path bug fixed.
- [ ] Remote agent registers, heartbeats, executes an `ExecutionRequest`, returns results/observations, survives reconnect, honors cancel; `websockets` header API correct.
- [ ] Integration config survives restart; `send_finding(Finding)` creates and then updates (not duplicates) a ticket in the lab tracker; delivery log present; CLI/API commands exist.
- [ ] AI proposal references only registry operations (schema-validated), lands as a draft workflow, and never executes; provider defaults correct per provider; placeholders removed or truthful.
- [ ] Full suite green in CI with `[dev]` extras; fixtures directory populated; lab capture scripts checked in; `tests/README.md` counts current.
- [ ] Deferred S19–S23 items are listed, not implemented, with the capability-scoped persistence additions enumerated for the S19 migration.
