# PurpleSploit CWP1–CWP9 Final Capability Review (Mythos 5.1, second pass)

Date: 26 October 2026. Scope: read-only audit of the working tree at `c962994` plus the uncommitted CWP1–CWP9 diff, the initial Mythos report, both roadmaps, and the Aranum study. No files were edited, no live tools run, no targets or providers contacted. Independent verification was done in a throwaway virtualenv under `/tmp` and with offline reproduction scripts; the only in-tree side effect was pip regenerating the gitignored `build/` and `purplesploit.egg-info/` metadata during a wheel build.

## 1. Executive verdict

**Code completion: CWP1–CWP9 is code-complete except for one P1 defect family in workflow option binding and one P1 parity gap in the CLI.** Every roadmap deliverable has real code behind it: the execution contract, workflow engine, auto-enum pipeline, spray engine, NXC/Impacket observation producers, nmap profiles and importer, canonical findings, attack graph ingestion, assessment lifecycle, interop exporters/importers, the `/api/v1` service surface, job manager, plugin lifecycle, distributed protocol, integration facade, and AI advisory. The test suite genuinely exercises them, including a real loopback HTTP/WebSocket agent.

The two P1 items are not cosmetic. First, any workflow step that needs a credential can never receive one, so the `ad_assessment`, `credential_harvest`, and the authenticated tail of `full_network_assessment` templates fail by construction once their conditions pass. Second, the CLI still runs workflows, auto-enum, and sprays synchronously on the REPL thread with its own engine instances, so the roadmap's own definition of done for job control "from CLI and API" is unmet and the CLI diverges from the service layer.

**Controlled demonstrations: not yet performed.** Nothing in the record shows an AD lab run, a web lab run, a cross-host agent run, a provider-backed advisory run, or a DefectDojo/Jira/Slack delivery against a real endpoint. These remain required before "capability-complete" becomes "capability-demonstrated" (section 8 lists them).

**Supported release: no, and the roadmap correctly says so.** The deferred S19–S23 controls are absent by design. Three documentation claims nevertheless imply controls or consolidation that do not exist; they are listed in section 9 and must be corrected before any external reader sees them.

## 2. Disposition of the initial Mythos checklist and major findings

### 2a. CWP9 completion checklist (gate C4, 17 items)

| # | Checklist item | Disposition | Evidence |
|---|---|---|---|
| 1 | Six templates pass real-module contract tests, no interactive ops | **Partially** | Only `quick_recon` and `full_network_assessment` run end to end (`tests/unit/core/test_workflow_contract.py:53-78`); no `tests/contract/` directory exists. Interactive rejection is real (`core/framework.py:426-427`). `ad_assessment`/`credential_harvest` cannot complete authenticated steps (P1-1, P2-1). |
| 2 | Auto-enum per-host CIDR endpoints, DOMAIN/DC/URL binding, authenticated rules, per-rule outcomes | **Resolved** | `core/auto_enum.py:1115-1134` credential injection, `1311-1314` session candidates, `1368-1379` truthful summary; `tests/unit/core/test_auto_enum_cwp1.py`. HTTPS rule gap remains (P2-2). |
| 3 | Spray: per-protocol fixtures, every attempt has an outcome, pins, LDAP/Kerberos supported or removed from help | **Partially** | `SprayAttemptOutcome` and pins (`core/credential_spray.py:644-657`) are real; Kerberos mapped, LDAP not, yet the CLI help still advertises `--protocol ldap` (`ui/commands.py:4696-4701`). Tests cover adapter argv boundaries, not golden output per protocol. |
| 4 | Execution dataclasses emitted by every external-tool module, persisted with history | **Resolved** | `core/execution.py`; `BaseModule.run_operation` wraps results; `test_execution_contract.py`. |
| 5 | Manifests validated in CI; `interactive`/`emits`/`requires`/`standards` populated; generated reference matches runtime | **Partially** | `normalize_operation` and `/api/v1/capabilities/reference` exist (`services/api.py:32`). No CI step validates manifests (`.github/workflows/ci.yml` runs tests/lint only); `standards` population per operation unverified. |
| 6 | Nmap profiles replace wrappers; one importer; Fast Scan top-ports | **Resolved** | `modules/recon/nmap.py` profiles, `interop/nmap_importer.py`, `test_nmap_profiles.py`. Wrappers kept as registry aliases per B2.1. |
| 7 | Deletions: `modules/smb/*`, `modules/recon/auto_enum.py`, `ui/command_mixins/*`, `reporting/models.Finding` | **Partially** | `reporting/models.py` is now an alias shim (done); `modules/smb/*` are shims over `_compat.py`; `modules/recon/auto_enum.py` and all 10 `ui/command_mixins/*` files remain and ship in the wheel. |
| 8 | AD lab run yields edges + BloodHound export/import | **Partially (demo pending)** | Code and fixtures exist (`interop/bloodhound.py`, `core/attack_graph.py` ingest, `tests/unit/interop/test_bloodhound.py`). No lab run recorded. |
| 9 | Web lab run reaches sqlmap on an observed form | **Partially (demo pending)** | Forms producer requires an operator-supplied `$html_file` (`core/workflow.py:282-291`); no `web_application_test` contract test; no lab run. |
| 10 | Identity/cloud/K8s/container/Linux/DB importers round-trip into one graph | **Resolved** | `interop/{identity,cloud,containers,host_database}.py`, `attack_graph.ingest_observations`, `tests/unit/interop/*`. |
| 11 | Engagement/test plan/manual entry/review/remediation/retest entities with CLI commands | **Partially** | Entities and API exist (`core/assessment.py`, `services/api.py:87-111`). The CLI dispatch map (`ui/commands.py:100-199`) has no assessment, engagement, review, or retest command. |
| 12 | Canonical JSON validates against published schema; consumer formats validate against consumer schemas | **Partially** | Canonical schema validation is real (`schemas/canonical-v1.schema.json`, `jsonschema` declared). SARIF/Navigator/STIX/DefectDojo are checked against hand-written "consumer-shaped" assertions (`tests/unit/interop/test_canonical_interchange.py:110-123`), not the official consumer JSON schemas; `interop/canonical.py:350` only embeds the schemastore URL. |
| 13 | Reports consume one finding model with zero field loss | **Resolved** | `reporting/models.py` re-exports `core.findings`; `from_dict` preserves unknown fields under `metadata.legacy_fields`; `tests/unit/reporting/test_canonical_findings.py`. |
| 14 | One web surface; API routes for all capabilities; parity test | **Partially** | `/api/v1` routes and the parity test are real (`services/api.py:28-240`, `tests/unit/api/test_services_cwp8.py:30`). "One surface" is false: `api/server.py` keeps 35 legacy routes and `web/dashboard.py` is a second FastAPI app with its own `purplesploit-web` entry point (`setup.py:84`). |
| 15 | Job runner pause/resume/stop/status from CLI and API | **Partially** | API: yes (`services/api.py` jobs routes, `test_services_cwp8.py:67,117`). CLI: no (P1-2). |
| 16 | Sample plugin lifecycle; local repository path bug fixed | **Resolved** | `examples/plugins/hello-demo`, `tests/unit/plugins/test_lifecycle.py` (12 tests incl. local archive repository). |
| 17 | Agent register/heartbeat/execute/results/reconnect/cancel; websockets header API correct | **Resolved in-process** | `tests/unit/distributed/test_protocol.py:259-408` runs a real loopback agent over HTTP and WebSocket. Cross-host demo pending. |

### 2b. Initial review findings (W = workflow, A = auto-enum, S = spray)

| ID | Finding | Disposition | Evidence |
|---|---|---|---|
| W1 | Background nmap reported success, no timeout | Resolved | `core/framework.py:417-419` forces BACKGROUND from the request; `core/workflow.py:1034-1041` passes `timeout_s`; background results pause the workflow (`workflow.py:1061-1066`). |
| W2 | Global service query | Resolved | `_service_exists` is target-scoped (`workflow.py:870-905`); `test_workflow_contract.py:91`. |
| W3 | Conditions had no producers | Partially | Producers exist (NXC users/groups, kerbrute, spray, forms). Kerbrute user observations fail target scoping (P2-1) and no step consumes produced credentials (P1-1). |
| W4 | Dead DAG fields | Resolved | `_branch_selected` (`workflow.py:795-808`), retry/timeout tests (`test_workflow_contract.py:105-144`). |
| W5 | Pause unreachable from CLI | Partially | Service/API path pauses via jobs; CLI `workflow run` is still synchronous (`ui/commands.py:3447`). |
| W6 | Persistence | Resolved | Atomic save/load/resume (`workflow.py` tempfile+fcntl), `test_workflow_contract.py:145`. |
| W7 | Validation side effects | Resolved | `instantiate_module` in `_execute_attempt` (`workflow.py:1000-1004`); `test_workflow_contract.py:80`. |
| W8 | URL binding | Partially | URL bound only when the target carries a scheme (`workflow.py:1024-1030`); discovered `http_endpoint` observations never feed a later step's URL. |
| W9 | Three operation resolvers | Still open | `Framework.find_operation` exists, but `core/credential_spray.py:665-666` and `core/auto_enum.py:753` still casefold-match independently. |
| W10 | Option validation at dry-run | Still open (low) | Unknown options raise only at execution (`workflow.py:1013-1016`). |
| W11 | Interactive operations | Resolved | Manifest `interactive` flag; `framework.py:426-427`; templates use "Spider Configured (No Download)". |
| A1 | Domain from IP | Resolved | `_set_module_target` (`auto_enum.py:1123`); DNS rule skipped without a domain (`test_auto_enum_cwp1.py:120-134`). |
| A2 | Port identity / HTTPS | Partially | Scheme by port in `_build_service_url` (`auto_enum.py:847-849`), but the nuclei rule is `service="http", ports=[80,443]` and no HTTPS rule exists for nuclei or feroxbuster (`auto_enum.py:189-200`). |
| A3 | Authenticated rules dead | Partially | Credential injection works (`auto_enum.py:1115-1134`); the exploitation phase still has zero rules (`_get_applicable_rules(..., EXPLOITATION)` at `auto_enum.py:649` iterates an empty set). |
| A4 | Parallel unsafe | Resolved | Per-worker `instantiate_module` and `_lock` serialization in `auto_enum.py`. |
| A5 | Untruthful summary | Resolved, with a side effect | `_build_summary` (`auto_enum.py:1368-1379`) is honest; JobManager then maps `partial`/`skipped` to `failed` (P2-3). |
| A6 | Artifacts CWD-relative | Partially | Nmap honors `RUN_DIR`/request cwd (`modules/recon/nmap.py:224-227`); no caller in `auto_enum.py`, `workflow.py`, or `services/` sets `run_dir`. |
| A7 | No discovery timeout | Partially | `timeout_s` plumbing exists (`core/module.py:583-588`); `auto_enum.py` never sets one (no `timeout` occurrence in the file). |
| A8 | Seed from existing knowledge | Resolved | Session/DB/Aranum seeding (`auto_enum.py:1311`, `interop/aranum.py` `seed_auto_enum`). |
| A9 | Typed results | Resolved | Observation-typed outputs through `_extract_workflow_data` and graph ingest. |
| A10 | Second auto-enum module | Still open | `modules/recon/auto_enum.py` still exists and is packaged. |
| A11 | CIDR registered as host | Resolved | Synthetic CIDR endpoints rejected; two-host XML fixture test (`test_auto_enum_cwp1.py:34-37`). |
| A12 | Fast Scan full-port | Resolved | `test_nmap_profiles.py`. |
| S1 | Context bleed between attempts | Resolved | Pinned options (`credential_spray.py:644-657`), test "pins empty credential fields". |
| S2 | Skipped attempts invisible | Resolved | `SprayAttemptOutcome.SKIPPED` recorded per user. |
| S3 | Unsupported protocols | Partially | Rejected before iteration, but help text still lists `ldap` (`ui/commands.py:4696`). |
| S4 | Outcome vocabulary | Resolved | `SprayAttemptOutcome` enum. |
| S5 | Per-attempt `use_module` | Resolved | Module cache via `instantiate_module`. |
| S6 | Golden fixtures per protocol | Partially | Argv boundaries tested; output-format fixtures per protocol absent; `[-]` anywhere in output still forces failure (`credential_spray.py:724`). |
| S7 | LDAP/Kerberos | Partially | Kerberos mapped; LDAP absent yet advertised. |
| S8 | `nxc_smb` HASH | Resolved | `nxc_common` auth builder accepts HASH; NXC modules expose the option. |

## 3. Concrete bugs

No P0.

**P1-1. Workflow steps can never receive session or discovered credentials.**
`core/workflow.py:1034-1041` builds the `ExecutionRequest` with `options={every option of the module}` and `options_locked=set(resolved_options) | {RHOST,TARGET,URL}`. `core/framework.py:412` then sets `module.options_locked = set(request.options_locked) | set(request.options)`, so every key is locked. `BaseModule.auto_set_from_context` (`core/module.py:405-414`, `441-450`) is the only path that fills USERNAME/PASSWORD/DOMAIN/DCIP from the session credential, and `set_option` (`module.py:246-247`) silently no-ops for locked keys while that context fill runs. Nothing in `workflow.py` binds `workflow.variables["credentials"]` into step options either. Offline repro with a session credential set: a `kerberoast` run through a workflow-shaped request returns `ExecutionOutcome.FAILED | Required option not set: USERNAME`, while the same module through the interactive path resolves `USERNAME=svc DOMAIN=CORP.LOCAL`. Consequence: `ad_assessment` steps 1 and 4, `credential_harvest` step 3, and `full_network_assessment` step 5 (`secretsdump`, requires USERNAME at `modules/impacket/secretsdump.py:50`) fail whenever their `has_valid_creds`/`has_admin_creds` conditions are true. Smallest fix: in `_execute_attempt`, set `module_instance.options_locked` to the resolved/bound keys only, call `module_instance.auto_set_from_context()` before snapshotting `options`, and for steps gated on a credential condition copy the first `_scoped_values("credentials")` entry into USERNAME/PASSWORD/HASH/DOMAIN before the snapshot. The request then carries explicit values and remote agents stay deterministic. Add `ad_assessment` and `credential_harvest` to the parametrized contract test.

**P1-2. The CLI bypasses the service and job layer, so CLI job control and CLI/API parity do not exist.**
`ui/commands.py` is untouched by the diff. `cmd_workflow` builds its own `WorkflowEngine` (`commands.py:3287-3291`) and `run_workflow` blocks the REPL (`commands.py:3447`); `_workflow_pause`/`_workflow_resume` (`3490`, `3504`) can only be typed after the run has already returned. `cmd_auto` (`4103`, `4155`) and `cmd_spray` (`4895`) are equally synchronous, so `auto stop` and `spray stop` are unreachable mid-run. There are no CLI commands for jobs, integrations, agents, assessments, importers, or advisory, and no reference to `PurpleSploitServices` or `JobManager` anywhere in the CLI. Roadmap B1.10 and C4 item 15 define done as CLI job control. Smallest fix: give `CommandHandler` a `PurpleSploitServices` instance, route `workflow run`, `auto`, and `spray` through `services.run_workflow/run_auto_enum/run_spray`, add a `jobs` command that wraps `services.jobs.status/pause/resume/stop`, and make `cmd_plugin` use `self.framework.plugin_manager` (see P2-4).

**P2-1. Kerbrute user observations use the username as `Observation.target`.**
`modules/ad/kerbrute.py:424-425` and `462-465` emit `observation("user", user, ...)`. `_target_matches` (`core/workflow.py:910-926`) compares that field to the workflow target, so `has_user_list` is false for every IP/CIDR/hostname workflow (offline repro: `has_user_list satisfied for IP-targeted workflow: False`). `ad_assessment` step 3 is therefore unreachable from step 2. NXC already uses the host as target with `username` as an attribute (`modules/network/nxc_common.py:168-250`), and the contract test expects that shape. Fix: emit `target=DC_IP or DC or DOMAIN` with `username=user` in attributes.

**P2-2. HTTPS services never reach nuclei or feroxbuster in auto-enum.**
`core/auto_enum.py:189-200`: nuclei rule is `service="http", ports=[80,443]`; nmap labels 443 as `https`/`ssl/http`, so port 443 matches nothing, and no HTTPS rule exists for feroxbuster. Fix: add `ServiceRule(service="https", ports=[443,8443], modules=["recon/nuclei"], ...)` and the feroxbuster equivalent.

**P2-3. Ordinary partial auto-enum runs are reported as `failed` jobs.**
`auto_enum.py:1372-1374` sets `success=False` when any rule was skipped (missing domain, missing creds); `core/jobs.py:137-142` maps `success is False` or status in `{partial, skipped}` to `failed`, and `test_jobs_cwp8.py:71` locks that in. An operator polling `/api/v1/jobs/{id}` sees `failed` for a run that completed its applicable rules. Fix: map `partial`/`skipped` to `completed` and keep `outcome` as the truthful status, or compute `success` from `failed_rules` only.

**P2-4. Two `PluginManager` instances over the same state.**
`core/framework.py:70-78` constructs `framework.plugin_manager`; `ui/commands.py:3654-3658` constructs a second one and performs install/enable/disable on it. In-memory enabled/disabled state and discovered plugin lists diverge within one session. Fix: `self._plugin_manager = self.framework.plugin_manager`.

**P2-5. `credential_harvest` template can never run past step 1.**
`core/workflow.py:325-349`: steps 2 and 3 are gated on `has_user_list`/`has_valid_creds`, but the template has no user-enumeration or spray producer before them. Fix: insert a `kerbrute` userenum step (after P2-1) or remove the template from the shipped set.

**P2-6. Undeclared runtime dependencies.**
`distributed/transport.py:30` imports `websockets`; `plugins/manager.py:481` imports `packaging.version`. Neither is in `setup.py:36-62` `install_requires`; both work today only because `uvicorn[standard]` and pip happen to pull them in. Fix: declare `websockets>=12` and `packaging>=23`.

**P2-7. Discovery runs with no timeout and artifacts land in the CWD.**
`auto_enum.py` never sets `timeout_s` or `run_dir`; `services/application.py:263-273` does not either. A hung nmap blocks a worker forever and `-oA` files land wherever the API process was started. Fix: pass `timeout_s=rule.timeout or 600` and `run_dir=<engagement artifact dir>` in the pipeline's request construction.

**P2-8. Advisory provider adapters are unreachable from any surface.**
`services/application.py:93` constructs `AdvisoryService(framework)` with no provider, so `/api/v1/ai/*` is always local mode; the OpenAI/Anthropic adapters in `ai/providers.py:41-53` are exercised only by direct Python in tests. Fix: build the provider from an explicit `PurpleSploitServices(advisory_provider=...)` argument or an environment variable; keep consent/approval policy in S22.

**P2-9. Stale CLI help and stale artifacts.**
`ui/commands.py:4696-4701` advertises `--protocol ldap`, which the engine rejects. `python/dist/` holds a September 14 `purplesploit-6.9.1` wheel/sdist; `setup.py` still reports 6.9.1 after the entire CWP block; `interop-channel` and `.interop/` at the repo root are untracked session artifacts.

## 4. CWP-by-CWP audit against the roadmap definitions of done

- **CWP1 (automation that runs real tools).** Workflow engine, auto-enum, spray, execution contract: done at engine level. Not done: CLI job registration/control (B1.10), credential binding into steps, `credential_harvest`/`ad_assessment` reachability. Verdict: partially met; P1-1 and P1-2 sit here.
- **CWP2 (unified recon/nmap).** Profiles, one XML importer, protocol on services, Fast Scan fixed. Wrappers remain as aliases, which B2.1 allows. Met.
- **CWP3 (service observation producers).** NXC parser emits typed host/service/identity/policy/share/user/group/computer/trust observations without inferring from exit status; Impacket modules emit credentials/findings; kerbrute emits users/creds with the target bug above. Met, with P2-1.
- **CWP4 (graph and findings).** `attack_graph.ingest_observation(s)`, `derive_attack_paths`, `_merge_properties`, STATUS_ORDER; one `Finding` model shared by core and reporting. Met.
- **CWP5 (assessment lifecycle).** `core/assessment.py` entities, six methodology JSONs, coverage computation, API routes. CLI commands absent (C4 item 11 says "with CLI commands"). Partially met.
- **CWP6 (interop).** Canonical schema, CSV/SARIF/DefectDojo/Navigator/STIX exporters, importer registry with explicit-format requirement, Aranum bundle round-trip, host/DB collector importers. Consumer-schema validation is fixture-shaped, not official-schema. Met for code; see section 6.
- **CWP7 (reporting).** Generator consumes canonical findings and framework findings manager; zero-loss snapshot tests. Met.
- **CWP8 (services/API/jobs).** `PurpleSploitServices`, `/api/v1`, `JobManager` with pause/resume/stop/events/stream, parity test against the manifest. "CLI, API and web call services" is not true for the CLI, and the legacy API and dashboard apps remain. Partially met.
- **CWP9 (ecosystem).** Section 5. Plugins, distributed, integrations, advisory are all functional in-process and tested; plugins are not exposed through services/API, and the advisory provider cannot be selected. Partially met on wiring, met on function.

## 5. Focused CWP9 audit

**Plugins.** `PluginManager` (`plugins/manager.py:34`, discover `117`, load `609`) implements discover/install/update/uninstall/enable/disable with manifest-driven module loading and a local archive repository; the hello-demo plugin round-trips in `test_lifecycle.py`. Lifecycle truth is good: state is written to disk and reloaded. Wiring is the gap: `services/application.py` has no plugin method, `services/api.py` has no plugin route, and the CLI uses a second manager (P2-4). The roadmap §7 sentence "Plugin, distributed, integration, and advisory services are wired into the primary API/service surface" is false for plugins. `examples/plugins/README.md` is honest that signing, trust, and sandboxing are deferred.

**Distributed execution.** `coordinator.py` is in-memory with lease semantics; `agent.py` is a single-worker poller that retains results on `LEASE_LOST` and resubmits on reconnect; `api.py:71-87` exposes `/ws/agent` as request/response over WebSocket plus HTTP equivalents. Reconnect and cancellation are tested with a real loopback agent (`test_protocol.py:259-408`), including cancel-while-running and heartbeat loss. Observable delivery: results flow into `services.ingest_remote_findings`, which writes directly into `FindingsManager.findings` and calls the private `_save_findings` (`application.py:428-434`), bypassing dedup and lifecycle hooks; worth routing through the public add path. Persistence: coordinator state dies with the process, which `distributed/README.md` states plainly, and `health()` reports `security_hardened: False`. That is the correct level of honesty for a fixture-lab protocol.

**Integrations.** `IntegrationService` facade wraps Jira, GitHub Issues, Slack, Teams, SIEM, DefectDojo with configure/send/deliveries/mappings and an action endpoint. Configuration (including tokens) is persisted as JSON with `chmod 0o600` and a comment that secret-provider migration is S20 (`integrations/manager.py:159-171`). The comment is accurate; no claim of secret management is made. Delivery records are persisted and queryable through `/api/v1/integrations/deliveries`. No live endpoint has been exercised.

**AI advisory.** `AdvisoryService.propose_workflow` (`ai/advisory.py:84-104`) validates proposals against `WORKFLOW_SCHEMA` and `_validate_workflow`, persists them tagged `["ai-proposal","draft"]`, and returns `draft: True, executed: False`. Inventory grounding comes from the live module registry and session state via `/api/v1/ai/inventory`. Draft-versus-execution boundary is correct: nothing in the advisory path calls `execute_request`, and a draft must be run through the ordinary workflow route. Provider usage: `providers.py` calls OpenAI `responses.create` with a JSON-schema response format and Anthropic `messages.create`; the defaults (`gpt-5-mini`, `claude-sonnet-4-6`) are unverified against live APIs by design of this review, and model names belong in configuration rather than code. Wiring gap is P2-8.

## 6. Interoperability assessment

- **Canonical JSON/Schema.** `schemas/canonical-v1.schema.json` ships in the wheel; export validates when `jsonschema` is present; required top-level keys and `$defs` are coherent. Good.
- **CSV.** Flat finding export; stable column order tested.
- **SARIF.** Rule index, location, fingerprint, and source retention are asserted (`test_canonical_interchange.py:110`). Not validated against the official SARIF 2.1.0 schema; the `$schema` URL is embedded only. Recommend a one-time offline validation with the vendored schema before the first external consumer.
- **DefectDojo.** Generic importer shape produced; untested against a live instance.
- **ATT&CK Navigator.** Layer JSON produced from technique mappings; fixture-shaped assertions only.
- **STIX.** Bundle with indicator/vulnerability/relationship objects; `validate_stix_bundle` is an internal structural check, not `stix2-validator`.
- **Graph / BloodHound.** `interop/bloodhound.py` imports and exports; `attack_graph` ingests users/groups/computers/sessions/trusts into typed nodes and edges. No lab-generated data has been through it.
- **Reports.** Single finding model, legacy fields preserved under `metadata.legacy_fields`. Good.
- **Provenance.** Every observation carries `source_execution_id`, `module_path`, `operation_name`, `observed_at`, `confidence`, `engagement_id`; executions persist in module history. This is the strongest interop property in the block.
- **Aranum.** `interop/aranum.py` imports bundles as the bounded "specialist producer" contract from the study and seeds auto-enum from them; the registry requires explicit format for ambiguous JSON, which avoids silent misparse. Matches the study's intent.

## 7. Architecture assessment

- **Duplicate paths.** Three HTTP surfaces (`services/api.py` `/api/v1`, `api/server.py` with 35 legacy routes, `web/dashboard.py` with its own app and entry point); two `WorkflowEngine` construction sites (services and CLI); two `PluginManager` instances; three operation resolvers (W9); two auto-enum modules (A10); `ui/command_mixins/*` still packaged beside the 5,705-line `commands.py`.
- **Service parity.** The service layer is the right seam and is the only place job semantics live. The CLI is the primary operator surface and does not use it. Parity today is API-to-manifest, not CLI-to-API.
- **Durable-state limits.** Jobs, coordinator leases, and advisory drafts beyond the JSON store are process-local. Workflow checkpoints are durable. A restart loses running job state; the README says so for the coordinator, the job API does not.
- **Extension seams.** The `ExecutionRequest`/`Observation` contract and the importer registry are clean seams; new modules only need to emit observations. Plugins load through the same registry. The integration facade is clean.
- **Scale limits.** Single-process JobManager with a thread pool; coordinator in memory; auto-enum per-worker module instances with a global lock around shared state. Adequate for one operator and a handful of agents; not beyond.
- **Consolidation recommendations.** (1) Make the CLI a client of `PurpleSploitServices` (closes P1-2, W5, P2-4). (2) Delete `api/server.py` routes that `/api/v1` covers and retire `purplesploit-web` or mount the dashboard on the `/api/v1` app. (3) Replace the two casefold resolvers with `Framework.find_operation`. (4) Delete `modules/recon/auto_enum.py` and `ui/command_mixins/*` once the CLI is on services. (5) Add a plugin service method and route so the roadmap sentence becomes true.

## 8. Packaging/runtime and test-evidence audit

**Test evidence.** The claim of 4,780 passed / 1 skipped is corroborated within environment differences. In a fresh virtualenv built from the declared dependencies (WeasyPrint omitted, `websockets`/`packaging`/`openpyxl` added) the full suite gave:

| Run | Result |
|---|---|
| Fresh venv, declared deps | 4,778 passed, 2 skipped, 1 failed (321 s) |
| Failing test rerun alone | `tests/benchmarks/test_startup_benchmark.py::test_full_startup` 1 passed |
| Current workstation interpreters | 143 failed, 441 errors, all in `ui/`, `benchmarks/`, `api/`, `web/`, `test_main.py` from missing `fastapi`, `prompt_toolkit`, `pytest-benchmark` |

The one venv failure is order-dependent and environmental, not a code defect. The two skips are the protobuf `importorskip` and PDF without WeasyPrint. Scoped Ruff on core/services/distributed/plugins/integrations/ai/interop/network/impacket passed; `git diff --check` passed. The important caveat: no machine on this host can run the suite without a purpose-built environment, so the 4,780 figure must come from such an environment and the CI workflow should pin it.

**Wheel.** A build into `/tmp` succeeded; it contains all six methodology JSON files, the canonical schema, `services/api.py`, `distributed/agent.py`, eleven interop modules, and also `web/dashboard.py` and ten `command_mixins` files that the roadmap intends to delete. `setup.py` still declares a Python 3.8 classifier against `python_requires=">=3.9"`, omits `websockets` and `packaging`, and keeps version 6.9.1. `python/dist/` holds a stale September build that will confuse anyone running `pip install dist/*`.

**Claims versus evidence.**
- "Capability-complete CWP1–CWP9": justified for engine/service/API code; not justified for CLI job control, authenticated workflow steps, or plugin wiring.
- "Plugin, distributed, integration, and advisory services wired into the primary API/service surface": false for plugins.
- "One FastAPI surface": false while `api/server.py` and `web/dashboard.py` ship.
- `docs/ARCHITECTURE.md:534-541` "No plaintext transmission over network", "Sandboxed output parsing": false today; agents speak plaintext HTTP/WS and parsers run in-process. These sentences predate the block but now read as claims about CWP9 and must be cut or rewritten as S19–S23 targets.
- Distributed README, plugins README, integrations S20 comment, advisory `draft: True, executed: False`, and roadmap §7's "development/lab capability build, not a hardened or supported release" are all accurate.

**Controlled demonstrations still required.** (1) AD lab: `ad_assessment` end to end after P1-1/P2-1, producing graph edges and a BloodHound export that BloodHound CE imports. (2) Web lab: `web_application_test` reaching sqlmap on a form imported from a real spider run. (3) Auto-enum against a /24 lab with HTTPS services after P2-2. (4) Cross-host agent: one remote `purplesploit` agent executing a job, losing the link, reconnecting, and delivering results. (5) One provider-backed advisory proposal after P2-8, with the provider response captured as a fixture. (6) One DefectDojo and one Jira delivery against test instances. (7) SARIF and STIX files validated with the official validators.

## 9. Blocker list and sign-off recommendation

**P1 blockers to the capability-complete claim (two):**
1. Workflow steps never receive credentials; authenticated template steps fail by construction (`core/workflow.py:1034-1041`, `core/framework.py:412`).
2. CLI does not use the service/job layer; CLI job control and CLI/API parity are unmet against B1.10 and C4 item 15 (`ui/commands.py:3287-3291, 3447, 4155, 4895`).

**P2 items to close in the same sprint:** kerbrute observation target, HTTPS rules, partial-run job status, duplicate PluginManager, `credential_harvest` producer, undeclared dependencies, auto-enum timeout/run_dir, advisory provider selection, stale help/artifacts.

**Misleading claims to correct now (documentation only):** the plugin wiring sentence and "one FastAPI surface" in the implementation roadmap §7; the three security sentences in `docs/ARCHITECTURE.md:534-541`.

**Sign-off recommendation.** Do not sign off CWP1–CWP9 as capability-complete yet. Both P1 items are small, mechanical, and fully specified above; neither requires design work. After they land with the two added template contract tests and the roadmap/architecture sentences are corrected, I would sign off CWP1–CWP9 as **code-complete**, with the seven controlled demonstrations in section 8 as the next gate and with no change to the S19–S23 schedule.

**S19–S23 observations, kept separate and not blocking:** plaintext agent transport and no mutual authentication; plugin code loads unsigned and unsandboxed; integration tokens stored in a 0600 JSON file; advisory requests send inventory to third-party providers once a provider is wired; no spray budget beyond `safe_attempts=1`; no authorization or rules-of-engagement gate before execution. All of these are already acknowledged in the code or README where they live, which is the correct state for this block.
