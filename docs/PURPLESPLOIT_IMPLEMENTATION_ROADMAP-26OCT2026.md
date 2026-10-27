# PurpleSploit Capability-First Implementation Roadmap

**Roadmap date:** 26 October 2026
**Source review:** `docs/PURPLESPLOIT_REVIEW_ROADMAP-25OCT2026.md`
**Repository baseline:** `main` at `c9629949033c`
**Status:** CWP1–CWP9 capability code complete after both requested Mythos reviews; controlled demonstrations pending
**Owner direction:** Deliver capabilities first; move every safety and integrity objective to the final schedule block
**Planning:** Two completed GPT-6 Astra planning reviews; no additional planning round
**Execution:** GPT-6.1 Sol agents

## 1. Program objective

The program now prioritizes useful pentest capability, technique breadth, automation, integrations, reporting, and visualization before authorization, safety, integrity, and release hardening.

The first implementation block restores and expands what PurpleSploit can do:

- make workflows, auto-enumeration, and credential spraying technically functional;
- deepen network, Windows, AD, SMB, web, API, identity, cloud, container, Linux, and database coverage;
- make plugins, distributed execution, integrations, and AI assistance operational at a technical level;
- improve reporting, imports/exports, graphs, dashboards, and manual assessment workflows.

The final implementation block then applies:

- canonical data integrity and migrations;
- engagement scope, authorization, rules of engagement, and permission contracts;
- spray budgets and lockout policy, secret protection, evidence integrity, and execution safety;
- application security, plugin trust, AI privacy, supply-chain controls, renderer hardening, CI gates, documentation truth, and release qualification.

Capability-phase outputs are development/lab builds until the final hardening block is complete. That status does not interrupt capability work or insert early safety gates.

## 2. Schedule and capacity

The roadmap uses 24 two-week sprints followed by 4–8 weeks of integration contingency.

| Block | Sprints | Calendar | Outcome |
|---|---:|---:|---|
| Existing capability restoration | S0–S2 | Weeks 1–6 | Current advertised automation works through real framework contracts |
| Core technique expansion | S3–S10 | Weeks 7–22 | Strong internal, web/API, identity/cloud, container, Linux, and database coverage |
| Assessment experience and ecosystem | S11–S18 | Weeks 23–38 | Manual workflows, interop, visualization, plugins, agents, integrations, and AI capabilities |
| Integrity and safety hardening — final block | S19–S23 | Weeks 39–48 | Data integrity, authorization, secrets, safety, security, packaging, and supported release |
| Integration contingency | — | Weeks 49–56 | Capability integration or final hardening corrections; no new scope |

### Reference team

| Role | Primary block |
|---|---|
| Capability/runtime lead | Framework execution, workflows, automation, module contract |
| Internal assessment engineer | Network, AD, SMB, identity, credential capabilities |
| Application assessment engineer | Web, API, Linux, database, reporting |
| Cloud/platform engineer | Cloud, Entra, containers, Kubernetes, distributed runtime |
| Application/interop engineer | CLI/API/web, import/export, visualization, integrations, AI |
| QA/lab engineer | Fixtures, owned labs, compatibility, end-to-end qualification |
| Security/data/release engineer | Joins primarily for S19–S23 hardening |

The roadmap is a sequencing contract, not a claim that all tracks fit one small team. Re-estimate at the end of S2, S10, and S18 using actual adapter and lab velocity. Reduce technique breadth instead of moving final hardening earlier when capacity is constrained.

## 3. Execution rules

1. Capability work is ordered before safety and integrity work.
2. Early contracts cover technical interoperability only: module lookup, operation selection, result shape, parsing, persistence needed for the feature, and interface behavior.
3. Authorization, ROE, permission contracts, spray safety budgets, secret hardening, evidence chain of custody, plugin trust, AI privacy, and application security are not early prerequisites. They are S19–S23 work.
4. Each capability sprint delivers executable code, tests at the external-process boundary, fixtures, and a usable CLI/API path where applicable.
5. Specialist tools remain backends. PurpleSploit adds orchestration, normalization, correlation, and user workflow.
6. Technique expansion uses owned labs and synthetic fixtures for development. Formal support certification occurs in the final block.
7. Stable technical identifiers are preferred during capability work, but schema compatibility and migration guarantees are finalized in the integrity block.
8. Sol agents receive bounded file ownership. Shared framework changes are serialized by the root execution agent.

## 4. Capability work packages

### CWP1 — Restore existing automation

**Sprints:** S0–S2
**Review recommendations:** Capability portions of R1-01–R1-05, R1-08, R3-03, R3-05, R3-06.

- Correct metadata-versus-live-module lookup across workflows, auto-enum, and spray.
- Add stable operation selection using registered operations rather than guessed display names.
- Repair workflow validation, condition handling, step/result propagation, pause/resume behavior, and template operation references.
- Make auto-enum select real Nmap/service operations, consume actual result structures, retain host/port/protocol observations, and produce follow-up module plans.
- Make credential spray configure and execute implemented protocol adapters through the framework contract.
- Introduce a common technical `ExecutionRequest`, `ExecutionResult`, and `Observation` shape without adding authorization policy yet.
- Replace contract-boundary mocks with real framework/fake process tests.

**Exit:** The real-framework reproductions from the review pass. Quick recon completes or fails truthfully; auto-enum discovers services and dispatches valid follow-ups; supported spray protocols reach their real adapter operations.

### CWP2 — Network, Windows, AD, and SMB depth

**Sprints:** S3–S4
**Review recommendations:** R3-03, R3-05, R3-06 and the strongest current capability area from the review.

- Consolidate duplicate Nmap wrappers into profiles while retaining command compatibility.
- Complete IPv4/IPv6, TCP/UDP, service/version, script, OS, segmented target-list, and import profiles.
- Normalize NetExec/NXC SMB, LDAP, WinRM, RDP, SSH, and MSSQL results.
- Expand AD discovery, delegation, trusts, Kerberos roasting, sessions, shares, local-admin relationships, and credential-use relationships.
- Add BloodHound-compatible import/export or adapter support as a capability feature.
- Improve Impacket operation coverage and parsing.
- Build resettable Windows/AD lab scenarios and golden fixtures.

**Exit:** An operator can move from subnet discovery to AD/SMB relationship data, authentication results, and graph-ready output without manually reconciling backend formats.

### CWP3 — Web and API assessment

**Sprints:** S5–S6
**Review recommendations:** R3-01, R3-03, R3-04, R3-06, R3-07 capability portions.

- Compose HTTPX, Feroxbuster, Nuclei, Wfuzz, WPScan, and SQLMap into working discovery and test plans.
- Add first-class HTTP request/response observations, forms, parameters, technologies, endpoints, and findings.
- Add OpenAPI/Swagger ingestion, endpoint generation, authenticated API collections, and replay.
- Add REST authorization test scaffolding, GraphQL introspection/query discovery, gRPC reflection inventory, and WebSocket endpoint testing.
- Support manual request/response notes and evidence attachment as operator capabilities.
- Map executable and manual procedures to OWASP WSTG, ASVS, and API Top 10 coverage.

**Exit:** A web/API target produces a navigable endpoint inventory, test plan, normalized observations, and findings across automated and manual steps.

### CWP4 — Modern identity and cloud

**Sprints:** S7–S8
**Review recommendations:** R3-04 and methodology expansion from R3-01.

- Add OAuth 2.0/OIDC discovery, client/redirect/scope inventory, token-claim inspection, and authorization-flow test helpers.
- Add SAML metadata/assertion inspection and MFA/session workflow capture.
- Add Entra ID tenant, application, service-principal, role, consent, and relationship inventory.
- Add AWS, Azure, and GCP inventory adapters using supported SDK/CLI output.
- Normalize identities, roles, policies, resources, public exposure, and privilege relationships.
- Add cloud evidence import paths for common native assessment outputs.

**Exit:** PurpleSploit can create a cross-provider identity/resource graph and drive review workflows from normalized cloud and federation observations.

### CWP5 — Containers, Kubernetes, Linux, and databases

**Sprints:** S9–S10
**Review recommendations:** R3-04 and technique-domain expansion.

- Add container image/runtime inventory and import adapters for common scanner outputs.
- Add Kubernetes context, cluster, namespace, workload, service, ingress, RBAC, secret-reference, and network-policy inventory.
- Add Linux host, package, service, permission, scheduled-task, credential-artifact, and privilege-escalation observations.
- Add PostgreSQL, MySQL/MariaDB, MSSQL, Oracle, Redis, MongoDB, and Elasticsearch discovery/enumeration adapters selected by available labs.
- Correlate exposed service → identity → role → data/resource relationships.

**Exit:** Container, Kubernetes, Linux, and selected database targets participate in the same target/service/identity/finding workflow as the original Windows modules.

### CWP6 — Assessment lifecycle capabilities

**Sprints:** S11–S12
**Review recommendations:** R3-01, R3-02, R3-07 and capability portions of R2-02/R2-03.

- Add engagement creation, target inventory, assessment phases, test-plan checklists, manual observations, notes, hypotheses, peer-review states, remediation, and retest UX.
- Add version-pinned methodology profiles for NIST SP 800-115, PTES, OWASP WSTG/ASVS/API Top 10, and MITRE ATT&CK.
- Distinguish tested, not tested, not applicable, automated, manual, and imported coverage states.
- Add operator-defined workflow templates and reusable assessment profiles.
- Add comparison views between baseline, current assessment, remediation, and retest.

**Exit:** An operator can run and document a complete assessment lifecycle inside PurpleSploit rather than only launch commands.

### CWP7 — Interoperability and reporting

**Sprints:** S13–S14
**Review recommendations:** Capability portions of R5-01–R5-05 and R5-08.

- Define the working canonical interchange model and JSON Schema.
- Make reports consume the unified finding/observation view without dropping fields.
- Add CSV, SARIF 2.1, and DefectDojo Generic Findings import/export.
- Add ATT&CK Navigator layer and STIX 2.1 export.
- Add graph exports suitable for BloodHound-style and generic graph consumers.
- Preserve source IDs and original payloads where mappings are lossy.
- Add round-trip and consumer-fixture tests.

**Exit:** Assessment data moves between PurpleSploit and common developer/security platforms without manual reformatting.

### CWP8 — Visualization and user experience

**Sprints:** S15–S16
**Review recommendations:** R5-07, R6-01, R6-02 and R4-06 capability portions.

- Consolidate command behavior behind reusable application services.
- Select and complete one primary browser experience while preserving CLI parity.
- Add asset/service topology, identity relationships, attack paths, ATT&CK/methodology coverage, finding trends, remediation/retest, and data-quality views.
- Add evidence and raw-output drill-down.
- Replace the unused duplicate command implementation progressively.
- Generate capability and operation reference content from module metadata.

**Exit:** Operators can navigate targets, relationships, coverage, findings, evidence, and retest state across CLI and browser interfaces.

### CWP9 — Advanced ecosystem capabilities

**Sprints:** S17–S18
**Review recommendations:** Technical capability portions of R4-01–R4-05.

- Make plugin discovery, install, registration, enable/disable, execution, and uninstall function end to end.
- Implement distributed coordinator/agent endpoints, task submission, heartbeats, status, cancellation, result/artifact transfer, and reconnect.
- Repair current WebSocket compatibility.
- Make Jira/GitHub/Slack/Teams/SIEM integrations persist configuration and perform observable sync/delivery.
- Ground AI recommendations in the live module/operation inventory and canonical observations.
- Implement structured advisory analysis and workflow proposal using current provider APIs.

**Exit:** A controlled lab can demonstrate a third-party plugin, a remote agent task, a finding sync, and a grounded AI workflow proposal end to end. Trust, privacy, authorization, and production hardening remain final-block work.

## 5. Final integrity and safety block

All safety and integrity objectives are intentionally placed after the capability sprints.

### Sprint 19 — Canonical data integrity and migration

**Review recommendations:** R2-01–R2-03, R2-05/R2-06 integrity portions, R5-01 compatibility guarantees.

- Select one transactional authority and migration framework.
- Unify assets, identities, services, executions, observations, findings, evidence, remediation, and retest records.
- Eliminate best-effort dual writes.
- Key all child records to engagements.
- Inventory and migrate all legacy databases/session/workflow/report files with reconciliation.
- Add schema versions, compatibility policy, backup/restore, and forward recovery.

**Exit:** One authoritative store passes migration, reconciliation, restart, backup, and restore tests.

### Sprint 20 — Evidence and secret integrity

**Review recommendations:** R2-04/R2-05, R5-05, integrity portions of R4-05.

- Introduce secret references and the selected local secret backend.
- Remove secret values from normal databases, history, logs, reports, prompts, and integrations.
- Add evidence hashes, immutable originals, derived redactions, manifests, retention, and deletion.
- Coordinate database, artifact, and secret recovery.

**Exit:** Credentials and evidence survive recovery without silent loss, plaintext propagation, or unverifiable mutation.

### Sprint 21 — Authorization and execution safety

**Review recommendations:** R1-06/R1-07; safety portions of R1-02–R1-05, R2-02, R3-03/R3-06.

- Add engagement authorization, target scope, exclusions, ROE, action risk, approval, rate, concurrency, and time-window contracts.
- Apply policy at every CLI/API/web/workflow/agent dispatch path.
- Add credential-spray domain/principal/cross-run budgets, lockout discovery, attempt reservation, and uncertain-outcome behavior.
- Add target containment for redirects, DNS changes, target files, crawling, templates, proxies, pivots, retries, and child-tool concurrency.
- Replace unsafe SSH/remote execution behavior with host-key verification, secret-safe delivery, structured remote arguments, cleanup, and authoritative result handling.

**Exit:** Out-of-scope and over-budget actions fail before or during effective dispatch consistently across all interfaces.

### Sprint 22 — Application, plugin, AI, output, and supply-chain security

**Review recommendations:** R0-03–R0-05, R2-07/R2-08, safety portions of R4-01–R4-05, R5-06.

- Add shared authentication, CSRF protection, session expiry, token rotation, safe WebSocket authentication, rate limits, and redacted audit logging.
- Add plugin signatures, independent trust roots, permissions, containment, isolated dependencies/processes, transactional install/uninstall, and path checks.
- Add distributed mutual authentication, scoped agent capabilities, replay/idempotency rules, and artifact verification.
- Add AI consent, context minimization/redaction, prompt-injection boundaries, provider audit, cost limits, and human approval before execution.
- Move integration secrets into the secret provider and add idempotency/conflict/retry controls.
- Neutralize spreadsheet formulas, sanitize report content/links, guarantee PDF temporary cleanup, and apply safe file modes.
- Add dependency audit, SBOM, provenance, and secret/artifact scanning.

**Exit:** Application and extension security regression suites pass across the complete capability set.

### Sprint 23 — Quality, license, documentation, certification, and release

**Review recommendations:** R0-01/R0-02/R0-04/R0-06/R0-07, R3-06, R5-08, R6-01/R6-03–R6-05.

- Resolve the license decision and align repository/package metadata and built artifacts.
- Establish one generated version source.
- Enforce format, selected Ruff rules, type checks, Bandit policy, dependency audit, tests, package build, and signed reproducible releases.
- Remove/replace operational artifacts, enforce synthetic fixtures, and document any history remediation.
- Certify the supported Python, external-tool, operation, and complete-plan matrix in owned labs.
- Generate accurate capability/API/security/deployment documentation.
- Complete observability, health/readiness, support bundles, migration/recovery rehearsal, full synthetic assessment, and local-user pilot.

**Exit:** Every supported claim has evidence; accepted P0/P1 issues are closed; signed artifacts and recovery evidence pass the release checklist.

## 6. Detailed sprint schedule

| Sprint | Primary deliverable | Demonstration |
|---:|---|---|
| S0 | Workflow runtime contract repair | Real framework executes a valid workflow operation; failure is reflected correctly |
| S1 | Auto-enum discovery and follow-up repair | Nmap result produces host/port/service observations and valid follow-up operations |
| S2 | Credential spray adapters plus common execution/result model | Implemented protocols reach real adapter operations through the framework |
| S3 | Network capability consolidation | Nmap profiles and normalized network observations work end to end |
| S4 | AD/SMB/Impacket depth | Owned AD lab produces users, groups, sessions, shares, privileges, and relationships |
| S5 | Web discovery/test plans | HTTP target produces endpoint, parameter, technology, scan, and manual-test inventory |
| S6 | API-specific testing | OpenAPI/REST/GraphQL/gRPC/WebSocket inventory and test workflows |
| S7 | Modern identity | OAuth/OIDC/SAML/Entra relationships and review workflows |
| S8 | Cloud | AWS/Azure/GCP inventory and privilege/resource graph |
| S9 | Containers/Kubernetes | Cluster, RBAC, workload, network, and exposure observations |
| S10 | Linux/databases | Host privilege and selected database enumeration workflows |
| S11 | Engagement/manual assessment UX | Test plans, notes, evidence attachment, review, remediation, and retest |
| S12 | Methodology coverage | Versioned coverage profiles and tested/not-tested/not-applicable views |
| S13 | Canonical interchange and Tier 1 interop | JSON/CSV/SARIF/DefectDojo import/export round trips |
| S14 | ATT&CK/STIX/graph/report expansion | Navigator/STIX/graph exports and complete reports |
| S15 | Shared application services | CLI/API/browser perform equivalent capability operations |
| S16 | Visualization | Evidence-linked topology, attack path, coverage, finding, and retest dashboards |
| S17 | Plugins/distributed/integrations | Plugin and remote task execute; finding sync completes |
| S18 | AI advisory capabilities | Grounded structured analysis and workflow proposal uses live inventory |
| S19 | Data integrity/migration | One authoritative store and reconciled legacy import |
| S20 | Secrets/evidence integrity | Secret references and verifiable evidence/recovery |
| S21 | Authorization/execution safety | Scope, ROE, budgets, containment, and remote-execution safety |
| S22 | Application/ecosystem security | Auth, CSRF, plugin/agent/AI trust, renderer and supply-chain hardening |
| S23 | Release integrity | License, CI gates, docs, certification, signed supported release |

## 7. Current execution status

### CWP1 capability implementation — completed 26 October 2026

The original restoration batch was followed by the first Mythos 5.1 review and
three bounded GPT-6.1 Sol correction tracks. The resulting foundation now includes:

1. **S0 workflow runtime contract repair**
   - uses live module instances instead of registry metadata;
   - validates exact registered operation names and executes through the framework;
   - propagates step failures to the workflow result and terminal state;
   - rejects unsupported condition types and implements the built-in `forms_found` condition;
   - corrects built-in SMB operation references;
   - preserves completed work across pause/resume, honors pauses between steps, and rebuilds truthful full-workflow summaries.
2. **S1 auto-enum core repair**
   - selects real Nmap operations for each active scope and skips Nmap in passive scope;
   - forces synchronous discovery so results are available to the pipeline;
   - consumes native, parsed, XML, and session-derived service results;
   - retains host, service, port, protocol, version, and raw service identity;
   - enumerates concrete hosts discovered from CIDR scans;
   - resolves exact registered follow-up operations and enforces service-rule ports.
3. **S2 credential-spray adapter repair**
   - maps only protocols with an implemented authentication operation;
   - configures canonical adapter options on a live module instance;
   - executes exact `Test Authentication` operations through the framework;
   - distinguishes credential success, failure, ambiguous tool success, and reported lockout responses.
4. **Common execution and observation contract**
   - serializable `ExecutionRequest`, `ExecutionResult`, `ExecutionOutcome`, and `Observation` records;
   - non-mutating module instantiation, stable operation lookup, explicit option locks, manifest normalization, process timeouts, artifacts, and truthful pending background handles;
   - legacy result-to-observation adaptation with deterministic provenance IDs.
5. **Mythos correction pass**
   - built-in Nmap workflow steps are synchronous and real templates are covered at the subprocess boundary;
   - conditions and database lookups are target scoped; retries and forward success/failure branches execute; workflow checkpoints are atomic, restart-visible, and do not replay an interrupted unknown external action;
   - validation and execution no longer replace the operator's selected module;
   - AutoEnum fixes real Fast/UDP argv, rejects synthetic CIDR endpoints, ingests external/session/database seeds, retains endpoint provenance, binds URLs/domains/controllers correctly, injects real credentials, and reports partial/skipped/failure states;
   - spray rejects unsupported adapters before iteration, pins empty credential fields against session-context bleed, reuses detached adapters, records skipped/ambiguous/tool-error outcomes, and is tested against the five real NXC adapter command boundaries.

Work previously started on renderer hardening and feature containment was reverted after the owner changed the sequence. No final-block safety or integrity objective remains in this capability batch.

### Verification evidence

- 525 combined execution, workflow, AutoEnum, Nmap, spray, and workflow-integration regressions passed after the Mythos correction pass.
- The focused spray suite passes 64 tests, including actual SMB/RDP/WinRM/SSH/MSSQL adapter argv checks.
- Real-framework tests retain actual module discovery, lookup, option, and operation contracts while replacing only the external process boundary.
- All registered operations referenced by the default auto-enum rules are checked by contract tests.
- Modified source and new contract tests pass Ruff; modified source passes Python compilation; `git diff --check` passes.
- The final integrated full-suite run passed 4,050 tests with no failures after the pause/resume follow-up.

### Gate C0 status — code complete; owned-lab evidence pending

The implementation portion of C0 is complete. The remaining acceptance item is an
owned-lab run of the recorded Nmap and NetExec paths; this environment deliberately did
not contact a live target. Process-boundary fixtures exercise the real modules and argv.
Crash recovery now preserves an interrupted external action as an unknown failed attempt
and never replays it automatically. DNS zone transfer is skipped unless a real domain is
available. Consolidation of legacy wrapper modules remains CWP2 work.

The first Mythos review is preserved at
`docs/reviews/MYTHOS51_CWP1-CWP9_INITIAL_REVIEW-26OCT2026.md`. The accepted Aranum study
is at `docs/ARANUM_INTEROP_STUDY-26OCT2026.md`; its bounded offline inventory/seed slice is
scheduled with CWP2 rather than broadening CWP1.

### CWP2–CWP5 technique expansion — completed 26 October 2026

- **CWP2:** Consolidated Nmap profiles and import behavior; normalized NXC observations;
  expanded Impacket/AD/SMB adapters; and added BloodHound-compatible relationship import.
- **CWP3:** Added normalized HTTP request/response, endpoint, form, parameter, and technology
  observations; OpenAPI, REST, GraphQL, gRPC, and WebSocket inventory paths; and composed
  HTTPX, Feroxbuster, Nuclei, Wfuzz, WPScan, and SQLMap assessment inputs.
- **CWP4:** Added offline OAuth/OIDC, SAML, Entra, AWS, Azure, and GCP normalization into the
  common identity/resource relationship model. Provider-native collection remains an adapter
  boundary rather than a replacement for supported SDKs and CLIs.
- **CWP5:** Added container/Kubernetes, Linux host, and database inventory importers and graph
  relationships for services, identities, roles, workloads, and resources.
- **Aranum:** Implemented the study's highest-value bounded slice: offline Aranum inventory
  import plus AutoEnum seed conversion with provenance. A live launcher, scheduler, or cache
  was intentionally not added because Aranum completion semantics are not yet stable enough.

### CWP6 assessment lifecycle — completed 26 October 2026

- Added engagement/assessment records, target inventory, phases, notes, manual observations,
  evidence references, review/remediation/retest state, and reusable workflow/assessment data.
- Added version-pinned methodology profiles and explicit coverage states for automated,
  manual, imported, tested, not-tested, and not-applicable work.
- Added canonical findings to reports without discarding provenance, evidence, remediation,
  or retest fields.

### CWP7 interoperability and reporting — completed 26 October 2026

- Added a canonical interchange model, JSON Schema, importer registry, source identifiers,
  original-payload preservation, and normalized graph envelope.
- Added JSON/CSV, SARIF 2.1, DefectDojo Generic Findings, ATT&CK Navigator, supported STIX 2.1,
  and generic graph JSON/CSV import/export paths with round-trip fixtures.
- Added BloodHound-style relationship handling through the graph/identity adapters.
- These are explicitly supported subsets. They do not claim universal SARIF, STIX, DefectDojo,
  or BloodHound dialect compatibility until S23 certification.

### CWP8 shared services and operator views — completed 26 October 2026

- Added reusable application services for modules/operations, execution, workflows/jobs,
  assessments, findings/reports, importers, graph data, and visualization view models.
- Added a primary versioned FastAPI surface backed by the same services, with generated
  capability reference content and tested API/service parity. Legacy compatibility routes and
  the older dashboard still ship and are not described as a single consolidated surface.
- Added topology, identity-relationship, attack-path, methodology coverage,
  findings/retest, and data-quality views with raw evidence links.
- The existing legacy dashboard and duplicate command mixins remain compatibility surfaces;
  progressive removal is deferred until the capability paths have field use evidence.

### CWP9 advanced ecosystem — completed 26 October 2026

- **Plugins:** Local discovery, install, startup registration, live framework registration,
  enable/disable, execution, recovery, and uninstall work end to end. A sample plugin and
  lifecycle regression coverage are included. Signing, containment, permissions, and isolated
  dependencies remain S22 work.
- **Distributed execution:** Coordinator/agent registration, heartbeat, task leasing,
  acknowledgement, at-least-once result submission, cancellation, reconnect, artifact/result
  ingestion, HTTP endpoints, and the WebSocket agent path are implemented. Cancellation is
  cooperative and may truthfully end as `cancel_unconfirmed`; mutual authentication,
  authorization, replay hardening, and artifact verification remain S21–S22 work.
- **Integrations:** Named Jira, GitHub, Slack, Teams, and SIEM instances persist configuration,
  field/status mappings, connection state, and observable delivery history. Live external
  delivery was not attempted from this environment; secret storage, retry/idempotency, and
  conflict hardening remain S20/S22 work.
- **AI advisory:** The recommender is grounded in the live registered module/operation inventory
  and canonical observations, filters nonexistent module suggestions, supports current OpenAI
  Responses and Anthropic message adapters, and creates draft workflows without executing them.
  Consent, redaction, provider governance, cost controls, and approval policy remain S22 work.
- **Unified API:** Plugin, distributed, integration, and advisory services are wired into the
  primary API/service surface rather than existing only as disconnected libraries.

### Current verification evidence

- The integrated CWP7–CWP9 capability slice passes **980 tests with 1 intentionally skipped**.
- After the final Mythos corrections, the complete Python repository suite passes
  **4,789 tests with 1 intentionally skipped**.
- The skipped test is an optional consumer-dependent interop case and is reported rather than
  silently treated as coverage.
- Scoped Ruff checks, Python compilation, and `git diff --check` pass. The final wheel builds
  successfully, declares `jsonschema`, `websockets`, and `packaging`, and contains all six
  methodology profiles plus the canonical schema.
- No live target, remote agent host, third-party ticket/chat system, or model provider was
  contacted. Process-boundary fakes and synthetic fixtures verify technical contracts; owned-lab
  and controlled external demonstrations remain gate evidence, not implied completed work.

### Final Mythos 5.1 review and disposition — completed 26 October 2026

The second and final independent review is preserved at
`docs/reviews/MYTHOS51_CWP1-CWP9_FINAL_REVIEW-26OCT2026.md`. It reported no P0 issue and two
P1 capability blockers. Both were corrected before sign-off:

1. **Authenticated workflow binding:** scoped credentials, domains, users, and generated user
   lists now bind into deterministic execution requests before option locking. The shipped
   `ad_assessment` and `credential_harvest` templates run through real module/process boundaries
   in contract tests.
2. **CLI/service parity:** the production console now owns the same `PurpleSploitServices`
   facade as the versioned API. Workflow, AutoEnum, and spray commands submit non-blocking jobs;
   CLI job status, pause, resume, and stop operate on the shared `JobManager`.

The capability-level P2 findings were also closed: Kerbrute observations retain the assessed
target, HTTPS reaches HTTPX/Feroxbuster/Nuclei, partial/skipped AutoEnum jobs complete with a
truthful outcome, the CLI reuses the framework plugin manager, credential-harvest has a user
producer, direct runtime dependencies are declared, AutoEnum supplies timeouts and isolated run
directories, advisory providers are selectable for production surfaces, plugin lifecycle is
available through services/API, and stale LDAP spray help was removed.

Release-version changes, cleanup of old built artifacts, final consolidation of the legacy API,
dashboard, and command mixins, and official consumer-validator certification were assigned to
S23 and are dispositioned in the final-block record below.
The `interop-channel` and `.interop/` files are retained intentionally as the owner-requested
Claude/Aranum collaboration channel; the durable study is in `docs/research/` and `docs/`.

### Gates C1–C4 status — code complete; controlled demonstrations pending

The implementation portions of C1 through C4 are complete. Formal technique support claims,
real-provider compatibility, owned-lab execution, and supported-release certification remain
environment-specific. CWP1–CWP9 entered the final hardening block only after their capability
implementation completed, preserving the owner-directed sequence.

### S19–S23 final integrity, safety, and release block — completed 27 October 2026

| Sprint | Delivered result | Verification evidence |
|---|---|---|
| S19 | Schema-migrated canonical SQLite authority, engagement ownership, revisions/audit chain, legacy reconciliation, backup and restore | Store/migration/restart/reconciliation tests and recovery rehearsal pass |
| S20 | Encrypted secret references, content-addressed immutable evidence, redactions/manifests, retention, and coordinated recovery | Integrity and integration tests pass; normal stores and outputs carry references rather than secret values |
| S21 | Fail-closed authorization/scope/ROE/risk/approval/rate/concurrency/window policy, spray reservations/budgets, containment, and verified SSH transport | Policy is enforced at direct, API, workflow, AutoEnum, spray, and agent dispatch boundaries; focused policy/remote suites pass |
| S22 | Shared application authentication/CSRF/session/WebSocket controls, signed isolated-process plugins, authenticated scoped agents, AI consent/redaction/budgets, integration delivery controls, output neutralization, and supply-chain gates | Focused security regressions, Bandit, dependency audit, Ruff, and scoped type checks pass |
| S23 | Version 7.0.0 single-source packaging, aligned CC-BY-NC-SA-4.0 metadata, supported fail-closed server, readiness/support bundle, artifact cleanup, deployment/recovery/security docs, reproducible builds, SBOM/provenance/signing workflow, and certification scripts | Full suite passes **4,828 tests with 1 intentional skip**; independent builds produce byte-identical wheel and normalized sdist; `twine check`, package certification, and recovery rehearsal pass |

The repository deliverables through S23 are complete and constitute a certified release
candidate. The release tag is intentionally a maintainer action; keyless signatures and their
transparency-log evidence are created only by the tag workflow. Live external-tool/provider
claims, an owned-lab run, and a local-user pilot remain acceptance evidence rather than claims
fabricated from this checkout. Those items do not represent unfinished implementation.

## 8. Recommendation traceability by schedule block

| Recommendation group | Capability-first delivery | Final safety/integrity delivery |
|---|---|---|
| R0-01–R0-07 | Packaging convenience changes may accompany capabilities only when non-blocking | License, CI/security gates, artifact hygiene, dependency integrity, version/docs truth in S22–S23 |
| R1-01–R1-05/R1-08 | Functional executor, workflows, auto-enum, spray, results, and tests in S0–S2 | Lifecycle safety, budgets, uncertain outcomes, and policy integration in S21 |
| R1-06/R1-07 | No early permission-contract sprint | Scope/ROE and remote-execution safety in S21 |
| R2-01–R2-08 | Minimum feature-local persistence and engagement UX in S0–S18 | Canonical authority, migration, isolation, secrets, evidence, concurrency, app security in S19–S22 |
| R3-01–R3-07 | Primary capability program S3–S12 | Certification portions in S21–S23 |
| R4-01–R4-06 | Technical plugin/agent/integration/AI functionality in S17–S18 | Trust, privacy, authorization, secret, replay, and isolation controls in S22 |
| R5-01–R5-08 | Formats, reports, visualization, and consumer behavior in S13–S16 | Evidence integrity, output hardening, compatibility/release gates in S20/S22/S23 |
| R6-01/R6-02 | Generated capability inventory and unified experience in S15–S16 | Security docs, deployment profiles, observability, and release integrity in S23 |
| R6-03–R6-05 | Operational hooks may be developed with their capabilities | Supported deployment, release checklist, signing, recovery, and certification in S23 |

## 9. Capability-first decision gates

| Gate | Timing | Decision |
|---|---:|---|
| C0 — Existing automation works | End S2 | Continue expansion only after workflows, auto-enum, and implemented spray adapters work through real contracts |
| C1 — Internal assessment breadth | End S4 | Confirm Windows/AD/SMB/network capability is strong enough to serve as the product anchor |
| C2 — Modern assessment breadth | End S10 | Confirm which web/API/identity/cloud/container/Linux/database adapters continue to supported release |
| C3 — Complete assessment experience | End S16 | Confirm interop, report, manual workflow, and visualization feature set |
| C4 — Advanced ecosystem | End S18 | Confirm plugin/distributed/integration/AI features to carry into hardening |
| H1 — Integrity complete | End S20 | Canonical data, migrations, secrets, and evidence ready for safety enforcement |
| H2 — Safety/security complete | End S22 | Full capability set passes authorization and security regression suites |
| G4 — Supported release | End S23 | License, quality, docs, certification, signing, recovery, and pilot accepted |

If a capability misses its gate, remove it from the later hardening scope or assign more capacity. Do not move the final safety/integrity block forward to compensate.

## 10. Model and execution protocol

The two requested planning reviews were completed with GPT-6 Astra at `xhigh` on 26 October 2026. The owner-directed capability-first reorder supersedes their safety-first sequencing and does not create a third review round.

GPT-6.1 Sol executes bounded tasks. Each task specifies capability outcome, files, real-framework or process-boundary tests, and non-goals. During S0–S18, prompts explicitly defer permission, safety, integrity, trust, privacy, and release-hardening work unless the owner changes direction again.

Human owners select technique breadth and accept demonstrations. Formal safety and supported-release acceptance occurs only in S19–S23.
