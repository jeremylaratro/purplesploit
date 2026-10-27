# PurpleSploit Technical Review and Recommendation Roadmap

**Review date:** 25 October 2026
**Repository baseline:** `main` at `c9629949033c`
**Review type:** Read-only architecture, correctness, capability, security, and interoperability review
**Implementation status:** No product changes were made as part of this review

## 1. Executive assessment

PurpleSploit has the beginnings of a useful local penetration-testing workbench: a broad Windows/AD/SMB capability set, shared target and credential context, a module abstraction, reporting in several human-readable formats, an attack graph, and unusually extensive unit tests for a project at this stage. Recent hardening also corrected several historically dangerous behaviors: external commands generally use `shell=False`, arbitrary API execution is disabled by default, the API defaults to loopback with token support, sensitive API fields are redacted, XML parsing is hardened, and plugin extraction has traversal and decompression checks.

It is not yet a dependable assessment orchestration platform. The highest-risk problem is not missing techniques; it is that several core features do not share the same runtime contract. Real framework instances reproduce failures in workflows and credential spraying that mocked unit tests do not expose. Auto-enumeration also selects invalid operation names and cannot reliably consume the asynchronous Nmap result it launches. At the data layer, multiple partially synchronized databases and three incompatible finding models prevent a trustworthy engagement record. These issues make additional technique breadth premature.

The recommended product direction is:

> Build PurpleSploit as an assessment orchestration, evidence, and interoperability platform around specialist security tools—not as a replacement for every scanner or exploitation framework.

That means a stable adapter contract, a canonical engagement data model, scope and safety enforcement at the engine boundary, versioned machine-readable output, and strong evidence provenance. Specialist tools such as Nmap, Nuclei, NetExec, Impacket, SQLMap, and future cloud/container tools should remain execution backends.

### Overall maturity

| Axis | Assessment | Summary |
|---|---:|---|
| Technical capabilities | 2.5 / 5 | Useful breadth and sound tool choices in the core Windows/network niche, but several orchestration features are prototypes and technique coverage is uneven. |
| Correctness and reliability | 2 / 5 | Large passing suite, but critical integration contracts fail at runtime; error states and exit results are sometimes reported as success. |
| Product concept and architecture | 2 / 5 | The local workbench concept is valuable. The current duplicate stores, finding types, web surfaces, and command implementations will not scale safely. |
| Interoperability and presentation | 2.5 / 5 | Good human-report and graph foundations, but no canonical schema, evidence bundle, or first-class imports/exports for common security platforms. |

### Product maturity by operating mode

| Operating mode | Current judgment |
|---|---|
| Local, manual CLI use by a knowledgeable operator | **Useful beta**, provided the operator reviews commands and raw output. |
| Automated workflow, auto-enumeration, and spraying | **Prototype / currently unreliable**. |
| Multi-engagement system of record | **Not ready**; data separation and provenance are insufficient. |
| Distributed operation and plugin marketplace | **Prototype / incomplete feature claim**. |
| AI-assisted analysis | **Experimental**; privacy, truthfulness, and module-reference issues need correction. |
| Reporting and graph interoperability | **Early beta**; good presentation seeds but weak machine contracts. |

## 2. Review method and limits

The review combined:

- static inspection of the framework, module, workflow, automation, database, API, web, reporting, graph, integration, distributed, plugin, and packaging code;
- runtime module and operation discovery;
- full unit and benchmark test execution in an isolated environment;
- source coverage measurement;
- compilation, lint, format, type/security CI-policy, packaging, and dependency inspection;
- focused contract reproductions using real framework objects rather than mocks;
- comparison against current primary standards and platform guidance.

### Measured baseline

| Measure | Result |
|---|---:|
| Application source files | 115 Python files |
| Approximate application source | 44,225 lines |
| Test files | 89 Python files |
| Approximate test source | 55,837 lines |
| Runtime-discovered modules | 44 |
| Full suite with declared benchmark dependency | 4,026 passed |
| Coverage suite | 3,982 passed, 75% total source coverage |
| Compilation | Passed |
| Ruff findings in product source | 230 |
| Ruff format drift | 97 files would be reformatted |

The 230 Ruff findings consist principally of 129 unused imports, 64 false/f-string-without-placeholder findings, and 29 unused variables, plus bare `except`, ambiguous names, and redefinitions. CI currently makes Ruff, formatting, Mypy, and Bandit advisory with `|| true`. Bandit is also configured to skip several subprocess and shell-related checks that matter for this product. `safety` is installed but not run.

The coverage run emitted two `coroutine was never awaited` warnings in distributed transport tests. The first test run failed only because `pytest-benchmark`, which is declared as a development dependency, was absent; installing it produced the clean 4,026-test result.

### Validation boundary

This was not an authorized live-target penetration test. Only Nmap, HTTPX, Feroxbuster, SQLMap, Kerbrute, and sshpass were present in the review environment. NetExec/NXC, Nuclei, Wfuzz, WPScan, Impacket executables, and Ligolo were absent. Therefore this report distinguishes code/contract validation from technique efficacy. External-tool correctness must ultimately be proven against owned lab fixtures and a supported tool-version matrix.

## 3. Priority and decision model

| Priority | Meaning |
|---|---|
| **P0** | Release or trust blocker; fix before presenting the affected capability as operational. |
| **P1** | Required for a dependable supported release. |
| **P2** | Important expansion or maintainability work after the foundation is stable. |
| **P3** | Optional enhancement driven by target users and deployment model. |

Recommendations have stable IDs so approval can be expressed by ID or by sign-off bundle in section 12.

## 4. Review Sprint 0 — Release truth, quality baseline, and supply chain

### Objective

Make the repository, package, documentation, and CI describe the same product and establish a trustworthy release gate.

### Findings

1. **The license is contradictory.** The root repository presents CC BY-NC-SA 4.0, while `setup.py` and built package metadata declare MIT. The built wheel and source distribution do not contain the license file. This is a release and downstream-consumption blocker.
2. **Versions and security documentation drift.** Package metadata is 6.9.1, the README is 6.8.1, quick-start content is 6.7.0, static pages identify as 2.0.0, and C2-facing components contain other versions. `docs/API.md` still describes an unauthenticated, wildcard-CORS server on `0.0.0.0` and credential responses containing passwords; the code now defaults to loopback, supports bearer tokens, uses localhost CORS, and redacts secrets. Stale security instructions can cause unsafe deployments even when the code is safer.
3. **Package dependencies do not match imports.** Shodan is imported directly but is not a runtime dependency or explicit extra. `packaging` and `websockets` are also used directly while relying on transitive installation. Conversely, several heavy dependencies appear unused by product source. The core install is larger and less deterministic than necessary.
4. **Python support claims are inconsistent.** Metadata/classifiers claim Python 3.8 and `python_requires >=3.9`, while CI tests 3.10–3.13. Python 3.8 is both contradictory and unverified.
5. **CI records quality and security findings without enforcing them.** Lint, formatting, type checking, and Bandit failures cannot fail the build. Dependency vulnerability checking is not actually run. The build job depends only on tests, not the quality/security jobs.
6. **Operational artifacts are tracked.** Scan output, session files, graph output, and a test PDF are present in source control. Even when current examples are harmless, this establishes an unsafe pattern for engagement data.

### Recommendations

| ID | Priority | Recommendation | Acceptance evidence |
|---|---|---|---|
| R0-01 | P0 | Choose one license with counsel/owner approval, align all metadata and headers, and include the license in wheel and sdist. | Repository and package metadata agree; automated artifact test confirms the license is shipped. |
| R0-02 | P1 | Establish a single generated version source and generate/version-check README, CLI, web, API, and C2 displays from it. | A CI test fails on version drift; no hand-maintained version strings remain. |
| R0-03 | P1 | Move packaging to `pyproject.toml`; declare every direct dependency directly; split core, API, reporting, AI, OSINT, distributed, and development extras; publish a constraints/lock policy and SBOM. | Fresh installs of each supported extra pass import and smoke tests without transitive accidents. |
| R0-04 | P1 | Turn format, selected Ruff rules, Mypy for core contracts, Bandit policy, dependency audit, package build, and tests into required checks. Ratchet existing lint debt rather than attempting a risky one-shot cleanup. | Protected builds cannot pass with new lint/type/security failures; a documented baseline is checked in. |
| R0-05 | P1 | Remove operational artifacts from tracked source, strengthen ignore rules, add secret/engagement-data scanning, and document a safe fixture policy. Rewrite history only after explicit owner review. | Repository contains synthetic fixtures only; CI detects likely credentials, tokens, and common scanner/session outputs. |
| R0-06 | P1 | Publish an explicit supported Python and external-tool version matrix; remove unsupported classifiers. | CI covers every claimed Python version and adapter compatibility fixtures cover each claimed tool family. |
| R0-07 | P1 | Replace stale security documentation immediately and generate API reference from the running OpenAPI contract where practical. | Documented bind/auth/CORS/redaction behavior matches executable defaults and security tests. |

### Sprint 0 decision gate

Do not publish a new package until R0-01 is resolved. Do not call a release supported until R0-03, R0-04, R0-06, and R0-07 are complete.

## 5. Review Sprint 1 — Execution correctness and operator safety

### Objective

Make every execution path use one validated module/operation contract and report failures truthfully.

### Findings

#### 5.1 Framework contract breaks real workflows and credential spraying

`Framework.get_module(path)` returns `ModuleMetadata`; `Framework.use_module(path)` returns a live module instance. Workflow and credential-spray code treat `get_module()` as a live module. A reproduction with the real framework produced:

```text
get_module_type ModuleMetadata
use_module_type NmapModule
quick_recon: success=True, completed_steps=0, failed_steps=1
first_error: 'ModuleMetadata' object has no attribute 'options'
credential_spray: false
error: 'ModuleMetadata' object has no attribute 'set_option'
```

The workflow still transitions to `COMPLETED` and returns overall success after the failed step. Unit tests hide this because they mock `get_module()` to return an object with live-module methods.

#### 5.2 Workflow behavior is fail-open and internally inconsistent

- Module-existence validation contains a TODO/pass.
- Unknown condition types evaluate permissively. Templates use a `forms_found` condition that is not implemented, so a guarded SQLMap step can run without the intended evidence.
- Service checks call a database method that does not exist and swallow the resulting error.
- Pause does not interrupt the active execution loop. Resume starts the workflow loop again and can rerun completed work.
- Created workflows are not immediately persisted, and storage is not restored consistently on startup.
- Several template operation names do not match registered module operations, such as `spider` versus `Spider Only (No Download)`.

#### 5.3 Auto-enumeration does not reliably control or consume modules

- It assigns `current_operation`, but the framework calls `module.run()` and has no `BaseModule.set_operation()` contract; the intended operation is therefore not selected consistently.
- Its Nmap scope names (`Quick Scan`, `Service Version`, `Full Scan`) do not match the module's actual operations. Only `Stealth` exists among the scope mappings.
- The `passive` scope still invokes Nmap, making a safety label actively misleading.
- Nmap defaults to background execution. Auto-enumeration immediately expects synchronous top-level `services`, while Nmap returns parsed results under a different structure or writes them to the database later.
- Service rules define ports, but the pipeline retains service names without a dependable host/port observation contract.
- Additional operation mismatches include `Enumerate Shares` versus `List Shares`, an absent `Domain Info`, an absent `RDP Screenshot`, and `Zone Transfer` versus `Zone Transfer (AXFR)`.

#### 5.4 Credential spraying is not a dependable safety-controlled capability

- Thirteen protocols are exposed but only seven have a module mapping; HTTP, FTP, OWA, and O365 paths are among those not implemented.
- The same metadata/instance mismatch prevents real execution, after which the code expects additional module APIs that are not part of the current base contract.
- Lockout-policy detection is a stub returning a conservative default, not actual discovery.
- In no-framework mode, known sample credentials can be simulated as successes. Simulation must never be indistinguishable from observed authentication.

#### 5.5 Execution results are not consistently authoritative

The external-tool base is safer than historical versions because it tokenizes commands and uses `shell=False`. However, modules still construct strings and reparse them instead of returning an argument vector. Deployment paths use `sshpass -p`, disable SSH host-key verification, interpolate remote shell fragments, and in several paths report success without making process exit status the source of truth. A structured execution result is missing.

### Recommendations

| ID | Priority | Recommendation | Acceptance evidence |
|---|---|---|---|
| R1-01 | P0 | Define one canonical module resolver/executor. Use immutable module IDs and stable operation IDs, not display strings. Eliminate ambiguity between metadata lookup and instance acquisition. | CLI, API, workflow, auto-enum, spray, AI, and plugins all execute through one typed interface; contract tests use real modules. |
| R1-02 | P0 | Repair workflow state semantics: validate modules/operations up front, fail closed on unknown conditions, propagate step failure to workflow result, implement cancellation-aware pause/resume, checkpoint state, and make retry/rerun behavior explicit. | Reproduced quick-recon failure is impossible; failure, skip, pause, resume, retry, and restart tests pass without duplicate execution. |
| R1-03 | P0 | Rebuild auto-enumeration on the canonical executor. Make passive mode truly passive, consume completed typed observations, preserve host/port/protocol identity, and validate every built-in plan during startup/CI. | Each scope produces a reviewed execution plan; zero invalid operation IDs; lab runs create deterministic observations. |
| R1-04 | P0 | Restrict credential spray to implemented protocol adapters; distinguish unsupported, simulated, attempted, blocked, and observed-success states; add real policy discovery where feasible; enforce per-domain/account budgets and stop conditions. | No simulated result can appear as evidence; lockout tests prove global and per-principal safety boundaries. |
| R1-05 | P1 | Introduce a structured `ExecutionRequest`/`ExecutionResult`/`Observation` contract with argv, timestamps, exit code, stdout/stderr references, timeout, cancellation, tool version, and provenance. | Every external adapter has golden contract tests; nonzero/timeout/cancel states cannot report success. |
| R1-06 | P0 | Put authorization scope and rules of engagement in the engine, not only the UI. Require engagement, target scope, action risk, side-effect declaration, concurrency budget, and approval policy before dispatch. Add dry-run/explain-plan. | All entry points reject out-of-scope actions identically; plans show exact targets, commands, risk, and expected artifacts. |
| R1-07 | P1 | Replace insecure SSH defaults: verify/pin host keys, avoid passwords in process arguments, quote remote arguments structurally, and centralize remote execution status and cleanup. | Deployment integration tests cover special characters, host-key mismatch, failed execution, timeout, and cleanup. |
| R1-08 | P0 | Add vertical integration tests that instantiate the real framework and run built-in plans against fake executors/owned lab services. Reduce mocks at contract boundaries. | Tests reproduce and then prevent every defect in this section. |

### Sprint 1 decision gate

R1-01, R1-02, R1-03, R1-04, R1-06, and R1-08 are prerequisites for describing automation as operational. Until then, label workflow, auto-enum, and spray commands experimental.

## 6. Review Sprint 2 — Engagement data, evidence, and application security

### Objective

Create one trustworthy, isolated assessment record that every interface reads and writes consistently.

### Findings

1. **There are multiple authorities for the same data.** The core uses a raw SQLite database while `models/database.py` maintains six SQLAlchemy SQLite databases for credentials, targets, web targets, AD targets, services, and exploits. Startup and mutation paths attempt best-effort synchronization and swallow failures. Different surfaces can also resolve different default data directories. There is no transaction spanning these stores.
2. **There are three finding models.** The core table, rich findings manager, and reporting model have incompatible severity/status/evidence fields. For example, `ACCEPTED_RISK` exists in one status enum but not another. Conversion drops evidence, proof, timestamps, assignment, tags, references, MITRE mappings, notes, or raw output depending on the route; some conversions can fail outright.
3. **Workspace is not a real engagement boundary.** A database table exists, but most records are not reliably keyed to a workspace/engagement. `Session.workspace` is a result dictionary, while the API models workspaces as directories. Cross-client or cross-assessment contamination is therefore plausible.
4. **Provenance is too weak for defensible evidence.** Assets, observations, findings, executions, assessment runs, tool versions, operator identity, `first_seen`/`last_seen`, and lineage do not share durable IDs. Evidence is generally a path or content field without an immutable copy, hash, manifest, or chain-of-custody record.
5. **Secrets are protected by filesystem modes but stored in plaintext.** The secure `0600` file/`0700` directory defaults are good. The platform lacks a vault/secret-reference abstraction, field encryption, retention/deletion policy, and comprehensive command-history redaction.
6. **Command-history redaction is incomplete.** Several credential-bearing command forms are not covered. History may then be included in AI context, causing secret disclosure to a configured model provider.
7. **The two web applications have different trust models.** The FastAPI surface has improved token/loopback protection. The separate Jinja dashboard on port 8000 lacks authentication and CSRF protection on mutating form routes. CORS does not prevent cross-site form submission to loopback.
8. **The API is appropriate only for a local single-user trust boundary today.** Query-string WebSocket bearer tokens may leak through logs/history; framework sessions have no meaningful TTL/bounds; C2 dispatch lacks robust quotas; and there is no RBAC, TLS posture, team audit model, or role separation.

### Recommendations

| ID | Priority | Recommendation | Acceptance evidence |
|---|---|---|---|
| R2-01 | P0 | Select one canonical persistence layer and migration system. Migrate legacy stores explicitly; remove best-effort dual writes. | One transactional source of truth; migration and rollback fixtures prove no silent loss. |
| R2-02 | P0 | Make `Engagement` a required first-class boundary with immutable IDs, authorization/scope, exclusions, dates, owners, methodology profile, retention policy, and keyed child records. | Every target, credential reference, run, observation, finding, evidence item, report, and audit event belongs to exactly one engagement. |
| R2-03 | P0 | Define one canonical domain model for asset, endpoint/service, identity, credential reference, execution, observation, finding, evidence, remediation, and retest. Use adapters only at import/export boundaries. | No lossy internal finding conversion; all UI/API/report paths preserve the same fields and status vocabulary. |
| R2-04 | P0 | Create a secret-provider interface using references rather than values. Support OS keyring or encrypted local storage first and enterprise vaults later. Implement retention, deletion, export controls, and complete history/log redaction. | Database/API/report/history/AI scans show no recoverable secret values unless an explicitly authorized secret operation requests them. |
| R2-05 | P1 | Build an evidence store with content hashes, MIME/type, source execution, tool/version, operator, captured time, original path, immutable copy, annotations, and signed/exportable manifests. | A report finding can be traced to observations, raw artifacts, and exact execution; tampering is detectable. |
| R2-06 | P1 | Declare the concurrency boundary. For local mode, enforce a single-writer architecture; for team/server mode, plan PostgreSQL plus a durable queue and object storage rather than stretching SQLite. | Load and crash-recovery tests prove the selected operating profile. |
| R2-07 | P1 | Consolidate web surfaces or place them behind one security boundary. Add CSRF protection to browser mutations, bounded expiring sessions, token rotation, header-only WebSocket auth where possible, rate/concurrency limits, and redacted audit logs. | Browser/API security tests cover CSRF, token leakage, expiration, brute-force/rate limits, and cross-engagement access. |
| R2-08 | P1 | Remove import-time database/module-discovery side effects and use an explicit application factory with validated configuration. | Imports are silent and side-effect free; each process receives one tested configuration object. |

### Sprint 2 decision gate

R2-01 through R2-05 are prerequisites for treating PurpleSploit as a system of record or producing client-defensible evidence. R2-06 and R2-07 are prerequisites for multi-user/server positioning.

## 7. Review Sprint 3 — Capability strategy and methodology coverage

### Objective

Decide what PurpleSploit should orchestrate, measure technique coverage honestly, and expand only through safe, testable adapters.

### Current capability assessment

| Capability area | Current assessment | Modern/useful judgment |
|---|---|---|
| Network discovery and service enumeration | Nmap-centered with parser/database support and multiple wrapper modules | **Useful and appropriate**, but duplicated operations and async result handling weaken orchestration. Add explicit IPv6/UDP/rate profiles and version-tested parsing rather than new wrappers. |
| Windows/AD/SMB | Broad NetExec/Impacket/SMB operation catalog | **Core strength**, assuming supported external versions. Needs lab validation, stable adapter IDs, lockout/scope controls, and stronger identity/relationship modeling. |
| Web discovery/testing | HTTPX, Feroxbuster, Wfuzz, WPScan, SQLMap, Nuclei wrappers | **Useful tool selection**, but it is a collection of wrappers rather than a coherent WSTG/API test workflow. Manual test evidence and API-specific coverage are thin. |
| OSINT | crt.sh, DNSDumpster, Shodan | **Useful baseline**, but provenance, rate limits, provider terms, confidence, and passive-scope semantics need to be first-class. |
| Deployment, scripts, pivoting, C2 | Script deployment and Ligolo-oriented code | **High risk / incomplete**; insecure SSH defaults, weak exit-state handling, cleanup gaps, and limited C2 safety policy require repair. |
| Workflow and auto-enum | Templates and rules exist | **Good concept, currently broken in practice** due contract, naming, state, and result-shape failures. |
| Credential spraying | Multi-protocol interface | **Potentially useful, currently unsafe/incomplete**; exposed protocol breadth exceeds implemented adapters and policy detection is a stub. |
| AI automation/methodology | Provider integrations plus deterministic recommendations | **Experimental**. Several “AI” operations are rules or placeholders; generated recommendations reference modules that do not exist. |
| Distributed execution | Task/transport primitives | **Skeleton only**. Agent/coordinator classes and corresponding API/WS endpoints are absent. |
| Reporting and graph | JSON/HTML/PDF/XLSX/Markdown and JSON/Cytoscape/DOT graph | **Promising foundation**, especially graph export, but models and machine schemas are inconsistent. |
| Plugins and integrations | Marketplace skeleton and Jira/GitHub/Slack/Teams/SIEM clients | **Useful direction, not production-ready**; plugin loading/trust and integration secret persistence are incomplete. |

### Pentest lifecycle gaps

The project currently emphasizes command execution more than assessment lifecycle. The largest conceptual omissions are:

- pre-engagement authorization, statement of work, rules of engagement, safe windows, exclusions, emergency contacts, and data-handling policy;
- canonical asset and identity inventory with confidence and ownership;
- versioned test plan/checklist and coverage evidence, including explicit “not tested” and “not applicable” states;
- manual observations, screenshots, notes, hypotheses, validation, peer/QA review, and false-positive disposition;
- evidence lineage, reproducibility, cleanup verification, and operator audit;
- remediation ownership, client acceptance, retesting, regression comparison, and closeout/debrief;
- collaboration, conflict control, permissions, and engagement isolation for teams.

### Technique-domain gaps

Coverage is strongest in classic internal Windows/network testing. Expansion candidates include cloud control planes (AWS/Azure/GCP), Entra ID and SaaS identity, containers/Kubernetes, OAuth/OIDC/SAML/MFA, API authorization/business logic, GraphQL/gRPC/WebSockets, Linux/Unix privilege escalation, non-MSSQL databases, TLS/configuration review, source/SAST/SCA/secrets/IaC, and—only if product strategy demands them—mobile, wireless, and thick-client evidence workflows.

Breadth should not be mistaken for quality. Each new domain creates tool-version, authorization, rate-limit, evidence, cleanup, and training obligations.

### Recommendations

| ID | Priority | Recommendation | Acceptance evidence |
|---|---|---|---|
| R3-01 | P1 | Establish a versioned coverage matrix mapping supported activities to NIST SP 800-115, OWASP WSTG, OWASP ASVS, OWASP API Security Top 10, PTES or the chosen pentest methodology, and MITRE ATT&CK where applicable. Include tested/not-tested/not-applicable evidence states. | Every claim in docs/UI is generated from the matrix and links to executable checks or manual procedures. |
| R3-02 | P1 | Adopt the orchestration/evidence-platform strategy explicitly. Treat specialist tools as adapters and reserve native code for policy, planning, normalization, correlation, evidence, workflow, and reporting. | Product charter and architecture decision record define what PurpleSploit will and will not replace. |
| R3-03 | P1 | Require declarative module manifests: stable IDs, version compatibility, inputs/outputs, capability/standard mappings, risk/side effects, privileges, network behavior, timeouts, concurrency, idempotency, cleanup, and evidence types. | CI validates all manifests and built-in plans without importing unsafe execution code. |
| R3-04 | P2 | Choose expansion domains from user demand and lab/support capacity. Recommended first sequence: modern identity/API testing, cloud/Kubernetes inventory and configuration evidence, then Linux/database depth. | Each approved domain has a threat model, owned lab, expert review, fixture corpus, and maintenance owner before implementation. |
| R3-05 | P1 | Consolidate duplicated Nmap and SMB wrappers behind profiles/operations rather than separate near-identical modules. | Lower module count without lost capability; a single adapter owns parsing/version behavior per backend. |
| R3-06 | P1 | Build owned lab scenarios and golden raw-output fixtures across the supported external-tool matrix. Test parsers against version changes and localized/partial/malformed output. | CI and scheduled lab runs detect adapter drift before release. |
| R3-07 | P2 | Add manual-test and QA workflows as first-class capabilities, not just more automation. | Operators can record hypotheses, steps, evidence, validation, reviewer decisions, cleanup, and retest status without leaving the engagement model. |

### Standards reference point

Use current primary sources as the coverage baseline: [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final), [OWASP Web Security Testing Guide](https://owasp.org/projects/web-security-testing-guide), [OWASP ASVS](https://asvs.owasp.org/), [OWASP API Security Top 10](https://api-security.owasp.org/editions/2023/en/0x04-release-notes/), and [MITRE ATT&CK data/tools](https://attack.mitre.org/resources/attack-data-and-tools/). Pin the exact standard version in each engagement rather than silently following a moving “latest.”

## 8. Review Sprint 4 — Automation, extensibility, distributed operation, and AI

### Objective

Make advanced features truthful, isolated, and safe enough to build upon—or deliberately remove them from supported claims.

### Findings

#### Plugins

Plugin archives receive good path/decompression checks, but the trust model is incomplete. The repository index is mutable; checksums are optional and can come from the same unsigned source; manifest signature fields are not verified; dependencies are installed into the current interpreter; installation can be marked complete after dependency-install failure; and the apparent module-loader path does not actually import/register plugin modules with the framework. Uninstall trusts a persisted install path without a final containment check.

#### Distributed execution

Only task and transport primitives are present. Package imports tolerate missing agent/coordinator classes, and the HTTP/WS endpoints expected by transports do not exist in the API. The installed modern `websockets` API uses `additional_headers`, while transport passes `extra_headers`, producing a runtime `TypeError`. Task delivery also needs idempotency, replay/reconnect, lease/heartbeat, capability negotiation, artifact transfer, cancellation, and authentication semantics before hostile-network use.

#### AI

The default model identifiers are stale or questionable, and OpenAI calls use the older chat-completions shape. That API can still be supported, but current official guidance recommends the Responses API for new implementations. More importantly:

- “Analyze Context” is deterministic rules and ignores supplied user context;
- “Automate Workflow” reports success for an explicitly unimplemented action;
- prompt context can include target and recent command history, which incomplete redaction may expose;
- database context calls nonexistent methods and silently returns empty context;
- recommendations and attack paths name modules that are not installed;
- “probabilities” are hard-coded heuristics and should not be presented as measured confidence.

AI should assist planning and summarization over typed data. It should not be an alternate unvalidated execution plane.

#### Integrations

Integration code is a useful start, but configuration persistence removes some token/key fields while saving webhook URLs and password-like values plaintext. Removed fields cannot be restored automatically, so integrations may fail after restart. Sync operations also need idempotency keys, remote-object mapping, provenance, retry/dead-letter policy, and conflict semantics.

#### CLI structure

`ui/commands.py` is approximately 5,705 physical lines. A separate `command_mixins` tree duplicates thousands of lines, but the primary command handler does not use it. This is architectural drift rather than active modularization. The `analysis` package is empty.

### Recommendations

| ID | Priority | Recommendation | Acceptance evidence |
|---|---|---|---|
| R4-01 | P1 | Redesign plugins around signed immutable releases, verified digests from an independent trust root, explicit permissions, isolated environments/processes, dependency lockfiles, compatibility checks, real framework registration, and safe uninstall containment. | A malicious/path-tampered plugin cannot escape its root or run before approval; a valid sample plugin installs, registers, executes, disables, and uninstalls transactionally. |
| R4-02 | P1 | Choose whether distributed operation is a supported feature. If yes, specify and version its protocol, implement coordinator/agent/API endpoints, mutual authentication, scoped capabilities, durable task state, leases, replay/idempotency, artifact hashing, quotas, and compatibility tests. If no, remove it from feature claims. | End-to-end reconnect/cancel/duplicate/crash tests pass across supported dependency versions. |
| R4-03 | P1 | Reframe AI as advisory. Require redacted, minimized, consented context; structured schema output; real module/operation inventory grounding; provider/version configuration; prompt-injection boundaries; cost/time limits; audit; and human approval before any execution. | AI cannot invent executable module IDs, receive secrets by default, or convert text directly into an unreviewed high-risk action. |
| R4-04 | P1 | Make AI operations truthful: fail unsupported placeholders, remove fabricated confidence labels, fix data retrieval through the canonical model, and migrate new OpenAI work to the Responses API while retaining a tested compatibility adapter if needed. | Contract tests verify provider payload, schema validation, redaction, failure states, and current module references. |
| R4-05 | P1 | Store integration secret references in the secret provider; add idempotent sync mappings, request/retry limits, delivery audit, conflict policy, and dry-run. | Restarted integrations work without plaintext secrets; duplicate retries do not duplicate tickets/findings. |
| R4-06 | P1 | Replace the command monolith and unused duplicate mixins with a declarative command registry over application services. Keep UI code free of business logic. | CLI, API, and web reuse the same services; command registration and permission/scope metadata are testable in isolation. |

Official OpenAI migration guidance used for R4-04: [Migrate to the Responses API](https://developers.openai.com/api/docs/guides/migrate-to-responses).

## 9. Review Sprint 5 — Interoperability, reporting, and visualization

### Objective

Make PurpleSploit data portable, lossless, useful to security ecosystems, and easy to understand at engagement scale.

### Findings

#### Existing strengths

- Nmap XML import/parsing provides a practical interoperability foundation.
- Nuclei and other wrappers expose raw or structured output options.
- HTML, PDF, XLSX, Markdown, and JSON meet common human-delivery needs.
- The attack graph exports JSON, Cytoscape.js-compatible data, and Graphviz DOT.
- Jira, GitHub, Slack, Teams, and SIEM integration clients provide useful design seeds.

#### Principal gaps

1. JSON output is project-specific and lacks a schema version and published JSON Schema.
2. Report conversions are lossy and can generate an empty report unless findings are supplied through a particular path.
3. There is no portable engagement/evidence bundle with hashes and a manifest.
4. Common interchange targets such as SARIF and DefectDojo Generic Findings Import are absent. CSV is also missing for simple analyst workflows.
5. ATT&CK mappings cannot be exported as Navigator layers or STIX 2.1 bundles. Graph interoperability with BloodHound-style ecosystems is not defined.
6. XLSX cells are written without neutralizing values beginning with `=`, `+`, `-`, or `@`, creating formula-injection risk when untrusted tool output enters a workbook.
7. PDF temporary HTML cleanup is not protected by `finally`, so sensitive intermediate material may remain on failure.
8. Current visualizations do not yet present engagement coverage, evidence lineage, asset/service change, attack-path rationale, remediation aging, retest status, or data-quality gaps from one canonical store.

### Interoperability priority tiers

| Tier | Formats/systems | Rationale |
|---|---|---|
| 1 | Versioned PurpleSploit JSON, JSON Schema, CSV, SARIF 2.1, DefectDojo Generic Findings Import | Establish a stable contract and integrate with common developer/security finding pipelines. |
| 2 | ATT&CK Navigator layer, STIX 2.1, graph CSV/JSON suitable for BloodHound-style import, SIEM event schema | Support purple-team mapping, graph analysis, and security operations. |
| 3 | Dradis/Faraday/native ticketing variants and other platform-specific formats | Add only from customer demand; keep these as adapters over the canonical schema. |

### Recommendations

| ID | Priority | Recommendation | Acceptance evidence |
|---|---|---|---|
| R5-01 | P0 | Publish a versioned canonical JSON model and JSON Schema for engagements, assets, identities, executions, observations, findings, evidence, remediation, and retests. Define compatibility and migrations. | Every export validates; old fixtures migrate; unknown fields and version errors have documented behavior. |
| R5-02 | P0 | Make all report generation consume the canonical model directly. Preserve evidence, proof, status, notes, references, mappings, timestamps, assignment, provenance, and raw-artifact links. Remove empty-default behavior. | Round-trip and golden-report tests prove no field loss across CLI/API/web routes. |
| R5-03 | P1 | Implement Tier 1 exports/imports with strict schema validation and source IDs. Start with CSV, SARIF 2.1, and DefectDojo Generic Findings Import. | Round-trip fixtures and validation against consumer schemas pass; duplicates remain idempotent. |
| R5-04 | P2 | Implement Tier 2 ATT&CK Navigator/STIX and graph adapters after canonical identity/relationship models exist. | Exported layers/bundles open in standard consumers and retain technique/evidence provenance. |
| R5-05 | P1 | Add a portable evidence bundle: canonical JSON, report outputs, referenced artifacts, hashes, manifest, tool/version inventory, and optional signature. | Offline verification detects omission or tampering and resolves every report reference. |
| R5-06 | P1 | Harden renderers: neutralize spreadsheet formulas, sanitize links/content, make PDF temp cleanup unconditional, and set safe file modes. | Malicious fixture corpus produces inert XLSX/HTML/PDF output with no leaked temp files. |
| R5-07 | P1 | Build dashboards from the canonical store for scope/coverage, asset-service topology, ATT&CK coverage, attack paths with evidence, finding aging/severity, remediation/retest, and data quality. | Every visual element drills down to source observations/evidence and distinguishes observed, inferred, and proposed relationships. |
| R5-08 | P1 | Treat interop as tested code: schema fixtures, consumer validation, import/export round trips, backward compatibility, and golden visual/report snapshots. | Release gate prevents undocumented schema or rendering drift. |

Use the official [MITRE ATT&CK STIX/Navigator resources](https://attack.mitre.org/resources/attack-data-and-tools/) and [OASIS SARIF 2.1 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) as normative references.

## 10. Review Sprint 6 — Product consolidation, documentation, and scale

### Objective

Turn the repaired foundation into a coherent supported product with explicit deployment profiles.

### Findings

- Feature and architecture documentation claim tools/modules that are not present, including several post-exploitation and directory-analysis capabilities.
- The static SPA, Jinja dashboard, CLI, and API expose overlapping but inconsistent slices of functionality. The reports page is incomplete.
- Current SQLite/session/API behavior is suitable for local use only, while distributed and team-oriented language implies a more demanding operating model.
- Module counts are inflated by near-identical wrapper modules, making breadth look greater than independently maintained capability.
- The lack of generated inventories lets operations, templates, documentation, AI recommendations, and UI labels drift independently.

### Recommendations

| ID | Priority | Recommendation | Acceptance evidence |
|---|---|---|---|
| R6-01 | P1 | Generate capability inventory, operation reference, risk labels, external-tool requirements, and OpenAPI/client documentation from validated manifests. | No documented module/operation can be absent at runtime; CI checks examples. |
| R6-02 | P1 | Consolidate the web experiences around the same application services and security boundary. Choose a primary interaction model; do not maintain two divergent dashboards. | CLI/API/web produce equivalent engagement state and honor identical authorization/scope policy. |
| R6-03 | P1 | Define explicit deployment profiles: local single-user first; team/server only after RBAC, TLS, PostgreSQL, durable jobs, object storage, audit, backup/restore, and tenancy controls are complete. | Each profile has a threat model, topology, support matrix, hardening guide, and deployment tests. |
| R6-04 | P1 | Add structured, redacted observability: audit events, execution correlation IDs, metrics, health/readiness, queue state, adapter/tool versions, and support bundles. | Operators can diagnose a failed run without exposing secrets or raw client data unnecessarily. |
| R6-05 | P1 | Add a release checklist covering migrations, schema compatibility, version consistency, license, SBOM/provenance, dependency audit, lab compatibility, docs, backup/restore, and rollback. | A reproducible signed release cannot be cut without all required evidence. |

## 11. Recommended sequence and dependencies

The review sprints are ordered by risk, not feature visibility:

```text
Sprint 0: release truth and gates
        ↓
Sprint 1: one safe execution contract
        ↓
Sprint 2: one engagement/evidence model
        ├──────────────→ Sprint 3: measured capability expansion
        ├──────────────→ Sprint 4: plugins/distributed/AI/integrations
        └──────────────→ Sprint 5: portable interop and visualization
                                ↓
                    Sprint 6: consolidated supported product
```

Do not implement major new scanners before Sprint 1. Do not build more exporters or dashboards before the canonical model in Sprint 2, except for short-lived prototypes. Do not enable third-party plugins, remote agents, or autonomous AI execution before their trust boundaries are specified and tested.

## 12. Sign-off bundles for implementation planning

These bundles provide manageable approval decisions. Individual recommendation IDs can be approved, rejected, or revised within a bundle.

### Bundle A — Stabilize the product foundation

**Recommended approval: immediate.**

Includes R0-01 through R0-07, R1-01 through R1-08, and R2-01 through R2-05. This resolves release truth, runtime contract failures, safety controls, data authority, engagement isolation, secrets, and evidence provenance.

### Bundle B — Make the platform operationally supportable

Includes R2-06 through R2-08, R3-01 through R3-03, R3-05 through R3-07, and R6-01 through R6-05. This turns the repaired foundation into an explicit local product with a credible route to team/server use.

### Bundle C — Expand advanced capabilities

Includes R3-04 and R4-01 through R4-06. Approve individual tracks separately: plugins, distributed agents, AI, integrations, CLI restructuring, and selected new technique domains have different risk and staffing needs.

### Bundle D — Interoperability and visualization

Includes R5-01 through R5-08. R5-01 and R5-02 belong with the foundation if external consumers are already using current JSON/report output; the remaining adapters can be prioritized by actual customer toolchain.

## 13. Immediate P0 recommendation list

For convenience, the release/trust blockers are:

1. **R0-01:** resolve license and package-artifact contradiction.
2. **R1-01:** establish one module/operation execution contract.
3. **R1-02:** make workflows validate and fail truthfully.
4. **R1-03:** repair auto-enumeration operation, safety, and observation handling.
5. **R1-04:** restrict and repair credential spraying; eliminate ambiguous simulation.
6. **R1-06:** enforce engagement scope and rules of engagement at dispatch.
7. **R1-08:** add real vertical contract/lab tests.
8. **R2-01:** choose one transactional data authority.
9. **R2-02:** enforce engagement isolation.
10. **R2-03:** unify the domain/finding model.
11. **R2-04:** use secret references and complete redaction/retention controls.
12. **R5-01/R5-02:** establish the canonical interchange/report model if current output has external consumers.

## 14. Final judgment

PurpleSploit should continue, but its next implementation cycle should be a consolidation cycle. The test volume, module abstractions, recent security hardening, Windows/network integrations, report generators, and attack graph are enough to justify the platform. The fastest route to a genuinely strong product is to make its core claims true end-to-end before adding more techniques.

The target architecture should have five clear layers:

1. **Policy and engagement:** authorization, scope, ROE, identity, approvals, budgets.
2. **Plan and execution:** typed plans and adapters with explicit risk and lifecycle.
3. **Canonical observations and evidence:** one transactional model with provenance.
4. **Correlation and decision support:** findings, attack paths, methodology coverage, optional AI advice.
5. **Presentation and interoperability:** CLI/API/web, reports, schemas, exports, integrations.

That structure preserves the best part of the current concept—one coherent operator workspace—while making it safer, more modular, more scalable, easier to test, and far more useful to the rest of a security toolchain.
