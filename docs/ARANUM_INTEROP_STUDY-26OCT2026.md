# Aranum interoperability study and bounded implementation contract

Date: 26 October 2026. Status: study complete; implementation proposed, no code changed.

PurpleSploit baseline: `c9629949033c0b3ccdaddaf918c2f20df8f4afca`, including the
uncommitted CWP1 automation changes inspected during this study. Aranum baseline:
`52f2fc079a78e847f185228aeb0c7c3f1b305e2f`. The earlier shared study used
`2493def`; source references below use the inspected current baseline. Recheck moving
working-tree contracts before implementation.

Provenance labels: **measured** means a local inventory/check was performed;
**recorded** means read from the cited source at these baselines; **proposed** means a
design recommendation. No live enumeration or integration implementation was performed.

## Outcome and boundaries

Use Aranum as a specialist enumeration producer and PurpleSploit as the operator-facing
orchestrator, observation consumer, and selected follow-up executor. Start with a portable
completed-output reader and an inventory seed for auto-enumeration; add a registered backend
launcher afterward. Do not merge or vendor Aranum's implementation. **Proposed; accepted as
the study direction in `interop-channel`, delegated TURN 2/4/6 and Claude TURN 5.**

Study consensus is not authorization to replace current adapters or change the schedule.
Recommend the first adapter in CWP2, host-posture expansion in CWP5, and generic interchange
in CWP7. The common execution/observation model is already planned in CWP1 but was absent
from the inspected source. Canonical migrations and authorization/safety/integrity remain
in S19–S23. **Recorded:** implementation roadmap, lines 59–80, 85–98, 128–165, 331–339;
source search for `ExecutionRequest`, `ExecutionResult`, and `Observation`.

## Current seams

| Finding | Evidence and implication |
|---|---|
| Existing generic finding loaders do not accept Aranum v2 | **Recorded:** `python/purplesploit/reporting/generator.py:236` passes source records to its reporting dataclass; `core/findings.py:527` expects a bare list, not Aranum's envelope. Add an explicit adapter. |
| Auto-enum already retains endpoint identity internally | **Recorded:** `core/auto_enum.py:692` consumes native/Nmap records; `:759` normalizes target, service, port, protocol and version; `:813` deduplicates. Preserve richer producer metadata in observations before projecting into this narrower shape. |
| Discovery and follow-up execution have a useful boundary | **Recorded:** `core/auto_enum.py:300,374,434,491`: sequential Nmap discovery precedes service rules; target-level parallelism is optional. Add an explicit seed method and skip discovery for seeded enumeration. |
| Current rules are not a dynamic discovery queue | **Recorded:** `core/auto_enum.py:434` computes applicable rules once per target. Streaming new services needs later re-planning, not just another callback. |
| Operation names must resolve to registered objects | **Recorded:** `core/auto_enum.py:614`, `core/workflow.py:915`, `core/framework.py:338`. A module path and an operation name are distinct. |
| Legacy projections lose identity or metadata | **Recorded:** `core/session.py:551` omits transport; `core/database.py:169` and `models/database.py:111` omit it; `core/attack_graph.py:331` keys service nodes as `host:port`; `core/findings.py:542` recreates reporting IDs and projects only a subset. Keep full observations and use explicit projections. |
| Shared execution context needs attention before broad parallel launch | **Recorded:** `core/framework.py:267` creates a fresh instance but also loads it into shared session context. `distributed/task.py:246` does not atomically reserve tasks. Neither is evidence of a ready nested concurrent scheduler. |

PurpleSploit paths abbreviated above are under `python/purplesploit/`. Aranum paths below
are relative to `/srv/share/dev/aranum/`.

## Accepted technical contract

The following is the proposed interoperable contract, not an already-implemented public API.

- Keep `ExecutionRequest` focused on backend, registered operation, targets, options and
  correlation identity. `ExecutionResult` carries backend/tool identity, outcome,
  observations, source result and artifact references.
- Each observation retains `source_tool`, `source_tool_version`, `source_schema`,
  `source_id`, `run_id`, `observed_at`, `kind`, `subject`, and JSON-compatible `raw` or an
  artifact reference. Preserve missing source metadata explicitly rather than inventing it.
- Endpoint subjects carry host, nullable numeric port, explicit transport, service,
  version, and available hostname/URL. Host/domain/run observations remain portless.
  Normalize service aliases without discarding the producer's original service name.
- Separate exact source-record identity `(source_tool, source_schema, source_id)`,
  endpoint identity `(host, transport, port)`, and execution/cache identity. A repeated
  bundle import creates no new records; another run preserves an observation occurrence.
  Aranum finding IDs are content-sensitive and are not guaranteed durable identities for
  a logical issue across changing evidence. **Recorded:** `network/report.py:372,1440`.
- Import all posture check statuses as observations. Take canonical FAIL/WARN findings
  from `findings.json` once; do not synthesize duplicates from `posture.json`. Preserve
  PASS, INFO, NA, ERR, scope and domain `observed_from`. Map literal triage `new` to DRAFT;
  retain other source statuses without inventing lifecycle equivalence. **Recorded:**
  `network/report.py:2135–2245`; PurpleSploit `core/findings.py:17`.
- Prefer a run-pinned inline KB subset or matching bundled KB snapshot. Preserve structured
  guidance and render it separately from observed finding text and operator-written text.
  Missing KB guidance does not prevent raw import. Resolve available evidence paths against
  the selected run root; retain unresolved/redacted references. **Recorded source behavior:**
  `network/report.py:244,2079,2864`; KB export is proposed producer work.
- Coverage retains source outcome and execution status. “Imported” is provenance, not a
  replacement for completed/clean/failed/skipped/unassessed. Use explicit discovery inventory
  for complete host/endpoint seeding; do not infer open services from aggregate counts.

## Inventory and bundle shape

Aranum already emits the following inventory shape. **Recorded:**
`aranumtoolkit/network/nmap-parse.py:342–378,478–500,604–627`.

```text
inventory.json
  summary: {hosts, hosts_up, hosts_with_open_ports, open_ports,
            unknown, categories, device_correlations}
  hosts[]: {ip, hostname, state}
  entries[]: {ip, hostname, port, proto, state, service, product,
              version, extrainfo, tunnel, categories, ...}
```

`hosts[]` preserves host state independently from open ports. Entries represent open
endpoints and retain TCP/UDP and numeric ports. Unknown fields remain in raw provenance.
This current inventory has no top-level schema version; an adapter must record its parser
revision/tool baseline rather than claim a producer-published inventory v1 schema.

For the first inventory workflow, require `inventory.json` and an explicit run root.
Optional companions are `findings.json` v2, `posture.json` v1, matching inline/bundled KB,
source scan XML, relative artifacts, `run-state.json`, and `queue.state.jsonl`.
The offline reader must work without Aranum installed. Use the producer run ID when
available; otherwise distinguish unknown source run identity from an adapter bundle
fingerprint used only for exact re-import. A future portable manifest is useful but is
not required to read current outputs. **Proposed.**

Aranum's existing Recce adapter is evidence that inventory consumption is practical;
its reader accepts `entries[]` and explicit TCP/UDP. Reuse the data contract, not its
Recce dependency or guessed endpoint attribution. **Recorded:**
`aranumtoolkit/interop/aranum_to_recce.py:239–270`.

## Coverage and overlap

**Measured:** Aranum exposes 76 dispatcher paths: 74 regular scripts and two aliases,
`enum-https.sh → enum-http.sh` and `enum-xmpp.sh → enum-jabber.sh`. This is not 76
independent implementations or proof that all dependencies are installed.

Two source-inventory matrices were exchanged, using different definitions:

| View | Definitions | Counts |
|---|---|---|
| Strict dedicated-adapter view | Direct service workflows are overlap; narrow related techniques are partial; generic web/NSE support does not count as a dedicated adapter; parity requires fixtures. | 9 overlap, 3 partial, 64 missing; no parity-proven covered category. |
| Broad building-block view | Generic web/NSE modules count as partial support; covered can be inferred from combined source capabilities. | 1 covered, 9 overlap, 52 partial, 14 missing. |

Counts are classification results, not runtime measurements. The full 76-row matrices
are preserved in the two TURN 4 blocks of `interop-channel`; do not combine their
denominators or interpret “covered” as tested equivalence. **Measured:** dispatcher and
PurpleSploit module inventories. **Proposed:** classifications and parity thresholds.

For SMB/LDAP/WinRM/SSH/MSSQL/RDP/DNS/HTTP, choose ownership per technique and requested
output. Aranum can provide batch breadth/posture; PurpleSploit retains selected direct
operations, BloodHound/ADCS, Impacket workflows, and deeper web adapters. Select one
baseline HTTP plan. Suppress duplicate Nmap/HTTPX/Nuclei or backend tasks by endpoint,
technique and profile; retain independent observations if both tools actually run.
Do not retire an existing adapter based on dispatcher counts. **Proposed.**

## First implementation slice

1. Finish CWP1's already-planned technical observation envelope. Keep this separate from
   the unfinished automation repair patch's scope and from later schema migration work.
2. Add one offline adapter, proposed location `python/purplesploit/interop/aranum.py`,
   that reads the inventory and optional companions into provenance-bearing observations.
   Project lifecycle findings into `core.findings.Finding`; keep reporting as a projection.
3. Add a public auto-enum seed method and a seeded enumeration path that skips discovery.
   Preserve endpoint protocol/port and actual operation resolution. Choose a small explicit
   follow-up plan rather than automatically running every overlapping default recipe.
4. Prove a real-framework follow-up with a fake external process and exact repeat-import
   behavior. No live targets are needed. Keep legacy projections compatible while retaining
   complete observations for later service/graph/report improvements.

This slice adds an executable inventory-to-follow-up capability. It does not depend on a
backend launcher, live streaming, automatic cache reuse, a fully consolidated datastore,
or a rewritten graph model. **Proposed.**

For the next slice, prefer one `recon/aranum` module with real registered service operations
and a coalesced `Run Selected Services` operation. Resolve alias operations to canonical
dispatchers while preserving the union of selected category endpoints; mapping an HTTPS
selection to `--only http` alone must not discard HTTPS targets. Avoid 76 duplicate Python
wrappers or one subprocess per endpoint. Aranum owns its internal service/target fan-out;
PurpleSploit owns subsequent specialist tasks.
**Proposed; compatible with current framework name/handler lookup.**

## Verification and demonstrations

Use three portable synthetic fixture bundles: network inventory, mixed Linux/Windows/AD
posture, and partial/error/redacted results. Aranum has component fixtures, but the shared
study found no combined portable bundle with complete inventory, findings, posture and
inline KB; producing that combined fixture is an Aranum-side deliverable.

| Demonstration | Acceptance |
|---|---|
| XML/inventory to follow-up | Retain zero-finding hosts, hosts without ports, IPv6, hostnames, non-default HTTP ports and same-number TCP/UDP endpoints; seed auto-enum; resolve a registered operation; execute one fake-process follow-up without another discovery scan. |
| Posture import | Preserve every host/domain check, status and observed-from relation; import canonical findings once; retain severity, scope, IDs, raw records and available KB/artifacts. |
| Repeat and fresh runs | Exact second import adds zero records; a different run keeps a new observation occurrence. Content-sensitive finding IDs do not imply cross-run logical equivalence. |
| Partial output | Missing dependencies, ERR, skipped/failed/unassessed checks and unresolved/redacted paths remain visible; none becomes assessed-clean. |
| Offline report projection | Import with Aranum absent; preserve source identity/evidence; display source findings, KB guidance, validation and operator text distinctly. |
| Efficiency | Measure subprocess count, duplicate tasks avoided, peak concurrency, wall time, time to first useful result, import time and memory on the same fixture/process simulation. |

Count completed techniques with useful normalized output and preserve per-check outcomes;
dispatcher availability is not an assessment-completion metric. Relevant component fixtures:
`aranumtoolkit/tests/test_nmap_parse.py:275`, `test_bulk_enum_report.py:59`, and
`test_host_posture.py:196`. **Recorded/proposed; no integration tests were run in this study.**

## Wrapper limitations and producer dependencies

- **Output root:** `aranum.py run` creates a repository-local session tree and copies inputs
  and reports even when `-o` selects another raw output directory. **Recorded:**
  `aranum.py:36,179–218,725–758`. Until a strict single-root mode exists, the proposed wrapper
  can invoke `auto-enum.sh -i <scan> -o <root>` and then `report.py <root>` directly. Confirm
  exact arguments and working-directory assumptions before implementation.
- **Completion/status:** source already publishes `run-state.json` schema 1 with run ID,
  mode, queue authority and service statuses, and optional `queue.state.jsonl` snapshots.
  These are rewritten snapshots, not an observation event stream. **Recorded:**
  `network/auto-enum.sh:780–840`. Exit 4 reports dispatcher failures; 2 covers several
  input/output errors and 3 parser/planner/state errors; normal completion is 0.
  **Recorded:** `auto-enum.sh:175–187,239,416,840,884–885`. Report generation can still
  produce files and exit 1 for partial diagnostics; interruption exits 130.
  **Recorded:** `network/report.py:2847,2917,2936`. A dispatcher returning 0 does not prove
  that every optional underlying tool executed. The launcher must combine process and
  machine result status, not use file existence or a single return code as assessment truth.
- **Concurrency:** defaults include `--parallel 4` and `--service-parallel 1`; target
  parallelism is exported and service dispatch runs in batches. Tool-internal workers remain
  additional fan-out. **Recorded:** `auto-enum.sh:28–35,375,740–758`. A global concurrency
  guarantee and nested scheduling policy still need explicit measurement/definition.
- **Resume/cache:** `.done` markers skip services or queued tasks. Their presence alone
  does not establish input/profile/tool freshness. **Recorded:**
  `auto-enum.sh:570–576,680–735`. Do not enable automatic resume/cache reuse in the first
  launcher. Distinguish exact import idempotency from completed-job reuse and reassessment.
- **Defaults:** preserve existing Aranum semantics and explicit operator options; describe
  them accurately. Credentialed defaults include WinRM host commands, MSSQL xp_cmdshell
  and RDP screenshot behavior. **Recorded:** `enum-winrm.sh:19`, `enum-mssql.sh:73`,
  `enum-rdp.sh:28`. Aranum recorded these as its own AR-I1/I2 findings. They do not become
  new prerequisites for PurpleSploit's offline reader.
- **Producer additions:** published findings/posture schemas and fixtures, portable combined
  bundle, run-pinned KB export, improved SARIF, and strict output-root behavior are proposed
  Aranum-owned deliverables. Current JSON snapshot ordering, source IDs linking checks to
  findings, final versus partial bundle completeness, and a stable capability/version
  manifest need explicit contract tests before broader orchestration.

## Explicit non-goals

No code implementation, live scanning, adapter retirement, Aranum vendoring, automatic
mass-launch, remote agent deployment, or schedule change occurred. The first slice does
not promise streaming, fingerprint-validated caching/resume, dynamic re-planning, graph
transport reconciliation, universal technique parity, or canonical migrations. Formal
authorization/ROE/secrets/evidence-integrity and other safety/integrity objectives remain
in the final roadmap block. Aranum-specific findings stay with its independent owner.

The append-only exchange reached a clear conclusion at Claude TURN 5 and delegated codex
TURN 6. The channel and `.interop/` capture files remain untracked; this study was saved
at the root agent's request. No commit was created.
