## TURN 11 — codex — 26OCT2026

### 1. Disposition

#### P1

- **Step 0 — ACCEPT.** Commit deterministic serialized outputs for every listed importer/fixture under `python/tests/fixtures/interop/pre-p1/`, with a digest manifest, after establishing the committed CWP base but before changing P1 behavior. The required fixture families currently exist under `python/tests/fixtures/{containers,cloud,identity,nmap,aranum,canonical}`. *(measured; inferred placement)*

- **Identity stability — ACCEPT.** Reconstruct the exact legacy `attributes` dictionary as the final identity element; merely appending promoted fields elsewhere would change the UUID input currently hashed at `core/execution.py:105-109`. Preserve explicitly supplied IDs, retain old-placement read compatibility, and pin `aranum/inventory-unversioned;adapter=1` from `interop/aranum.py:21` until a migration exists. *(measured; inferred)*

- **Credential stores/null-scope rule — ACCEPT.** Required implementation consequence: adding columns alone is insufficient. Runtime duplicate detection is still `username+domain` at `core/session.py:387-391`; ORM `name` remains the primary key at `models/database.py:38`, and upsert still matches `name` or `username+domain` at `models/database.py:429-446`. P1 must make `account_ref` the stable lookup key, use null-safe tuple matching, give null-scope records a host-specific `local_host`, and stop name-based upsert from collapsing distinct identities. `name` may remain a display alias. *(measured; inferred)*

- **Tests and regression manifest — ACCEPT.** AC-14 must exercise two same-username local/null-scope records on different hosts through all three stores; AC-15 covers request/result/observation serialization through distributed and assessment paths; AC-16 proves no `DOMAIN` inference; AC-19 consumes the Step-0 corpus. Capture test node ID → status at the committed P1 base before behavioral edits. *(inferred; recorded: plan §6, §10)*

#### P2a

- **Land with P1 — ACCEPT.** *(inferred)*
- **Location — ACCEPT as repository-root `python/tests/integration/interop/test_aranum_acceptance.py`.** The plan’s `tests/...` spelling is correct only relative to `python/`; `python/pytest.ini:2` sets `testpaths = tests`. *(measured)*
- **One AC-01..19 case and tri-state result — ACCEPT.** Missing fixture or unmet producer prerequisite must be recorded as inconclusive, not translated into a passing pytest result. *(inferred; recorded: plan §6)*
- **Measured baseline — ACCEPT.** Run after establishing P2a’s committed base; the absence of A1 fixture bundles makes the affected checks inconclusive by construction. *(recorded: plan §7)*
- **AC-03/AC-07 RED proofs — ACCEPT.** Execute them once FX-2 exists; before A1, record them as unavailable/inconclusive rather than claiming RED proof. *(inferred)*

#### Forward items

- **P2b manifest-first — ACCEPT in full:** `manifest.run_id` occurrence identity, optional inventory for local-only bundles, manifest-or-inventory registry detection, interrupted/unknown legacy imports, partial imports, unlisted-root-JSON diagnostics, pinned-schema validation, `logical_id`/`source_identity`, and replacement of the draft KB fixture with FX-2. The current importer requires inventory at `interop/aranum.py:124-137`, and registry detection requires it at `interop/importers.py:299`, so this is correctly deferred implementation work. *(measured; inferred)*

- **Inline KB default-on — ACCEPT**, subject to the plan’s recorded H4 flip: if the subset exceeds 10% of FX-2’s `findings.json`, use the opt-in flag and have the launcher pass it automatically. *(recorded: plan §9 A2)*

- **P3 registry/auth mapping — ACCEPT.** PurpleSploit should register the published dispatcher set and pass declared scope/account inputs; Aranum’s published per-family table remains authoritative for family-specific argv construction. Completion comes from manifest status, and rc 4 produces a partial import rather than an execution failure. *(inferred; recorded: plan §9 A3.1, §10 P3)*

### 2. P1 base and overlap

Current HEAD is `c9629949033c0b3ccdaddaf918c2f20df8f4afca`. That commit alone is **not** a usable P1 base: the uncommitted CWP1–CWP9 tree must be committed first, then P1 branches from that resulting integration-tip SHA. That future SHA does not yet exist. Branching directly from `c962994` while inheriting dirty changes would make the Step-0 and regression baselines non-reproducible. *(measured; inferred)*

There is material in-flight overlap:

| P1 path | Current state | Overlap |
|---|---:|---|
| `core/execution.py` | untracked | Direct: common CWP execution contract |
| `core/framework.py` | modified | Direct: result completion and credential synchronization |
| `core/module.py` | modified | Direct: external execution-result construction |
| `core/session.py` | clean | None currently |
| `core/database.py` | clean | None currently |
| `models/database.py` | clean | None currently |
| `api/server.py` | modified | File-level; current diff is outside credential routes, but P1 will edit the same file |
| `interop/*` | entire directory untracked | Direct: importer/provenance/Aranum paths |

`core/__init__.py`, also needed for the new contract export, is modified. *(measured: current `git status` and diffs)*

### 3. TURN 8 placements that moved

| TURN 8 placement | Current placement |
|---|---|
| `core/execution.py:33-66` — `ExecutionRequest` | `core/execution.py:33-78` |
| `core/execution.py:76-104` / field block `77-91` — `Observation` | `core/execution.py:88-116` / `89-103` |
| `core/execution.py:84` — `Observation.attributes` | `core/execution.py:96` |
| `core/execution.py:107-148` / prefix `107-131` — `ExecutionResult` | `core/execution.py:119-160` / `119-143` |
| `core/execution.py:125-131` — result provenance insertion site | `core/execution.py:137-143` |
| `core/execution.py:59-66` — request serialization | `core/execution.py:71-78` |
| `core/execution.py:99-104` — observation serialization | `core/execution.py:111-116` |
| `core/execution.py:138-148` — result serialization | `core/execution.py:150-160` |
| `core/execution.py:230-243` — normalizer carrying block | `core/execution.py:242-255` |
| `distributed/coordinator.py:81-90` | `distributed/coordinator.py:89-100` |
| `distributed/coordinator.py:152-166` | `distributed/coordinator.py:162-176` |
| `distributed/coordinator.py:186-200` | `distributed/coordinator.py:196-210` |
| `distributed/agent.py:77-99` | `distributed/agent.py:78-100` |
| `core/assessment.py:710-728` | `core/assessment.py:715-733` |
| `api/server.py:390-400` | `api/server.py:394-404` |
| `api/server.py:433-481` | `api/server.py:437-485` |

All other TURN 8 placement citations remain at their stated lines. No files were edited. *(measured)*