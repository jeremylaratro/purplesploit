# PLAN-002 — aranum ↔ purplesploit integration

**Status:** active. Written 28OCT2026 (the effort began 26OCT2026; this doc is the
retro-captured plan of record — earlier sprints were driven from per-sprint briefs).
**Planner/reviewer:** Opus. **Implementer:** codex `gpt-5.6-sol` effort `high`, to a
`.interop/<sprint>-codex-prompt-N.md` brief (codex leaves work uncommitted; Opus
reviews, runs the host gate, commits/PRs/merges; 2-round fix cap).

## Goal

Make **aranum** purplesploit's breadth-first enumeration engine, and make purplesploit
the operator console that consumes aranum's results — a bounded producer/consumer
integration over a frozen file contract, not a code merge. aranum enumerates and
emits a bundle; purplesploit imports it, derives analysis (reuse, effective access,
posture), and orchestrates credentialed campaigns that drive aranum.

This is **authorized-testing tooling, unsafe by design.** The integration adds
*capability and accounting*, never offensive playbooks. No sprint adds safety lockdowns
to the tools themselves; every sprint honors aranum's OPSEC defaults (enumeration-only
unless the operator opts in) and purplesploit's attribution/commit policy.

## Contract (frozen, produced by aranum A1–A6)

A **bundle** = a directory with `bundle-manifest.json` (per-file `{path,schema,sha256}`
+ `status` ∈ complete|partial|failed|interrupted|stale|unknown), `findings.json`
(findings-2 envelope: findings[], `summary.coverage[]`, `per_host[]`, run-pinned `kb`
subset, `auth_outcomes[]`), optional `inventory.json`/`posture.json`, rendered
`report.{md,html}` (aranum-authored placeholders), and per-stage records. Seven
digest-pinned JSON schemas are vendored at `python/purplesploit/schemas/aranum/`.
`auth_context` = `{account_label, scope∈local|domain, scope_basis, domain, local_host,
auth_method∈password|hash|key|kerberos|anonymous|null-session, invocation{…}}`.
`auth_outcome` = `{host, transport, outcome∈success|failure|lockout|error|anonymous|
null-session, auth_context}`.

## Sprint ledger

| Sprint | Scope | State |
|---|---|---|
| aranum A1–A6 | producer: stage records, manifest, findings-2, SARIF, inline KB, declared auth-scope, auth_outcomes+AUTH_LOCKOUT, interop fixtures (fx-1…fx-5, fx-2-rerun) | **MERGED** (aranum main) |
| P1 | purplesploit auth-context + scoped credential identity | **MERGED** #115 |
| P2b | manifest-first forgiving importer v2 (digest verify, schema validation, KB enrichment, auth_context, auth_outcomes→observations) | **MERGED** #116 |
| P3 | `recon/aranum` backend module + auto-enum coalescing (owned baselines) | **MERGED** #117 |
| P4 | account-derived analysis + Linux posture (derivation layer) | **MERGED** #118 |
| P6 | credential-reuse campaign (orchestration) | **MERGED** #119 |
| P5 | interchange / SARIF fallback (independent) | planned (this doc) |

AC-01..AC-20 (acceptance harness `python/tests/integration/interop/
test_aranum_acceptance.py`) all pass as of P3. Acceptance IDs are assigned in
**landing order** so the harness's generated `AC_IDS` stays contiguous: P4 (lands
first) adds AC-21..AC-24 (derivation); P6 adds AC-25..AC-28 (campaign). P5 adds
AC-29.. as needed.

---

## P4 — account-derived analysis + Linux posture

**Altitude:** P4 is a pure, deterministic **derivation layer** over data the P2b
importer already produces. It runs on an imported bundle; it performs no network
action and drives no tool. It turns observations into findings and graph structure.

### Capability
1. **Account reuse.** From the imported `auth_outcome` observations, a single
   `account_label` with `outcome == success` on **≥2 distinct hosts** is a
   **credential-reuse finding**. `scope == local` → "local-account reuse across hosts"
   (the genuine reuse signal). `scope == domain` → "domain account effective on
   multiple hosts" (effective-access, labeled distinctly — a domain credential working
   on many hosts is expected, not reuse). Severity/label follow the KB; the finding
   lists the hosts and the transport(s).
2. **Effective access / lateral candidates.** Feed `auth_outcome` successes into the
   existing `core/attack_graph.py` as credential→host `AUTHENTICATES_TO` edges, then
   `derive_attack_paths`/`find_lateral_paths` to surface candidate lateral routes. Honor
   the existing honesty caveat ("possession on source host is unproven") — these are
   candidates, not proven paths.
3. **Linux host posture.** Consume aranum's host posture (`posture.json` + findings
   `per_host`) into purplesploit findings/observations for Linux hosts, mirroring the
   KB-enriched finding shape (description/impact/remediation/validation/auth_context)
   that P2b already produces for service findings.
4. **Lockout visibility.** `outcome == lockout` observations surface as a distinct
   finding/observation (an account was locked during enumeration) so the operator sees
   it — this is also the signal P6's accounting consumes.

### Where it plugs in
A derivation entrypoint (e.g. `interop/derive.py` or an extension of the importer
result path) that takes the `AranumBundle`/`ImportResult` and returns additional
`Finding`s + graph nodes/edges. Build on `attack_graph.ingest_observations` +
`derive_attack_paths`; do not reinvent graph logic. Derivation is **forgiving** (never
raises; missing signals → no derived finding, not an error) and **deterministic**
(stable ordering, stable finding `logical_id`s).

### Acceptance (new AC-21..AC-24)
- **AC-21 reuse-local:** importing `fx-5` derives exactly one local-account-reuse
  finding for `svc-local` naming hosts 10.0.0.1 and 10.0.0.2 (both `success`), and
  does **not** flag 10.0.0.3 (lockout) as a reuse host.
- **AC-22 effective-domain:** `fx-5`'s `dom-user` (`scope=domain`, success on
  10.0.0.4) derives an effective-on-host finding labeled distinctly from local reuse
  (not a "reuse" finding).
- **AC-23 posture:** a bundle with Linux `per_host`/`posture` (fx-2/fx-3) derives one
  posture finding per host posture-check, each carrying a non-empty remediation and a
  non-empty validation/test — sourced from the run-pinned KB when the check id resolves
  in `kb.checks`, otherwise from a deterministic fallback (fx-2's `LIN-SUDO`/`WIN-SMB`
  are **not** in the fixture KB, so they exercise the fallback path). A bundle with no
  posture derives zero posture findings (no crash). Requires `AranumBundle` to expose
  the run-pinned `kb` subset (small importer addition).
- **AC-24 lockout-surfaced + graph:** `fx-5`'s lockout surfaces as its own
  finding/observation, and the derived graph contains credential→host
  `AUTHENTICATES_TO` edges for the successes (reuse candidate path present), with the
  "unproven possession" caveat intact.

---

## P6 — credential-reuse campaign (orchestration)

**Altitude / ownership (owner decision, standing):** purplesploit **drives** —
it selects the credential corpus, the target hosts, the scope, and the transports, and
it does **lockout accounting**; aranum **executes** each credentialed test via its
existing dispatchers / `recon/aranum` handoff (P3). P4 derives the findings from the
collected outcomes. purplesploit adds **no spray/guessing logic of its own** — it
orchestrates one declared credentialed test per (credential, host, transport) that the
operator authorized, exactly as the existing access layer already runs, and records
the outcome. This is capability + accounting, not an offensive playbook.

### Capability
1. **Corpus + scope selection.** The operator supplies a credential corpus (from the
   session credential store) and a host set (from inventory/targets), a scope
   (local/domain), and a transport preference list (the P3 owned baselines /
   local-enum transports). The campaign enumerates the (credential, host, transport)
   matrix it will test — deterministically, no implicit expansion.
2. **Lockout accounting.** Before/while testing, the campaign tracks per-account
   attempt counts against a configurable lockout threshold and a cooldown, and
   **stops testing an account before it would cross the threshold** (and immediately on
   an observed `lockout` outcome from aranum). Accounting is the core safety-relevant
   feature and must be deterministic and testable.
3. **Execution handoff.** For each matrix cell the campaign hands the credentialed
   test to aranum through the P3 `recon/aranum` path (or the documented local-enum
   transport), collects the resulting bundle's `auth_outcomes`, and feeds them to P4.
4. **Derivation.** Multi-host successes → P4 reuse/effective-access findings; lockouts
   → P4 lockout findings + accounting state.

### Where it plugs in
A campaign orchestrator (e.g. `core/reuse_campaign.py` or a `modules/` operation) that
composes: session credential store → matrix builder → lockout accountant → P3 aranum
handoff (mockable) → P4 derivation. No new transport code — reuse P3/local-enum.

### Acceptance (new AC-25..AC-28; aranum execution mocked, no network/sockets)
- **AC-25 matrix + ownership:** given a corpus of 2 credentials × 3 hosts × a
  transport list, the campaign builds exactly the declared matrix (no implicit
  expansion) and routes execution through `recon/aranum` (asserted via a mocked
  handoff), honoring `ARANUM_OWNED_BASELINES` transport ownership.
- **AC-26 lockout accounting:** with a lockout threshold of N, an account that has
  reached N-1 prior failures is **not** tested again (campaign skips it with a recorded
  reason); an observed `lockout` outcome halts further tests for that account for the
  cooldown. Assert the exact attempt counts and the stop decision.
- **AC-27 scope discipline:** a `local`-scope campaign tests credentials as local
  accounts per host (no domain argument); a `domain`-scope campaign stamps the domain —
  assert the scope flows into the aranum invocation and into the derived findings'
  `auth_context` (zero inference; declared only).
- **AC-28 end-to-end derivation:** a mocked campaign whose handoff returns fx-5-shaped
  `auth_outcomes` derives (via P4) the local-reuse finding across the success hosts and
  the lockout finding, and records a campaign summary (tested/skipped/locked counts).

---

## P5 — interchange / SARIF fallback (independent)

Make purplesploit's import robust when a producer emits only SARIF or a partial
interchange (no full bundle): map aranum SARIF (ruleId=rule_id, rules[] from KB) into
the same `Finding` shape, degrade forgivingly when the inline KB is absent. Independent
of P4/P6; can land any time. Acceptance: AC-29 (SARIF-only import yields findings with
KB enrichment when present, and without when absent, never raising).

## Sequencing

P4 → P6 (P6 feeds P4; P4's derivation must exist first). P5 independent. Then a full
**tmux manual bug/quirk walkthrough** of purplesploit (owner directive). Cut the next
minor release at effort end.

## Invariants (every sprint)

- codex implements to brief, uncommitted; Opus reviews + runs the **host** gate (venv
  `build/venv-plan002`, `pip install -e python/` from the current checkout first) +
  commits/PRs/merges. Independent review ≠ author model.
- purplesploit identity `jeremylaratro <62393443+jeremylaratro@users.noreply.github.com>`,
  `core.hooksPath .githooks`, hooks ENFORCED, never `--no-verify`, **never** a Claude
  attribution trailer / session link / "Generated with" line (global + repo policy).
- Conventional commits (`feat(interop):` / `test(interop):`); interop sprints do not
  touch CHANGELOG (updated at version-cut).
- Forgiving-by-default (never lose a finding); derivations deterministic; no fixture is
  aranum-authored-artifact regenerated by purplesploit.
