# PLAN-DUALMODE — Dual-mode dispatch surface + real T3 chaining (26NOV2026)

**Owner requirement (26NOV2026):** every validation technique must be executable
**both** (1) as an individual standalone job the operator dispatches after manually
identifying a precondition, **and** (2) as a composable edge the engine auto-composes
via other escalations / lateral movements. Build this **before T4**, and prove the
chain mode with a **live multi-step chain on GOAD**.

**Scope decision (26NOV2026, post plan-review):** owner chose a **lateral T3 chain now,
defer T3→DA.** The full "T3 edge reaches Domain Admin" path requires the engine's
principal-escalation model (which `states.py` calls "not yet built") plus an
engine-owned DA-equivalence authority — a large, false-DA-prone feature. This sprint
proves a **lateral** T3 composition (control → abuse → recovered lateral credential)
and the existing **front→DCSYNC→DA** chain live; full **T3→DA is a later sprint**.

Plan reviewed by Codex Sol (`docs/reviews/PLAN-DUALMODE-26NOV2026-codex-sol-plan-review.md`,
FIX-FIRST, 4 BLOCKER + 5 HIGH). Resolutions table at the end.

## Objective / acceptance

- First-class CLI for both modes over the one shared `execute()` core (no technique
  logic duplicated): `validate run <TECH>` (individual) and `validate chain`
  (auto-compose), plus the existing batch `pipeline`.
- A **T3 technique genuinely composes** into a multi-step **lateral** escalation
  (edge1's *produced* capability is what makes edge2 applicable), proven live on GOAD.
- The existing **front→DCSYNC→DA** chain proven live, on a **repaired** DCSYNC terminal.
- **Integrity:** the engine never claims an escalation it did not produce (H5); a
  lateral chain never reaches `S_DA`; DCSYNC proves DA only on real krbtgt-replication
  evidence; no recovered secret ever reaches a receipt/report/error/note.

## Current state (verified 26NOV2026)

- Executor core already dual-mode (`run()`/`run_composable()` wrap one `execute()`,
  base.py:544/555). `ChainEngine`/`da_in_minutes` work for N1 front→DCSYNC (unit-tested).
- Gap A: no `validate run`. Gap B: no `validate chain` entry. Gap C: T3 edges don't
  multi-step-chain — `produced()` emits CAP_NONE principal states that `_run_one`
  discards; `search()` is generic-only; principal-binding is "not yet built."
- **Pre-existing bug (BLOCKER 4, verified):** `dcsync.py` `_RE_DCSYNC_KRBTGT` accepts
  the bare banner `Dumping Domain Credentials` → a denied/exit-1/no-secret run reads as
  a proved krbtgt dump.

## Sprints

### S1 — Dual-mode dispatch CLI (pipeline / run / chain)

Restructure `cli.py` into **subcommands** on a shared parent parser (domain/dc-ip/auth/
output/timeout/allow-destructive/score-proof/proof-truth/host-alias):

- `pipeline` (default, backward-compatible) → today's `ValidationOrchestrator.run()`.
- `run <TECHNIQUE>` → individual dispatch. **Technique-specific input adapter (H7):** a
  per-technique map from `--param k=v` (repeatable) + `--target` to the `finding.entity`
  fields that technique's `param_specs`/`target_identity` actually require (ADD-MEMBER:
  `group`,`member`; TARGETED-KERBEROAST: `victim`,`spn`; WRITE-DACL/OWNER: `target`,
  `trustee`[,`rights`]; GENERIC-ALL: `target`,`pivot`; FORCE-CHANGE: `victim`; DCSYNC:
  `dc_host`). Missing required params → a clear non-zero error listing them, **never** a
  silent partial finding. Then `get_executor(TECH).run(ctx, finding, overrides)` → emit
  the `proof.v1` receipt; optional score.
- `chain` → `--goal <state>` (default `S_DA`), `--allow-crack`, `--allow-destructive`,
  `--map TECH=target` (repeatable) → `finding_for(edge)` resolves each edge's finding via
  the **same** per-technique adapter (H7); explicit DCSYNC DC-finding construction. →
  `da_in_minutes(base_ctx, finding_for, goal, …)` → emit the `ChainReport`.
- **Secret-safe output (H8):** `run`/`chain` must emit only payload-free public error
  codes; exception text is captured to a private field and replaced in `errors`/`note`
  with a code. A serialized-receipt/report secret-sentinel test gates this.

### S1b — Repair the DCSYNC terminal (BLOCKER 4)

`terminal_fact.ok` for DCSYNC requires **presence-only evidence of actual krbtgt
replication from the current invocation** — a `krbtgt:<rid>` / NT-hash-shaped
replication line — **not** the `Dumping Domain Credentials` banner (drop the banner and
"Kerberos keys grabbed" as sufficient markers). A denied/partial run → `ok=False`,
`complete=False`. RED proof: the banner-only + access-denied transcript scores
not-proved. (Needed for the front→DCSYNC live proof to be trustworthy.)

### S2 — Lateral T3 chain enablement (engine) — NOT DA

Make **WRITE-DACL (grant control over X) → GENERIC-ALL (abuse it, recover X's
credential) → `cred_for(X)`** a real, *found*, *escalation* path to a **lateral** goal
(`cred_for(X)`), with these invariants (each RED-provable):

1. **Typed, deferred control product (H6, B2).** In composed mode, WRITE-DACL/WRITE-OWNER/
   ADD-MEMBER **defer** their inline rollback to a teardown obligation and emit a typed
   `control_for(X)` capability describing {actor=operator, object=X, right, lifetime=until
   teardown}. The consumer checks the specific {object,right}, not any `control_for(*)`.
2. **Planning-time link (H5).** Add a **bounded candidate-effect / compatibility relation**
   so `search()` can propose WRITE-DACL→GENERIC-ALL for the same X (GENERIC-ALL's
   control-pre is satisfiable by a produced `control_for(X)`), WITHOUT making GENERIC-ALL
   seed-runnable for X when the operator lacks control. Preserve every existing path
   (front→DCSYNC regression-protected).
3. **Escalation from the consumed capability (B2).** The chain counts as an escalation
   only when GENERIC-ALL's applicability for X was established by WRITE-DACL's *produced*
   `control_for(X)` (provenance ≠ seed), selected atomically; immutable provenance through
   any alias. If the operator already had control over X (seed), it is **not** an
   escalation.
4. **Lateral only — never DA (defer B1/B3).** `cred_for(X)` is the goal; it **never**
   satisfies a `da_creds`/`S_DA` pre in this sprint. The DA-equivalence authority and
   DCSYNC credential-usability threading are explicitly **out of scope** (the deferred
   T3→DA sprint). A `chain --goal S_DA` that can only get `cred_for(X)` honestly reports
   not-reached.
5. **Secret-safe (H8).** The recovered credential stays in a private runtime field for
   teardown/threading; never in the receipt/report/errors/note.

### S3 — Live proofs on GOAD

1. **Individual:** `validate run WRITE-DACL --target robb.stark --param trustee=vagrant …`
   live → receipt → harness `proved` (re-proves a T3 technique through the real command).
2. **Chain A (front→DCSYNC→DA):** `validate chain --goal S_DA` → CERTIFRIED/ESC8 → DCSYNC
   on GOAD essos → `reached=True, escalation=True, clean=True`, on the **repaired**
   terminal (S1b). Live krbtgt dump on the authorized lab; H6 keeps the secret out.
3. **Chain B (lateral T3):** pick a GOAD account X the operator can WriteDACL but does not
   already control → `validate chain --goal cred_for(X)` composes WRITE-DACL→GENERIC-ALL →
   `cred_for(X)`, `escalation=True`, `clean=True` (deferred rollback verified at teardown).
   Recon the concrete X in S3; reconfigure the lab if needed (owner authorized).

## Test plan (before execution; non-vacuous — H9)

- S1: per-subcommand arg→finding/engine wiring; `run` builds the same receipt as
  `ps_drive`; missing-required-param errors; serialized-receipt secret-sentinel test (H8).
- S1b: banner-only+access-denied DCSYNC transcript → not-proved (RED); a real
  `krbtgt:<rid>` replication line → proved (GREEN).
- S2 **positive (required):** a scripted-fake run whose **exact** chosen path is
  WRITE-DACL→GENERIC-ALL, where GENERIC-ALL is applicable for X **only because** WRITE-DACL
  produced `control_for(X)`, reaching `cred_for(X)` with `escalation=True`. **Negatives
  (isolated):** operator already controls X (seed) → not an escalation; WRITE-DACL
  incomplete → no `control_for(X)` → GENERIC-ALL not applicable for X → not reached;
  forged control claim without a real produced cap → not reached; `--goal S_DA` with only
  a lateral cred → not reached. Keep the front→DCSYNC positive regression test.
- S3: live receipts/report harness-scored; shred artifacts, copy back only receipt/report.

## Delegation split (codex-interop)

- Plan + design: Claude (Opus), reviewed by Codex Sol (done — this doc).
- S1 + S1b + S2 implementation: **Codex Sol** in a worktree against this plan; Claude
  reviews the diff (cross-family), runs the gate, proves live, integrates.
- S3 live proofs: Claude on GOAD (kali-vr), harness-scored.

## Plan-review resolutions (Codex Sol, 26NOV2026)

| # | Finding | Resolution |
|---|---------|-----------|
| B1 | "enumeration" not an independent DA authority | **Deferred** with T3→DA; this sprint's lateral chain never claims DA. |
| B2 | principal aliases launder seed provenance | S2§3: immutable provenance, atomic single-capability consumption, escalation from the consumed cap. |
| B3 | value+channel insufficient; DCSYNC falls back to seed auth | **Deferred** with T3→DA (no credential threaded into a terminal this sprint; lateral control gates applicability only, operator auth throughout). |
| B4 | DCSYNC banner terminal = false DA | S1b: require real krbtgt-replication evidence; RED-proved. |
| H5 | search can't discover T3→consumer | S2§2: planning-time bounded candidate-effect/compatibility link; regressions protected. |
| H6 | control tokens lack lifetime; inline rollback | S2§1: deferred teardown + typed {actor,object,right,lifetime} products. |
| H7 | host=target incomplete; no DCSYNC finding | S1: per-technique input adapters + explicit DCSYNC DC-finding; same binding for plan+exec. |
| H8 | exception text leaks secrets to errors/note | S1/S2§5: private runtime fields + payload-free codes; serialized-output sentinel test. |
| H9 | RED tests pass vacuously | S2 test plan: required POSITIVE exact-path test where the produced cap is what enables edge2; isolated negatives; both `reached=False` and `escalation=False`. |
