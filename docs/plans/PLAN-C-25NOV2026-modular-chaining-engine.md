# PLAN-C (25NOV2026) — modular chaining engine (DA in minutes)

**Status:** DRAFT → 1 independent review (Opus, VERDICT REVISE — 6 findings) → **revised (all applied, see Review section)** → execute (C.0 refactor → C.1 engine) → verify.
**Objective:** compose the existing validated techniques (edges) into a **capability-state graph** that reaches Domain Admin by *search*, not a script (ADR-002 D4 modularity mandate: `a1+b1` ⇒ DC on system 1, `a2+b1` ⇒ DC on system 2, same `b1`). Deliver the engine + a `da-in-minutes` entrypoint that, on a freshly-enumerated/probed domain, finds and executes the shortest viable `S0 → S_DA` path, stops at the first `proved` DCSync, and leaves the lab clean (chain-level verified rollback). Acceptance: `ESC8+DCSync` and `Certifried+DCSync` both reach a `proved` DA via the SAME `DCSync` module, found by graph search (no hardcoded chain); mutating edges are rolled back + VERIFIED before "DA-proved-and-clean"; the suite stays green.

Evidence: ADR-002 D4 (+ review addenda), research catalog §1-2 (ranked paths, graph model), `states.py` (N1 capability constants), the 15 executors + their probes, PLAN-N1 review (H3 deferred rollback, H5 front+DCSYNC pair).

## Review (25NOV2026) — VERDICT REVISE; corrected design (all findings applied)
Independent Opus review found the plan's direction right but the `a1+b1` composition **wired to nothing / scripted** until concrete code hooks are added. All 6 findings accepted → the plan now has a **prerequisite composition-enabling refactor (C.0)** before the engine (C.1), and the corrections below supersede the drafted §1b/§1c/§2/§4.

**C.0 — composition-enabling refactor (must land before the engine; each with its own tests):**
- **(B1) ExecutorContext input slot + DCSync threading.** Add a typed `input_caps` (and an `env` passthrough) to `ExecutorContext`. `DCSyncExecutor.execute` must forward `env={"KRB5CCNAME": <ccache>}` to `runner.run` (it currently passes none — unlike unconstrained_deleg/adcs_esc1/rbcd/constrained_deleg which all do) AND derive its target principal from the threaded capability (a produced `principal`, e.g. `dc01$`), not `cfg.username`; add `ccache`/`principal` params to `DCSync.param_specs`.
- **(B2) Typed `CapabilityOutput` + per-channel routing.** `CapabilityOutput` payload is TYPED: `ccache_path | nt_hash | aes_key | principal`. The engine routes each to the matching DCSync input channel (ccache→`KRB5CCNAME`; nt_hash→`-hashes`; principal→target). So hash-producing fronts (shadow-creds, ESC1-with-DA-SAN, relay) compose too — not only ccache fronts. Secrets (nt_hash) are passed in-memory to the next edge's argv (masked by `redact_argv`), NEVER serialized.
- **(B3) Deferred-rollback executor API (fixes H3).** Add to `ValidationExecutor`: a `composed` flag read from ctx that makes `execute` SKIP the inline rollback (and not gate `complete` on it); `produced(result) -> CapabilityOutput` exposing the ccache/hash/principal; a PUBLIC `teardown(ctx, obligation)` the engine invokes later, where `obligation` carries the (secret) pfx/ccache paths the engine captured. ESC8/ESC11/Certifried stop self-destroying their ccache when `composed`.

**C.1 corrections (supersede the draft):**
- **(H5a) `eff` is PRINCIPAL-TYPED, mode-aware, and `smb_sam`≠DA.** `NTLM-RELAY smb_sam eff = {S_LOCAL_ADMIN(host)}` (a NEW state that does NOT feed `S_DA` — a member's local SAM can't DCSync); `ldap_rbcd eff = {S_RBCD_WRITE}`. Register **per-mode edges** (mode is a runtime param; one class-level `eff` can't express it). `SHADOW-CREDS eff = {cred_for(principal)}` (its terminal is the victim's NT hash, `secret_recovered` — NOT `DC_TGT`); `ADCS-ESC1 eff = {cred_for(SAN-principal)}`. Only when the bound principal is a DA/DC does a `cred_for(principal)` satisfy a `DCSync`/`S_DA` `pre` — the search binds the principal and a normal principal yields a lateral cred, never DA.
- **(H4) Teardown obligation at mutation-flip, drain ALL candidates.** The engine registers a teardown obligation the INSTANT an edge flips `mutation.applied` (not at edge return). Early-exit/cancel must drain EVERY candidate's obligations (cancelled included), each rollback VERIFIED (positive confirmation) before the report says DA-proved-and-clean; an unverified teardown → "DA proved but NOT clean" (loud). **First C executes ONE best path, NOT a top-k race** (racing multiplies in-flight mutations + the cancelled-sibling window); racing is added only after cancelled-sibling verified teardown is proven.
- **(H6) ChainReport serializes NAMES + receipts + teardown status ONLY.** State-store `CapabilityOutput` payloads (ccache paths, hashes) stay in the in-memory store, never in `ChainReport`/the "path taken" (the state name `dc_tgt` is not secret-marked so `scrub` wouldn't catch its path value).
- **(H5b) Seed-restriction + provenance.** The engine's seed state set = `{S0_USER_CREDS}` ONLY — it REFUSES `DA_CREDS`/`DC_TGT` as seeds. Every state in the store is tagged with provenance (producing edge-id vs operator-seed). A `DCSync` whose `pre` was satisfied only by an operator-seed/provenance-less cred is labelled "DA given creds", NOT an escalation proof; a composed escalation receipt carries BOTH the front receipt(s) AND the `DCSYNC` receipt.
- **(Q4) Crack/destructive are HARD FILTERS** (excluded from the graph unless `--allow-crack`/`--allow-destructive`), not cost multipliers (a multiplier still picks them when they're the only path).

## 1. Edge/state model

### 1a. Capability states (extend `states.py`)
Add the states the fronts traverse (research §2): `S0_USER_CREDS`, `S_COMPUTER_CONTROL`, `S_COERCED_AUTH`, `cert_for(host)`, `DC_TGT`, `S_RBCD_WRITE`, `S_IMPERSONATION_TGT`, `DA_CREDS`, `KRBTGT`, `S_DA`. (N1 already has `S0_USER_CREDS`, `DC_TGT`, `DA_CREDS`, `KRBTGT`, `S_DA`, `cert_for`.)

### 1b. Annotate the existing 11 edges with `pre`/`eff` (N1's 4 already have them)
> ⚠ **The `eff` column below is SUPERSEDED by the Review corrections (H5a).** Build the `eff` as PRINCIPAL-TYPED and mode-aware: `smb_sam → {S_LOCAL_ADMIN(host)}` (NEVER `DA_CREDS`/`S_DA`), `SHADOW-CREDS → {cred_for(principal)}` (secret_recovered, not DC_TGT), `ADCS-ESC1 → {cred_for(SAN-principal)}`, per-mode edge registration for NTLM-RELAY. The table is kept only to show the pre-correction draft.

Each executor gains class attrs `pre: frozenset`, `eff: frozenset` over `states` (no behaviour change). Draft mapping (CORRECTED by H5a above):
| edge | pre | eff |
|---|---|---|
| COERCION | S0 | S_COERCED_AUTH |
| NTLM-RELAY (ldap_rbcd) | S_COERCED_AUTH | S_RBCD_WRITE |
| NTLM-RELAY (smb_sam) | S_COERCED_AUTH | DA_CREDS (SAM = local, not DA — see Q) |
| RBCD | S_COMPUTER_CONTROL ∨ S0(MAQ) | S_RBCD_WRITE |
| (RBCD/KCD) S4U | S_RBCD_WRITE ∨ allowed-deleg | S_IMPERSONATION_TGT |
| CONSTRAINED-DELEG-PT | S0(deleg) | S_IMPERSONATION_TGT |
| SHADOW-CREDS | write-KeyCredLink | DC_TGT ∨ DA_CREDS |
| UNCONSTRAINED-DELEG | S_COERCED_AUTH + controlled-unconstrained | (monolithic → emits replication_dump itself; H4: keep as-is OR split in C — see Q) |
| ESC8/ESC11/Certifried | S0 | DC_TGT |
| ADCS-ESC1 | S0(template) | S_IMPERSONATION_TGT ∨ DA_CREDS |
| DCSYNC (`b1`) | DC_TGT ∨ DA_CREDS ∨ S_IMPERSONATION_TGT | KRBTGT, S_DA |
Each edge also carries `crack_free: bool`, `destructive: bool`, `mutating` (already present) for cost/gating.

### 1c. Capability-payload threading (THE composition mechanism — the crux)
> ⚠ **SUPERSEDED by the Review corrections (B1/B2/B3/H6).** The threading is REAL only after the C.0 refactor: `CapabilityOutput` is TYPED (ccache_path|nt_hash|aes_key|principal) with per-channel routing (not ccache-only); DCSync must forward `env={KRB5CCNAME}` AND derive its principal from the threaded capability (it does NEITHER today — B1); mutating fronts need `composed`/`produced()`/public `teardown()` (B3); payloads stay in-memory, never in the ChainReport (H6).

A proof receipt is not machine-consumable by the next edge. So each edge, **on success, returns a `CapabilityOutput`**: the concrete artifact/cred for each `eff` state it established — e.g. ESC8 → `{DC_TGT: ccache_path("<out>/dc01$.ccache"), principal("dc01$")}`; SHADOW-CREDS → `{cred_for(victim): nt_hash(...)}`; DCSync → `{KRBTGT: <present-only marker>, S_DA: True}`. The engine **threads** a produced capability into the next edge's input **by type**: a `ccache_path` → `KRB5CCNAME=<ccache>` in that edge's `ExecutorContext.env` AND a `ccache` param; a `principal` → the DCSync target principal; an `nt_hash` → `-hashes` (in-memory, masked by `redact_argv`, never serialized). This is how `a1.eff` literally feeds `b1.pre` — NOT a hardcoded "if ESC8 then DCSync". Edges expose `produced(result) -> CapabilityOutput` (default empty); the engine's state store maps `state -> payload`, kept in-memory only.

## 2. `ChainEngine` (new `engine/chain_engine.py`), injectable + fake-testable
> ⚠ **Steps below are REVISED by the Review corrections (H4/H5b/H6/Q4).** First C runs ONE best path (not top-k racing); seed set = `{S0_USER_CREDS}` only + provenance tags; teardown obligation registered at the `mutation.applied`-flip and ALL candidates' obligations (cancelled included) drained+VERIFIED before "clean"; crack/destructive are hard filters; ChainReport serializes names+receipts+teardown only.

`run(goal=S_DA) -> ChainReport`:
1. **Probe** (reuse D1 `run_probes`): prune edges whose precondition probe is a confident `viable=False`; `unknown`/`viable` stay (fail-safe).
2. **Search**: over the viable edge set, find paths `S0_USER_CREDS → … → goal` by matching `eff`⊇next-`pre` (BFS/weighted). Cost `= base × (1/reliability) × (crack_free?1:BIG) × (destructive?GATE:1)` → prefers crack-free, non-destructive, short. Return ranked candidate paths. **No path baked in** — if a new edge is added it participates automatically.
3. **Execute** the top path, threading `CapabilityOutput` edge→edge (1c). A mutating front, when composed, **defers its rollback** (H3) — the engine records it in a teardown stack, does NOT run the per-edge immediate rollback.
4. **Early-exit**: the instant a `DCSYNC` edge emits a receipt the real scorer grades `proved` for a DA-equivalent target, stop; cancel other candidates.
5. **Teardown (verified)**: roll back every mutating edge in the teardown stack in reverse, and **require each rollback VERIFIED** (positive confirmation, per D3) before the report says "DA-proved-and-clean" (ADR-002 D4 addendum). An unverified teardown → report `DA proved but NOT clean` (loud), never silently clean.
6. **Record the composed proof (H5)**: `ChainReport` holds the ORDERED list of per-edge `proof.v1` receipts (the front receipt(s) + the `DCSYNC` receipt) + the path taken + teardown status. The DA claim = the `DCSYNC` `proved` **plus** the front receipts that produced the creds — a chain may NOT hand `DCSync` pre-supplied `DA_CREDS` and call it an escalation (the engine refuses to count a DCSync whose `pre` was satisfied only by operator-supplied DA creds as an *escalation* proof; it's labelled "DA given creds").

## 3. `da-in-minutes` entrypoint (extend `validation/cli.py` or a sibling)
Operator sets the same `ValidationConfig` (domain/DC/creds/targets) + a `--goal da` flag → the engine runs → prints the path found, the per-edge verdicts, the composed DA proof, and the teardown status. `--allow-crack` to include crack-dependent edges (default masked). `--allow-destructive` to include Zerologon-class (default off). Non-interactive `--yes` accepts the recommended path.

## 4. Safety
- Crack-free-first (crack edges masked unless `--allow-crack`, time-budgeted → `inconclusive` not lost).
- Destructive edges (none yet; Zerologon is N3) gated off by default.
- **Chain-level verified teardown is mandatory** before "clean": the obligation is registered at the `mutation.applied`-flip, and EVERY candidate's teardown stack (including a cancelled sibling's) is drained + each rollback VERIFIED before DA-proved-and-clean (H4). First C runs a single best path, so there is one stack; racing is deferred until cancelled-sibling verified teardown is proven.
- DCSync-krbtgt default DA proof (non-destructive, read); add-to-DA only behind `--allow-destructive`.

## 5. Test plan (Phase 7)
Fake executors/edges (scripted `CapabilityOutput` + receipts) + a fake scorer, so the engine is driven with NO lab:
- **Modularity**: register `ESC8` and `Certifried` fronts (both `eff={DC_TGT}`) + `DCSync` (`pre={DC_TGT}`); assert the search finds `ESC8→DCSync` AND `Certifried→DCSync` with the SAME DCSync edge; adding a 3rd front auto-produces a 3rd path with no engine edit.
- **Threading**: assert ESC8's produced `DC_TGT` ccache is set as `KRB5CCNAME` for the DCSync edge (the composition is real, not scripted).
- **Early-exit**: first proved DCSync stops the run; siblings cancelled.
- **Teardown**: a mutating front (ESC8) is rolled back + VERIFIED at teardown (not per-edge); an unverified teardown → report "proved but NOT clean".
- **H5 integrity**: DCSync fed only operator-supplied DA creds → labelled "DA given creds", NOT an escalation proof.
- **No path**: goal unreachable (all fronts probed not-viable) → honest "no viable path", no false DA.
- Real-scorer cross-check: the composed `DCSYNC` receipt scores `proved` on a DC host_id (the DA proof). Keep the 172 current tests green.

## 6. Benefit (Phase 8)
`coerce→ESC8→DCSync = DA` and `Certifried→DCSync = DA`, both found by graph search over the same reusable `DCSync` terminal — the modular DA-in-minutes capability, demonstrable on the fake harness end-to-end (and lab-pinnable via the verified_recipe=False flags).

## Open questions — RESOLVED by the 25NOV review
1. **§1b mapping — NOT correct (HIGH5).** `smb_sam → {S_LOCAL_ADMIN(host)}`, never feeds `S_DA` (local SAM can't DCSync); `SHADOW-CREDS → {cred_for(principal)}` = the victim's NT hash (`secret_recovered`), not `DC_TGT`; `ADCS-ESC1 → {cred_for(SAN-principal)}`. All three are **principal-typed**: only a DA/DC-bound principal satisfies a `DCSync`/`S_DA` `pre`; a normal principal yields a lateral cred. NTLM-RELAY is one class with a runtime `mode` → register **per-mode edges**. (See H5a.)
2. **Keep UNCONSTRAINED-DELEG standalone** (agree with the lean) — it is the only working DCSync path today precisely because the standalone `b1` isn't wired yet (B1); once B1 lands, it stays as a convenience DA edge, not split in C. Modularity is proven by `ESC8+DCSync` / `Certifried+DCSync`.
3. **`CapabilityOutput` is right, but must be TYPED + routed per channel (B2),** and consumed via an explicit **input-capability param + `env=` passthrough on the edge's context (B1)** — NOT by mutating a shared `os.environ`/ctx (racy across parallel candidates). A ccache **path** is project-marked secret, so it must stay in-memory and out of the ChainReport (H6); `nt_hash` payloads are in-memory + `redact_argv`-masked, never serialized.
4. **Weighted-cost with crack/destructive as HARD FILTERS (Q4)** (excluded unless `--allow-crack`/`--allow-destructive`), not multipliers — a multiplier still selects them when they're the only path. **Execute ONE best path for the first C, NOT a top-k race** (H4) — racing multiplies in-flight mutations and opens the cancelled-sibling teardown window; add racing only after cancelled-sibling VERIFIED teardown is proven.
5. **New `validation/engine/` package** (agree) — not in `orchestrator.py`.
