# PLAN-C (25NOV2026) — modular chaining engine (DA in minutes)

**Status:** DRAFT → 1 independent review (Opus) → execute → verify.
**Objective:** compose the existing validated techniques (edges) into a **capability-state graph** that reaches Domain Admin by *search*, not a script (ADR-002 D4 modularity mandate: `a1+b1` ⇒ DC on system 1, `a2+b1` ⇒ DC on system 2, same `b1`). Deliver the engine + a `da-in-minutes` entrypoint that, on a freshly-enumerated/probed domain, finds and executes the shortest viable `S0 → S_DA` path, stops at the first `proved` DCSync, and leaves the lab clean (chain-level verified rollback). Acceptance: `ESC8+DCSync` and `Certifried+DCSync` both reach a `proved` DA via the SAME `DCSync` module, found by graph search (no hardcoded chain); mutating edges are rolled back + VERIFIED before "DA-proved-and-clean"; the suite stays green.

Evidence: ADR-002 D4 (+ review addenda), research catalog §1-2 (ranked paths, graph model), `states.py` (N1 capability constants), the 15 executors + their probes, PLAN-N1 review (H3 deferred rollback, H5 front+DCSYNC pair).

## 1. Edge/state model

### 1a. Capability states (extend `states.py`)
Add the states the fronts traverse (research §2): `S0_USER_CREDS`, `S_COMPUTER_CONTROL`, `S_COERCED_AUTH`, `cert_for(host)`, `DC_TGT`, `S_RBCD_WRITE`, `S_IMPERSONATION_TGT`, `DA_CREDS`, `KRBTGT`, `S_DA`. (N1 already has `S0_USER_CREDS`, `DC_TGT`, `DA_CREDS`, `KRBTGT`, `S_DA`, `cert_for`.)

### 1b. Annotate the existing 11 edges with `pre`/`eff` (N1's 4 already have them)
Each executor gains class attrs `pre: frozenset`, `eff: frozenset` over `states` (no behaviour change). Draft mapping (review to confirm):
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
A proof receipt is not machine-consumable by the next edge. So each edge, **on success, returns a `CapabilityOutput`**: the concrete artifact/cred for each `eff` state it established — e.g. ESC8 → `{DC_TGT: "<out>/dc01$.ccache"}`; SHADOW-CREDS → `{DC_TGT: "<ccache>"}`; DCSync → `{KRBTGT: <present-only marker>, S_DA: True}`. The engine **threads** a produced capability into the next edge's input: for `DC_TGT` it sets `KRB5CCNAME=<ccache>` in that edge's `ExecutorContext` (and/or a param), so `DCSync` authenticates with the TGT `ESC8` produced. This is how `a1.eff` literally feeds `b1.pre` — NOT a hardcoded "if ESC8 then DCSync". Edges expose `produced(result) -> CapabilityOutput` (default empty); the engine's state store maps `state -> payload`.

## 2. `ChainEngine` (new `engine/chain_engine.py`), injectable + fake-testable
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
- **Chain-level verified teardown is mandatory** before "clean"; parallel/raced candidates each roll back their mutations (verified) before DA-proved-and-clean.
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

## Open questions for the review
1. The `pre`/`eff` mapping of the existing 11 (§1b) — correct? Esp. NTLM-RELAY smb_sam `eff` (SAM = local admin on a member, NOT domain creds — should it feed `S_DA` at all, or only lateral?), and SHADOW-CREDS/ADCS-ESC1 `eff` (do they yield `DC_TGT` or `S_IMPERSONATION_TGT`?).
2. UNCONSTRAINED-DELEG is monolithic (front+DCSync). Keep it as a standalone DA edge (its own `replication_dump`) AND NOT split it in C (defer the split), or split now so `b1` is the single DCSync module? (Lean: keep it standalone in C; the split is optional later — C's modularity is demonstrated by ESC8/Certifried+DCSync.)
3. Capability-payload threading (§1c): is `CapabilityOutput` + `KRB5CCNAME` threading the right mechanism, or should edges take an explicit input-capability param? Any secret-handling risk in threading a ccache path between edges (it's a path, not a secret value — confirm)?
4. Search: BFS-shortest vs weighted-cost — is the cost model right, and should the engine execute ONE best path or race top-k disjoint paths (ADR-002 said race; is that needed for the first C, or is single-best-path enough)?
5. Engine placement: a new `validation/engine/` package vs inside `orchestrator.py`?
