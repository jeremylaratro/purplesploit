# PLAN — ADR-003 Phase 1: universal Credential producer + cleartext threading (27NOV2026)

**Status:** ready to implement (Sol high)
**Implements:** [ADR-003](../adr/ADR-003-27NOV2026-universal-credential-producers-and-autopwn.md) Phase 1.
**Base:** main @ e6fe0a2 (Phase 0 + reveal rollout landed; `_reveal` capture exists on every
secret-recovering technique).

## Objective

Every secret-recovering technique **produces** its recovered credential as a standardized,
runtime-only `Credential` capability — so gained creds (user:password, machine:hash, ticket) are
first-class, available to the engine, the future store, and the reveal — AND the engine can thread
**cleartext** creds (today `CAP_PASSWORD` is never routed). This makes gained creds chainable to the
EXISTING consumers (DCSYNC, ticket-forgers, …). Identity re-scope of `discover`/`recon` and the
driver are later phases (3/4) — NOT here.

## Design

1. **Standardized `Credential`.** Extend the existing `Capability` (base.py) with optional
   credential metadata (do NOT break current fields `state/channel/value/principal/provenance`):
   `domain`, `is_machine`, `secret_type` (password|nthash|aeskey|ccache|pfx — align with the
   `CAP_*` channel), `source_technique`, `reach_hint` (optional). `value` stays the secret
   (runtime-only, NEVER serialized — same invariant as today and as `--show-flag`).
2. **Produce from every secret-recoverer.** Reuse the `_reveal` capture (principal/kind/value
   already captured at recovery time, pre-cleanup, all branches). Each technique's `produced()`
   also emits the standardized `Credential`(s) for what it recovered — on BOTH standalone and
   composed branches (fix the composed-only gap), at recovery time, proof-independent. Map
   `kind`→`secret_type`→`channel`:
   - cracked password / LAPS / reset_password / looted cleartext → `CAP_PASSWORD`
   - NT hash (Kerberoast NT, shadow-creds, PKINIT, SAM) → `CAP_NT_HASH`
   - AES key → `CAP_AES_KEY`; ccache/ticket → `CAP_CCACHE`; pfx → (pfx)
   The no-secret primitives still produce nothing.
3. **Engine: thread `CAP_PASSWORD`.** `chain_engine._thread_caps` routes only
   control/ccache/nt_hash/aes_key/principal today. Add a `CAP_PASSWORD` route into `input_caps`
   (e.g. `input_caps["password"]`) so a recovered cleartext cred can re-auth a downstream edge that
   consumes it. (Broadening which executors CONSUME `input_caps` for auth is Phase 3 — here just
   make the channel routable + one consumer proven.)

## Test plan

- **Per technique:** `produced()` emits the expected `Credential` (right principal/secret_type/
  value) on a standalone run, at recovery time, even when a later proof fails. Reuse the
  `test_show_flag` fakes.
- **Engine:** a produced `CAP_PASSWORD` cred is threaded into a downstream edge's `input_caps`
  (prove with one consumer); existing typed-channel threading unchanged.
- **Invariant (unchanged, re-gated):** `Credential.value` never reaches the receipt / JSON /
  write_receipt / chain-report / proof_token (it is a runtime Capability like today). Re-run the
  `--show-flag` invariant gate — still green.
- Regression: full suite stays green (baseline 911).

## Delegation

Claude plans + reviews + runs the invariant gate; **Sol (high effort)** implements in a worktree.
Secret rules + no-attribution restated in the brief. Independent (Claude) review of the diff before
landing.

## Risks

- **Capability-field change blast radius** — adding optional metadata must not disturb the engine's
  channel routing or existing `produced()`/`_thread_caps`. Keep new fields optional + defaulted.
- **Secret in a produced Credential** — same as today's Capability.value (runtime-only); the
  invariant gate guards it.
- Producing a cred nothing yet consumes is fine (foundation); the `CAP_PASSWORD` route + existing
  consumers give immediate partial chaining.
