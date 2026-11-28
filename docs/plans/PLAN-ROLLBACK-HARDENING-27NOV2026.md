# PLAN — interrupt-safe rollback + dirty-state (prereq for autopwn 4b) (27NOV2026)

**Status:** ready to implement (Sol high)
**Fixes:** Codex Phase-4 safety review BLOCKER #5 + HIGH #6. **Base:** main @ f9b3050.
**Why now:** prerequisite for the autopwn execution loop (4b), and a general safety win for EVERY
manual mutating technique — an interrupted mutation must still roll back (or be flagged dirty),
never silently persist.

## The gaps (from the review, confirmed in code)

- `_execute_to_artifact` (base.py:597) catches `except Exception` — `KeyboardInterrupt`/SIGINT is
  NOT caught, so an interrupt between a mutating write and its inline rollback leaves AD mutated and
  never rolled back.
- On a caught exception it marks `mutation.applied=True` ONLY if `ctx._pending_teardown` was set;
  a mutation performed WITHOUT a pre-registered obligation normalizes to `applied=False` — hiding
  an outstanding mutation.
- RBCD and other mutating executors roll back via ordinary inline control flow AFTER the write, so
  an interrupt/exception in between skips rollback entirely.

## Design

1. **Pre-write obligation registration.** Every mutating executor registers its teardown
   obligation (`ctx._pending_teardown = {...}` with the secret paths/targets its rollback needs)
   **BEFORE** performing the mutating write — not after. So an interrupt/exception at any point
   after the write has a registered obligation to execute.
2. **Interrupt-safe `_execute_to_artifact`.** Catch `BaseException` (so `KeyboardInterrupt` is
   handled): if `ctx._pending_teardown` is set, RUN the teardown (best-effort) before re-raising /
   returning; record whether it verified. Re-raise `KeyboardInterrupt` after cleanup so the caller
   still stops.
3. **Dirty-state, never a hidden mutation.** If a mutation MAY have occurred (a pre-write
   obligation was registered) and the outcome is uncertain (exception/interrupt), the artifact is
   `mutation.applied=True` with a `mutation.dirty=True` (or `rollback.verified=False` +
   `dirty` marker) — NEVER normalized to `applied=False`. An uncertain outcome is reported, not hidden.
4. **`rollback.verified` reliability (for #6).** Ensure `mutation.rollback.verified` is set only on
   a genuinely verified rollback (the driver in 4b advances ONLY on `verified`), and is False/unset
   on a dirty/uncertain outcome.

## Scope (mutating executors to register-before-write)

rbcd, adcs_esc1, esc8, certifried, write_dacl, write_owner, add_member, gpo_abuse,
force_change_password, targeted_kerberoast, generic_all, shadow_creds, openshares. (Non-mutating
techniques unchanged.) Keep each existing verified-rollback behavior; only move the obligation
registration earlier and route cleanup through the interrupt-safe path.

## Test plan (the safety gates — each RED-provable)

- **Interrupt mid-mutation:** a fake runner raises `KeyboardInterrupt` AFTER the mutating write but
  before inline rollback; assert the teardown RUNS (rollback invoked) and the artifact is
  `applied=True` (never `False`); `KeyboardInterrupt` still propagates.
- **Exception mid-mutation:** same with an ordinary Exception; assert `applied=True` + dirty, never
  hidden as `applied=False`.
- **Pre-registration:** assert the obligation is set BEFORE the write (a runner that inspects
  `ctx._pending_teardown` at write time sees it).
- **Verified gate:** a rollback whose verification fails yields `rollback.verified=False` + dirty;
  a clean rollback yields `verified=True`.
- Regression: full suite green (baseline 1199) — existing rollback/teardown tests still pass.

## Risks

- **Delicate core change** (base.py execution wrapper + every mutating executor). Keep the composed
  deferred-rollback path (B3) working; the pre-registration must not double-run the rollback on the
  normal success path. Thorough tests for both normal and interrupted paths.
