# ADR-001 (24NOV2026) — Listener-based validation executors (COERCION, NTLM-RELAY, UNCONSTRAINED-DELEG)

**Status:** PROPOSED — awaiting cross-family review (Codex uncap 25NOV) before build.
**Scope:** PLAN-003 validation automation, tranche **T1c-2** (the final 3 of the 11 proven techniques). T1 techniques 1–8 (RBCD, KERBEROAST, AS-REP, LAPS, CONSTRAINED-DELEG-PT, OPENSHARES-WRITE, SHADOW-CREDS, ADCS-ESC1) are already implemented on the synchronous chassis and harness-verified.
**Author model tier:** Tier-2 cyber (design). Build to follow after review.

## Context / problem

The last three techniques cannot be expressed as the existing executors are. Every T1-1..8 executor is a **synchronous** chain: `ctx.runner.run(argv) -> RunResult`, one tool at a time, each step's `ok` decided by a predicate over that tool's output. The remaining three need a **capture process running concurrently with a trigger**:

| Technique | Facet terminal | Facet mutating | Vuln keys | Shape |
|---|---|---|---|---|
| COERCION | `authn_success` | false | `{host_id}` dc01/dc02/dc03 | start a listener → coerce the victim machine account to authenticate to it → the **captured auth** is the proof |
| NTLM-RELAY | `[replication_dump, rbcd_access]` | false (LDAP-RBCD mode mutates) | `{host_id}` srv02/srv03/dc01/dc02/dc03 | start `ntlmrelayx` at a signing-off target → coerce → relayed auth → **SMB SAM dump** (`replication_dump`, read) **or LDAP RBCD write** (`rbcd_access`, mutating → rollback) |
| UNCONSTRAINED-DELEG | `replication_dump` | false | `{host_id}` dc01/dc02/dc03 | start a TGT monitor on a controlled unconstrained host → coerce the DC to it → capture its TGT → **DCSync** |

All three are `verified_recipe = False` — recipe-known, **not proven end-to-end** on GOAD (#66146 C2/C5/C8). They must ship honest: a clean run scores `proved`; anything short scores `not-proved`/`inconclusive`; nothing is ever faked.

## Decision 1 — chassis extension: a `ProcessManager` for background capture

Add an injected `ProcessManager` abstraction alongside the existing `CommandRunner`, so a listener can run while a trigger fires, and so the whole thing stays unit-testable with a scripted fake (no lab, no real listener).

```
class ProcessManager(ABC):
    def start(self, argv, *, env=None, cwd=None) -> Handle      # non-blocking (Popen)
    def read(self, handle) -> str                               # output captured so far
    def stop(self, handle) -> str                               # terminate + reap -> final output
class SubprocessProcessManager(ProcessManager): ...             # real adapter (Popen, non-blocking reads)
```

- `ExecutorContext` gains `proc_manager: ProcessManager` (defaulted in the orchestrator, injected in tests), exactly mirroring how `runner`/`authorizer`/`scorer` are injected today. This is the one **contract change to `base.py`** — additive (new optional field + new ABC), no change to existing executors.
- A listener-based executor: `start` the capture → `run` the trigger (synchronous, via the existing `runner`) → **poll** `read` until a success marker appears or a bounded timeout elapses → `stop` → derive the terminal fact from the captured output. The poll is bounded by `config.tool_timeout_s`; a timeout with no capture is an honest `inconclusive` (collection failed), never a proof.
- Secrets (captured hashes, relayed SAM, TGTs) follow the existing rule: presence-detected / used in-process only, never written to the receipt; `proof_token` over public identifiers only.

**Alternative considered (rejected):** overload `CommandRunner.run` with a "background=True" flag returning a handle. Rejected — it muddies the clean synchronous contract the 8 existing executors rely on and the fake runners assume. A separate, small, injected abstraction is cleaner and leaves T1-1..8 untouched.

## Decision 2 — framework-managed listener, operator-overridable host

The #66142 UX is "the framework automatically validates." So the **default is a framework-managed listener** on the framework's own interface. But real engagements often run the relay/capture box separately, so every listener executor exposes a `listener_host` (and `listener_iface`) **recommended-default + operator-override** param: unset → framework-managed on the local interface; set → the framework only fires the trigger and polls the operator's listener/loot path. This is the superset of both engagement styles and matches the override model used everywhere else (#66142).

**This is the one point worth an explicit owner confirmation** — see "Open question for the owner".

## Decision 3 — per-technique design

Identities below are what `target_identity` must emit to match the facet (subset match, case-insensitive).

- **COERCION** — `coerce`, terminal `authn_success`, **non-mutating**, no rollback.
  - `target_identity = resolve_target_identity(victim_dc)` → `{host_id}`.
  - Steps: `start` listener (ntlmrelayx `-socks`/Responder/minimal SMB capture) → `run` the trigger (Coercer/PetitPotam/printerbug) against `victim_dc` pointing at `listener_host` → poll for the victim **machine account** (`<DC>$`) authenticating to us → terminal `authn_success ok = captured`.
  - params: `victim_dc` (recommended `finding.host`), `listener_host` (recommended auto/local), `method` (recommended `auto`: petitpotam→printerbug→dfscoerce fallback).

- **NTLM-RELAY** — `relay`, terminal `replication_dump` **or** `rbcd_access`, **mode-dependent mutation**.
  - `target_identity = resolve_target_identity(relay_target)` → `{host_id}`.
  - `mode` param (recommended `smb_sam`): `smb_sam` → ntlmrelayx relays to a signing-off SMB target and dumps SAM → terminal `replication_dump`, **read-only** (no rollback). `ldap_rbcd` → relays to LDAP and writes RBCD on the target → terminal `rbcd_access`, **sets `mutation.applied=True` → requires a verified rollback** (RBCD flush, reusing the RBCD executor's flush+read-verify). The scorer's `is_mutating = facet.mutating OR mutation.applied` makes the rollback guard fire for `ldap_rbcd` even though the facet lists `mutating:false`.
  - params: `relay_target` (recommended the signing-off `finding.host`), `mode`, `listener_host`, plus the coercion sub-params (it drives a coercion trigger to feed the listener).

- **UNCONSTRAINED-DELEG** — `delegation`, terminal `replication_dump`, **non-mutating** (DCSync is replication-read; no AD write).
  - `target_identity = resolve_target_identity(victim_dc)` → `{host_id}`.
  - Steps: `start` a TGT monitor (krbrelayx/Rubeus monitor) on a **controlled unconstrained host** → `run` the coercion trigger against `victim_dc` → poll for the DC's captured TGT → use it for `secretsdump` DCSync → terminal `replication_dump ok = DCSync returned krbtgt/replication data` (presence only; no secret stored).
  - params: `victim_dc` (recommended `finding.host`), `unconstrained_host` (recommended operator-supplied — the controlled host with unconstrained delegation), `listener_host`.

## Decision 4 — honesty posture (do NOT lab-prove first)

These recipes are unproven, but per the owner's standing direction we do **not** hand-drive them against GOAD to "prove the lab is vulnerable" — we encode them faithfully and let the harness be the judge at operator run time. `verified_recipe=False` means the orchestrator's `AutoConfirm` skips them unless the operator passes `include_unverified` — so they never run silently in auto mode, but are fully available on opt-in. All tool output markers are UNVERIFIED and flagged in-module (as `laps.py`/`shadow_creds.py`/`adcs_esc1.py` already do), to be pinned at the first real lab run.

## Testing

- Unit: a scripted fake `ProcessManager` (start returns a handle, `read`/`stop` return scripted listener output) + the existing fake `CommandRunner` for triggers. Per technique: mapping+param defaults, override (incl. `listener_host`, `mode`), proved-shaped receipt, no-secret-leak, and honest `not-proved`/`inconclusive` on no-capture / timeout / denied gate / (ldap_rbcd) unverified rollback.
- Real cross-repo scoring per technique against `adlab/score_proof.py` + `truth/GOAD-proof.json` (proved path → exit 0; a `{host_id}` outside the vuln set → `not-proved`), exactly as T1-1..8 were verified.

## Review gate (dev-methodology, contract change)

This introduces a chassis contract change (`ProcessManager`), so it takes a **peer-reviewed plan before build**. The review runs at **Codex uncap (25NOV)** as one pass over (a) this ADR and (b) the whole `dev/validation-automation` T0→T1 diff, cross-family (Daybreak Blue / Sol). Build T1c-2 only after the review is green; then the full T1 branch + the harness S0 scorer branch fast-forward to `main` together.

## Open question for the owner

**Listener architecture (Decision 2):** default to a **framework-managed** listener (auto, matches the #66142 "automatically validate" spec) with a `listener_host` override for operators who run their own relay box? This ADR assumes **yes**. The alternative is operator-positions-the-listener-always (framework only triggers + scores), which is simpler but less "automatic". The proposed design is the superset, so a "no" would only *remove* the framework-managed default, not require a redesign.

## Unverified assumptions

- Exact coercion method availability per target (PetitPotam vs printerbug vs DFSCoerce) and their success markers.
- ntlmrelayx output/loot format for SAM-dump and LDAP-RBCD-write success.
- krbrelayx/Rubeus TGT-capture markers and the secretsdump DCSync success marker.
- That a framework-managed listener can bind a reachable interface in the operator's environment (else `listener_host` override is required).
