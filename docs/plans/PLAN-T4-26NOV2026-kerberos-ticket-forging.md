# PLAN-T4 — Kerberos ticket forging (Golden / Silver / Diamond / Sapphire) — 26NOV2026

**Tranche T4** of PLAN-NEWTECH (order T3 → **T4** → T6 → T2 → T7 → T1 → T8). Base: purplesploit
`main` @ `fe4a7fb` (T3 + dual-mode + portability all merged). Cadence: plan → 1 cross-family
review → build → probe → prove on GOAD → integrate → **portability audit** (standing directive).

**Build/prove order (owner directive 26NOV2026): "Kerberos ticket work first. Then full chain."**
- **T4a — ticket work (FIRST):** the 4 forging executors built and proven **individually** as
  standalone `validate run` jobs (forge → reauth → harness `proved`), each recipe pinned live
  against the real tools, *before* any engine composition.
- **T4b — full chain (SECOND):** only once T4a's executors are proven, wire the capability-state
  edges (`KRBTGT`-fed `S_PERSISTENCE`) and prove the composed **DCSYNC → GOLDEN** chain live.
This de-risks the core recipes before layering on chaining — the same individual-then-chainable
order used in the dual-mode sprint.

## Phase 0 — Frame
- Repo: purplesploit (`.claude/worktrees/t4-kerberos-forging`, branch `dev/t4-kerberos-forging`).
- Governing rules: purplesploit `CLAUDE.md` (author `jeremylaratro`, no attribution, local tests
  only, no force-push); the ValidationExecutor contract; secrets presence-only in receipts; the
  dual-mode CLI (`validate run`/`chain`); the capability-state engine.

## Phase 1 — Objective + techniques
**Objective:** add 4 Kerberos-forging techniques as ValidationExecutors + capability-state edges,
each proven live on GOAD and scored `proved` by ad-lab-harness, **reusing the `KRBTGT` state the
engine's DCSYNC already produces**, with a **persistence** terminal distinct from DCSYNC's
replication terminal. Non-mutating (forging is offline; the terminal is authenticating with the
forged ticket) — **no rollback**, clean terminals for the engine.

**Toolchain (verified on kali-vr, impacket 0.13.1):** `impacket-ticketer` (Golden `-nthash`,
Silver `-spn`, Diamond `-request`, Sapphire `-request -impersonate`), `impacket-getST
-u2u -self -impersonate`, `impacket-lookupsid` (domain SID).

| Technique | Recipe (terminal = authenticate with the forged ticket) | pre → eff |
|---|---|---|
| **GOLDEN-TICKET** | `ticketer -nthash/-aesKey <krbtgt> -domain-sid <SID> -domain <d> -groups 512 <u>` → ccache → `nxc smb <dc> -k` (Pwn3d) | `KRBTGT` → `S_PERSISTENCE` (+`S_DA`) |
| **SILVER-TICKET** | `ticketer -spn <svc>/<host> -nthash <service_hash> -domain-sid <SID> -domain <d> <u>` → ccache → access that service `-k` | `cred_for(service)` → service access |
| **DIAMOND-TICKET** | `ticketer -request -user <d>/<lowpriv> -hashes/-password <lowpriv> -aesKey <krbtgt_aes> -domain-sid <SID> -groups 512 <u>` (clone a real TGT, re-sign PAC) → use `-k` | `KRBTGT`(aes)+`S0` → `S_PERSISTENCE` (+`S_DA`) |
| **SAPPHIRE-TICKET** | `ticketer -request -impersonate <DA> -user <d>/<lowpriv> -aesKey <krbtgt_aes> …` (real DA PAC via S4U2self+U2U) → use `-k` | `KRBTGT`(aes)+`S0` → `S_PERSISTENCE` (+`S_DA`) |

**New state `S_PERSISTENCE`** (BASE_STATES): "a forged, reusable authenticator that survives
credential resets." The forging edges' eff is `S_PERSISTENCE` (the distinct T4 value), NOT merely
`S_DA` — DCSYNC already reaches `S_DA`, so modeling T4 as `S_DA` would add no real graph edge; the
chain **DCSYNC → `KRBTGT` → GOLDEN → `S_PERSISTENCE`** is the new, meaningful composition.

## Phase 2 — Triage (all `now`, one sprint; split if a review round can't hold it)
Relevance 5 (headline persistence edges, reuse the existing DCSync output). Complexity: Golden/
Silver are low (offline forge + reauth, no new engine machinery); Diamond/Sapphire are medium
(`-request` needs a live low-priv cred + the AES krbtgt key). One sprint, 4 executors.

## Phase 4/5 — Design (per executor)
- **Shared base:** a `forge_common.py` (mirroring `acl_common.py`): the domain-SID helper
  (operator param, else `impacket-lookupsid` auto-resolve — presence-detected, never trusted
  blindly), the ccache-path parser, the `nxc … -k` authn-success predicate (reuse `_RE_NXC_PWNED`/
  `_RE_NXC_AUTH_OK`), and the secret-safe argv (krbtgt/service key rides `-nthash`/`-aesKey` so
  `redact_argv` masks it; the forged ccache PATH is engine-only, never in the receipt).
- **param_specs:** `domain_sid` (auto), `forged_user`/`impersonate` (default a plausible DA),
  `groups` (default 512), `krbtgt_key`/`service_key` (from the threaded `KRBTGT` capability in a
  chain, or an operator param standalone), `spn`/`service_host` (Silver), `reauth_target`.
- **execute:** forge (ticketer) → `ok` from the **reauth** positive predicate (never the forge
  call's exit code; `exit 0 is never proof`) → terminal `authn_success`. Non-mutating; no rollback.
- **target_identity:** `{domain, principal: <forged/impersonated user>}` (Silver: `+ spn`/host) —
  match the harness facet key names exactly (read the facet shapes, like T3).
- **produced (composition C):** a `CAP_CCACHE` capability for `S_PERSISTENCE` (the forged ccache),
  engine-only; the krbtgt key is never re-emitted. `chain_pre` = `{KRBTGT}` so the engine composes
  **DCSYNC → GOLDEN** (and Diamond/Sapphire also take `S0`). `accepts_*` validates the threaded
  krbtgt key is usable (an NT hash / AES key, not a placeholder) — the B3 lesson from the review.
- **Engine filters:** Diamond/Sapphire need a live request (a real low-priv cred) — mark them so a
  purely-offline seed can't silently run them; Golden/Silver forge fully offline from the key.

## Phase 7 — Test plan (non-vacuous, before execution)
- Unit (scripted fakes, no lab): each executor forges + reauths → proved; **`exit 0` with no
  reauth success → not-proved** (RED); secret-sentinel test — the krbtgt/service key and the ccache
  path never appear in the serialized receipt; the domain-SID auto-resolve fails safe (unknown, not
  fabricated). Composition: **DCSYNC → GOLDEN** is a found path where GOLDEN is applicable only
  because DCSYNC produced a usable `KRBTGT` (mirror `test_chain_lateral_t3.py`'s non-vacuous shape);
  a valueless/placeholder krbtgt never establishes the forge. `S_PERSISTENCE` added to the state
  tests. New harness facet entries get their own RED (fabrication guard on a non-vulnerable target).
- Gate: the full validation suite stays green.

## Phase 8 — Proof plan (live on GOAD)
1. Individual via `validate run`: GOLDEN (krbtgt from a DA DCSync of essos/north), SILVER (a machine
   account's hash), DIAMOND & SAPPHIRE (`-request` with a non-DA operator + the krbtgt AES key) →
   receipt → harness `proved`. Shred every ccache/pfx; copy back only the receipt.
2. Composition via `validate chain --goal S_PERSISTENCE`: DCSYNC → GOLDEN live (reuses the merged
   DCSYNC NetBIOS-qualified krbtgt), `reached + escalation + clean`.
3. Secrets: the krbtgt hash and forged tickets NEVER reach a receipt/report (presence-only).

## Harness (ad-lab-harness, separate worktree)
Add 4 T4 facet entries to `GOAD-proof.json` (`class: kerberos_forge`, `terminal: authn_success`,
`mutating: false`, `vulnerable` keyed per each executor's `target_identity`). No scorer change
needed (non-mutating → no rollback guard; `S_PERSISTENCE` is a purplesploit-side state, not a
scorer concept). Reviewed truth only.

## Delegation split (codex-interop)
- Plan + design (this doc): Claude (Opus). **Cross-family plan review by Codex Sol** before build.
- Build (`forge_common.py` + 4 executors + states `S_PERSISTENCE` + engine edges + non-vacuous
  tests + harness facet): **Codex Sol** in a worktree; Claude reviews the diff, runs the gate,
  proves live, integrates.
- Live proofs + harness scoring + portability audit: Claude on GOAD (kali-vr).

## Open decisions (resolved)
- Terminal/eff = `S_PERSISTENCE` (not bare `S_DA`) so the forging edges add real graph value.
- Linux/impacket toolchain (no Rubeus) — verified; Diamond/Sapphire via `ticketer -request`.
- Silver's key source is a service/computer hash (operator-supplied or a prior edge), not krbtgt.

## Plan-review resolutions (Codex Sol r1, 26NOV2026 — FIX-FIRST, 3 BLOCKER + 6 HIGH)
Review: `docs/reviews/PLAN-T4-26NOV2026-codex-sol-plan-review-r1.md`. All verified by the supervisor
(B1 params_preview serializes value+recommended; B3 goal-check reaches a base-state goal from `eff`
alone with an empty store; B2 nxc predicate is the generic `SMB…[+]`).

| # | Finding | Resolution | Stage |
|---|---------|-----------|-------|
| B1 | secret params leak via `params_preview` (value+recommended) | signing keys are NOT ParamSpecs — they arrive via a private, presence-only channel (threaded `KRBTGT` cap, or an env/`--key-file` operator input, never argv/preview). Add a secret-kind that `params_preview` masks. Sentinel test over every serialization (receipt/report/preview/prompt/errors). | T4a |
| B2 | reauth may use an inherited/stale ticket; nxc `[+]` matches non-login diagnostics | forge with `KRB5CCNAME` UNSET + a fresh per-run dir; require a newly-created, parseable ccache with the expected principal/realm(/service); reauth ONLY through that cache (`nxc … --use-kcache`, no operator creds); match the actual cache-backed login line for the bound identity; `Pwn3d` proves only that host's admin, never `S_DA`. Shred the ccache on every path. | T4a |
| H6 | Sapphire inputs insufficient (needs both signing-key + requester `-password`; `-user` → Principal; `-user-id` default 500) | pin Sapphire's ACTUAL required inputs live; pass requester name separate from domain; resolve/bind the impersonated account's real RID; filter chains lacking the inputs. | T4a |
| H7 | SID auto-resolve: "a SID present" ≠ the domain SID | bind `lookupsid` to the intended domain/DC, select the domain-SID explicitly, parse the full domain SID; missing/malformed/ambiguous/mismatched → unknown, no fabrication; operator override always available. | T4a |
| H8 | Silver is service-scoped, not persistence; SMB predicate can't validate arbitrary SPNs | Silver emits its cache under a SERVICE-ACCESS effect (not `S_PERSISTENCE`); restrict this tranche to `cifs/<host>` (SMB-validatable) or add protocol adapters; `chain_pre={cred_for(service_account)}`. Bound Golden's persistence meaning by ticket lifetime + krbtgt validity (not "survives resets"). | T4a (scope) / T4b (edge) |
| H9 | listed negatives don't defeat an impl that SKIPS forging (auths via an ambient cache) | fake auth-success is CONDITIONAL on the forge having created the EXACT `KRB5CCNAME` cache; assert the consumed signing key + ordered calls; a no-op forge must FAIL the positive; add stale-cache/wrong-identity/auth-only/placeholder-key/failed-reauth/missing-goal controls, scored through the real harness. | T4a |
| B3 | engine reaches a base-state goal from `eff` alone (no capability/terminal) | `S_PERSISTENCE` is a CAPABILITY-BACKED goal: the goal-reached check must require the produced capability in the store for it (like `cred:`/`control:`), and `produced()` emits it ONLY on reauth success. `S_DA` (terminal, reached by a completing DCSYNC) keeps its current semantics. | T4b |
| H4 | `pre={KRBTGT,S0}` is OR → seed-runnable; `accepts_*` isn't auto-wired | `chain_pre={KRBTGT}` only; the live requester cred (Diamond/Sapphire) is validated separately at EXECUTION (deferred, not a pre-resolved required param); wire key acceptance into `_consume`/execute (channel + key format + placeholder rejection + principal/domain binding); composed exec never substitutes an operator key for an absent/invalid produced key. | T4b |
| H5 | live escalation needs a front; no special DCSYNC→GOLDEN planning link | the distinct `S_PERSISTENCE` goal makes DCSYNC→GOLDEN discoverable already. Prove a real FRONT→DCSYNC→GOLDEN from the default seed; add a given-key control (no escalation provenance) + a missing-product control (GOLDEN never runs despite an operator key). | T4b |
