# PLAN — ADR-003 Phase 3: identity re-scope via `--as-cred` (27NOV2026)

**Status:** ready to implement (Sol high)
**Implements:** ADR-003 Phase 3 (identity re-scope). **Base:** main @ e1a5dd3 (Phase 1 producer +
Phase 2 store landed).

## Key simplification

The ADR anticipated a pervasive per-executor refactor. It isn't needed: `discover`, `recon`, and
every executor resolve their auth identity from the **`ValidationConfig`** (`username` / `password`
/ `nt_hash` / `aes_key` / `domain`). So identity re-scope = **swap the config to a stored
credential** and the entire command runs as that identity, including `discover` re-scanning "from
the new user's perspective." One mechanism, no executor edits.

## Objective

`--as-cred <selector>` resolves a credential from the Phase 2 store and runs the command
(run / discover / chain / pipeline) AS that identity — the manual autopwn primitive
(gain a cred → `discover --as-cred <it>` → see the next hop). The autopwn DRIVER that loops this is
Phase 4; here it is operator-directed, one command at a time.

## Design

1. **`--as-cred <selector>`** on the shared CLI parser. `<selector>` is a PUBLIC identifier —
   `principal` or `principal@domain` (or a stable store index). Never the secret.
2. **Resolve** against the credential store (Phase 2). Missing/ambiguous → a clear error, no run.
3. **Derive a re-scoped config** (`dataclasses.replace` on the base config):
   - `username = cred.principal` (machine accounts keep the trailing `$`)
   - `domain   = cred.domain` (fallback to base `domain`)
   - the secret field BY `secret_type`: password→`password`, nthash→`nt_hash`, aeskey→`aes_key`;
     ccache→set `KRB5CCNAME` in the run env (no ccache config field); pfx→(skip / not an auth cred here).
   - **clear the other secret fields** so only the gained cred authenticates.
   - keep `dc_ip`, `extra_targets`, `output_dir`, timeouts, etc.
4. **Apply** the derived config to the chosen command. Print a one-line banner naming the active
   identity (`now acting as <principal>@<domain> [source: <technique>]`) — public, no secret.

## Test plan

- `--as-cred <principal>` resolves + derives a config with the right username/domain and the secret
  on the field matching `secret_type`; other secret fields cleared; ccache sets `KRB5CCNAME`.
- `discover`/`run --as-cred`: the probes/executor see `cred.principal` as the identity (not the
  operator's) — assert via a fake runner capturing the resolved auth.
- Unknown/ambiguous selector → error, no config change, no run.
- Base behavior unchanged when `--as-cred` is absent.
- Secret safety: the derived config's secret never reaches a receipt / proof_token / log; the
  `--as-cred` selector and the banner carry only public identifiers.
- Regression: full suite green (baseline 1124).

## Delegation

Claude plans + reviews + runs the leak gate; **Sol (high)** implements. Secret rules + no-attribution
restated in the brief.

## Risks

- **Secret-type → config-field mapping** must be exact (a wrong field silently fails auth). Covered
  by per-type tests.
- **Machine-account principals** (`HOST$`) + realm handling — test one.
- Re-scoping must be a DERIVED config, never mutate the base (keep operator identity intact for
  other commands).
