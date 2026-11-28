# PLAN — ADR-003 Phase 2: session credential store + list/reveal (27NOV2026)

**Status:** ready to implement (Sol high)
**Implements:** ADR-003 Phase 2 (credential store; manual use). **Base:** main @ b06d576 (Phase 1
Credential producer landed — every secret-recoverer produces a standardized `Credential`).

## Objective

Collect every produced `Credential` into a session/engagement **credential store** the operator can
list and (with `--show-flag`) reveal — so gained creds (user:password, machine:hash, ticket)
accumulate in one place across runs. This is the operator-visible vault + the frontier source the
autopwn loop (Phase 4) will consume. **Identity re-scope / running techniques AS a stored cred is
Phase 3 — NOT here.** Here: collect, persist (securely), list, reveal.

## Design (mirror the proven `share_loot` loot-store)

1. **`CredentialStore`** (new module): persists collected `Credential`s to a 0600 engagement file,
   created `os.open(..., O_CREAT|O_EXCL, 0o600)` + `json.dump`, path from
   `cfg.cred_store_dir`/`cred_store_file` else `output_dir/cred-store/creds.json` — EXACTLY the
   secret-handling share_loot uses for its loot-store. Each entry: `principal, domain, is_machine,
   secret_type, source_technique, value, first_seen`. Dedup by `(principal, domain, secret_type)`.
2. **Collection:** after each edge runs on the run / chain / pipeline / discover paths, the CLI
   gathers that edge's produced `Credential`s (secret-channel caps) and upserts them into the store.
   Gate collection behind a config flag (`cfg.collect_creds`, default ON for these commands) so it
   can be disabled.
3. **CLI `creds` command:** `creds list` prints store entries as METADATA ONLY by default
   (principal, domain, secret_type, source_technique, first_seen — NO value); values are shown ONLY
   with `--show-flag`, routed through the EXISTING `/dev/tty` reveal sink (reuse `reveal_to_terminal`
   + `SecretReveal`). Add `creds clear` (wipe the store). 
4. **Secret invariant:** the store file holds secrets and is the operator's access-controlled
   working file (0600) — the SAME boundary as the existing loot-store; it is OUT OF SCOPE of the
   receipt invariant. BUT: store values must NEVER reach a receipt / proof_token / chain-report /
   claude-mem, and `creds list` without `--show-flag` must print NO secret.

## Test plan

- Store collects a produced Credential after a real `run`; dedup on repeat; `creds clear` empties it.
- Store file mode is `0600`; file created with `O_EXCL` (mirror share_loot test).
- `creds list` default output contains the metadata but NO secret value; with `--show-flag` the
  value goes to the (fake) reveal sink, not stdout.
- Invariant: a seeded credential value never appears in any receipt / proof_token / chain-report;
  `--show-flag` invariant gate still green.
- Regression: full suite stays green (baseline 1098).

## Delegation

Claude plans + reviews + runs the invariant/leak gate; **Sol (high)** implements in a worktree.
Secret rules + no-attribution restated in the brief.

## Risks

- **New persisted-secret surface (the store file).** Must mirror share_loot EXACTLY (0600, O_EXCL,
  operator-only) and never widen beyond it; never into the receipt/token/claude-mem.
- Collection must not alter receipts or the default (non-show-flag) output — gated + metadata-only.
