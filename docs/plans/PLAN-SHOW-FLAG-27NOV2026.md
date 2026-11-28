# PLAN — `--show-flag`: opt-in live secret reveal (terminal-only) for all techniques (27NOV2026)

**Status:** DRAFT → design review FOLDED (Codex r1, rev 2 below)
**Supersedes framing:** this is **Phase 0 (reveal mechanism) + Phase 1 (capture)** of
[ADR-003](../adr/ADR-003-27NOV2026-universal-credential-producers-and-autopwn.md). F2's per-technique
capture is realized as the **universal `Credential` producer** (one capture → three consumers:
reveal / manual store / automated chaining), captured at recovery time (pre-cleanup, all branches),
NOT a reveal-only stash. Build F1 (reveal sink + hook + CLI + invariant gate) first; build F2 as the
producer contract.
**Path:** full cycle (cross-cutting: base.py contract + CLI + every secret-recovering executor;
touches the core secret invariant → peer-reviewed design mandatory)
**Repo:** `purplesploit` — base `main` @ f381145
**Owner directive (HIGH):** "a flag to print the secrets, for all techniques. In CTFs, showing the
flag or using the cred is required to win. add `--show-flag` to print the secret/cred/etc."

## Objective

Let the operator OPT IN (`--show-flag`) to see the actual recovered secret (NT/AES hash, cleartext
password, krbtgt key, looted cred, GPP cpassword, LAPS password, impersonation ticket, CTF flag)
for every technique — printed to the **live terminal only** — while the stored receipt,
proof_token, written receipt files, memory, and peer/agent prompts stay **secret-free exactly as
today**. Default (no flag) behavior is unchanged.

## The invariant this must NOT break

Secrets are deliberately discarded today: `_receipt_from` drops `_`-prefixed engine-only keys and
`proof.scrub()` drops any secret-marker key, so the `proof.v1` receipt holds only public
identifiers + non-secret predicates. `Capability.value` (secret-channel) is "runtime only — NEVER
serialized." `--show-flag` must preserve ALL of this: it only adds a **separate terminal print**,
never a new field in any persisted artifact.

## Design (rev 2 — folds Codex leak-path review r1)

1. **Terminal-only sink (Codex BLOCKER #1).** Revealed secrets are written to the controlling
   terminal **`/dev/tty`**, NOT stdout/stderr. If `/dev/tty` cannot be opened (output redirected,
   no controlling terminal, run by an agent/CI), the reveal is REFUSED: print a one-line notice to
   stderr (`--show-flag suppressed: no interactive terminal`) and reveal nothing. This defeats
   `--show-flag > run.log` capture AND keeps secrets out of an agent's tool transcript/prompts.
2. **Reveal hook (base.py):** `revealed_secrets(artifact) -> list[SecretReveal]`
   (`SecretReveal = {technique, kind, principal, value}`), reading ONLY from `_`-prefixed
   engine-only artifact keys the executor stashed. It does NOT derive from `produced()` (that path
   is composed-only and post-cleanup — Codex #3/#4). Default returns `[]`.
3. **Capture at recovery time (Codex #3/#4) — the core correction.** Each secret-recovering
   `execute()` stashes its secret under a `_reveal`-style `_`-prefixed key **the moment it is
   recovered — BEFORE any ticket/key destruction, on BOTH the standalone and composed branches,
   and REGARDLESS of whether the downstream proof (local-admin, nxc access) later succeeded.**
   Capture is unconditional (the in-memory artifact is never serialized); `--show-flag` gates only
   the display. This replaces the broken "derive from produced()" default.
4. **Runtime handoff (Codex #2) — must NOT go through the report dict.** `scrub()` only drops
   secret-MARKER keys, not `_`-prefixed keys, and the report writers (`json.dump`,
   `write_receipt`, `chain-report.json`) do not reject underscore keys — so the artifact must
   NEVER be embedded in the returned report. Instead add a dedicated path, e.g.
   `run(...) -> receipt` unchanged PLUS `reveal(ctx, finding, params, artifact)` surfaced through a
   separate return value or a sink callback the CLI owns. The CLI serializes ONLY the receipt and
   sends reveals straight to the `/dev/tty` sink.
5. **CLI (`--show-flag`):** `ValidationConfig.show_flag: bool = False`; add `--show-flag` to the
   shared parser. On every run path (run / chain / pipeline / discover --exploit), when `show_flag`,
   collect `revealed_secrets()` and emit to the `/dev/tty` sink:
   ```
   ⚠  --show-flag: LIVE SECRETS — terminal only, NOT in any receipt/log  ⚠
     [DCSYNC]  nt_hash  krbtgt  <value>
   ```
6. **Hard rule:** `revealed_secrets()` is called ONLY in the CLI display path — NEVER in
   `_receipt_from` / `build_receipt` / `write_receipt` / `chain-report.json` / memory / peer paths.
7. **Invariant scope (Codex #7).** `--show-flag` introduces **no NEW persisted secret** and leaves
   the receipt/proof_token clean. Pre-existing operational files (SHARE-LOOT loot-store JSON,
   roast hash/pot files) exist today regardless of this flag and are the operator's
   access-controlled working files — OUT OF SCOPE for this change. The invariant targets the
   receipt/report/token, not "nothing anywhere on disk."

## Sprint map

### F1 — mechanism + producer coverage
`SecretReveal` type + `revealed_secrets()` hook (default from `produced()`) in base.py; `show_flag`
config field; `--show-flag` CLI wiring; the terminal display in every run path. Immediately covers
all techniques that already emit secret-channel capabilities.

### F2 — non-producer coverage (owner: EVERY technique, no exceptions)

Audit ALL 30 techniques. Each either reveals its recovered secret via `--show-flag` or, if it
recovers none (a pure ACL/write/detection primitive), `revealed_secrets()` returns `[]` by design.
Authoritative inventory (the build confirms each against the executor source):

| Technique | Secret to reveal | Covered by |
|-----------|------------------|-----------|
| DCSYNC | krbtgt key + every dumped NT/AES hash | F1 produced() + F2 (full dump list) |
| SHARE-LOOT | looted creds / GPP cpassword / file secrets | F1 produced() |
| GENERIC-ALL | recovered NT hash (`_recovered_hash`) + ticket | F1 + F2 (the hash) |
| BRONZE-BIT / S4U2SELF / CONSTRAINED-DELEG-PT | impersonation ccache/ticket | F1/F2 |
| CERTIFRIED / ESC8 / ESC11 | DC TGT (ccache) | F1 produced() |
| GOLDEN / SILVER / DIAMOND / SAPPHIRE-TICKET | forged ticket (ccache) | F1 produced() |
| ADCS-ESC1 | PKINIT-recovered NT hash | **F2** (`_recovered_hash`) |
| KERBEROAST / ASREP / TARGETED-KERBEROAST | crackable hash **and** cracked plaintext | **F2** |
| LAPS | recovered local-admin password | **F2** |
| SHADOW-CREDS | PKINIT-recovered NT hash | **F2** |
| FORCE-CHANGE-PASSWORD | the new password it set | **F2** |
| NTLM-RELAY (smb_sam) | the dumped SAM hashes (loot file content) | **F2** (read loot file) |
| UNCONSTRAINED-DELEG | captured TGT + any DCSync'd secret | **F2** |
| ADD-MEMBER, WRITE-DACL, WRITE-OWNER, GPO-ABUSE, OPENSHARES-WRITE, RBCD, COERCION, SIGNING-RELAY(detect) | — none (write/detection primitive) | `revealed_secrets()` → `[]` |

Every secret-recovering `execute()` stashes under a `_`-prefixed engine-only key; each technique
gets a test (reveals the seeded secret, and the no-secret ones assert `[]`).

## Test plan (the security-critical gates)

- **(a) regression:** full suite stays green (no behavior change when `--show-flag` is absent).
- **(b) new behavior, per secret-recovering technique:** with `show_flag=True`, `revealed_secrets()`
  returns the seeded secret with the right kind/principal; the CLI display contains it.
- **(c) INVARIANT gate (RED-provable, the whole point):** with `show_flag=True`, seed a sentinel
  secret and assert it appears in the terminal display BUT is ABSENT from: the receipt dict, the
  JSON-serialized receipt, `proof.write_receipt` output on disk, and the proof_token. Mutate: if a
  secret ever lands in the receipt, this test goes RED. Also assert `show_flag=False` reveals
  nothing anywhere. Vary the secret payload and assert proof_token invariance.

## Delegation (codex-interop, Codex-heavy)

Design review FIRST (leak-path audit — this touches the secret invariant), then Codex Sol
implements F1 then F2 in a worktree; Claude reviews the diff + runs the invariant gate itself.
Secret rules + no-attribution restated in every brief.

## Risks

- **Leak via a new path** (the display code accidentally mutating the receipt, or revealed_secrets
  called in a persisted path) — the (c) invariant gate is the guard; peer-review the design for it.
- **Secret in the in-memory artifact** — acceptable (artifact is never persisted; only the scrubbed
  receipt is), but F1 must confirm no code serializes the raw artifact.
- **TUI** — out of scope here (CLI flag); the TUI reveal rides the later TUI-bridge sprint.
