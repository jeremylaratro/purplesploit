# NEXT STEPS — execution handoff (27NOV2026)

Resume point for the purplesploit AD-validation effort. Everything needed to continue without the
authoring session. **Read `docs/adr/ADR-003-27NOV2026-*` first** (the north-star + roadmap).

## Landed state (main @ cd68e1f or later)

- **R1 (PR #147):** NTLM-RELAY coercion→`coercer` routing, SMB-only listener, honest 5-state
  classifier, per-mode `proven` map, secret guards. 567 tests.
- **R2 (PR #148):** operator `external_listener` + SIGNING-RELAY action verbs
  (detect|escalate|shell|crawl|dump), channel-gated, SHARE-LOOT crawl chaining. 620 tests.
- **Docs (PR #149, #150):** relay plans, ADR-003 (universal producers + autopwn), show-flag plan
  (Codex leak-path review folded), ADCS T2 plan.
- Relay-actionable effort (R1+R2) is COMPLETE. Live note: in-process listener catch is unreliable
  on the host-network container; the operator-external-listener path is the supported route.

## Execution queue (ordered; status)

| # | Work | Doc | Status |
|---|------|-----|--------|
| 0 | `--show-flag` reveal mechanism | PLAN-SHOW-FLAG (rev 2) | **NEXT — spec below** |
| 1 | Universal `Credential` producer (= show-flag F2, all techniques) | ADR-003 Ph1 | after Ph0 |
| 2 | Credential store + manual multi-identity use | ADR-003 Ph2 | queued |
| 3 | Identity re-scope everywhere (discover/recon/executors) | ADR-003 Ph3 | queued (the lift) |
| - | ADCS T2 (ESC2-7/9/10/13/15/16 + Golden-Cert) | PLAN-ADCS-T2 | independent; interleave |
| 4 | Autopwn driver (greedy, safety-fenced) | ADR-003 Ph4 | queued |
| - | Auto ligolo-ng setup + agent dispersal | BACKLOG | after Ph4 |
| 5 | BloodHound-optimal pathing | ADR-003 Ph5 | queued |

## Phase 0 — `--show-flag` (execution-ready spec)

Build order within Phase 0 (one worktree, mirror ESC1/R1 conventions):
1. **`SecretReveal`** dataclass + **`revealed_secrets(artifact) -> list[SecretReveal]`** hook on
   `ValidationExecutor` (base.py). Default `[]`. Reads ONLY `_`-prefixed engine-only artifact keys.
2. **Terminal-only sink:** write reveals to **`/dev/tty`**; if it can't be opened (redirected / no
   tty / agent-run) REFUSE — one-line stderr notice, reveal nothing. (Codex BLOCKER: plain stdout
   leaks to `> run.log` and agent transcripts.)
3. **`ValidationConfig.show_flag: bool = False`** (config.py) + **`--show-flag`** on the shared CLI
   parser (cli.py), mirroring `--allow-destructive`.
4. **Runtime handoff — NOT via the report dict** (`scrub()` keeps `_` keys; writers don't reject
   them). Add a dedicated return/sink so the CLI gets the artifact's reveals while serializing ONLY
   the receipt. Wire the sink into run / chain / pipeline / discover paths.
5. **Reference capture+reveal for 3 techniques** proving all secret shapes: DCSYNC (producer/hash),
   LAPS (non-producer/password), KERBEROAST (non-producer/cracked hash+plaintext). Capture **at
   recovery time, pre-cleanup, on standalone AND composed branches, regardless of proof success.**
6. **Invariant gate test (the point):** sentinel secret originates in FAKE tool output, traverses
   the REAL dispatch path; assert it reaches the tty-sink BUT is ABSENT from: receipt dict, JSON
   dump, `write_receipt` on disk, `chain-report.json`, and `proof_token`. Assert the no-tty REFUSAL
   reveals nothing. Vary the secret payload → `proof_token` byte-invariant. (Must go RED on a real
   leak; not a mocked-hook comparison.)

**Invariant (unchanged):** receipt / proof_token / write_receipt / chain-report / memory / peer
paths stay secret-free. `revealed_secrets()` is called ONLY in the CLI display path. Pre-existing
operational files (loot-store JSON, roast hash/pot files) are out of scope — do not claim "nothing
on disk."

## Phase 1 — Universal `Credential` producer (next dispatch after Ph0 verified)

Standardize the Ph0 capture as the `Credential` capability (ADR-003 schema) and roll it out to
EVERY secret-recovering technique (capture→produce→reveal unified). Per-technique inventory is in
PLAN-SHOW-FLAG F2 + ADR-003. No-secret primitives (ADD-MEMBER, WRITE-DACL/OWNER, GPO-ABUSE,
OPENSHARES, RBCD-write-only, COERCION, SIGNING-RELAY detect) produce nothing. Each technique gets a
reveal test; the invariant gate re-runs across all.

## How to resume / verify a Codex dispatch

1. Worktree: `git -C <repo> worktree add .claude/worktrees/codex-<task> -b codex/<task> origin/main`;
   baseline `python -m pytest tests/unit/validation -q` from `python/` (expect 620+).
2. Codex brief + launch: `~/.claude/skills/codex-interop/scripts/peer.sh run --family codex
   --tier bulk --role implement --cd <worktree> --out <OUT> --prompt-file <brief>` (background).
3. On return: run the suite YOURSELF, review the diff, **run the invariant gate** (the security
   gate — verify a seeded secret never reaches the receipt/token), check no attribution, then
   commit (author `jeremylaratro`, no Claude trailers), PR, rebase-merge, cleanup worktree.

## Dispatch status (this session)

- If Phase 0 was dispatched to Codex Sol this session, its brief is at
  `/tmp/codex-out/showflag-ph0-brief.md` and output path recorded in
  `/tmp/codex-out/.showflag-ph0-out-path`. Verify per "How to resume" before landing.
