# PLAN-SHARELOOT — SMB + NFS share discovery / crawl / loot-search — 27NOV2026

The first **joint Windows/Linux** module. Supersedes `BACKLOG-27NOV2026-smb-nfs-share-loot-search-module.md`.
Methodology: dev-methodology full cycle. **Status: PLAN — awaiting design sign-off before build.**

## Phase 0 — Frame
- Project `purplesploit` (`/srv/share/dev/purplesploit`), base **`1bf7a81`** (main after DNSHARDEN).
- CLAUDE.md: `jeremylaratro` authorship, no attribution, local tests are the gate, no CI.
- Package root `python/purplesploit/validation/`; executors follow the `ValidationExecutor` pattern.

## Phase 1 — Objective + gap analysis (evidence-based, base `1bf7a81`)
**Objective:** given a target scope, **exhaustively** (1) discover SMB **and** NFS shares, (2) access
them **read-only** (crawl/mount-ro), (3) search contents for interesting info + credentials, emitting
ranked, deduplicated, **presence+location** findings — recovered secret VALUES go to the operator's
out-of-band store, never a stored receipt. Dual-mode: standalone (`validate run`) AND composable
(a looted credential feeds a downstream engine edge). Read-only; portable; clear diagnostics.

| ID | Type | Evidence | Prov |
|----|------|----------|------|
| **S1** | gap | SMB share **discovery** exists only as `OpenSharesProbe` (`nxc smb --shares`, read-only) + `OPENSHARES-WRITE` (a single-share MUTATING canary write). No multi-host enum, no **crawl/listing of contents**, no recursive spider. | measured |
| **S2** | gap | **NFS: nothing.** `grep -rln "nfs\|showmount\|rpcinfo"` over validation/ → empty. Greenfield. | measured |
| **S3** | gap | **No loot/secret-search engine.** No rule pack, no file-content search, no credential detection over files. | measured |
| **S4** | gap | No cross-OS (Windows+Linux) module exists — the toolchain is AD/Windows-only. This is the first. | measured |
| **S5** | reuse | DNSHARDEN `netresolve` (just merged) gives portable host/KDC resolution the crawl should route through. The `ValidationExecutor` dual-mode + `Capability` threading + proof.v1 receipts are reusable. | measured |

## Phase 2 — Triage
All `now`, one module, 4 sprints. **Out of scope (declared):** exploitation of looted creds inside this
module (that's the downstream engine edge); writing to any share; non-SMB/NFS protocols (FTP/WebDAV);
AV/EDR evasion; destructive actions. Read-only is absolute.

## Phase 3 — Sprint split (proposed)
- **S1 — SMB discovery + read-only crawl.** Multi-host share enum (`nxc smb --shares` / per-host),
  then read-only recursive listing + file fetch to a scratch dir (smbclient / nxc `--spider`-style).
  No write ever. Branch `dev/shareloot-s1`.
- **S2 — NFS discovery + read-only access.** `showmount -e` / `rpcinfo`; read-only crawl (mount-ro
  where privileged, else list). Greenfield.
- **S3 — the loot search engine.** Pluggable rule pack (regex + filename/path + file-type signatures),
  size/time bounds, binary-aware, a secrets rule pack. Findings = presence + location (ranked, deduped);
  any recovered secret handled **presence-only** in receipts (value → operator out-of-band store).
- **S4 — dual-mode integration + live proof.** Expose the module standalone AND as an engine edge
  (a looted credential → a downstream `cred:*` capability). Prove on GOAD (owned shares).

## Phase 4/5 — Design (DRAFT — the open forks are below, for sign-off)
- **Module shape:** a cohesive `share_loot` capability with stages discover → access(read-only) →
  search, emitting `proof.v1` receipts (presence+location findings) and, on a real credential hit, a
  typed `Capability` (e.g. `cred:nt_hash` / `cred:password` / principal) for the engine to thread.
- **Access engine:** SMB via `smbclient`/`nxc`; NFS via `showmount` + read-only `mount`/crawl. Route
  host resolution through `netresolve` (portable). A scratch dir per run, shredded after; only the
  **findings receipt** persists.
- **Search engine:** a rule pack of (name/path globs, content regex, file-type signatures) + a curated
  **secrets pack** (`.kdbx`/`.ppk`/`id_rsa`/`unattend.xml`/`web.config`/`.env`/connection strings/
  cloud tokens/"password"-shaped). Size/time bounds; binary-aware; ranked + deduped hits.
- **Integrity:** read-only; unreachable/denied share → explicit `inconclusive`, never a fabricated hit;
  recovered secret value never in a stored receipt (presence + location only).

### Open design decisions (need sign-off before build)
1. **Access method default** — crawl-only (smbclient/nxc fetch to scratch; no OS mount; most portable,
   no root) **vs** mount read-only (mount.cifs / mount -o ro,nfsvers; faster for big trees, needs
   privilege). Recommend: crawl-only default, mount opt-in.
2. **Loot rule-pack aggressiveness** — curated secrets-first pack (high signal, fewer FPs) **vs** broad
   (all "interesting" file types + PII + large-file heuristics; exhaustive but noisier). Recommend:
   curated secrets-first in S3, broad pack as an opt-in rule set.
3. **Build order** — SMB first then NFS (ship value fast on the AD lab) **vs** both in parallel.
   Recommend: SMB first (S1), NFS next (S2), since the GOAD lab is SMB-rich.
4. **Secret-value handling** — presence+location only in receipts, value copied to an operator
   out-of-band store path (operator-configured), shredded from scratch. (This matches the toolchain's
   standing secret rule; confirming it applies here.)

## Phase 7/8 (to finalize at plan sign-off)
Test plan + benefit metric drafted per sprint after the design is confirmed (e.g. S1 benefit =
shares discovered + files crawled + secrets found on an owned GOAD share, scored against a seeded
truth). Peer-reviewed (Codex Sol) before build, per methodology.
