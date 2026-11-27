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

### Design decisions (RESOLVED — owner sign-off 27NOV2026)
1. **Access method = BOTH, operator-selectable.** A `share_access_mode` config field selects `crawl`
   (default: smbclient/nxc read to a scratch dir; no OS mount, no root) or `mount` (read-only
   `mount.cifs`/`mount -o ro`; faster on big trees, needs privilege). Both built in S1 (SMB); the
   access layer is OS-generic so S2 (NFS) reuses it.
2. **Loot pack = curated secrets-first** (S3): high-signal, low-FP (id_rsa/.ppk/.kdbx/.pfx/
   unattend.xml/web.config/.env, connection strings, cloud tokens, "password"-shaped). A broad pack
   ships later as an opt-in rule set.
3. **Build order = SMB first, then NFS.** S1=SMB discover+access, S3=loot engine, S4=dual-mode+proof;
   **S2 (NFS) comes after** S1 on the SMB-rich GOAD lab (sprint order S1→S3→S4, then S2, or S2 folded
   before S4 — decided at S1 close).
4. **Secret-value handling = presence+location only** in receipts (standing toolchain rule); a
   recovered secret value goes to an operator-configured out-of-band store and is shredded from
   scratch. Proof tokens over PUBLIC identifiers (host/share/path) only.

## Phase 4/5 — S1 design (SMB discover + read-only access)
New `share_loot.py` → `ShareLootExecutor` (technique `SHARE-LOOT`, class `share_loot`,
`mutating=False`, read-only). Stages run in one `execute()`: **discover → access → (search=S3 no-op)
→ shred**. S1 delivers discover + access (a crawled file **inventory** — paths/sizes, which are
location, not content); the content search is S3.

- **Discover:** per in-scope host, `nxc smb <host> <auth> --shares` (auth + `netresolve` discovery
  flags reused), parse share names + read/write perms; READ-capable shares proceed. Unreachable/denied
  → `inconclusive` diagnostic (via `netresolve.classify_resolution_failure` where resolution-shaped),
  never a fabricated share.
- **Access (read-only), mode-selected:**
  - `crawl` (default): `smbclient //host/share -c 'recurse ON; ls'` to list, then bounded `get` of
    candidate files into a per-run scratch dir. Never `put`/`rm`/`mkdir`.
  - `mount`: `mount -t cifs -o ro,guest|creds //host/share <mnt>` → `os.walk` read-only → `umount`.
    Guarded: mount only under a dedicated mountpoint; always unmount in a `finally`; `-o ro` enforced.
  - Bounds: max files, max bytes/file, max depth, timeout — all config, so a huge tree can't hang.
- **Receipt:** `proof.v1` with a terminal fact `shares_enumerated` (ok = ≥1 readable share crawled),
  steps (discover/access), and a public inventory (host, share, path, size — NO content). Scratch
  shredded on every path.
- **Read-only guarantee (the core invariant):** the executor NEVER emits a write/delete/mkdir verb.
  A unit test asserts no mutating smbclient/mount verb is ever in any built argv.

## Phase 7 — S1 test plan (non-vacuous)
- Discover: a scripted `nxc --shares` output → parsed share set + perms; a denied/unreachable host →
  `inconclusive` with a diagnostic, not a fabricated share.
- Access crawl: a scripted smbclient listing + gets → the inventory lists exactly the crawled files;
  bounds enforced (a file over the cap is skipped and logged, not fetched).
- Access mount: a fake runner records `mount -o ro` then `umount` (always, even on crawl error);
  `-o ro` present; no write verb.
- **Read-only invariant:** across every code path, assert no `put`/`rm`/`mkdir`/`rmdir`/rw-mount verb
  is ever built (the central safety gate — shown able to go RED by a mutant that adds one).
- Scratch shredded; receipt carries no file content.

## Phase 8 — S1 benefit (pre-registered)
On an owned GOAD host with a seeded readable share: count shares discovered + files crawled into the
inventory (vs baseline = no such capability). Measured live on kali-vr against an owned share; scored
against a small seeded truth (expected shares/files). Read-only confirmed (share contents unchanged;
no canary written).

## Delegation (codex-interop, ~60/40)
Plan: Claude. **Plan review (Phase 5 gate): Codex Sol.** S1 impl: Claude → Codex reviews diff.
Live proof: Claude (GOAD).

## Plan-review resolutions (Codex Sol r1, 27NOV2026 — FIX-FIRST, 2 BLOCKER + 5 HIGH)
Review: `docs/reviews/PLAN-SHARELOOT-27NOV2026-codex-sol-plan-review-r1.md`. All verified against code
and the NetExec/smbclient docs. The review reshaped S1's design — the safe design below replaces the
draft above.

| # | Finding (verified) | Resolution |
|---|--------------------|-----------|
| 1 BLOCKER | `nxc smb --shares` CREATES+DELETES a write-probe file/dir unless `--no-write-check` — bare discovery would VIOLATE read-only. The argv invariant test stays GREEN while nxc mutates internally. | **Discovery is read-only by construction:** enumerate shares with `smbclient -L` (lists, never writes); read-perm is inferred from a read-only `ls` attempt. If NetExec is ever used it MUST carry `--no-write-check` behind a verified-version gate (fail closed otherwise). A live read-only assertion (seed a canary on the share out-of-band; confirm it is unchanged + no new files after a run) backstops the argv test. |
| 2 BLOCKER | Interpolating server-controlled filenames into `smbclient -c 'get <file> <local>'` crosses smbclient's `;`-separated command parser → command injection; mount `-o ro` does not confine symlink targets. | **Crawl via a PROGRAMMATIC SMB client** (impacket `SMBConnection` list/read) — no `smbclient -c` string, so no shell/command-parser interpolation. Local destinations are **opaque content-addressed names** (never server names). Mount mode walks with `follow_symlinks=False` + realpath-containment (reject any entry resolving outside the mountpoint). No remote delete, ever. |
| 3 HIGH | `umount` in `finally` isn't enough (EBUSY, timeouts, cleanup exceptions); never recursively shred an attached mount; cleanup failure must block clean-success. | Track mount ownership; verify unmount (re-check `/proc/mounts`); **scratch cleanup is independent of unmount** and runs regardless; shred targets ONLY the scratch dir after confirming it is not (and does not contain) the mountpoint; any cleanup/unmount failure → the run is `inconclusive`, not clean-success. |
| 4 HIGH | Bounds don't bound real consumption (aggregate bytes, entry count, listing size, whole-run deadline; empty-dir farm; file grows between list↔fetch; cycles). | Enforce limits **during** traversal/transfer: aggregate scratch-byte cap, entry-count cap, per-read byte cap (stop mid-file at the cap), max depth, cycle/visited-inode detection, and a **whole-run deadline**. Hitting any bound → an explicit `partial` result, never a silent truncation. |
| 5 HIGH | A filename/path can CONTAIN a secret; the proof scrubber filters field NAMES not path VALUES — raw paths in receipts/tokens/diagnostics would leak. | **Opaque location IDs** in receipts/proof-tokens/diagnostics: each finding carries a stable ID (e.g. `loc:<rand>`); the raw host/share/path→ID map lives ONLY in the operator's protected out-of-band store. A path is never a proof-token input. Applies to diagnostics + tool logs. |
| 6 HIGH | `shares_enumerated` is not an accepted `terminal_kind` (dropped); the base adapter discards an inventory returned as an extra artifact field; discovery ≠ credential recovery. | Add a dedicated terminal kind (e.g. `share_inventory`) to `proof.py` accepted kinds + a result adapter so the (opaque-ID) inventory persists; coordinate the harness scorer/truth facet. Discovery is its own result type, never a `cred:*`. |
| 7 HIGH | "one readable share crawled = success" is existential, not exhaustive; hides denied/unreachable/truncated hosts. | Record **per-host/per-share outcomes** (listed-ok / denied / unreachable / malformed / truncated); separate *observed access* from *coverage completeness*; a mixed or bounded run is `partial`/`inconclusive` for completeness. Fixtures: mixed success/denial, root-readable+child-denied, malformed output, each truncation reason. |

**Net effect on S1:** crawl uses a programmatic SMB client (impacket), discovery uses `smbclient -L`
(read-only), receipts use opaque location IDs + a new `share_inventory` terminal kind with a result
adapter, bounds + cleanup + exhaustiveness are first-class. This is a larger, security-critical S1
than the draft; it is the correct scope. Build proceeds from this resolved design (a short r2 verify
of the revised plan precedes implementation).

## Plan-review r2 verify (Codex Sol, 27NOV2026) — scope decision
Review: `docs/reviews/PLAN-SHARELOOT-27NOV2026-codex-sol-plan-review-r2.md`. 4 SOUND (#1 read-only
discovery, #5 opaque IDs, #6 `share_inventory` terminal kind, #7 exhaustiveness). The 3 partials
(#2 mount TOCTOU/symlink race, #3 mount crash-recovery/`SIGKILL`, #4 whole-directory accumulation)
are all MOUNT-mode OS-level safety — too deep to build safely in the same pass.

**Decision: S1 ships CRAWL mode ONLY (programmatic impacket `SMBConnection`). MOUNT mode is DEFERRED
to its own sprint (S1b).** Rationale:
- Crawl uses the impacket SMB client to read REMOTE paths and writes to opaque content-addressed
  names in a flat scratch dir — there is **no local mount and no local filesystem walk**, so #2
  (realpath→open TOCTOU, symlink escape) and #3 (attached-mount unmount/crash recovery) **do not
  apply**. The user's "both access modes" decision is preserved as the end state; crawl (the
  no-privilege, portable default) lands first.
- #4 (bounded consumption) still applies to crawl and IS resolved: all limits — aggregate scratch
  bytes, total entry count, per-read byte cap (stop mid-file at the cap), max depth, max files,
  visited-cycle detection, and a **whole-run deadline checked between every blocking op** — are
  enforced DURING traversal; any bound hit yields an explicit `partial` outcome. Residual (documented,
  accepted): impacket `listPath` returns one directory's entries as a list, so a single pathologically
  huge directory's listing is bounded by the whole-run deadline (wall-clock) rather than streamed;
  a paged-listing follow-up is noted. No `os.walk`, no mount → no TOCTOU.
- **S1b (deferred, documented requirements for mount mode):** private mountpoint + verify actual CIFS
  identity & `ro` flags; descriptor-anchored race-resistant traversal (`openat2` RESOLVE_BENEATH |
  RESOLVE_NO_SYMLINKS, fail closed if unavailable); bounded worker shutdown before shred; mount-state
  reconciliation on post-attach timeout; crash-recovery marker so scratch is reclaimable after an
  uncatchable kill. Until S1b, `share_access_mode="mount"` returns `inconclusive:mount_mode_deferred`.

**S1 build (crawl-only, from this resolved design):** discovery via impacket `listShares` (read-only,
programmatic — no `smbclient` shell at all); crawl via `listPath`/`getFile` with the #4 bounds +
cycle detection; opaque location IDs (raw map → operator store); `share_inventory` terminal kind
(+ harness mirror); per-host/share exhaustiveness; scratch shredded in `finally`.

## S1 build + live proof (27NOV2026)
S1 shipped (crawl-only, programmatic impacket). Committed on dev/shareloot-s1. Proven live on GOAD
(winterfell.north.sevenkingdoms.local, vagrant creds):

| metric | result |
|---|---|
| terminal | `share_inventory` ok=True (read-only access observed) |
| shares enumerated | 5 (ADMIN$, C$, IPC$, NETLOGON, SYSVOL) via impacket listShares |
| crawled | 300 files + 19,913 dirs before the `share_max_files=300` bound → `truncated`/`partial`, `complete=False` (honest) |
| secret-safety | **0 raw paths in the receipt**; all 20,213 raw paths confined to the opaque-ID operator store (`loc:*`) |
| read-only | by construction (ShareReader = list ops only); unit-proven (only read methods called); no write on the live run |

Bounds, cycle guard, per-share exhaustiveness, and opaque-ID secret-safety all demonstrated live.
412/412 validation unit tests green (400 baseline + 12); secret-path gate mutation-proven RED.
Scratch + loot-store shredded after the run.

Remaining for the module: harness `proof_adapters` mirror of `share_inventory`; diff review + merge S1;
then **S1b** (mount mode, deferred OS-safety), **S2** (NFS), **S3** (loot search engine), **S4**
(dual-mode + full proof).

## S3 build + live proof (27NOV2026) — the loot search engine
S3 shipped: a curated secrets-first rule pack (`loot_rules.py`) + bounded content fetch wired into
the crawler. Filename rules (id_rsa/.ppk/.kdbx/.pfx/unattend.xml/web.config/.env/Groups.xml/.aws+vcs
creds/suggestive names) mark fetch-worthy files; content rules (PRIVATE KEY blocks, GPP cpassword,
AWS keys, DB connection strings, API tokens, Slack tokens, password assignments incl. prefixed
fields) scan the fetched bytes. Findings are **PRESENCE + CATEGORY + opaque loc_id** in the receipt;
the recovered secret VALUE/context goes ONLY to the operator `0600` store. Fetch bounded
(loot_max_fetch_files / per-file / aggregate caps; binaries skipped; deadline-gated).

Proven live on GOAD (winterfell): the crawl found 11 real items (web.config + password-named files
in WinSxS) with no false positives on template configs; **a planted canary secret was found**
(private_key_block + suggestive_name), its token present in the `0600` store but **NOT in the
receipt**, and the canary was deleted (lab restored). 423/423 validation tests green (416 base + 7).

## S4 build + live proof (27NOV2026) — dual-mode: looted credentials -> composable capability
S4 shipped: usable-credential extraction (GPP `cpassword` AES-decrypt via whatever crypto backend is
present; parses Groups/Services/ScheduledTasks/DataSources XML, either attribute order) ->
`loot_rules.extract_credentials`. The executor gains `eff={S_looted_creds}` and `produced()` emits an
in-memory SECRET `Capability(S_looted_creds, CAP_PASSWORD, value, principal)` per usable credential
(new `CAP_PASSWORD` channel in `_SECRET_CHANNELS`; new `S_looted_creds` capability-backed state).

Receipt semantics refined: `complete` now means the EDGE OBSERVED ACCESS (so a bounded/partial crawl
still yields its loot + capabilities); EXHAUSTIVE COVERAGE stays a separate dimension
(`coverage.complete` + the `partial:*` errors). The receipt carries a `usable_credentials` PRESENCE
COUNT only -- the (principal, secret) pairs live in the in-memory capability + the `0600` operator
store, never a receipt.

**Proven live on GOAD (end-to-end dual-mode):** a seeded GPP `Groups.xml` (cpassword encrypting a real
account's password) was crawled read-only, decrypted to a usable credential (`vagrant`), produced as a
secret `S_looted_creds`/`CAP_PASSWORD` capability (value NOT in the receipt), and that LOOTED credential
**authenticated downstream** -> `WINTERFELL [+] …\vagrant:vagrant (Pwn3d!)`. The GPP canary was deleted
(lab restored). 425/425 validation tests green (416 baseline + 9).

## Status
S1 (SMB discover+crawl) merged; S3 (loot engine) + S4 (dual-mode creds) built + live-proven on this
branch. Remaining: S2 (NFS, multi-method discovery -- NOT showmount-only; nmap rpcinfo/nfs-showmount +
pyNfsClient portmap/NFSv4, programmatic read); S1b (mount mode, openat2). The owner's "don't rely only
on showmount" directive is recorded for S2.
