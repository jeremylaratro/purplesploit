# Outbrief — PLAN-003 OCD AD Mind-Map Capability Work

**Date:** 16 NOV 2026
**Scope of this session:** make the Orange Cyberdefense AD mind-map (v2025.03) the methodology /
tooling / capability basis for PLAN-003, then begin implementing the PurpleSploit modules that back it.
**Continuation:** `docs/plans/PLAN-003-CONTINUATION-ROADMAP-16NOV2026.md`
**Issue ledger:** `docs/PLAN-003-OPS-DEFERRED-LOG-16NOV2026.md`

---

## 1. What was accomplished (with evidence)

**Methodology basis established (merged).**
- Parsed the OCD AD mind map deterministically from markdown source (pinned commit `6d16ca0d`) —
  17 attack-phase categories, 128 subjects, 707 items, 159 tools — into three durable, machine- and
  human-readable references: operator command reference, taxonomy, and a `taxonomy.json`
  (`docs/research/OCD-AD-MINDMAP-*-16NOV2026.md`, `docs/research/data/`). **PR #126.**
- Produced the category → capability **mapping** (`...CAPABILITY-MAPPING-16NOV2026.md`),
  independently reviewed by Sol (`docs/reviews/...SOL-R1...`). **PR #126.**

**Executable capability registry (merged — round 1).**
- `python/purplesploit/capabilities/` — `ocd_registry.json` (17 categories), `ocd.py` loader with a
  `validate_backing_modules()` that proves the registry never claims a module that doesn't exist,
  and `coverage_report()`. 4 unit tests. Sol-reviewed. **PR #127 (`3c9b7ae`).**

**First capability modules (merged — round 2).**
- Four new modules, all discovered by the framework, **31 unit tests green**:
  `impacket/finddelegation` (delegation enum), `impacket/getst` (S4U delegation abuse),
  `impacket/ticketer` (golden/silver persistence), `crack/hashcat` (new `crack` category, offline
  cracking). **PR #128 (`4fac580`).**
- Sol review (R2) returned FIX-FIRST / 10 findings; the correctness findings were verified against
  the code and fixed **in-round** (fixed-width table parse, hashcat last-colon + `$HEX` decode +
  status-line guard + stdin-hang guard, success gated on real evidence rather than exit code,
  upstream message-variant tolerance). Durable review in `docs/reviews/...SOL-R2...`.

**Coverage now:** `HAVE 3 · PARTIAL 11 · STUB 0 · GAP 3` (delegation & persistence moved
STUB→PARTIAL this session; crack_hash held at GAP on purpose — see §3).

**Process adherence.** Every change: Opus implemented → Sol (other family, read-only) reviewed →
findings verified before acting → committed clean (author `jeremylaratro`, zero Claude attribution,
hooks satisfied, never `--no-verify`) → PR → merge → `/git-cleanup`. Repos left CLEAN each round.

---

## 2. Current state

- **Git:** `purplesploit` `main` == `origin/main` at `4fac580`. No branches, worktrees, stashes, or
  open PRs from this work. `pt_provision` and `ad-lab-harness` were read-only this session.
- **No running jobs**; no uncommitted work; no unverified claims presented as done.
- The deferred log is the single source of open items (29 → now ~37 entries, all with IDs/status).

---

## 3. Key judgment calls (so they aren't re-litigated)

- **crack_hash is GAP, not HAVE**, even though the module exists — because hashcat is **not in the
  provisioning bundle**, so the capability is not runnable on a provisioned host. `module_status` is
  operator-facing ("can it run as provisioned?"), not "does code exist." Sol concurred (R2 F10). The
  unblock is **D-043 (HIGH): add hashcat to `pt_provision`.**
- **The attack commands are the deliverable, not something to self-censor** (owner directive). The
  operator reference contains the full technique commands with `<placeholders>`; it lives in files.
- **Parse robustness is the main defect surface.** Sol R2's 10 findings were almost all in output
  parsing. The modules now parse fixed-width tables by column span, split hashes on the last colon,
  decode `$HEX[]`, and reject tool banner/status text.

---

## 4. Top risks / open HIGHs carried forward

1. **D-050 (HIGH)** — shared `ImpacketAdapter.run()` reports success from exit code only, so the 6
   pre-existing impacket modules over-report success. Fixed locally in the new ticket modules;
   needs a one-place fix in `common.py` + regression of all impacket tests. **Do this first next
   session** (roadmap §1).
2. **D-043 (HIGH)** — hashcat (and any future-wrapped tool) must be added to the provisioning
   bundle or the module is inert on a real host.
3. **D-001 / D-006 (HIGH, Track B)** — aranum adapter builds an argv the real CLI rejects; harness
   quiet-gate stalls lab start. Block live qualification, not Track A.
4. **Track B is gated on the user:** **OD-1** (Debian pins) and **Deviation 1** (BloodHound
   readiness) must be decided before GOAD provisioning / harness qualification can advance.

---

## 5. Recommended next move

Open the continuation roadmap and do **§1 (fix D-050)** first — highest-value, unambiguous, real
bug in shipped code — then proceed down the Track A build queue (R3a `getTGT`/`rbcd`/`addcomputer` →
R3b `certipy` → …). Surface OD-1 and Deviation 1 to the owner early so Track B can unblock in
parallel.
