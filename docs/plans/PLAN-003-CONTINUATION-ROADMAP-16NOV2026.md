# PLAN-003 — Continuation Roadmap (for the next session)

**Date:** 16 NOV 2026
**Picks up from:** OCD AD mind-map capability outline, round 2 merged (PR #128, `4fac580`).
**Parent plan:** `docs/plans/PLAN-003-14NOV2026-ad-engagement-toolchain.md`
**Running ledger:** `docs/PLAN-003-OPS-DEFERRED-LOG-16NOV2026.md` (authoritative issue list)

This roadmap exists so a future session can resume without re-deriving context. Read this top to
bottom, then open the deferred log and the capability registry before touching code.

---

## 0. Where things stand (one screen)

Two tracks run under PLAN-003:

- **Track A — capability implementation** (active, unblocked): build PurpleSploit modules that
  back the 17 OCD AD mind-map attack-phase categories. This is what rounds 1–2 did.
- **Track B — box/lab qualification** (blocked on user decisions): provision the GOAD lab via
  `pt_provision`, qualify the toolchain against it with `ad-lab-harness`. Blocked on **OD-1** and
  **Deviation 1** (see §4).

**Track A coverage today** (`python/purplesploit/capabilities/ocd.py` → `coverage_report()`):

```
module_status: HAVE 3 · PARTIAL 11 · STUB 0 · GAP 3
```

Source of truth for the build queue: `python/purplesploit/capabilities/ocd_registry.json`
(`missing_modules` per category). The loader's `validate_backing_modules()` proves no over-claim —
run it after every change; it must return `[]`.

**Operator/methodology references** (do not regenerate — they are parsed, frozen, and merged):
- `docs/research/OCD-AD-MINDMAP-OPERATOR-REFERENCE-16NOV2026.md` (per-technique commands)
- `docs/research/OCD-AD-MINDMAP-TAXONOMY-16NOV2026.md` + `docs/research/data/ocd-ad-mindmap-2025.03.taxonomy.json`
- `docs/research/OCD-AD-MINDMAP-CAPABILITY-MAPPING-16NOV2026.md` (category → capability mapping)

---

## 1. START HERE — the first thing to do next session

**Fix D-050 (HIGH) — shared `ImpacketAdapter.run()` success-gating.** This is the highest-value,
lowest-ambiguity open item and it is a real correctness bug in *shipped* code.

- **What:** `python/purplesploit/modules/impacket/common.py` `ImpacketAdapter.run()` sets the
  top-level `result["success"]` from the tool's exit code only. Impacket tools routinely exit 0
  while producing no result (a rejected S4U, an empty roast, a failed dump), so the 6 pre-existing
  impacket modules (`kerberoast`, `asreproast`, `secretsdump`, `psexec`, `wmiexec`, `smbclient`)
  over-report success.
- **The fix (already proven in the round-2 modules):** gate success on the parser —
  `result["success"] = bool(result.get("success")) and bool(parsed.get("success"))` — when
  `parse_output` returns a `success` key. Round 2 applied this locally in `getst.py`/`ticketer.py`
  via a `run()` override; folding it into `common.run()` lets those overrides be removed.
- **Why it needs care (not a one-liner merge):** each of the 6 modules' `parse_output` must be
  confirmed to set `success` truthfully, and their existing tests (`tests/unit/modules/test_impacket.py`,
  `test_impacket_cwp2.py`, `tests/unit/parsers/test_impacket_parsers.py`) may assert top-level
  success on mocked exit-0 runs and will need updating.
- **Process:** this is a shared-infra change → 1 Sol review (pattern B), run the full impacket +
  parser suites, then merge. After it lands, delete the now-redundant `run()` overrides in
  `getst.py`/`ticketer.py` (keep hashcat's — it is not an ImpacketAdapter).

---

## 2. Track A — capability build queue (ordered)

Each item follows the **established cadence**: build module(s) → 1 Sol review (codex bulk,
read-only, pattern B) → fix correctness findings in-round, log residuals → unit tests → commit →
PR → merge → `/git-cleanup`. Model the modules on the existing pattern (`ImpacketAdapter` for
impacket tools; the standalone `crack/hashcat.py` shape for others). **Offline-testable argv +
parse_output unit tests only — no live services.**

| # | Build | OCD cat(s) | Backing pattern | Closes | Notes |
|---|---|---|---|---|---|
| R3a | `impacket/getTGT` + `impacket/rbcd` + `impacket/addcomputer` | delegation, persistence, lat_move | `ImpacketAdapter` | D-042, D-015 tail | RBCD write-primitive + ticket acquisition; completes the delegation chain started in r2 |
| R3b | `network/certipy` (enum + ESC request paths) | adcs, know_vuln_auth, persistence | standalone `ExternalToolModule` | D-013 | certipy IS a denominator capability; wrap `find`/`req`/`auth`. ADCS enum currently only `nxc -M adcs` |
| R4a | BloodHound-CE ingest/query + `rusthound-ce` collector modules | authenticated, acl, trusts | standalone | D-014, D-033 | Qualify `nxc -M bloodhound` output for CE compatibility while here |
| R4b | LAPS-password + gMSA-password retrieval; GPP cpassword discovery/decrypt | acl, know_vuln_auth | `ImpacketAdapter`/`nxc` adapters | D-030, D-031 | nxc adapters expose neither today |
| R5 | MSSQL linked-server enum/traversal | trusts | extend `network/nxc_mssql` | D-032 | `nxc_mssql` has no linked-server op |
| R6 | Poison/relay/coercion suite: `responder`, `mitm6`, `impacket-ntlmrelayx`, `krbrelayx`, Coercer/PetitPotam | mitm, no_creds, delegation | standalone (long-running/background) | D-010 | **Biggest GAP.** `mitm` is 0-backing. Needs the module system's background-job path — heavier than the wrappers above |
| R7 | On-host persistence / SCCM | persistence, admin, sccm | deploy/host-ops | D-012, D-016 | Lowest priority; SCCM is a later profile |

**Recommended order:** R3a → R3b → R4a → R4b → R5, then R6 (the hard one), R7 last. R3a/R3b are the
closest to the round-2 pattern and will move delegation/adcs toward COVERED fastest.

---

## 3. Track A — recurring discipline (do not skip)

- **Registry honesty:** `module_status` is operator-facing ("can it run as provisioned?"). A module
  whose denominator tool is **not in the `pt_provision` bundle** stays **GAP**, not HAVE/PARTIAL —
  see `crack_hash` (D-041 resolved → GAP). Record the code in `backing_modules`, the bundling gap
  in `missing_modules`.
- **Provisioning couples to this:** every new tool a module wraps must be added to
  `pt_provision/config/repositories.tsv` / the wheelhouse, or the module is inert on a real host.
  **hashcat is the live example — D-043 (HIGH).**
- **Parse robustness is where the bugs are** (Sol R2 found 10, mostly in parsing): fixed-width
  tables by column span (not token split); last-colon boundaries for hashes that contain colons;
  `$HEX[]` decode; reject tool status/banner text; never fabricate a record from a sentinel line.
- **Discovery is `os.walk` by file path** (`core/framework.py:216`) — a new category dir needs an
  `__init__.py` for test imports but not for discovery. Operation-less modules execute via
  `module.run()` (framework.py:659); `get_operation_manifest()` is catalog-only (D-052).

---

## 4. Track B — blocked, needs the user

The GOAD provisioning + harness-qualification track cannot advance until the owner decides:

- **OD-1 — Debian package pins.** `pt_provision` offline bundle: pin exact Debian package versions
  vs. track-latest. (Blocks box track P0-S3 → P0-S4.)
- **Deviation 1 — BloodHound readiness gate.** Accept the current BloodHound-CE readiness posture
  or require the CE-compat qualification (D-033) first.

Surface these to the user early next session; they are the gate for everything in Track B.

**Also parked in Track B / sweep:** the pre-round sweep produced the aranum/harness bug set
(D-001…D-006, all HIGH/OPEN) — notably **D-001** (aranum adapter builds an argv the real CLI
rejects, `modules/recon/aranum.py:172-186`) and **D-006** (harness quiet-gate stalls P0-S1 start).
These block live qualification but not Track A module building. Fix them when Track B unblocks, or
pull D-001 forward if aranum is exercised sooner.

---

## 5. Open issue summary (full detail in the deferred log)

| Priority | IDs | One-liner |
|---|---|---|
| **HIGH** | D-050 | shared `common.py` success-gating (6 modules over-report) — **§1, do first** |
| **HIGH** | D-043 | hashcat not in provisioning bundle — crack module inert until added |
| **HIGH** | D-001, D-006 | aranum argv bug + harness quiet-gate (Track B) |
| HIGH | D-002…D-005 | aranum false-clean / AS-REP / delegation-inverted / certipy-rule bugs (Track B) |
| MEDIUM | D-010…D-016, D-030…D-034 | capability gaps = the Track A build queue (§2) |
| MEDIUM | D-051, D-052, D-053 | ticket save-race residual; manifest/dispatch mismatch; DC_IP-vs-RHOST requires |
| MEDIUM | D-020…D-024 | mapping/plan debt (incl. D-024: fold the 9 r6 recommendations into PLAN-003) |
| LOW | D-022, D-025, D-040, D-044 | small gaps + provisioning pin notes + registry reformat (done) + observation-surfacing check |

---

## 6. Facts the next session will want (so it doesn't re-discover them)

- **Tests:** `cd purplesploit/python && PYTHONDONTWRITEBYTECODE=1 python3 -m pytest <path> -q`
  (pytest `-B` is not a pytest flag; use the env var). Round-2 suite:
  `tests/unit/modules/test_capability_modules_round2.py` (31 tests).
- **Loader check:** `cd purplesploit/python && PYTHONPATH=. python3 -c "from purplesploit.capabilities import ocd; print(ocd.coverage_report())"`.
- **Merge contract (repo CLAUDE.md):** author `jeremylaratro`, **no** Claude/Anthropic attribution
  (enforced by PreToolUse + commit-msg hooks; never `--no-verify`). Merge via
  `gh api -X PUT repos/jeremylaratro/purplesploit/pulls/N/merge -f merge_method=merge -f sha=<head>`;
  never `gh pr merge --delete-branch`.
- **Peer review:** `~/.claude/skills/codex-interop/scripts/peer.sh run --family codex --tier bulk
  --role review --cd <repo> --out <file> --prompt-file <brief>`; Sol = `gpt-6.1-sol`. Reviewer must
  be the other family; verify every peer claim before acting; copy durable reviews to `docs/reviews/`.
- **Base repos / provisioning:** 6 base repos; `pt_provision/deploy.sh` bundles 7 (purplesploit,
  aranum, supwngo, WinBins, GTFOBins, LOLBAS, pentest_scripts) by cloning HEAD unpinned
  (`repositories.tsv`); 28julytoolkit is not bringable (no remote + 22 submodules). (D-025.)
- **Hosts:** net0srv is the default worker; `jay@wks0` and `j@fedora` are available to offload
  heavy work (credentials are owner-provided per-session and must never be persisted to files,
  memory, claude-mem, or peer/agent prompts).
