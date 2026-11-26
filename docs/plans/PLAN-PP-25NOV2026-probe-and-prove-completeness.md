# PLAN-PP (25NOV2026) — probe-and-prove completeness

**Status:** DRAFT → 1 independent review (Opus, VERDICT REVISE) → **resolutions applied (see Review section)** → execute → verify → notify owner.
**Owner directive (25NOV2026):** "all non-probed reach the probed bar, then all probed reach
the proven bar; notify me when finished, then we add new pathways." New techniques are a
SEPARATE later effort — this plan only raises the EXISTING 15 to fully-probed + fully-proven.

## Objective (acceptance)
Every one of the 15 implemented techniques is BOTH:
1. **Probed** — has a non-destructive detect-before-fire `PreconditionProbe` in `PROBE_REGISTRY`.
2. **Proven** — `verified_recipe=True`, earned by a live GOAD run whose receipt the independent
   ad-lab-harness `score_proof.py` grades `proved` (or honestly `inconclusive` with the blocker
   named — never a flag flipped by assertion).

## Review (25NOV2026) — VERDICT REVISE; resolutions applied
Independent Opus review. The flip-rule integrity was confirmed sound (the scorer makes a
`proved` verdict structurally imply a verified rollback for any mutating chain, and terminal
`ok` reflects real PKINIT — so there is NO path to a false `proved`). Findings + resolutions:
- **HIGH-1 (PP-2 fail-safe) — APPLIED in code.** `NTLMRelayProbe` no longer returns
  `viable=False` on signing: SMB-signing-True does not rule the technique out (it also relays
  over LDAP/`ldap_rbcd`, and DCs — which require SMB signing — are prime LDAP-relay targets per
  the GOAD truth). Now only a POSITIVE surface (SMB off, or LDAP channel-binding/signing not
  enforced) → `viable`; anything else → `unknown`. Mirrors Rbcd/ShadowCreds.
- **HIGH-2 (PROVE mechanism source) — pinned.** The reviewer read ad-lab-harness `main`; the
  scorer + truth live on the branch, not main. CORRECTION (verified THIS session): the scorer
  `adlab/score_proof.py` and the reviewed truth facet `truth/GOAD-proof.json`
  (schema `adlab.plan003.proof-truth.v1`, enumerating all 7 techniques' GOAD host_ids:
  COERCION/UNCONSTRAINED dc01/02/03, LAPS/relay srv02/03 + DCs, CERTIFRIED `{srv03, essos.local}`,
  ESC8/ESC11 dc01/srv03) EXIST and WORK on the `dev/validation-proof-scorer` worktree — I scored
  real composed receipts `proved` on dc01 with them earlier today. So PP-4..10 CAN score
  `proved`. **This plan pins that worktree's scorer + facet as the PROVE oracle**; each flip
  cites a `proved` score result from it. Prereqs before the live runs: (a) confirm each
  executor's `target_identity` resolves to the truth host_id (ESC8/ESC11/Certifried→CA host;
  coercion/unconstrained→DC); (b) merging the scorer+facet into harness `main` is a tracked
  follow-up, NOT a blocker (the worktree oracle is authoritative for this effort).
- **MEDIUM-1 (PP-3 host-anchoring) — already correct in code; prose fixed.** The IMPLEMENTATION
  anchors to the host: `(sAMAccountName=<host>$)` then checks `uac & 0x80000` on that object (not
  the domain-wide filter the draft prose showed). Keeps `viable=False` only on a confident
  host-anchored read with the bit clear (the aranum finding names the carrier).
- **MEDIUM-2 (PP-1) — APPLIED.** `coercer scan` is NON-MUTATING but ACTIVE (sends RPC
  enumeration; it does not coerce to an external listener) — prose corrected. The probe no longer
  returns `viable=False` (a zero-method scan is not a reliable negative; DCs are near-universally
  coercible) → `viable` on a positive method, else `unknown`. Binary pinned LOWERCASE `coercer`
  in BOTH probe and executor (executor `coercion.py` had `"Coercer"`, which does not exist on
  kali-vr — fixed; was an execution-blocking bug). PP-1 live-verify runs from **kali-vr** (coercer
  is there, not net0srv).
- **MEDIUM-3 (artifact secret-leak) — folded into the live-run protocol.** NTLM-RELAY SAM loot
  (`*_samhashes.sam`) and UNCONSTRAINED-DELEG `<DC>$.ccache` (a usable DC TGT) are written to
  `out_dir` and NEVER deleted (both non-mutating, no rollback). The Stage-2 driver therefore MUST:
  copy back ONLY the single scrubbed receipt JSON (never `out_dir`), and `shred`/`rm -rf` the
  per-run `out_dir` (ccache/pfx/sam/loot) on kali-vr immediately after extracting the receipt. A
  usable TGT or SAM dump must never leave the lab box or persist on kali-vr.

## Current ladder (measured 25NOV2026)
- **Non-probed (3):** `COERCION`, `NTLM-RELAY`, `UNCONSTRAINED-DELEG` (the listener trio).
- **Probed-but-not-proven (`verified_recipe=False`), 7:** `ESC8`, `ESC11`, `CERTIFRIED`, `LAPS`
  + the 3 above (once probed). The 8 already proven: ADCS-ESC1, ASREP, CONSTRAINED-DELEG-PT,
  DCSYNC, KERBEROAST, OPENSHARES-WRITE, RBCD, SHADOW-CREDS.

## Feasibility (measured)
- **GOAD is LIVE** on VirtualBox, reachable from net0srv/kali-vr at `192.168.56.0/24`:
  DC01 `.10`, DC02 `.11`, DC03 `.12`, SRV02 `.22`, SRV03 `.23` (all :445 open).
- **kali-vr** container Up, `host` network (reaches the lab), FULL toolchain:
  impacket-ntlmrelayx, certipy-ad, nxc, hashcat, coercer (PetitPotam/printerbug/dfscoerce
  multiplexer), krbrelayx.py. **The repo is NOT mounted in kali-vr** → staging required.
- net0srv has only a partial toolchain (impacket-secretsdump, nxc, bloodyAD, certipy) — enough
  for the non-destructive **probes** (Stage 1 live-verify), not for the relay/coercion proofs.

## Gap inventory (IDs)
| ID | Type | Item | Stage |
|----|------|------|-------|
| PP-1 | gap | CoercionProbe (coercer-scan surface) | 1 |
| PP-2 | gap | NTLMRelayProbe (target signing-not-enforced) | 1 |
| PP-3 | gap | UnconstrainedDelegProbe (UAC TRUSTED_FOR_DELEGATION 0x80000) | 1 |
| PP-4 | prove | LAPS verified_recipe (login-lab quirk, #—) | 2 |
| PP-5 | prove | CERTIFRIED verified_recipe (CVE-2022-26923 on ESSOS-CA/srv03) | 2 |
| PP-6 | prove | ESC8 verified_recipe (coerce→relay→web-enroll on dc01/srv03) | 2 |
| PP-7 | prove | ESC11 verified_recipe (coerce→relay→ICPR on dc01/srv03) | 2 |
| PP-8 | prove | COERCION verified_recipe (coerce DC→listener capture) | 2 |
| PP-9 | prove | NTLM-RELAY verified_recipe (relay→SAM/LDAP-RBCD) | 2 |
| PP-10 | prove | UNCONSTRAINED-DELEG verified_recipe (coerce→capture TGT→DCSync) | 2 |

## Sprint A — Stage 1: non-probed → probed (PP-1..3)
Three `PreconditionProbe` subclasses in `probes.py`, registered in `_PROBES`, each mirroring the
existing pattern (non-destructive read via `ctx.runner`; `viable`/`viable=False`/`unknown`;
fail-safe unknown never skips). Add `UAC_TRUSTED_FOR_DELEGATION = 0x80000`.
- **PP-1 Coercion:** `coercer` (lowercase) `scan -u <u> <auth> -t <victim_dc> -d <domain>` —
  NON-MUTATING but ACTIVE (sends RPC enumeration; does not coerce to an external listener). ≥1
  reachable method → viable; anything else → **unknown** (a zero-method scan is not a reliable
  negative; DCs are near-universally coercible). NEVER viable=False. Markers UNVERIFIED, pin in lab.
- **PP-2 NTLM-RELAY:** `nxc smb <target>` banner `signing:False` → relayable (viable); else read
  `nxc ldap <target>` — channel-binding/signing not enforced → viable (ldap_rbcd). SMB-signing-True
  NEVER yields viable=False (the LDAP/`ldap_rbcd` and web-enroll paths are independent of SMB
  signing, and DCs are prime LDAP targets) → **unknown**. Fail-safe.
- **PP-3 UNCONSTRAINED-DELEG:** host-anchored `nxc ldap <dc> --query "(sAMAccountName=<host>$)"
  "sAMAccountName userAccountControl"`, then check `uac & 0x80000` (TRUSTED_FOR_DELEGATION) on
  THAT object (not a domain-wide filter). Bit set → viable (control-to-capture flagged `unknown`,
  mirroring RBCD); bit clear on a confident host read → viable=False (the aranum finding names the
  carrier). Combined filter `(&(sAMAccountName=<host>$)(userAccountControl:...:=524288))` optional.
- **Tests:** unit (scripted fake runner, RED→GREEN per probe: viable / viable=False where it
  applies / unknown / tool-error). Then **live-verify each from kali-vr** against GOAD (coercer +
  the working nxc are there; net0srv's nxc is flaky non-interactively) — read-only, safe — and
  record the real markers, pinning the UNVERIFIED regexes.
- **Exit:** `PROBE_REGISTRY` has all 15; suite green; live-verify evidence recorded.

## Sprint B — Stage 2 setup + non-relay proofs (PP-4, PP-5)
- **Stage the package into kali-vr — DONE** (via `docker cp` to `/opt/ps-validation`, with an
  empty `purplesploit/__init__.py` shim so the import skips the heavy `core.framework`; verified
  importing 15 probes + 15 executors). A thin `drive_validation.py` runs ONE executor via `run()`
  against the live lab, writes the receipt JSON to a path OUTSIDE `out_dir`, and prints it.
  **Secret-artifact protocol (review MEDIUM-3):** copy back to net0srv ONLY the single scrubbed
  receipt JSON — NEVER `out_dir`. Immediately after extracting the receipt, `shred -u` / `rm -rf`
  the per-run `out_dir` on kali-vr (it holds the un-deleted `<DC>$.ccache` TGT, issued `*.pfx`, and
  `*_samhashes.sam` loot). GOAD creds supplied via env on kali-vr only — NEVER written to the
  repo/receipts/memory/this plan.
- **PP-4 LAPS** (srv02/srv03): read ms-Mcs-AdmPwd/msLAPS-Password, log in as the local admin,
  capture `authn_success`. Non-mutating. Fix the login-lab quirk that set verified_recipe=False.
- **PP-5 CERTIFRIED** (srv03/ESSOS-CA): create computer (MAQ>0), spoof dNSHostName, request Machine
  cert on the unpatched CA, PKINIT as the DC; **mutating → verified rollback (delete computer +
  LDAP read-back + destroy pfx)** must verify before flipping the flag.
- **Exit:** each receipt scores `proved` on its truth host via `score_proof.py`; flip
  verified_recipe=True ONLY on a proved+clean receipt; else keep False and record the blocker.

## Sprint C — Stage 2 relay/coercion proofs (PP-6..10)
On kali-vr against live GOAD, in dependency order (coercion underpins the relays):
- **PP-8 COERCION** (dc01/02/03): `coercer`/printerbug trigger → listener captures the DC machine
  auth (`authn_success`). Non-mutating.
- **PP-9 NTLM-RELAY** (srv02/03 SMB signing off; DCs LDAP): relay coerced auth → SAM dump
  (`replication_dump`) or LDAP-RBCD write (`rbcd_access`, mutating → verified rollback).
- **PP-6 ESC8** (dc01/srv03): coerce → relay to `certsrv/certfnsh.asp` → DC cert → PKINIT;
  mutating (a cert is issued) → verified key-material destruction before flag flip.
- **PP-7 ESC11** (dc01/srv03): coerce → relay to the ICPR RPC endpoint → cert → PKINIT; mutating.
- **PP-10 UNCONSTRAINED-DELEG** (dc01/02/03): coerce the DC to a controlled unconstrained host,
  capture its TGT (krbrelayx), DCSync. Non-mutating (capture+replicate).
- **Exit:** each scores `proved`/`inconclusive` honestly; flag flipped only on proved+clean.

## "Proven" definition (integrity — non-negotiable)
`verified_recipe=True` is flipped per technique ONLY when a LIVE GOAD receipt is graded `proved`
by `score_proof.py` on that technique's truth host AND (if mutating) the rollback is VERIFIED.
A technique that will not validate (lab config, tool gap) stays `verified_recipe=False` with the
blocker recorded — per the owner's "floor = design problem to hack": first try to reshape the run
(lab fix, tool install on kali-vr, marker correction) to make it REAL; never fake the flag.
Secrets (GOAD creds, cracked pw, NT hash, ccache, pfx) never reach repo / receipts / memory / this
doc; receipts are presence-only + redacted (existing proof.scrub + redact_argv).

## Test plan (Phase 7)
- Sprint A: unit RED→GREEN per probe (4 states each) + live read-only verify on GOAD.
- Sprint B/C: the live receipt itself is the proof; regression = the full validation suite stays
  green (probe + executor unit tests unaffected; a flipped verified_recipe updates its executor's
  unit assertion). Each flag flip cites the proved receipt (score result path + host_id).

## Rollback / safety
- Probes are read-only. Mutating proofs (CERTIFRIED, ESC8, ESC11, relay-RBCD) run only with their
  verified rollback; a receipt that is proved-but-NOT-clean does NOT flip the flag.
- kali-vr tool installs are pre-authorized; GOAD is the authorized lab; libvirt stays read-only
  (the production KVM guests are untouched — GOAD is the VirtualBox lab).

## Out of scope (declared)
New techniques/pathways (owner will assign next); tool hardening/compliance; the other-11-edge
graph annotation (separate PLAN-C follow-up); non-GOAD targets.
