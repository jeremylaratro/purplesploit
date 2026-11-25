# PLAN-PP (25NOV2026) — probe-and-prove completeness

**Status:** DRAFT → 1 independent review (Opus) → execute → verify → notify owner.
**Owner directive (25NOV2026):** "all non-probed reach the probed bar, then all probed reach
the proven bar; notify me when finished, then we add new pathways." New techniques are a
SEPARATE later effort — this plan only raises the EXISTING 15 to fully-probed + fully-proven.

## Objective (acceptance)
Every one of the 15 implemented techniques is BOTH:
1. **Probed** — has a non-destructive detect-before-fire `PreconditionProbe` in `PROBE_REGISTRY`.
2. **Proven** — `verified_recipe=True`, earned by a live GOAD run whose receipt the independent
   ad-lab-harness `score_proof.py` grades `proved` (or honestly `inconclusive` with the blocker
   named — never a flag flipped by assertion).

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
- **PP-1 Coercion:** `coercer scan -u <u> <auth> -t <victim_dc> -d <domain>` (non-destructive
  enumeration — scan mode does not trigger). ≥1 method listed → viable; explicit none → viable=False;
  tool-error/unparsed → unknown. Mirror markers UNVERIFIED, pin in lab.
- **PP-2 NTLM-RELAY:** `nxc smb <target>` banner `signing:False` → relayable (viable); all
  candidate targets `signing:True` → viable=False; also read `nxc ldap <dc>` channel-binding where
  available. The coerced victim + a signing-off target is the real precondition; the victim side is
  flagged `unknown`.
- **PP-3 UNCONSTRAINED-DELEG:** `nxc ldap <dc> --query
  "(userAccountControl:1.2.840.113556.1.4.803:=524288)" "sAMAccountName userAccountControl"` →
  the target host's TRUSTED_FOR_DELEGATION bit. Set → viable (control-to-capture flagged `unknown`,
  mirroring RBCD's ACL-not-readable path); not set → viable=False.
- **Tests:** unit (scripted fake runner, RED→GREEN per probe: viable / viable=False / unknown /
  tool-error). Then **live-verify** each against GOAD from net0srv (nxc/coercer present) — read-only,
  safe — and record the real markers, pinning the UNVERIFIED regexes.
- **Exit:** `PROBE_REGISTRY` has all 15; suite green; live-verify evidence recorded.

## Sprint B — Stage 2 setup + non-relay proofs (PP-4, PP-5)
- **Stage the package into kali-vr** (copy the worktree tree in, or a volume mount; no repo secrets).
  A thin `drive_validation.py` runs ONE executor via `run()` against the live lab and prints the
  receipt JSON; receipts copied back to net0srv for harness scoring. GOAD creds supplied via env
  on kali-vr only — NEVER written to the repo/receipts/memory/this plan.
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
