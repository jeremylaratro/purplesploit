# ADR-002 (24NOV2026) — Bulletproof hardening + DA-in-minutes chaining

**Status:** PROPOSED — awaiting owner sign-off on scope + decisions below, and an independent review, before build.
**Driver:** owner directive — "beat the hell out of this tool… I need to scan a domain and show proof of domain admin within minutes… bulletproof." Supersedes the baseline-only plan; ADR-001 (listener trio) folds in as one tranche.
**Evidence:** `docs/research/ad-attack-robustness-catalog-24NOV2026.md` (five cited research lanes).

## Problem

The current framework validates **individual** findings against one lab with a fixed `proof-truth`. To be bulletproof and prove DA in minutes it must additionally: (1) survive real-world **version/patch/config variation**; (2) **detect before it fires** so it only attempts what will work; (3) assert on **robust artifacts**, not tool output strings; (4) offer **tool fallbacks** per technique; (5) **chain** validated primitives to Domain Admin and stop at the first proof. And it must fix two confirmed live bugs: the ADCS-ESC1 revoke (certipy has no revoke) and the already-fixed scorer mutation-kind gap.

## Decisions — four new architectural layers (all injectable, lab-free testable)

### D1. Precondition-probe layer (`PreconditionProbe`)
Per technique, a **non-destructive** CHECK that reads AD/SMB/registry state and returns `{viable: bool, reason, evidence}`. The orchestrator runs all probes **concurrently** before planning, caches results as edge preconditions, and **surfaces every skip with its reason** ("RBCD skipped: MAQ=0 and no owned computer and no WriteAccountRestrictions edge"). Probe set from the research §0.2: MAQ + add-workstation right, `msDS-SupportedEncryptionTypes`, UAC delegation bits, delegation attribute reads, LDAP signing/CBT mode (`CheckLDAPStatus.py`), SMB signing, patch build, Certifried SID-ext oracle, `certipy find` ESC surface, StrongCertBinding mode fingerprint. This is the single biggest reliability lever and makes the tool explainable.

### D2. Tool-adapter + fallback layer (`ToolAdapter`)
Each technique declares an **ordered list of tool adapters** (e.g. KERBEROAST: `nxc --kerberoasting` → `GetUserSPNs -request` → `Rubeus /tgtdeleg`). An adapter has its own arg-builder, env/version detection, and robust predicate. The executor tries them in order until one succeeds or all are exhausted (→ honest `inconclusive`). Encodes the research fallback tables. Also centralizes LDAP-bind fallbacks (`-ldap-scheme ldap`, `-no-ldap-channel-binding`) and clock-sync (`faketime`/`rdate`) as pre-run steps.

### D3. Robust-predicate layer
A shared helper module: `strip_ansi()` + whitespace/`[*]`/`[+]`/`[-]`-tolerant matching applied to **all** tool output before any regex; plus **artifact predicates** — `file_exists_and_parses(pfx)`, `ccache_authenticates()`, `ldap_attr_readback(dn, attr, expected)`, `loot_file_present(lootdir, pattern)`, `hash_blob_matches(etype)`. Every executor's terminal `ok` must come from one of these, never a bare stdout string. Retrofit the existing 8 executors (their output markers are flagged UNVERIFIED today).

### D4. Chaining engine (`ChainEngine`) + ProcessManager (from ADR-001)
The state/technique graph from research §2: nodes = capability states, edges = executors (each emits a `proof.v1` receipt). Parallel precondition probing → weighted shortest path (`crack_free` and `destructive` as cost multipliers) → race top-k disjoint chains off one coercion listener → **early-exit on the first `proved` DCSync**, roll back siblings. `ProcessManager` (start/read/stop, injected, fake-able) carries the background listeners. Default DA proof = **DCSync of krbtgt** (`replication_dump`, read-only, no cleanup).

## Decision — the ADCS-ESC1 revoke fix (D5)

certipy cannot revoke in any version. Replace the broken `certipy ca -revoke-request` with a **two-part rollback**:
1. **Always: destroy the local key material** (`.pfx`/`.key`/`.ccache` the executor created) and verify by file-absence. For ESC1 **no AD object changed**, so destroying the only private-key copy is a **complete functional rollback** — the issued cert can no longer be used. `mutation.rollback.verified = key_material_destroyed_confirmed`.
2. **Optional (CA-DB hygiene): `certutil -revoke <serial> 6`** (reversible Certificate Hold) via impacket remote-exec on the CA, then `certutil -CRL`; confirm via **CA-DB disposition=Revoked + serial in CRL** (never a PKINIT re-test — the KDC ignores CRLs). Best-effort; `rollback_unverified` only if the operator *required* formal revocation and it couldn't be confirmed.
3. The recovered NT hash/TGT is unrollbackable → the receipt flags the impersonated principal for **credential rotation** (non-secret advisory).

Stateful ESCs (ESC4 template, ESC7 officer/SubCA, ESC9/10/16 UPN+shadow, Certifried machine acct) use certipy-native **checkpoint-before-exploit + guaranteed-restore-on-error**. *Build opportunity (flagged):* a network-native **MS-CSRA `RevokeCertificate` Opnum 10** DCERPC primitive so an ESC7 officer cred can revoke without CA code-exec.

## Decision — safety tiering (D6)
- **Default frontier (crack-free, deterministic):** ESC1, ESC8, ESC11, Certifried, shadow-creds, RBCD, constrained/unconstrained delegation, noPac → all terminate in non-destructive DCSync.
- **Opt-in, verified-restore:** destructive/code-exec — **Zerologon** (severe: mandatory recover-original-pw → persist off-box → non-skippable restore → verify-restore → single-DC, per research §3.4), PrintNightmare, CVE-2025-33073.
- **Masked behind `--allow-crack` + per-edge time budget:** kerberoast, AS-REP → over-budget = `inconclusive`, finding preserved.
Every mutating edge carries a verified rollback or scores `inconclusive` (harness-enforced, commit f305f3d).

## Harness facet extensions (ad-lab-harness)
Extend `truth/GOAD-proof.json` with a **DA goal** + new technique entries (ESC8, ESC11, Certifried, noPac, DCSync, shadow-creds already present), all within the existing six terminal kinds — **no schema break**; `replication_dump` already covers DCSync-as-DA. New entries keyed on `{host_id}`/`{domain}` as appropriate. Keep the scorer the independent judge.

## Revised tranche plan

| Tranche | Content | Depends on |
|---------|---------|-----------|
| **B0 (baseline)** | ADCS-ESC1 revoke fix (D5); apply the already-landed scorer fix; finish verifying the 8 implemented | — |
| **T1c-2** (ADR-001) | listener trio: COERCION (Coercer multiplexer), NTLM-RELAY (+ESC8/ESC11 relay targets), UNCONSTRAINED-DELEG (krbrelayx) + `ProcessManager` | B0 |
| **H (harden)** | retrofit D1 probes + D2 fallbacks + D3 robust predicates onto all executors; clock-sync; etype-aware crack mode; LDAP-bind fallbacks | B0 |
| **N1 (ADCS keystone)** | ESC8 (coerce→relay→DC cert→DCSync), ESC11, Certifried; StrongCertBinding mode fingerprint + SID-supplying variants | H, T1c-2 |
| **N2 (fast DA primitives)** | DCSync edge + krbtgt proof; shadow-creds-via-relay; noPac; golden/silver ticket + PtH/PtT/OverPass post-ex edges | H |
| **C (chaining engine)** | `ChainEngine` graph + parallel probe + race + early-exit + DA-in-minutes CLI; harness DA-goal facet | N1, N2 |
| **N3 (coverage long tail)** | ESC2/3/4/6/7/9/10/13/15/16; targeted-kerberoast + no-preauth; `/altservice`; `WriteAccountRestrictions` write-path; LAPSv2/GMSA; n-days BadSuccessor / CVE-2025-33073 / WinReg; MS-CSRA revoke primitive | C |

Each tranche: precondition probes + robust predicates + fake-runner tests + real-scorer cross-check + independent (Opus/Sonnet) review before merge. This marches toward full OCD-mindmap coverage with the "DA in minutes" capability landing at tranche **C**.

## Decisions for the owner (proceeding on these defaults unless steered)
1. **Scope depth:** build all of N1–N3 (the full ESC family + n-days + chaining) toward complete OCD coverage, in the tranche order above? (Default: yes.)
2. **Destructive techniques:** Zerologon/PrintNightmare/CVE-2025-33073 included but default-off, opt-in, verified-restore, snapshot-required? (Default: yes.)
3. **Tool provisioning:** install krbrelayx, Coercer, PetitPotam/printerbug/dfscoerce into the `kali-vr` exec env (needed for T1c-2/N1)? (Default: yes.)
4. **MS-CSRA revoke primitive:** build the network-native cert-revoke (N3), or rely on `certutil -revoke` via remote-exec in the interim? (Default: interim now, build in N3.)
5. **DA proof default:** DCSync-krbtgt (non-destructive) as the standing proof, with add-to-Domain-Admins only behind a destructive opt-in? (Default: yes.)

## Review addenda (independent review, 25NOV2026)

A review of the chassis + 8 executors found four HIGH rollback/terminal integrity
holes (vacuous-verified rollbacks + a benign-phrase terminal match) — all fixed and
regression-tested (commit `a3fea34`). Two design constraints it raised bind the
engine build:

- **D4 (ChainEngine):** when racing top-k disjoint chains with early-exit, a losing
  sibling's mutating edges must be rolled back **and the rollback VERIFIED** (not
  merely attempted) before the run reports DA-proved-and-clean. "Attempted" rollback
  is insufficient given how easily a vacuous verify slips through (the four holes).
- **D2 (ToolAdapter fallback):** a *mutating* adapter that partially applied before
  the next adapter is tried must roll back its partial mutation before fallback —
  define rollback-across-fallback, don't just try the next tool.
- **D3 is the structural fix** for the whole class: artifact predicates / attribute
  re-reads (a file/CA-DB/CRL/LDAP read that *positively confirms* the end state),
  never "I couldn't observe it, so assume success." Prioritize D3 in the H tranche.

## Unverified assumptions to pin in-lab
Exact tool output markers across versions (ntlmrelayx/certipy/Coercer/krbrelayx) — mitigated by D3 artifact predicates; certipy `relay` vs ntlmrelayx `--adcs` behavior for ESC8/ESC11; StrongCertBinding behavioral fingerprint reliability; whether destroying `.pfx` is accepted as sufficient ESC1 rollback by the harness/owner (D5.1 — flagged for review).
