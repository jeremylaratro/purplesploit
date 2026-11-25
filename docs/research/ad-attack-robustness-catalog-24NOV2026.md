# AD Attack Robustness Catalog (24NOV2026)

Synthesis of five parallel research lanes for making the PLAN-003 validation toolchain **bulletproof** (works across real 2024–2026 environments, version/patch variation handled) and capable of **proving Domain Admin in minutes**. Judged by `ad-lab-harness`. This is the durable reference behind `docs/adr/ADR-002-24NOV2026-bulletproof-hardening-and-DA-chaining.md`.

Lanes: (1) Kerberos roasting + delegation, (2) ADCS ESC1–ESC16 + Certifried, (3) coercion + NTLM/Kerberos relay, (4) critical n-day CVEs, (5) DA-in-minutes chaining. Every claim here carries an inline source in the per-lane sections below.

---

## 0. Cross-cutting principles (the spine of "bulletproof")

1. **One universal, version-stable proof of DA: `DCSync` of `krbtgt`.** Build-independent, non-destructive (replication is a read), no cleanup, and only a DA-equivalent can replicate secrets — so success *is* DA. Every lane converges here. This is the engine's default DA predicate; terminal kind = `replication_dump` (already in the harness vocabulary).
2. **Detect before you fire.** Every technique gets a *non-destructive* precondition CHECK (LDAP/SMB/registry reads) that predicts success, so the tool only attempts what will work and can *explain every skip*. The check set: `ms-DS-MachineAccountQuota`, the "Add workstations" right, `msDS-SupportedEncryptionTypes` (RC4 vs AES → crackability), UAC delegation bits (`TRUSTED_FOR_DELEGATION 0x80000`, `TRUSTED_TO_AUTH_FOR_DELEGATION 0x1000000`, `DONT_REQ_PREAUTH 0x400000`), `msDS-AllowedToActOnBehalfOfOtherIdentity` / `msDS-AllowedToDelegateTo` reads, LDAP signing + channel-binding mode, SMB signing, patch build (`operatingSystemVersion`), the Certifried SID-extension oracle, and `certipy find` for the whole ESC surface.
3. **Robust predicates = artifacts / attribute re-reads, never console strings.** A loot file on disk, a `.pfx` that parses + PKINITs, a `<DC>$.ccache` that authenticates, an **LDAP re-read** of a written attribute (and a post-rollback re-read confirming it cleared). Record the Kerberos etype inside each roasted hash and auto-select the hashcat mode.
4. **Safety tiering drives default behavior:**
   - **crack-free deterministic (default frontier):** ESC8/ESC1/ESC11 + Certifried + shadow-creds + RBCD + constrained/unconstrained delegation + noPac.
   - **destructive, opt-in, verified-restore:** Zerologon (severe — resets DC machine pw), PrintNightmare + CVE-2025-33073 (code-exec on a live DC).
   - **crack-dependent, masked behind `--allow-crack` + time budget:** kerberoast, AS-REP. Over-budget → `inconclusive`, finding preserved.
5. **Clock skew + etype are the silent Kerberos killers.** `KRB_AP_ERR_SKEW` red-walls everything at >300 s drift → `faketime`/`rdate -n <DC>` before every Kerberos request. Guessing RC4 on an AES hash wastes the whole crack → record etype → mode 13100/19600/19700/18200.
6. **Mutation-ness is per-achieved-terminal, harness-owned** (already fixed in the scorer, commit f305f3d): any chain achieving a write terminal (`rbcd_access`, `cert_issued_and_used`, `file_write_readback`) must carry a verified rollback or it scores `inconclusive`.

---

## 1. Ranked fastest reliable zero-to-DA paths (2026), crack-free first

Start state: creds for one low-priv user (the normal post-enumeration state). Wall-clock = execution only.

| # | Path | Key preconditions | Crack-free | Wall-clock | Reliability 2026 | Proof (terminal) |
|---|------|-------------------|:---------:|-----------|------------------|------------------|
| 1 | **ESC1** direct cert (SAN=DA, `-sid`) → PKINIT → DCSync | vuln template (EnrolleeSuppliesSubject + ClientAuth + no approval) | ✅ | 30–90 s | High where present | `cert_issued_and_used`→`replication_dump` |
| 2 | **Coerce DC → relay to ADCS ESC8** → DC cert → PKINIT → DCSync | CA web enrollment, HTTP no EPA; a coercion vector | ✅ | 1–3 min | **High** | `cert_issued_and_used`→`replication_dump` |
| 3 | **Shadow Credentials** on a Tier-0 object → PKINIT → DCSync | write edge (`GenericWrite`/`AddKeyCredentialLink`) to Tier-0; PKINIT | ✅ | 1–2 min | High where ACL edge exists | `secret_recovered`→`replication_dump` |
| 4 | **Coerce DC → relay to LDAP → RBCD** on DC → S4U → DCSync | LDAP signing/CBT **off**; computer control (MAQ>0 / owned) | ✅ | 1–3 min | High→Med (2025 LDAP hardening shrinking) | `rbcd_access`→`replication_dump` |
| 5 | **Unconstrained deleg** TGT capture → DCSync | control an unconstrained host; coercion vector | ✅ | 1–2 min | Med-High | `replication_dump` |
| 6 | **Certifried** (CVE-2022-26923) | unpatched ADCS/DC (pre-May-2022); MAQ>0; Machine template | ✅ | 1–2 min | Low-Med (patched) | `cert_issued_and_used`→`replication_dump` |
| 7 | **noPac** (CVE-2021-42278/87) | unpatched DC (pre-Nov-2021); MAQ>0 | ✅ | 15–60 s | Low-Med (patched) | `replication_dump` |
| 8 | **Zerologon** (CVE-2020-1472) — DESTRUCTIVE | unpatched DC (pre-Aug-2020/Feb-2021 enforce) | ✅ | 15–60 s | Low | `replication_dump` |
| 9 | **Kerberoast DA-SPN → crack → re-auth** | DA-group SPN account w/ weak pw | ❌ | min→hours→never | Low for a demo | `authn_success` |

**Headline:** the reliable "minutes" tier is **#1–#5**, all crack-free, all terminating in non-destructive DCSync. **#2 (coerce → ESC8 → DCSync) is the single most reliable no-creds-needed path** because ESC8 **bypasses the LDAP signing + channel-binding hardening** that is increasingly killing the RBCD/shadow-cred LDAP relay paths, and CA web enrollment ships NTLM-over-HTTP without EPA by default ([dirkjanm ESC8](https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/), [SpecterOps low-priv HTTP→LDAP, Aug 2025](https://specterops.io/blog/2025/08/22/operating-outside-the-box-ntlm-relaying-low-privilege-http-auth-to-ldap/)). #6–#8 are faster *when present* but CVE-gated → opportunistic accelerators, never default.

---

## 2. Chaining-engine model (DA in minutes)

**State/technique graph.** Nodes = capability states (`S0_user_creds → S_computer_control → S_coerced_auth → S_cert_identity → S_dc_tgt → S_rbcd_write → S_impersonation_tgt → S_krbtgt_hash → S_DA`). Edges = the existing per-technique executors, each carrying `pre`, `eff`, `crack_free`, `mutating`, `rollback`, `terminal_kind`, and each already emitting a `proof.v1` receipt. Any `S0 → … → S_DA` is a candidate chain (BloodHound-style shortest-path over *executor* edges instead of ACL edges).

**Selection:** (1) fan out non-mutating precondition probes concurrently to light up viable edges; (2) weighted shortest path cost `= base_latency × (1/reliability) × (crack_free ? 1 : BIG) × (destructive ? GATE : 1)`; (3) race the top-k *disjoint* chains off one coercion listener; (4) **early-exit on the first `proved` DCSync**, cancel siblings, roll back any mutating edges they left. The engine orders techniques, never re-implements them — it threads one edge's non-secret output state into the next edge's `pre`.

**Default DA proof = DCSync of krbtgt** (`replication_dump`, read-only, no cleanup). Alternative gated proofs: admin action on a DC (`authn_success`/`file_write_readback` canary), golden-ticket use (confirmation/persistence), add-to-Domain-Admins (destructive, opt-in, read-back-verified removal). Post-ex primitives as edges: DCSync (`secretsdump`), golden/silver/diamond ticket (`ticketer`/Rubeus), PtH/PtT/OverPass (all read/ephemeral).

Sources: [ired.team ADCS+PetitPotam→krbtgt](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/adcs-+-petitpotam-ntlm-relay-obtaining-krbtgt-hash-with-domain-controller-machine-certificate), [Praetorian LDAP-relay ACL paths](https://www.praetorian.com/blog/how-to-exploit-active-directory-acl-attack-paths-through-ldap-relaying-attacks), [BloodHound CoerceAndRelayNTLMtoLDAP](https://bloodhound.specterops.io/resources/edges/coerce-and-relay-ntlm-to-ldap.md), [SpecterOps ADCS attack paths in BloodHound](https://specterops.io/blog/2024/01/24/adcs-attack-paths-in-bloodhound-part-1/).

---

## 3. Per-technique robustness (field failure modes, nuances, fallbacks)

### 3.1 Kerberos roasting + delegation
- **Kerberoast:** exclude computer/MSA/gMSA/dMSA (uncrackable 120-char pw); AES-only account → hash obtained but uncrackable → predict crackability from `msDS-SupportedEncryptionTypes` (RC4 bit `0x4` / unset-on-user = fast mode 13100; AES `0x8`/`0x10` = slow 19600/19700). **Server 2019+ KDC ignores the client's requested etype** → RC4 downgrade via Rubeus `/tgtdeleg` "generally fails" on 2019+. RC4 deprecated/disabled by default in Win11 24H2/Server 2025. Fallback: `nxc ldap --kerberoasting` / `GetUserSPNs.py -request` → `Rubeus kerberoast /tgtdeleg|/rc4opsec`. ([SpecterOps AES-256 kerberoast 2025](https://specterops.io/blog/2025/10/21/is-kerberoasting-still-a-risk-when-aes-256-kerberos-encryption-is-enabled/), [MS Oct-2024 guidance](https://www.microsoft.com/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting), [KB5021131](https://support.microsoft.com/help/5021131))
- **Targeted kerberoast** (Write-SPN edge): add `cifs/<sam>`, roast, delete — **cleanup re-read mandatory** (`targetedKerberoast.py` / `nxc --targeted-kerberoast`). **Kerberoast without pre-auth** (`GetUserSPNs.py -no-preauth` via an AS-REP-roastable account). ([thehacker.recipes targeted](https://thehacker.recipes/ad/movement/dacl/targeted-kerberoasting), [Swarm kerberoast-without-SPNs](https://swarm.ptsecurity.com/kerberoasting-without-spns/))
- **AS-REP:** only `DONT_REQ_PREAUTH` (`0x400000`) accounts; AES-only → `KDC_ERR_ETYPE_NOTSUPP`. MitM variant `ASRepCatcher relay` forces RC4. Fallback: `nxc --asreproast` / `GetNPUsers.py -request` → `Rubeus asreproast`. ([thehacker.recipes asreproast](https://thehacker.recipes/ad/movement/kerberos/asreproast), [MWR](https://www.mwrcybersec.com/?p=1815))
- **Unconstrained deleg:** exclude Protected Users (RID `-525`) / `AccountNotDelegated` (TGT not forwarded). Detect `TRUSTED_FOR_DELEGATION 0x80000`, exclude DCs. Capture: `krbrelayx` / `Rubeus monitor`; coerce: printerbug → PetitPotam → dfscoerce. **Fastest DA: coerce DC → DC$ TGT → DCSync.** ([BloodHound CoerceToTGT](https://bloodhound.specterops.io/resources/edges/coerce-to-tgt))
- **Constrained deleg (+PT):** `KDC_ERR_BADOPTION` = target sensitive **or** no protocol transition (`TRUSTED_TO_AUTH_FOR_DELEGATION 0x1000000` absent → needs RBCD/coercion pivot). **Prefer RID-500 Administrator** (delegatable even in Protected Users). **`/altservice` sname-swap** (`http/DC`→`ldap/DC`) → DCSync — the `sname` isn't integrity-protected. Bronze Bit (`getST -force-forwardable`, CVE-2020-17049) on unpatched DCs. ([thehacker.recipes constrained](https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained), [SpecterOps Rubeus constrained](https://docs.specterops.io/ghostpack/rubeus/constrained-delegation-abuse))
- **RBCD:** `MachineAccountQuota=0` blocks `addcomputer` → workarounds: shadow-creds on an owned computer, or SPN-less U2U with a sacrificial user. **MAQ>0 is not enough — also need the "Add workstations to domain" right.** Write path: `GenericWrite`/`GenericAll`/`WriteDacl`/`WriteOwner`/**`WriteAccountRestrictions`** (easy-to-miss). RBCD invisible in UAC — read `msDS-AllowedToActOnBehalfOfOtherIdentity` directly. `addcomputer -method SAMR|LDAPS` (plain LDAP can't set the pw). DFL ≥ 2012. **Rollback: attribute re-read for write → `-action flush` → re-read to confirm cleared.** ([thehacker.recipes rbcd](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd), [netspi MAQ](https://www.netspi.com/blog/technical-blog/network-pentesting/machineaccountquota-is-useful-sometimes/), [SpecterOps WriteAccountRestrictions](https://specterops.io/blog/2025/10/01/writeaccountrestrictions-war-what-is-it-good-for/))

### 3.2 ADCS (ESC1–ESC16 + Certifried)
**StrongCertificateBindingEnforcement timeline** ([KB5014754](https://support.microsoft.com/en-us/help/5014754)): May-2022 Compatibility → **Feb-11-2025 Full Enforcement by default** → Sep-2025 opt-out removed. **Under Full Enforcement, bare UPN/SAN-swap (ESC9/ESC10/bare-ESC16) die** (DC Event 39; SID mismatch = Event 41). **Still alive:** any attack supplying the target SID in the cert — ESC1/ESC6/ESC15/Certifried via `-sid`, or SID-in-SAN URI `tag:microsoft.com,2022-09-14:sid:<SID>` when the SID extension is stripped (ESC16+ESC6, ESC15+SID-in-SAN). **Fingerprint the mode behaviorally** (UPN-swap probe + Event 39/41). ([trackr.live ESC16 bypass](https://www.trackr.live/?p=1226), [Netwrix ESC9/ESC16](https://netwrix.com/en/resources/blog/esc9-esc16-same-flaw-different/))

| ESC | Detect | DA-speed | Rollback |
|-----|--------|----------|----------|
| ESC1 | EnrolleeSuppliesSubject+ClientAuth+noApproval | **Fastest** | destroy `.pfx` (no AD change) |
| ESC2/ESC3 | AnyPurpose / CertReqAgent EKU | Fast (on-behalf-of) | destroy `.pfx` |
| ESC4 | dangerous template ACL | Fast (→ESC1) | **`-save-configuration` first, restore JSON** (CA caches edits min-hrs) |
| ESC6 | `User Specified SAN: Enabled` | High *chained* (dead alone in enforce) | restore EditFlags if set |
| ESC7 | ManageCA/ManageCertificates | High | `-remove-officer`, `-disable-template SubCA`; **officer right = can revoke** |
| **ESC8** | Web Enrollment, HTTP no EPA | **Fastest no-cred** (coerce) | destroy `.pfx`; **use `DomainController` template for a DC, not Computer** |
| ESC9/10 | NO_SECURITY_EXTENSION / weak DC maps + write victim | Medium | **restore UPN + `shadow clear`**; Schannel-only → accept `-ldap-shell` as success |
| ESC11 | `Enforce Encryption: Disabled` (RPC/ICPR) | High | destroy `.pfx`; `-ca` required |
| ESC13 | `OIDGroupLink` (BloodHound) | **conditional** (= linked group) | destroy `.pfx` |
| ESC15 | V1 schema + ESS + unpatched (CVE-2024-49019) | High | destroy `.pfx`; `-application-policies`; PKINIT fails→Schannel |
| ESC16 | `DisableExtensionList` has `…311.25.2` | High | restore UPN/shadow/CA-reg |
| Certifried | MAQ>0 + Machine template; SID-ext oracle | **Fastest from plain user** | **delete machine acct**, revert dNSHostName |

**Revocation (the resolved blocker):** certipy cannot revoke, any version. For 10/13 ESCs no AD object changes → **destroying `.pfx`/key is a complete functional rollback**. Formal CA-DB revoke = `certutil -revoke <serial> 6` (reversible Certificate Hold) via impacket remote-exec + `certutil -CRL`; **confirm via CA-DB disposition=Revoked + serial in CRL, NOT via PKINIT re-test (KDC ignores CRLs)**. Build opportunity: network-native MS-CSRA `ICertAdminD::RevokeCertificate` Opnum 10 (an ESC7 officer cred already has the *right*). Extracted NT hash/TGT is unrollbackable → flag the principal for rotation. ([Certipy wiki cmd ref](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference), [MS certutil](https://learn.microsoft.com/windows-server/administration/windows-commands/certutil), [MS-CSRA RevokeCertificate](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-csra/d2fb086e-8447-409b-bd5e-60c9e6b05c14))

### 3.3 Coercion + relay
- **Coercion (use `Coercer` as the multiplexer: `scan` then `coerce`):** reliable on a fully-patched 2026 DC = **authenticated MS-EFSR (PetitPotam)** and **MS-DFSNM (DFSCoerce)** — both no-CVE/won't-fix, only RPC filters stop them. MS-RPRN (PrinterBug) only if Spooler up (often off on hardened DCs). MS-FSRVP (ShadowCoerce) needs the VSS agent (rare on DCs). WebDAV/WebClient = HTTP feeder (→ HTTP relay, SYSTEM context) when WebClient runs. CVE-2025-33073 reflective SMB relay (patched Jun-2025, partial). ([p0dalirius Coercer](https://github.com/p0dalirius/Coercer), [thehacker.recipes MS-EFSR](https://thehacker.recipes/ad/movement/mitm-and-coerced-authentications/rpc-coercions/ms-efsr), [Synacktiv CVE-2025-33073](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025))
- **Relay matrix:** **HTTP→ADCS ESC8 is the best** (immune to LDAP signing/CBT). HTTP→LDAP (HTTP NTLM doesn't negotiate signing → clean) when LDAP signing off. SMB→LDAP needs `--remove-mic` (CVE-2019-1040, mostly dead). SMB→SMB dying (24H2/Server 2025 require signing). Detect mode: `CheckLDAPStatus.py` / NetExec LDAP banner. ([SpecterOps Aug-2025](https://specterops.io/blog/2025/08/22/operating-outside-the-box-ntlm-relaying-low-privilege-http-auth-to-ldap/), [MS SMB signing 2025](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591))
- **ntlmrelayx flags (confirmed):** `-t/-tf`, `-l/--lootdir`, `-of`, `-smb2support`, `--remove-mic`, `--delegate-access` (RBCD), `--shadow-credentials`, `--dump-laps/--dump-gmsa`, `--adcs --template`, `-socks`. SAM/secrets/pfx land as lootdir files = **robust artifact predicate**. **krbrelayx** (unconstrained TGT capture → `<DC>$.ccache`; Kerberos relay) and **Coercer** are **NOT installed by default** — provision in bootstrap.

### 3.4 Critical n-day CVEs (safety-ranked)
| CVE | Vulnerable | Safe to automate | DA-speed | Rollback | SAFE check |
|-----|-----------|:----------------:|----------|----------|------------|
| Certifried 2022-26923 | AD CS pre-May-2022 | ✅ light gating | min | delete computer | baseline `User` cert **lacks** SID ext ("Certificate object SID" absent); MAQ>0 |
| noPac 2021-42278/87 | DC pre-Nov-2021 | ✅ light gating | **sec** | delete computer | MAQ>0; per-DC build < fixed CU |
| PetitPotam→ESC8 | CA web enroll no EPA | ✅ bounded coercion | min | revoke cert | `certsrv` HTTP no EPA (`Certipy find -vulnerable`) |
| BadSuccessor 2025-53779 | Server 2025 pre-Aug-2025 | ✅ light gating | min | delete dMSA | LDAP audit dMSA create/link rights |
| WinReg relay 2024-43532 | pre-Oct-2024 | ✅ bounded coercion | min (user cert) | revoke cert | Remote Registry + CA no EPA |
| PrintNightmare 1675/34527 | Spooler pre-Jul-2021 | ⚠️ opt-in (live service) | sec-min | remove acct/driver | `rpcdump` MS-RPRN/MS-PAR; Point-and-Print keys |
| Reflective relay 2025-33073 | unsigned SMB; Jun-2025 fix partial | ⚠️ opt-in (code-exec) | fast | remove principal | SMB signing not required |
| AD DS EoP 2025-21293 | pre-Jan-2025; needs NCO membership | ⚠️ opt-in (LPE) | fast | revert artifact | build + NCO membership |
| **Zerologon 2020-1472** | DC pre-Aug-2020/Feb-2021 | ❌ **last-resort, mandatory restore** | **sec** | **restore DC machine pw + verify** | Secura zero-challenge probe (non-destructive) |

**Zerologon invariants (never default-on):** successful non-destructive CHECK → dry-run that the original machine pw is recoverable from local SECRETS → persist original hash off-box → non-skippable restore → **restore verification** (probe now fails + replication healthy) → single DC, alarm-and-halt on restore failure. ([SecuraBV checker](https://github.com/SecuraBV/CVE-2020-1472), [dirkjanm exploit+restore](https://github.com/dirkjanm/CVE-2020-1472), [CrowdStrike noPac](https://www.crowdstrike.com/blog/nopac-exploit-latest-microsoft-ad-flaw-may-lead-to-total-domain-compromise/), [Akamai BadSuccessor](https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch), [Akamai WinReg](https://www.akamai.com/blog/security-research/winreg-relay-vulnerability))

---

## 4. New techniques to add beyond the original 11

Priority additions surfaced by the research (detail → ADR-002 tranches): **ESC8** (keystone coerce→DA), **ESC11** (RPC relay alt to ESC8), **Certifried**, **noPac**, **shadow-creds-via-relay**, **DCSync** (as both escalation edge and universal DA proof), **targeted kerberoast** + **kerberoast-without-preauth**, constrained-deleg **`/altservice`**, **`WriteAccountRestrictions`** RBCD write-path, **golden/silver/diamond ticket + PtH/PtT/OverPass** (post-ex edges), and modern n-days **BadSuccessor** (Server 2025), **CVE-2025-33073**, **CVE-2024-43532 (WinReg)**, **ESC13/ESC15/ESC16** (certipy 5.x). Plus the **MS-CSRA RevokeCertificate** primitive for clean cert rollback.

---

## 5. Tool provisioning + install reality
Confirmed on `kali-vr` + host venv: present = impacket-*, certipy-ad 5.1.0, nxc/NetExec, secretsdump. **Absent (must provision for the listener/chaining tranches):** `krbrelayx.py`, `Coercer`, `PetitPotam.py`, `printerbug.py`, `dfscoerce.py` (Coercer is on the host venv). Also pin: certipy 5.x `-ldap-scheme ldap`/`-no-ldap-channel-binding`/`-no-ldap-signing` as LDAP-bind fallbacks; `CheckLDAPStatus.py` for signing/CBT detection. Prefer **certipy `relay`** (single-tool) or **ntlmrelayx `--adcs`** for ESC8.
