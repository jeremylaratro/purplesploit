# PLAN-003 capability coverage against the OCD AD mind map

**Date:** 16NOV2026 · **Status:** FINAL (Sol peer review R1 incorporated) · recommendations target plan revision **r6**.

**Basis of record:** Orange Cyberdefense AD mind map v2025.03, parsed taxonomy
(`docs/research/OCD-AD-MINDMAP-TAXONOMY-16NOV2026.md`, full commands in
`OCD-AD-MINDMAP-OPERATOR-REFERENCE-16NOV2026.md`, machine-readable
`docs/research/data/ocd-ad-mindmap-2025.03.taxonomy.json`), pinned to source commit
`6d16ca0d`. **Measured against:** PLAN-003's 17-capability attack-box denominator
(`docs/plans/PLAN-003-14NOV2026-ad-engagement-toolchain.md:292`).

**Authoring:** drafted by an Opus 5.5 subagent; adversarially reviewed by Sol
(`docs/reviews/OCD-MAPPING-PEER-REVIEW-SOL-R1-16NOV2026.md`, VERDICT FIX-FIRST, 8
findings, all source-verified and applied); integrated by the orchestrator. Parse
fidelity independently verified CLEAN.

> Scope: inventory / methodology cross-reference and gap analysis. No attack procedures.
> Every claim cites a `file:line` or an OCD category key.

## 0. Two denominators — do not conflate them (Sol #1)

- **Provisioning denominator (17 capabilities)** — what the P0-S3 offline lock must
  *resolve and install* (`PLAN-003:292`). Its exit (`PLAN-003:172`) is a provisioning
  test; P0-S4 qualifies the release; later sprints qualify production workflows.
- **Methodology denominator (17 OCD categories)** — what the engagement must be able to
  *exercise*, from the mind map.

This document is a **coverage ledger** that relates the two. It does **not** replace the
P0-S3 provisioning gate or the P0-S4 release gate. Any coverage-based acceptance must be
defined per profile with a bounded subject set and explicit treatment of deferred
categories — see §5.

**The denominator (provisioning), from `PLAN-003:292`:** PurpleSploit, Aranum, Nmap, DNS
client, LDAP client, SMB client, RPC client, Kerberos clients, NetExec, Impacket,
`pywinrm`, Certipy, PowerShell, RDP client, RustHound-CE, BloodHound CE Python collector,
BloodHound CE analysis service.

**Bundle today (`pt_provision/config/repositories.tsv:2-8`):** `purplesploit`, `aranum`,
`supwngo`, `winbin` (WinBins), `GTFOBins`, `LOLBAS`, `pentest_scripts`. Only PurpleSploit
and Aranum directly satisfy a denominator identity — **2/17 measured** (`PLAN-003:294`);
the remaining 15 are native packages/collectors the P0-S3 lock must resolve
(`PLAN-003:172`). WinBins/GTFOBins/LOLBAS are bundled but **not named** in §3.6 — see §3b.

**Verdict scale** (ability to *self-containedly exercise* the phase with the current
denominator, from a Linux attack box): **COVERED** = a denominator capability performs
the phase's core subjects end to end; **PARTIAL** = core subjects reachable but one or
more named subjects have a missing prerequisite or no denominator equivalent; **GAP** =
no denominator capability performs the phase.

## 1. Coverage matrix (all 17 OCD categories)

| # | OCD category (key) | Subj. | Denominator coverage | Verdict | Unmet (subject → missing prerequisite) |
|---|---|--:|---|---|---|
| 1 | No Credentials (`no_creds`) | 11 | Nmap, DNS/LDAP/SMB/RPC clients, NetExec, Kerberos clients, Impacket (GetNPUsers) | **PARTIAL** | Poisoning (no Responder); Coerce (no RPC coercion trigger); PXE (no SCCM) |
| 2 | Valid user / no password (`valid_user`) | 2 | NetExec spray, Impacket GetNPUsers/GetUserSPNs, LDAP, PowerShell | **COVERED** | ends at ASREP/roast output; cracking → `crack_hash`. Spray automation not authorized while C4 unset |
| 3 | Valid Credentials (`authenticated`) | 9 | BloodHound-CE stack, RustHound-CE, LDAP, NetExec, Impacket, Certipy (ADCS enum) | **PARTIAL** | SCCM enum; Coerce (RPC trigger); Scan-Auto audit layer |
| 4 | Low access / privesc (`low_access`) | 8 | Aranum privesc enum, PowerShell | **PARTIAL** | AppLocker/UAC checks, SEImpersonate/potato, Kerberos relay, file search — **server-applicable, not WS01-only** (Sol #8) |
| 5 | Kerberos Delegation (`delegation`) | 5 | Impacket (findDelegation/getST/getTGT/rbcd/addcomputer), BloodHound MATCH | **PARTIAL** | Unconstrained abuse needs force-auth **coercion** + ticket capture (no krbrelayx/coercion in denominator) (Sol #2) |
| 6 | Admin access (`admin`) | 6 | NetExec (sam/lsa/dpapi/lsassy), Impacket (secretsdump/reg/regsecrets) | **PARTIAL** | on-host mimikatz LSASS; dedicated DPAPI looters |
| 7 | Domain admin (`dom_admin`) | 2 | Impacket (secretsdump DCSync+ntds; `dpapi.py backupkeys`) | **PARTIAL** | ntds COVERED. "Grab backup Keys" = DPAPI domain PVK (map tool `donpapi`, not bundled); equivalent is Impacket `dpapi.py backupkeys` — **pending bundled-version evidence** (Sol #7) |
| 8 | Quick Compromise (`low_hanging`) | 11 | Impacket mssqlclient (Database/MSSQL enum) | **PARTIAL** | Database subject covered; the other 10 (Zerologon/EternalBlue/Tomcat/Log4shell/Veeam/GLPI/Exchange…) are n-day/service exploitation — out of GOAD scope (Sol #5) |
| 9 | MITM — Listen & Relay (`mitm`) | 3 | Impacket ntlmrelayx (**NTLM relay engine only**), NetExec | **PARTIAL** | no listener/poisoner (Responder), no IPv6 takeover (mitm6), no Kerberos relay (krbrelayx) (Sol #3) |
| 10 | Known vulns authenticated (`know_vuln_auth`) | 7 | Certipy (Certifried), Impacket (goldenPac/MS14-068/GPP), NetExec | **PARTIAL** | noPac/PrintNightmare/PrivExchange/ProxyNotShell PoCs; Exchange items need Exchange profile |
| 11 | ADCS (`adcs`) | 7 | Certipy (enum + ESC1/2/3/9/10/13 request paths), Impacket (ntlmrelayx, gettgtpkinit), LDAP | **PARTIAL** | ESC8/ESC11 need incoming-auth **coercion/relay** (not in denominator); ESC15 carries a Certipy **version/PR dependency** `#[PR 228]`; "all abuse modes" needs version evidence (Sol #4) |
| 12 | Lateral Move (`lat_move`) | 6 | Impacket (psexec/wmiexec/smbexec/atexec/dcomexec/mssqlclient/passthecert), NetExec, pywinrm, RDP, Certipy (pfx→auth) | **COVERED** | pywinrm ≠ full evil-winrm interactivity (parity caveat, not a gap) |
| 13 | Trusts (`trusts`) | 5 | Impacket (raiseChild/ticketer/lookupsid/mssqlclient/secretsdump), BloodHound/RustHound-CE, PowerShell, LDAP | **COVERED** | child→parent, SID-history, MSSQL links all have denominator tools |
| 14 | Crack hash (`crack_hash`) | 10 | — none — | **GAP** | hashcat/john in neither denominator nor bundle |
| 15 | ACLs/ACEs (`acl`) | 10 | BloodHound-CE (ACL analysis), Impacket (DCSync/dacledit), NetExec (LAPS/GMSA), Certipy (shadow creds), PowerShell | **PARTIAL** | GPO abuse (OUned) is a genuine small gap; shadow creds **covered by Certipy** (remove pyWhisker from the gap list — Sol #8) |
| 16 | SCCM (`sccm`) | 14 | Impacket (ntlmrelayx/mssqlclient/secretsdump — generic only), NetExec | **GAP** | no SCCM tooling; explicit later profile (`PLAN-003:63,241`) |
| 17 | Persistence (`persistence`) | 12 | Impacket ticketer (golden/silver/diamond/sapphire), Certipy (golden cert), PowerShell | **PARTIAL** | on-host-only: skeleton key, custom SSP, DCShadow, DSRM |

**Tally: COVERED 3 · PARTIAL 12 · GAP 2.** COVERED: `valid_user`, `lat_move`, `trusts`.
GAP: `crack_hash`, `sccm`. The denominator is strongest on the **credentialed → DA graph
path** (enumerate → BloodHound → ACL/delegation primitives → lateral → DCSync → tickets)
and weakest on **pre-auth poison/relay/coerce**, **hash cracking**, **SCCM**, and **n-day
exploitation**. (Grade changes vs the draft, all from Sol R1: `delegation`, `adcs`,
`dom_admin` COVERED→PARTIAL; `low_hanging` GAP→PARTIAL.)

## 2. Tool-capability gaps

Separate five distinct capabilities the draft had collapsed into one "relay gap" (Sol #3):

| Capability | In denominator? | Map tools | Needed by |
|---|---|---|---|
| NTLM **relay engine** | **Yes** (Impacket ntlmrelayx) | ntlmrelayx | mitm, adcs ESC8, sccm |
| **Poison / capture** (listen) | No | Responder, Pcredz, bettercap | no_creds, mitm |
| **Auth induction** (IPv6/LLMNR) | No | mitm6 | no_creds, mitm |
| **RPC coercion** (unauthenticated) | No | PetitPotam, Coercer, printerbug | no_creds, authenticated Coerce, delegation force-auth, adcs ESC8 |
| **Kerberos relay** | No | krbrelayx | mitm, low_access Kerberos-relay |

NetExec does provide *authenticated, permission-gated* file-based coercion (SCF/`--coerce`
style), so authenticated Coerce is partly reachable — but that does **not** remove the
**unauthenticated RPC-coercion** gap (Sol #3).

**Other true gaps:** offline **hash cracking** (hashcat/john) — cross-cutting terminal
step of `valid_user`/`authenticated`/`admin`/`no_creds` roasting; **on-host LSASS +
mimikatz-class persistence** — remote LSASS/secrets covered by NetExec/secretsdump, but
interactive dumping and 4 persistence primitives have no denominator entry.

**Covered by a denominator equivalent (corrected attributions — Sol #7):**
`certify.exe`→Certipy; `sharphound/rusthound/SOAPHound`→RustHound-CE + BH-CE collector;
`ldeep/ldapdomaindump/bloodhound-python`→LDAP client + BH-CE collector;
`evil-winrm`→pywinrm (command transport; not full interactivity); exec/mssql via Impacket.
Note: `gettgtpkinit.py`/`getnthash.py` are **PKINITtools**, `passthecert.py` is standalone,
`regsecrets.py` rides an **Impacket PR** — cite the real artifact, not "Impacket" wholesale.
`certsync` is an **ntds-dump** alternative (taxonomy lists it under *Dump ntds.dit*), **not**
a backup-key path.

**Out of scope / deferred:** SCCM tooling (later SCCM profile); n-day PoCs + nuclei/msf
(GOAD is a misconfiguration lab, not an n-day service lab); Potato/LOLBAS target-side
artefacts. A WinBins **repo row does not prove** specific binaries are bundled — an
artifact inventory is required before crediting it against any gap (Sol #8).

## 3. Denominator critique

**3a. Capabilities the map implies are missing:** (1) a **poison/coercion/Kerberos-relay**
capability — the map gives it a full column (`mitm`) and threads it through
`no_creds`/`authenticated`/`delegation`/`adcs`; (2) a **hash-cracking** capability;
(3) an **on-host LSASS/persistence** capability (or document as target-delivered with the
remote NetExec/secretsdump path as the measured substitute); (4) **SCCM** tooling, as a
named later-profile capability rather than an unqualified GAP.

**3b. Bundle ↔ denominator mismatch:** `WinBins`/`LOLBAS`/`GTFOBins` are bundled
(`repositories.tsv:5-7`) but unnamed in §3.6. Reconcile: either name what they cover
(after an artifact inventory) or mark them reference-only. Today "resolves all 17
capabilities" (`PLAN-003:172`) can pass while the bundle silently over/under-delivers.

**3c. Unequal weight:** ~5 heavy capabilities (PurpleSploit, Aranum, NetExec, Impacket,
BH-CE stack + Certipy) carry most covered subjects; RDP client (`PLAN-003:136`, one
subject), pywinrm (one), RPC/DNS clients (thin), and Linux-side PowerShell (largely
target-delivered) are single-column / payload capabilities — qualify them as such, don't
read "17" as 17 equal pillars.

## 4. GOAD target-capability coverage — evidence tiers (Sol #6)

GOAD topology is established (`PLAN-003:227-231`: 3 DCs + 2 members, **no workstation**; 2
forests / 3 domains; **bidirectional** external trust; AD CS on `dc01`+`srv03`, custom
templates on `dc03`). **Topology is not vulnerability evidence**: AD CS present ≠ Certifried
vulnerable; a DC ≠ Zerologon-vulnerable; a trust's existence ≠ a source of coerced auth.
GOAD *is* a seeded-vulnerability lab by design, but each phase claim must cite GOAD's own
**scenario definitions**, not the topology inventory. Classify each subject as
**topology-supported / scenario-qualified / conditional (patch-level) / absent** before
asserting any aggregate. The earlier "~13 of 17" figure is therefore **provisional pending
scenario-level citation** against GOAD's recipe data.

Phases needing extra profiles (already flagged by PLAN-003, retained — Sol #6): **SCCM**
(`:63,241`); **WS01** workstation depth (`:244-251,179`, a required later gate, not
optional); **Exchange/NHA** (`:241`). The one-way trust cases in `trusts` are **not**
qualified by GOAD's bidirectional external trust. `low_hanging` n-day services are absent
from GOAD entirely.

## 5. Recommendations for r6 (prioritized)

1. **Cite the OCD map as the methodology spec.** Add the taxonomy + reference + JSON to
   PLAN-003 §3.1 Evidence reviewed; anchor §3.6 (`:290-296`) to the 17 OCD category keys.
   *(sound — Sol)*
2. **Add this matrix as a coverage *ledger*, not the P0-S3 acceptance oracle.** Keep the
   provisioning exit (`:172`) and the P0-S4 release gate intact; define any coverage-based
   acceptance **per profile**, with a bounded subject set and explicit deferred-category
   treatment. *(revised per Sol #1 — do not conflate the two denominators)*
3. **Add a subject-level dependency ledger** (NEW, Sol's critical miss): per OCD subject,
   record tool, **version/PR evidence**, target prerequisite (creds/coercion/auth source),
   and qualification status. Category totals alone cannot support acceptance.
4. **Add the missing pre-auth capabilities as *separate* gates**, not one lump: poison/
   capture (Responder), auth induction (mitm6), **RPC coercion** (PetitPotam/Coercer),
   **Kerberos relay** (krbrelayx). The NTLM-relay engine is already present; naming them
   separately prevents the "closes the whole `mitm` column" overclaim. *(revised per Sol #3)*
5. **Resolve hash cracking:** add hashcat/john **or** declare a formal off-box cracking
   companion step so roasting tails are accounted for.
6. **Reconcile bundle ↔ denominator:** inventory `WinBins` artifacts; then either name the
   on-host-ops capability it provides or mark `WinBins`/`LOLBAS`/`GTFOBins` reference-only.
   *(revised per Sol #8 — inventory before crediting)*
7. **Name SCCM / Exchange-NHA / WS01 as explicit later-profile gates**, each with its OCD
   acceptance subject set; preserve WS01 as the already-required gate (`:179,244-251`).
8. **Scope `low_hanging` precisely:** exclude the specific n-day CVE/service subjects in
   writing (GOAD ships none), but **keep the Database/MSSQL subject** as covered — do not
   drop the whole category as GAP. *(revised per Sol #5)*
9. **Weight the denominator:** record RDP/pywinrm/RPC/DNS and Linux-side PowerShell as
   single-column / target-delivered, and focus P0-S3 qualification on the ~5 heavy
   capabilities.

### Appendix — source anchors

- Taxonomy/reference: `docs/research/OCD-AD-MINDMAP-TAXONOMY-16NOV2026.md`,
  `OCD-AD-MINDMAP-OPERATOR-REFERENCE-16NOV2026.md`,
  `docs/research/data/ocd-ad-mindmap-2025.03.taxonomy.json` (pinned `6d16ca0d`).
- Denominator / 2-of-17: `PLAN-003:292`, `:294`. P0-S3 exit: `:172`. GOAD: `:227-231`.
  Later profiles: `:63`, `:241`, `:244-251`, `:179`. RDP P2: `:136`.
- Bundle: `pt_provision/config/repositories.tsv:2-8`.
- Peer review: `docs/reviews/OCD-MAPPING-PEER-REVIEW-SOL-R1-16NOV2026.md`.
