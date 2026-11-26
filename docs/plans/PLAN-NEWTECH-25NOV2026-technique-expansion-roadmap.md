# PLAN-NEWTECH (25NOV2026) — technique-expansion roadmap

**Status:** DRAFT → owner review (reorder / greenlight) → per-tranche: plan → 1 review → build → probe → prove.
**Context:** the toolchain covers **15** techniques today (KERBEROAST, ASREP, CONSTRAINED-DELEG-PT,
UNCONSTRAINED-DELEG, RBCD, SHADOW-CREDS, LAPS, OPENSHARES-WRITE, COERCION, NTLM-RELAY, ADCS-ESC1,
ESC8, ESC11, CERTIFRIED, DCSYNC). This roadmap enumerates the techniques to **add** and sorts them
into tranches for owner sign-off. Each added technique becomes a `ValidationExecutor` + a detect
probe + a capability-state edge (so it joins the chaining engine), and is proven on (re-configurable)
GOAD before its `verified_recipe` flips.

## Selection criteria (how tranches were ordered)
1. **DA-impact** — does it reach Domain Admin (the "prove DA in minutes" headline)?
2. **Engagement-commonality** — how often it's the real path in live AD.
3. **Composition value** — does it add a reusable *edge* the chaining engine can route through?
4. **GOAD-demonstrability** — can we prove it on the lab (several already confirmed present).
5. **Effort / pattern-reuse** — cheap wins (reuse ADCS/ticket/ACL patterns) vs net-new tooling.

## Proposed tranche order (owner may reorder)
| # | Tranche | Techniques | Primary impact | GOAD-demo | Effort | Why here |
|---|---------|-----------|----------------|-----------|--------|----------|
| **T1** | Instant-DA n-days | Zerologon, noPac (sAMAccountName spoof), PrintNightmare | **DA** / SYSTEM | Yes (DCs `no_update`) | Med | Highest headline value; each is a one-shot DA |
| **T2** | ADCS completion | ESC2, ESC3, ESC4, ESC5, ESC6, ESC7, ESC9, ESC10, ESC13, ESC15, ESC16, Golden-Cert | **DA**/priv | Yes (braavos has ESC6/7/9/13) | Low | Reuses our cert→PKINIT pattern; lab is ADCS-rich |
| **T3** | ACL / object-takeover edges | GenericAll, GenericWrite, WriteDACL, WriteOwner, ForceChangePassword, AddSelf/AddMember, Targeted-Kerberoast, GPO-abuse | lateral→**DA** | Yes | Low-Med | The BloodHound edges — **biggest composition win** for the chaining engine |
| **T4** | Kerberos ticket forging | Golden Ticket, Silver Ticket, Diamond Ticket, Sapphire Ticket | persistence/**DA** | Yes | Low | Reuses DCSync krbtgt output; terminal persistence edges |
| **T5** | Credential access | GMSA read, DPAPI (domain backup key), remote SAM/LSA secrets, UnPAC-the-hash, Timeroasting | cred→priv | Yes | Med | Secret-recovery edges feeding the graph |
| **T6** | Delegation & relay extras | Bronze Bit (CVE-2020-17049), S4U2self-abuse, Kerberos-relay (krbrelayx), DFSCoerce, ShadowCoerce, WebDAV-coercion | **DA**/lateral | Yes | Med | Completes the delegation + coercion families |
| **T7** | Trusts & cross-forest | SID-history injection, trust-key extraction→inter-realm TGT, cross-forest kerberoast/ASREP, foreign-group abuse | cross-domain **DA** | Partial (GOAD multi-domain) | High | Advanced; depends on T4 (forging) |
| **T8** | Emerging | BadSuccessor (dMSA, 2025), new CVEs as they land | **DA** | Needs 2025 DC | High | Cutting-edge; lab may need a Server 2025 DC |

## Per-tranche detail

### T1 — Instant-DA n-day CVEs
- **Zerologon (CVE-2020-1472)** — Netlogon auth bypass → reset the DC machine password → DCSync. **Destructive** (must restore the DC's original machine password from the registry hash; rollback = restore). Terminal `replication_dump`. DA.
- **noPac (CVE-2021-42278/42287)** — create a computer (MAQ>0), clear its SPN, rename to a DC's sAMAccountName, request an S4U ticket → DA. Mutating (computer create/rename; rollback = delete). DA.
- **PrintNightmare (CVE-2021-1675 / 34527)** — spooler RCE/LPE → SYSTEM on the target (DC if spooler on). Terminal `code_exec`/`authn_success`. Mutating (drops a DLL; rollback = remove).

### T2 — ADCS completion (reuses the ADCS-ESC1/ESC8 executor base)
- **ESC2/ESC3** (any-purpose / enrollment-agent EKU), **ESC4** (template ACL write → make it ESC1), **ESC5** (CA object ACL), **ESC6** (EDITF_ATTRIBUTESUBJECTALTNAME → SAN on any template), **ESC7** (CA Manager/Officer → approve/ESC6), **ESC9/ESC10** (no-security-extension / weak cert mapping), **ESC13** (issuance-policy→group link), **ESC15** (CVE-2024-49019 app-policy, v1 templates), **ESC16** (security extension disabled). **Golden Certificate** (steal the CA private key → forge arbitrary certs). All terminal `cert_issued_and_used` → PKINIT → DA.

### T3 — ACL / object-takeover primitives (the chaining-engine edges)
- **GenericAll / GenericWrite** over a user/computer → pivot to Targeted-Kerberoast / Shadow-Creds / RBCD / reset-password (mutating; verified rollback restores the ACL/attr). **WriteDACL / WriteOwner** → grant self rights then abuse. **ForceChangePassword** (mutating; rollback restores). **AddSelf/AddMember** to a privileged group (mutating; rollback removes). **Targeted Kerberoast** (write a SPN → roast → restore). **GPO abuse** (WriteGPO → immediate scheduled task → SYSTEM; rollback removes the task). These are the highest-value *edges* — each becomes a graph edge the engine composes toward DA.

### T4 — Kerberos ticket forging (reuses DCSync krbtgt)
- **Golden Ticket** (krbtgt hash → forge any TGT), **Silver Ticket** (service account key → forge a service ticket), **Diamond Ticket** (decrypt+modify a real TGT), **Sapphire Ticket** (S4U2self PAC of a high-priv user). Terminal `authn_success`/`persistence`. Non-mutating (ticket in memory) — clean terminals for the engine.

### T5 — Credential access
- **GMSA read** (read msDS-ManagedPassword → NT hash of a gMSA, often privileged), **DPAPI** (domain backup key → decrypt any user's masterkeys/secrets), **remote SAM/LSA secrets** (secretsdump of a member → local creds/cached), **UnPAC-the-hash** (PKINIT cert → recover the NT hash), **Timeroasting** (unauthenticated — roast computer accounts via NTP). Terminal `secret_recovered`.

### T6 — Delegation & relay extras
- **Bronze Bit (CVE-2020-17049)** — forge the S4U2self service ticket to bypass "not delegatable"/protocol-transition. **S4U2self-abuse** (constrained deleg w/o protocol transition via a self ticket). **Kerberos relay** (krbrelayx → relay AS-REP/TGT to LDAP/SMB/ADCS). **DFSCoerce (MS-DFSNM)**, **ShadowCoerce (MS-FSRVP)**, **WebDAV coercion (PushSubscription/Change-Notify)** — coercion vectors beyond PetitPotam/printerbug.

### T7 — Trusts & cross-forest
- **SID-history injection** (intra/inter-forest → DA via a golden ticket with an EA SID), **trust-key extraction** (→ forge an inter-realm TGT across a trust), **cross-forest kerberoast/ASREP**, **foreign-group membership** abuse. Depends on T4.

### T8 — Emerging
- **BadSuccessor** (dMSA abuse, Server 2025 — simulate any user via a delegated MSA → DA). Needs a 2025 DC added to GOAD (per owner's "simulate non-included vulns" license). Plus new CVEs as they land.

## Owner decisions (25NOV2026) — GREENLIT
- **Execution order:** **T3 → T4 → T6 → T2 → T7 → T1 → T8.** (T5 credential-access omitted from the
  order — PARKED at the end / pending owner confirm; not in the active queue.)
- **Destructive handling:** every destructive op PRINTS A WARNING and requires the operator to press
  **yes** to proceed (interactive confirmation gate, not a silent `--allow-destructive`). Applies to
  T1 Zerologon/PrintNightmare and any mutating step.
- **Cadence:** per tranche — plan → 1 independent (cross-family) review → build → probe → prove on
  (re-configurable) GOAD → integrate. One tranche at a time; each opens by reviewing the prior output.
- **Delegation model:** token-heavy work (executor/test/boilerplate implementation, large reads,
  verbose drafts) is delegated to **Codex Sol** via `/codex-interop` file-handoff; Claude (Opus)
  SUPERVISES — plans, reviews diffs, runs the gates, proves on GOAD, commits/integrates. Usage-
  conserving (owner directive 25NOV2026: low on Opus usage).

## Open ordering questions for the owner
1. **Order:** is `T1 (instant-DA) → T2 (ADCS) → T3 (ACL edges) → …` right, or do you want **composition-first** (T3 ACL edges earlier, since they give the chaining engine the most new routes), or **ADCS-first** (T2, since the lab is already ADCS-rich and it's the cheapest)?
2. **Scope cuts:** any tranche/technique to drop (e.g., T7 trusts or T8 emerging if out of scope for now)?
3. **Destructive classes:** T1 Zerologon + PrintNightmare mutate the DC — keep them (with verified restore) or gate behind an explicit `--allow-destructive` and defer?
4. **Per-tranche cadence:** same ops method as before (plan → 1 independent review → build → probe → prove on GOAD), one tranche at a time, each opening by reviewing the prior tranche's output?
