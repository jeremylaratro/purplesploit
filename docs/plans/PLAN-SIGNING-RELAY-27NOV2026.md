# PLAN-SIGNING-RELAY (27NOV2026) — SMB/LDAP signing-posture + relay/reflection exposure

Owner queue item: "the ldap/smb signing bypass recently disclosed." Delivers a read-only VALIDATION edge
for the 2025 NTLM-relay CVEs, following the Bronze Bit lesson (research + probe susceptibility first, then
build the provable/honest classification).

## Research + susceptibility (probed 27NOV2026)
- **CVE-2025-33073** (SMB NTLM reflection, Synacktiv Jun 2025): RCE as SYSTEM on hosts **not enforcing SMB
  signing**; a signing-required target rejects the relayed/reflected session (the control that collapses the
  class). Tooling: ntlmrelayx + coercion + DNS manipulation.
- **CVE-2025-54918** (NTLM MIC/LDAP signing bypass): needs **Server 2025** without CVE-2025-33073 -> NOT
  exploitable on GOAD (Server 2019), like Bronze Bit's patched KDC.
- GOAD signing posture (nxc): DCs kingslanding/winterfell SMB signing **required** but LDAP signing **None**
  + channel binding **Never**; **braavos SMB signing False** (not required, Server 2016); castelblack SMB
  signing required. So there ARE provable relay-exposed targets (braavos SMB, the DCs LDAP).

Conclusion: the honest, provable, high-value deliverable is a **signing-posture + relay-exposure
classification** (the control the CVEs hinge on) -- not a weaponized coerce->relay->SYSTEM chain (a
listener-based follow-up on NTLM-RELAY, patch-dependent).

## Design — `SIGNING-RELAY` (signing_relay.py)
Read-only, non-mutating. Per target host: `nxc smb` -> SMB signing (required?); `nxc ldap` -> LDAP signing
(required?) + channel binding. Classify exposure:
- **smb_relay** -- SMB signing NOT required -> NTLM relay + CVE-2025-33073 reflection applicable.
- **ldap_relay** -- LDAP signing NOT required, or channel binding not "Always" -> LDAP relay applicable.
Terminal `relay_exposure` (new kind): ok = any host relay-exposed; extra carries per-host posture +
exposed classes/hosts. `exit 0 is never proof` -- the parsed posture decides. Secret-safe (creds masked,
only public posture in the receipt). Run-dispatchable (`inputs.TARGET_PARAM["SIGNING-RELAY"]="hosts"`),
probe + smart-gate (no special prereq). Only "Always" counts as full channel-binding enforcement
("When Supported" is bypassable).

## Proof (live, real `run SIGNING-RELAY` vs GOAD north, as jon.snow)
`ok=True`, exposed_classes `[ldap_relay, smb_relay]`, exposed_hosts `[winterfell(DC), braavos]`:
- winterfell DC: smb signing required, **LDAP signing not required** (cb never) -> `ldap_relay`.
- braavos: **SMB signing not required** -> `smb_relay` (CVE-2025-33073 reflection surface).
- castelblack: SMB signing required, not a DC -> no exposure (correctly protected).

522 validation tests (515 base + 7). `verified_recipe=True`.

## Follow-ups (documented)
- The weaponized relay (coerce -> ntlmrelayx -> SMB reflection / LDAP relay -> SYSTEM/DCSync) as a mode on
  NTLM-RELAY, for a relay-exposed target; patch-dependent (CVE-2025-33073 unpatched host), needs a coercion
  source + DNS record. CVE-2025-54918's required-signing bypass needs a Server 2025 target (not on this GOAD).
