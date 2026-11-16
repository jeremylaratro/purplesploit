# PLAN-003 ops — deferred issues & review log

Running log of bugs, review findings, and deferred items caught while driving fast toward a
working capability outline. Ops-mode rule: **log here, keep moving; patch at a later review.**
Nothing here is lost — each item has an ID, a source, and a status.

Status: `OPEN` · `IN-PROGRESS` · `FIXED (sha)` · `WONTFIX (reason)`.
Severity: `BLOCKER` · `HIGH` · `MEDIUM` · `LOW`.

## Bugs / correctness

| ID | Sev | Source | Item | Status |
|---|---|---|---|---|
| D-001 | HIGH | sweep R1-ARANUM-01 | `modules/recon/aranum.py:172-186` builds `[exe,--only,…]` with no subcommand; real Aranum returns rc2 "unknown command: --only". Unit test pins the broken argv. | OPEN |
| D-002 | HIGH | sweep ARANUM-01 | Aranum `assessed_clean` when a dispatcher skipped its checks (false-clean record). | OPEN |
| D-003 | HIGH | sweep ARANUM-06 | AS-REP hand-off never connects. | OPEN |
| D-004 | HIGH | sweep ARANUM-07 | delegation signal is inverted. | OPEN |
| D-005 | HIGH | sweep ARANUM-08 | Certipy rule matches only a synthetic format. | OPEN |
| D-006 | HIGH | sweep PLANMAP-03 / R1-HARNESS-02 | harness quiet-gate samples PSI only pre-run; stalls P0-S1 start on loaded host. | OPEN |

## Capability gaps (from OCD mapping, drive the outline)

| ID | Sev | OCD cat | Missing capability (no backing module yet) | Status |
|---|---|---|---|---|
| D-010 | HIGH | mitm, no_creds, delegation, adcs | Poison/capture (Responder), auth induction (mitm6), RPC coercion (PetitPotam/Coercer), Kerberos relay (krbrelayx). NTLM relay engine (ntlmrelayx) present in Impacket. | OPEN |
| D-011 | HIGH | crack_hash (+roasting tails) | Offline hash cracking (hashcat/john) — not in denominator or bundle. | OPEN |
| D-012 | HIGH | admin, persistence | On-host LSASS + mimikatz-class persistence (skeleton key/SSP/DCShadow/DSRM). | OPEN |
| D-013 | MEDIUM | adcs, know_vuln_auth | Certipy capability module (enum + ESC request paths). | OPEN |
| D-014 | MEDIUM | authenticated, acl, trusts | BloodHound-CE ingest/query + RustHound-CE collector modules. | OPEN |
| D-015 | MEDIUM | delegation, lat_move, trusts, persistence | Kerberos ticket tools (getTGT/getST/ticketer/passthecert) as modules. | OPEN |
| D-016 | MEDIUM | sccm | SCCM tooling (later profile). | OPEN |

## Review items / plan debt (deferred, non-blocking)

| ID | Sev | Source | Item | Status |
|---|---|---|---|---|
| D-020 | MEDIUM | Sol R1 #7 | `dom_admin` "Grab backup Keys" — confirm bundled Impacket ships `dpapi.py backupkeys` (DPAPI domain PVK). | OPEN |
| D-021 | MEDIUM | Sol R1 #8 | WinBins artifact inventory — prove which binaries are bundled before crediting on-host-ops gap. | OPEN |
| D-022 | LOW | Sol R1 #8 | GPO abuse (OUned) is a genuine small `acl` gap. | OPEN |
| D-023 | MEDIUM | mapping §4 | GOAD coverage needs scenario-level citation (topology ≠ vulnerability); re-tier before publishing "~13/17". | OPEN |
| D-024 | MEDIUM | mapping §5 r6 | Fold the 9 r6 recommendations into PLAN-003 (deferred — ops-first). | OPEN |
| D-025 | LOW | provisioning | pt_provision `repositories.tsv` pins by HEAD not commit (PROVISION-08); 28julytoolkit no remote + 22 submodules (GAP3); requirements resolved from caller cwd (PROVISION-02). | OPEN |

## Round 1 registry refinements (Sol R1 applied — build queue now in ocd_registry.json missing_modules)

| ID | Sev | OCD cat | New missing-module wrapper to build | Status |
|---|---|---|---|---|
| D-030 | MEDIUM | acl | LAPS-password retrieval + gMSA-password retrieval wrappers (nxc adapters expose neither) | OPEN |
| D-031 | MEDIUM | know_vuln_auth | GPP cpassword discovery/recovery/decryption | OPEN |
| D-032 | MEDIUM | trusts | MSSQL linked-server enumeration/traversal (nxc_mssql has no linked-server op) | OPEN |
| D-033 | LOW | authenticated | Qualify `nxc -M bloodhound` output for BloodHound-CE compatibility (handlers exist; CE-compat unproven) | OPEN |
| D-034 | LOW | low_access | Separate WinPEAS delivery (have, via deploy/script) from SEImpersonate/Potato exploit (gap) | OPEN |
