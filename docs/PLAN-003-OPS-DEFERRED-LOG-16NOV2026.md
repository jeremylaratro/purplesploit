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
| D-010 | HIGH | mitm, no_creds, delegation, adcs | Poison/capture (Responder), auth induction (mitm6), RPC coercion (PetitPotam/Coercer), Kerberos relay (krbrelayx). NTLM relay engine (ntlmrelayx) present in Impacket. | PARTIAL — r2 added `delegation` enum+abuse (findDelegation/getST); coercion/relay/poison remain |
| D-011 | HIGH | crack_hash (+roasting tails) | Offline hash cracking (hashcat/john) — not in denominator or bundle. | IN-PROGRESS — r2 added `crack/hashcat` module; the TOOL is still not in the provisioning denominator (see D-043); `john` module still missing |
| D-012 | HIGH | admin, persistence | On-host LSASS + mimikatz-class persistence (skeleton key/SSP/DCShadow/DSRM). | OPEN |
| D-013 | MEDIUM | adcs, know_vuln_auth | Certipy capability module (enum + ESC request paths). | OPEN |
| D-014 | MEDIUM | authenticated, acl, trusts | BloodHound-CE ingest/query + RustHound-CE collector modules. | OPEN |
| D-015 | MEDIUM | delegation, lat_move, trusts, persistence | Kerberos ticket tools (getTGT/getST/ticketer/passthecert) as modules. | IN-PROGRESS — r2 added getST + ticketer; getTGT + passthecert still missing (see D-042) |
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

## Round 2 capability implementation (modules scaffolded; registry STUB/GAP → PARTIAL)

Round 2 added 4 modules: `impacket/finddelegation`, `impacket/getst`, `impacket/ticketer`,
`crack/hashcat` (new `crack` category). 21 unit tests pass; all discovered by the framework.
Registry: delegation STUB→PARTIAL, persistence STUB→PARTIAL, crack_hash GAP→PARTIAL
(HAVE 3 · PARTIAL 12 · STUB 0 · GAP 2).

| ID | Sev | Source | Item | Status |
|---|---|---|---|---|
| D-040 | LOW | r2 registry | `ocd_registry.json` re-serialized with `json.dump(indent=2)`, normalizing the file's inconsistent original indentation. One-time whitespace churn bundled in the r2 PR; semantic change is only the 3 categories (verify with `git diff -w`). | FIXED (bundled r2) |
| D-041 | MEDIUM | r2 mapping | crack_hash status is the two-denominator question: the MODULE exists but the TOOL (hashcat) is not in the provisioning denominator. | RESOLVED — Sol R2 F10 adjudicated **GAP** (not runnable as provisioned, denominator tool absent); set GAP, loader docstring clarified, backing ref retained. Unblock = D-043. |
| D-042 | MEDIUM | delegation/persistence tails | Still missing as modules: `getTGT`, `passthecert` (ticket acquisition/auth), `rbcd`/`addcomputer` (RBCD write primitives). getST+ticketer cover the abuse/forge legs only. | OPEN |
| D-043 | HIGH | provisioning (links D-011) | hashcat/john are NOT in `pt_provision` `repositories.tsv`/wheelhouse. The crack module is inert on a provisioned host until the cracking tool is added to the offline bundle. | OPEN |
| D-044 | LOW | r2 contract | hashcat module surfaces observations/credentials via a custom `run()` override (mirrors ImpacketAdapter); confirm the services/jobs layer reads `result["observations"]` the same way for non-impacket modules. | OPEN |

## Round 2 Sol review (R2) — findings deferred (pre-existing / shared-infra / lower-value)

Sol R2 verdict FIX-FIRST, 10 findings. F1, F2, F4, F5, F6, F9 and the correctness part of
F3/F8/F10 were fixed in the r2 modules (verified; 31 tests). These remain, logged per ops-mode:

| ID | Sev | Source | Item | Status |
|---|---|---|---|---|
| D-050 | HIGH | Sol R2 F3 (shared) | `impacket/common.py` `ImpacketAdapter.run()` sets top-level `success` from exit code only, not gated on `parsed.success`. Fixed locally in getST/ticketer via `run()` override; the **6 pre-existing impacket modules** (kerberoast, asreproast, secretsdump, psexec, wmiexec, smbclient) still over-report success on exit-0-without-evidence. Fix once in `common.run()` and regression-test all. | OPEN |
| D-051 | MEDIUM | Sol R2 F3 | getST/ticketer log "Saving ... ticket in" *before* the file write; a write error after the log line still parses a ticket. Success-gating mitigates (write error → non-zero exit → gated False), but a 0-exit partial write is a residual. Confirm the ccache exists before emitting. | OPEN |
| D-052 | MEDIUM | Sol R2 F7 (framework-wide) | `get_operation_manifest()` advertises op `run`, but `Framework.find_operation(module,"run")` searches `get_operations()` (empty) → returns None. Pre-existing across ALL impacket modules; not a blocker because operation-less modules execute via `module.run()` directly (framework.py:659). Reconcile the catalog with the dispatch path. | OPEN |
| D-053 | LOW | Sol R2 F8 | getST/findDelegation require `RHOST` even when `DC_IP` is supplied (builder prefers DC_IP). Add conditional "DC_IP or RHOST" validation instead of a hard RHOST require. | OPEN |
