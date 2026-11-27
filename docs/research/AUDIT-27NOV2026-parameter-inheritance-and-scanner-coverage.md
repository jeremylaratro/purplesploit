# Audit — parameter inheritance + scanner identify/auto-exploit coverage (27NOV2026)

Scope: the 29 validation techniques on `main` @ `ed82c20`. Answers two operator questions and records
a backlog item. Evidence is from code introspection (`validation/executors/*`, `inputs.py`, `cli.py`,
`orchestrator.py`, `findings.py`, `probes.py`), not assumption.

## Q1 — Do all modules auto-load the global settings (user / password / domain / dc-ip / hash / aes-key)?

**Yes.** Those six are `ValidationConfig` fields, not per-technique params. `cli.build_config` sets them
once from `--domain --dc-ip --user --password --hash --aes-key`, and every executor reads them directly
(`cfg.domain`, `cfg.username`, `cfg.password`, `cfg.nt_hash`, `cfg.aes_key`, `cfg.dc_ip`) — e.g. the getST
auth target, the nxc kerberos flags, the SMB login. **No module re-asks for credentials**; set them once
and all 29 inherit them.

What is NOT a global credential is the per-technique **target selector** — *which* object the technique
acts on. 10 techniques have a required selector that cannot be derived from creds + the host alone:

| Technique(s) | Required selector | Where it comes from |
| --- | --- | --- |
| ASREP, KERBEROAST | `principal` | the roastable user |
| FORCE-CHANGE-PASSWORD, TARGETED-KERBEROAST | `victim` | the target user |
| ADD-MEMBER | `group` | the target group |
| ADCS-ESC1, ESC11, CERTIFRIED | `ca` | the CA name |
| GPO-ABUSE | `gpo_guid` | the target GPO |
| OPENSHARES-WRITE | `share` | the writable share |

These are **not a gap** — they auto-fill in the two supported ways:
- **Pipeline (scan) mode:** from the aranum finding's `entity` (`roast.py` reads `finding.entity["principal"]`,
  `add_member.py` reads `entity["group"]`, etc.). The scanner discovers the object and fills the selector.
- **Run mode:** from `--target` (bound via `inputs.TARGET_PARAM`) and `--param key=value`.

**Verdict:** credential inheritance is complete; a technique still needs a *target*, supplied by the scan
finding or the operator. The other 19 techniques auto-fill every required param from globals + the host.

## Q2 — Can the scanner take the creds, scan for all techniques, identify them, and offer auto-exploit?

**Partially — the machinery exists, with two real gaps.** The `pipeline` mode (`ValidationOrchestrator.run`)
already does: **enumerate (aranum) → map findings to techniques → probe viability (detect-before-fire) →
confirm → execute → score.** Key properties:
- **Probe-gated:** a finding whose precondition probe returns `viable=False` is *skipped* (never executed);
  `unknown`/`viable` proceed (`orchestrator.confirm`).
- **Auto-exploit:** `--yes` installs `AutoConfirm`, which opts every viable finding in automatically (interactive
  mode prompts per issue instead). So `pipeline --yes` IS "scan → identify → auto-exploit".

**Gap A — identification covers 18 of 29 techniques.** Only techniques with a rule in the aranum findings
mapper (`findings.py`) become `validatable` and enter the pipeline:

- **Mapped / scan-identified (18):** KERBEROAST, ASREP, TARGETED-KERBEROAST, RBCD, CONSTRAINED-DELEG-PT,
  UNCONSTRAINED-DELEG, LAPS, SHADOW-CREDS, ADCS-ESC1, COERCION, NTLM-RELAY, WRITE-DACL, WRITE-OWNER,
  ADD-MEMBER, FORCE-CHANGE-PASSWORD, GENERIC-ALL, GPO-ABUSE, OPENSHARES-WRITE.
- **NOT mapped — invisible to a scan (11):** BRONZE-BIT, S4U2SELF, DCSYNC, ESC8, ESC11, CERTIFRIED,
  GOLDEN/SILVER/DIAMOND/SAPPHIRE-TICKET, SHARE-LOOT.
  - Some are *inherently* not discoverable from creds alone — they are downstream **chain** edges or need
    material you don't have at scan time: the 4 T4 forging edges (need a krbtgt/service key), DCSYNC (the
    DA terminal), SHARE-LOOT (needs no finding; it IS the discovery).
  - Others ARE environment-detectable and should be surfaced: **BRONZE-BIT / S4U2SELF** (a delegation scan —
    their probes already read `msDS-AllowedToDelegateTo`), **ESC8 / ESC11 / CERTIFRIED** (an ADCS scan for
    web-enrollment / ESC-vulnerable templates — their probes already check this).

**Gap B — the probes are reactive, not a discovery pass.** All 29 techniques now have a precondition probe
(`PROBE_REGISTRY`), but a probe only runs to *gate a finding that was already mapped*. There is no mode that
runs **every** technique's probe against the environment and reports which are viable. That proactive
"capability discovery" is exactly the "scan for all techniques, then offer auto-exploit" the operator wants.

**Verdict:** `pipeline --yes` auto-identifies and auto-exploits the 18 mapped techniques today (probe-gated,
verified recipes). It does NOT yet (a) surface the probe-detectable delegation/ADCS edges, or (b) run a
proactive probe-all discovery. The building blocks (29 probes, viability model, auto-confirm) are present.

### Recommended remediation (if we want "scan everything → auto-exploit")
1. **Capability-discovery mode** — a pass that runs all 29 probes against the supplied scope and emits a
   viability report (viable / unknown / not-viable + evidence), then feeds the viable set into the existing
   confirm→execute→score path (so `--yes` auto-exploits everything identified). Reuses `run_probes` + the
   confirmer; no executor changes.
2. **Close the findings-mapper gap** for the environment-detectable edges: add mapper rules (or discovery
   producers) for BRONZE-BIT / S4U2SELF (delegation scan) and ESC8 / ESC11 / CERTIFRIED (ADCS scan), so a
   plain `pipeline` surfaces them.
3. Leave the inherently-downstream edges (T4 forging, DCSYNC) to `chain`/`run` — they can't be identified
   from creds alone, by design.

## Q3 — Backlog: the recently-disclosed LDAP/SMB signing bypass
Two 2025 NTLM-relay-family disclosures (same family as the existing NTLM-RELAY / COERCION edges):
- **CVE-2025-54918** — NTLM/**LDAP signing & channel-binding bypass** (patched Sep 2025): coerce → relay to a
  DC over LDAP while stripping the signing flags (keeping LOCAL_CALL), bypassing signing + channel binding
  even on hardened DCs → Domain User → SYSTEM.
- **CVE-2025-33073** — **SMB NTLM reflection** (patched Jun 2025): reflect NTLM back to the originating
  machine → SYSTEM on any host not enforcing SMB signing.

Recorded as a backlog candidate in `docs/plans/BACKLOG-27NOV2026-ntlm-relay-signing-bypass-cve-2025.md`
(a new relay sub-technique or a T6-adjacent addition; needs a lab with an unpatched/mis-signed target to
prove, which this GOAD may not provide).

## Summary
- **Q1:** Global creds inherit everywhere; targets come from the scan finding or the operator. Working as designed.
- **Q2:** `pipeline --yes` scans, identifies (18), probe-gates, and auto-exploits today; a capability-discovery
  pass + mapper rules for the delegation/ADCS edges would extend it toward "identify + auto-exploit everything".
- **Q3:** CVE-2025-54918 (LDAP) + CVE-2025-33073 (SMB) logged to the backlog.
