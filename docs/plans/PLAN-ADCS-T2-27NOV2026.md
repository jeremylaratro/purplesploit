# PLAN — ADCS T2 completion: the remaining ESC family + Golden-Cert (27NOV2026)

**Status:** skeleton (Phase 0–3) → research + per-sprint plan pending
**Path:** full cycle (multi-item, cross-module; mutating AD/CA changes → contracts + rollback)
**Repo:** `purplesploit` — base `main` @ 18016af
**Owner directive:** after R1/R2 relay work, complete the ADCS tranche. Codex-heavy.

## Phase 0 — Frame

ADCS executors follow the **ESC1 reference** (`adcs_esc1.py`): `certipy-ad req` (issue a cert on a
flawed template/CA) → `certipy-ad auth` (PKINIT → TGT + NT hash) → `nxc smb -k` (ticket-backed
access = terminal proof `cert_issued_and_used`). Mutating (a cert is issued) → **verified
rollback** = destroy the issued key material (`.pfx`/`.ccache`; certipy has no revoke, #66157),
verified by confirmed file-absence. Secrets (pfx/hash/ccache) are masked by `redact_argv` and
never enter the receipt; proof_token is over public identifiers. Enumeration tool = `certipy-ad
find` (`_certipy_find` already wired in probes/discovery).

**Lab:** GOAD ESSOS-CA (braavos .23, Server2016, essos.local) — ESC1 PROVEN here. GOAD ships a
training CA with several vulnerable templates; which ESCs are lab-provable depends on the
templates/CA config actually present (confirm via `certipy-ad find -vulnerable` in Phase 4).

## Phase 1 — Gap (implemented vs T2 target)

- **Implemented (4):** ESC1, ESC8 (HTTP relay), ESC11 (RPC relay), CERTIFRIED.
- **T2 target (12):** ESC2, ESC3, ESC4, ESC5, ESC6, ESC7, ESC9, ESC10, ESC13, ESC15, ESC16,
  Golden-Cert.

## Phase 2 — Triage (by mechanism + GOAD feasibility)

| ESC | Mechanism | Reuse of ESC1 | GOAD feasibility (confirm P4) |
|-----|-----------|---------------|-------------------------------|
| ESC2 | Any-Purpose / no-EKU template | HIGH (req→auth→nxc, different template) | likely (classic GOAD template) |
| ESC3 | Enrollment-Agent cert → on-behalf-of | MED (two req steps: EA cert, then `-on-behalf-of`) | likely |
| ESC6 | CA `EDITF_ATTRIBUTESUBJECTALTNAME2` → SAN on any template | HIGH (req `-upn` w/ flag) | lab-dependent (CA flag) |
| ESC4 | Writable template ACL → make it ESC1 → restore | MED (certipy `template` write + ESC1 + **ACL rollback**) | likely |
| ESC7 | CA ACL (ManageCA/ManageCertificates) → enable SAN / approve | MED-HIGH | lab-dependent |
| ESC5 | Writable PKI object ACL | MED | lab-dependent |
| ESC9 | `szOID_NTDS_CA_SECURITY_EXT` absent + weak mapping | MED | recipe-known (needs config) |
| ESC10 | Weak cert mappings (registry) | MED | recipe-known |
| ESC16 | CA security extension disabled globally | MED | recipe-known |
| ESC13 | Issuance policy linked to a group → cert grants membership | MED | lab-dependent |
| ESC15 | EKUwu (CVE-2024-49019) app-policies on v1 templates | MED | version-dependent (patched?) |
| Golden-Cert | Steal CA private key (`certipy ca -backup`) → forge arbitrary certs | LOW (new flow: CA key theft + forge) | needs CA key access (DA) |

- **Out of scope (declared):** tool-hardening/compliance findings; deliberate lab-only constants.
- **Pre-existing:** ESC8/ESC11/CERTIFRIED are `verified_recipe=False` (relay chassis) — NOT part
  of T2's remediation; tracked by the relay effort.

## Phase 3 — Sprint map (one mechanism band per sprint; each independently shippable)

- **A1 — template-request ESCs (highest ESC1 reuse):** ESC2, ESC3, ESC6. Pattern = ESC1 with
  template/EKU/CA-flag variation; ESC3 adds the on-behalf-of second request. Mutating → key-material rollback.
- **A2 — ACL-abuse ESCs:** ESC4 (writable template → ESC1 → **restore template ACL/flags**),
  ESC7 (CA ACL), ESC5 (PKI-object ACL). Mutating AD/CA ACLs → **verified ACL rollback** (reuse the
  WRITE-DACL/RBCD flush+read-back pattern).
- **A3 — mapping/extension ESCs:** ESC9, ESC10, ESC16. Often recipe-known on GOAD; ship honest
  (negative-validation where the CA/registry config isn't present, with a clean control).
- **A4 — newest + forge:** ESC13 (issuance policy→group), ESC15 (EKUwu), Golden-Cert (CA key
  theft → forge; mutating only in that a forged cert exists → destroy key material).

Order: A1 → A2 → A3 → A4 (A1 is the fastest, highest-reuse, most GOAD-provable).

## Phase 4 — Research (per sprint, before building)

- Run `certipy-ad find -vulnerable -u <op>@essos.local ... -dc-ip <dc>` against GOAD ESSOS-CA to
  learn which ESCs are actually present → decide proved vs recipe-known per technique.
- Pin each certipy subcommand's real flags/markers against the installed certipy-ad (the ESC1
  markers are UNVERIFIED-assumption style; verify per new subcommand: `template`, `ca`,
  `req -on-behalf-of`, `forge`).

## Delegation (codex-interop, Codex-heavy)

Per-sprint: Claude plans + reviews + proves on GOAD + integrates; **Codex Sol implements** each
executor + unit tests in a worktree (ESC1 is the template to mirror). Independent cross-family
review each sprint. Secret rules + no-attribution restated in every brief.

## Risks

- **certipy marker drift** across versions → each new subcommand's markers verified in Phase 4;
  honest not-proved on mismatch (never fabricate issuance).
- **Mutating CA/ACL changes (A2/A4)** → every one carries a verified rollback or scores
  inconclusive; Golden-Cert's CA-key backup is highly sensitive (DA-only, destroy the exported key).
- **GOAD may lack some ESC configs** → ship those as recipe-known with reproduced negative
  controls, per the integrity rule (not a fake proof).
