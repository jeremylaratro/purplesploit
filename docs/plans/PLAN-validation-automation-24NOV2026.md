# PLAN-003 — Operator-Driven AD Validation Automation (architecture + scaffold)

Date: 24NOV2026
Status: scaffold landed on `dev/validation-automation` (core orchestrator +
config/recommendation layer + RBCD vertical slice; other executors stubbed).
Scope: **framework build**, target-agnostic. Nothing in this effort runs against
the GOAD lab — GOAD is only the authorized lab the recipes were proven against.

Specs consumed (cite):
- **claude-mem #66142** — the operator-driven enum→validate UX with
  recommended-default + override parameters (the worked `joe` example).
- **claude-mem #66146** — the PROVEN per-technique executor recipes + gotchas
  (encoded, not re-derived).
- **claude-mem #66119 / #66120** — the proof-chain scope (C1–C11) and the
  classifier denial→STOP protocol.
- ad-lab-harness `adlab/score_proof.py` + `truth/GOAD-proof.json` — the
  `adlab.plan003.proof.v1` receipt schema and the proof-truth facet the
  executors must satisfy. Verified: a receipt from the RBCD executor scores
  `proved` under the real `score_proof` with `GOAD-proof.json`.
- aranum `aranumtoolkit/network/report.py` + `auto-enum.sh` — the structured
  findings this framework consumes.

---

## 1. Where it lives

```
python/purplesploit/validation/
├── __init__.py          package API (ValidationConfig, load_findings, ValidationOrchestrator)
├── config.py            ValidationConfig dataclass — all operator inputs up front
├── findings.py          NormalizedFinding + aranum findings.json parser + finding→technique map
├── recommend.py         ParamSpec / ParamValue / resolve_params + default-derivation helpers
├── proof.py             adlab.plan003.proof.v1 receipt builder (the cross-repo contract)
├── orchestrator.py      ValidationOrchestrator (enum→plan→confirm→execute→score) + injectable
│                        AranumRunner / ProofScorer / ConfirmationProvider
├── cli.py               `python -m purplesploit.validation.cli` entrypoint + interactive prompt
└── executors/
    ├── __init__.py      REGISTRY: technique → executor class; get_executor / is_implemented
    ├── base.py          ValidationExecutor ABC, CommandRunner, AuthorizationProvider, plan/step records
    ├── rbcd.py          RBCD executor — FULLY IMPLEMENTED vertical slice
    └── stubs.py         the other 10 executors — recipe documented (#66146), execute() raises

tests/unit/validation/test_recommendation.py   recommendation/defaulting + RBCD end-to-end (fake runner)
```

Runtime assumption (verified in #66146): the framework runs where the Kali
toolset is on `PATH` (`impacket-*`, `certipy-ad`, `bloodyad`, `nxc`,
`hashcat`+rockyou) — e.g. the Kali container. `SubprocessRunner` shells out to
those names.

---

## 2. Config schema (`ValidationConfig`)

All operator inputs are set once, up front (requirement #66142 step 1):

| Field | Meaning |
| --- | --- |
| `domain`, `dc_ip` | **required** target identity |
| `username`, `password`, `nt_hash`, `aes_key` | operator credentials (any one secret form) |
| `extra_targets` | additional member hosts / DCs (IP or FQDN) |
| `output_dir` | run root (receipts, ccache, enum tree, score result) |
| `aranum_bin`, `nmap_input`, `findings_json` | detection layer inputs |
| `score_proof_cmd`, `proof_truth` | scoring layer (ad-lab-harness) |
| `host_aliases` | raw host/IP → canonical identity attrs (e.g. `host_id`) for scoring |
| `authorized` | engagement authorized → gate default `not_required`; else fail closed |
| `auto_confirm` | accept recommended defaults non-interactively |
| `tool_timeout_s` | per-tool timeout |

Derived helpers: `principal_base` (`NORTH\joe`/`joe@dom`/`joe` → `joe`),
`netbios`, `has_credentials`, `auth_method`, `resolve_target_identity(host)`,
and `redacted()` (secrets masked for any log/preview).

---

## 3. Orchestrator flow (enum → plan → confirm → execute → score)

```
                       ┌─────────── ValidationConfig (operator sets all inputs) ──────────┐
                       ▼                                                                   │
 (2) enumerate  → AranumRunner.findings_path(config)                                       │
                     aranum run -i <nmap> -o <out> -u -p --domain --dc-ip                  │
                     aranum report -o <out>  →  <out>/findings.json                        │
                     load_findings() → [NormalizedFinding]  (map each to a technique)      │
                       ▼                                                                   │
 (3) plan       → for each validatable finding with a registered executor:                 │
                     executor.plan(ctx, finding) → ValidationPlan                          │
                       (target, params w/ recommended defaults, step preview, mutating?)   │
                       ▼                                                                   │
 (4) confirm    → ConfirmationProvider.confirm(plan) per issue  →  Choice(validate, overrides)
                     opt-in per issue; operator overrides any param                        │
                       ▼                                                                   │
 (5) execute    → executor.run(ctx, finding, overrides)                                    │
                     recipe steps via CommandRunner; mutating ops gated;                   │
                     verified rollback; proof.v1 receipt written to receipts/              │
                       ▼                                                                   │
 (6) score      → ProofScorer.score(receipts, proof_truth) (ad-lab-harness score_proof)    │
                     → proved / not-proved / inconclusive report ──────────────────────────┘
```

`AranumRunner`, `ProofScorer`, `ConfirmationProvider`, `CommandRunner`,
`AuthorizationProvider` are all injectable, so the pipeline is unit-testable
without a lab, aranum, or the harness on `PATH`. Defaults:
`CliAranumRunner` / `CliProofScorer` / (`AutoConfirm` if `auto_confirm` else
`DeclineAll`) / `SubprocessRunner` / `AuthorizedLabProvider`.

---

## 4. ValidationExecutor interface

```python
class ValidationExecutor:
    technique: str            # proof-truth technique key, e.g. "RBCD"
    technique_class: str      # "delegation", "adcs", ...
    terminal_kind: str        # one of proof.TERMINAL_KINDS
    mutating: bool            # changes AD → rollback required
    verified_recipe: bool     # recipe PROVEN end-to-end (#66146)?
    recipe_ref: str           # the #66146 recipe string encoded

    def param_specs(ctx, finding) -> list[ParamSpec]      # overridable params + recommended defaults
    def execute(ctx, finding, params) -> dict             # run recipe → loose artifact
    def target_identity(ctx, finding, params) -> dict      # identity for proof-truth matching
    # shared: plan(ctx, finding, overrides) -> ValidationPlan
    #         run(ctx, finding, overrides)  -> proof.v1 receipt (resolve→execute→build_receipt)
```

The loose artifact `execute` returns is
`{steps, gate, mutation, terminal_fact, complete, errors}`; the base `run`
turns it into a strict receipt via `proof.build_receipt`. Any exception (or a
stub's `StubNotImplemented`) yields an **incomplete** receipt carrying the error
— never a fabricated proof. `exit 0 is never proof`: each step's `ok` is decided
by a predicate over tool output, not by a return code.

---

## 5. Recommendation / override model (#66142)

`ParamSpec(name, kind, description, recommended, rationale, validator, advisory)`
declares one overridable parameter with a **recommended default already derived
from the operator's inputs**. `resolve_params(specs, overrides)`:

- applies an operator override where present (marked `operator-override`),
- else takes the recommended default (marked `recommended`),
- validates every resolved value (defaults included — a bad default fails as
  loudly as a bad override), raising `ParamValidationError` on a bad value or an
  unknown override key,
- attaches non-fatal advisories (e.g. a computer name over the 15-char legacy
  convention) without failing.

Derivation helpers encode the owner worked example verbatim:
`escalation_test_user("joe") → "joe_escalation_test"`,
`delegation_computer("joe") → "joe_cmp_delegation"`,
`recommended_spn("cifs", host) → "cifs/<host>"`.

**RBCD params (the worked example, implemented):** `new_computer`
(recommended `<user>_cmp_delegation`), `delegate_to` (recommended = the finding
host), `impersonate` (recommended `Administrator` — a sensible high-value
escalation target; override to the supplied user or a specific DC per #66142),
`target_spn` (recommended `cifs/<delegate_to>`). The operator can change any of
them; the CLI prompts per param with the recommended default shown.

---

## 6. Finding → technique mapping

`findings.py` normalizes each aranum finding and attaches the proof technique it
can be validated by. Signals are ordered (first match wins); rule-id signals
(strongest) precede category/line signals.

| Signal (aranum) | → technique | class | confidence |
| --- | --- | --- | --- |
| `rule_id=promoted-kerberoast-spn` | KERBEROAST | kerberoast | **verified** |
| `rule_id=promoted-asrep-user/-userlist` | ASREP | asrep | **verified** |
| `rule_id=promoted-adcs-ca/-tpl` | ADCS-ESC1 | adcs | **verified** |
| `rule_id=promoted-relay-candidate` | NTLM-RELAY | relay | **verified** |
| `rule_id=promoted-coerce-signal` | COERCION | coerce | **verified** |
| `rule_id=promoted-shadow-creds` | SHADOW-CREDS | shadow_creds | **verified** |
| line `msDS-AllowedToActOnBehalfOfOtherIdentity` | RBCD | delegation | **verified** |
| line `UNCONSTRAINED DELEGATION` | UNCONSTRAINED-DELEG | delegation | **verified** |
| line `READABLE (LAPSv1/2` / `ENCRYPTED (LAPSv2)` | LAPS | laps | **verified** |
| line `msDS-AllowedToDelegateTo` / `TRUSTED_TO_AUTH…` | CONSTRAINED-DELEG-PT | delegation | ⚠ assumed |
| line `writable share` / `RW share` / `non-default RW` | OPENSHARES-WRITE | openshares | ⚠ assumed |

Per-entity extraction pulls `principal` (kerberoast/asrep SPN account), `esc` /
`template` / `ca` (ADCS), `share` (openshares), `host` from the finding `line` +
`host`. Each `NormalizedFinding` carries `verified_signal` so the operator (and
the orchestrator) can tell a verified mapping from an assumed one.

---

## 7. Rollback handling

Every mutating executor must capture **and verify** a rollback, or the harness
scores the chain `inconclusive` (`rollback_unverified`) — never `proved`
(`score_proof` rollback guard). The receipt carries
`mutation.rollback = {performed, method, verified}`. The RBCD executor:

1. runs `impacket-rbcd -action flush` (clear the SD),
2. **verifies** via `impacket-rbcd -action read` (the new computer$ no longer
   appears),
3. runs `impacket-addcomputer -delete`,
4. sets `verified = flush_ok AND cleared AND delete_ok`.

Rollback runs even when a prerequisite step fails after a mutation, and is
itself gated (a denied rollback is surfaced, never bypassed).

---

## 8. Wiring to aranum + score_proof

- **aranum (detection):** `CliAranumRunner` runs `aranum run -i <nmap> -o <out>`
  (auth passed through) then `aranum report -o <out>`, and reads
  `<out>/findings.json`. If `config.findings_json` is set, enumeration is
  skipped and that file is read directly.
- **score_proof (judging):** executors emit `adlab.plan003.proof.v1` receipts
  whose shape is identical to what the harness adapter
  `adlab.proof_adapters.from_chain_artifact` produces, so they are directly
  scoreable. `CliProofScorer` invokes `score_proof --proof-truth <facet>
  --proof <receipt>… --result <out>` and returns the proved/not-proved/
  inconclusive roll-up. purplesploit does **not** import ad-lab-harness; the
  `proof.v1` receipt is the only contract between them.

---

## 9. Unverified assumptions (to confirm before a live run)

1. **aranum `run -i` needs an nmap file.** The orchestrator either runs
   `aranum run` on a supplied nmap output or consumes a pre-made
   `findings.json`. An integrated nmap step is not built yet.
2. **CONSTRAINED-DELEG-PT and OPENSHARES-WRITE mapping markers are assumed.**
   The exact aranum line wording was not pinned in `report.py`; both are flagged
   `verified_signal=False`. Confirm the real markers against a live aranum AD run
   and tighten the regexes.
3. **`host_id` identity for scoring is lab-specific.** The proof-truth facet keys
   RBCD/LAPS/relay/coercion on `host_id` (dc01/…). For a generic target the
   operator supplies `host_aliases` (raw host → `host_id`) or the facet is keyed
   on `host`/`principal`. Unmapped hosts carry only the raw `host` in the
   receipt target.
4. **Tool output predicate strings** (`Successfully added machine account`,
   `Delegation rights modified successfully`, `Saving ticket in`, `(Pwn3d!)`,
   …) are drawn from the #66146 recipe tooling; pin them against the installed
   impacket/nxc versions and adjust if the wording drifts.
5. **`impacket-addcomputer -delete`** is used per the proven #66146 recipe;
   confirm the flag on the installed impacket (some builds differ).

---

## 10. What is implemented vs stubbed

- **Implemented end-to-end:** RBCD (`rbcd.py`) — parameterized recipe,
  recommended-default + override params, gated mutating ops, verified rollback,
  `proof.v1` emission. Confirmed `proved` under the real `score_proof`.
- **Stubbed (recipe documented, `execute` raises `StubNotImplemented`):**
  KERBEROAST, ASREP, CONSTRAINED-DELEG-PT, ADCS-ESC1, SHADOW-CREDS, LAPS,
  OPENSHARES-WRITE, COERCION, NTLM-RELAY, UNCONSTRAINED-DELEG. Each carries its
  #66146 recipe string and a TODO describing its params / terminal fact /
  rollback. To implement one, mirror `rbcd.py`.

Suggested implementation order (by proven-ness + value): KERBEROAST → ASREP
(non-mutating, opt-in crack) → CONSTRAINED-DELEG-PT (non-mutating, reuses getST)
→ OPENSHARES-WRITE / SHADOW-CREDS / ADCS-ESC1 (mutating + rollback) →
LAPS (expect a classifier gate) → COERCION → NTLM-RELAY → UNCONSTRAINED-DELEG
(recipe-known-not-run; validate the recipe in-lab first).
