# PLAN — ADR-003 Phase 4: the autopwn driver (dry-run default, fenced) (27NOV2026)

**Status:** DRAFT → adversarial safety review pending
**Implements:** ADR-003 Phase 4. **Base:** main @ f9b3050 (Phases 1-3 landed: produce / store /
re-scope). **Owner safety decisions (27NOV2026):** default posture = **plan/dry-run**; mandatory
guardrails = **scope fence**, **full path audit**, **kill-switch**.

## Objective

An `autopwn` command that loops scan → gain → re-scan → execute toward a goal state (default DA),
composing the existing primitives: `discover --as-cred <identity>` (Phase 3) → pick the next hop →
execute (gated) → the produced `Credential` (Phase 1) lands in the store (Phase 2) → re-scope to it
→ repeat. **It is dry-run by default and auto-executes NOTHING mutating without explicit opt-in.**

## Safety model (owner-set; non-negotiable)

1. **Default = dry-run/plan.** From the start identity it runs READ-ONLY `discover`, prints the
   eligible actionable hops, which would gain a cred / reach the goal, and a best-effort projected
   path. It executes NO mutating technique and gains NO credential. Purely projective.
2. **Execute mode requires ALL of:** `--execute` AND `--yes` AND `--allow-destructive` AND
   `--scope <fence>`. Missing any one → stays dry-run (or errors for a bare `--execute` with no
   `--scope`). No other path reaches execution.
   **PLUS a risk acknowledgement (owner 27NOV):** before the first mutating hop, print a LOUD
   warning naming the accepted residual risk — "auto-executes mutating AD techniques toward DA;
   rollback is NOT guaranteed if the run is interrupted (SIGINT/kill may leave AD mutated); scope
   fence <…> is the only boundary" — and REQUIRE the operator to type an explicit acceptance
   (interactive). **`--dangerous`** bypasses only the interactive acceptance (for non-interactive
   use); it does NOT bypass `--scope`/`--yes`/`--allow-destructive`. The warning text + whether it
   was accepted-interactively or via `--dangerous` is recorded in the audit header.
3. **Scope fence — explicit, but with bulk forms for large scopes (owner 27NOV).** The fence is
   REQUIRED for `--execute`; there is no implicit/empty fence. A target is in-scope iff it matches
   one of:
   - **`--scope <host,host,…>`** — an explicit host allow-list (FQDN or IP).
   - **`--scope-domain <domain[,domain…]>`** — whole-domain fence: any target whose domain matches
     (FQDN suffix match on the domain, case-insensitive) is in-scope. For large/entire-domain
     engagements — no host enumeration needed.
   - **`--scope-enumerate <domain>`** — materialize: query the DC (LDAP `objectClass=computer`) for
     every host in `<domain>` and add them all to the explicit host allow-list up front, so the
     fence is a concrete, auditable host set (and is recorded in the audit). Combine freely with the
     above.
   EVERY `discover` target, every hop target, AND every coercion-callback / relay target is checked
   against the resolved fence; anything outside is skipped and audited as `skipped_out_of_scope`.
   A whole-domain fence is a deliberately wide but EXPLICIT blast radius (the operator named the
   domain); it is never the default and never implicit. The resolved fence (hosts + domains, and
   the enumerated host set) is written into the audit header so the run's exact scope is recorded.
4. **Full path audit.** A complete, append-only run record: each identity gained, each hop
   PROJECTED (dry-run) or EXECUTED (with outcome + rollback status), and the final path/goal
   status, written to a run artifact. **Secret-safe:** identities + techniques + outcomes only —
   NO secret values (those stay in the store / `--show-flag`); the audit is subject to the same
   receipt invariant.
5. **Kill-switch.** SIGINT clean-stop AND a `--kill-file` sentinel, checked between hops; the loop
   halts cleanly, finishing any in-flight verified rollback first, and writes the partial audit.
6. **Budget / termination** (loop correctness): `--max-hops`, `--max-time`; the loop also stops on
   goal reached (`S_DA`/`DA_CREDS`), empty frontier, or no new progress. Visited-set prevents
   re-exploiting an identity (cycle-safe).
7. **Per-mutation verified rollback preserved** — each executed mutating hop goes through the
   existing proof.v1 gated rollback; an unverified rollback halts the loop (never silently continue).

## The loop (execute mode)

```
frontier=[operator identity]; visited=set(); audit=[]
until goal reached OR frontier empty OR budget OR kill-switch:
  identity = frontier.pop(priority: DA-adjacent first)
  if identity in visited: continue
  visited.add(identity)
  findings = discover(as=identity)                  # read-only; targets ∩ scope only
  for hop in select_toward_goal(findings):          # greedy: gains a NEW identity or reaches goal
    if hop.target not in scope: audit(skipped_out_of_scope); continue
    result = execute(hop, as=identity, gated, rollback)   # mutating hop -> verified rollback
    audit(executed hop + outcome + rollback)
    for cred in result.produced_credentials:
       store.upsert(cred);  if cred.identity not in visited: frontier.append(cred.identity)
    if goal_reached(cred): break
print audit + path + goal status
```
Dry-run runs only the first `discover` (read-only) per the start identity and the projected hops —
no execute, no gain, no recursion past what read-only discovery reveals.

## Test plan (safety is the point — each gate RED-provable)

- **Dry-run executes nothing mutating:** with no `--execute`, assert no mutating executor is ever
  invoked (fake runner records calls); only read-only discover runs.
- **Execution gate:** `--execute` without `--scope` errors; without `--yes`/`--allow-destructive`
  stays dry-run. All-four-present is the ONLY path that executes (prove each missing flag blocks).
- **Scope fence:** a hop/target outside `--scope` is skipped + audited; prove an out-of-scope target
  is never dispatched.
- **Kill-switch:** a kill-file set mid-loop halts before the next hop; partial audit written.
- **Termination:** budget (max-hops) halts; visited-set prevents re-exploiting an identity; goal
  reached stops.
- **Audit secret-safety:** seed a secret; assert it never appears in the audit artifact / stdout
  (reuse the reveal invariant harness).
- **Rollback halt:** a mutating hop whose rollback is unverified halts the loop (no silent continue).
- Regression: full suite green (baseline 1199).

## Delegation

Claude plans + **adversarial Codex design-review of this plan FIRST** (safety-hole hunt: scope
bypass, dry-run→execute leak, kill-switch race, audit secret leak, non-termination), fold, then
**Sol (high)** implements; Claude verifies every safety gate itself before landing.

## Risks

- **Dry-run → execute leak** (any code path that mutates in dry-run) — the #1 thing the review +
  tests must rule out.
- **Scope-fence bypass** (a target reaching a tool without the fence check).
- **Audit secret leak** (a produced secret written into the path record).
- **Non-termination / cycles** — budget + visited-set.

## Codex adversarial safety review r1 (27NOV2026, FIX-FIRST) — findings + re-scope

The review found the DRY-RUN itself is unsafe and the EXECUTION path needs foundational hardening.
Re-scoping Phase 4 into two shippable stages:

### Phase 4a — the safe dry-run planner (buildable now)
Default plan-only driver that NEVER mutates and NEVER reads a secret:
- **Non-secret discovery mode (#1):** a dry-run `discover` that EXCLUDES secret-bearing probes (LAPS
  `ms-Mcs-AdmPwd`/`msLAPS-Password`, any read that returns credential material). Planning uses only
  posture/eligibility reads.
- **Fence BEFORE recon + empty-halt (#2):** resolve the fence first; if the fence excludes the DC,
  recon/candidate fallback must NOT contact `cfg.dc_ip`; an empty in-scope set HALTS (never expands
  to an implicit DC/target). Infra endpoints (DC/KDC/CA) must be explicitly in-fence to be touched.
- **Fence every resolved destination (#3):** check not just `hop.target` but every resolved
  parameter — DC/KDC, CA, `reauth_target`, coercion victim+callback, relay target, discovered
  endpoints — against the fence (all three fence forms: hosts / --scope-domain / --scope-enumerate).
- **Audit = public-event allowlist (#7):** fixed outcome codes + public identifiers ONLY (technique,
  target, classification, identity principal). Raw results / `Credential.value` / teardown
  obligations / exception messages NEVER enter the audit or any log. Do NOT rely on `proof.scrub`
  (it retains a `value` field). The resolved fence is written to the audit header.
- Kill-switch + budget admission checks before every projected hop and every tool launch (#4).

### Phase 4b — the execution loop (gated on execution-model hardening)
Requires fixing foundational gaps BEFORE any auto-execution of mutating hops:
- **Interrupt-safe rollback (#5):** register cleanup BEFORE the write; `_execute_to_artifact` must
  handle `KeyboardInterrupt`/SIGINT and run (or flag) the pending rollback; an uncertain outcome is
  DIRTY-state, never normalized to `mutation.applied=False`. (Touches base.py + rbcd.py and the
  other mutating executors.)
- **Verified-rollback gate before advancing (#6):** the loop advances ONLY on
  `mutation.rollback.verified` — not `complete`/`performed`; a failed-verification rollback HALTS.
- Full-destination fence (#3) + per-hop/per-tool kill+budget (#4) enforced on the live path too.

**Recommendation:** build 4a now (safe, delivers the planner — the owner's default posture). Treat
the execution-model hardening (#5/#6, and extending the non-secret guarantee) as a prerequisite
sprint before 4b. 4a has no auto-execution, so it cannot mutate or leak a secret even if a later
bug exists.
