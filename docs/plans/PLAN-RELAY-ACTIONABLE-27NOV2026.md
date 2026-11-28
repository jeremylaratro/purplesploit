# PLAN — Actionable SIGNING-RELAY: operator relay actions on the proven chassis (27NOV2026)

**Status:** peer-reviewed (Codex Sol r1: FIX-FIRST, all 4 folded in) → **ready to build (R1)**
**Follow-on (owner, 27NOV):** after R3, move to **ADCS (T2)** — Codex-heavy. R1 proving the
relay chassis directly de-risks the ADCS relay fronts (ESC8/ESC11/CERTIFRIED, same chassis).
**Path:** full cycle (multi-item, cross-module, touches a contract: the relay chassis + a new operator-action surface)
**Repo:** `purplesploit` — base SHA `main` (confirm at sprint branch)
**Owner directive (verbatim):** "the signing modules should work like this: the operator
should have options to escalate a user, get a shell (if applicable), crawl privileged shares
(chained with the secrets finder), or dump secrets."

## Objective

Turn the relay/signing surface from **detect-only** into **operator-actionable**: after
SIGNING-RELAY identifies a relay-exposed target, the operator can pick one of four actions and
have it executed (and honestly scored) against that target:

1. **escalate a user** — relay → LDAP → RBCD write → S4U impersonation
2. **get a shell** (if applicable) — relay → SMB on a signing-off host → command exec
3. **crawl privileged shares** — relay → authenticated SMB access → chain into SHARE-LOOT (the secrets finder)
4. **dump secrets** — relay → SMB → SAM/LSA dump

**Acceptance:** each action runs the *real* attack and emits a `proof.v1` receipt that
CLASSIFIES the outcome (exploited / target-not-relayable / victim-not-admin / patched /
inconclusive), with a negative control where the lab posture forbids the action. Secrets never
reach a stored receipt (presence-only; proof_token over public identifiers).

## Phase 1 — the gap (detect-vs-act audit, 30 techniques)

- **Pure detect-only (1):** SIGNING-RELAY (reads posture, fires nothing). ← this effort.
- **Actionable but `verified_recipe=False` (10):** COERCION, NTLM-RELAY, UNCONSTRAINED-DELEG
  (relay/coercion chassis — never fired on GOAD); ESC8, ESC11, CERTIFRIED (ADCS relay fronts on
  the same chassis); GPO-ABUSE; BRONZE-BIT (lab patched), LAPS (read-only proven), SHARE-LOOT
  (flag not flipped) — partials.
- **Actionable + proven on GOAD (`verified_recipe=True`) (19):** the rest.

**Root-cause insight:** the 4 requested actions map onto the relay chassis
(`ntlm_relay.py` + `coercion.py` + `process_manager.py`), which has **never been proven
end-to-end on GOAD**. NTLM-RELAY already encodes two of the four actions (`smb_sam`=dump,
`ldap_rbcd`=escalate) but flagged recipe-known-not-run. So the critical path is *proving the
chassis*, not writing four new executors from scratch.

## Architecture decision

**Chosen (revised per Codex r1):** make **SIGNING-RELAY** the detect-front that **delegates to
the NTLM-RELAY executor object** for the two existing, about-to-be-proven modes
(`smb_sam`=dump, `ldap_rbcd`=RBCD-write). SIGNING-RELAY keeps its read-only `detect` default; a
new `action` param routes to the relay executor. No chassis extraction up front.

- *Option A — delegation (chosen):* SIGNING-RELAY calls the NTLM-RELAY executor for existing
  modes. **Why (Codex steer):** lower risk — avoids duplication *without moving the chassis*,
  so R1 proves exactly the code paths that ship. New actions (shell, crawl) are added to the
  relay executor behind their own per-mode verification, never inheriting NTLM-RELAY's flag.
- *Option B — shared `relay_chassis.py` extraction (deferred):* only if a clean seam emerges
  after R1; extraction must then be re-proven through the existing modes before R2 (Codex HIGH).
- *Option C — 4 actions inside SIGNING-RELAY's own chassis (rejected):* duplicates the chassis.

**Per-mode verification (Codex HIGH):** `verified_recipe` is a class-wide attribute, so flipping
NTLMRelayExecutor to `True` would falsely label later-added `shell`/`crawl` modes as proven.
R1 introduces a **per-mode `proven` map** (e.g. `{'smb_sam': bool, 'ldap_rbcd': bool}`); a mode
ships "proven" only with its own GOAD evidence. SIGNING-RELAY's existing
`verified_recipe=True` covers *detection only* and must not bleed onto the actions.

**Crawl session contract (Codex BLOCKER):** a naive `relay → SHARE-LOOT` chain is a **false
proof** — NTLM-RELAY stops its listener before returning (`ntlm_relay.py:259`) and SHARE-LOOT
opens a *fresh* connection from **config creds** (`share_loot.py:141`), never a relayed session.
With low-priv config creds crawl fails; with priv config creds it succeeds *independently* and
falsely attributes access to the relay. **Requirement:** `crawl` keeps the relayed session live
(`ntlmrelayx -socks`, or `-i` interactive) and SHARE-LOOT crawls **through that relayed
transport** via a live-session-backed `ShareReader` with an explicit lifetime — NOT config
creds. Falsifying test: **config-denied + relayed-success** (low-priv config creds that cannot
reach the share on their own, yet the relayed identity can), with no mocked-away auth.

## Sprint map

### R1 — PROVE the relay chassis on GOAD (gates everything)
Flip COERCION + NTLM-RELAY from `verified_recipe=False` → proven, using the EXISTING
`smb_sam` (dump) and `ldap_rbcd` (escalate) modes. No new actions yet.
- Live: stand up the ntlmrelayx listener + coercion against GOAD; relay to a signing-off target.
  Candidate paths (validate feasibility live): coerce a member host → relay → **braavos** (SMB
  signing OFF) SAM dump; coerce/relay → DC **LDAP** (signing None, CB Never) RBCD write.
- If a path is not exploitable in-lab (victim-not-admin, DC-to-DC relay mitigations): classify
  honestly (negative validation) and record the lab posture — the executor still RUNS + classifies.
- **Exit (revised per Codex HIGH):** evidence for **both existing modes** — `smb_sam` AND
  `ldap_rbcd` — each either scored-proved (secret-clean) **or** a reproduced negative-validation
  verdict with a clean control. One mode's success does NOT open R2. The per-mode `proven` map
  is updated to exactly what fired; `shell`/`crawl` stay unproven (not yet built). R1 touches no
  new modes. NOTE: `ldap_rbcd` proves the **RBCD write only**, not user impersonation — see R2.

### R2 — complete the action verbs (all ride the R1-proven chassis)
- **escalate (complete the verb; Codex HIGH):** R1 proved only the RBCD *write*. The full
  "escalate a user" = RBCD write → **select the impersonated user** → **S4U2proxy** for a
  service ticket as that user → **use** it (prove access) → then verified rollback. Scheduled
  here explicitly; R1's write-and-flush must NOT be reported as an escalated user.
- **shell** — relay → SMB `-c <cmd>` / interactive exec on a signing-off host (new mode).
  Classify: exec-as-SYSTEM / exec-as-victim / not-admin / inconclusive. Per-mode `proven`.
- **crawl** — relay keeps the session **live** (`ntlmrelayx -socks` / `-i`); a live-session-
  backed `ShareReader` crawls **through the relayed transport** (NOT config creds) and feeds
  SHARE-LOOT's loot rules. Explicit reader lifetime + private transport. Falsifier: config-
  denied + relayed-success (Codex BLOCKER).

### R3 — operator action surface + SIGNING-RELAY front + TUI
- SIGNING-RELAY gains `action` param (`detect`(default)|escalate|shell|crawl|dump); detect →
  routes the operator to the viable action(s) for each exposed host.
- `discover --exploit` auto-routes a relay-exposed finding to the eligible action (gated:
  escalate/shell/crawl/dump are mutating/impactful → require `--allow-destructive` except
  read-only dump/crawl where applicable).
- Wire into the TUI console (`ui/commands.py`) — the queued "works thru the TUI" item.

## Test plan (per sprint, dev-methodology Phase 7)

- **(a) regression:** `pytest tests/unit/validation` per-test manifest, no prior pass regresses.
- **(b) new behavior:** each action's classifier asserted against seeded outputs
  (exploited/not-relayable/not-admin/patched/inconclusive); crawl chain asserts SHARE-LOOT
  receives the relayed context and loots a seeded secret (presence-only).
- **(c) gates RED-provable:** secret-leak guard; negative control (signing-required target →
  classified not-relayable, never a false proof); rollback-verified guard for escalate (RBCD
  flush + read-back).
- **(c+) arbitrary-secret guard for shell/crawl (Codex HIGH):** a shell command or a looted
  file can emit *any* plaintext secret, so SAM/hash/cpassword pattern checks are insufficient.
  Seed **arbitrary secret sentinels** (cleartext passwords, AES/krbtgt-shaped blobs, secret-
  bearing crawl paths) and assert none appear in success/timeout/error receipts. Additionally:
  **vary the secret payload while holding the public facts constant and assert `proof_token`
  is byte-identical** — a substring check can't catch a token derived from a secret.
- **Live proof:** GOAD, via the real CLI (`run SIGNING-RELAY --param action=...` and
  `chain`), outcomes-only printed, secrets in-memory.

## Split table (codex-interop — usage-conserving; Claude supervises)

| Artifact | Author | Reviewer | Handoff |
|---|---|---|---|
| This plan | Claude (Opus) | **Codex Sol** (bulk) | file |
| R1 chassis-prove harness + flag/classifier edits | Claude (holds GOAD context) | Codex Sol | file |
| R2 shell+crawl mode code + unit tests | **Codex Sol** (implement, worktree) | Claude | file |
| R3 CLI/TUI action surface | Claude | Codex Sol | file |

## Risks

- **GOAD relay feasibility:** DC-to-DC relay mitigations + no obvious admin-on-braavos victim
  may make a *positive* relay proof impossible in-lab. Mitigation: owner directive — a floor
  result is a design problem; classify honestly (negative validation) and prove the executor's
  *classification* is correct, which is the shippable deliverable.
- **Secret leakage via new actions (shell output, crawl loot):** strongest guard; shell exec
  output and crawl loot are presence-only / masked, never stored verbatim.

## Review record — Codex Sol round 1 (27NOV2026, FIX-FIRST)

| # | Sev | Finding | Resolution (verified against code) |
|---|-----|---------|-----------------------------------|
| 1 | BLOCKER | crawl `relay → SHARE-LOOT` has no session contract; SHARE-LOOT auths from config creds (`share_loot.py:141`), listener stopped at `ntlm_relay.py:259` → false proof | crawl now requires a live relayed session (`-socks`/`-i`) + session-backed `ShareReader`; falsifier = config-denied + relayed-success. Architecture flipped to **delegation** (lower risk). |
| 2 | HIGH | R1 exit opens R2 on one mode; `verified_recipe` is class-wide → new modes inherit "proven" | R1 requires BOTH existing modes (proved or reproduced-negative); per-mode `proven` map; new modes stay unproven. |
| 3 | HIGH | `escalate` never reaches impersonation — `ldap_rbcd` writes+flushes RBCD and returns (`ntlm_relay.py:293`) | R1 claims RBCD-write only; full escalate (user select → S4U2proxy → use → rollback) is explicit R2 scope. |
| 4 | HIGH | shell/crawl can emit arbitrary plaintext secrets; SAM/hash/cpassword checks insufficient | Test plan (c+): arbitrary secret sentinels across success/timeout/error receipts + `proof_token` byte-invariance under varied secret payloads. |

Round 2 available on request; findings are design-level and folded, so proceeding to R1.

## R1 live spike findings (27NOV2026) — chassis mechanics PROVEN; code fixes identified

Established empirically against GOAD north (jon.snow low-priv cred):

1. **Network path works** — under PetitPotam coercion the north DC (192.168.56.11)
   authenticated to the attacker listener (192.168.56.1:445) **10+ times** (proven with a
   standalone socket listener that logged `GOT ('192.168.56.11', …)`). Not a reverse-path/
   firewall problem.
2. **Coercion fires through the executor** — `method=auto` (coercer multiplexer) →
   `coerce_trigger=True`. The listener chassis binds (`start_listener=True`).
3. **BUG (confirmed): named coercion methods call uninstalled tools.** `coercion_trigger_argv`
   returns `PetitPotam.py` / `printerbug.py` / `dfscoerce.py` (ntlm_relay.py via coercion.py
   lines 113-123) — **none on PATH** in kali-vr; only `coercer` is installed. `method=petitpotam`
   → `coerce_trigger=False`. **Fix:** route every single-vector method through
   `coercer coerce --filter-method-name <vector>` (installed + proven to fire).
4. **Listener reliability:** ntlmrelayx's full server suite throws fatal thread exceptions from
   port conflicts on the host-network container. **Fix:** add
   `--no-http/wcf/raw/rpc/winrm/mssql/rdp-server` (SMB-only) to the listener argv. (Verified the
   patched staged copy starts clean.)
5. **Classifier gap:** with coercion firing, `relay_rbcd_write=False` currently collapses to one
   error `relay_no_rbcd`, conflating *coercion-didn't-land* / *relay-landed-but-RBCD-denied* /
   *poll-timeout*. The cross-domain DC→DC relay used here (victim north-DC → relay to parent-DC
   LDAP) is a **likely genuine denial**, but the executor can't say so. **Fix:** distinct
   classifier states (coerce_not_fired / coerce_fired_no_auth_landed / relay_landed_action_denied
   / action_succeeded / inconclusive) — this IS the per-mode outcome the plan requires.

**R1 build scope (→ Codex Sol, heavy):** (a) coercion→`coercer` routing for all vectors;
(b) SMB-only listener flags; (c) per-mode `proven` map; (d) the richer classifier states;
(e) unit tests proving each state from seeded tool output + the secret guards. Then re-run the
executor live → trustworthy classification (positive, or a clean negative-validation for the
cross-domain path with a control). Coercion/path mechanics are already proven, so this is
code + a classification, not an open feasibility question.

## Owner decisions (27NOV2026) + queue

- **R1: LANDED** (PR #147, merged `ef81db5`; main `18016af`). Coercion-via-coercer + SMB-only
  listener + 5-state classifier + per-mode proven + secret guards; 567 tests.
- **D (owner): de-scope the auto-listener.** The in-process ntlmrelayx does not reliably CATCH
  the coerced auth on the host-network attacker container (coercion fires + the DC's auth
  provably reaches the host, but the executor's listener catches nothing). Rather than fight it:
  **the operator runs their own listener (ntlmrelayx manually) and provides the listener IP**;
  the module uses that external listener for the action options. This matches real operator flow.
- **R2 (next): operator-custom-listener + action verbs.** Add an `external_listener` capability to
  the relay executor (skip the in-process listener; fire coercion toward the operator's endpoint;
  classify from a shared artifact where the operator exposes one, else report coercion-fired for
  the operator to collect). Expose the 4 verbs (escalate / shell / crawl / dump) on SIGNING-RELAY,
  each routed to the relay executor with external-listener support.
- **Then: ADCS (T2 completion).** ESC2-7/9/10/13/15/16 + Golden-Cert. The relay chassis proven in
  R1 de-risks the ADCS relay fronts (ESC8/ESC11/CERTIFRIED).
- **Queue (owner, after ADCS): auto ligolo-ng setup + auto agent dispersal** — automated pivot
  tunnel bring-up + agent deployment across reachable hosts. (Backlogged; see BACKLOG doc.)
