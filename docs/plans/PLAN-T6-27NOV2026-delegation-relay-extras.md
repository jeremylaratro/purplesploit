# PLAN-T6 (27NOV2026) — Delegation & relay extras

Tranche **T6** of PLAN-NEWTECH (greenlit order T3→T4→**T6**→T2→T7→T1→T8). Opens by reviewing the prior
tranche output (T4 forging merged + live-proven; N1 ESC8/ESC11/CERTIFRIED/DCSYNC merged). Cadence:
plan → 1 independent cross-family review → build → probe → prove on GOAD → integrate, one sprint at a time.

## Phase 0 — Frame
- Repo `purplesploit` (branch `dev/t6-delegation-relay`, base `66a8cc4`). Rules: author `jeremylaratro`,
  no Claude attribution (commit-msg hook). Executors are `ValidationExecutor`s; `exit 0 is never proof`;
  secrets never reach a receipt; proof via a terminal predicate + ticket-backed access.
- Live lab: GOAD is UP on `192.168.56.0/24` (.10 kingslanding, .11 winterfell [north DC], .12 meereen,
  .22 castelblack, .23 braavos/ADCS). Operator creds supplied at runtime, never stored.

## Phase 1 — Objective + gap analysis (what T6 adds vs what exists)
**Objective:** add the T6 delegation/relay-extra techniques as parameterized executors, **chain-wire the
producers** (close part of the composition gap), and prove each on GOAD (or record an honest
inconclusive with the lab reason).

T6 roadmap items and their current state (measured):
| Item | State | T6 work |
| --- | --- | --- |
| **Bronze Bit (CVE-2020-17049)** | absent | **NEW executor** (S1) |
| **S4U2self-abuse** | absent | **NEW executor** (S2) |
| **DFSCoerce (MS-DFSNM)** | ALREADY a `coercion.py` method (`dfscoerce`) | none (done) |
| **ShadowCoerce (MS-FSRVP)** | absent | **new COERCION method** (S3) |
| **WebDAV coercion** | absent | **new COERCION method** (S3) |
| **Kerberos-relay (krbrelayx)** | absent | **assess** (S4) — listener-based, niche |

GOAD recon (impacket-findDelegation, north, 27NOV2026) — provable targets confirmed:
- `jon.snow` — Constrained **w/ Protocol Transition** → CIFS/winterfell (CONSTRAINED-DELEG-PT, already proven).
- `CASTELBLACK$` — Constrained **w/o Protocol Transition** → HTTP/winterfell → **the Bronze Bit target**.
- `CASTELBLACK$` — a computer account → **the S4U2self-abuse target** (self-ticket → local admin on castelblack).
- `WINTERFELL$` — Unconstrained (UNCONSTRAINED-DELEG).

## Phase 2 — Triage
- **now:** S1 Bronze Bit (headline CVE, clean recipe, provable), S2 S4U2self-abuse (reuses getST, provable),
  S3 coercion extras (cheap COERCION additions).
- **assess:** S4 Kerberos-relay — decide in Phase 5 (listener complexity + lab conditions; may defer with reason).
- **out of scope:** the already-covered dfscoerce; tool-hardening/opsec findings; non-delegation techniques.

## Phase 3 — Sprint split
- **S1 — Bronze Bit** (`bronze_bit.py`): new executor + chain wiring. Base `66a8cc4`.
- **S2 — S4U2self-abuse** (`s4u2self.py`): new executor + chain wiring. Branches from S1 tip.
- **S3 — Coercion extras**: `shadowcoerce` + `webdav` methods in `coercion.py`. Branches from S2 tip.
- **S4 — Kerberos-relay** (assess): thin krbrelayx executor OR deferred-with-reason.
Each sprint: independently shippable, its own commit(s), diff-review, tests, GOAD proof, merge.

## Phase 4/5 — Design (per sprint)

### S1 — Bronze Bit (CVE-2020-17049)
The near-twin of CONSTRAINED-DELEG-PT, for the **no-protocol-transition** case. A service account with
`msDS-AllowedToDelegateTo` but not `TrustedToAuthForDelegation` normally gets a **non-forwardable**
S4U2self ticket → S4U2proxy refuses. `-force-forwardable` forges the forwardable flag using the service
account's own key (the CVE), so S4U2proxy to the allowed SPN succeeds.
- **Recipe:** `impacket-getST -spn <allowed_spn> -impersonate <HVT> -force-forwardable [-altservice <svc>/<host>]
  <dom>/<service_acct> -hashes/-aesKey <service_key>` (KRB5CCNAME unset → ccache in CWD) → `nxc smb <host>
  -k --use-kcache` = ticket-backed access = terminal proof. `-altservice` rewrites the sname so the HTTP
  delegation yields a CIFS ticket on the same host (same host key) for an SMB proof.
- **Auth = the service account's key** (the compromised account IS the credential), supplied via the
  standard operator cred (`--user CASTELBLACK$ --hash <nt>` / `--aes-key`) exactly like
  CONSTRAINED-DELEG-PT's `_op_auth_target`; masked by `redact_argv`; ticket in a local var only.
- **GOAD proof:** `-spn HTTP/winterfell.. -impersonate Administrator -force-forwardable -altservice
  cifs/winterfell.. north/CASTELBLACK$ -hashes <castelblack_nt>` → cifs ticket as Administrator → nxc smb
  winterfell → Pwn3d. CASTELBLACK$'s hash obtained operationally (DCSync, in-memory, never stored).
- **Options weighed:** (a) altservice-to-cifs for an SMB proof (CHOSEN — reuses the proven nxc-smb predicate);
  (b) prove against the literal HTTP service (WinRM/ADCS-web) — more moving parts, deferred. Flip trigger:
  if altservice is blocked on the target, fall back to the HTTP-service proof.
- **Chain wiring:** `pre={S0_user_creds}` (the service-account key is the cred) → `eff={S_impersonation_tgt}`
  (a privileged impersonation ticket toward the target host) — makes Bronze Bit a chain producer, unlike the
  standalone CONSTRAINED-DELEG-PT. Non-mutating; no rollback.
- **Terminal:** `authn_success`, ok = nxc access; predicate names service_acct→impersonate@spn (public ids);
  proof_token over public ids only.

### S2 — S4U2self-abuse
Control of a computer/service account → S4U2self returns a ticket to the account's **own** service as any
user; because the ticket is encrypted with the account key you hold, you access that host's services as the
impersonated (privileged) user = local admin on the machine you control.
- **Recipe:** `impacket-getST -self -impersonate <HVT> -altservice cifs/<self_host> <dom>/<computer$>
  -hashes/-aesKey <machine_key>` (KRB5CCNAME unset) → `nxc smb <self_host> -k --use-kcache` = proof.
- **GOAD proof:** `-self -impersonate Administrator -altservice cifs/castelblack north/CASTELBLACK$
  -hashes <castelblack_nt>` → cifs ticket to castelblack as Administrator → nxc smb castelblack → Pwn3d.
- **Chain wiring:** `pre={S0_user_creds}` (machine key) → `eff={S_computer_control}` (local admin on the
  self host). Non-mutating.
- **Options:** (a) `-self` only, (b) `-self -altservice` to pick the service class — CHOSEN (b) so an SMB proof
  is possible from any registered SPN class.

### S3 — Coercion extras (ShadowCoerce + WebDAV)
Extend `coercion.py` only (no new executor): add `shadowcoerce` (MS-FSRVP, e.g. `coercer coerce -m fsrvp` or
`ShadowCoerce.py`) and `webdav` (PushSubscription/change-notify, e.g. `coercer coerce -m webdav` /
`PetitPotam`-style WebClient trigger) to `COERCION_METHODS` + `coercion_trigger_argv`, mirroring the existing
`dfscoerce` branch (argv list, secret-masked). These are coercion VECTORS of the existing COERCION edge;
`verified_recipe` stays per-edge (FSRVP is often patched → likely proven-or-inconclusive on GOAD).

### S4 — Kerberos-relay (assess)
krbrelayx relays Kerberos auth (AS-REP/TGT) to LDAP/SMB/ADCS. Listener-based (like NTLM-RELAY), needs a
coercion source + a relay target without the right protections. **Decision (Phase 5):** build a thin
executor mirroring NTLM-RELAY's listener/flow IF a clean GOAD proof path exists; otherwise DEFER with a
written reason (keep T6's proven value in S1–S3 rather than ship an unprovable listener). Recorded either way.

## Phase 7 — Test plan (per sprint, non-vacuous)
- Scripted `CommandRunner` fakes: getST emits a "Saving ticket in X" line (+ ccache file), nxc emits
  `(Pwn3d!)` / `[+]`. Assert: the argv carries `-force-forwardable` (S1) / `-self` (S2) and the right
  `-spn`/`-altservice`/`-impersonate`; the service key is **masked** in every stored argv; the ticket path
  never reaches the receipt; terminal `ok` tracks the nxc predicate, not the return code.
- Gate RED: a getST that saves no ticket → no_ticket, terminal ok False (prove the ticket-gate fires); an nxc
  without Pwn3d/[+] → ok False (prove the access predicate decides, not exit 0).
- Chain: `produced()` emits the eff capability only on success; secret key/ticket never in the receipt.
- Regression: full `tests/unit/validation` vs the 485 baseline.

## Phase 8 — Benefit (pre-registered)
Each new executor goes from absent → a working, chain-wired edge proven live on GOAD (Bronze Bit: access
winterfell as Administrator via CASTELBLACK$ w/o protocol transition; S4U2self: local admin on castelblack).
Scored by ad-lab-harness where a proof-truth facet exists; else the terminal `ok` + the captured nxc output.

## Delegation (codex-interop, cross-family)
Cyber Tier-2. Plan + build: Claude (Opus). **Plan review (this gate) + each diff review: Codex Sol**
(cross-family). ~60/40 over the tranche. Live proof + integration: Claude.

## Plan-review resolutions + susceptibility probe (Codex Sol, 27NOV2026 — FIX-FIRST → resolved)
Cross-family review raised 1 BLOCKER + 5 HIGH; all addressed, with an empirical GOAD probe (operator
creds in-memory only, CASTELBLACK$ key via DCSync):

1. **BLOCKER — S1 provability unproven.** PROBED: GOAD north's KDC **enforces the CVE-2020-17049 patch**.
   Negative control (no `-force-forwardable`) → `KDC_ERR_BADOPTION` (non-forwardable, as designed); positive
   (`-force-forwardable`) → **`KRB_AP_ERR_MODIFIED`** (the KDC rejects the forged ticket = patched). So Bronze
   Bit cannot be *exploited* here. **Resolution (owner "a failure is a design problem to hack"):** this is a
   valuable *negative validation* — the executor runs the real attack and **classifies** the target:
   `exploited` (ticket + Pwn3d) / `kdc_patched` (KRB_AP_ERR_MODIFIED) / `not_delegatable` (BADOPTION) / error.
   GOAD proof = it correctly classifies north as `kdc_patched`. `verified_recipe=False` (no in-lab exploit),
   but the classification is proven against real KDC responses. S2 carries T6's success proof.
2. **S2 WORKS (probed):** `getST -self -impersonate Administrator -altservice cifs/castelblack` as CASTELBLACK$
   → `nxc smb castelblack -k` → **`(Pwn3d!)` local admin**. S4U2self is not CVE-patch-dependent. `verified_recipe=True`.
3. **HIGH — key handling.** Prefer `-aesKey` (the probe needed AES; an NT hash can't decrypt an AES S4U2self
   ticket); when only an NT hash is supplied, normalize to `:<NT>` (impacket requires `LM:NT`/`:NT`). Shared
   `_s4u_common` formats the key; don't drop AES in an if/elif when AES is present.
4. **HIGH — S2 predicate.** Require **`Pwn3d!`** for the local-admin claim (plain `[+]` auth is NOT local
   admin — S4U2self preserves the user's real authorization). Negative test: `[+]` without `Pwn3d` → not admin.
5. **HIGH — S2 capability.** Not `S_computer_control` (that's AD-object control). Emit `local_admin_for(self_host)`
   on the Pwn3d proof; stash the ccache in `artifact["_composed_products"]` so `produced()` returns a
   `CAP_CCACHE` capability (local-var tickets can't feed a producer). S1 → `S_impersonation_tgt` (same pattern),
   emitted only on an actual exploit.
6. **HIGH — S3 coercer invocations.** Coercer has no `-m fsrvp`/`-m webdav`: use `--filter-protocol-name
   MS-FSRVP` (ShadowCoerce) and a real HTTP-capable EFSR/DFSNM method over WebDAV transport; add `--hashes`
   (double-dash, Coercer's flag) to `redact_argv._SECRET_FLAGS` (currently only `-hashes` is masked → a leak).
7. **S4 Kerberos-relay: DEFER** (reviewer concurred) — no clean GOAD proof path; description corrected to
   *relaying service-ticket/AP-REQ auth* (not TGT capture). mitm6→ADCS-over-DNS is a candidate, prerequisites
   not established on this GOAD. Recorded, not built this tranche.

## S1+S2 build + live proof (27NOV2026)
Shipped: `bronze_bit.py` (BRONZE-BIT) + `s4u2self.py` (S4U2SELF) over a shared `_s4u_common.py`
(key formatting + Kerberos-failure classification). Both: run-dispatchable (`inputs.TARGET_PARAM`),
chain-wired (BRONZE-BIT → `S_impersonation_tgt`; S4U2SELF → `local_admin_for(self_host)` via
`chain_eff`, both producing a `CAP_CCACHE` capability on success), with viability probes. Secret-safe
(service key masked; ccache engine-only, never in the receipt).

**Proven live via the REAL executor CLI against GOAD north** (CASTELBLACK$ AES key via DCSync, in-memory):
- `run S4U2SELF` → **`ok=True classification=local_admin`** — CASTELBLACK$ → Administrator → local admin on
  castelblack (Pwn3d). `verified_recipe=True`.
- `run BRONZE-BIT` → **`ok=False classification=kdc_patched`** — the executor runs the real CVE-2020-17049
  attack (`-force-forwardable`) and correctly classifies north's KDC as patched (`KRB_AP_ERR_MODIFIED`), the
  determined-negative validation. `verified_recipe=False` (no in-lab exploit; the classification is real).

496/496 validation tests (485 base + 11); classification + Pwn3d-requires-admin + no-secret-in-receipt +
kdc_patched detection + chain-producer gates covered.

## Baseline
485 validation tests @ `66a8cc4` (captured; per-sprint manifests at each sprint's real base SHA).
