# PLAN-DNSHARDEN — DNS / FQDN / remote-host processing hardening — 27NOV2026

Supersedes the backlog note `BACKLOG-27NOV2026-dns-fqdn-host-processing-hardening.md`
(which stays as the origin record). Methodology: dev-methodology full cycle, right-sized to
3 tight sprints. Owner directive 27NOV2026: "do the gardening first, then immediately move
into nfs/smb."

## Phase 0 — Frame
- Project: `purplesploit` (`/srv/share/dev/purplesploit`), git repo. Base SHA **`3e5931b`** (main
  after the T4 merge).
- Governing `CLAUDE.md`: author/committer `jeremylaratro`, NO attribution lines; local unit tests
  are the merge gate (no GitHub CI); conventional commits; branch cycle + worktree teardown after
  merge.
- Package root: `python/purplesploit/validation/`.

## Phase 1 — Objective + gap analysis (evidence-based)

**Objective (acceptance criterion):** the validation executors drive their remote tools against a
**never-before-seen AD system with NO operator `/etc/hosts` carrier entries**, succeeding by
deriving + passing explicit name-resolution flags — or failing with a **clear, actionable
diagnostic** (which name failed, which resolver was tried), never a silent/opaque/misleading
result and never a fabricated success. Everything config-parameterized (portability directive,
claude-mem #66220).

| ID | Type | Evidence (measured 27NOV2026, base `3e5931b`) | Provenance |
|----|------|-----------------------------------------------|------------|
| **G1** | gap | No up-front name-resolution / validation layer exists anywhere (`grep getaddrinfo\|socket\|resolve\|reach` over `executors/ config.py findings.py inputs.py` → empty). Resolution failures surface as opaque tool errors. | measured |
| **G2** | bug | Kerberos calls build `nxc smb <t> -k --use-kcache` with **NO `--kdcHost`/`--dns-server`**: `constrained_deleg.py:169`, `generic_all.py:667`. These pass live ONLY because the kali-vr carrier has the GOAD realms in `/etc/hosts`; on a fresh system they fail realm→KDC resolution. Portability defect. (forge_common:194-195 and silver/golden/diamond DO pass `--kdcHost`.) | measured |
| **G3** | issue | NetBIOS qualification duplicated in **3** places with no canonical source: `config.netbios()` (c.130), `forge_common.netbios()` (c.32), `dcsync._krbtgt_target()` (c.86). GC-ambiguity fix (`ERROR_DS_NAME_ERROR_NOT_UNIQUE`) is ad-hoc per-site. | measured |
| **G4** | gap | No `ValidationConfig` surface for `kdc_host` / `dns_server` / `host_map` (FQDN→IP) / `use_gc`; all derived ad-hoc from `dc_ip`. 27/30 executor files inline `-dc-ip {cfg.dc_ip}`. | measured |
| **G5** | gap | No diagnostic classification of resolution/discovery failures → not surfaced as `inconclusive`/actionable; attributed to the technique instead of the environment. | measured |

Pre-existing, out of scope (noted, not adopted): the `ui/web/service` test modules fail to COLLECT
for missing optional deps (`fastapi`, …) — environmental, unrelated.

## Phase 2 — Triage

| ID | Relevance | Complexity | Tier | Lane |
|----|-----------|-----------|------|------|
| G2 | 5 (real portability bug; blocks fresh-host runs) | 2 | T3→T2 | now (S2) |
| G3 | 4 (correctness/consistency; recurs) | 2 | T3 | now (S1) |
| G4 | 4 (enables G1/G2/G5; config surface) | 2 | T3 | now (S1) |
| G1 | 4 (the core hardening: validate up front) | 3 | T2 | now (S3) |
| G5 | 3 (diagnostics quality) | 2 | T2 | now (S3) |

**Out of scope (declared, repeat in every delegated prompt):** tool-hardening/opsec/detectability;
rewriting the tools themselves; IPv6 edge cases; WINS/mDNS; anything beyond AD name resolution
(DNS/KDC/GC/SPN/FQDN-vs-IP). Deliberate constants are features.

## Plan-review resolutions (Codex Sol r1, 27NOV2026 — FIX-FIRST, 9 HIGH)
Review: `docs/reviews/PLAN-DNSHARDEN-27NOV2026-codex-sol-plan-review-r1.md`. Every finding verified
by the supervisor against code. The plan is **re-scoped to the safe, high-value core** (realm/KDC +
GC + actionable diagnostics) and explicitly **defers** the large/risky parts the review surfaced.

| # | Finding (verified) | Resolution |
|---|--------------------|-----------|
| 1 | G2 coverage undercounts: `rbcd.py:253`, `adcs_esc1.py:272` also omit flags; **implicit Kerberos via `--aesKey`** (roast/add_member/targeted_kerberoast/generic_all/gpo_abuse/certifried) is missed by a `-k` grep. | S2 is driven by an **explicit nxc call-site + auth-mode inventory** (not a grep). Every Kerberos-mode call (`-k`, `--use-kcache`, `--aesKey`) gets discovery flags; NTLM modes (`-p`/`-H`) do not. |
| 2 | NetBIOS copies are NOT identical (config ignores override; forge_common no-trim; dcsync trims + `/krbtgt`). The equivalence test contract was wrong. | Canonical `netbios(cfg)` = trim + upper, honoring `netbios_domain`. `gc_qualify(cfg,sam)="{netbios}/{sam}"`. Test asserts **`dcsync._krbtgt_target(cfg) == gc_qualify(cfg,"krbtgt")`** (not `== netbios`). `config.netbios` (no callers) delegates → now honors the override (latent-bug fix, recorded). |
| 3 | Unconditional `--dns-server` **bypasses nxc's system/`/etc/hosts` resolver** → breaks the carrier path (reproduced). "Additive" claim is false. | **`--dns-server` is OPT-IN** (emitted only when `cfg.dns_server` is explicitly set). Default run is byte-for-byte unchanged (system/hosts resolution preserved). `--kdcHost` IS safe-additive (it sets the KDC location only; it does not touch host resolution) and is always derived. |
| 4 | Scripted-runner tests prove fragments, not resolution; flag-presence permits wrong/dup values; Phase-8 must count scored `proved`/terminal, not `complete` (constrained_deleg/generic_all set `complete=getst_ok`, True even when SMB auth fails). | Tests assert **exact** flag values + no duplicates + the carrier (no-`dns_server`) argv is unchanged. Phase-8 counts **`terminal_ok` / harness-scored `proved`**, never `complete`. The `complete=getst_ok` gap is logged as pre-existing item **PX-1** (out of scope, noted). |
| 5a | Flags wire discovery but not `HostResolution.ip`; nxc replaces the resolved transport addr with the hostname for Kerberos → IP substitution would break the SPN. | **No IP substitution.** The FQDN stays the connection + auth target; we only add `--kdcHost`/opt-in `--dns-server`. This sidesteps transport-vs-auth entirely. `host_map` is **dropped** (no safe consumer without IP substitution). |
| 5b | Executor-level blanket preflight → false `inconclusive` (Silver w/ usable ticket needs no KDC; AD-account "targets" in GenericAll/ShadowCreds aren't endpoints). | **No blanket preflight.** S3 is a **post-hoc failure classifier**: it only runs on an **already-failed** tool call and labels the cause. It can never pre-reject a working path. |
| 5c | SPN/LDAP/LDAPS/DC-vs-GC unspecified; `use_gc` has no consumer. | `use_gc` **dropped**. SPN/LDAP-scheme/GC-routing explicitly **DEFERRED** (follow-up backlog), with the existing `adcs_esc1` LDAP-scheme override left intact. |
| 5d | A diagnostic in an arbitrary artifact field / step note is **dropped** by `_receipt_from` / `proof.normalize_steps` (keeps only `{name,ok}`). | The diagnostic is written to **`errors`** (a persisted receipt field — confirmed: T4 receipts carry `errors`) as `resolution_failed:<which>`, and S3 tests assert it is present **in the final receipt**. |
| 6 | Import-cycle risk: `config→netresolve` + `netresolve→config`. | `netresolve` imports **nothing** from the package (operates on a duck-typed `cfg`). `config` imports `netresolve` one-way. A **cold-import test** covers config / netresolve / the executor registry. |

**Deferred to a follow-up backlog (review 5a/5c)** — too large/risky for this gardening pass:
`host_map`→IP transport substitution, auth-mode/pivot-aware up-front preflight, SPN resolution,
LDAP-vs-LDAPS routing, DC-vs-GC selection. The core observed pain (realm→KDC resolution, GC
account-name ambiguity, opaque resolution failures) is fully covered by S1–S2 below.

## Phase 3 — Sprint split (2 sprints, re-scoped)

- **S1 — `netresolve` layer + config + NetBIOS consolidation (G3, G4-core).** New dependency-free
  `netresolve.py`; config fields `kdc_host` / `dns_server` (both `Optional`, non-secret); collapse the
  3 NetBIOS sites to the canonical helper (correct contract); import hygiene. **No change to emitted
  tool argv** (NetBIOS now flows through one function; config.netbios gains the override fix).
  Branch `dev/dnsharden-s1`.
- **S2 — wire `--kdcHost` to all Kerberos-mode nxc calls + persisted resolution diagnostics
  (G2, G1-core, G5).** Auth-mode inventory → append `netresolve.nxc_kerberos_flags(cfg)` to every
  Kerberos-mode nxc call; `--dns-server` opt-in only; keep the FQDN target. On a failed Kerberos/
  remote call, classify the cause into an `errors` `resolution_failed:<which>` diagnostic. Prove live
  on GOAD (realm `/etc/hosts` removed, `kdc_host` set). Branch from S1 tip.

## Phase 4/5 — Design (re-scoped)

### `netresolve.py` — new, **dependency-free** (duck-typed `cfg`, imports nothing from the package)
- `netbios(cfg) -> str` — `(cfg.netbios_domain or cfg.domain.split(".",1)[0] or "").strip().upper()`.
- `gc_qualify(cfg, sam) -> str` — `f"{netbios(cfg)}/{sam}"` (the generalization of `_krbtgt_target`).
- `kdc_host(cfg) -> str` — `cfg.kdc_host or cfg.dc_ip`.
- `dns_server(cfg) -> Optional[str]` — `cfg.dns_server or None` (**opt-in**; None ⇒ flag omitted).
- `nxc_kerberos_flags(cfg) -> list[str]` — `["--kdcHost", kdc_host(cfg)]` **+** `["--dns-server", dns_server(cfg)]` only when `cfg.dns_server` is set.
- `classify_resolution_failure(text) -> Optional[str]` — maps a FAILED tool's combined stdout/stderr
  to `resolution_failed:realm_kdc` (`<REALM>:88` / KDC not found), `:fqdn` (name resolution / NXDOMAIN
  for the target), or `:dns` (generic resolver failure); `None` when no resolution-shaped error is
  present. **Classifier only — never decides success.**

### `ValidationConfig` (G4-core)
Add `kdc_host: Optional[str] = None`, `dns_server: Optional[str] = None` (non-secret; not in the
`redacted()` secret set). `netbios` property delegates to `netresolve.netbios(self)` (import one-way).

### S2 wiring (G2) — driven by the auth-mode inventory
For each nxc call-site: if its auth mode is Kerberos (`-k`, `--use-kcache`, or `--aesKey`), append
`netresolve.nxc_kerberos_flags(cfg)`. Confirmed sites to wire: `constrained_deleg`, `generic_all`,
`rbcd`, `adcs_esc1`, and the `--aesKey` paths in `roast`/`add_member`/`targeted_kerberoast`/
`gpo_abuse`/`certifried` (the S2 implementation re-derives the full list from a fresh inventory and
records it). `forge_common`/silver/golden/diamond already pass `--kdcHost` (leave, or route through
the helper for consistency — no value change). NTLM-mode calls untouched.

### S3 diagnostic (folded into S2) — post-hoc, persisted
After a Kerberos/remote call that did NOT succeed, call `classify_resolution_failure` on its output;
if it returns a label, append it to `errors` (persisted) and to the step note. Never changes a
success path; never fabricates. Opt-in per wired call-site.

## Phase 7 — Test plan (per sprint, non-vacuous)
- **S1:** `netbios` (override wins + trimmed + upper; empty-domain safe); `gc_qualify` shape;
  **`dcsync._krbtgt_target(cfg) == gc_qualify(cfg,"krbtgt")`** across default + custom (whitespace)
  override; `kdc_host`/`dns_server` default vs explicit; `nxc_kerberos_flags` = exactly
  `["--kdcHost", <dc>]` with no `dns_server`, and exactly `[...,"--dns-server",<v>]` with it (no dup,
  right values); `classify_resolution_failure` on sample realm/FQDN/DNS error strings + a success
  string (→ None); **cold-import** of config/netresolve/registry. RED: drop the override in `netbios`
  → "override wins" fails; a mutant that emits `--dns-server` unconditionally → the "carrier argv
  unchanged" test fails.
- **S2:** for each wired executor, the built nxc argv **contains `--kdcHost <dc>`** and, with no
  `cfg.dns_server`, **does NOT contain `--dns-server`** (carrier path byte-identical); a failed call
  with a realm-resolution error string yields `errors` ⊇ `{resolution_failed:realm_kdc}` **in the
  final receipt**; a success yields none. RED: remove the flag append → argv assertion fails; return
  `complete` on a resolution failure → diagnostic-in-receipt test fails. Existing executor tests stay
  green (NTLM paths unchanged).

## Phase 8 — Benefit (pre-registered, rigorous per r1 #4)
**Metric:** count of Kerberos-mode executors whose **terminal succeeds** (harness-scored `proved`, or
`terminal_ok=True` where no facet) on GOAD with the **realm `/etc/hosts` lines removed** and
`cfg.kdc_host` set — vs the baseline (same removal, base code) where realm→KDC resolution fails.
**Controls (all four cells):** {baseline, hardened} × {carrier realm lines present, absent}, fresh
per-run ticket state, pinned tool versions (impacket 0.13.1 / installed nxc), the exact removed lines
recorded. Count **`terminal_ok`/`proved`, never `complete`** (PX-1). A null/!=expected result is
reported, not massaged.

## Pre-existing items found (noted, not adopted — out of scope)
- **PX-1:** `constrained_deleg` (`complete=getst_ok`, c.190) and `generic_all`
  (`complete=getst_ok and rollback`, c.691) report `complete=True` even when the SMB terminal fails.
  Semantic inconsistency vs the forging executors (complete requires the terminal). Logged for a
  future correctness pass; the DNS-harden Phase-8 metric avoids it by counting `terminal_ok`.

## Delegation split (codex-interop, ~60/40 — running tally)
- Plan (this doc): Claude. **Plan review r1: Codex Sol** (FIX-FIRST, 9 HIGH — all addressed/deferred
  above). Plan verify r2: Codex Sol.
- S1/S2 implementation: Claude (touches many call-sites) → **Codex Sol reviews each diff**.
- Live proofs: Claude (GOAD/kali-vr). Tally so far — Claude: plan+impl (60); Codex: reviews (40).
