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

## Phase 3 — Sprint split (3 sprints, each shippable/testable/revertable)

- **S1 — the resolution layer + config surface (G3, G4).** New `netresolve.py` with canonical
  helpers; new config fields; replace the 3 NetBIOS copies. Pure addition + DRY refactor, **no
  change to emitted tool argv yet** except NetBIOS now flows through one function. Branch
  `dev/dnsharden-s1`.
- **S2 — wire Kerberos discovery into executors (G2, portability).** Every `-k`/`--use-kcache`
  and forge-reauth call passes derived `--kdcHost`/`--dns-server`; impacket calls get consistent
  `-dc-ip` via the layer. Fixes the fresh-host bug. Branch from S1 tip.
- **S3 — up-front resolution preflight + diagnostics (G1, G5).** A preflight the executors call
  that validates FQDN/realm reachability and returns a clear actionable diagnostic / `inconclusive`
  on failure (never a fabricated success, never blamed on the technique). Branch from S2 tip.

## Phase 4/5 — Design

### `netresolve.py` (new shared module — the single resolution authority)
Plain functions + a small dataclass (mirrors `forge_common`/`acl_common` style). No host-pinning;
every value derives from `cfg` or an explicit operator field.

- `netbios(cfg) -> str` — THE canonical NetBIOS short name (explicit `cfg.netbios_domain`, else the
  FQDN's first label, upper-cased). `config.netbios()`, `forge_common.netbios()`, and
  `dcsync._krbtgt_target()` all delegate here (G3).
- `gc_qualify(cfg, sam) -> str` — NetBIOS-qualify a possibly-GC-ambiguous account name
  (`<NETBIOS>/<sam>`), the generalization of `dcsync._krbtgt_target` (G3).
- `kdc_host(cfg) -> str` — `cfg.kdc_host` or `cfg.dc_ip` (G4).
- `dns_server(cfg) -> str` — `cfg.dns_server` or `cfg.dc_ip` (G4).
- `kerberos_flags(cfg) -> list[str]` — `["--kdcHost", kdc_host(cfg), "--dns-server", dns_server(cfg)]`
  for nxc Kerberos calls (G2). (impacket uses `-dc-ip`; add `dc_ip_flags(cfg)` for symmetry.)
- `resolve_host(cfg, fqdn) -> HostResolution` — resolve an FQDN to an IP, trying in order: the
  operator `host_map` (FQDN→IP), then `cfg.dns_server`/DC-as-resolver, then system resolver; return
  a dataclass `{fqdn, ip|None, via, ok, diagnostic}` — presence-only, never fabricated (G1/G5).
- `realm_kdc_reachable(cfg) -> HostResolution` — can the realm's KDC (`kdc_host(cfg):88`) be reached?
  (G1).

### `ValidationConfig` new fields (G4) — all optional, runtime, no host-pinning
`kdc_host: Optional[str]`, `dns_server: Optional[str]`, `host_map: dict[str,str]` (FQDN→IP),
`use_gc: bool=False`. None of these are secrets (not added to `redacted()`'s secret set).

### S2 wiring (G2)
`constrained_deleg` nxc argv, `generic_all` nxc argv, and (confirm) `forge_common` reauth all append
`netresolve.kerberos_flags(cfg)`. Any `-dc-ip` built inline is routed through `dc_ip_flags`.
**Behavior change is ADDITIVE** (extra discovery flags) — must not regress the carrier-/etc/hosts path.

### S3 preflight (G1/G5)
A reusable `preflight_target(ctx, host)` the executors can call before the first remote call:
resolves the target + checks realm→KDC; on failure returns a structured `inconclusive` artifact
(`resolution_failed:<which>`), never a `complete` receipt. Opt-in per executor (start with the
Kerberos-dependent ones), so it is additive and does not change a passing path.

### Alternatives weighed (material decisions)
- **One shared module vs per-executor helpers.** Chosen: one module (`netresolve`) — G3 is literally
  3 copies diverging; centralizing is the point. Rejected per-executor: perpetuates the drift.
  Flip if a single module forced an import cycle (it will not — leaf module, imports only `config`).
- **Preflight: always-on vs opt-in.** Chosen: opt-in per executor (S3), so it never changes a
  currently-passing path without that executor explicitly adopting it. Rejected always-on: a
  blanket preflight could turn a working run `inconclusive` on a benign resolver quirk.
- **Derive `--dns-server` from `dc_ip` vs require explicit.** Chosen: derive (DC is a DNS server in
  AD) with an explicit `cfg.dns_server` override — matches how forge_common already works and keeps
  zero-config operation on a standard AD.

## Phase 7 — Test plan (per sprint, non-vacuous)
- **S1:** `netbios`/`gc_qualify`/`kdc_host`/`dns_server`/`kerberos_flags` unit tests (explicit
  override wins; derived fallback; GC-qualify shape). A test that the 3 former NetBIOS call-sites now
  return identical results to `netresolve.netbios`. `resolve_host` host_map hit / miss / unresolvable
  → diagnostic (fake resolver; no live DNS). RED proof: a mutant that drops the override must fail
  the "override wins" test.
- **S2:** each wired executor's built argv CONTAINS `--kdcHost`/`--dns-server` (scripted-runner argv
  assertion); the carrier path still works (existing executor tests stay green). RED: remove the
  flag append → the argv assertion fails.
- **S3:** `preflight_target` returns `inconclusive` with `resolution_failed:*` on an unresolvable
  host/unreachable KDC, and passes through on a resolvable one; an executor using it never emits
  `complete` on a resolution failure. RED: a mutant that returns `complete` on failure fails the gate.

## Phase 8 — Benefit (pre-registered metric)
**Metric:** number of Kerberos-dependent executors that succeed on GOAD **with the carrier
`/etc/hosts` realm entries removed** (explicit discovery flags only). Baseline (base `3e5931b`,
G2 present): the `-k --use-kcache` executors FAIL realm resolution without `/etc/hosts`. Target:
they succeed via derived `--kdcHost`/`--dns-server`. Measured live on kali-vr by temporarily
masking the realm `/etc/hosts` lines in an isolated run. (A clean control: restore `/etc/hosts`.)

## Delegation split (codex-interop, ~60/40)
- Plan (this doc): Claude (Opus). **Plan review (Phase 5 gate): Codex Sol** (bulk, read-only).
- S1/S2 implementation: Claude (context-heavy, touches many call-sites) → **Codex Sol reviews each
  diff**. S3 preflight: candidate to hand to Codex Sol to implement against this design, Claude
  reviews. Keep the 60/40 tally here.
- Live proofs on GOAD (kali-vr): Claude.
