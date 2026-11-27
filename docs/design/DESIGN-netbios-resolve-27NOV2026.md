# DESIGN — active NetBIOS resolution (layered: main + backups + heuristic) — 27NOV2026

Follow-up to DNSHARDEN. Owner request: "one main method for netbios, then one or two backup
methods that all can try after 3 fails."

## Problem
`netresolve.netbios(cfg)` is a **guess** — the FQDN's first label, upper-cased. The real NetBIOS
short name can differ from the first DNS label; when it does, GC-qualification
(`gc_qualify` → the DCSYNC krbtgt target) is wrong, re-introducing
`ERROR_DS_NAME_ERROR_NOT_UNIQUE` in a multi-domain forest.

## Design (all methods verified live on GOAD)
`resolve_netbios(cfg, runner, attempts=3)` layers, most-authoritative first:
1. **MAIN — `rpcclient … -c lsaquery`** → `Domain Name: <NETBIOS>`. Retried up to `attempts` (3).
2. **BACKUP 1 — `rpcclient … -c querydominfo`** → `Domain: <NETBIOS>` (a different RPC/SAMR path).
3. **BACKUP 2 — `impacket-lookupsid … 1200`** → the `<NETBIOS>\<account>` prefix (a different tool).
4. **FALLBACK — the heuristic** (`netbios()`: operator override, else FQDN first label). Always returns.

An explicit `cfg.netbios_domain` override **short-circuits** (never queries).
`ensure_netbios(cfg, runner)` resolves then **caches** a NETWORK result onto `cfg.netbios_domain`
(so later `netbios()`/`gc_qualify()` use it); a heuristic fallback is **not** cached, so a transient
failure never permanently pins the guess.

## Integration
`dcsync.execute()` calls `ensure_netbios` before building the krbtgt target, recording a public
`resolve_netbios` step (`NetBIOS=<name> via <method>`). The credentialed probe argv is **not**
recorded; `redact_argv` masks `-U user%pass` and the `domain/user:password@host` lookupsid target if
ever recorded. The resolved name is a PUBLIC short domain name — safe in receipts.

## Proof (live, GOAD 27NOV2026)
- `north.sevenkingdoms.local` → **NORTH via lsaquery(attempt 1)**.
- A deliberately mislabeled `fake-label.north.sevenkingdoms.local` (heuristic would guess the WRONG
  `FAKE-LABEL`) → still **NORTH via lsaquery** — the active resolution beats the guess.
- Unit (`test_netbios_resolve`, 10): main-wins-first; main retried exactly 3× then backup; fall to
  lookupsid; all-fail → heuristic; `attempts` configurable; override short-circuits (no query); noise
  rejected; ensure caches network/not heuristic; Kerberos-only cfg declines gracefully. Retry
  non-vacuity mutation-proven. 400/400 validation tests green (390 baseline + 10).
