# BACKLOG — DNS / FQDN / remote-host processing hardening

**Status: QUEUED** (future step; does NOT block the active tranche series). Logged at owner
request 27NOV2026.

## Problem
The validation executors drive impacket / nxc / certipy / bloodyAD against a remote AD server.
These tools frequently fail or misbehave on **name-resolution / server-discovery** issues that are
not the operator's fault and currently surface as opaque errors or silent failures. Observed live
during T3/T4:
- **FQDN invalid / unresolvable** — Kerberos needs the target + realm FQDN; a carrier without the
  target domain's DNS fails ("Temporary failure in name resolution"). Worked around with
  `/etc/hosts` on kali-vr.
- **KDC / realm not resolvable** — tools resolve the *realm name* to locate the KDC and fail
  (`<REALM>:88` name resolution); needs an explicit `--kdcHost`.
- **Global-catalog name ambiguity** — a bare account name (e.g. `krbtgt`) resolves to multiple
  objects across a multi-domain forest via the GC (`ERROR_DS_NAME_ERROR_NOT_UNIQUE`); needs NetBIOS
  qualification. (Already fixed for DCSYNC in `fe4a7fb`; the pattern recurs elsewhere.)
- **Generic** — any case where impacket or another tool can't **find or process** the remote
  server: DNS, KDC discovery, GC-vs-DC choice, SPN resolution, LDAP-vs-LDAPS, IP-vs-FQDN
  requirements.

## Scope of the hardening
A shared **remote-host / name-resolution layer** the executors call, that:
1. **Auto-remediates where safe:** derive + pass `--kdcHost` / `--dns-server` / `-dc-ip` from the
   configured DC; NetBIOS-qualify GC-ambiguous names; choose DC vs GC correctly; prefer the FQDN
   for Kerberos and the IP for NTLM as each tool requires.
2. **Resolves + validates the target up front:** is the FQDN resolvable (via configured DNS, the
   DC as resolver, or an operator host-map)? is the realm→KDC reachable? — fail with a **clear,
   actionable diagnostic** (which name failed, which resolver was tried), never a silent or
   misleading result.
3. **Config surface:** `ValidationConfig` fields for `kdc_host`, `dns_server`, `host_map`
   (FQDN→IP), `use_gc` where relevant — all runtime params, no host-pinning (portability directive).
4. **Fail-safe:** a resolution / discovery failure is an explicit `inconclusive` / unknown, never a
   fabricated success and never attributed to the technique.

## Why queued, not now
Cross-cutting infra touching many executors. The active tranches work on GOAD with the carrier
`/etc/hosts` + `--kdcHost` in place. Schedule after the active tranche series, or sooner if a
technique is blocked by a resolution issue the per-executor workaround can't cover.

## Related
- DCSYNC NetBIOS-qualified `krbtgt` (fixed, `fe4a7fb`) — one instance of this class.
- T4 reauth `--kdcHost` / `--use-kcache` + carrier `/etc/hosts` (claude-mem #66223).
- Portability directive (claude-mem #66220): everything environment-parameterized, no host-pinning.
