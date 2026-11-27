# BACKLOG — SMB + NFS share discovery, crawl & loot-search module (first joint Windows/Linux module)

**Status: QUEUED** — scheduled AFTER T4 completes. Logged at owner request 27NOV2026.

## Goal
An **exhaustive** share-search capability that, given a target scope, automatically:
1. **Discovers** shares across both OS families — **SMB** (Windows/Samba) **and NFS** (Linux/Unix
   exports). This is the **first joint Windows/Linux module** (the toolchain has been AD/Windows
   only so far).
2. **Mounts or crawls** each reachable share — NFS `mount`/`showmount`; SMB via smbclient /
   NetExec `spider_plus` / manspider-style recursive listing (mount where useful, crawl where not).
3. **Searches** the contents exhaustively for **interesting information and credentials** —
   passwords, hashes, keys (SSH/PFX/PEM), connection strings, `.kdbx`/`.ppk`/`unattend.xml`/
   `web.config`/`.env`/`id_rsa`/`*.vmdk` creds, cloud tokens, PII, "password"-shaped strings, and
   high-value file types/paths — with ranked, deduplicated hits.

## Shape (to design when scheduled)
- **Dual-mode like every technique**: an operator can dispatch it standalone (`validate run` or a
  dedicated command) AND it composes as an engine edge (a discovered credential feeds downstream
  edges — e.g. a looted hash → DCSYNC/forging).
- **Discovery**: SMB (nxc `--shares`, enum per host), NFS (`showmount -e`, `rpcinfo`); scope =
  the configured targets / an enumeration finding.
- **Access**: read-only crawl by default; mount NFS read-only; never write to a share.
- **Search engine**: pluggable rule set (regex + filename/path + file-type signatures), size/time
  bounds, binary-aware, with a secrets rule pack. Findings are **presence + location**, and any
  recovered secret value is handled presence-only in receipts (same rule as the rest of the
  toolchain) — the loot itself goes to the operator's out-of-band store, never a stored receipt.
- **Portability**: honor the standing directives — environment-parameterized, no host-pinning,
  and route DNS/FQDN/host-resolution through the queued hardening layer
  (BACKLOG-27NOV2026-dns-fqdn-host-processing-hardening).
- **Integrity/scope**: authorized-lab/engagement only; read-only; clear diagnostics on
  unreachable/denied shares (inconclusive, never a fabricated hit).

## Why queued
Large, cross-OS, new capability dimension (not an AD attack technique). Design it as its own
plan/sprint after T4 is complete and operator-ready. It will likely want the DNS/host-resolution
hardening done first (or alongside).

## Related
- Existing `OPENSHARES-WRITE` executor (SMB writable-share check) — a narrow precursor; this
  module is the broad discover-crawl-loot capability.
- Standing directives: portability (claude-mem #66220), DNS/FQDN hardening
  (BACKLOG-27NOV2026-dns-fqdn..., claude-mem #66225), dual-mode dispatch (#66215).
