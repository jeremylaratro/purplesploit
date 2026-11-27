# PurpleSploit Python Package

PurpleSploit is a modular security-testing framework with terminal and web
interfaces. It centralizes target, credential, service, session, and finding
state so authorized assessment workflows can reuse context safely across
modules.

It also ships an operator-driven Active Directory validation subsystem
(`purplesploit.validation`) that turns detection findings into scored `proof.v1`
receipts across the AD attack surface (Kerberos roasting, delegation, ACL takeover,
AD CS, coercion/relay, DCSync, ticket forging, and read-only SMB/NFS share loot). See
the [Validation Ops Manual](../docs/guides/VALIDATION-OPS-MANUAL.md) for per-technique
commands.

The complete documentation, walkthrough, and source repository are available
at [github.com/jeremylaratro/purplesploit](https://github.com/jeremylaratro/purplesploit).
