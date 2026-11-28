# Autopwn planner (ADR-003 Phase 4a)

`purplesploit-validate autopwn` inspects posture from the configured start identity
and prints eligible projected alternatives, whether each technique could produce
a credential or reach the requested goal, the resolved fence, and goal status.
It never calls an executor, acquires a credential, or rescans as a projected
identity. `goal_reached` is always false; `goal_status=projected` is a prediction.
The default goal is `S_DA` (`--goal DA` is an alias).

For example, using your existing authentication options:

```sh
purplesploit-validate --domain lab.example --dc-ip dc.lab.example \
  --user operator autopwn --scope dc.lab.example,member.lab.example \
  --param ASREP.principal=svc --max-hops 100 --max-time 60
```

Scope is required and resolved before posture reads. Combine these forms:

- `--scope host,host`: explicit host/IP membership.
- `--scope-domain lab.example`: case-insensitive FQDN suffix membership, with a
  label boundary. Supply concrete planning hosts using shared `--target` options.
- `--scope-enumerate lab.example`: LDAP `objectClass=computer`, requesting only
  `dNSHostName`, materializes hosts into the fence. The LDAP DC must already be
  fenced, or its FQDN must belong to the explicitly named enumeration domain.
  An IP has no inferable domain membership: add `--scope <DC-IP>` for that case.

Enumeration bootstrap endpoints are recorded separately in the audit header.
They become planning targets only when explicitly scoped or returned by the
computer query. An empty target set halts; it never selects the DC implicitly.
Domain scope does not authorize IP addresses by DNS inference. DC, KDC, and an
explicit resolver must also be fenced. Every resolved secondary destination is
checked, including SPNs, CA hosts, callback/listener hosts, reauthentication and
relay targets, and host lists extended from configuration. Unresolved local
callback defaults are rejected.

The discovery variant uses an explicit posture-probe allowlist and a second,
deny-by-default tool boundary: reviewed LDAP attributes, SMB metadata, and ACL
reads only. LAPS password reads, credential-store selection (`--as-cred`), signing
key file reads, reveal options, ADCS endpoint discovery, and active coercion scans
are excluded. Unavailable or unverified posture cannot become an eligible hop.

`--execute` always errors with `execution not yet supported (Phase 4b)`, including
when execution authorization flags are supplied. There is no execution loop.

SIGINT, `--kill-file <sentinel>`, `--max-hops`, and `--max-time` are checked before
every candidate expansion and tool launch. The hop budget counts candidate
expansions, including skipped candidates; tool timeouts are capped by the remaining
time budget. A stop preserves the public partial audit.

Each run creates a new `autopwn-<run-id>.jsonl` under `--output`. The first record
contains the resolved fence, including enumerated hosts and bootstrap endpoints.
Public events are appended and flushed during planning. Only fixed outcome codes,
classifications, scope membership, identity principals, technique names, public
destination hosts, and projection booleans are serialized. Raw results, probe
reasons/evidence, credential values, teardown data, and exception text are never
copied into the report, audit, or planner logs.
