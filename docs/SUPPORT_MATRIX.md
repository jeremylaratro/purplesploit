# Version 7 support matrix

| Area | Supported claim | Certification evidence |
|---|---|---|
| Python | CPython 3.10–3.13 on Linux | CI matrix and package build |
| Storage | Canonical SQLite schema v2, backup/restore, audit chain | S19/S20 unit tests and `scripts/recovery_rehearsal.py` |
| Service | Authenticated local/operator-controlled FastAPI service | S21–S23 API security tests |
| Execution | Explicit requests with engagement scope, ROE, risk, rate, concurrency and time controls | Policy and dispatch tests |
| Agents | Pre-provisioned HMAC identities, capability scope, leases, replay rejection, artifact SHA-256 | Distributed protocol/security tests |
| Plugins | Signed Ed25519 packages, declared permissions, isolated-process execution | Plugin lifecycle/security tests |
| AI | Local advice or consented OpenAI/Anthropic provider drafts | Offline provider contract tests; no execution path |
| Interop | Canonical JSON/CSV, SARIF, DefectDojo, ATT&CK Navigator/STIX/graph CSV plus documented importers | Golden round-trip suites |
| Reports | JSON, Markdown, HTML, XLSX and optional WeasyPrint PDF | Reporting tests; formula/link neutralization |

Nmap, NetExec, Impacket, Kerbrute, Nuclei, Feroxbuster, HTTPX, SQLMap, WPScan,
WFuzz and deployment helpers are external executables. PurpleSploit certifies command
construction, structured result handling, and synthetic parsing; the upstream tools,
target compatibility, and live exploit outcomes are not product guarantees. Operators
must validate selected versions in an owned lab before an engagement.

The in-process job queue and coordinator are single-node facilities. High-availability,
multi-tenant hosting, hostile-plugin OS sandboxing, Windows service hosting, and macOS
service hosting are not supported claims for 7.0.0.
