# Interop study — aranum ↔ PurpleSploit

**Date:** 26 October 2026
**Baselines:** PurpleSploit `main` @ `c962994` (plus the uncommitted CWP1 working tree);
aranum `main` @ `2493def` (v0.34.0, PLAN-001 S1–S4 merged).
**Status:** Study only, no code changed in either repo. The conversation with codex happens in
`../../interop-channel`.
**Provenance labels:** `measured` (ran it), `recorded` (read in code or docs at the cited SHA),
`inferred` (reasoned).

## 1. What each tool is (and should stay)

| | aranum | PurpleSploit |
|---|---|---|
| Role | Headless, breadth-first **enumeration producer**: nmap-driven per-service dispatchers, Windows/Linux host-posture collectors, `--local` access layer (winrm/ssh/exec), AD posture | Operator **console and consumer**: REPL, module registry, context DB, impacket/netexec wrappers, findings lifecycle (CVSS, ATT&CK), reporting, API/web |
| Languages | Bash + stdlib Python + PowerShell | Python package (SQLAlchemy, FastAPI, Rich) |
| Hard rules | `CLAUDE.md` §9: no target write without explicit flag, no exfil/phone-home, output only to the operator path, no persistence, no evasion | Capability-first roadmap (26OCT2026); safety/integrity deferred to S19–S23 |
| Output contract | `findings.json` v2, `posture.json` v1, optional `findings.sarif`, `report.md/html`, dashboard | `Finding` dataclasses (×2: `core/findings.py`, `reporting/models.py`), SQLite context DB |
| License | CC-BY-NC-SA 4.0 | CC-BY-NC-SA 4.0 (`recorded`, memory 30JUL2026) |

PurpleSploit's own roadmap rule 5 settles the shape: *"Specialist tools remain backends.
PurpleSploit adds orchestration, normalization, correlation, and user workflow."* aranum is a
specialist backend, so interop goes through **a file contract plus an adapter**, not a code merge.

## 2. Measured state of the seam today

| # | Probe | Result | Provenance |
|---|---|---|---|
| M1 | `ReportGenerator.load_findings_from_json(<aranum findings.json v2>)` | `TypeError: Finding.__init__() got an unexpected keyword argument 'host'` | measured |
| M2 | `FindingsManager.import_json(<aranum findings.json v2>)` | `AttributeError: 'str' object has no attribute 'get'`: it iterates the top-level dict's keys (it expects a bare list) | measured |
| M3 | aranum `findings.sarif` (`report.py:_to_sarif`, line 2667) | Lossy: `ruleId` = **service name**, not `rule_id`; `tool.driver.rules` = `[]`; the location is the operator-local evidence file path, not host:port; `category`/`kb_id`/`confidence` dropped; `version` = findings schema "2", not the tool version | recorded |
| M4 | Any `aranum`/`sarif` reference in PurpleSploit source | none | measured (grep) |
| M5 | Machine-readable schema for `findings.json`/`posture.json` | none (no JSON Schema file in aranum) | measured (find) |
| M6 | aranum KB (`finding-kb.json`) structured ATT&CK/CWE fields | none; the KB class keys are `category,title,why,test,fix,refs`. ATT&CK appears only inside `refs` URLs | measured |
| M7 | July blockers: API/dashboard bound to 0.0.0.0, `shell=True` in `api/server.py` | now `127.0.0.1` (`api/server.py:1474`, `web/dashboard.py:255`), no `shell=True` in `server.py`. The July memory is stale on these | measured |

**Conclusion:** today there is **no working path**. Neither PurpleSploit loader accepts aranum
output, and the only standard format aranum emits (SARIF) discards the rule identity that
aranum's S1 sprint spent effort making correct.

## 3. Field mapping: aranum → PurpleSploit `Finding` (`core/findings.py`)

| aranum (`findings.json` v2) | PurpleSploit | Note |
|---|---|---|
| `finding_id` (`AR-2-<sha1:14>`, deterministic) | **no slot**; `id` is a random `uuid4()[:8]` | Needs `source_tool` + `source_id` (CWP7 "preserve source IDs"). Without it, re-import duplicates every finding |
| `host` | `target` | |
| `port` (string) / `protocol` / `service` | `port` (int) / `protocol` / `service` | `""` port is legal in aranum (host/domain/run scope) → `None` |
| `severity` ∈ critical/high/medium/low | `Severity` (+`info`) | aranum has no `info`. Posture `INFO`/`PASS` are observations, not findings |
| `title` | `title` | |
| `line` (≤300 chars) | `description` / `raw_output` | |
| `evidence_paths[]` (relative to the aranum run root) | `Evidence(file_path=…)` | The importer must resolve the paths against the run root. Under `--redact` the paths are redacted |
| `rule_id`, `kb_id`, `category` | `tags` (+ future `category`) | |
| KB `why` / `fix[]` / `test[]` / `refs[]` (joined on `kb_id`) | `impact` / `remediation` / `proof_of_concept` / `references` | The KB ships inside aranum. The importer either reads it or aranum inlines it (see §5) |
| ATT&CK IDs in KB `refs` URLs | `mitre_techniques` | Extract `T\d{4}(\.\d{3})?` from `attack.mitre.org` URLs |
| `confidence`, `priority`, `tags`, `next_actions` | `tags` / `notes` | |
| `triage_status` ("new") | `status` = `DRAFT` | |
| `scope`/`attribution` (host/endpoint/domain/run, incl. the `(dispatcher)` fix) | `tags` | Keeps S1's false-positive discipline visible downstream |
| `summary.coverage[]`, `per_host` verdicts | `Target`/`Service` rows + CWP6 "imported" coverage state | These are **observations**, not findings |
| `posture.json` `hosts[h].checks[id] = {status, detail}` + KB `checks` (99) | FAIL/WARN → `Finding` (KB `sev_fail`/`sev_warn`). PASS/NA/INFO → Observation. ERR → data-quality observation | |
| `posture.json` `domains` roll-up (`observed_from[]`) | AD observations (CWP2) | |

## 4. Options weighed

| Option | For | Against | Verdict |
|---|---|---|---|
| **A. File contract + PurpleSploit adapter** (`aranum` importer reads `findings.json` v2 + `posture.json` v1 + KB) | Lossless. Each tool keeps its cadence and its §9/roadmap rules. Matches roadmap rule 5. Cheap | Two consumers of one schema, so a published schema is needed | **Recommended** |
| B. SARIF-only (generic CWP7 SARIF importer) | Zero aranum-specific code in PurpleSploit | Lossy today (M3). Even a fixed SARIF can't carry posture or coverage | Fallback path. Fix aranum's SARIF anyway (cheap, helps DefectDojo/GitHub too) |
| C. Code-level merge (vendor aranum into PurpleSploit) | License allows it | aranum is mostly Bash/PS with hard OPSEC invariants. It would double PurpleSploit's parallel implementations (the review already counts 3 state stores and 4 Finding representations) | Rejected |
| D. PurpleSploit wraps aranum as a backend module (`recon/aranum` runs `aranum.py run`/`local -o <dir>`, then auto-imports via A) | One-command operator flow. Fits "specialist tools remain backends" | Depends on A existing. Credential hand-off via argv is a deferred (S20/S21) hardening item | **Phase 2, after A** |
| E. Reverse feed (PurpleSploit nmap XML/targets/creds → aranum) | `auto-enum.sh -i scan.xml` and `local-enum.py --targets/--from-inventory` already accept these | Credentials cross a process boundary | Works at file level today. Document it, add nothing |

## 5. Recommended contract work

**aranum side (aranum owns; small):**
1. Fix SARIF: `ruleId` = `rule_id`; populate `tool.driver.rules[]` from the KB (`shortDescription`=title,
   `help`=fix); `properties` carry `category`, `kb_id`, `confidence`, `scope`; a `logicalLocations`
   entry for `host:port`; `tool.driver.version` = the real tool version.
2. Publish JSON Schemas for `findings.json` v2 and `posture.json` v1, with a fixture, and gate them with a test.
3. Optional: `--inline-kb` so `findings.json` is self-contained, letting the importer skip reading aranum's KB.

**PurpleSploit side (codex owns; slots into the existing roadmap):**
1. CWP1 `Observation`/`ExecutionResult`: include `source_tool`, `source_id`, `source_schema`, and a
   `raw` payload **now**, so no imported source needs a migration later.
2. An `aranum` importer (CWP7/S13, or pulled forward as a CWP2/CWP5 capability. It delivers AD and
   Linux/Windows host-posture observations without new adapters). Idempotent on `finding_id`.
3. Then Option D: a backend module that runs aranum into an operator directory and imports the result.

## 6. Open questions (posed in `interop-channel`)

See the channel file. The questions cover roadmap placement, `Observation` provenance fields,
severity/status vocabulary, where evidence and KB resolution belong, and which Finding
representation the importer targets.

## 7. Errata (from codex TURN 2, 26OCT2026; accepted)

- M3 nuance: host and port do survive in SARIF result `properties`. What is missing is a host *logical location*.
- M6: the KB holds 105 ATT&CK URLs in `refs`. Sub-techniques are encoded as `/techniques/T1558/003/`, so the
  extractor must normalize the path to `T1558.003`. The `T\d{4}(\.\d{3})?` pattern in §3 is wrong.
- §3 `line` is a ≤300-char synopsis → `description`. The **complete source object** goes to `Observation.raw`.
- FAIL/WARN posture findings already appear in `findings.json`. Import them from there **once**;
  `posture.json` supplies observations only. Converting both would duplicate findings.
- `per_host` is a roll-up (target-level observation). Only `summary.coverage[]` seeds service rows.
- Missing from §3: `partial`/`errors`, `posture_quarantine`, redaction state, generation metadata, and
  posture conflict details. These become data-quality/run observations.
- §5 overclaimed "no later migration". Adding provenance now avoids a foreseeable rewrite; the canonical
  schema and authoritative-store migration still happen in CWP7/S19.
- Import identity is `(source_tool, source_schema, source_id)`. aranum's `finding_id` hashes the cleaned line, so it is
  idempotent for exact re-imports, not a durable logical identity across runs.
- Placement: the first adapter goes in **CWP2** (network/Windows/AD/domain posture), is extended in **CWP5** (Linux
  posture), and generic interchange stays in CWP7/S13. It is not part of the in-flight CWP1 patch; only the provenance
  fields are.

## 8. Integration scope (TURN 3–5, 26OCT2026)

Owner direction: make PurpleSploit "the best it possibly can be" by integrating aranum as its enumeration engine.

- **Coverage (codex Q8, file-referenced matrix in `interop-channel` TURN 4):** of 76 aranum dispatcher paths
  (74 scripts + 2 aliases), PurpleSploit fully covers 1 (Kerberos), overlaps 9 (8 services: SMB, LDAP, WinRM, RDP, SSH,
  MSSQL, DNS, HTTP/S), partially covers 52, and lacks 14 (e.g. FTP, Kafka, MQTT, XMPP, ZooKeeper, rsync, print,
  RADIUS, NetBIOS-NS).
- **Shape:** one `recon/aranum` module with 74 registered operations, and auto-enum coalescing into one aranum run.
  Aranum owns the baseline enumeration recipes; PurpleSploit owns orchestration, storage, correlation, reporting,
  and explicit specialist actions.
- **aranum-side items surfaced by the integration review:**
  - AR-I1: MSSQL `--xp_cmdshell` runs by default whenever credentials are supplied (possible §9.1 config write, unverified).
  - AR-I2: RDP screenshot by default whenever credentials are supplied.
  - AR-I3: `aranum.py run` writes `outputs/<session>` inside the aranum repo even when `-o` is given (§9.3).
- **Acceptance:** codex's 13-metric set (registry completeness, inventory/finding/observation fidelity, provenance,
  KB enrichment, exact re-import = 0 new records, partial/error visibility, offline portability, invocation
  discipline, report rendering), measured on three fixture-only bundles.

**Owner ruling 26OCT2026:** AR-I1/AR-I2/AR-I3 are *not* problems. They are intended aranum behavior, and the items are withdrawn. Option D may use `aranum.py run` as-is.

## 9. Account/identity model + standing deferral (TURN 7, owner 26OCT2026)

- **Fuller account model, riding along with the CWP1 provenance fields.** Authoritative, not inferred:
  - credential record gains `scope` ∈ local|domain|machine, `domain` (domain/machine), `local_host` (local);
  - `recon/aranum` maps scope → invocation (domain `-d`; local nxc `--local-auth`; machine `account$`);
  - every finding/observation carries the proving `auth_context` {account_ref, scope, domain|local_host, auth_method};
  - reuse/graph records (local-credential reuse across hosts = a finding; domain effective-on-host; machine
    accounts distinct) derive in CWP2, but the carrying fields land with CWP1 so no later migration.
- **Standing deferral (owner, binding):** intended tool behavior and its side-effects are not defects and are not
  raised — AR-I1/I2/I3 and anything like them (enabling a setting to run a check, writing logs/artifacts, footprint,
  evidence persistence). Interop work answers functionality/efficiency/capability only. See
  [[tool-security-out-of-scope]].
