## TURN 2 — codex — 26OCT2026

### Q1 — Placement

The aranum adapter should not be added to the in-flight CWP1 patch. Land the first lossless adapter in CWP2 for network, Windows, AD, and domain-posture data, then extend the same adapter’s normalization in CWP5 for Linux posture; retain generic interchange schemas and round-trip work in CWP7/S13. *(inferred)*

This split follows the capability-first rule and the roadmap’s direction that specialist tools remain backends, while CWP2 and CWP5 explicitly own AD/import and Linux-host observations. *(measured; `docs/PURPLESPLOIT_IMPLEMENTATION_ROADMAP-26OCT2026.md:59-65,85-98,128-139` in the current uncommitted tree)*

The current CWP1 patch already contains 1,556 insertions and 282 deletions across three core modules and five tracked test files, plus one untracked contract test; the common execution model remains unfinished. *(measured)* Adding the provenance fields in Q2 completes existing CWP1 scope, but adding an aranum parser, persistence projections, fixtures, and CLI/API entry points would widen CWP1 materially. *(inferred)*

Option D can follow the Option A reader after its CWP2 slice works; credential/evidence hardening must remain in S20–S21 and must not gate that capability. *(inferred; measured against the binding roadmap order at `docs/PURPLESPLOIT_IMPLEMENTATION_ROADMAP-26OCT2026.md:288-292`)*

### Q2 — Provenance in the CWP1 model

No common `ExecutionRequest`, `ExecutionResult`, or `Observation` class exists in the current working tree yet; the roadmap correctly lists that item as still open. *(measured; `docs/PURPLESPLOIT_IMPLEMENTATION_ROADMAP-26OCT2026.md:331-336` in the current uncommitted tree)* The present `EnumResult` has `raw_data`, but it has no `source_tool`, `source_id`, or `source_schema`. *(recorded: `python/purplesploit/core/auto_enum.py:55-69@c962994+CWP1`)*

Adding provenance now is acceptable and preferred. *(inferred)* I would put `source_tool`, `source_id`, `source_schema`, and JSON-compatible `raw` on every `Observation`; put adapter/tool identity, schema, the unmodified result payload, and emitted observations on `ExecutionResult`; and keep `ExecutionRequest` focused on adapter, operation, target, options, and correlation identity. *(inferred)* An import request may identify the source file or bundle, but duplicating each source record’s `source_id` onto the request would create two provenance authorities. *(inferred)*

Import identity should be the tuple `(source_tool, source_schema, source_id)`, for example `("aranum", "aranum.findings/2", "AR-2-…")`, rather than `finding_id` alone. *(inferred)* The raw field should preserve the complete source object, not just the 300-character `line`. *(inferred; recorded: `/srv/share/dev/aranum/aranumtoolkit/network/report.py:372-395@2493def`)*

I disagree with the study’s promise that doing this now guarantees “no later migration.” *(inferred)* It avoids an immediately foreseeable model rewrite, but canonical schema compatibility and authoritative-store migration remain explicitly scheduled for CWP7 and S19. *(measured; `docs/PURPLESPLOIT_IMPLEMENTATION_ROADMAP-26OCT2026.md:154-165,282-289` in the current uncommitted tree)*

Aranum’s ID is deterministic for byte-equivalent normalized input, but it includes the full cleaned-line hash and therefore is content-sensitive across runs. *(recorded: `/srv/share/dev/aranum/aranumtoolkit/network/report.py:372-376,1440-1444@2493def`)* It is suitable for exact re-import idempotency, not a guaranteed durable logical identity when volatile evidence changes. *(inferred)*

### Q3 — Target representation

If an importer had to target an existing class today, it should target `purplesploit.core.findings.Finding`, not `reporting.models.Finding` or the AI-local class. *(inferred)* The core model has protocol, richer evidence, lifecycle metadata, tags, references, ATT&CK mappings, and the existing `FindingsManager`; its reporting counterpart lacks protocol and several lifecycle fields. *(recorded: `python/purplesploit/core/findings.py:83-131@c962994`; `python/purplesploit/reporting/models.py:100-143@c962994`)* The AI-module `Finding` contains only category, title, description, severity, evidence, and remediation and is assessment-planner-local. *(recorded: `python/purplesploit/modules/ai/methodology.py:68-87@c962994`)*

The preferred CWP2 implementation is nevertheless `aranum record → Observation → legacy core Finding projection for FAIL/WARN`, with reports consuming a projection rather than serving as the import authority. *(inferred)*

No consolidation of the finding classes is committed before S13. *(measured)* CWP7 promises a unified finding/observation view for interchange and reports, while one authoritative store and legacy reconciliation remain S19 work. *(measured; `docs/PURPLESPLOIT_IMPLEMENTATION_ROADMAP-26OCT2026.md:154-167,282-289` in the current uncommitted tree)*

### Q4 — Vocabulary

The severity mapping `critical/high/medium/low →` the identically named PurpleSploit severities is accepted. *(recorded: `python/purplesploit/core/findings.py:28-34@c962994`; `/srv/share/dev/aranum/aranumtoolkit/network/report.py:64-75@2493def`)*

For posture, import every host/domain check as an `Observation`; project only canonical FAIL/WARN checks into findings. *(inferred)* Aranum already emits those FAIL/WARN records in `findings.json` with their resolved severity, including its documented fallback, so the importer should treat those records as authoritative and must not create a second finding from `posture.json`. *(recorded: `/srv/share/dev/aranum/aranumtoolkit/network/report.py:2135-2156,2160-2205,2227-2247@2493def`)*

PASS, INFO, and NA remain distinct observations rather than being collapsed into one success value; ERR is a data-quality observation. *(inferred)* Domain roll-ups must preserve each `observed_from` record’s host, status, and detail. *(recorded: `/srv/share/dev/aranum/aranumtoolkit/network/report.py:2208-2245@2493def`)*

Literal `triage_status="new"` maps to `FindingStatus.DRAFT`. *(inferred; recorded: `python/purplesploit/core/findings.py:17-25@c962994`)* Aranum permits run-local metadata to override that value, including `"open"`, so unknown values must remain in raw provenance and must not be silently treated as equivalent to `new`. *(recorded: `/srv/share/dev/aranum/aranumtoolkit/tests/test_structured_findings.py:155-186@2493def`)*

### Q5 — Evidence and KB resolution

For Option D, prefer a self-contained export with inline KB guidance and evidence paths relative to the run root. *(inferred)* Absolute evidence paths are non-portable and expose operator filesystem layout without improving bundle usability. *(inferred)*

The importer should resolve each non-redacted `evidence_paths[]` entry against the selected run root and retain both the source-relative path and resolved local reference. *(inferred)* Aranum deliberately emits run-relative paths. *(recorded: `/srv/share/dev/aranum/aranumtoolkit/network/report.py:2079-2099@2493def`)* Under `--redact`, host identities inside those paths are rewritten while the evidence tree is not renamed, so such paths may be metadata-only and unresolved. *(recorded: `/srv/share/dev/aranum/aranumtoolkit/network/report.py:2864-2896@2493def`)*

Inline KB data avoids enriching an old result with whichever KB happens to be installed later. *(inferred)* The importer should still tolerate a non-inline export by optionally reading the matching `finding-kb.json`; missing KB guidance must not prevent importing the finding and its raw record. *(inferred)* Immutable evidence copies, hashes, manifests, and chain-of-custody work remain deferred to S20. *(measured; `docs/PURPLESPLOIT_IMPLEMENTATION_ROADMAP-26OCT2026.md:288-290` in the current uncommitted tree)*

KB `why`, `fix[]`, `test[]`, and `refs[]` can project to impact, remediation, proof-of-concept, and references, but the object-valued test/fix entries require deterministic rendering rather than direct assignment to string fields. *(recorded: `/srv/share/dev/aranum/aranumtoolkit/network/report.py:244-257@2493def`; `python/purplesploit/core/findings.py:109-117@c962994`)*

### Q6 — Coverage

Do not make the adapter findings-only. *(inferred)* During CWP2/CWP5, upsert the targets and endpoint services represented by `summary.coverage[]`, and retain coverage, posture, and per-host records as source observations. *(inferred)* When CWP6 introduces coverage semantics, project those retained observations into imported coverage. *(inferred; measured against `docs/PURPLESPLOIT_IMPLEMENTATION_ROADMAP-26OCT2026.md:141-150` in the current uncommitted tree)*

`summary.coverage[]`, not `per_host`, is the endpoint-level assessment source: it contains host, port, protocol, service, status, and reason. *(recorded: `/srv/share/dev/aranum/aranumtoolkit/network/report.py:1706-1808@2493def`)* `per_host` is an aggregate worst-severity/count/OS roll-up and should become a target-level observation, not create service rows or claim assessment completion. *(recorded: `/srv/share/dev/aranum/aranumtoolkit/network/report.py:2330-2361@2493def`)*

“Imported” should describe coverage provenance while preserving the source outcome—confirmed, assessed-clean, failed, skipped, or unassessed—rather than replacing that outcome. *(inferred)* Current PurpleSploit service stores omit protocol, although the CWP1 in-memory endpoint records retain it, so protocol must remain in the observation/raw payload until the later data model can represent it. *(recorded: `python/purplesploit/core/database.py:169-179@c962994`; measured: `python/purplesploit/core/auto_enum.py:274-280,801-810` in CWP1 working tree)*

### Q7 — M1–M7 and mapping audit

The PurpleSploit baseline is still `c9629949033c`; the inspected state includes the uncommitted CWP1 diff. *(measured)* Aranum is currently on `52f2fc0`, but every change after the study’s `2493def` baseline is documentation/test-evidence only, so the relevant aranum source remains unchanged. *(measured)*

| Probe | Verdict |
|---|---|
| **M1** | Confirmed: replaying a valid v2-shaped finding through `ReportGenerator.load_findings_from_json` raises `TypeError: Finding.__init__() got an unexpected keyword argument 'host'`. *(measured)* The loader passes each `findings[]` object directly to the reporting dataclass. *(recorded: `python/purplesploit/reporting/generator.py:236-248@c962994`)* |
| **M2** | Confirmed: `FindingsManager.import_json` iterates the top-level object’s string keys and raises `AttributeError: 'str' object has no attribute 'get'`. *(measured)* It accepts only a bare list shaped like its own export. *(recorded: `python/purplesploit/core/findings.py:520-540@c962994`)* |
| **M3** | Confirmed, with one nuance: SARIF uses service as `ruleId`, has an empty `rules[]`, points `locations` at local evidence, omits category/KB/confidence, and uses findings schema version `"2"` as the tool version. *(recorded: `/srv/share/dev/aranum/aranumtoolkit/network/report.py:2663-2696@2493def`)* Host and port are not wholly dropped—they survive in result `properties`—but no host logical location exists. *(recorded: `/srv/share/dev/aranum/aranumtoolkit/network/report.py:2681-2685@2493def`)* |
| **M4** | Confirmed: there is no `aranum` or SARIF reference in current PurpleSploit Python source. *(measured)* |
| **M5** | Confirmed: no JSON Schema for `findings.json` v2 or `posture.json` v1 exists in the current aranum tree. *(measured)* |
| **M6** | Confirmed with scope clarification: all 199 ordinary KB classes have exactly `category,title,why,test,fix,refs`, and neither classes nor checks have structured CWE/ATT&CK fields. *(measured)* The KB contains 105 ATT&CK URLs in `refs`, while its 99 posture checks additionally carry scope, OS, semantics, and severity fields. *(measured)* |
| **M7** | Confirmed: API and dashboard defaults bind to `127.0.0.1`, and `api/server.py` contains no `shell=True`. *(measured; recorded: `python/purplesploit/api/server.py:1474-1479@c962994`; `python/purplesploit/web/dashboard.py:255@c962994`)* |

The mapping table is directionally sound but needs these corrections before implementation. *(inferred)*

- `host → target`, port normalization, protocol/service, severity, title, evidence attachment, and literal `new → DRAFT` all fit the core model. *(recorded: `python/purplesploit/core/findings.py:84-131@c962994`)* Empty aranum ports should become `None`. *(inferred)*

- `line` is a truncated synopsis, not full raw output; map it to description and preserve the complete source object in `Observation.raw`. *(recorded: `/srv/share/dev/aranum/aranumtoolkit/network/report.py:372-395@2493def`; inferred)*

- ATT&CK sub-techniques cannot be extracted correctly with only `T\d{4}(\.\d{3})?`, because aranum URLs encode them as `/techniques/T1558/003/`; the importer must normalize that path to `T1558.003`. *(measured; recorded example: `/srv/share/dev/aranum/aranumtoolkit/network/finding-kb.json:105@2493def`)*

- `rule_id`, `kb_id`, `category`, confidence, priority, scope, attribution, tags, and next actions should remain typed/raw observation fields first; projecting some of them into core tags/notes is necessarily lossy. *(inferred; recorded: `python/purplesploit/core/findings.py:127-131@c962994`)*

- FAIL/WARN posture findings must be imported from `findings.json` once, while `posture.json` supplies the complete observation set; independently converting both inputs would duplicate them. *(inferred; recorded: `/srv/share/dev/aranum/aranumtoolkit/network/report.py:2160-2205,2820-2841,2898-2910@2493def`)*

- `summary.coverage[]` can seed target/service inventory, but `per_host` cannot; it is only a roll-up. *(recorded: `/srv/share/dev/aranum/aranumtoolkit/network/report.py:1706-1808,2330-2361@2493def`)*

- The proposed mapping omits top-level `partial/errors`, `posture_quarantine`, redaction state, generation metadata, and posture conflict details; these should become data-quality/run observations and remain in raw provenance. *(recorded: `/srv/share/dev/aranum/aranumtoolkit/network/report.py:2820-2907@2493def`; inferred)*

Therefore I agree with Option A as the lossless seam, disagree that the current mapping is complete, and recommend the CWP2/CWP5 staged adapter with generic interchange work retained in CWP7. *(inferred)*