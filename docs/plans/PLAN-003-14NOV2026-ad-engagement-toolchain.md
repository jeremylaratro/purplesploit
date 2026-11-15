# PLAN-003 — AD engagement toolchain qualification and delivery plan

**Date:** 14NOV2026  
**Status:** PLAN r3 — owner directive incorporated, 14NOV2026; P0-S0 toolkit half DONE, provisioner half BLOCKED; P0-S1 BLOCKED on SP0-01 prerequisites
**Plan host:** PurpleSploit, because it owns cross-repository integration. `[recorded: owner brief, 14NOV2026]`

## Revision r3 (14NOV2026)

- Added C7 with the verbatim owner directive: no ShadowHex dependency and no LLM in any engagement, lab or analysis step; all analysis, ranking and reporting use deterministic code. `[recorded: owner directive, 14NOV2026]`
- Reassigned every active harness owner, component, command, schema, fixture, profile, truth file, record, measurement directory and rollback to the dedicated `ad-lab-harness`; retained branch names. Recorded root `782b499`, local-only state, stdlib runtime, pytest, tri-state exits and read-only libvirt allowlist. Its own full suite is the regression manifest; there is no inherited regression surface. `[measured: git -C /srv/share/dev/ad-lab-harness log --oneline --all; git -C /srv/share/dev/ad-lab-harness remote -v]` `[recorded: /srv/share/dev/ad-lab-harness/CLAUDE.md]`
- Withdrew G6-04/P6-S3 and roadmap P6-06 under C7, retaining identifiers and removing controller evaluation from active dependencies; there is no LLM controller. `[recorded: owner directive, 14NOV2026]`
- Classified all seven `purplesploit/ai/` files and `modules/ai/ai_automation.py` from code under C7, permitted inert provider-disabled startup while prohibiting LLM-reaching entrypoints, and required all planned commands to work without `openai`/`anthropic`. Added one SDK-absence test-plan row to P0-S3 and made P3-S2's deterministic ranking method explicit. `[verified: python/purplesploit/ai]` `[verified: python/purplesploit/modules/ai/ai_automation.py]` `[inferred]`
- Recorded P0-S0 toolkit completion, byte fidelity and Sol review disposition; the provisioner permission block; SP0-01 implementation, Astra review fixes, unchanged-logic port and inconclusive dry run; and the resulting P0-S1 prerequisite block. Preserved initial baselines as dated starting snapshots alongside current status. `[recorded: 28julytoolkit/docs/test-strategy/PLAN003-P0-S0-TEST-CARD-14NOV2026.md]` `[recorded: ad-lab-harness/docs/records/PLAN003-SP0-01-TEST-CARD-2026-11-14.md]` `[measured: git -C /srv/share/dev/28julytoolkit rev-parse HEAD plan003-p0-source-base^{commit}, 14NOV2026]`
- Marked retained historical evidence read-only in §3.1 and prepended owner-directive errata to the assessment without rewriting its body. Other gates, tests, denominators and baseline values remain intact. `[recorded: owner directive, 14NOV2026]` `[inferred]`
- Reconciled SP0-01 recovery: `fail` requires the owner to name another host; `inconclusive` requires fixing the prerequisite or harness cause and rerunning once, then the owner names another host if still inconclusive. P0-S1 stays blocked until a `pass`; the pre-install dry run is a precondition check and does not consume the single rerun. `[recorded: owner decision C6]` `[recorded: ad-lab-harness/docs/plans/PLAN003-SP0-01-PROVIDER-COEXISTENCE-2026-11-14.md]` `[inferred]`

## Effort objective

From a fresh offline attack box, run the automated chain—no-credentials enumeration → low-privilege enumeration → BloodHound collection/ingest/path analysis → local access → local checks → report—against qualified lab profiles with measured coverage and no silent gaps. `[recorded: owner brief, 14NOV2026]`

Phase 0 delivers the full upstream GOAD first gate, truth model, versioned inputs, reproducible attack box, offline release, and interoperability gates needed to make the full objective measurable. `[inferred]`

The security and integrity of the project’s own tooling—including hardening, authentication, secret handling, compliance, threat modelling, supply-chain controls, and tamper resistance—remain outside this plan. `[recorded: standing owner directive, 14NOV2026]`

### Evidence convention

- `[verified: path]` — inspected on disk.
- `[measured: command]` — obtained through a read-only inspection command.
- `[recorded: doc]` — stated in an owner decision, existing record, or cited primary document.
- `[inferred]` — recommendation, calculation, proposed design, or conclusion from evidence.
- `[upstream knowledge, unverified]` — not established from the on-disk sources; a dependent implementation must receive a time-boxed verification or decision record. `[recorded: owner brief, 14NOV2026]`

No builds, installers, VMs, or test suites were run while preparing this document revision; execution results below are carried forward from cited records. `[recorded: owner brief, 14NOV2026]`

## Owner decisions and constraints

| ID | Constraint |
|---|---|
| C1 | The first gate is the full upstream `ad/GOAD` lab: five VMs, two forests, three domains, an external trust, and AD CS. Later profiles provide deeper or additional coverage such as SCCM, NHA, a workstation, or a custom extra forest/CA. No smaller GOAD-family profile may substitute for the first gate. `[recorded: owner decision, 14NOV2026]` `[verified: upstream/GOAD/ad/GOAD/data/config.json]` `[verified: upstream/GOAD/ad/GOAD/data/inventory]` |
| C2 | The attack box is Linux, Kali or Debian, and must function fully offline after deployment. The planning host and bundle builder may use the internet. `[recorded: owner brief, 14NOV2026]` |
| C3 | Writable-path checks use ACL/effective-rights evaluation by default. Any target-side file creation requires explicit `--write` mode. `[recorded: owner brief, 14NOV2026]` |
| C4 | Lockout and traffic budgets remain unset. Configuration fields remain present but null; this plan does not invent operational values. `[recorded: owner brief, 14NOV2026]` |
| C5 | The supported team size is one through five concurrent operators. `[recorded: owner brief, 14NOV2026]` |
| C6 | The lab runs on net0srv using VirtualBox and Vagrant. SP0-01 is a one-day predecessor go/no-go gate proving that VirtualBox can operate beside the running KVM/libvirt VMs. If SP0-01 fails, P0-S1 is `blocked` until the owner names another host; this plan defines no alternate provider or host. `[recorded: owner decision, 14NOV2026]` |
| C7 | Owner directive (14NOV2026), verbatim: "Don't use ShadowHex here, we won't have any LLM". No LLM in any engagement, lab or analysis step; no dependency on, invocation of, writes to, or qualification by ShadowHex. Every analysis, ranking and reporting step uses deterministic code. The independent lab-truth and qualification authority is the dedicated LLM-free `ad-lab-harness`. Inert startup is permitted: `PURPLESPLOIT_AI_PROVIDER` must be unset, so `provider_from_environment()` returns `None` and `AdvisoryService` is constructed with provider `None`. No PLAN-003 sprint may invoke `AdvisoryProvider.generate`, `AdvisoryService` analysis/workflow-draft entrypoints (`analyze`, `propose_workflow`), or `purplesploit.modules.ai.ai_automation` operations, including local fallback entrypoints. The offline attack box must not need their SDKs (`openai`, `anthropic`) for any planned command. This requires no PurpleSploit code change. `[verified: python/purplesploit/ui/console.py:43]` `[verified: python/purplesploit/services/application.py:169]` `[verified: python/purplesploit/ai/providers.py:12]` `[inferred]` `[recorded: owner directive and harness choice, 14NOV2026]` `[recorded: /srv/share/dev/ad-lab-harness/CLAUDE.md]` |

### C7 code classification (read-only)

Classification concerns callable behavior, including indirect provider calls; an `ai/` directory name alone does not imply a provider. Definitions imported by the package initializer do not call a provider or load either SDK. Console startup calls `provider_from_environment()` and constructs `AdvisoryService`; with `PURPLESPLOIT_AI_PROVIDER` unset, the provider is `None` and this inert construction is permitted. Deterministic helpers remain eligible through direct deterministic entrypoints; `AdvisoryProvider.generate`, `AdvisoryService.analyze`/`propose_workflow` and `ai_automation` operations remain prohibited, including local fallbacks. `[verified: python/purplesploit/ui/console.py:43]` `[verified: python/purplesploit/services/application.py:169]` `[verified: python/purplesploit/ai/providers.py:12]` `[verified: python/purplesploit/ai/__init__.py:8]` `[verified: python/purplesploit/ai/providers.py:31]` `[inferred]`

| Module (relative to `python/purplesploit/`) | Calls LLM? (C7 classification) | Code evidence and PLAN-003 disposition |
|---|---|---|
| `ai/providers.py` | Yes, directly | SDK imports at 37/40; `client.responses.create` at 56 and `client.messages.create` at 63. `AdvisoryProvider.generate` is excluded; the provider-disabled startup call to `provider_from_environment()` is permitted under C7. `[verified: python/purplesploit/ai/providers.py:37]` `[verified: python/purplesploit/ai/providers.py:56]` `[verified: python/purplesploit/ai/providers.py:63]` |
| `ai/advisory.py` | Yes, indirectly when configured | `self.provider.generate` at 146; analysis/workflow branches call it at 184/203. Local recommendation branch at 171 is deterministic, but `analyze`/`propose_workflow` remain excluded by C7; inert construction with provider `None` is permitted. `[verified: python/purplesploit/ai/advisory.py:146]` `[verified: python/purplesploit/ai/advisory.py:171]` `[verified: python/purplesploit/ai/advisory.py:203]` |
| `modules/ai/ai_automation.py` | Yes, directly and indirectly | SDK imports at 185/188; direct provider calls at 242/249; advisory entrypoints at 314/327 construct a provider at 336. Local suggestion at 365 is deterministic, but this module's operations are excluded. `[verified: python/purplesploit/modules/ai/ai_automation.py:185]` `[verified: python/purplesploit/modules/ai/ai_automation.py:242]` `[verified: python/purplesploit/modules/ai/ai_automation.py:314]` `[verified: python/purplesploit/modules/ai/ai_automation.py:336]` `[verified: python/purplesploit/modules/ai/ai_automation.py:365]` |
| `ai/recommender.py` | No; deterministic rules | Static service map at 51, prerequisite filtering at 395, priority/confidence sort at 419 and arithmetic confidence at 571. `[verified: python/purplesploit/ai/recommender.py:51]` `[verified: python/purplesploit/ai/recommender.py:395]` `[verified: python/purplesploit/ai/recommender.py:419]` `[verified: python/purplesploit/ai/recommender.py:571]` |
| `ai/attack_paths.py` | No; deterministic templates | Probability product at 66; fixed-template evaluation and sorting at 345/351; text report at 472. These generic templates do not replace authoritative BloodHound AD semantics. `[verified: python/purplesploit/ai/attack_paths.py:66]` `[verified: python/purplesploit/ai/attack_paths.py:345]` `[verified: python/purplesploit/ai/attack_paths.py:472]` `[inferred]` |
| `ai/nlp.py` | No; deterministic regex/templates | Intent matching uses `re.search` at 156; response handler dispatch at 120; direct deterministic recommender/path helpers at 231/554. `[verified: python/purplesploit/ai/nlp.py:120]` `[verified: python/purplesploit/ai/nlp.py:156]` `[verified: python/purplesploit/ai/nlp.py:231]` `[verified: python/purplesploit/ai/nlp.py:554]` |
| `ai/inventory.py` | No; deterministic introspection | Instantiates/imports module definitions at 19/21, reads metadata at 29, resolves operations at 37; does not run operations. Behavior still depends on the inspected module's constructor. `[verified: python/purplesploit/ai/inventory.py:19]` `[verified: python/purplesploit/ai/inventory.py:29]` `[verified: python/purplesploit/ai/inventory.py:37]` |
| `ai/__init__.py` | No call; mixed re-exports | Imports deterministic helpers at 8–10 and provider/advisory definitions at 11–12; imports alone do not load the lazy SDKs or invoke the exported services. Use deterministic helper entrypoints and the inert startup permitted by C7 only. `[verified: python/purplesploit/ai/__init__.py:8]` `[verified: python/purplesploit/ai/__init__.py:11]` `[verified: python/purplesploit/ai/providers.py:31]` |

## Repository bases

| Repository/input | Base | State |
|---|---|---|
| PurpleSploit | `918d73c` on `main`, matching `origin/main`. `[recorded: owner brief, 14NOV2026]` | Phase 0 integration consumer and plan host. `[inferred]` |
| Aranum | `550f1cd` on `main`, matching `origin/main`. `[recorded: owner brief, 14NOV2026]` | Enumeration and local-check producer. `[inferred]` |
| `ad-lab-harness` | Root `782b499`; local-only, no remote. `[measured: git -C /srv/share/dev/ad-lab-harness log --oneline --all; git -C /srv/share/dev/ad-lab-harness remote -v]` | Independent lab truth and qualification harness, LLM-free under C7; `adlab/`, stdlib-only runtime, pytest tests, tri-state verdicts (exits 0/1/2) and read-only libvirt allowlist. `[recorded: /srv/share/dev/ad-lab-harness/CLAUDE.md]` |
| GOAD reference clone | `74af01e`, commit date 2026-10-24. `[measured: git -C upstream/GOAD show -s --format='%H %cI %s']` | Immutable upstream lab input. `[inferred]` |
| `pt_provision` | No base SHA; `master` has zero commits. `[measured: git -c safe.directory=/srv/share/dev/pt_provision -C /srv/share/dev/pt_provision rev-parse --verify HEAD]` | Eight intended untracked top-level source entries are visible, including `AGENTS.md`; generated bundle files are ignored. `[measured: P0-S0 top-level inventory command]` |
| `28julytoolkit` | Byte-faithful root `195acd2`, tagged `plan003-p0-source-base`; `main` at `2f0dede`. `[measured: git -C /srv/share/dev/28julytoolkit rev-parse HEAD plan003-p0-source-base^{commit}, 14NOV2026]` | P0-S0 toolkit half DONE 14NOV2026; initial 11-entry inventory retained in §4.1. `[recorded: 28julytoolkit/docs/test-strategy/PLAN003-P0-S0-TEST-CARD-14NOV2026.md]` |

Every sprint records its actual execution-start SHA. `ad-lab-harness` must not assume root `782b499` remains current. `[inferred]`

---

# 1. Triage

## 1.1 Scoring rule

Relevance measures movement toward the effort objective: `5` means wrong results, data loss, a blocked end-to-end path, or inability to establish that a path completed; `1` means little current objective impact. Complexity combines effort, blast radius, and uncertainty: `1` is narrow and known; `5` is architecture-level or live-environment dependent. `[recorded: owner brief, 14NOV2026]`

Priority is derived without manual adjustment:

- `P0`: relevance 5, regardless of complexity.
- `P1`: relevance 4, or relevance 3 with complexity 1–2.
- `P2`: relevance 3 with complexity 3–5, or relevance 2 with complexity 1–3.
- `P3`: relevance 1, or relevance 2 with complexity 4–5. `[inferred]`

There are no manual tier adjustments. `[inferred]`

## 1.2 Gap triage table

| ID | Gap | R | C | Tier | Lane | Basis |
|---|---|---:|---:|---|---|---|
| G0-01 | No qualified Windows domain lab with seeded truth. `[verified: /srv/share/dev/ShadowHex/docs/EXPANDED-AD-LINUX-APPLICATION-GATE-2026-11-02.md]` | 5 | 5 | P0 | now | Without truth, transport, graph, and collector results cannot be measured. `[inferred]` |
| G0-02 | Attack-box definition omits the native AD stack and BloodHound CE service. `[verified: /srv/share/dev/pt_provision/config/repositories.tsv]` | 5 | 4 | P0 | now | A fresh box cannot run the required chain. `[inferred]` |
| G0-03 | Existing offline bundle predates the October integration. `[verified: /srv/share/dev/pt_provision/pt-offline-bundle-20260915T023140Z.tar.gz.enc]` | 5 | 2 | P0 | now | The deployable artifact cannot represent the current chain. `[inferred]` |
| G0-04 | Repository inputs follow remote HEAD rather than a declared lock. `[verified: /srv/share/dev/pt_provision/deploy.sh]` | 5 | 3 | P0 | now | Equivalent build requests can resolve different inputs. `[inferred]` |
| G0-05 | At the initial r2 baseline, `pt_provision` and `28julytoolkit` had no commits or base SHAs; toolkit half now DONE, provisioner half BLOCKED (§4.1). `[measured: repository-base commands]` | 5 | 2 | P0 | now | No dependent sprint can state a source baseline until versioned roots exist. `[inferred]` |
| G1-01 | Discovery and Aranum enumeration remain separate workflows. `[verified: /srv/share/dev/aranum/aranumtoolkit/network/auto-enum.sh]` | 5 | 3 | P0 | now | This blocks the production one-run chain. `[inferred]` |
| G1-02 | Unauthenticated AD coverage is not truth-measured or scale-qualified. `[verified: /srv/share/dev/aranum/aranumtoolkit/network/enum-smb.sh]` | 5 | 4 | P0 | now | Missing DCs or signals could remain silent. `[inferred]` |
| G1-03 | Retry/resume and attempted-versus-absent accounting are not proven at scale. `[verified: /srv/share/dev/aranum/aranumtoolkit/schemas/run-state-1.schema.json]` | 5 | 4 | P0 | now | A partial run could be mistaken for complete coverage. `[inferred]` |
| G2-01 | Authenticated directory inventory lacks a truth-tested completeness contract. `[verified: /srv/share/dev/aranum/aranumtoolkit/network/enum-ldap.sh]` | 5 | 4 | P0 | now | Objects or relationship classes can be silently omitted. `[inferred]` |
| G2-02 | Lockout scheduling requires policy and ROE values not supplied under C4. `[verified: /srv/share/dev/aranum/standalones/creds/spray-scheduler.py]` `[recorded: owner decision C4]` | 4 | 2 | P1 | later | Preserve null configuration slots; implementation waits for explicit budgets. `[inferred]` |
| G2-03 | Multiple BloodHound collectors are not wired into one production run. `[verified: /srv/share/dev/28julytoolkit/ad-modern/bloodhound-collectors/docs/README.md]` | 5 | 4 | P0 | now | Collection depends on manual invocation and file movement. `[inferred]` |
| G2-04 | AD CS, GPO, and delegation outputs lack one normalized completeness model. `[verified: /srv/share/dev/aranum/aranumtoolkit/network/enum-ldap.sh]` | 4 | 4 | P1 | later | It affects comparison and reporting but not the first mechanical path. `[inferred]` |
| G3-01 | No provisioned BloodHound CE analysis service exists. `[verified: /srv/share/dev/pt_provision/config/repositories.tsv]` | 5 | 4 | P0 | now | Collection cannot be reliably ingested on a fresh attack box. `[inferred]` |
| G3-02 | PurpleSploit imports only a limited BloodHound relationship subset. `[verified: /srv/share/dev/purplesploit/python/purplesploit/interop/bloodhound.py]` | 5 | 4 | P0 | now | Complete AD path semantics must remain authoritative in BloodHound CE. `[inferred]` |
| G3-03 | NetExec BloodHound results do not automatically become registered ingest artifacts. `[verified: /srv/share/dev/purplesploit/python/purplesploit/modules/network/nxc_ldap.py]` | 5 | 2 | P0 | now | Successful collection can finish without usable graph state. `[inferred]` |
| G3-04 | Generic path scoring is too simple for AD prioritization. `[verified: /srv/share/dev/purplesploit/python/purplesploit/core/attack_graph.py]` | 4 | 4 | P1 | later | Ranking follows reliable ingest and path retrieval. `[inferred]` |
| G4-01 | RDP/VNC local transports are absent. `[verified: /srv/share/dev/aranum/aranumtoolkit/network/local-enum.py]` | 3 | 5 | P2 | later | Important for some hosts, but WinRM/SSH qualification precedes it. `[inferred]` |
| G4-02 | Aranum local access is not exposed through PurpleSploit. `[verified: /srv/share/dev/purplesploit/python/purplesploit/modules/recon/aranum.py]` | 5 | 3 | P0 | now | The production automated chain currently leaves the operator console. `[inferred]` |
| G4-03 | WinRM/Windows bulk transport lacks live domain qualification. `[verified: /srv/share/dev/aranum/aranumtoolkit/docs/ADR-003-20MAY2026-windows-bulk-enum-design.md]` | 5 | 3 | P0 | now | The primary Windows fleet path is only mock/dry-run tested. `[inferred]` |
| G4-04 | Manual/console session results lack a standard import route. `[inferred]` | 3 | 2 | P1 | later | It improves completeness but does not block automated transports. `[inferred]` |
| G5-01 | Writable-directory coverage is PATH-centric. `[verified: /srv/share/dev/aranum/standalones/windows/Get-WritablePathDirs.ps1]` | 4 | 4 | P1 | later | Broader bounded volume/share coverage follows the default-write correction. `[inferred]` |
| G5-02 | Scheduled-task analysis omits parts of referenced action chains. `[verified: /srv/share/dev/aranum/standalones/windows/Get-ScheduledTasks.ps1]` | 4 | 3 | P1 | later | This is a coverage expansion rather than a Phase 0 prerequisite. `[inferred]` |
| G5-03 | Broad autorun/startup/DLL search-path checks are missing or partial. `[verified: /srv/share/dev/aranum/standalones/windows/Invoke-PrivEscEnum.ps1]` `[inferred]` | 4 | 4 | P1 | later | This is a coverage expansion after the host pipeline is qualified. `[inferred]` |
| G5-04 | Three default Windows writability implementations create and delete target files. `[measured: repo-wide target-writer sweep in §3.7]` | 5 | 2 | P0 | now | `Get-UnquotedServices.ps1`, `Get-WritablePathDirs.ps1`, and `Invoke-PrivEscEnum.ps1` conflict with C3; three additional opt-in target-output sites are separately inventoried. `[verified: cited files in §3.7]` |
| G5-05 | Fleet completion, retry, timeout, and partial-host behavior are not demonstrated at domain scale. `[verified: /srv/share/dev/aranum/aranumtoolkit/network/bulk-enum-windows.py]` | 5 | 4 | P0 | now | Silent host gaps violate the objective. `[inferred]` |
| G6-01 | Canonical/job state is not a durable shared store for one through five operators. `[verified: /srv/share/dev/purplesploit/python/purplesploit/distributed/README.md]` `[recorded: owner decision C5]` | 5 | 5 | P0 | now | Multi-operator ownership and restartability are blocked. `[inferred]` |
| G6-02 | Aranum, PurpleSploit, and `pentest_scripts` evidence manifests are separate. `[verified: /srv/share/dev/pentest_scripts/evidence/workspace.py]` | 3 | 2 | P1 | later | The reporting chain functions before this bridge. `[inferred]` |
| G6-03 | Graph, access, service, and host findings lack one correlation rule set. `[verified: /srv/share/dev/purplesploit/python/purplesploit/services/README.md]` | 4 | 4 | P1 | later | Correlation follows stable source contracts. `[inferred]` |
| G6-04 | **WITHDRAWN under C7** — production LLM controller evaluation. | 2 | 1 | P2 | withdrawn | Owner directive excludes this work; no controller ADR or E2/E3 reconsideration dependency remains. `[recorded: owner directive, 14NOV2026]` |

### Lane summary

- **Now — 18 items:** G0-01–G0-05; G1-01–G1-03; G2-01, G2-03; G3-01–G3-03; G4-02–G4-03; G5-04–G5-05; G6-01. `[inferred]`
- **Later — 10 items:** G2-02, G2-04, G3-04, G4-01, G4-04, G5-01–G5-03, G6-02–G6-03. `[inferred]`
- **Withdrawn — 1 item:** G6-04 under C7; retained for traceability, outside the active lanes. `[recorded: owner directive, 14NOV2026]`
- **Out-of-scope gap items — none.** The standing exclusions are not converted into work items. `[inferred]`

---

# 2. Sprint map

All proposed branches, exits, blast radii, rollback actions, and roadmap IDs are `[inferred]` unless a cell carries a more specific evidence label.

## 2.1 Whole-effort map, ordered by tier then dependency

| Order | Sprint/gate | Band | Gap items | Roadmap/ride-alongs | Repo(s) and branch | Independently shippable exit | Blast radius and rollback |
|---:|---|---|---|---|---|---|---|
| 0 | SP0-01 — provider coexistence go/no-go | predecessor | C6 | Provider eligibility | ad-lab-harness preliminary record | VirtualBox and Vagrant complete one disposable create/start/snapshot/restore cycle on net0srv while the previously running KVM/libvirt VMs remain running and observable. Only a pass permits P0-S1; recovery follows §2.2. Harness implemented/reviewed; unchanged-logic port recorded in §4.2. Current dry run: exit 2, inconclusive/prerequisite_missing; owner must install VirtualBox 7.1 and Vagrant before re-run. `[recorded: ad-lab-harness/docs/records/PLAN003-SP0-01-TEST-CARD-2026-11-14.md]` | Disposable spike VM only; remove the spike VM after evidence capture. No alternate host/provider is selected. |
| 1 | P0-S0 — versioned source roots | P0 | G0-05 | P0-02, P0-03 | `pt_provision`, `28julytoolkit`: `bootstrap/plan003-source-baseline` | Both inputs have reviewed root commits, clean intended-source inventories, and recorded tree hashes. Toolkit half DONE 14NOV2026; provisioner half BLOCKED on owner/root directory-permission fix (§4.1). `[recorded: 28julytoolkit/docs/test-strategy/PLAN003-P0-S0-TEST-CARD-14NOV2026.md]` | Version metadata only; before integration drop the branch, after integration correct forward without deleting source files. |
| 2 | P0-S1 — full-GOAD first gate and truth model | P0 | G0-01 | P0-01, P0-06; scaffolding for G1-02/G2-01 | ad-lab-harness: `plan003/p0-goad-truth-gate`; GOAD remains pinned/unchanged | Full `ad/GOAD` rebuilds twice and topology/trust/AD-CS truth comparison returns only pass/fail/inconclusive, with no inconclusive counted as pass. Currently BLOCKED on SP0-01 prerequisites and a subsequent pass (§4.2). `[recorded: ad-lab-harness/docs/records/PLAN003-SP0-01-TEST-CARD-2026-11-14.md]` | Lab harness and VMs; revert the harness commit and power off retained test VMs. |
| 3 | SP0-04 — effective-rights decision record | predecessor | C3 | API comparison | ad-lab-harness/Aranum record | Authz and AccessCheck are compared against the same controlled Windows ACL fixtures on a qualified P0-S1 Windows host; the record selects the implementation used by P0-S2. | Decision record only; supersede if evidence changes. |
| 4 | P0-S2 — ACL-first writable-path contract | P0 | G5-04 | P0-05 | Aranum: `plan003/p0-acl-first-write-gate` | All three default writability checks use one effective-rights implementation without file creation; the repo-wide writer inventory and classification manifest agree exactly; no `default-probe` or ungated `opt-in-output` site remains; every target-side creation site is reachable only through explicit `--write`/`-WriteValidate`. | Windows collectors and flag plumbing; revert the sprint commit to compare behavior, while marking the prior version unqualified under C3. |
| 5 | P0-S3 — pinned offline attack-box definition | P0 | G0-02, G0-04, G3-01 | P0-02; packaging support for G2-03 | `pt_provision`: `plan003/p0-ad-box-lock` | A Debian-based lock resolves all 17 capabilities, native packages, both collectors, and the selected three-service BloodHound CE composition. | Provisioning manifest/build output; revert the sprint commit and continue using the parent only for non-PLAN-003 uses. |
| 6 | P0-S4 — reproducible offline release | P0 | G0-03 | P0-03 | `pt_provision`: `release/plan003-p0-offline-bundle` | Two builds resolve identical normalized identities; a pristine pinned-base VM, disconnected before real bootstrap, consumes only the release artifact and passes installation/service/import/report checks. | Release artifact only; withdraw a failed release record and rebuild from the retained lock. |
| 7 | P0-S5 — live Phase 0 interoperability smoke | P0 | G4-03 | P0-04, P0-05; non-promoting probes of later interfaces | ad-lab-harness, Aranum, PurpleSploit: `plan003/p0-live-interoperability` | The detached attack box produces six lineage-linked stage receipts plus success/denied/unavailable/partial/inconclusive transport classifications. This qualifies interoperability and G4-03, not the production automated chain. | Qualification fixtures and harness records; revert commits and retain raw run evidence outside source trees. |
| 8 | P1-S1 — discovery-to-Aranum production workflow | P0 | G1-01, G1-02 | P1-01, P1-02 | PurpleSploit + Aranum: `plan003/p1-discovery-chain` | One run ID preserves discovery XML, runs unauthenticated enumeration, imports results, and matches lab truth. | Discovery/workflow adapter; revert both coordinated commits. |
| 9 | P1-S2 — resumable coverage ledger | P0 | G1-03 | P1-03, P1-04 | Aranum: `plan003/p1-resume-ledger` | Interrupted synthetic and lab runs resume without converting skipped work to absence. | Run-state schema; additive rollback through reader compatibility and commit revert. |
| 10 | P2-S1 — directory inventory and graph collection | P0 | G2-01, G2-03 | P2-02, P2-03, P2-05 | Aranum + ad-lab-harness: `plan003/p2-directory-graph` | Versioned inventory and collection receipts match truth with discrepancy classifications. | LDAP schemas/collector adapter; revert additive schema and adapter commits. |
| 11 | P3-S1 — authoritative graph ingest | P0 | G3-02, G3-03 | P3-02, P3-03; G3-01 closed by P0-S3 | PurpleSploit: `plan003/p3-bhce-ingest` | Collector artifacts automatically register, ingest into BloodHound CE, and return normalized path receipts. | Artifact/job contracts; revert adapter and retain raw collection. |
| 12 | P4-S1 — local access through the console and workstation profile | P0 | G4-02 | P4-01, P4-02, P4-05; later WS01 profile | PurpleSploit + Aranum + ad-lab-harness: `plan003/p4-aranum-local` | Proven transport capabilities determine eligible local jobs; results return through the importer; the later WS01 truth profile proves one workstation path without changing the first gate. | Console adapter, access schema, and separate WS01 truth profile; revert additive operations/profile. |
| 13 | P5-S1 — restartable fleet execution | P0 | G5-05 | P5-04, P5-06; G5-04 closed by P0-S2 | Aranum + ad-lab-harness: `plan003/p5-fleet-coverage` | Mixed full-GOAD/WS01 and simulated runs report a terminal state for every host/check and resume after interruption. | Fleet state/fixtures; revert additive queue changes. |
| 14 | P6-S1 — durable one-to-five-operator state | P0 | G6-01 | P6-01, P6-02 | PurpleSploit: `plan003/p6-durable-team-state` | Acceptance passes independently at operator counts 1, 2, 3, 4, and 5, including restart and ownership/lease transitions at counts 1 and 5. | Canonical persistence and jobs; restore the pre-migration export and revert code. |
| 15 | P2-S2 — policy slots and normalized domain classes | P1 | G2-02, G2-04 | P2-01, P2-04 | PurpleSploit + Aranum: `plan003/p2-domain-normalization` | Null lockout/traffic slots remain unusable until explicitly populated; AD CS/GPO/delegation rows have terminal coverage. | Configuration/schema changes; revert additive fields/adapters. |
| 16 | P3-S2 — path prioritization | P1 | G3-04 | P3-04, P3-05 | PurpleSploit + ad-lab-harness: `plan003/p3-path-ranking` | Seeded paths rank deterministically with visible factors and unproven prerequisites remain unconfirmed. | Ranking/query pack; revert query-pack version. |
| 17 | P4-S2 — manual session records | P1 | G4-04 | P4-04 | PurpleSploit: `plan003/p4-manual-sessions` | Manual observations enter the same access/coverage model without claiming automated proof. | Additive record/UI path; revert schema/UI commit. |
| 18 | P5-S2 — expanded Windows local coverage | P1 | G5-01, G5-02, G5-03 | P5-02, P5-03; WS01 workstation depth | Aranum + ad-lab-harness: `plan003/p5-windows-depth` | Bounded directory/share, task-chain, startup, search-path, and workstation truth cases have explicit results and negative controls. | Windows collectors and truth profile; revert collector pack version. |
| 19 | P6-S2 — evidence bridge and correlation | P1 | G6-02, G6-03 | P6-03–P6-05 | PurpleSploit + `pentest_scripts`: `plan003/p6-correlation-evidence` | One run registers all artifacts and produces deduplicated findings with retained lineage. | Correlation/evidence registration; revert rules and bridge commits. |
| 20 | P4-S3 — interactive desktop access | P2 | G4-01 | P4-03 | Aranum: `plan003/p4-desktop-transports` | RDP produces qualified collection results and VNC records assisted/manual status explicitly. | Transport resolver; revert additive transport implementation. |
| 21 | P6-S3 — controller decision — **WITHDRAWN under C7** | withdrawn (formerly P2) | G6-04 (withdrawn) | P6-06 (withdrawn) | None; no branch or repository work | No LLM controller; no ADR, reproduction test or promotion dependency. `[recorded: owner directive, 14NOV2026]` | No implementation to roll back; identifier retained only for traceability. |

## 2.2 Dependency order

1. SP0-01 is a hard predecessor of P0-S1, which stays `blocked` until a `pass`. A `fail` requires the owner to name another host (C6). An `inconclusive` result requires fixing the prerequisite or harness cause and rerunning once; if still inconclusive, the owner names another host. The pre-install dry run is a precondition check, not the SP0-01 result, and does not consume the single rerun. No provider engineering or alternate-host work is implied. `[recorded: owner decision C6]` `[recorded: ad-lab-harness/docs/plans/PLAN003-SP0-01-PROVIDER-COEXISTENCE-2026-11-14.md]` `[inferred]`
2. P0-S0 precedes every later `pt_provision` or `28julytoolkit` modification. The toolkit half is DONE; provisioner changes remain blocked until its permission fix and reviewed root commit. `[recorded: 28julytoolkit/docs/test-strategy/PLAN003-P0-S0-TEST-CARD-14NOV2026.md]` `[measured: git -C /srv/share/dev/28julytoolkit rev-parse HEAD plan003-p0-source-base^{commit}, 14NOV2026]`
3. P0-S1 starts only after SP0-01 passes. Its lab-ready Windows slice precedes SP0-04. `[inferred]`
4. SP0-04’s signed decision record precedes P0-S2 implementation. P0-S2 is therefore not independent of the lab. `[inferred]`
5. P0-S3 depends on P0-S0 and on SP0-02/SP0-03 decision records for the base release and BloodHound CE composition. `[inferred]`
6. P0-S4 depends on P0-S3. `[inferred]`
7. P0-S5 depends on passed P0-S1, P0-S2, and P0-S4 gates. `[inferred]`
8. Phase 1 depends on the Phase 0 interoperability gate. Phase 2 depends on Phase 1 discovery/coverage. Phase 3 depends on Phase 2 collection. Phase 4 depends on proven access state. Phase 5 depends on Phase 4 dispatch eligibility. Active Phase 6 sprints P6-S1 and P6-S2 depend on stable producer contracts from Phases 1–5. `[inferred]`
9. Before a Phase 4 or 5 exit may claim per-workstation coverage, P4-S1 must install and separately qualify the upstream WS01 extension profile. The full-GOAD first-gate denominator remains five VMs. `[recorded: owner decision C1]` `[verified: upstream/GOAD/extensions/ws01/README.md]`
10. Lower-tier work never pulls a higher-tier gap item into the same sprint. `[inferred]`

---

# 3. Phase 0 research

## 3.1 Evidence reviewed

The ShadowHex citations below and in G0-01 are read-only historical references; nothing in PLAN-003 reads, writes or depends on ShadowHex at runtime. `[recorded: owner directive, 14NOV2026]`

1. GOAD clone at `upstream/GOAD`, including `ad/`, `extensions/`, provider definitions, documentation, `goad.py`, and provider factory. `[verified: upstream/GOAD]`
2. ShadowHex expanded AD gate. `[verified: /srv/share/dev/ShadowHex/docs/EXPANDED-AD-LINUX-APPLICATION-GATE-2026-11-02.md]`
3. ShadowHex roadmap, RFI, and ADR records mentioning GOAD/provider selection. `[verified: /srv/share/dev/ShadowHex/docs/ROADMAP-AND-EXECUTION-PROPOSAL-2026-11-02.md]` `[verified: /srv/share/dev/ShadowHex/docs/rfi/rfi-queue.json]` `[verified: /srv/share/dev/ShadowHex/docs/adr/ADR-REGISTER-2026-11-05.md]`
4. `pt_provision`, including the current deploy/unpack artifact contract. `[verified: /srv/share/dev/pt_provision]`
5. `28julytoolkit/ad-modern`. `[verified: /srv/share/dev/28julytoolkit/ad-modern]`
6. Aranum dependency checker, Windows collectors, payload builders, and Windows bulk design. `[verified: /srv/share/dev/aranum/deps-check.sh]` `[verified: /srv/share/dev/aranum/standalones/windows]` `[verified: /srv/share/dev/aranum/aranumtoolkit/network]`
7. Aranum PLAN-001 and PurpleSploit PLAN-002. `[verified: /srv/share/dev/aranum/docs/plans/PLAN-001-25OCT2026-fp-ad-local-posture.md]` `[verified: /srv/share/dev/purplesploit/docs/plans/PLAN-002-28OCT2026-aranum-purplesploit-integration.md]`

The prior plans establish per-sprint baseline capture, mutation-backed gates, producer/consumer separation, and the existing Aranum bundle acceptance suite. `[recorded: cited plans]`

## 3.2 Full-GOAD first gate

The full `ad/GOAD` profile contains three DCs and two member servers, with no workstation. `[verified: upstream/GOAD/ad/GOAD/data/config.json]`

It contains two forests and three domains: `sevenkingdoms.local`, child `north.sevenkingdoms.local`, and `essos.local`, plus an explicit bidirectional external trust. `[verified: upstream/GOAD/ad/GOAD/data/config.json]` `[verified: upstream/GOAD/ad/GOAD/data/inventory]`

AD CS is present on `dc01` and `srv03`, with custom templates on `dc03`. `[verified: upstream/GOAD/ad/GOAD/data/inventory]`

The VirtualBox definition declares five VMs, 20,000 MB total RAM, and 10 vCPUs. `[measured: rg ':cpus|:mem' upstream/GOAD/ad/GOAD/providers/virtualbox/Vagrantfile]`

No per-VM disk size is declared in that Vagrantfile. `[verified: upstream/GOAD/ad/GOAD/providers/virtualbox/Vagrantfile]`

GOAD’s Linux installation document estimates approximately 115 GB total disk and recommends at least 24 GB RAM for GOAD. `[verified: upstream/GOAD/docs/mkdocs/docs/installation/linux.md:25]`

The first-gate truth denominator is therefore fixed at five expected hosts, three domains, two forests, one external-trust relationship represented in both directions, and the AD CS roles/templates parsed from the pinned inventory. `[inferred]`

Later profiles may deepen truth assertions over the same lab or add SCCM, NHA, another forest/CA, Exchange, mixed Linux, or workstation coverage; none may replace the first full-GOAD gate. `[recorded: owner decision C1]`

## 3.3 Workstation profile

The upstream `ws01` extension adds a Windows 10 workstation named `casterlyrock` to GOAD or GOAD-Light in `sevenkingdoms.local`. `[verified: upstream/GOAD/extensions/ws01/README.md]` `[verified: upstream/GOAD/extensions/ws01/data/config.json]`

Its VirtualBox definition declares one two-vCPU, 4,000 MB VM. `[verified: upstream/GOAD/extensions/ws01/providers/virtualbox/Vagrantfile]`

WS01 is not required for the Phase 0 first gate because C1 fixes that gate to the unextended five-VM `ad/GOAD` profile. `[recorded: owner decision C1]`

P4-S1 adds WS01 as a separate later truth profile before claiming per-workstation local access; P5-S1 and P5-S2 reuse that profile for fleet and workstation-local enumeration coverage. `[inferred]`

## 3.4 Provider and net0srv decision

The GOAD clone includes a VirtualBox/Vagrant provider but no native libvirt/KVM provider. `[verified: upstream/GOAD/goad/dependencies.py]` `[verified: upstream/GOAD/goad/provider]`

The owner-recorded net0srv candidate has 32 cores, 62 GB RAM with about 53 GB available, 1.2 TB free disk, KVM/libvirt installed, `/dev/kvm`, and running libvirt VMs; Vagrant and VirtualBox were not installed at the time of measurement. `[recorded: owner brief, 14NOV2026]`

The declared full-GOAD RAM/vCPU requirement and upstream disk estimate fit within the recorded raw capacity, but raw arithmetic does not prove that VirtualBox can coexist with the running KVM/libvirt workloads. `[inferred]`

C6 therefore fixes the following outcome:

- SP0-01 installs/prepares only what is required for a one-day disposable VirtualBox/Vagrant coexistence probe on net0srv. `[recorded: owner decision C6]`
- A pass requires the pre-existing KVM/libvirt VM set to remain running and observable before, during, and after a VirtualBox create/start/snapshot/restore cycle. `[inferred]`
- P0-S1 stays blocked until SP0-01 passes; failure and inconclusive recovery follow §2.2. `[recorded: owner decision C6]` `[recorded: ad-lab-harness/docs/plans/PLAN003-SP0-01-PROVIDER-COEXISTENCE-2026-11-14.md]`
- This plan contains no provider-development path and no alternate host. `[recorded: owner decision C6]`

## 3.5 Kali versus Debian

| Criterion | Kali | Debian |
|---|---|---|
| Initial AD-tool availability | `28julytoolkit/ad-modern` assumes NetExec and Certipy are present on a standard Kali image. `[verified: /srv/share/dev/28julytoolkit/ad-modern/README.md]` | More dependencies must be declared explicitly. `[inferred]` |
| Reproducible package base | A rolling package stream makes long-lived exact reconstruction harder. `[upstream knowledge, unverified]` | A pinned stable release is better aligned with an exact offline package set. `[upstream knowledge, unverified]` |
| Offline definition | A complete image/package/artifact set would still have to be captured. `[inferred]` | The smaller base makes required capabilities and packages explicit. `[inferred]` |
| Phase 0 selection | Rejected initially. `[inferred]` | Selected, with the exact Debian stable release decided by SP0-02. `[inferred]` |

The selection flips to Kali only if SP0-02 demonstrates that a pinned Kali image resolves and reconstructs all 17 capabilities twice while the Debian candidate cannot provide a required functional capability or materially increases offline installation complexity. `[inferred]`

SP0-02’s decision record is a predecessor to P0-S3 implementation. `[inferred]`

## 3.6 Attack-box capability denominator

The Phase 0 attack-box denominator contains 17 capabilities: PurpleSploit, Aranum, Nmap, DNS client, LDAP client, SMB client, RPC client, Kerberos clients, NetExec, Impacket, `pywinrm`, Certipy, PowerShell, an RDP client, RustHound-CE, BloodHound CE Python collector, and a BloodHound CE analysis service with its required runtime. `[inferred]`

The current `repositories.tsv` contains seven repository rows, of which PurpleSploit and Aranum directly satisfy two identities in that denominator: **2/17 measured**. `[measured: cd /srv/share/dev/pt_provision && awk -F '\t' '$1=="purplesploit" || $1=="aranum" {n++} END{print n+0}' config/repositories.tsv]`

Aranum separately marks Python, Nmap, curl, dig, `ldapsearch`, `smbclient`, `rpcclient`, `showmount`, and `rsync` as required, and lists NetExec, Impacket, `pywinrm`, BloodHound collectors, Certipy, PowerShell, and supporting programs at recommended or optional levels. `[verified: /srv/share/dev/aranum/deps-check.sh]`

## 3.7 Complete repo-wide target-side writer inventory

The inventory scope is every `*.ps1` and `*.psm1` beneath `/srv/share/dev/aranum/`, explicitly excluding only `tests/` and `fixtures/`. Nineteen production-source PowerShell files are in scope. `[measured: rg --files /srv/share/dev/aranum -g '*.ps1' -g '*.psm1' -g '!**/tests/**' -g '!**/fixtures/**' | wc -l]`

The candidate signature covers the required PowerShell and .NET output families: `WriteAllText`, `WriteAllBytes`, `WriteAllLines`, `AppendAllText`, `New-Item`, `Set-Content`, `Add-Content`, `Out-File`, `Export-Csv`, `Export-Clixml`, `Start-Transcript`, `Tee-Object`, `Copy-Item`, `Move-Item`, `[IO.File]`/`[System.IO.File]`, `StreamWriter`, `FileStream`, and `>`/`>>` including numbered/all-stream forms. Block comments, full-line comments, and double-quoted example strings are skipped before candidates are inspected. `[inferred]`

The exact read-only candidate sweep was:

```bash
rg -n -U --pcre2 \
  --glob '*.ps1' \
  --glob '*.psm1' \
  --glob '!**/tests/**' \
  --glob '!**/fixtures/**' \
  '(?s:<#.*?#>)(*SKIP)(*F)|(?m:^\s*#.*$)(*SKIP)(*F)|"(?:`.|[^"\r\n])*"(*SKIP)(*F)|(?i:\b(?:WriteAllText|WriteAllBytes|WriteAllLines|AppendAllText|New-Item|Set-Content|Add-Content|Out-File|Export-Csv|Export-Clixml|Start-Transcript|Tee-Object|Copy-Item|Move-Item)\b|\[(?:System\.)?IO\.File\]|\b(?:StreamWriter|FileStream)\b|(?<![-<])(?:\*|[1-6])?>>?\s*(?!\$null\b)(?=\S))' \
  /srv/share/dev/aranum
```

It returned seven executable-code candidates across five files. Six are target-side writer sites. The seventh, `standalones/passwords/Get-WeakPassword.ps1:180`, constructs `System.IO.FileStream` with `FileMode.Open` and `FileAccess.Read`; it is a recorded non-writer exclusion, not a writer site. `[measured: stated command]` `[verified: /srv/share/dev/aranum/standalones/passwords/Get-WeakPassword.ps1:176]`

There are therefore exactly **six current target-side writer sites across five PowerShell files**:

| Site | Required category | Reason and resolution |
|---|---|---|
| `standalones/windows/Get-UnquotedServices.ps1:19` | `default-probe` | Runs without an operator write flag, creates and deletes `<guid>.tmp`, and therefore violates C3. Replace the probe with shared effective-rights evaluation; optional validation may call only the shared `write-gated` validation path. `[verified: cited path]` `[inferred]` |
| `standalones/windows/Get-WritablePathDirs.ps1:16` | `default-probe` | Runs without an operator write flag, creates and deletes `.write_test_<guid>`, and therefore violates C3. Apply the same replacement. `[verified: cited path]` `[inferred]` |
| `standalones/windows/Invoke-PrivEscEnum.ps1:224` | `default-probe` | Runs by default and is shipped by the full WinRM path. Replace it with shared effective-rights evaluation; do not retain a per-collector writer. `[verified: cited path]` `[verified: /srv/share/dev/aranum/aranumtoolkit/network/bulk-enum-windows.py:122]` `[inferred]` |
| `standalones/windows/Invoke-PrivEscEnum.ps1:29` | `opt-in-output` | `Start-Transcript` runs only when the operator supplies `-OutFile`. The destination flag is explicit but is not the unified C3 authorization flag; require both `-OutFile` and `-WriteValidate`, with Python `--write` supplying the latter. `[verified: cited path]` `[inferred]` |
| `standalones/windows/Get-ThickClientEnum.ps1:220` | `opt-in-output` | `Tee-Object -FilePath` runs only when the operator supplies `-OutFile`. Require both `-OutFile` and `-WriteValidate`. `[verified: cited path]` `[inferred]` |
| `standalones/passwords/Get-WeakPassword.ps1:359` | `opt-in-output` | `Export-Csv -Path $OutFile` runs only inside `if ($OutFile)`; `$OutFile` defaults empty. It is not a default probe, but it still creates a target file and must require `-WriteValidate` in addition to `-OutFile`. `[verified: /srv/share/dev/aranum/standalones/passwords/Get-WeakPassword.ps1:71]` `[verified: cited path]` `[inferred]` |

The classification is exhaustive and mutually exclusive:

| Category | Definition | Current count |
|---|---|---:|
| `default-probe` | Writes on the target without an operator write flag. C3 requires removal from the default path and replacement with effective-rights evaluation. | **3** |
| `opt-in-output` | Writes only when an operator supplies a destination/output parameter such as `-OutFile`, but lacks the unified write-authorization flag. | **3** |
| `write-gated` | Target-side creation is reachable only after explicit `--write`/`-WriteValidate` authorization. | **0** |
| `operator-side` | The PowerShell writer executes on the attack box rather than the assessed target. | **0** |

`opt-in-output` does **not** satisfy Aranum’s unified explicit-write invariant as implemented today. `-OutFile` selects a destination; it does not establish the common authorization state required by C3. P0-S2 must therefore route all three opt-in sites through `--write`/`-WriteValidate`, while retaining their destination parameters. `[recorded: owner decision C3]` `[inferred]`

P0-S2 centralizes optional validation creation in the shared effective-rights library. Its expected post-change inventory is one shared `write-gated` validation writer plus the three output sinks reclassified as `write-gated`; the three current per-collector `default-probe` sites disappear. The classification gate uses set equality rather than assuming that the current six-site count remains the post-change count. `[inferred]`

A separate `write_text|write_bytes` sweep found 32 operator-side artifact writes across seven Python files under `aranumtoolkit`; these write attack-box result artifacts rather than target files and remain outside the PowerShell target-writer denominator. `[measured: rg -n --glob '*.py' --glob '!**/tests/**' -e 'write_text\(' -e 'write_bytes\(' /srv/share/dev/aranum/aranumtoolkit]`

`local-enum.py` builds its compact exec probe from `Invoke-HostPosture.ps1`; the repo-wide writer signature has zero matches in that source. `[verified: /srv/share/dev/aranum/aranumtoolkit/network/local-enum.py:574]` `[measured: §4.3 payload-family baseline command]`

The full WinRM/SSH payload uses `Invoke-PrivEscEnum.ps1` and therefore currently reaches one default probe and one opt-in transcript writer. `[verified: /srv/share/dev/aranum/aranumtoolkit/network/bulk-enum-windows.py:122]` `[verified: /srv/share/dev/aranum/aranumtoolkit/network/local-enum.py:1107]`

## 3.8 Windows effective-rights decision

### Method A — Authz API, selected

Use a small PowerShell/C# interop wrapper around `AuthzInitializeResourceManager` with `AUTHZ_RM_FLAG_NO_AUDIT`, `AuthzInitializeContextFromToken` for the current token, and `AuthzAccessCheck` against each directory security descriptor. Request directory-specific create/write masks separately and return the granted mask plus error status. `[inferred]`

Microsoft documents `AuthzAccessCheck` as determining which access bits can be granted to a client for supplied security descriptors, and recommends token-derived contexts when an actual token is available. `[recorded: [Microsoft AuthzAccessCheck](https://learn.microsoft.com/windows/win32/api/authz/nf-authz-authzaccesscheck), inspected 14NOV2026]` `[recorded: [Microsoft client-context guidance](https://learn.microsoft.com/en-us/windows/win32/secauthz/initializing-a-client-context), inspected 14NOV2026]`

This method is selected because it evaluates the current token’s group membership and the complete security descriptor without reimplementing ACE ordering in PowerShell. `[inferred]`

### Method B — `AccessCheck`, rejected initially

The alternative is P/Invoke to `advapi32!AccessCheck` using an impersonation token, `GENERIC_MAPPING`, `MapGenericMask`, a privilege-set buffer, and the target security descriptor. `[upstream knowledge, unverified]`

It is rejected initially because it requires more token/generic-mask plumbing for the same current-token decision and does not improve the Phase 0 fixture denominator. `[inferred]`

The choice flips to `AccessCheck` if SP0-04 shows that Authz is unavailable under a supported Windows PowerShell/CLR combination or disagrees with controlled create/deny/inherited/group fixtures while `AccessCheck` agrees with the separately observed results. `[inferred]`

Manual parsing of only `Allow` ACEs and `icacls` text is rejected regardless of the selected native API because it can omit deny, group, inheritance, and ordering semantics. `[inferred]`

SP0-04 compares both concrete methods on a qualified P0-S1 Windows host and records the selected API before P0-S2 implementation starts. `[inferred]`

## 3.9 Collector and BloodHound CE packaging decision

`28julytoolkit/ad-modern` contains 736 files, including a 5,884,248-byte RustHound-CE binary, BloodHound CE Python source/bootstrap, a legacy collector, and 195 wheelhouse files. `[measured: find and file-size inventory over /srv/share/dev/28julytoolkit/ad-modern]`

The inspected RustHound SHA-256 is `1acfa0df51fce778ddc77b7cbc40b3c221b8280a4ad3529a5612b8354ff2560b`. `[measured: sha256sum /srv/share/dev/28julytoolkit/ad-modern/bloodhound-collectors/rusthound-ce/bin/rusthound-ce]`

The local collector documentation recommends RustHound-CE as the static Linux primary and BloodHound CE Python as the fallback; both produce CE-compatible ZIP output. `[recorded: /srv/share/dev/28julytoolkit/ad-modern/bloodhound-collectors/docs/README.md]`

No BloodHound CE server/database deployment exists in the reviewed `ad-modern` tree or current provisioner. `[verified: /srv/share/dev/28julytoolkit/ad-modern]` `[measured: find /srv/share/dev/pt_provision for BloodHound/compose/OCI definitions returned 0]`

### Method A — pinned official Docker Compose composition, selected

Use the upstream official Docker Compose service graph pinned to an exact upstream revision, with exact OCI image digests for PostgreSQL, Neo4j, and the BloodHound CE application. Store the compose file, environment-independent service facts, image archives, and identities in the root attack-box lock. `[inferred]`

SpecterOps’ official example identifies those three components and supports Docker-compatible runtimes. `[recorded: [official BloodHound CE Compose documentation](https://github.com/SpecterOps/BloodHound/blob/main/examples/docker-compose/README.md), inspected 14NOV2026]`

This method is selected for the offline release because the service graph and three-image denominator remain explicit, versionable, and directly loadable from bundled OCI archives. `[inferred]`

### Method B — pinned `bloodhound-cli`, rejected initially

The alternative is a pinned `bloodhound-cli` release managing its Docker Compose configuration through Docker Compose v2 or a compatible runtime. `[recorded: [official bloodhound-cli README](https://github.com/SpecterOps/bloodhound-cli/blob/main/README.md), inspected 14NOV2026]`

It is the upstream-recommended convenience installer, but it still depends on Compose and the same underlying service images, while adding another manager/config-generation behavior to the offline denominator. `[recorded: [official custom-installation guidance](https://bloodhound.specterops.io/get-started/custom-installation), inspected 14NOV2026]` `[inferred]`

It is rejected for the first offline release because direct pinned Compose gives P0-S4 an explicit service and image-consumption oracle. `[inferred]`

The choice flips to `bloodhound-cli` only if SP0-03 proves, with networking disabled and a supplied compose file, that a pinned CLI consumes only the bundled files/images, exposes the same exact three-service identities, and reduces lifecycle steps without hidden retrieval. `[inferred]`

SP0-03 records the selected upstream revision, exact image digests, compatible runtime/Compose versions, health interfaces, import interface, and offline load/start commands before the BloodHound portion of P0-S3 is implemented. `[inferred]`

## 3.10 Phase 0 spikes and decisions

| ID | Time box | Question and decisive evidence | Predecessor/home |
|---|---:|---|---|
| SP0-01 | 1 day | Can VirtualBox/Vagrant on net0srv create, start, snapshot, restore, and stop one disposable VM while the pre-existing KVM/libvirt VM set remains running and observable? Only a pass permits P0-S1; failure and inconclusive recovery follow §2.2. `[recorded: owner decision C6]` `[recorded: ad-lab-harness/docs/plans/PLAN003-SP0-01-PROVIDER-COEXISTENCE-2026-11-14.md]` | Hard predecessor to P0-S1 |
| SP0-02 | 0.5 day | Which exact Debian stable base/repository snapshot resolves the native capability set for the recorded architecture? Flip to Kali only under §3.5’s evidence. `[inferred]` | Decision record precedes P0-S3 |
| SP0-03 | 1 day | Pin and validate the selected official three-service BloodHound CE Compose graph, OCI identities, runtime, health checks, and import interface; compare it with pinned `bloodhound-cli` under §3.9. `[inferred]` | Decision record precedes P0-S3 service implementation |
| SP0-04 | 0.5 day | Compare Authz and `AccessCheck` on allow, deny, inherited, group, and mixed-order fixtures under the supported Windows PowerShell/CLR versions; select under §3.8. `[inferred]` | P0-S1 Windows slice → SP0-04 → P0-S2 |
| SP0-05 | 0.5 day | Record disk consumed after image/template acquisition and both full-GOAD builds. `[inferred]` | P0-S1 |

---

# 4. Phase 0 sprint plans

## 4.0 Common Phase 0 gate semantics

Every new acceptance gate has exactly three outcomes:

- `pass`: the property was positively observed.
- `fail`: the property was falsified.
- `inconclusive`: the required observation could not be made, the harness failed, the lab was not ready, or evidence was incomplete. `[inferred]`

`inconclusive` never counts as pass and prevents sprint exit. Every absence assertion is paired with a presence assertion so an empty or broken collector cannot pass. Wrong-but-present mutations are used for absence gates. `[recorded: owner brief, 14NOV2026]`

Regression manifests contain the exact suite command, working directory, execution-start SHA, inputs, denominator, and one row per test identity with `pass|fail|skip|inconclusive`. `[inferred]`

Except for the completed P0-S0 toolkit work and SP0-01 records cited below, per-test statuses remain deferred to sprint execution; this document revision runs no implementation tests. `[recorded: owner brief, 14NOV2026]`

## 4.1 P0-S0 — versioned source roots

### Problem and closure

At the initial r2 baseline, `pt_provision` and `28julytoolkit` both had zero commits. This sprint closes G0-05 and is a hard dependency for every later modification to those repositories; current disposition is partial completion as recorded below. `[measured: repository-base commands, initial r2 baseline]` `[inferred]`

### Status (14NOV2026)

- **28julytoolkit half: DONE.** Byte-faithful root `195acd2`, tag `plan003-p0-source-base`, `main` at `2f0dede`. `tests/test-ad-modern-inventory.sh` passes **18/18 on main**, covering **23,389 blobs, 0 byte mismatches**. `[measured: bash tests/test-ad-modern-inventory.sh on 28julytoolkit main 2f0dede, exit 0, 14NOV2026]`
- **Review:** Sol R1 **FIX-FIRST** identified CRLF normalization; fixed. Sol R2 **SHIP**. `[recorded: 28julytoolkit/docs/reviews/PLAN003-P0-S0-REVIEW-SOL-R1-14NOV2026.md]` `[recorded: 28julytoolkit/docs/reviews/PLAN003-P0-S0-REVIEW-SOL-R2-14NOV2026.md]` `[recorded: 28julytoolkit/docs/test-strategy/PLAN003-P0-S0-TEST-CARD-14NOV2026.md]`
- **pt_provision half: BLOCKED** until the owner fixes directory write permission: owner `srv0:nfs_users`, mode `755/2755`; root is required. It still has no accepted root. This is a prerequisite block, not a failed source-fidelity gate. `[measured: stat -c '%U:%G %a' /srv/share/dev/pt_provision gives srv0:nfs_users 2755, 14NOV2026]` `[inferred]`

### Decisions

**Method A — reviewed root commits, selected.** Commit the intended existing source trees without changing content, record tree hashes, and tag the accepted roots `plan003-p0-source-base`. `[inferred]`

**Method B — external tarball plus digest, rejected.** It would identify bytes but would not give later changes real Git ancestry. `[inferred]`

The `pt_provision` root includes exactly these eight intended source entries: `.gitignore`, `AGENTS.md`, `README.md`, `config/`, `deploy.sh`, `templates/`, `tests/`, and `unpack.sh`. `[measured: P0-S0 top-level inventory command]`

The current encrypted bundle and checksum remain generated artifacts excluded by `.gitignore`. `[verified: /srv/share/dev/pt_provision/.gitignore]`

The accepted `28julytoolkit` root includes the 11 entries recorded as untracked at the initial r2 baseline: `CYBER-FLAGS-LOG.md`, `README.md`, `ROE-TEMPLATE.md`, `ad-modern/`, `aranum/`, `c2-alt/`, `evasion-modern/`, `payloads/`, `potatoes/`, `sliver/`, and `toolchains/`. `[measured: P0-S0 top-level inventory command]`

If the owner does not intend all 11 entries to share one history, P0-S0 stops and records an owner-approved root boundary before committing anything. `[inferred]`

### Components and failure modes

| Repo/path | Change/command ownership | Contract affected | Introduced failure mode |
|---|---|---|---|
| `pt_provision/{.gitignore,AGENTS.md,README.md,config,deploy.sh,templates,tests,unpack.sh}` | Track the eight reviewed source entries unchanged in the root commit. `[inferred]` | Provisioner source provenance. `[inferred]` | Intended source omitted or generated artifact included. `[inferred]` |
| `pt_provision/tests/test-deploy.sh` | Existing regression command; content changes only if the root-baseline work exposes a real path issue. `[inferred]` | Existing bundle fixture regression. `[verified: path]` | Regression output not tied to the root commit. `[inferred]` |
| `pt_provision/tests/test-source-baseline.sh` | New source inventory/tree-status test. `[inferred]` | Root provenance gate. `[inferred]` | Expected inventory becomes stale. `[inferred]` |
| `pt_provision/docs/test-strategy/raw/plan003/p0-s0/{test-deploy.log,source-baseline.tsv}` | Own both command outputs. `[inferred]` | Execution record. `[inferred]` | Output references the wrong tree. `[inferred]` |
| `28julytoolkit/{CYBER-FLAGS-LOG.md,README.md,ROE-TEMPLATE.md,ad-modern,aranum,c2-alt,evasion-modern,payloads,potatoes,sliver,toolchains}` | Track the 11 owner-approved root entries. `[inferred]` | Toolkit source provenance. `[inferred]` | Unrelated generated data enters the root or a required artifact is omitted. `[inferred]` |
| `28julytoolkit/tests/test-ad-modern-inventory.sh` | New static inventory test for collector paths, wheel count, and RustHound digest. `[inferred]` | Toolkit baseline. `[inferred]` | Static denominator disagrees with the accepted root. `[inferred]` |
| `28julytoolkit/docs/test-strategy/raw/plan003/p0-s0/ad-modern-inventory.tsv` | Own the inventory command output. `[inferred]` | Toolkit execution record. `[inferred]` | Record not tied to the root tree hash. `[inferred]` |

### Test plan

```bash
cd /srv/share/dev/pt_provision
bash tests/test-deploy.sh \
  | tee docs/test-strategy/raw/plan003/p0-s0/test-deploy.log
bash tests/test-source-baseline.sh \
  --output docs/test-strategy/raw/plan003/p0-s0/source-baseline.tsv
```

```bash
cd /srv/share/dev/28julytoolkit
bash tests/test-ad-modern-inventory.sh \
  --output docs/test-strategy/raw/plan003/p0-s0/ad-modern-inventory.tsv
```

These are proposed execution commands. `[inferred]`

RED proof:

- Add a wrong-but-present untracked source file under `ad-modern/` and require the clean-tree gate to fail; pair it with presence assertions for `ad-modern/README.md`, the RustHound binary, and the Python collector bootstrap. `[inferred]`
- Replace the recorded RustHound digest with another well-formed digest and require the inventory gate to fail. `[inferred]`
- A Git ownership/read error is `inconclusive`, never pass. `[inferred]`

### Baselines

The two rows below preserve the initial r2 starting measurements (before P0-S0 execution). Current source addressability is **1/2**, with the toolkit DONE and provisioner BLOCKED as recorded above; re-running the literal commands will reflect that progress. `[recorded: 28julytoolkit/docs/test-strategy/PLAN003-P0-S0-TEST-CARD-14NOV2026.md]`

| Metric | Exact command and working directory | Inputs and denominator | Baseline |
|---|---|---|---|
| Version-addressable source repositories | `git -c safe.directory=/srv/share/dev/pt_provision -C /srv/share/dev/pt_provision rev-parse --verify HEAD; git -c safe.directory=/srv/share/dev/28julytoolkit -C /srv/share/dev/28julytoolkit rev-parse --verify HEAD` from any directory | Two repositories | **0/2 measured; both commands returned status 128.** `[measured: stated commands]` |
| Intended top-level source inventories committed | `for repo in /srv/share/dev/pt_provision /srv/share/dev/28julytoolkit; do git -c safe.directory="$repo" -C "$repo" status --porcelain=v1 --untracked-files=normal \| awk -v repo="$repo" 'substr($0,1,2)=="??" {p=substr($0,4); split(p,a,"/"); seen[a[1]]=1} END {print repo, length(seen)}'; done` from any directory | Eight `pt_provision` entries and 11 `28julytoolkit` entries | **0/2 committed inventories; command returned 8 and 11 untracked top-level identities, 19 total.** `[measured: stated command]` |

### Rollback

Before integration, remove only the bootstrap branches/tags; existing working files remain. `[inferred]`

After integration, do not delete tracked source to undo the root. Retire the baseline tag, add a corrective commit or owner-approved replacement root, and block dependent branches until rebased onto corrected provenance. `[inferred]`

## 4.2 P0-S1 — full-GOAD first gate and truth model

### Status and SP0-01 predecessor (14NOV2026)

SP0-01's harness is implemented and reviewed. Astra R1 raised **1 HIGH, 3 MEDIUM, 1 LOW**, all fixed; Astra R2 raised no new BLOCKER/HIGH and its MEDIUM was fixed. `[recorded: ad-lab-harness/docs/reviews/PLAN003-SP0-01-CODE-REVIEW-ASTRA-R1-2026-11-14.md]` `[recorded: ad-lab-harness/docs/reviews/PLAN003-SP0-01-CODE-REVIEW-ASTRA-R2-2026-11-14.md]`

The owner-directed port targets `ad-lab-harness/adlab/provider_coexistence.py`, with logic unchanged. The port has now landed at `30bcff3` (docs at `0a38f41`); its recorded full-suite result is **47 passed**. Root `782b499` had no pre-existing regression surface; the regression manifest is this repository's own full suite. `[measured: git -C /srv/share/dev/ad-lab-harness log --oneline --all]` `[recorded: ad-lab-harness/docs/records/PLAN003-SP0-01-TEST-CARD-2026-11-14.md]`

Dry run on net0srv: **exit 2, `inconclusive` / `prerequisite_missing`**, because `VBoxManage`, `vagrant` and `vboxdrv` are absent. **P0-S1 stays BLOCKED** until the owner installs **VirtualBox 7.1 and Vagrant** and SP0-01 then passes. This pre-install dry run is a precondition check, not the SP0-01 result, and does not consume the single rerun. For SP0-01, `fail` requires the owner to name another host (C6); `inconclusive` requires fixing the prerequisite or harness cause and rerunning once, then the owner names another host if still inconclusive. P0-S1 stays blocked until a `pass`. `[recorded: owner decision C6]` `[recorded: ad-lab-harness/docs/plans/PLAN003-SP0-01-PROVIDER-COEXISTENCE-2026-11-14.md]` `[measured: dry run recorded in ad-lab-harness/docs/records/PLAN003-SP0-01-RAW-2026-11-14/port-dryrun.json]` `[recorded: ad-lab-harness/docs/records/PLAN003-SP0-01-TEST-CARD-2026-11-14.md]` `[inferred]`

### Problem and closure

There is no reproducibly built, truth-backed Windows domain lab. This sprint closes G0-01 using the fixed full `ad/GOAD` profile. `[inferred]`

### Decisions

**Gate profile:** exactly `upstream/GOAD/ad/GOAD`; no variant selector exists in the gate. `[recorded: owner decision C1]`

**Provider:** VirtualBox/Vagrant on net0srv, allowed to proceed only after SP0-01 passes. `[recorded: owner decision C6]`

**Blocked result:** P0-S1 stays `blocked` until SP0-01 returns `pass`. A `fail` requires the owner to name another host (C6). An `inconclusive` result requires fixing the prerequisite or harness cause and rerunning once; if still inconclusive, the owner names another host. The pre-install dry run does not consume that single rerun. No other provider or host work starts under this plan. `[recorded: owner decision C6]` `[recorded: ad-lab-harness/docs/plans/PLAN003-SP0-01-PROVIDER-COEXISTENCE-2026-11-14.md]` `[inferred]`

**Truth source:** construct expected truth from GOAD’s pinned `config.json`, inventory, and provider host definitions, then observe provisioned state independently. Runtime self-discovery is not the expected-truth source. `[inferred]`

**First-gate scope:** five hosts, roles, domains/forests, external trust, AD CS roles/templates, selected principals/groups, service reachability, DNS, LDAP, SMB, and WinRM positive/negative inputs. `[inferred]`

### Components and failure modes

| Repo/path | Change/command ownership | Contract affected | Introduced failure mode |
|---|---|---|---|
| `upstream/GOAD` | No edits; retain pin `74af01e`. `[inferred]` | Immutable lab definition. `[inferred]` | Local drift from the pin. `[inferred]` |
| `ad-lab-harness/adlab/provider_coexistence.py` | Implemented SP0-01 observer/runner; unchanged-logic port recorded above. `[recorded: ad-lab-harness/docs/records/PLAN003-SP0-01-TEST-CARD-2026-11-14.md]` | C6 go/no-go record. `[inferred]` | Existing libvirt state not sampled at all required points. `[inferred]` |
| `ad-lab-harness/fixtures/virtualbox-onevm/Vagrantfile` | Own the disposable one-VM Vagrant fixture used only by SP0-01. `[inferred]` | Provider coexistence input. `[inferred]` | Fixture exercises a path unlike the selected provider. `[inferred]` |
| `ad-lab-harness/docs/records/PLAN003-SP0-01-net0srv.json` | Own the coexistence result consumed by P0-S1. `[inferred]` | Predecessor decision. `[inferred]` | Missing pre/during/post KVM observations. `[inferred]` |
| `ad-lab-harness/adlab/goad_profile.py` | Parse only full GOAD metadata and normalize hosts, domains, forests, trusts, AD CS, and resources. `[inferred]` | Lab-profile contract. `[inferred]` | Parent/child and external trust are conflated. `[inferred]` |
| `ad-lab-harness/profiles/GOAD-virtualbox.json` | Own the fixed first-gate profile used by every command. `[inferred]` | Gate input. `[inferred]` | Profile points to another variant or provider. `[inferred]` |
| `ad-lab-harness/schemas/truth.schema.json` | Define expected, observed, status, evidence, and reason fields with `pass|fail|inconclusive`. `[inferred]` | Truth-comparison contract. `[inferred]` | Missing rows are silently accepted. `[inferred]` |
| `ad-lab-harness/truth/GOAD.json` | Own reviewed full-GOAD truth from pin `74af01e`. `[inferred]` | Expected lab state. `[inferred]` | Stale truth after pin change. `[inferred]` |
| `ad-lab-harness/adlab/qualify.py` | Build/observe/compare two full-GOAD runs and emit the result. `[inferred]` | First-gate command. `[inferred]` | Empty observations pass or unknown becomes absence. `[inferred]` |
| `ad-lab-harness/tests/unit/`, `ad-lab-harness/tests/lab/` | Own full-suite regression manifest, including SP0-01 and new GOAD-specific tests; no pre-existing regression surface at root `782b499`. `[recorded: ad-lab-harness/docs/records/PLAN003-SP0-01-TEST-CARD-2026-11-14.md]` `[inferred]` | Harness regression surface. `[inferred]` | A collected test is omitted from the manifest. `[inferred]` |
| `ad-lab-harness/docs/test-results/plan003-p0-s1-base.xml` | Own pytest output. `[inferred]` | Regression manifest. `[inferred]` | Results reference the wrong SHA. `[inferred]` |
| `ad-lab-harness/docs/test-results/plan003-p0-s1-live.json` | Own the gate output. `[inferred]` | Live qualification record. `[inferred]` | Result is not linked to truth/profile/run IDs. `[inferred]` |
| `ad-lab-harness/docs/records/PLAN003-P0-GOAD-GATE-<run>.json` | Own provider, GOAD pin, two rebuilds, SP0-05 disk measurements, and terminal result. `[inferred]` | Promotion record. `[inferred]` | Summary disagrees with the raw result. `[inferred]` |

### Test plan

SP0-01 predecessor command:

```bash
cd /srv/share/dev/ad-lab-harness
python3 -B adlab/provider_coexistence.py \
  --host net0srv \
  --fixture fixtures/virtualbox-onevm/Vagrantfile \
  --result docs/records/PLAN003-SP0-01-net0srv.json
```

P0-S1 regression command (the repository's own full suite, not a borrowed suite):

```bash
cd /srv/share/dev/ad-lab-harness
PYTHONDONTWRITEBYTECODE=1 python3 -B -m pytest -q -p no:cacheprovider \
  --junitxml=docs/test-results/plan003-p0-s1-base.xml
```

Fixed full-GOAD gate command:

```bash
cd /srv/share/dev/ad-lab-harness
python3 -B adlab/qualify.py \
  --profile profiles/GOAD-virtualbox.json \
  --truth truth/GOAD.json \
  --result docs/test-results/plan003-p0-s1-live.json
```

These are proposed execution commands. `[inferred]`

New acceptance:

- Parse every truth field from fixture copies at pin `74af01e`. `[inferred]`
- Assert exact host/domain/forest/trust/AD-CS denominators for full GOAD. `[inferred]`
- Reject profiles referencing anything other than `ad/GOAD` and VirtualBox. `[inferred]`
- Reject truth with zero expected hosts, domains, observers, or AD CS rows. `[inferred]`
- Compare two clean rebuild observations and require stable logical identities. `[inferred]`
- Record SP0-05 disk consumption after both builds. `[inferred]`

RED proof:

- Change `essos.local` to a different wrong-but-present domain and require an exact mismatch. `[inferred]`
- Add an unexpected CA and require the “no unexpected CA” assertion to fail; pair it with presence assertions for every expected CA. `[inferred]`
- Remove all observations and require `inconclusive`. `[inferred]`
- Change one trust direction while leaving a trust present and require failure. `[inferred]`
- Change the profile path to GOAD-Light and require profile validation failure before any build. `[inferred]`

### Baselines

These values preserve the initial r2 starting snapshot; the commands/directories below are mapped to the new harness for execution-start refresh, not represented as new measurements. The current SP0-01 dry-run record is cited above and is inconclusive, so it does not qualify P0-S1. `[recorded: PLAN-003 r2 initial baselines]` `[inferred]`

| Metric | Exact command and working directory | Inputs and denominator | Baseline |
|---|---|---|---|
| Passed full-GOAD gate records | `find docs/records -maxdepth 1 -type f -name 'PLAN003-P0-GOAD-GATE-*.json' -print \| wc -l` in `/srv/share/dev/ad-lab-harness` | Passed records; denominator one required first gate | **0 measured.** `[measured: stated command]` |
| Machine-readable full-GOAD truth manifests | `find truth -maxdepth 1 -type f -name 'GOAD.json' -print \| wc -l` in `/srv/share/dev/ad-lab-harness` | One required manifest | **0/1 measured.** `[measured: stated command]` |
| Provider coexistence records | `find docs/records -maxdepth 1 -type f -name 'PLAN003-SP0-01-*.json' -print \| wc -l` in `/srv/share/dev/ad-lab-harness` | One required SP0-01 result | **0/1 measured.** `[measured: stated command]` |

### Rollback

Before integration, discard the ad-lab-harness branch and power off the test VMs; retain raw measurements until review completes. `[inferred]`

After integration, revert the qualification-harness commit and mark the gate record superseded. VM removal is a separate lab-cleanup decision. `[inferred]`

## 4.3 P0-S2 — ACL-first writable-path contract

### Problem and closure

The complete current inventory contains six target-side writer sites across five PowerShell files: three default probes and three opt-in output sinks. This sprint closes G5-04, replaces all default probes with effective-rights evaluation, and places every remaining target writer behind one explicit C3 authorization contract. `[measured: §3.7 repo-wide sweep]` `[inferred]`

### Decisions

**Effective-rights method:** use the API selected by SP0-04. The planned selection is Authz; the named rejected method and flip evidence are in §3.8. `[inferred]`

**Shared implementation:** all three writability collectors import one `EffectiveRights.ps1` library rather than retaining independent ACE logic. Optional creation-based validation is centralized in that library and is unreachable without `-WriteValidate`. `[inferred]`

**Flag contract:** Aranum’s Python CLIs expose `--write`; PowerShell receives `-WriteValidate`. Default mode has no reachable target-side file creation. `[inferred]`

**Output-sink decision:** the existing `-OutFile` parameters are destination selectors, not sufficient authorization under C3. `Invoke-PrivEscEnum.ps1`, `Get-ThickClientEnum.ps1`, and `Get-WeakPassword.ps1` must refuse target output unless both the destination parameter and `-WriteValidate` are present. Python-driven execution sets `-WriteValidate` only from explicit `--write`. `[recorded: owner decision C3]` `[inferred]`

**Inventory contract:** a canonical repo-wide scanner and classification manifest use set equality. A writer is not accepted merely because it was not part of the original six-site baseline. `[inferred]`

### Components and failure modes

| Repo/path | Change/command ownership | Contract affected | Introduced failure mode |
|---|---|---|---|
| `aranum/standalones/windows/EffectiveRights.ps1` | Add the SP0-04-selected Authz/AccessCheck wrapper, normalized result, and sole optional validation writer guarded by `-WriteValidate`. `[inferred]` | Shared effective-rights and validation contract. `[inferred]` | Incorrect access mask, API cleanup, or validation writer reachable without authorization. `[inferred]` |
| `aranum/standalones/windows/Get-UnquotedServices.ps1` | Remove the direct temporary-file probe; use shared rights and optional shared validation. `[inferred]` | Unquoted-service result/write mode. `[inferred]` | Candidate parent classified incorrectly. `[inferred]` |
| `aranum/standalones/windows/Get-WritablePathDirs.ps1` | Remove the direct `.write_test` probe; use shared rights and optional shared validation. `[inferred]` | PATH result/write mode. `[inferred]` | Standalone result diverges from aggregate collector. `[inferred]` |
| `aranum/standalones/windows/Invoke-PrivEscEnum.ps1` | Remove the embedded probe; require `-WriteValidate` for shared validation and transcript output. `[inferred]` | Primary Windows collector. `[inferred]` | Full WinRM payload retains an ungated writer. `[inferred]` |
| `aranum/standalones/windows/Get-ThickClientEnum.ps1` | Require both `-OutFile` and `-WriteValidate` for its target-side output sink. `[inferred]` | Workstation collector output. `[inferred]` | Direct invocation bypasses the unified contract. `[inferred]` |
| `aranum/standalones/passwords/Get-WeakPassword.ps1` | Retain read-only scanning by default; require both `-OutFile` and `-WriteValidate` for `Export-Csv`. `[inferred]` | Password-compliance output. `[inferred]` | Direct invocation writes with only `-OutFile`. `[inferred]` |
| `aranum/aranumtoolkit/network/bulk-enum-windows.py` | Add `--write`, pass `-WriteValidate`, and record mode in `_meta.json`. `[inferred]` | Windows bulk invocation. `[inferred]` | Flag accepted but not applied. `[inferred]` |
| `aranum/aranumtoolkit/network/local-enum.py` | Pass write mode only when requested; include it in dry-run rows and metadata; verify the compact probe remains writer-free. `[inferred]` | Local-access invocation. `[inferred]` | Consent state is lost between dispatcher and transport. `[inferred]` |
| `aranum/aranum.py` | Add `--write` to the correct Windows local/bulk partition. `[inferred]` | Unified CLI. `[inferred]` | Flag reaches unrelated commands or is dropped. `[inferred]` |
| `aranum/standalones/windows/README.md`, `aranum/wiki/windows.md` | Document default effective-rights behavior, output-destination semantics, and explicit write mode. `[inferred]` | Operator-visible behavior. `[inferred]` | Documentation differs from flag plumbing. `[inferred]` |
| `aranum/aranumtoolkit/tests/writer_inventory.py` | Own the canonical candidate signature from §3.7, inspect executable candidates, and emit stable writer identities plus recorded non-writer exclusions. `[inferred]` | Repo-wide classification gate. `[inferred]` | Positional cmdlet, .NET stream, or redirection writer is missed. `[inferred]` |
| `aranum/aranumtoolkit/tests/writer-sites.tsv` | Record each writer’s stable identity, execution side, exactly one allowed category, guard, and disposition; separately record the read-only `FileStream` exclusion with evidence. `[inferred]` | Exhaustive writer inventory. `[inferred]` | New writer or stale classification passes silently. `[inferred]` |
| `aranum/aranumtoolkit/tests/test_acl_effective_rights.ps1` | Own Authz/AccessCheck fixture cases. `[inferred]` | API regression. `[inferred]` | Fixtures omit deny/inheritance/group cases. `[inferred]` |
| `aranum/aranumtoolkit/tests/test_write_contract.py` | Re-run the canonical sweep, require set equality with `writer-sites.tsv`, and test Python/PowerShell flag propagation. `[inferred]` | C3 regression. `[inferred]` | Empty scan or unclassified writer passes. `[inferred]` |
| `aranum/aranumtoolkit/tests/run_live_write_gate.py` | Own the live GOAD before/after observation. `[inferred]` | Live C3 acceptance. `[inferred]` | Filesystem observer cannot distinguish default and explicit modes. `[inferred]` |
| `aranum/aranumtoolkit/tests/` | Existing `unittest` and `pytest` discovery root. `[verified: path]` | Existing regression suite input. `[inferred]` | Existing failures are omitted from the sprint record. `[inferred]` |
| `aranum/aranumtoolkit/tests/smoke.sh` | Existing smoke command input. `[verified: path]` | Aranum smoke regression. `[inferred]` | Smoke result is not captured. `[inferred]` |
| `aranum/aranumtoolkit/tests/data_audit.py` | Existing data-audit command input. `[verified: path]` | Aranum data regression. `[inferred]` | Data-audit result is not captured. `[inferred]` |
| `ad-lab-harness/profiles/GOAD-virtualbox.json` | P0-S1-owned external live-gate input; P0-S2 consumes but does not modify it. `[inferred]` | Qualified Windows target selection. `[inferred]` | Live gate runs against an unqualified profile. `[inferred]` |
| `aranum/docs/test-strategy/raw/plan003/p0-s2/` | Own `base-unittest.log`, `base.xml`, `smoke.log`, `data-audit.log`, `writer-inventory.tsv`, `effective-rights.json`, and `live-write-gate.json`. `[inferred]` | All sprint command outputs. `[inferred]` | Outputs reference the wrong decision record/SHA. `[inferred]` |
| `aranum/docs/decisions/PLAN003-SP0-04-effective-rights.md` | Own the prerequisite API comparison/selection. `[inferred]` | Implementation decision. `[inferred]` | Implementation begins before selection. `[inferred]` |

### Test plan

Existing regression:

```bash
cd /srv/share/dev/aranum
python3 -m unittest discover -s aranumtoolkit/tests -v \
  | tee docs/test-strategy/raw/plan003/p0-s2/base-unittest.log
python3 -m pytest aranumtoolkit/tests -v -rA \
  --junitxml=docs/test-strategy/raw/plan003/p0-s2/base.xml
bash aranumtoolkit/tests/smoke.sh \
  | tee docs/test-strategy/raw/plan003/p0-s2/smoke.log
python3 aranumtoolkit/tests/data_audit.py \
  | tee docs/test-strategy/raw/plan003/p0-s2/data-audit.log
```

Classification/API/static gate:

```bash
cd /srv/share/dev/aranum
python3 aranumtoolkit/tests/writer_inventory.py \
  --root /srv/share/dev/aranum \
  --classifications aranumtoolkit/tests/writer-sites.tsv \
  --output docs/test-strategy/raw/plan003/p0-s2/writer-inventory.tsv
pwsh -NoProfile -File aranumtoolkit/tests/test_acl_effective_rights.ps1 \
  -Output docs/test-strategy/raw/plan003/p0-s2/effective-rights.json
python3 -m pytest \
  aranumtoolkit/tests/test_write_contract.py -q
```

Live gate after P0-S1 and SP0-04:

```bash
cd /srv/share/dev/aranum
python3 aranumtoolkit/tests/run_live_write_gate.py \
  --profile /srv/share/dev/ad-lab-harness/profiles/GOAD-virtualbox.json \
  --decision docs/decisions/PLAN003-SP0-04-effective-rights.md \
  --result docs/test-strategy/raw/plan003/p0-s2/live-write-gate.json
```

These are proposed execution commands. `[inferred]`

New acceptance:

- The canonical sweep covers every production `*.ps1`/`*.psm1` under the repository and excludes only `tests/` and `fixtures/`. `[inferred]`
- Every executable candidate is either a writer with exactly one of `default-probe|opt-in-output|write-gated|operator-side`, or a separately reviewed non-writer exclusion with semantic evidence such as `FileAccess.Read`. `[inferred]`
- The emitted writer set and `writer-sites.tsv` are exactly equal; duplicate, unknown, missing, or multiply classified identities fail. `[inferred]`
- The gate asserts the six measured pre-migration identities are present in the baseline fixture. After migration it asserts the three retained output identities and shared validation identity are present; an empty scan cannot pass. `[inferred]`
- No `default-probe` or ungated `opt-in-output` category remains at sprint exit. `[inferred]`
- Explicit allow, explicit deny, inherited allow, group allow, mixed ordering, null DACL, and unavailable descriptor cases are covered. `[inferred]`
- All three writability collectors return the same normalized result for the same descriptor/token fixture. `[inferred]`
- Default full WinRM and standalone payloads contain no reachable target writer. `[inferred]`
- The compact probe remains target-writer-free. `[inferred]`
- Default and explicit modes are separately recorded in metadata. `[inferred]`

RED proof:

- In a pytest-created disposable source tree, add a wrong-but-present writer using one of the covered APIs without adding a classification row; the classification gate must fail `unclassified writer`. The disposable tree is removed by the test fixture. `[inferred]`
- Run the same mutation while removing all known writer fixtures; the independent presence assertion must fail before absence could be mistaken for success. `[inferred]`
- Leave `-WriteValidate` declared but remove its conditional from one retained output writer; the static and live default-mode gates must fail. `[inferred]`
- Supply `-OutFile` without `-WriteValidate` to each output sink and require refusal with no target file; then supply both under explicit mode and require the separately observed validation write. `[inferred]`
- Ignore a deny ACE and require the fixture to fail. `[inferred]`
- Pair “no target file created” with presence assertions that directories were enumerated and the seeded writable directory was classified. `[inferred]`
- If process/filesystem observation is unavailable, the live result is `inconclusive`. `[inferred]`

### Baselines

| Metric | Exact command and working directory | Inputs and denominator | Baseline |
|---|---|---|---|
| Default write-probe implementations avoiding creation | `rg -l --glob '*.ps1' 'WriteAllText\|\.write_test\|Test-Writable' standalones/windows \| wc -l` in `/srv/share/dev/aranum` | Three identified default-probe files | **0/3 avoid creation; three files match.** `[measured: stated command]` |
| Current target-side writer sites and existing `WriteValidate` references | `rg -n --pcre2 --glob '*.ps1' --glob '*.psm1' --glob '!**/tests/**' --glob '!**/fixtures/**' -e '(?i)\[(?:System\.)?IO\.File\]::(?:WriteAllText\|WriteAllBytes\|WriteAllLines\|AppendAllText)\b' -e '(?i)\b(?:New-Item\|Set-Content\|Add-Content\|Out-File\|Export-Csv\|Export-Clixml\|Start-Transcript\|Tee-Object\|Copy-Item\|Move-Item)\b(?=[^#\r\n]*(?:-(?:Path\|LiteralPath\|FilePath\|Destination\|ItemType)\b))' -e '(?i)\b(?:StreamWriter\|FileStream)\b(?=[^#\r\n]*(?:FileAccess\]::Write\|FileMode\]::(?:Create\|CreateNew\|Append\|OpenOrCreate)))' -e '(?i)^(?!\s*(?:#\|"))[^\r\n]*?(?<=\s)(?:\*\|[1-6])?>>?\s*(?!\$null\b)(?=\S)' /srv/share/dev/aranum \| wc -l; rg -n --glob '*.ps1' --glob '*.psm1' --glob '!**/tests/**' --glob '!**/fixtures/**' '\bWriteValidate\b' /srv/share/dev/aranum \| wc -l` from any directory | Six current target-side writer sites and their unified authorization guard | **6 writers; 0 `WriteValidate` references; 0/6 currently unified-gated.** `[measured: stated command]` |
| Payload-family writer counts | `for file in standalones/windows/Invoke-HostPosture.ps1 standalones/windows/Invoke-PrivEscEnum.ps1; do count=$(rg -n --pcre2 -e '(?i)\[(?:System\.)?IO\.File\]::(?:WriteAllText\|WriteAllBytes\|WriteAllLines\|AppendAllText)\b' -e '(?i)\b(?:New-Item\|Set-Content\|Add-Content\|Out-File\|Export-Csv\|Export-Clixml\|Start-Transcript\|Tee-Object\|Copy-Item\|Move-Item)\b(?=[^#\r\n]*(?:-(?:Path\|LiteralPath\|FilePath\|Destination\|ItemType)\b))' "$file" \| wc -l); printf '%s %s\n' "$file" "$count"; done` in `/srv/share/dev/aranum` | Compact and full payload source families | **Compact `0`; full `2` current writer sites.** `[measured: stated command]` |

### Rollback

Before integration, discard the Aranum branch and fixtures. `[inferred]`

After integration, revert the sprint commit only for comparison and mark the prior collector unqualified for Phase 0; rollback may not be used to claim C3 compliance. `[inferred]`

## 4.4 P0-S3 — pinned offline attack-box definition

### Problem and closure

The current provisioner vendors Python-oriented source and wheels but omits native AD clients, collectors, and BloodHound CE; it clones repository HEADs and treats native dependencies as prerequisites. This closes G0-02, G0-04, and G3-01. `[verified: /srv/share/dev/pt_provision/README.md]` `[verified: /srv/share/dev/pt_provision/config/repositories.tsv]` `[verified: /srv/share/dev/pt_provision/deploy.sh]`

### Decisions

**Base distribution:** pinned Debian stable, with the exact release/snapshot selected by SP0-02 before implementation. `[inferred]`

**Native dependencies:** bundle exact `.deb` identities and an offline package index. Preinstalling dependencies outside the release is rejected because it cannot qualify a fresh box. `[inferred]`

**Lock shape:** `config/ad-attack-box.lock.toml` is authoritative and references normalized subordinate locks for sources, OS packages, Python artifacts, standalone binaries, and OCI images. Independent locks without a root digest are rejected because they can be mixed. `[inferred]`

**Collectors:** RustHound-CE primary and BloodHound CE Python fallback; legacy BloodHound is compatibility-only and outside the 17-capability gate. `[recorded: /srv/share/dev/28julytoolkit/ad-modern/bloodhound-collectors/docs/README.md]` `[inferred]`

**BloodHound CE:** use the pinned official three-service Compose composition selected in §3.9 and finalized by SP0-03. `[inferred]`

**Deployment form:** retain the provisioner’s bundle model and add pinned base/native/OCI inputs. A prebuilt appliance is rejected initially because the current builder already has build, manifest, unpack, and offline Python reconstruction contracts. `[verified: /srv/share/dev/pt_provision/README.md]` `[inferred]`

**Runtime manifest contract:** `deploy.sh` generates normalized `manifest/build.json` inside the release from `ad-attack-box.lock.toml` and every referenced subordinate lock, and emits an identical external sidecar via `--manifest-out`. During real bootstrap, `templates/bootstrap.sh` copies that released member verbatim to `/mnt/attack-box/manifest/build.json`. P0-S4 proves the installed file’s identity; P0-S5 consumes that exact path. `[inferred]`

### Components and failure modes

| Repo/path | Change/command ownership | Contract affected | Introduced failure mode |
|---|---|---|---|
| `pt_provision/config/ad-attack-box.lock.toml` | Root lock with schema, base identity, architecture, subordinate digests, 17 capability IDs and the exact planned deterministic stage-command manifest consumed by the SDK-absence test. `[inferred]` | Reproducible input contract. `[inferred]` | Root references mismatched subordinate locks. `[inferred]` |
| `pt_provision/config/repositories.tsv` | Add exact revision/tree fields and versioned `28julytoolkit` input. `[inferred]` | Source resolution. `[inferred]` | Requested revision resolves to another tree. `[inferred]` |
| `pt_provision/config/base-os.lock` | Own SP0-02-selected Debian base and repository snapshot facts. `[inferred]` | Qualification base. `[inferred]` | Base and package set disagree. `[inferred]` |
| `pt_provision/config/os-packages.lock` | Exact native package identities and offline index metadata. `[inferred]` | Native capability availability. `[inferred]` | Architecture/release mismatch. `[inferred]` |
| `pt_provision/config/python-tools.lock` | Exact wheels/sdists and target compatibility. `[inferred]` | Python capability availability. `[inferred]` | Wheel incompatible with target Python/architecture. `[inferred]` |
| `pt_provision/config/binaries.lock` | RustHound and standalone binary identities. `[inferred]` | Static capability availability. `[inferred]` | Binary is wrong architecture or not runnable. `[inferred]` |
| `pt_provision/config/bloodhound-compose.yml` | Pinned official three-service composition from SP0-03. `[inferred]` | Offline graph-service topology. `[inferred]` | Composition and image lock diverge. `[inferred]` |
| `pt_provision/config/oci-images.lock` | Exact PostgreSQL, Neo4j, and BloodHound CE image digests/archive names. `[inferred]` | Offline service inputs. `[inferred]` | Missing/incompatible archive. `[inferred]` |
| `pt_provision/config/engagement-profile.example.yaml` | Own the C4 null configuration example. `[inferred]` | Engagement configuration. `[inferred]` | A null field receives an invented value. `[inferred]` |
| `pt_provision/deploy.sh` | Resolve only locked inputs; add `--lock` and `--manifest-out`; generate bundle member `manifest/build.json` and an identical external sidecar from the root/subordinate locks. `[inferred]` | Bundle builder, runtime-manifest producer, and P0-S4 sidecar contract. `[inferred]` | A consumed input is absent from either manifest or the two copies differ. `[inferred]` |
| Bundle member `manifest/build.json` | Generated in P0-S3 by `deploy.sh`; immutable input to unpack/bootstrap and source for the installed runtime manifest. `[inferred]` | Build identity handoff. `[inferred]` | Bundle lacks the normalized identity consumed by later stages. `[inferred]` |
| `pt_provision/templates/bootstrap.sh` | Install native/Python artifacts, load all three OCI archives, and copy bundle member `manifest/build.json` to `/mnt/attack-box/manifest/build.json` during the real qualified bootstrap. `[inferred]` | Fresh-box installation and exact runtime-manifest path. `[inferred]` | Bootstrap omits or transforms the runtime manifest. `[inferred]` |
| `/mnt/attack-box/manifest/build.json` | Installed by `templates/bootstrap.sh` from the released bundle member; verified by P0-S4 and read-only input to P0-S5. `[inferred]` | Installed build identity. `[inferred]` | P0-S5 consumes an unproduced or unrelated path. `[inferred]` |
| `pt_provision/templates/offline-smoke.sh` | Check 17 capabilities, service health, collector startup, fixture import/query, PurpleSploit import, and report rendering through deterministic direct interfaces; expose the same commands to the SDK-absence test below. `[inferred]` | Post-bootstrap acceptance. `[inferred]` | Presence-only shim passes. `[inferred]` |
| `pt_provision/tests/test-deploy.sh` | Existing fixture regression extended for the root lock/manifest contract. `[inferred]` | Regression gate. `[inferred]` | Fixture does not cover a new artifact class. `[inferred]` |
| `pt_provision/tests/test-locks.sh` | New lock/identity/denominator tests. `[inferred]` | Lock validation. `[inferred]` | Valid-looking mixed locks pass. `[inferred]` |
| `pt_provision/tests/test-offline-smoke.sh` | Fixture-only smoke regression plus the C7 `--sdk-absent --commands-from-lock` mode below; never a release promotion oracle. `[inferred]` | Smoke harness regression. `[inferred]` | Fixture-only result is confused with real installation. `[inferred]` |
| `pt_provision/tests/test-manifest.py` | Validate root lock, generated bundle/runtime-manifest fields, and 17-capability mapping. `[inferred]` | Capability and manifest denominator. `[inferred]` | Duplicate capability IDs or missing install-path facts pass. `[inferred]` |
| `pt_provision/docs/test-strategy/raw/plan003/p0-s3/` | Own `test-deploy.log`, `test-locks.log`, `fixture-smoke.log`, `sdk-absent.json`, and `manifest.json`. `[inferred]` | All sprint test outputs. `[inferred]` | Output references the wrong lock/SHA. `[inferred]` |
| `pt_provision/docs/decisions/PLAN003-SP0-02-base.md`, `PLAN003-SP0-03-bhce.md` | Own predecessor decisions. `[inferred]` | Implementation inputs. `[inferred]` | Implementation starts before a decision is final. `[inferred]` |

C4 remains represented as:

```yaml
lockout_threshold: null
lockout_window: null
traffic_budget:
  per_principal: null
  per_subnet: null
  per_service: null
  per_hour: null
```

The file owning this example is `config/engagement-profile.example.yaml`, and null account-use values cannot enable account-use automation. `[inferred]`

### Test plan

```bash
cd /srv/share/dev/pt_provision
bash tests/test-deploy.sh \
  | tee docs/test-strategy/raw/plan003/p0-s3/test-deploy.log
bash tests/test-locks.sh \
  | tee docs/test-strategy/raw/plan003/p0-s3/test-locks.log
bash tests/test-offline-smoke.sh --fixture-only \
  | tee docs/test-strategy/raw/plan003/p0-s3/fixture-smoke.log
python3 tests/test-manifest.py \
  --lock config/ad-attack-box.lock.toml \
  --output docs/test-strategy/raw/plan003/p0-s3/manifest.json
```

These fixture commands test the builder and harness but cannot promote P0-S3 or P0-S4 as an offline release. `[inferred]`

| Additional test | Command, observation and required result |
|---|---|
| C7 — planned command chain with provider SDKs absent | From `/srv/share/dev/pt_provision`, run proposed `bash tests/test-offline-smoke.sh --sdk-absent --commands-from-lock config/ad-attack-box.lock.toml --output docs/test-strategy/raw/plan003/p0-s3/sdk-absent.json`. In a clean offline Python environment, assert that the attack-box environment leaves `PURPLESPLOIT_AI_PROVIDER` unset (even an empty value fails) and positively establish that both `openai` and `anthropic` distributions and import specs are absent; run every command in the lock's planned chain through its real installed entrypoint/direct interface over recorded GOAD fixtures, covering console startup/module discovery, no-credentials enumeration, low-privilege enumeration, collector/ingest/query, deterministic path ranking, local access/checks, import and report rendering. After real console startup, assert `console.services.advisory.provider is None`; any configured provider fails this test. Instrument imports and excluded entrypoints before application startup in every Python process, including children; any invocation of `AdvisoryProvider.generate`, `AdvisoryService.analyze`/`propose_workflow`, or `purplesploit.modules.ai.ai_automation` operations during the planned chain fails this test, including local fallbacks. Any attempted import of either SDK fails this test even if application code catches `ImportError` and reports success. Require a non-empty command manifest, exact planned-command coverage and successful functional receipts, including a rendered report; missing observations are inconclusive. Prove the check detects an import by adding a test-only `import openai` and then `import anthropic` separately to a disposable copy of a planned command: each run must fail, then the restored chain must pass. Use the existing direct stage interfaces available at P0-S3; refresh this same test when a later sprint adds or changes planned commands. This creates no prerequisite on later production adapters and leaves P0-S4's pristine-VM release gate intact. `[recorded: owner directive C7, 14NOV2026]` `[inferred]` |

New gates:

- All 17 capability IDs exist exactly once and resolve to an artifact/package/runtime entry. `[inferred]`
- Every repository resolves the exact requested revision and tree identity. `[inferred]`
- Native packages install from the bundled package index in a fixture with networking unavailable. `[inferred]`
- All three OCI archives load from bundled files. `[inferred]`
- Functional version/help/import/health probes execute; `command -v` alone is insufficient. `[inferred]`
- Internal and external build manifests describe the same inputs/content. `[inferred]`
- The bundle contains `manifest/build.json`, and bootstrap maps it to exactly `/mnt/attack-box/manifest/build.json`. `[inferred]`

RED proof:

- Substitute another valid commit and require tree-identity failure. `[inferred]`
- Replace an OCI archive or RustHound binary with wrong-but-present bytes and require identity/execution failure. `[inferred]`
- Remove one capability while leaving the manifest non-empty; retain denominator 17 and identify the missing row. `[inferred]`
- Replace the bundle member with a wrong-but-present manifest and require the internal/sidecar comparison to fail. `[inferred]`
- Pair no-network assertions with consumption receipts for the package index, wheelhouse, standalone binaries, and all three OCI archives. `[inferred]`

### Baselines

| Metric | Exact command and working directory | Inputs and denominator | Baseline |
|---|---|---|---|
| Required capability identities directly represented | `awk -F '\t' '$1=="purplesploit" || $1=="aranum" {n++} END{print n+0}' config/repositories.tsv` in `/srv/share/dev/pt_provision` | Current manifest versus 17 capabilities | **2/17 measured.** `[measured: stated command]` |
| Repository rows with requested revision/tree fields | `awk -F '\t' '!/^#/ && NF && NF>=7 {n++} END{print n+0}' config/repositories.tsv` in `/srv/share/dev/pt_provision` | Seven repository rows | **0/7 measured.** `[measured: stated command]` |
| BloodHound CE service definitions | `find . -type f \( -iname '*compose*.yml' -o -iname '*compose*.yaml' -o -iname '*bloodhound*' -o -iname '*oci-images*' \) -print \| wc -l` in `/srv/share/dev/pt_provision` | One composition plus three image identities required | **0 definitions measured.** `[measured: stated command]` |
| `28julytoolkit` source base | `git rev-parse --verify HEAD` in `/srv/share/dev/28julytoolkit` | One source base | **Initial r2 baseline: no SHA; command returned status 128.** `[measured: stated command, initial r2 baseline]` Current root `195acd2`, `main` `2f0dede`; P0-S0 toolkit half DONE. `[measured: git -C /srv/share/dev/28julytoolkit rev-parse HEAD plan003-p0-source-base^{commit}, 14NOV2026]` |

### Rollback

Before integration, discard the feature branch; the P0-S0 provenance root remains. `[inferred]`

After integration, revert the provisioner/lock commit and mark bundles produced from it unqualified. Existing non-AD behavior remains available from the parent commit. `[inferred]`

## 4.5 P0-S4 — reproducible offline release

### Problem and closure

The only existing bundle is dated `20260915T023140Z`, is 617,833,472 bytes, and has SHA-256 `b8303563269f7a66cdc2cff3dd03f56b7055c7b376d72578b1fda382c60516b3`; it predates the current integration. This closes G0-03. `[measured: stat and sha256sum on /srv/share/dev/pt_provision/pt-offline-bundle-20260915T023140Z.tar.gz.enc]` `[recorded: owner brief, 14NOV2026]`

### Decisions

**Reproducibility oracle:** compare normalized sidecar build manifests and unencrypted content identities across two builds, not encrypted archive bytes. `[inferred]`

**Release storage:** store the large bundle outside Git and commit only its reproducibility/release record. `[inferred]`

**Acceptance environment:** start from a pristine VM matching `base-os.lock`, attach only the release artifact, disconnect upstream connectivity before unpack/bootstrap, run the real bundled `bootstrap.sh`, then start BloodHound CE and perform collector/import/query/report probes. `[inferred]`

A prepared VM, host package cache, preloaded image store, or fixture-only bootstrap cannot promote the release. `[inferred]`

**Manifest installation proof:** the real bootstrap must install the released `manifest/build.json` at `/mnt/attack-box/manifest/build.json`, and the qualification receipt must prove it is identical to the Build A sidecar before P0-S5 may consume it. `[inferred]`

### Components and failure modes

| Repo/path | Change/command ownership | Contract affected | Introduced failure mode |
|---|---|---|---|
| `pt_provision/deploy.sh` | P0-S3-owned `--manifest-out` emits `$BUILD_DIR/build.json` plus identical bundle member `manifest/build.json`. `[inferred]` | External comparison and runtime-manifest source. `[inferred]` | Sidecar differs from archived manifest. `[inferred]` |
| `pt_provision/unpack.sh` | Existing real archive extraction command used by qualification. `[verified: path]` | Release extraction. `[inferred]` | Harness bypasses the released unpack path. `[inferred]` |
| `pt_provision/tests/compare-build-manifests.py` | Compare sources, packages, wheels, binaries, OCI images, compose revision, and content hashes. `[inferred]` | Two-build oracle. `[inferred]` | Meaningful field excluded. `[inferred]` |
| `pt_provision/qualification/run-offline-vm.py` | Create/reset pristine VM, attach bundle only, remove upstream route, execute real unpack/bootstrap/smoke, verify `/mnt/attack-box/manifest/build.json`, and collect receipts. `[inferred]` | C2 promotion gate and installed-manifest proof. `[inferred]` | Route is removed after bootstrap, a host cache remains visible, or manifest installation is skipped. `[inferred]` |
| `pt_provision/qualification/offline-vm-profile.json` | Own base-lock reference, lab route/DNS expectation, allowed attachment, bootstrap/smoke paths, and the exact installed-manifest destination. `[inferred]` | Qualification input. `[inferred]` | Profile permits extra cache/media or another manifest path. `[inferred]` |
| `/mnt/attack-box/manifest/build.json` | P0-S3-produced runtime artifact installed by real bootstrap and verified against Build A’s sidecar. `[inferred]` | P0-S5 build-identity input. `[inferred]` | Runtime identity is absent or unrelated to the release. `[inferred]` |
| `pt_provision/docs/test-strategy/raw/plan003/p0-s4/build-compare.json` | Own two-build comparison output. `[inferred]` | Reproducibility record. `[inferred]` | Output references wrong sidecars. `[inferred]` |
| `pt_provision/docs/test-strategy/raw/plan003/p0-s4/offline-vm.json` | Own route, artifact-consumption, runtime-manifest, service, import, query, and report receipts. `[inferred]` | Offline acceptance record. `[inferred]` | Missing stage becomes success. `[inferred]` |
| `pt_provision/releases/PLAN003-P0-<release>.json` | Own artifact checksum, lock digest, compatibility facts, and qualification result. `[inferred]` | Release record. `[inferred]` | Record points to another artifact. `[inferred]` |
| External build directories | Own Build A/Build B archives and `build.json` sidecars under `/var/tmp/plan003-build-a.XXXXXX` and `/var/tmp/plan003-build-b.XXXXXX` until comparison. `[inferred]` | Candidate artifacts. `[inferred]` | Candidate identity is confused. `[inferred]` |

### Test and release plan

Builder regression:

```bash
cd /srv/share/dev/pt_provision
bash tests/test-deploy.sh
bash tests/test-locks.sh
bash tests/test-offline-smoke.sh --fixture-only
```

The fixture-only command remains regression evidence and cannot promote the release. `[inferred]`

Two real builds:

```bash
cd /srv/share/dev/pt_provision
PLAN003_BUILD_A="$(mktemp -d /var/tmp/plan003-build-a.XXXXXX)"
PLAN003_BUILD_B="$(mktemp -d /var/tmp/plan003-build-b.XXXXXX)"

./deploy.sh --offline \
  --lock config/ad-attack-box.lock.toml \
  --path "$PLAN003_BUILD_A" \
  --manifest-out "$PLAN003_BUILD_A/build.json"

./deploy.sh --offline \
  --lock config/ad-attack-box.lock.toml \
  --path "$PLAN003_BUILD_B" \
  --manifest-out "$PLAN003_BUILD_B/build.json"

python3 tests/compare-build-manifests.py \
  "$PLAN003_BUILD_A/build.json" \
  "$PLAN003_BUILD_B/build.json" \
  --output docs/test-strategy/raw/plan003/p0-s4/build-compare.json
```

Real pristine-VM qualification:

```bash
cd /srv/share/dev/pt_provision
python3 qualification/run-offline-vm.py \
  --profile qualification/offline-vm-profile.json \
  --base-lock config/base-os.lock \
  --bundle-dir "$PLAN003_BUILD_A" \
  --result docs/test-strategy/raw/plan003/p0-s4/offline-vm.json
```

These are proposed execution commands. `[inferred]`

The qualification harness must enforce this order:

1. Reset/create the VM from the pinned pristine base. `[inferred]`
2. Confirm that no `pt_provision` packages, wheelhouse, BloodHound images, previous bundle, or installed PLAN-003 manifest are present. `[inferred]`
3. Attach only the released encrypted bundle, checksum, and released `unpack.sh`. `[inferred]`
4. Remove upstream/default connectivity while retaining only the declared lab route and DNS. `[inferred]`
5. Prove upstream/default connectivity is absent before extraction or bootstrap. `[inferred]`
6. Run the released `unpack.sh`, then the released real `bootstrap.sh`; do not call a fixture bootstrap. `[inferred]`
7. Assert consumption receipts for the offline package index, wheelhouse, standalone binaries, compose file, and all three OCI archives. `[inferred]`
8. Assert `/mnt/attack-box/manifest/build.json` exists and is identical to the released bundle member and Build A sidecar. `[inferred]`
9. Start the released BloodHound CE composition and require all three services to become healthy. `[inferred]`
10. Run collector recognition, fixture collection import/query, PurpleSploit import, and report rendering. `[inferred]`
11. Run `offline-smoke.sh` as the post-bootstrap functional check and store its JUnit/result data inside the release record. `[inferred]`

RED proof:

- Add a wrong-but-present default route and require failure; pair it with a positive lab-route assertion. `[inferred]`
- Preload one required OCI image in the base VM and require the pristine-base assertion to fail. `[inferred]`
- Mutate one package identity between build manifests and require comparison failure. `[inferred]`
- Replace an executable with a shim that prints a version but fails its functional probe. `[inferred]`
- Remove the fixture collection while leaving BloodHound healthy; import/query must fail. `[inferred]`
- Install a wrong-but-present runtime manifest and require the sidecar/runtime identity assertion to fail. `[inferred]`
- Run bootstrap before disconnection in a mutation fixture and require ordering failure. `[inferred]`
- If route, cache, manifest, or consumption state cannot be observed, the result is `inconclusive`. `[inferred]`

### Baselines

| Metric | Exact command and working directory | Inputs and denominator | Baseline |
|---|---|---|---|
| Current-chain qualified release records | `find releases -maxdepth 1 -type f -name 'PLAN003-P0-*.json' -print \| wc -l` in `/srv/share/dev/pt_provision` | One required current-chain release record | **0 measured.** `[measured: stated command]` |
| Same-lock build pairs with identical normalized identities | Deferred: `tests/compare-build-manifests.py` does not exist and two builds were prohibited during planning. The future exact command is the two-sidecar comparison above. | One Build A/Build B pair | **Deferred/unknown; no zero is inferred.** `[recorded: owner brief, 14NOV2026]` |
| Pristine disconnected real-bootstrap acceptance | Deferred: `qualification/run-offline-vm.py` and the P0-S3 release do not yet exist, and VM execution was prohibited. The future exact command is the qualification command above. | One pristine VM and one release artifact | **Deferred/unknown.** `[recorded: owner brief, 14NOV2026]` |

### Rollback

Before integration, discard candidate builds and uncommitted records. `[inferred]`

After integration, mark the release record `withdrawn`, stop selecting the artifact for deployments, and rebuild from the retained P0-S3 lock. Retain the withdrawn manifest for reproducibility comparison. `[inferred]`

## 4.6 P0-S5 — live Phase 0 interoperability smoke

### Problem and closure

The attack box, live Windows transport, bundle compatibility, BloodHound lifecycle, and six stage interfaces have not been observed together. Aranum records WinRM as mocked/dry-run rather than live-domain qualified. This sprint closes G4-03 and provides interoperability evidence only. `[verified: /srv/share/dev/aranum/aranumtoolkit/docs/ADR-003-20MAY2026-windows-bulk-enum-design.md]` `[inferred]`

P0-S5 does not close G1-01, G2-03, G3-02, G3-03, or G4-02 and does not qualify the production automated chain; those gaps remain assigned to P1-S1, P2-S1, P3-S1, and P4-S1. `[inferred]`

### Decisions

**Harness authority:** ad-lab-harness’s truth comparator owns the live smoke result; Aranum and PurpleSploit retain producer/consumer roles. `[inferred]`

**Transport cases:** require one successful low-privilege WinRM case plus denied, unavailable, and partial/error controls. `[inferred]`

**Smoke scope:** execute real stage commands or existing direct interfaces and verify their contracts, but do not substitute the harness for production adapters scheduled later. `[inferred]`

**Lineage:** each of the six receipts records `input_receipt_ids`, and stages 2–6 must reference the immediately preceding stage’s output identity. A merely present set of six unrelated receipts fails. `[inferred]`

**Attack-box manifest input:** `/mnt/attack-box/manifest/build.json` is produced by P0-S3 `deploy.sh`, installed by the P0-S3 `bootstrap.sh` contract, identity-qualified by P0-S4, and consumed read-only by `qualify_interop.py`. P0-S5 does not synthesize or relocate it. `[inferred]`

### Components and failure modes

| Repo/path | Change/command ownership | Contract affected | Introduced failure mode |
|---|---|---|---|
| `ad-lab-harness/adlab/qualify_interop.py` | Run/score the six-stage interoperability smoke, verify receipt lineage, and read the installed attack-box build manifest. `[inferred]` | Phase 0 interoperability gate. `[inferred]` | Unrelated stage outputs or unqualified build identities are accepted. `[inferred]` |
| `ad-lab-harness/schemas/interop.schema.json` | Define stage ID, command identity, inputs, outputs, lineage, coverage, and tri-state result. `[inferred]` | Qualification artifact. `[inferred]` | Partial/inconclusive collapses to success. `[inferred]` |
| `ad-lab-harness/profiles/GOAD-interoperability.json` | Own fixed GOAD stage targets/expected truths. `[inferred]` | Live smoke input. `[inferred]` | Profile silently includes WS01 or another lab. `[inferred]` |
| `/mnt/attack-box/manifest/build.json` | Exact P0-S3-produced/P0-S4-qualified command input; installed by `pt_provision/templates/bootstrap.sh` from released `manifest/build.json`. `[inferred]` | Attack-box source/build identity. `[inferred]` | Smoke reads an unmapped or stale manifest. `[inferred]` |
| `ad-lab-harness/tests/unit/`, `ad-lab-harness/tests/lab/` | Own full suite plus interop schema/lineage tests; no inherited regression surface. `[inferred]` | ad-lab-harness regression. `[inferred]` | Gate code is not regression-tested. `[inferred]` |
| `ad-lab-harness/docs/test-results/plan003-p0-s5-ad-lab-harness-base.xml`, `plan003-p0-s5-live.json` | Own ad-lab-harness regression/live outputs. `[inferred]` | Qualification record. `[inferred]` | Live result points to fixture evidence. `[inferred]` |
| `aranum/aranumtoolkit/network/bulk-enum-windows.py` | Existing production WinRM command under live qualification; no new production workflow adapter is claimed here. `[inferred]` | G4-03 transport. `[inferred]` | Harness wrapper masks transport classification. `[inferred]` |
| `aranum/aranumtoolkit/tests/test_bulk_enum_windows.py`, `test_bulk_enum_windows_transports.py`, `test_local_access.py`, `test_interop_contract.py` | Existing regression command inputs. `[verified: paths]` | Aranum regression. `[inferred]` | Regression baseline omitted. `[inferred]` |
| `aranum/docs/test-strategy/raw/plan003/p0-s5/aranum-base.xml` | Own Aranum pytest output. `[inferred]` | Regression manifest. `[inferred]` | Wrong execution SHA. `[inferred]` |
| `aranum/docs/test-strategy/cards/CARD-PLAN003-P0-WINRM.md` | Own live success/denied/unavailable/partial transport facts. `[inferred]` | G4-03 record. `[inferred]` | Card not tied to bundle/run IDs. `[inferred]` |
| `aranum/aranumtoolkit/tests/fixtures/plan003/` | Own sanitized live transport outputs after the run. `[inferred]` | Future regression surface. `[inferred]` | Fixture parser differs from live output. `[inferred]` |
| `purplesploit/python/tests/integration/interop/test_aranum_acceptance.py`, `test_pre_p1_identity.py` | Existing consumer regression inputs. `[verified: paths]` | PurpleSploit regression. `[inferred]` | Existing consumer regressions omitted. `[inferred]` |
| `purplesploit/python/tests/integration/interop/test_plan003_live_acceptance.py` | Verify receipt import, lineage, graph receipt, local result, and report. `[inferred]` | Cross-repo smoke acceptance. `[inferred]` | Counts pass while required classes are empty. `[inferred]` |
| `purplesploit/python/tests/integration/interop/fixtures/plan003/` | Own complete/partial receipts captured from the smoke. `[inferred]` | Consumer fixtures. `[inferred]` | Consumer regenerates its own expected evidence. `[inferred]` |
| `purplesploit/docs/test-results/plan003-p0-s5-purplesploit-base.xml` | Own PurpleSploit regression output. `[inferred]` | Regression manifest. `[inferred]` | Wrong execution SHA. `[inferred]` |

### Test plan

Aranum regression:

```bash
cd /srv/share/dev/aranum
python3 -m pytest \
  aranumtoolkit/tests/test_bulk_enum_windows.py \
  aranumtoolkit/tests/test_bulk_enum_windows_transports.py \
  aranumtoolkit/tests/test_local_access.py \
  aranumtoolkit/tests/test_interop_contract.py \
  -q --junitxml=docs/test-strategy/raw/plan003/p0-s5/aranum-base.xml
```

PurpleSploit regression:

```bash
cd /srv/share/dev/purplesploit/python
python -m pytest \
  tests/integration/interop/test_aranum_acceptance.py \
  tests/integration/interop/test_pre_p1_identity.py \
  -q --junitxml=../docs/test-results/plan003-p0-s5-purplesploit-base.xml
```

ad-lab-harness regression (its own full suite; root `782b499` had no pre-existing regression surface):

```bash
cd /srv/share/dev/ad-lab-harness
PYTHONDONTWRITEBYTECODE=1 python3 -B -m pytest -q -p no:cacheprovider \
  --junitxml=docs/test-results/plan003-p0-s5-ad-lab-harness-base.xml
```

Live interoperability command:

```bash
cd /srv/share/dev/ad-lab-harness
python3 -B adlab/qualify_interop.py \
  --profile profiles/GOAD-interoperability.json \
  --attack-box-manifest /mnt/attack-box/manifest/build.json \
  --result docs/test-results/plan003-p0-s5-live.json
```

These are proposed execution commands. `[inferred]`

Required receipts:

1. No-credentials enumeration receipt. `[inferred]`
2. Low-privilege directory/service enumeration receipt referencing receipt 1’s target/domain output. `[inferred]`
3. BloodHound collection/import/query receipt referencing receipt 2’s domain/credential context. `[inferred]`
4. Local access classification receipt referencing graph/host output from receipt 3. `[inferred]`
5. Default no-write local-check receipt referencing the qualified access result from receipt 4. `[inferred]`
6. PurpleSploit report receipt referencing receipts 1–5 and showing incomplete states. `[inferred]`

Receipt completion proves interoperability only; it does not prove that PurpleSploit automatically orchestrates all six production stages. `[inferred]`

RED proof:

- Delete one receipt while leaving five valid receipts; denominator remains six and the smoke fails. `[inferred]`
- Keep six receipts but replace one predecessor ID; lineage fails. `[inferred]`
- Change a success result to wrong-but-present `partial`; success-path assertion fails while terminal accounting still passes. `[inferred]`
- Replace the installed build manifest with another well-formed build identity and require P0-S4 lineage validation to fail. `[inferred]`
- Remove an expected graph edge and require the reachable path assertion to fail; retain a seeded unreachable negative control. `[inferred]`
- Reintroduce default PATH file creation and require the filesystem assertion to fail while proving the collector ran. `[inferred]`
- Break report coverage while leaving findings present and require failure. `[inferred]`
- Any unattributed transport, graph, or report result is `inconclusive`. `[inferred]`

### Baselines

The initial r2 baseline values are retained; the harness-owned command below is mapped to the new repository for execution-start refresh, not a fresh measurement. `[recorded: PLAN-003 r2 initial baselines]` `[inferred]`

| Metric | Exact command and working directory | Inputs and denominator | Baseline |
|---|---|---|---|
| Passed live interoperability records | `find docs/test-results -maxdepth 1 -type f -name 'plan003-p0-s5-live.json' -print \| wc -l` in `/srv/share/dev/ad-lab-harness` | One required live smoke | **0 measured.** `[measured: stated command]` |
| Captured Aranum live transport fixtures | `find aranumtoolkit/tests/fixtures/plan003 -type f -print \| wc -l` in `/srv/share/dev/aranum` | Four transport classifications required | **0 files measured.** `[measured: stated command]` |
| PurpleSploit PLAN-003 live acceptance fixture/test | `find python/tests/integration/interop/fixtures/plan003 -type f -print \| wc -l; find python/tests/integration/interop -maxdepth 1 -type f -name 'test_plan003_live_acceptance.py' -print \| wc -l` in `/srv/share/dev/purplesploit` | At least one live fixture set and one acceptance test | **0 fixtures and 0 test files measured.** `[measured: stated commands]` |

### Rollback

Before integration, discard source branches and retain raw qualification evidence outside the repositories for review. `[inferred]`

After integration, revert only harness/fixture changes and mark the smoke record superseded. Preserve the qualified P0-S4 release unless its own gate failed. `[inferred]`

---

# 5. Phases 1–6 sprint skeletons

Detailed designs, exact file lists, mutation tests, and execution-start baselines are deferred until their predecessor contracts pass. This deferral applies only to later phases, not unresolved Phase 0 choices. `[inferred]`

## Phase 1 — unauthenticated discovery and enumeration

### P1-S1 — discovery-to-Aranum production workflow

- **Items:** G1-01, G1-02; P1-01, P1-02. `[inferred]`
- **Scope:** PurpleSploit creates one run, preserves Nmap XML, invokes the versioned Aranum unauthenticated profile, imports the bundle, and compares DC/domain/service results to GOAD truth. `[inferred]`
- **Exit:** discovered DC/domain truth matches; anonymous, denied, unavailable, absent, and inconclusive remain distinct; every expected target/check has a coverage row. `[inferred]`
- **Relationship to P0-S5:** this sprint closes the production orchestration gap that the Phase 0 interoperability smoke intentionally leaves open. `[inferred]`

### P1-S2 — resumable coverage ledger

- **Items:** G1-03; P1-03, P1-04. `[inferred]`
- **Scope:** persistent phase/host/check work ledger, retry/resume, and staged 10/50/200-host synthetic acceptance. `[inferred]`
- **Exit:** interruption does not repeat completed checks unnecessarily or mark skipped work absent; concurrency and delay are measured, with C4 values still unset. `[inferred]`

## Phase 2 — authenticated low-privilege enumeration

### P2-S1 — directory inventory and graph collection

- **Items:** G2-01, G2-03; P2-02, P2-03, P2-05. `[inferred]`
- **Scope:** versioned AD inventory, per-class coverage, RustHound primary and Python fallback production adapters, collection receipts, and truth comparison. `[inferred]`
- **Exit:** users, groups, computers, OUs, trusts, GPOs, SPNs, delegation, and visible managed-account classes match truth or carry explicit unavailable/inconclusive states. `[inferred]`
- **Relationship to P0-S5:** this sprint replaces the direct collector smoke with the production collector workflow. `[inferred]`

### P2-S2 — policy slots and normalized domain classes

- **Items:** G2-02, G2-04; P2-01, P2-04. `[inferred]`
- **Scope:** preserve null C4 budget slots, require explicit owner values before account-use jobs, and normalize AD CS/GPO/delegation completeness. `[inferred]`
- **Exit:** null values refuse execution without invented defaults; every seeded domain-class condition has one canonical result and negative control. `[inferred]`

## Phase 3 — graph analysis and prioritization

### P3-S1 — authoritative graph ingest

- **Items:** G3-02, G3-03; P3-02, P3-03. G3-01 is closed in Phase 0. `[inferred]`
- **Scope:** register collector artifacts, ingest into BloodHound CE, store receipts, execute a versioned query pack, and import normalized path summaries. `[inferred]`
- **Exit:** collection completion creates an ingest job; success/failure is visible; expected GOAD paths and source-edge references return consistently. `[inferred]`
- **Relationship to P0-S5:** this sprint closes the production registration/ingest gaps that a direct Phase 0 import cannot close. `[inferred]`

### P3-S2 — path prioritization

- **Items:** G3-04; P3-04, P3-05. `[inferred]`
- **Scope:** deterministic ranking from reachability, evidence confidence, prerequisites, and affected assets without treating hypotheses as confirmed. Use versioned BloodHound CE queries plus an explicit weighted scoring function and stable path-ID tie-break over recorded path receipts. `purplesploit/ai/attack_paths.py` is deterministic template/probability code (66, 345, 351), but its generic templates are not the AD ranking authority; this sprint does not invoke advisory/provider/automation entrypoints. `[verified: python/purplesploit/ai/attack_paths.py:66]` `[verified: python/purplesploit/ai/attack_paths.py:345]` `[verified: python/purplesploit/ai/attack_paths.py:351]` `[inferred]`
- **Exit:** seeded path ordering is reproducible and every factor is inspectable; removed truth edges remove or downgrade the related result. `[inferred]`

## Phase 4 — local access

### P4-S1 — local access through PurpleSploit and WS01 profile

- **Items:** G4-02; P4-01, P4-02, P4-05. G4-03 is qualified in Phase 0. `[inferred]`
- **Scope:** capability model for authentication, resource read/write, command, desktop, and console; expose Aranum local jobs and eligibility preview. `[inferred]`
- **Workstation profile:** install the pinned `upstream/GOAD/extensions/ws01` extension against an already passed full-GOAD base, create a separate truth/profile record, and keep the five-VM first-gate record unchanged. `[verified: upstream/GOAD/extensions/ws01/README.md]` `[inferred]`
- **Exit:** only hosts with proven selected-transport capability are queued; member-server and WS01 workstation results return through the normal bundle importer with distinct host-role coverage. `[inferred]`

### P4-S2 — manual session records

- **Items:** G4-04; P4-04. `[inferred]`
- **Scope:** record operator-assisted or console observations using the same host/access/evidence model without claiming automated proof. `[inferred]`
- **Exit:** manual and automated observations coexist with distinct proof types and explicit coverage. `[inferred]`

### P4-S3 — interactive desktop transports

- **Items:** G4-01; P4-03. `[inferred]`
- **Scope:** qualified RDP collection and explicitly assisted VNC workflow, including the WS01 later profile. `[inferred]`
- **Exit:** RDP-supported hosts produce results; VNC never claims automated collection when assistance was required. `[inferred]`

## Phase 5 — local checks at scale

### P5-S1 — restartable fleet execution

- **Items:** G5-05; P5-04, P5-06. G5-04 is closed in Phase 0. `[inferred]`
- **Scope:** per-host leases, retries, timeout/partial handling, restart, and mixed full-GOAD/WS01/simulated qualification. `[inferred]`
- **Exit:** every eligible server and workstation check has success, denied, timeout, partial, unreachable, unsupported, or inconclusive state after restart. `[inferred]`

### P5-S2 — expanded Windows local coverage

- **Items:** G5-01, G5-02, G5-03; P5-02, P5-03. `[inferred]`
- **Scope:** bounded directory/share effective rights, complete scheduled-task action chains, autorun/startup/DLL search paths, and workstation-local cases on WS01. `[inferred]`
- **Exit:** seeded server and workstation positives/negative controls resolve; default mode remains ACL/read-only and explicit `--write` mode is separately recorded. `[inferred]`

## Phase 6 — correlation, reporting, and team workflow

### P6-S1 — durable one-to-five-operator state

- **Items:** G6-01; P6-01, P6-02. `[inferred]`
- **Scope:** shared durable canonical records and persistent jobs/leases/artifacts for C5’s one-through-five operators. `[inferred]`
- **Acceptance matrix:** execute separate cases for 1, 2, 3, 4, and 5 concurrent clients; do not infer intermediate behavior from the maximum case. `[recorded: owner decision C5]` `[inferred]`
- **Singleton boundary:** one operator acquires, renews, releases, and recovers ownership across coordinator/worker restart without duplicate ownership. `[inferred]`
- **Intermediate cases:** counts 2, 3, and 4 exercise distinct owners, lease transfer, completion visibility, and one-client restart. `[inferred]`
- **Maximum boundary:** five clients exercise concurrent ownership/lease transitions and coordinator/worker restart without divergent records. `[inferred]`
- **Exit:** all five cardinality cases pass independently. `[inferred]`

### P6-S2 — evidence bridge and correlation

- **Items:** G6-02, G6-03; P6-03–P6-05. `[inferred]`
- **Scope:** register Aranum bundles, graph receipts, and PurpleSploit exports into the evidence workspace; deduplicate domain, graph, access, service, and local findings. `[inferred]`
- **Exit:** one run registers all expected artifacts; merged findings retain every affected asset and evidence lineage; reports show incomplete checks. `[inferred]`

### P6-S3 — controller decision — WITHDRAWN under C7

- **Items:** G6-04 and P6-06 are withdrawn; identifiers retained without renumbering. `[recorded: owner directive, 14NOV2026]`
- **Reason:** no LLM controller under C7; no controller ADR, engagement dispatch or E2/E3 reproduction work is scheduled here. `[recorded: owner directive, 14NOV2026]`
- **Decision tree disposition:** C7 withdraws controller evaluation on every branch; no E2/E3 outcome reactivates it. P6-S1/P6-S2 and all other active gates retain their existing dependencies, and `ad-lab-harness` is solely the independent deterministic lab-truth and qualification authority. `[recorded: owner directive, 14NOV2026]` `[inferred]`

---

# 6. Open owner questions

No owner question is required before beginning the approved work. C1 and C6 are final, C4 remains intentionally unset, and the Phase 0 method choices have named selections, rejected alternatives, flip evidence, and predecessor decision records. `[recorded: owner decisions, 14NOV2026]` `[inferred]`

---

# 7. Peer review record

## Round 1

**Reviewer:** GPT-5.6-Sol, xhigh  
**Review date:** 14NOV2026  
**Verdict:** RED  
**Response status:** All ten findings accepted and answered in r1. `[recorded: independent peer review, 14NOV2026]`

### Findings disposition

| ID | Disposition | Change made | Where |
|---|---|---|---|
| R1 | Accepted | C1 is fixed to full `ad/GOAD`; all first-gate alternatives, `GOAD_FIRST_GATE`, and the C1 owner question were removed. Later profiles are explicitly post-gate. `[recorded: owner decision C1]` | Constraints; §§2.1–2.2, 3.2–3.3, 4.2, 6 |
| R2 | Accepted | Replaced the incorrect two-site denominator with a whole-source sweep: three default write probes, five total target-side writer sites, 32 operator-side Python artifact writes, compact-probe zero target writers, and the full WinRM inheritance path. All three probes share effective rights; all five target writers require explicit write mode. `[measured: §3.7 sweeps]` | G5-04; §§3.7–3.8, 4.3 |
| R3 | Accepted | P0-S4 now starts from a pristine pinned-base VM, attaches only the release, disconnects before extraction/bootstrap, runs the real released bootstrap, proves artifact consumption, then starts BloodHound and runs import/query/report checks. Fixture-only tests cannot promote. `[inferred]` | §§4.4–4.5 |
| R4 | Accepted | Added C6 and made SP0-01 a predecessor go/no-go. Failure or inconclusive blocks P0-S1 until the owner names another host; no fallback is planned. `[recorded: owner decision C6]` | Constraints; §§2.1–2.2, 3.4, 3.10, 4.2 *Superseded in r3: see the SP0-01 recovery reconciliation in Revision r3 and §2.2.* |
| R5 | Accepted | Narrowed P0-S5 to an interoperability smoke that explicitly does not qualify or close the production adapters. Added receipt lineage and kept the production closures in P1/P2/P3/P4. `[inferred]` | Sprint map; §4.6; §§5 Phase 1–4 |
| R6 | Accepted | Named and compared Authz versus `AccessCheck`, and pinned official Compose versus `bloodhound-cli`; selected one in each pair, recorded rejection and flip evidence, and made SP0-03/SP0-04 decisions predecessors. `[inferred]` | §§3.8–3.10; §§4.3–4.4 |
| R7 | Accepted | P0-S2 now depends on a P0-S1 Windows lab slice and SP0-04; its live GOAD gate is no longer presented as independent. `[inferred]` | §§2.1–2.2, 3.10, 4.3 |
| R8 | Accepted | Replaced vague baseline nouns with exact commands, working directories, inputs, and denominators. Unexecutable build/VM baselines are `deferred/unknown`, not inferred zeroes. `[inferred]` | All Phase 0 baseline tables |
| R9 | Accepted | Added component ownership for every sprint command/input/output, including `AGENTS.md`, GOAD profiles/commands, static inventory tests, engagement profile, sidecar build manifests, qualification VM harness, and result paths. `[inferred]` | Every §4 component table |
| R10 | Accepted | P6-S1 now has independent acceptance cases for operator counts 1, 2, 3, 4, and 5, with restart and ownership/lease behavior at singleton and maximum boundaries. `[inferred]` | Sprint map; §5 Phase 6 |

### Class sweeps

Sweep scope is the complete normative plan in §§1–6 plus the cited source roots where the class concerns implementation inventory. Literal search expressions inside this table are excluded from their own counts to avoid self-matches. `[inferred]`

| Review class | Match identity searched | Count | Resolution |
|---|---|---:|---|
| Fixed constraint reopened | Normative-plan regex `GOAD_FIRST_GATE|confirmation question|Interpretation [AB]|Does C1|first gate.*(MINILAB|GOAD-Light)|(MINILAB|GOAD-Light).*first gate` | **0 unresolved matches** | Full `ad/GOAD` is the sole first gate; later profiles cannot substitute. `[recorded: owner decision C1]` |
| Incomplete mutation-path inventory | Source signature `WriteAllText|New-Item .*-ItemType File|Set-Content|Out-File|\.write_test|Test-Writable`, then expanded target signature adding `Start-Transcript|Tee-Object .*FilePath`, over `standalones/windows`, `aranumtoolkit`, full WinRM selectors, and compact-probe sources | **3 default probe sites; 5 total target-writer sites across 4 PowerShell files; 32 operator-side Python artifact writes across 7 files; 0 compact-probe target writers** | Three probes move to one effective-rights implementation; all five target writers require explicit write mode; operator-side artifacts remain outside C3. `[measured: §3.7 commands]` |
| Vacuous offline qualification | P0-S3/P0-S4 obligations searched: `pristine base`, `attach only release`, `disconnect before bootstrap`, real `unpack.sh`, real `bootstrap.sh`, package-index consumption, wheelhouse consumption, three OCI loads, BloodHound start/import/query/report; also searched `fixture-only` promotion language | **10/10 required obligations present; 0 fixture-only promotion paths** | P0-S4’s ordered real-bootstrap gate is the only release promotion path. `[inferred]` |
| Blocked contingency | Normative-plan search `fallback host|supplied host|another host|Ludus|Proxmox|native libvirt provider`; separate search for `SP0-01.*blocked|blocked.*P0-S1` | **0 alternate/fallback paths; 2 explicit blocked clauses** | C6 is implemented exactly: failed/inconclusive coexistence blocks P0-S1. `[recorded: owner decision C6]` *Superseded in r3: see the SP0-01 recovery reconciliation in Revision r3 and §2.2.* |
| Qualification-path substitution | Normative-plan search for claims matching `qualif(y|ies).*production.*chain` before P1/P2/P3/P4 closure, plus `smoke-only ride-along` | **0 premature production-qualification claims** | P0-S5 is explicitly interoperability-only and leaves five production gaps open. `[inferred]` |
| Unresolved Phase-0 choice | Phase 0 search `selected by SP|another .* API|another upstream|subject to|method TBD` | **0 unspecified Phase 0 methods; 2 concrete comparison pairs** | Authz and pinned official Compose are selected; `AccessCheck` and `bloodhound-cli` are named rejections with flip evidence and predecessor records. `[inferred]` |
| Missing test dependency | Compared every live Phase 0 consumer against §2.2 edges: P0-S1/provider, SP0-04/Windows host, P0-S4/P0-S3 release, P0-S5/P0-S1+S2+S4 | **4 live consumers; 0 missing edges** | P0-S2 is no longer independent of the lab. `[inferred]` |
| Non-reproducible baseline | All 18 Phase 0 benefit-baseline rows searched for `static inventory command|Release manifest query|Provider preflight|measured: awk and rg|\[inferred\].*0` and for omitted working directory/input/denominator | **18 rows reviewed; 0 vague or inferred-zero rows** | Every row has an exact command and directory or an explicit deferred/unknown reason. `[inferred]` |
| Artifact-map drift | For each §4 sprint, command-block/input/output paths matching `(?:/srv/share/dev/|(?:tests|config|templates|qualification|probes|docs|aranumtoolkit|python/tests)/)[A-Za-z0-9_./${}-]+` were cross-checked against that sprint’s component table | **0 unmapped command/input/output paths** | Profiles, commands, sidecars, fixtures, records, `AGENTS.md`, and engagement-profile ownership are explicit. `[inferred]` |
| Boundary-only range test | Normative-plan search `one-to-five|one through five|1–5|five concurrent` and comparison with P6-S1 acceptance cardinalities | **1 support range; 5 independent cardinality cases; 0 boundary-only exits** | Counts 1, 2, 3, 4, and 5 are tested; restart/lease transitions are explicit at 1 and 5. `[inferred]` |

## Round 2

**Reviewer:** GPT-5.6-Sol, xhigh  
**Review date:** 14NOV2026  
**Verdict:** RED  
**Response status:** R2, R8, and R9 accepted and structurally answered in r2; pending round-3 verification. `[recorded: independent peer review, 14NOV2026]`

### Findings disposition

| ID | Disposition | Change made | Where |
|---|---|---|---|
| R2 | Accepted | Replaced the hand-picked roots with a repo-wide sweep of all production `*.ps1`/`*.psm1`, explicitly excluding only tests/fixtures, and expanded the signature across all named cmdlet/.NET/redirection families. Recorded seven executable candidates, one evidenced read-only `FileStream` exclusion, and six writer sites across five files. Classified all six exactly once: three `default-probe`, three `opt-in-output`, zero `write-gated`, and zero `operator-side`. Decided that `-OutFile` alone does not satisfy C3 and routed all three opt-in sites through the unified write contract. Added a set-equality classification gate, unclassified-writer mutation, and independent known-site presence assertions. `[measured: §3.7 command]` `[inferred]` | G5-04; sprint-map P0-S2; §§3.7, 4.3 |
| R8 | Accepted | Replaced the two procedural P0-S2 baseline descriptions and the P0-S0 top-level-status description with literal copy-pasteable commands and working directories. Re-swept all 18 Phase 0 baseline rows; no description-only row remains, while the two prohibited-execution rows remain explicit `deferred/unknown`. `[measured: baseline-row sweep below]` | §§4.1, 4.3; all §4 baseline tables |
| R9 | Accepted | Defined `deploy.sh` as producer of released `manifest/build.json`, `bootstrap.sh` as installer of `/mnt/attack-box/manifest/build.json`, P0-S4 as identity qualifier, and P0-S5 as read-only consumer. Added `smoke.sh`, `data_audit.py`, the discovery root, writer inventory/classification inputs, and the external GOAD profile to P0-S2’s component table. Expanded the artifact regex to `/mnt`, `/opt`, `/var`, `$HOME`, and `~/` runtime forms. `[inferred]` | §§4.3–4.6 |

### Round-2 sweeps

Sweep scope is the revised normative plan in §§1–6 and the cited Aranum source root. Historical Round-1 text is retained unchanged as the review record and is not a normative denominator. `[inferred]`

| Review class | Exact match identity | Count | Resolution |
|---|---|---:|---|
| Repo-wide PowerShell writer candidates | `rg -n -U --pcre2 --glob '*.ps1' --glob '*.psm1' --glob '!**/tests/**' --glob '!**/fixtures/**' '(?s:<#.*?#>)(*SKIP)(*F)\|(?m:^\s*#.*$)(*SKIP)(*F)\|"(?:`.\|[^"\r\n])*"(*SKIP)(*F)\|(?i:\b(?:WriteAllText\|WriteAllBytes\|WriteAllLines\|AppendAllText\|New-Item\|Set-Content\|Add-Content\|Out-File\|Export-Csv\|Export-Clixml\|Start-Transcript\|Tee-Object\|Copy-Item\|Move-Item)\b\|\[(?:System\.)?IO\.File\]\|\b(?:StreamWriter\|FileStream)\b\|(?<![-<])(?:\*\|[1-6])?>>?\s*(?!\$null\b)(?=\S))' /srv/share/dev/aranum` | **7 executable candidates: 6 writers across 5 files; 1 recorded read-only `FileStream` exclusion** | All six writers appear in §3.7 and have exactly one required category. `[measured: stated command]` |
| Writer classification completeness | Canonical writer identity set from the preceding sweep, compared with `writer-sites.tsv`; allowed categories `default-probe|opt-in-output|write-gated|operator-side` | **6/6 current writers classified; 0 unclassified; category counts 3/3/0/0** | The P0-S2 gate requires set equality, fails an added unclassified writer, and separately proves known identities are present. `[inferred]` |
| Non-literal Phase 0 baselines | `awk '/^### Baselines$/ {b=1; next} b && /^###? / {b=0} b && /^\|/ && $0 !~ /^\|---/ && $0 !~ /^\| Metric / {rows++; if ($0 !~ /^\|[^|]+\| `/ && $0 !~ /^\|[^|]+\| Deferred: `/) vague++} END {print "rows=" rows; print "description_only=" vague+0}' docs/plans/PLAN-003-14NOV2026-ad-engagement-toolchain.md` in `/srv/share/dev/purplesploit` | **18 rows; 0 description-only rows** | Every executable baseline begins with a literal command; prohibited build/VM measurements remain explicit deferrals. `[measured: stated command]` |
| Absolute runtime artifact identities | `sed -n '/^# 4\./,/^---$/p' docs/plans/PLAN-003-14NOV2026-ad-engagement-toolchain.md \| rg -o --pcre2 '(?:/srv/share/dev/\|/(?:mnt\|opt\|var)/\|\$HOME/\|~/\|(?:tests\|config\|templates\|qualification\|probes\|docs\|aranumtoolkit\|python/tests)/)[A-Za-z0-9_./${}*<>:-]+' \| rg '^(?:/(?:mnt\|opt\|var)/\|\$HOME/\|~/)' \| sort -u` in `/srv/share/dev/purplesploit` | **3 distinct absolute runtime identities: 1 `/mnt` manifest path, 2 `/var/tmp` build paths; 0 `/opt`, `$HOME`, or `~/`; 0 unmapped** | `/mnt/attack-box/manifest/build.json` is produced, installed, qualified, and consumed under §§4.4–4.6; both `/var/tmp` paths belong to the P0-S4 external-build-directory row. `[measured: stated command]` |
| Full command/input/output artifact map | §4 token regex `(?:/srv/share/dev/\|/(?:mnt\|opt\|var)/\|\$HOME/\|~/\|(?:tests\|config\|templates\|qualification\|probes\|docs\|aranumtoolkit\|python/tests)/)[A-Za-z0-9_./${}*<>:-]+`, cross-checked per sprint against its component table | **0 unmapped command/input/output identities** | P0-S2 command inputs and the P0-S5 runtime manifest now have explicit producer/owner rows. `[inferred]` |

## Round 3 verification

**Reviewer:** GPT-5.6-Sol, xhigh  
**Review date:** 14NOV2026  
**Verdict:** GREEN — no unresolved BLOCKER/HIGH finding, vacuous gate, or regression. `[recorded: docs/reviews/PLAN-003-PEER-REVIEW-R3-14NOV2026.md]`  
**Scope:** verify-only (R2, R8, R9; regressions against R1/R3–R7/R10 and C1–C6; new BLOCKER/HIGH only).

| ID | Severity | Verified | Evidence summary |
|---|---|---|---|
| R2 | HIGH | Yes | §3.7 sweep reproduces 19 in-scope files, 7 candidates, 6 writers across 5 files, and 1 read-only `FileStream` exclusion. The 3/3/0/0 classification matches source. Requiring `-WriteValidate` in addition to `-OutFile` agrees with C3 and Aranum's explicit-flag invariant without removing capability. The classification gate is non-vacuous: set equality, known-identity presence, empty-scan rejection, and unclassified-writer and guard-removal mutations. |
| R8 | MEDIUM | Yes | Baseline-row sweep reproduces `rows=18`, `description_only=0`. The P0-S0 and P0-S2 literal commands reproduce their recorded values. The two prohibited-execution rows remain explicit `Deferred/unknown`. |
| R9 | MEDIUM | Yes | Runtime-path sweep returns exactly `/mnt/attack-box/manifest/build.json` plus the two `/var/tmp/plan003-build-{a,b}.XXXXXX` directories. The manifest chain is producer (`deploy.sh`) → installer (`bootstrap.sh`) → qualifier (P0-S4) → read-only consumer (P0-S5). The P0-S2 command inputs are mapped. |

Orchestrator cross-check (14NOV2026, before round 3): the §3.7 sweep, the baseline-row `awk`, and the absolute-runtime-path pipeline were re-run against the saved r2 and matched the plan's recorded values. `[measured: stated commands]`

Raw reviews: `docs/reviews/PLAN-003-PEER-REVIEW-R1-14NOV2026.md`, `…-R2-14NOV2026.md`, `…-R3-14NOV2026.md`. The plan/review loop closed within the three-round limit; no escalation was needed. Phase 5 gate: **green**. Phase 6 (P0-S0) starts only on the owner's go.