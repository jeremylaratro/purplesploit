# AD engagement tooling assessment and phased build plan

**Assessment date:** 2026-11-14  
**Scope:** Capability, coverage, integration, scale, and validation readiness for an authorized enterprise Active Directory assessment.  
**Evidence convention:** Every current-state claim is marked `[verified: path]` or `[inferred]`. Recommendations and proposed designs are marked `[inferred]`.

## 1. Executive summary

The team already has two strong foundations:

- **Aranum is the appropriate headless enumeration producer.** It has broad unauthenticated and authenticated service enumeration, Windows and Linux host-posture collectors, structured findings, bulk SSH/WinRM execution, local-access classification, throttling, and an export bundle contract. `[verified: /srv/share/dev/aranum/README.md]` `[verified: /srv/share/dev/aranum/aranumtoolkit/network/auto-enum.sh]`
- **PurpleSploit is the appropriate operator console and consumer.** PLAN-002 implemented the Aranum bundle importer, canonical findings/observations, coverage views, access summaries, workflows, reporting, and an adapter that can invoke selected Aranum service enumeration. `[verified: /srv/share/dev/purplesploit/docs/plans/PLAN-002-28OCT2026-aranum-purplesploit-integration.md]` `[verified: /srv/share/dev/purplesploit/python/purplesploit/modules/recon/aranum.py]`

This is not yet a complete enterprise AD assessment pipeline. The main problem is not an absence of tools; it is that several existing capabilities are disconnected, only fixture-tested, or lack a qualified Windows domain lab.

### Top five gaps

1. **There is no current, reproducibly pinned, lab-qualified engagement attack box.** `pt_provision` omits major native AD dependencies and its existing September bundle predates the October Aranum/PurpleSploit integration. `[verified: /srv/share/dev/pt_provision/config/repositories.tsv]` `[verified: /srv/share/dev/pt_provision/README.md]` `[verified: /srv/share/dev/pt_provision/pt-offline-bundle-20260915T023140Z.tar.gz.enc]`

2. **BloodHound is not wired end to end.** Aranum can invoke a collector, PurpleSploit can invoke NetExec BloodHound operations, and `28julytoolkit` ships several collectors, but there is no provisioned BloodHound CE analysis service or automatic collection → registration → ingest → query → finding path. `[verified: /srv/share/dev/aranum/aranumtoolkit/network/enum-ldap.sh]` `[verified: /srv/share/dev/purplesploit/python/purplesploit/modules/network/nxc_ldap.py]` `[verified: /srv/share/dev/28julytoolkit/ad-modern/README.md]`

3. **Windows/AD transport and local-access qualification is incomplete.** Aranum supports local, SSH, WinRM, and compact Windows execution paths, but its own design record says WinRM was mocked or dry-run rather than validated against a known-good domain VM. RDP/VNC S5 work was not started. `[verified: /srv/share/dev/aranum/aranumtoolkit/docs/ADR-003-20MAY2026-windows-bulk-enum-design.md]` `[verified: /srv/share/dev/aranum/docs/plans/PLAN-001-25OCT2026-fp-ad-local-posture.md]`

4. **Windows local privilege-escalation coverage is useful but not comprehensive enough for the stated objective.** Services, tasks, token privileges, stored credentials, PATH directories, AD CS signals, LAPS, GPP, named pipes, and several domain checks exist; comprehensive writable `C:\` trees/shared directories, full task action-chain analysis, autoruns/startup paths, and broad DLL search-path checks are incomplete or not found in the reviewed primary collectors. `[verified: /srv/share/dev/aranum/standalones/windows/Invoke-PrivEscEnum.ps1]` `[verified: /srv/share/dev/aranum/standalones/windows/Get-ScheduledTasks.ps1]` `[inferred]`

5. **Team workflow is not yet a durable multi-operator system.** PurpleSploit has canonical SQLite state, workflows, evidence records, reporting, and a distributed protocol, but coordinator queues, leases, artifacts, and pending state remain in memory and are documented as fixture-lab capabilities. `[verified: /srv/share/dev/purplesploit/python/purplesploit/services/application.py]` `[verified: /srv/share/dev/purplesploit/python/purplesploit/distributed/README.md]`

### Recommended path

Use this toolchain for the engagement:

- **Aranum:** all read-side network, AD, host-posture, and local enumeration. Preserve its enumeration/validated-proof boundary and require explicit `--write`, `--exploit`, or `--send` behavior for target changes. `[verified: /srv/share/dev/aranum/CLAUDE.md]`
- **PurpleSploit:** operator console, job dispatch, imports, canonical access/coverage/findings state, prioritization, and reporting. `[verified: /srv/share/dev/purplesploit/python/purplesploit/services/README.md]`
- **BloodHound CE:** authoritative AD graph and path engine; PurpleSploit should store collection/import receipts and normalized path findings, not initially reimplement the complete BloodHound relationship model. `[inferred]`
- **`pt_provision`:** engagement attack-box and offline bundle builder, extended with native AD tools, BloodHound CE, exact pins, and acceptance tests. `[inferred]`
- **`28julytoolkit/ad-modern`:** source for selected pinned collectors and their offline dependencies, not the engagement orchestrator. `[inferred]`
- **`pentest_scripts`:** workstation, pivot, packet, and evidence-workspace helpers only; do not revive its legacy enumeration surfaces. `[verified: /srv/share/dev/pentest_scripts/GAP-REPORT-14SEP2026.md]`
- **ShadowHex:** use its lab truth/gate concepts during Phase 0, but keep it off the engagement critical path until its AD E2/E3 gates pass. `[verified: /srv/share/dev/ShadowHex/docs/EXPANDED-AD-LINUX-APPLICATION-GATE-2026-11-02.md]`
- **four8pwn:** exclude; its newer status describes a single-host CTF-oriented recon-to-foothold MVP, not an enterprise AD assessment engine. `[verified: /srv/share/dev/tmp/ad-assess-14NOV2026/gh/four8pwn/docs/status/RESUME-STATE-19JUL2026.md]`

---

## 2. Inventory

### Aranum

Aranum is the most mature AD-relevant producer. It consumes Nmap output, builds service buckets, and runs bounded parallel unauthenticated or authenticated enumeration with credential scope, domain context, throttling, raw evidence, structured findings, and reports. `[verified: /srv/share/dev/aranum/aranumtoolkit/network/auto-enum.sh]` Its SMB and LDAP dispatchers cover null-session signals, users, groups, computers, password-policy signals, shares, sessions, SPNs, GPO-related directory data, delegation, BloodHound collection, and AD CS discovery where the external dependencies exist. `[verified: /srv/share/dev/aranum/aranumtoolkit/network/enum-smb.sh]` `[verified: /srv/share/dev/aranum/aranumtoolkit/network/enum-ldap.sh]`

PLAN-001 added a finding KB, AD view, Windows and Linux host posture, domain rollups, and the `--local` access layer. `[verified: /srv/share/dev/aranum/docs/plans/PLAN-001-25OCT2026-fp-ad-local-posture.md]` The local layer supports local execution, Linux/Windows SSH, WinRM, and compact Windows command transports; it explicitly refuses RDP/VNC until S5 is implemented. `[verified: /srv/share/dev/aranum/aranumtoolkit/network/local-enum.py]` Windows collection includes services, scheduled tasks, token privileges, stored credentials, unquoted paths, writable PATH entries, network/share inventory, AD depth, AD CS, LAPS/GPP, named pipes, and thick-client artifacts. `[verified: /srv/share/dev/aranum/standalones/windows/Invoke-PrivEscEnum.ps1]`

Two limitations matter immediately. WinRM has not been qualified against a real domain VM in the reviewed design record. `[verified: /srv/share/dev/aranum/aranumtoolkit/docs/ADR-003-20MAY2026-windows-bulk-enum-design.md]` Also, writable-PATH checks create and delete test files by default, which conflicts functionally with Aranum’s “no target write without an explicit gate” invariant. `[verified: /srv/share/dev/aranum/standalones/windows/Get-WritablePathDirs.ps1]` `[verified: /srv/share/dev/aranum/CLAUDE.md]`

### PurpleSploit

PurpleSploit is the correct consumer and operator surface. Its application services cover assessment state, workflows, findings, graph data, imports, reports, jobs, topology, identity relationships, attack paths, coverage, retest state, and data-quality views. `[verified: /srv/share/dev/purplesploit/python/purplesploit/services/README.md]` PLAN-002 implemented the Aranum bundle contract and imports findings, inventory, host posture, authentication outcomes, coverage, and per-host rollups. `[verified: /srv/share/dev/purplesploit/docs/plans/PLAN-002-28OCT2026-aranum-purplesploit-integration.md]`

The live adapter can run selected Aranum service dispatchers and import complete or partial bundles. `[verified: /srv/share/dev/purplesploit/python/purplesploit/modules/recon/aranum.py]` It does not currently expose Aranum’s local-access workflow. `[verified: /srv/share/dev/purplesploit/python/purplesploit/modules/recon/aranum.py]`

PurpleSploit has a BloodHound importer, but it intentionally handles only users, groups, computers, domains, memberships, sessions, local administrators, and trusts. It explicitly does not provide full collector or OpenGraph parity. `[verified: /srv/share/dev/purplesploit/python/purplesploit/interop/bloodhound.py]` Its generic attack graph performs directed path search and basic risk scoring, but that is not equivalent to BloodHound’s full AD relationship semantics. `[verified: /srv/share/dev/purplesploit/python/purplesploit/core/attack_graph.py]` NetExec BloodHound operations exist, but their output is treated primarily as command observations rather than automatically located and ingested as graph artifacts. `[verified: /srv/share/dev/purplesploit/python/purplesploit/modules/network/nxc_ldap.py]` `[verified: /srv/share/dev/purplesploit/python/purplesploit/modules/network/nxc_common.py]`

Reporting to Markdown, HTML, PDF, and XLSX is present. `[verified: /srv/share/dev/purplesploit/python/purplesploit/reporting]` Canonical state is currently SQLite/in-process, while the distributed coordinator’s operational state is in memory. `[verified: /srv/share/dev/purplesploit/python/purplesploit/services/application.py]` `[verified: /srv/share/dev/purplesploit/python/purplesploit/distributed/README.md]`

### `28julytoolkit`

The AD-relevant portion is `ad-modern`, not the toolkit’s payload or C2 material. `ad-modern` ships offline copies of RustHound-CE, BloodHound CE Python, legacy BloodHound Python, Coercer, Certipy dependencies, AzureHound/ROADtools, and DPAPI tooling including DonPAPI and dpapick3. `[verified: /srv/share/dev/28julytoolkit/ad-modern/README.md]` The collector documentation describes RustHound-CE as the fast/static default, BloodHound CE Python as a Python fallback, and the legacy collector as a compatibility option. `[verified: /srv/share/dev/28julytoolkit/ad-modern/bloodhound-collectors/docs/README.md]`

The toolkit includes an offline wheelhouse and collector bootstrap scripts. `[verified: /srv/share/dev/28julytoolkit/ad-modern/wheelhouse]` `[verified: /srv/share/dev/28julytoolkit/ad-modern/bloodhound-collectors/bloodhound-ce-python/bootstrap.sh]` It does not, in the reviewed `ad-modern` tree, provide the BloodHound CE server/database deployment needed for analysis. `[inferred]` It was assembled in July and is not presently connected to `pt_provision`, Aranum, or PurpleSploit’s automated run contract. `[verified: /srv/share/dev/28julytoolkit/README.md]` `[verified: /srv/share/dev/pt_provision/config/repositories.tsv]`

### `pt_provision`

`pt_provision` creates an encrypted offline Linux bundle containing source snapshots, a Python environment, wheels, checksums, and commit provenance. `[verified: /srv/share/dev/pt_provision/README.md]` Its current repository manifest includes PurpleSploit, Aranum, supwngo, WinBins, GTFOBins, LOLBAS, and `pentest_scripts`. `[verified: /srv/share/dev/pt_provision/config/repositories.tsv]`

It does not currently include `28julytoolkit/ad-modern`, BloodHound CE, NetExec, native SMB/RPC/LDAP/Kerberos clients, RDP clients, Certipy, or the other required native attack-box dependencies. `[verified: /srv/share/dev/pt_provision/config/repositories.tsv]` Native dependencies are explicitly left as operating-system prerequisites. `[verified: /srv/share/dev/pt_provision/README.md]` Builds record the exact cloned commits, but the input definition follows repository HEAD rather than pinning exact revisions before the build. `[verified: /srv/share/dev/pt_provision/deploy.sh]`

The existing September 15 bundle predates the October 28 Aranum/PurpleSploit integration and the current ShadowHex work. `[verified: /srv/share/dev/pt_provision/pt-offline-bundle-20260915T023140Z.tar.gz.enc]` It should be treated as stale for this engagement. `[inferred]`

### `pentest_scripts`

`pentest_scripts` has deliberately moved away from owning enumeration. Its current role is attack-workstation setup, evidence handling, network configuration, pivot support, data transformation, packet tooling, and reusable scripts/templates. `[verified: /srv/share/dev/pentest_scripts/GAP-REPORT-14SEP2026.md]` The evidence helper creates structured raw/derived/notes/log/state directories and manifest records, while the Ligolo helper supports proxy, interface, route, and agent-command preparation. `[verified: /srv/share/dev/pentest_scripts/evidence/workspace.py]` `[verified: /srv/share/dev/pentest_scripts/pivots/ligolo/ligolo-helper.sh]`

The local checkout is one commit behind `origin/main`; the missing commit adds Scapy-oriented packet tooling and does not materially change AD coverage. `[verified: /srv/share/dev/pentest_scripts/.git]` Its legacy AD/recon scripts should remain compatibility surfaces rather than becoming new development targets. `[verified: /srv/share/dev/pentest_scripts/docs/ENUMERATION-MIGRATION.md]`

### ShadowHex

ShadowHex is a research-stage orchestration engine with a shared application layer, CLI/web adapters, Postgres-backed records, job concepts, recon modules, and substantial lab/benchmark infrastructure. `[verified: /srv/share/dev/ShadowHex/README.md]` It has a well-scoped expanded AD qualification plan covering a real Windows mini-domain, identity/account-service behavior, GPOs, shares, AD CS, BloodHound, and Aranum integration. `[verified: /srv/share/dev/ShadowHex/docs/EXPANDED-AD-LINUX-APPLICATION-GATE-2026-11-02.md]`

Those AD cases are specified but not passed. `[verified: /srv/share/dev/ShadowHex/docs/EXPANDED-AD-LINUX-APPLICATION-GATE-2026-11-02.md]` ShadowHex should therefore contribute the Phase 0 lab truth model and acceptance-gate structure, but should not replace Aranum/PurpleSploit during this engagement. `[inferred]`

### Other repositories

- **four8pwn:** newer status records a single-host CTF-oriented recon/enumeration/foothold stack, with privilege escalation and broader real-world qualification still pending. It is not an enterprise AD toolchain. `[verified: /srv/share/dev/tmp/ad-assess-14NOV2026/gh/four8pwn/docs/status/RESUME-STATE-19JUL2026.md]`
- **CloudGraph:** has graph collection, rule analysis, Neo4j integration, and reporting, but its implemented domain is AWS; Azure and GCP are described as placeholders. It is not an on-premises AD graph engine. `[verified: /srv/share/dev/tmp/ad-assess-14NOV2026/gh/CloudGraph/README.md]`
- **autoCTT:** provides structured risk, prioritization, ATT&CK mapping, and deliverable generation, but not live AD collection. It could consume final findings later. `[verified: /srv/share/dev/tmp/ad-assess-14NOV2026/gh/autoCTT/README.md]`
- **WinBins:** updates/builds Windows assessment binaries; it is not an enumeration or orchestration engine. `[verified: /srv/share/dev/tmp/ad-assess-14NOV2026/gh/WinBins/README.md]`
- **MCP-Kali-Server_Bridges:** is a generic remote command wrapper with no structured AD evidence or engagement-state contract. `[verified: /srv/share/dev/tmp/ad-assess-14NOV2026/gh/MCP-Kali-Server_Bridges/README.md]`
- **lss2:** is an IDS/host-monitoring control panel, not an AD assessment producer. `[verified: /srv/share/dev/lss2/README.md]`
- **notes:** contains unstructured historical notes rather than reusable engagement automation. `[verified: /srv/share/dev/tmp/ad-assess-14NOV2026/gh/notes]`
- **claude_plugins:** the supplied two-level listing shows historical AD knowledge material, but no current structured AD runtime can be established from that inventory alone. `[verified: /srv/share/dev/tmp/ad-assess-14NOV2026/pack/claude_plugins.md]`

### Planning host

`net0srv` has Nmap, PowerShell, Docker, and general development tooling, but lacks the normal AD engagement stack on PATH or in system Python: NetExec, SMB/RPC clients, LDAP utilities, Kerberos clients, Impacket, BloodHound collectors, Neo4j, Certipy, RDP, and WinRM tooling are absent. `[verified: /srv/share/dev/tmp/ad-assess-14NOV2026/pack/host-inventory.md]` This matches its intended role as a development/research host rather than the attack box. `[inferred]`

---

## 3. Capability matrix

**Legend:** `H` = implemented and wired in its own surface; `P` = partial or not live-qualified; `NW` = capability exists but is not wired into the engagement pipeline; `M` = missing from the reviewed surface.

| Phase capability | Aranum | PurpleSploit | 28July AD | `pt_provision` | `pentest_scripts` | ShadowHex |
|---|---|---|---|---|---|---|
| P0: Windows AD lab | M `[verified: /srv/share/dev/aranum/docs/plans/PLAN-001-25OCT2026-fp-ad-local-posture.md]` | M `[inferred]` | M `[inferred]` | M `[inferred]` | M `[inferred]` | P: specified, not passed `[verified: /srv/share/dev/ShadowHex/docs/EXPANDED-AD-LINUX-APPLICATION-GATE-2026-11-02.md]` |
| P0: attack-box build | P: dependency checker only `[verified: /srv/share/dev/aranum/deps-check.sh]` | P: Python package artifacts `[verified: /srv/share/dev/purplesploit/python/dist]` | P: offline AD tools/wheels `[verified: /srv/share/dev/28julytoolkit/ad-modern]` | P: Python-centric bundle `[verified: /srv/share/dev/pt_provision/README.md]` | H: workstation helpers `[verified: /srv/share/dev/pentest_scripts/README.md]` | P: runner/lab components `[verified: /srv/share/dev/ShadowHex/probes/recon_lab]` |
| P1: network discovery | P: consumes Nmap, does not own initial scan `[verified: /srv/share/dev/aranum/aranumtoolkit/network/auto-enum.sh]` | H: scan modules and target context `[verified: /srv/share/dev/purplesploit/README.md]` | M `[inferred]` | M `[inferred]` | P: legacy discovery surfaces `[verified: /srv/share/dev/pentest_scripts/recon]` | P: recon stack, not AD-qualified `[verified: /srv/share/dev/ShadowHex/shadowhex/enumeration.py]` |
| P1: unauthenticated AD signals | H: SMB/LDAP/Kerberos/DNS dispatchers `[verified: /srv/share/dev/aranum/aranumtoolkit/network/enum-smb.sh]` | P: wrappers plus Aranum import `[verified: /srv/share/dev/purplesploit/python/purplesploit/modules/recon/aranum.py]` | M `[inferred]` | M `[inferred]` | Legacy only `[verified: /srv/share/dev/pentest_scripts/enumeration/ad_enum.sh]` | P: planned AD-01 cases `[verified: /srv/share/dev/ShadowHex/docs/EXPANDED-AD-LINUX-APPLICATION-GATE-2026-11-02.md]` |
| P1: throttle/resume/coverage | P: throttles, manifests, state; large-domain proof pending `[verified: /srv/share/dev/aranum/aranumtoolkit/network/auto-enum.sh]` | P: jobs/coverage exist `[verified: /srv/share/dev/purplesploit/python/purplesploit/services/README.md]` | M `[inferred]` | M `[inferred]` | P: retry/parallel templates `[verified: /srv/share/dev/pentest_scripts/templates]` | P: queue/campaign concepts `[verified: /srv/share/dev/ShadowHex/docs/plans/JOB-QUEUE-BREAKDOWN-2026-11-07.md]` |
| P2: directory inventory | H: LDAP/AD posture collection `[verified: /srv/share/dev/aranum/aranumtoolkit/network/enum-ldap.sh]` | P: NXC modules and imported observations `[verified: /srv/share/dev/purplesploit/python/purplesploit/modules/network/nxc_ldap.py]` | P: collectors available `[verified: /srv/share/dev/28julytoolkit/ad-modern/README.md]` | M `[inferred]` | M `[inferred]` | P: planned, not qualified `[verified: /srv/share/dev/ShadowHex/docs/EXPANDED-AD-LINUX-APPLICATION-GATE-2026-11-02.md]` |
| P2: GPO/delegation/AD CS | P: multiple checks; completeness not truth-tested `[verified: /srv/share/dev/aranum/aranumtoolkit/network/enum-ldap.sh]` | P: individual operations `[verified: /srv/share/dev/purplesploit/python/purplesploit/modules/network/nxc_ldap.py]` | NW: Certipy/collector dependencies present `[verified: /srv/share/dev/28julytoolkit/ad-modern/wheelhouse]` | M `[inferred]` | M `[inferred]` | P: planned AD-04/AD-06 `[verified: /srv/share/dev/ShadowHex/docs/EXPANDED-AD-LINUX-APPLICATION-GATE-2026-11-02.md]` |
| P2: BloodHound collection | H when dependency installed `[verified: /srv/share/dev/aranum/aranumtoolkit/network/enum-ldap.sh]` | NW: NXC operations do not ingest artifacts `[verified: /srv/share/dev/purplesploit/python/purplesploit/modules/network/nxc_ldap.py]` | H: three collector options `[verified: /srv/share/dev/28julytoolkit/ad-modern/bloodhound-collectors/docs/README.md]` | M `[verified: /srv/share/dev/pt_provision/config/repositories.tsv]` | M `[inferred]` | P: planned AD-07 `[verified: /srv/share/dev/ShadowHex/docs/EXPANDED-AD-LINUX-APPLICATION-GATE-2026-11-02.md]` |
| P2: lockout-aware account use | P: stateful scheduler requires policy input `[verified: /srv/share/dev/aranum/standalones/creds/spray-scheduler.py]` | P: authentication outcomes and context exist `[verified: /srv/share/dev/purplesploit/docs/plans/PLAN-002-28OCT2026-aranum-purplesploit-integration.md]` | M `[inferred]` | M `[inferred]` | Legacy spray surfaces only `[verified: /srv/share/dev/pentest_scripts/initial-access/password_spray.sh]` | P: bounded credential adapters, AD unqualified `[verified: /srv/share/dev/ShadowHex/shadowhex/credentials.py]` |
| P3: full BloodHound ingest | M `[inferred]` | P: explicit subset importer `[verified: /srv/share/dev/purplesploit/python/purplesploit/interop/bloodhound.py]` | Collectors only `[verified: /srv/share/dev/28julytoolkit/ad-modern/README.md]` | M: no BHCE service `[verified: /srv/share/dev/pt_provision/config/repositories.tsv]` | M `[inferred]` | P: future gate only `[verified: /srv/share/dev/ShadowHex/docs/EXPANDED-AD-LINUX-APPLICATION-GATE-2026-11-02.md]` |
| P3: path analysis/prioritization | M `[inferred]` | P: generic graph paths/basic score `[verified: /srv/share/dev/purplesploit/python/purplesploit/core/attack_graph.py]` | M `[inferred]` | M `[inferred]` | M `[inferred]` | P: engine concepts, no AD proof `[verified: /srv/share/dev/ShadowHex/README.md]` |
| P3: findings/evidence model | H: structured findings/bundles `[verified: /srv/share/dev/aranum/aranumtoolkit/schemas/findings-2.schema.json]` | H: canonical findings/import/report services `[verified: /srv/share/dev/purplesploit/python/purplesploit/services/README.md]` | M `[inferred]` | Build manifests only `[verified: /srv/share/dev/pt_provision/deploy.sh]` | H: evidence workspaces `[verified: /srv/share/dev/pentest_scripts/evidence/workspace.py]` | H: records/ledger substrate `[verified: /srv/share/dev/ShadowHex/README.md]` |
| P4: auth/resource/command access | H: structured auth outcomes/local planning `[verified: /srv/share/dev/aranum/aranumtoolkit/network/local-enum.py]` | P: effective-access summaries `[verified: /srv/share/dev/purplesploit/docs/plans/PLAN-002-28OCT2026-aranum-purplesploit-integration.md]` | M `[inferred]` | M `[inferred]` | M `[inferred]` | P: credential adapters, not AD-qualified `[verified: /srv/share/dev/ShadowHex/shadowhex/credentials.py]` |
| P4: SSH/WinRM/compact execution | P: implemented, Windows live validation incomplete `[verified: /srv/share/dev/aranum/aranumtoolkit/network/local-enum.py]` | NW: Aranum local not exposed `[verified: /srv/share/dev/purplesploit/python/purplesploit/modules/recon/aranum.py]` | P: dependencies exist `[verified: /srv/share/dev/28julytoolkit/ad-modern/wheelhouse]` | M `[inferred]` | P: pivot helpers `[verified: /srv/share/dev/pentest_scripts/pivots]` | P: session substrate, not domain-qualified `[verified: /srv/share/dev/ShadowHex/README.md]` |
| P4: RDP/VNC/console | M: explicitly deferred `[verified: /srv/share/dev/aranum/aranumtoolkit/network/local-enum.py]` | P: RDP service modules, no local handoff `[verified: /srv/share/dev/purplesploit/python/purplesploit/modules]` | M `[inferred]` | M `[inferred]` | P: manual evidence capture only `[verified: /srv/share/dev/pentest_scripts/evidence/workspace.py]` | M for qualified AD flow `[verified: /srv/share/dev/ShadowHex/docs/EXPANDED-AD-LINUX-APPLICATION-GATE-2026-11-02.md]` |
| P5: Windows host checks | P: broad but incomplete `[verified: /srv/share/dev/aranum/standalones/windows/Invoke-PrivEscEnum.ps1]` | NW: deployment/operation surfaces, no Aranum local integration `[verified: /srv/share/dev/purplesploit/README.md]` | NW: supplementary tools present `[verified: /srv/share/dev/28julytoolkit/README.md]` | M `[inferred]` | Legacy checks only `[verified: /srv/share/dev/pentest_scripts/windows/privilege-escalation]` | P: future gate `[verified: /srv/share/dev/ShadowHex/docs/EXPANDED-AD-LINUX-APPLICATION-GATE-2026-11-02.md]` |
| P5: Linux host checks | H: collector and bulk SSH path `[verified: /srv/share/dev/aranum/aranumtoolkit/network/bulk-enum-linux.sh]` | NW: imported only through Aranum bundle `[verified: /srv/share/dev/purplesploit/docs/plans/PLAN-002-28OCT2026-aranum-purplesploit-integration.md]` | M `[inferred]` | M `[inferred]` | Legacy helper `[verified: /srv/share/dev/pentest_scripts/privilege-escalation/linux_privesc.sh]` | P: Linux cases planned `[verified: /srv/share/dev/ShadowHex/docs/EXPANDED-AD-LINUX-APPLICATION-GATE-2026-11-02.md]` |
| P5: fleet execution | P: bounded Windows/Linux bulk paths `[verified: /srv/share/dev/aranum/aranumtoolkit/network/bulk-enum-windows.py]` | P: jobs exist; local flow disconnected `[verified: /srv/share/dev/purplesploit/python/purplesploit/services/README.md]` | M `[inferred]` | M `[inferred]` | P: bounded-parallel templates `[verified: /srv/share/dev/pentest_scripts/templates/bash/bounded-parallel.sh]` | P: queue model, AD unqualified `[verified: /srv/share/dev/ShadowHex/docs/plans/JOB-QUEUE-BREAKDOWN-2026-11-07.md]` |
| P6: correlation/reporting | P: report/dashboard producer `[verified: /srv/share/dev/aranum/aranumtoolkit/network/report.py]` | H: canonical import, findings, coverage, reports `[verified: /srv/share/dev/purplesploit/python/purplesploit/services/README.md]` | M `[inferred]` | M `[inferred]` | P: separate evidence workspace `[verified: /srv/share/dev/pentest_scripts/evidence/workspace.py]` | P: records/report direction, not integrated `[verified: /srv/share/dev/ShadowHex/README.md]` |
| P6: durable multi-operator state | M `[inferred]` | P: SQLite plus in-memory coordinator `[verified: /srv/share/dev/purplesploit/python/purplesploit/distributed/README.md]` | M `[inferred]` | M `[inferred]` | M `[inferred]` | P: Postgres engine exists but is not the current AD toolchain `[verified: /srv/share/dev/ShadowHex/README.md]` |

---

## 4. Gap register

**Size guide:** `S` = approximately 1–3 engineering days, `M` = approximately 1–2 weeks, `L` = multi-sprint or architecture-level work. `[inferred]`

| ID | Phase | Gap and type | Impact | Selected closure | Size |
|---|---:|---|---|---|---:|
| G0-01 | 0 | No qualified Windows mini-domain with seeded truth; **missing**. `[verified: /srv/share/dev/ShadowHex/docs/EXPANDED-AD-LINUX-APPLICATION-GATE-2026-11-02.md]` | Transport, directory, graph, and host-check results cannot be measured for recall or false positives. `[inferred]` | Extend **ShadowHex** with the planned E2 mini-domain gate and reusable truth manifest. `[inferred]` | L |
| G0-02 | 0 | Attack-box definition omits native AD stack and BHCE; **partial**. `[verified: /srv/share/dev/pt_provision/config/repositories.tsv]` | The automation cannot run from a freshly provisioned engagement box. `[inferred]` | Extend **pt_provision** with OS packages, selected Python tools, collectors, containers, and smoke tests. `[inferred]` | M |
| G0-03 | 0 | Existing offline bundle predates current integration; **stale/untested**. `[verified: /srv/share/dev/pt_provision/pt-offline-bundle-20260915T023140Z.tar.gz.enc]` | Deployment may reproduce an older, incompatible tool set. `[inferred]` | Rebuild via **pt_provision** after pins and acceptance checks land. `[inferred]` | S |
| G0-04 | 0 | Tool inputs follow repository HEAD rather than a declared lock; **partial**. `[verified: /srv/share/dev/pt_provision/deploy.sh]` | Two builds can contain different versions before a bundle is produced. `[inferred]` | Add a commit/image/package lockfile to **pt_provision**. `[inferred]` | S |
| G1-01 | 1 | Initial discovery and Aranum enumeration are separate workflows; **not integrated**. `[verified: /srv/share/dev/aranum/aranumtoolkit/network/auto-enum.sh]` | Operators must manually bridge scan outputs and enumeration runs. `[inferred]` | Extend **PurpleSploit** with an engagement discovery workflow that emits Nmap XML and immediately starts Aranum importable enumeration. `[inferred]` | M |
| G1-02 | 1 | Unauthenticated AD coverage is broad but not measured against domain truth or large subnet scale; **untested**. `[verified: /srv/share/dev/aranum/aranumtoolkit/network/enum-smb.sh]` | Missing DCs, domains, or anonymously exposed data may go unnoticed. `[inferred]` | Extend **Aranum** test fixtures and run the Phase 0 lab gate at increasing host counts. `[inferred]` | M |
| G1-03 | 1 | Retry/resume and “not attempted versus absent” accounting are not proven for a large enterprise domain; **partial**. `[verified: /srv/share/dev/aranum/aranumtoolkit/schemas/run-state-1.schema.json]` | Partial runs may be mistaken for complete coverage. `[inferred]` | Extend **Aranum** with phase/host/check coverage ledgers and resumable queue tests. `[inferred]` | M |
| G2-01 | 2 | Authenticated directory data is collected through several commands but lacks a truth-tested completeness contract; **partial**. `[verified: /srv/share/dev/aranum/aranumtoolkit/network/enum-ldap.sh]` | Objects or relationship classes can be silently omitted. `[inferred]` | Extend **Aranum** with a versioned AD inventory schema and per-class counts/coverage. `[inferred]` | M |
| G2-02 | 2 | Lockout-aware scheduling requires manually supplied thresholds and intervals; **partial**. `[verified: /srv/share/dev/aranum/standalones/creds/spray-scheduler.py]` | Account-use automation is not automatically aligned with the policy discovered during enumeration. `[inferred]` | Extend **PurpleSploit** to derive a proposed budget from Aranum password-policy evidence and require operator confirmation before use. `[inferred]` | S |
| G2-03 | 2 | BloodHound collectors exist in multiple locations but are not wired into one run; **not integrated**. `[verified: /srv/share/dev/28julytoolkit/ad-modern/bloodhound-collectors/docs/README.md]` | Collection depends on operator memory and ad hoc file movement. `[inferred]` | Adopt **RustHound-CE** as primary and **bloodhound-ce-python** as fallback; wrap both in Aranum with structured collection receipts. `[inferred]` | M |
| G2-04 | 2 | AD CS/GPO/delegation outputs do not yet share one normalized completeness model; **partial**. `[verified: /srv/share/dev/aranum/aranumtoolkit/network/enum-ldap.sh]` | Domain-level issues are harder to compare, deduplicate, and mark complete. `[inferred]` | Extend **Aranum** schemas and KB classes rather than adding a separate repo. `[inferred]` | M |
| G3-01 | 3 | No provisioned BloodHound CE analysis service; **missing**. `[verified: /srv/share/dev/pt_provision/config/repositories.tsv]` | Collected graphs cannot be reliably ingested and queried on a fresh attack box. `[inferred]` | Add pinned **BloodHound CE** containers and lifecycle checks to **pt_provision**. `[inferred]` | M |
| G3-02 | 3 | PurpleSploit BloodHound importer retains only a limited relationship subset; **partial**. `[verified: /srv/share/dev/purplesploit/python/purplesploit/interop/bloodhound.py]` | ACL, GPO, delegation, remote-access, and other path semantics may be omitted from its local graph. `[inferred]` | Keep **BloodHound CE authoritative**; extend PurpleSploit to register collections and import query results/path summaries rather than cloning all semantics initially. `[inferred]` | M |
| G3-03 | 3 | NetExec BloodHound operations do not automatically locate and ingest their artifacts; **not integrated**. `[verified: /srv/share/dev/purplesploit/python/purplesploit/modules/network/nxc_ldap.py]` | A successful collection can finish without becoming usable graph state. `[inferred]` | Extend **PurpleSploit** operation results with declared output artifacts and collection-import jobs. `[inferred]` | S |
| G3-04 | 3 | Generic path scoring is too simple for AD prioritization; **partial**. `[verified: /srv/share/dev/purplesploit/python/purplesploit/core/attack_graph.py]` | Path ordering may not reflect reachability, evidence confidence, prerequisite count, or number of affected assets. `[inferred]` | Extend **PurpleSploit** with a versioned BloodHound query pack and evidence-based prioritization model. `[inferred]` | M |
| G4-01 | 4 | RDP/VNC local transports were deferred; **missing**. `[verified: /srv/share/dev/aranum/aranumtoolkit/network/local-enum.py]` | Hosts reachable only through interactive desktop access cannot enter the automated local pipeline. `[inferred]` | Implement Aranum **S5**, beginning with RDP-native collection and assisted VNC. `[inferred]` | L |
| G4-02 | 4 | Aranum local access is not exposed through PurpleSploit; **not integrated**. `[verified: /srv/share/dev/purplesploit/python/purplesploit/modules/recon/aranum.py]` | Operators must leave the console to run host enumeration and manually reimport results. `[inferred]` | Extend the **PurpleSploit Aranum adapter** with the existing local bundle contract. `[inferred]` | M |
| G4-03 | 4 | WinRM/Windows bulk transport lacks real-domain qualification; **untested**. `[verified: /srv/share/dev/aranum/aranumtoolkit/docs/ADR-003-20MAY2026-windows-bulk-enum-design.md]` | The primary Windows fleet path may fail during the engagement. `[inferred]` | Reuse existing **Aranum** transport and qualify it in the Phase 0 lab before adding alternatives. `[inferred]` | S |
| G4-04 | 4 | Console/manual session outcomes have no standard import route; **missing**. `[inferred]` | Local observations from console or operator-assisted RDP become separate notes rather than correlated access evidence. `[inferred]` | Extend **PurpleSploit** with a manual-session record/import form using the same access and evidence model. `[inferred]` | S |
| G5-01 | 5 | Writable directory coverage is PATH-centric rather than a bounded `C:\`/share assessment; **partial**. `[verified: /srv/share/dev/aranum/standalones/windows/Get-WritablePathDirs.ps1]` | Writable shared or operational directories can be missed. `[inferred]` | Extend **Aranum** with bounded ACL-first directory/share enumeration and exclusions. `[inferred]` | M |
| G5-02 | 5 | Scheduled-task analysis checks action executable ACLs but not every referenced script, argument, or working directory; **partial**. `[verified: /srv/share/dev/aranum/standalones/windows/Get-ScheduledTasks.ps1]` | Modifiable privileged task chains can be underreported. `[inferred]` | Extend **Aranum** scheduled-task normalization and effective-rights checks. `[inferred]` | M |
| G5-03 | 5 | Broad autorun/startup/DLL search-path coverage was not found in the reviewed main collector; **missing or partial**. `[verified: /srv/share/dev/aranum/standalones/windows/Invoke-PrivEscEnum.ps1]` `[inferred]` | Common local misconfiguration classes are not covered uniformly. `[inferred]` | Adopt read-side logic from an established collector such as **PrivescCheck** or **winPEAS**, normalize the results in Aranum, and retain Aranum-native focused checks where stronger. `[inferred]` | M |
| G5-04 | 5 | Default writable-PATH checks perform target writes without an explicit write-mode switch; **functional contract mismatch**. `[verified: /srv/share/dev/aranum/standalones/windows/Get-WritablePathDirs.ps1]` `[verified: /srv/share/dev/aranum/CLAUDE.md]` | The default collection behavior does not match Aranum’s required invariant. `[inferred]` | Change **Aranum** default to effective-ACL evaluation; place write validation behind explicit `--write` and record the validation mode. `[inferred]` | S |
| G5-05 | 5 | Fleet-scale completion, retries, timeouts, and partial-host behavior are not demonstrated against a domain-sized lab; **untested**. `[verified: /srv/share/dev/aranum/aranumtoolkit/network/bulk-enum-windows.py]` | A large run can leave silent host gaps or require substantial manual cleanup. `[inferred]` | Extend **Aranum** fleet state and run staged 10/50/200-host synthetic acceptance tests plus the real mini-domain. `[inferred]` | M |
| G6-01 | 6 | PurpleSploit canonical and job state is not yet a durable shared multi-operator store; **partial**. `[verified: /srv/share/dev/purplesploit/python/purplesploit/distributed/README.md]` | Operators cannot reliably share ownership, leases, progress, and restartable work. `[inferred]` | Extend **PurpleSploit** to a Postgres-backed engagement store and durable job coordinator. `[inferred]` | L |
| G6-02 | 6 | Aranum, PurpleSploit, and `pentest_scripts` evidence manifests are separate; **not integrated**. `[verified: /srv/share/dev/pentest_scripts/evidence/workspace.py]` | Team evidence and generated findings require manual reconciliation. `[inferred]` | Add a **pentest_scripts** evidence-workspace bridge that registers Aranum bundles and PurpleSploit exports. `[inferred]` | S |
| G6-03 | 6 | Graph paths, host posture, access state, and service findings lack one deduplication/correlation rule set; **partial**. `[verified: /srv/share/dev/purplesploit/python/purplesploit/services/README.md]` | Duplicate findings and unlinked paths make prioritization less useful. `[inferred]` | Extend **PurpleSploit** canonical correlation and finding lineage. `[inferred]` | M |
| G6-04 | 6 | ShadowHex AD integration remains an open gate; **untested**. `[verified: /srv/share/dev/ShadowHex/docs/EXPANDED-AD-LINUX-APPLICATION-GATE-2026-11-02.md]` | Making it the controller now would add an unqualified dependency to the engagement. `[inferred]` | Accept the gap for the current critical path; reconsider ShadowHex after E2/E3 pass. `[inferred]` | S decision |

---

## 5. Phased sub-goal roadmap

All roadmap items below are proposed work. `[inferred]`

### Phase 0 — Lab and provisioning

| ID | Objective | Input | Deliverable artifact | Acceptance criteria | Dependencies | Repo |
|---|---|---|---|---|---|---|
| P0-01 | Build a minimal AD truth lab: DC, member server, workstation, ordinary user, delegated user, local administrator, seeded shares/tasks/services/GPO relationships, and optional enterprise CA. | ShadowHex E2 specification; engagement target versions. | Versioned lab definition plus `truth.json`. | Clean rebuild succeeds twice; expected users, computers, groups, policies, services, shares, and seeded relationships match `truth.json`. | Team lead chooses OS/domain versions. | ShadowHex |
| P0-02 | Define the engagement attack-box manifest. | Current host gap list; Aranum dependency checks; `28julytoolkit/ad-modern`. | `ad-attack-box.lock` covering native packages, Python tools, collectors, BHCE images, and versions. | Fresh VM exposes all required binaries and passes version/smoke checks without manual installation. | P0-01 topology known. | `pt_provision` |
| P0-03 | Produce a deterministic online/offline build. | P0-02 lockfile; existing provisioner. | New encrypted offline bundle, manifest, and build report. | Two builds from the same lock resolve identical commits/package/image identifiers; offline bootstrap passes. | P0-02. | `pt_provision` |
| P0-04 | Establish cross-repo fixture compatibility. | Existing Aranum PLAN-002 bundles and PurpleSploit fixtures. | CI acceptance suite for bundle → import → views → report. | Complete and partial bundles import without dropping declared records; fixture counts match expected values. | Existing PLAN-002 contract. | PurpleSploit |
| P0-05 | Qualify live Windows transports. | Mini-domain; low-priv and local-admin test contexts. | Transport qualification matrix and captured test bundles. | Local, Windows SSH if enabled, WinRM, and each compact transport produce explicit success/denied/unavailable/partial outcomes. | P0-01, P0-03. | Aranum |
| P0-06 | Promote to a larger GOAD-equivalent lab after the minimal gate is stable. | Mini-domain results; required enterprise features. | Expanded truth manifest and nightly acceptance profile. | Multi-domain/trust/GPO/AD CS paths are detected with measured recall; failures identify the missing collection class. | P0-01 through P0-05. | ShadowHex |

### Phase 1 — Unauthenticated discovery and enumeration

| ID | Objective | Input | Deliverable artifact | Acceptance criteria | Dependencies | Repo |
|---|---|---|---|---|---|---|
| P1-01 | Create one discovery workflow from scope to Nmap XML to Aranum bundle. | Engagement scope, scan/noise profile. | PurpleSploit workflow and run manifest. | A single queued workflow discovers the lab systems, preserves Nmap XML, runs Aranum, and imports the bundle under one run ID. | P0-03, P0-04. | PurpleSploit |
| P1-02 | Define an unauthenticated AD profile. | DNS, SMB, LDAP, Kerberos, RPC, RDP, WinRM targets. | Versioned Aranum engagement profile and structured coverage rows. | Lab DCs and domain names are discovered; anonymous/denied/not-supported states are distinguished; no credentials are required. | P1-01. | Aranum |
| P1-03 | Make unauthenticated enumeration resumable. | Existing queue/run-state schemas. | Persistent phase/host/check work ledger. | Interrupting and resuming a run does not repeat completed checks unnecessarily and does not mark skipped checks as absent. | P1-02. | Aranum |
| P1-04 | Add scale/noise acceptance. | Synthetic 10/50/200-host inventories and mini-domain. | Performance and completeness report. | Configured concurrency and delay are respected; every target/check receives a terminal coverage status; DC recall matches truth. | P1-03. | Aranum |

### Phase 2 — Authenticated low-privilege domain enumeration

| ID | Objective | Input | Deliverable artifact | Acceptance criteria | Dependencies | Repo |
|---|---|---|---|---|---|---|
| P2-01 | Define account-use budgets from domain policy. | Aranum password-policy evidence; team ROE limits. | PurpleSploit credential-use plan with operator approval state. | Proposed threshold/interval never exceeds the configured ROE budget; every attempt is attributable to a credential context and run. | P1-02. | PurpleSploit |
| P2-02 | Normalize complete directory inventory. | Low-priv domain credential; LDAP/SMB evidence. | `ad-inventory-v1` objects, relationship counts, and coverage summary. | Users, groups, computers, OUs, trusts, GPOs, SPNs, delegations, and relevant LAPS/gMSA visibility match lab truth or are marked unavailable. | P2-01. | Aranum |
| P2-03 | Integrate BloodHound collection. | RustHound-CE and BloodHound CE Python from `28julytoolkit`. | Aranum collector adapter, raw CE zip, collection receipt, and manifest entries. | Primary and fallback collectors run from the provisioned attack box; output is associated with the same run/domain/credential context. | P0-02, P2-02. | Aranum |
| P2-04 | Normalize GPO, delegation, and AD CS findings. | Directory inventory, Certipy/read-side ADSI outputs. | Structured Aranum findings with affected objects and evidence references. | Each seeded lab condition yields one canonical finding; negative controls remain clear; unsupported checks are visible in coverage. | P2-02, optional lab CA. | Aranum |
| P2-05 | Run authenticated truth comparison. | Mini-domain truth plus collection bundles. | Machine-readable expected/actual diff. | Object and relationship recall thresholds agreed by the team are met; every discrepancy is classified as collector, permission, parser, or fixture behavior. | P2-02 through P2-04. | ShadowHex |

### Phase 3 — Graph analysis, prioritization, and findings model

| ID | Objective | Input | Deliverable artifact | Acceptance criteria | Dependencies | Repo |
|---|---|---|---|---|---|---|
| P3-01 | Provision BloodHound CE as the authoritative AD graph service. | P0-02 image pins and attack-box design. | BHCE deployment profile and health/import smoke test. | Fresh attack box starts BHCE and imports the Phase 2 lab collection without manual repair. | P0-03, P2-03. | `pt_provision` |
| P3-02 | Automate collection registration and ingest. | Aranum collection receipt and CE zip. | PurpleSploit artifact/import job and import receipt. | Completion of P2-03 automatically creates an ingest job; success/failure and collection identifiers appear in the run. | P3-01. | PurpleSploit |
| P3-03 | Create a versioned AD query pack. | BHCE graph; owned principals; high-value targets. | Query definitions and normalized path-summary schema. | Seeded shortest paths, high-value exposure, delegation, ACL, GPO, session, and AD CS paths are returned consistently. | P3-02. | PurpleSploit |
| P3-04 | Add evidence-based path prioritization. | Path summaries, access state, finding severity, prerequisites, affected-host counts. | Ranked path findings with factor breakdown. | Ranking is deterministic; paths with unproven prerequisites are not presented as confirmed; operators can see why one path ranks above another. | P3-03. | PurpleSploit |
| P3-05 | Validate the finding model against graph truth. | Seeded lab paths and negative controls. | Path expected/actual suite and review report. | Every expected path maps to its source graph edges and collection; removed edges remove or downgrade the corresponding finding. | P3-04. | ShadowHex |

### Phase 4 — Local access capabilities

| ID | Objective | Input | Deliverable artifact | Acceptance criteria | Dependencies | Repo |
|---|---|---|---|---|---|---|
| P4-01 | Define a consistent access-capability model. | Authentication outcomes, share access, command execution, desktop sessions, console observations. | Schema distinguishing `auth`, `resource-read`, `resource-write`, `command`, `interactive-desktop`, and `console`. | The same credential can have different capabilities per host/service without collapsing them into one “valid” state. | P2-01. | PurpleSploit |
| P4-02 | Expose Aranum local through the operator console. | Existing Aranum local CLI and bundle importer. | PurpleSploit local-enumeration module/workflow. | Operator selects eligible hosts and a credential context; results return through the normal Aranum bundle importer. | P0-05, P4-01. | PurpleSploit |
| P4-03 | Finish RDP/VNC S5. | Existing Aranum transport abstraction; lab desktop hosts. | RDP-native collection path and assisted VNC workflow. | RDP-supported lab hosts produce collection artifacts; VNC clearly records assisted/manual status; unavailable prerequisites produce explicit coverage states. | P0-05. | Aranum |
| P4-04 | Capture console and manual-session results. | Console/RDP observations and operator evidence. | Manual-session record tied to host, operator, credential context, and evidence files. | A manual local assessment appears in the same access and coverage views as an automated one without claiming automated proof. | P4-01. | PurpleSploit |
| P4-05 | Prevent invalid fleet dispatch. | Access-capability records. | Eligibility filters and dispatch preview. | Local enumeration is queued only where the selected transport capability is evidenced; denied/unavailable hosts remain visible but unqueued. | P4-01 through P4-04. | PurpleSploit |

### Phase 5 — Local host enumeration and privilege-escalation checks at scale

| ID | Objective | Input | Deliverable artifact | Acceptance criteria | Dependencies | Repo |
|---|---|---|---|---|---|---|
| P5-01 | Align writable-path checks with Aranum’s target-write invariant. | Existing PATH collector and repo invariant. | ACL-first collector plus explicit optional `--write` validation mode. | Default run creates no validation file; explicit write mode is recorded and detects the seeded writable location. | P0-01. | Aranum |
| P5-02 | Expand Windows directory/share coverage. | Local volumes, shares, ACLs, bounded exclusions. | Structured writable-location and share-permission findings. | Seeded writable shared directories and selected `C:\` paths are found; system-noise paths are bounded; affected principal and evidence are recorded. | P5-01. | Aranum |
| P5-03 | Expand task/service/autorun search paths. | Scheduled tasks, services, startup entries, referenced actions, focused OSS collector logic. | Normalized host findings for action-chain and startup misconfigurations. | Each seeded executable/script/argument/working-directory/autorun case is found; negative controls remain clear. | P5-01. | Aranum |
| P5-04 | Make fleet execution restartable and coverage-aware. | Host eligibility, transport outcomes, host collectors. | Fleet queue with leases, retry policy, per-host terminal states, and rollup. | Killing and restarting a 50-host simulated run retains completed work and reports success/denied/timeout/partial/unreachable independently. | P4-05. | Aranum |
| P5-05 | Validate Linux parity. | Existing Linux host-posture and privilege-enumeration collectors. | Linux truth fixtures and coverage report. | Seeded sudo, SUID, capabilities, cron, group, container, and writable-file cases are detected with explicit negative controls. | P5-04. | Aranum |
| P5-06 | Execute a mixed-estate acceptance gate. | Windows and Linux lab hosts with seeded positives/negatives. | Signed-off Phase 5 acceptance report and bundles. | All mandatory check classes have a terminal coverage state; expected positives are found; unsupported cases are listed rather than silently omitted. | P5-02 through P5-05. | ShadowHex |

### Phase 6 — Correlation, reporting, and team workflow

| ID | Objective | Input | Deliverable artifact | Acceptance criteria | Dependencies | Repo |
|---|---|---|---|---|---|---|
| P6-01 | Move canonical engagement state to a shared durable database. | Current SQLite models and service layer. | Postgres implementation plus migration/import tool. | Two operators see the same targets, credentials references, runs, findings, coverage, and assignments; restart does not lose state. | Stable schemas from Phases 1–5. | PurpleSploit |
| P6-02 | Make distributed jobs durable. | Existing coordinator protocol. | Persistent jobs, leases, workers, artifacts, retries, and cancellation. | Worker restart and coordinator restart preserve pending/running work; duplicate completion is handled deterministically. | P6-01. | PurpleSploit |
| P6-03 | Bridge the evidence workspace. | Aranum bundles, BH collection receipts, PurpleSploit exports. | `pts evidence register-engagement-run` or equivalent. | One command registers all run artifacts in a `pentest_scripts` evidence workspace and verifies expected files are present. | P3-02, P5-04. | `pentest_scripts` |
| P6-04 | Correlate graph, domain, host, access, and service findings. | Canonical observations and evidence references. | Versioned correlation/deduplication rules. | Duplicate manifestations merge without losing affected hosts or evidence; graph paths reference contributing domain/local findings. | P6-01. | PurpleSploit |
| P6-05 | Produce team and client-ready views. | Correlated findings, assignments, coverage, retest state. | Operator dashboard plus Markdown/HTML/PDF/XLSX report pack. | Report shows domain coverage, host coverage, incomplete checks, ranked attack paths, local findings, evidence references, ownership, and retest status. | P6-02, P6-04. | PurpleSploit |
| P6-06 | Decide whether ShadowHex becomes the future controller. | Passed E2/E3 AD gates and a completed Aranum/PurpleSploit run. | Architecture decision record. | Adopt only if ShadowHex can reproduce the run without losing data or duplicating producer/consumer responsibilities; otherwise retain it as the lab gate harness. | P6-05. | ShadowHex |

---

## 6. Integration architecture

### Recommended ownership

| Concern | Authority |
|---|---|
| Scan and service/raw enumeration artifacts | Aranum `[inferred]` |
| AD graph relationships and graph queries | BloodHound CE `[inferred]` |
| Engagement targets, credential contexts, access capabilities, findings, coverage, assignments, and job state | PurpleSploit `[inferred]` |
| Attack-box build and tool pins | `pt_provision` `[inferred]` |
| Operator workstation, pivots, packet helpers, and external evidence workspace | `pentest_scripts` `[inferred]` |
| Lab truth and acceptance gates | ShadowHex `[inferred]` |

### Proposed shared artifact layout

```text
engagements/<engagement-id>/
├── scope/
│   ├── targets.json
│   ├── exclusions.json
│   └── operating-profile.json
├── tool-lock/
│   ├── ad-attack-box.lock
│   └── build-manifest.json
├── runs/<run-id>/
│   ├── discovery/
│   │   └── nmap.xml
│   ├── aranum/
│   │   └── bundle/
│   ├── bloodhound/
│   │   ├── collection.zip
│   │   └── import-receipt.json
│   ├── manual/
│   └── exports/
└── reports/
```

This file store should hold raw and rendered artifacts; PurpleSploit’s shared database should hold references, normalized records, workflow state, and correlations. `[inferred]`

### Data contracts

- **Discovery:** Nmap XML is the handoff from the discovery job to Aranum. `[verified: /srv/share/dev/aranum/aranumtoolkit/network/nmap-parse.py]`
- **Aranum bundle:** `bundle-manifest-1`, `findings-2`, `inventory-1`, `posture-1`, `run-state-1`, KB subset, authentication outcomes, coverage, per-host summaries, and raw artifacts. `[verified: /srv/share/dev/aranum/aranumtoolkit/schemas]` `[verified: /srv/share/dev/purplesploit/docs/plans/PLAN-002-28OCT2026-aranum-purplesploit-integration.md]`
- **BloodHound:** collector-native BloodHound CE ZIP/JSON plus a collection receipt containing run, domain, collector, version, credential-context reference, and hashes. `[inferred]`
- **PurpleSploit:** canonical observations, findings, access capabilities, coverage rows, workflow/job records, graph-query summaries, and report state. `[verified: /srv/share/dev/purplesploit/python/purplesploit/services/README.md]`
- **Evidence workspace:** raw artifacts remain files; `pentest_scripts` registers them into its workspace manifest rather than copying data into a second findings database. `[inferred]`
- **Reports:** PurpleSploit renders Markdown, HTML, PDF, and XLSX from canonical findings and coverage. `[verified: /srv/share/dev/purplesploit/python/purplesploit/reporting]`

### One automated run

1. The lead defines scope, exclusions, concurrency, noise level, account-use budget, and required coverage. `[inferred]`
2. PurpleSploit creates a run and executes discovery, preserving Nmap XML. `[inferred]`
3. PurpleSploit invokes Aranum’s unauthenticated profile; Aranum emits a bundle containing inventory, signals, raw evidence, coverage, and findings. `[inferred]`
4. PurpleSploit imports the bundle and proposes authenticated jobs based on discovered domains, DCs, services, and the approved credential context. `[inferred]`
5. Aranum performs low-privilege directory, SMB, GPO, delegation, AD CS, and BloodHound collection, emitting a second bundle and collection receipt. `[inferred]`
6. PurpleSploit registers the graph artifact and queues BloodHound CE ingest. The query pack returns normalized paths and contributing graph-edge references. `[inferred]`
7. PurpleSploit correlates path prerequisites with proven access capabilities and ranks paths without treating unproven prerequisites as confirmed. `[inferred]`
8. Hosts with console, RDP, SSH, WinRM, or compact command capability are placed in the local-assessment queue according to the proven transport. `[inferred]`
9. Aranum runs Windows/Linux host collectors with bounded concurrency and per-host terminal coverage states, then PurpleSploit imports the resulting bundles. `[inferred]`
10. PurpleSploit deduplicates domain, graph, access, service, and local findings; assigns work; tracks retests; and renders reports. `[inferred]`
11. `pentest_scripts` registers the run’s raw artifacts and exports into the external evidence workspace. `[inferred]`

### ShadowHex decision boundary

ShadowHex should initially execute lab gates and compare actual outputs with truth manifests. `[inferred]` It should not dispatch production engagement work until its real Windows mini-domain and mixed Aranum/BloodHound/PurpleSploit gates pass. `[inferred]` If those gates pass, it can later be evaluated as the outer campaign controller while Aranum and PurpleSploit retain their producer/consumer roles. `[inferred]`

---

## 7. Open questions for the team lead

1. Which Windows Server and workstation versions must the mini-domain represent, and must the first lab include AD CS, Exchange, SCCM/MECM, multiple domains, or trusts? `[inferred]`
2. Is GOAD or an equivalent multi-domain environment acceptable for Phase 0 expansion, or must the lab mirror the production domain’s topology and functional levels? `[inferred]`
3. What OS and architecture will the engagement attack box use, and must it operate fully offline after deployment? `[inferred]`
4. What refresh cadence should apply to the pinned attack-box bundle: per engagement, monthly, or only after qualification? `[inferred]`
5. Should BloodHound CE remain the authoritative graph engine, with PurpleSploit importing path summaries, or is full native BloodHound semantic parity inside PurpleSploit a requirement? `[inferred]`
6. For writable paths and shares, should default assessment be ACL-only, with file creation permitted only under an explicit `--write` validation mode? `[inferred]`
7. Is assisted VNC acceptable, or must Phase 4 provide fully automated collection for every interactive desktop transport? `[inferred]`
8. What account-lockout and traffic budgets must the default engagement profile enforce per principal, subnet, service, and hour? `[inferred]`
9. How many concurrent operators and workers must the shared PurpleSploit deployment support? `[inferred]`
10. Is console access expected to be common enough to warrant a dedicated manual-session workflow in the first release, or can it follow RDP/WinRM integration? `[inferred]`
11. What minimum recall threshold should gate authenticated directory and BloodHound collection against lab truth? `[inferred]`
12. What exact ShadowHex milestone permits reconsidering it as the production controller: E2 only, E2 plus E3, or the full E4/GOAD-equivalent gate? `[inferred]`
13. Which reporting destinations are required beyond the built-in report pack—for example Jira, a shared case system, or a team collaboration channel? `[inferred]`
---

## 8. Owner decisions (14NOV2026, recorded by the orchestrator)

Answers to the Phase 0-blocking questions. They are constraints for PLAN-003
(`purplesploit/docs/plans/PLAN-003-14NOV2026-ad-engagement-toolchain.md`).

| ID | Question | Decision |
|---|---|---|
| C1 | Lab contents (Q1/Q2) | Start with GOAD. Once that gate is cleared, add forests, AD CS, etc. |
| C2 | Attack box (Q3) | Linux, Kali or Debian; must run fully offline after deployment. |
| C3 | Writable-path default (Q6) | Yes: ACL/effective-rights evaluation by default; file creation only under explicit `--write`. |
| C4 | Lockout / traffic budgets (Q8) | Leave unset for now. |
| C5 | Concurrent operators (Q9) | 1-5. |

Orchestrator check of G5-04 (14NOV2026): `aranum/standalones/windows/Get-WritablePathDirs.ps1`
has an empty `param()` (line 9) and writes then deletes `.write_test_<guid>` in every PATH
directory unconditionally (lines 15-17). Confirmed.

Orchestrator facts added for PLAN-003: `pt_provision` and `28julytoolkit` are git repos with
**zero commits** (no base SHA); net0srv offers libvirt/KVM with 32 cores, 62 GB RAM, 1.2 TB free.

Follow-up owner decisions (14NOV2026, after PLAN-003 peer review round 1):

| ID | Question | Decision |
|---|---|---|
| C1 (final) | Which GOAD variant is the first gate? | Full upstream `ad/GOAD` (5 VMs, 2 forests, 3 domains, AD CS). Later forests/AD CS = additional profiles. Workstation coverage (full GOAD has none) via a later profile, e.g. the upstream `extensions/ws01`. |
| C6 | Where does the lab run? | net0srv with VirtualBox + Vagrant, after a 1-day coexistence spike with the running KVM VMs. If the spike fails, the lab sprint is `blocked` until another host is named. |
