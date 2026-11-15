# PLAN-003 r3 — independent review record (Astra, two rounds)

- **Artifact:** `docs/plans/PLAN-003-14NOV2026-ad-engagement-toolchain.md` r3. Also the errata line in `docs/research/AD-TOOLING-ASSESSMENT-14NOV2026-gap-analysis-and-roadmap.md`.
- **Why r3:** owner directive, 14NOV2026: no ShadowHex and no LLM anywhere in the engagement, the lab or analysis. The SP0-01 harness moved to the new LLM-free repo `ad-lab-harness`.
- **Author:** Sol (`gpt-6.1-sol`) drafted r3 and the fix round. The orchestrating session corrected both before committing (see below).
- **Reviewer:** Astra (`gpt-6-astra`), cross-family top tier, read-only, run through a file handoff.
- **Commits:** `562f8cb` is r3 and was reviewed in round 1. `54818f8` is the fix round and was reviewed in round 2.
- **Outcome:** round 1 FIX-FIRST (2 MEDIUM); round 2 **SHIP**, no new BLOCKER or HIGH. The review limit is two rounds, so this cycle is closed.

## Disposition

| ID | Severity | Finding (round 1) | Disposition | Verified by orchestrator | Round 2 |
|---|---|---|---|---|---|
| F1 | MEDIUM | The recovery rules for an inconclusive SP0-01 conflicted. Line 475 said installing and rerunning unblocks P0-S1; lines 167 and 487 required another host after any inconclusive. | **Accepted.** One rule is now applied at lines 15, 143, 168, 237, 367, 476 and 488. A `fail` means the owner names another host (C6). An `inconclusive` means fixing the prerequisite or harness cause and rerunning once; if it is still inconclusive, the owner names another host. P0-S1 stays blocked until a `pass`, and the pre-install dry run does not use up the rerun. | Each line read. The rule matches the harness decision tree, `ad-lab-harness` `docs/plans/PLAN003-SP0-01-PROVIDER-COEXISTENCE-2026-11-14.md:89` (row "Final fail or inconclusive"). | Resolved |
| F2 | MEDIUM | The blanket C7 module ban conflicted with the console startup that P0-S3 needs: `console.py:43` calls `provider_from_environment()`, and `application.py:169` constructs `AdvisoryService`. | **Accepted.** C7 (lines 45 and 49) now allows inert startup: with `PURPLESPLOIT_AI_PROVIDER` unset the provider is `None`. It still forbids `AdvisoryProvider.generate`, `AdvisoryService.analyze` and `propose_workflow`, and `modules/ai/ai_automation.py` operations. The P0-S3 SDK-absence row (line 780) also asserts that the variable is unset (an empty value fails) and that `console.services.advisory.provider is None`. | `advisory.py:146` (`generate`), `:169` (`analyze`) and `:193` (`propose_workflow`) all exist, so every forbidden entrypoint C7 names is real. | Resolved |

Astra round 1 also checked and found clean:
- the classification of the eight `ai/` modules;
- that the withdrawal of G6-04, P6-S3 and P6-06 is consistent (18 now, 10 later, 1 withdrawn);
- the harness path mapping;
- that the SDK-absence test cannot pass vacuously;
- that the toolkit and harness status facts match their records.

## Orchestrator corrections to peer drafts (applied before commit)

| Draft | Problem | Correction |
|---|---|---|
| r3 (Sol) | Six provenance labels said "owner-supplied" for values the orchestrating session had measured. | Re-measured each value and replaced the label with the command that produced it, for example `[measured: git -C /srv/share/dev/28julytoolkit rev-parse HEAD plan003-p0-source-base^{commit}, 14NOV2026]`. |
| Fix round (Sol) | It rewrote two historical r1 disposition rows, R4 and "Blocked contingency" (now lines 1192 and 1209). | Restored the original text and added *"Superseded in r3: see the SP0-01 recovery reconciliation in Revision r3 and §2.2."*, keeping the errata beside the original rather than rewriting history. |

---

## Round 1 — verbatim (Astra, `/tmp/codex-out/plan003-r3-astra-review-14NOV2026-221632.md`, line numbers are at `562f8cb`)

VERDICT: FIX-FIRST

1. **MEDIUM — [PLAN-003-14NOV2026-ad-engagement-toolchain.md:475](/srv/share/dev/purplesploit/.claude/worktrees/codex-plan003-r3/docs/plans/PLAN-003-14NOV2026-ad-engagement-toolchain.md:475): Conflicting recovery rules for the recorded inconclusive result.** The new status says installing prerequisites and passing a rerun on net0srv unblocks P0-S1. But lines 167 and 487 require the owner to name another host after **any** inconclusive SP0-01 result. An executor following those clauses must keep P0-S1 blocked even after the prescribed successful retry. The test card supports the prerequisite-install/retry next step, but r3 incorrectly claims the decision tree remains unchanged. **Minimal fix:** explicitly distinguish prerequisite-only retries from coexistence failure/inconclusive outcomes, reconcile all affected clauses, and cite the recorded authority for that distinction.

2. **MEDIUM — [PLAN-003-14NOV2026-ad-engagement-toolchain.md:44](/srv/share/dev/purplesploit/.claude/worktrees/codex-plan003-r3/docs/plans/PLAN-003-14NOV2026-ad-engagement-toolchain.md:44): The blanket module-invocation ban conflicts with required console startup.** P0-S3 explicitly tests console startup, which calls `provider_from_environment()` at [console.py:43](/srv/share/dev/purplesploit/.claude/worktrees/codex-plan003-r3/python/purplesploit/ui/console.py:43) and constructs `AdvisoryService` at [application.py:169](/srv/share/dev/purplesploit/.claude/worktrees/codex-plan003-r3/python/purplesploit/services/application.py:169). These execute code in two excluded modules even with no provider configured. They do **not** call an LLM or import its SDK, so the SDK test can pass while the broader C7 prohibition remains unsatisfied. **Minimal fix:** explicitly permit inert, provider-disabled startup construction while retaining the excluded analysis/operation entrypoints, or assign removal of that startup coupling before P0-S3 acceptance.

Checked and found clean:

- Full r3 plan and two-file diff reviewed; no active ShadowHex dependency remains. Assessment-body references are explicitly historical.
- All eight AI classification rows agree with the inspected code; no LLM-calling module is misclassified as deterministic.
- G6-04/P6-S3/P6-06 withdrawal is consistent; sprint identities match detailed sections. Counts are **18 now, 10 later, 1 withdrawn**.
- Harness path mappings, command working directories, output ownership, and rollback references agree.
- The SDK-absence specification is non-vacuous for attempted SDK imports, including caught imports and child processes.
- Toolkit and harness status claims agree with the cited records and revision history.
- No other unrelated gate, denominator, baseline-value, or decision-tree change found. No files edited or test suites run.

---

## Round 2 — verbatim (Astra, `/tmp/codex-out/plan003-r3-astra-r2-14NOV2026-222906.md`, line numbers are at `54818f8`)

VERDICT: SHIP

| Finding | Status | Evidence |
|---|---|---|
| Round-1 #1: conflicting SP0-01 recovery rules | Resolved | [Plan:168](/srv/share/dev/purplesploit/.claude/worktrees/codex-plan003-r3/docs/plans/PLAN-003-14NOV2026-ad-engagement-toolchain.md:168), also lines 476 and 488: failure requires another host; inconclusive permits correction and one rerun; the pre-install dry run is exempt. P0-S1 still requires a pass. The cited [authority:89](/srv/share/dev/ad-lab-harness/docs/plans/PLAN003-SP0-01-PROVIDER-COEXISTENCE-2026-11-14.md:89) supports the recovery rule. |
| Recovery consistency throughout the plan | Confirmed | [Plan:15](/srv/share/dev/purplesploit/.claude/worktrees/codex-plan003-r3/docs/plans/PLAN-003-14NOV2026-ad-engagement-toolchain.md:15), C6:44, and lines 143, 168, 237, 367, 476 and 488 agree. Historical r1 rows at lines 1192 and 1209 explicitly mark their former wording superseded. |
| Round-1 #2: C7 conflicts with console startup | Resolved | [Plan:45](/srv/share/dev/purplesploit/.claude/worktrees/codex-plan003-r3/docs/plans/PLAN-003-14NOV2026-ad-engagement-toolchain.md:45), also lines 12, 49 and 53–60: permits inert construction with the provider unset/`None`, while retaining excluded operations and local fallbacks. This matches `console.py:43`, `application.py:169` and `providers.py:12`. |
| Extended P0-S3 test decides its property | Confirmed as specified | [Plan:780](/srv/share/dev/purplesploit/.claude/worktrees/codex-plan003-r3/docs/plans/PLAN-003-14NOV2026-ad-engagement-toolchain.md:780) requires real startup, provider/SDK absence, entrypoint instrumentation, nonempty exact command coverage, successful functional receipts and a rendered report. Missing observations are inconclusive; separate SDK-import negative controls must fail before the restored chain passes. |

No new BLOCKER/HIGH findings introduced by the fix.
