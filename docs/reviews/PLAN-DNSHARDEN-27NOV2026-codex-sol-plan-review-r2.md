VERDICT: FIX-FIRST

- **#1 — Sound:** S2 requires a recorded call-site/auth-mode inventory covering implicit Kerberos through `--aesKey`.
- **#2 — Sound:** Trim+upper normalization honors the override; `_krbtgt_target(cfg) == gc_qualify(cfg,"krbtgt")` is the correct contract.
- **#3 — HIGH, unresolved:** [Plan:107](/srv/share/dev/purplesploit/.claude/worktrees/dnsharden-s1/docs/plans/PLAN-DNSHARDEN-27NOV2026-dns-fqdn-host-processing-hardening.md:107) permits leaving `forge_common` unchanged, retaining unconditional `--dns-server` and ignoring the new overrides; require helper routing there too. Installed NXC confirms `--kdcHost` sets KDC location without disabling target resolution.
- **#4 — Sound:** Phase 8 counts `terminal_ok`/scored `proved`, supplies comparison controls, and records PX-1.
- **#5a — Sound:** Keeping the FQDN target and dropping `host_map` removes the proposed transport/auth-name substitution problem.
- **#5b — Sound:** Post-failure classification only appends diagnostics; those labels do not themselves change success predicates or cause a scorer `inconclusive`.
- **#5c — Sound:** `use_gc` is dropped and routing deferrals are explicit.
- **#5d — HIGH, partially resolved:** Verified that `errors` survives `_receipt_from` → `build_receipt`, but [the specified diagnostic](/srv/share/dev/purplesploit/.claude/worktrees/dnsharden-s1/docs/plans/PLAN-DNSHARDEN-27NOV2026-dns-fqdn-host-processing-hardening.md:93) retains only a category; persist the failed name, attempted resolver, reason, and corrective action, and assert that context in the final receipt.
- **#6 — Sound:** Package-independent, duck-typed `netresolve`, one-way imports, and cold-import coverage address the cycle.