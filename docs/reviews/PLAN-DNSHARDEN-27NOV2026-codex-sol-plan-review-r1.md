VERDICT: FIX-FIRST

Validation code in this worktree matches `3e5931b`. Findings below concern the [plan](/srv/share/dev/purplesploit/.claude/worktrees/dnsharden-s1/docs/plans/PLAN-DNSHARDEN-27NOV2026-dns-fqdn-host-processing-hardening.md), checked against code and isolated resolver experiments; no live GOAD run was performed.

**1. G2 — Kerberos call-site coverage**

- **HIGH — The omissions are real, but S2’s explicit wiring list is incomplete.** Both cited calls lack discovery flags. Two more executable NXC calls do too: [rbcd.py:253](/srv/share/dev/purplesploit/.claude/worktrees/dnsharden-s1/python/purplesploit/validation/executors/rbcd.py:253) and [adcs_esc1.py:272](/srv/share/dev/purplesploit/.claude/worktrees/dnsharden-s1/python/purplesploit/validation/executors/adcs_esc1.py:272). `forge_common.py:194–195` already supplies both flags and serves Golden/Silver/Diamond/Sapphire. DCSync’s four conditional `-k` branches and unconstrained delegation’s secretsdump call already supply Impacket’s `-dc-ip`; they should not receive NXC flags.

  Searching literal `-k` also misses **implicit Kerberos through `--aesKey`**: NXC authentication helpers in `roast`, `add_member`, `targeted_kerberoast`, `generic_all`, `gpo_abuse`, and `certifried` emit it without discovery flags. S2 needs an explicit executor/auth-mode inventory. Otherwise supported credential modes retain the portability defect. [NetExec’s authentication-mode selection](https://raw.githubusercontent.com/Pennyw0rth/NetExec/89d25017ad40afa70551b6e8d006c2956ef4b282/nxc/connection.py)

**2. G3 — NetBIOS consolidation**

- **HIGH — These are not behaviorally identical copies, and the proposed equivalence test has the wrong contract.** [config.netbios](/srv/share/dev/purplesploit/.claude/worktrees/dnsharden-s1/python/purplesploit/validation/config.py:130) ignores `netbios_domain`; `forge_common.netbios` honors it without trimming; [DCSync’s helper](/srv/share/dev/purplesploit/.claude/worktrees/dnsharden-s1/python/purplesploit/validation/executors/dcsync.py:79) trims and preserves a bare `krbtgt` fallback.

  For `domain="north.example"` and override `" CUSTOM "`, the outputs are respectively `NORTH`, `" CUSTOM "`, and `CUSTOM/krbtgt`. Consolidation is feasible, but requires an explicit normalization/compatibility decision. Phase 7 must assert `_krbtgt_target(cfg) == gc_qualify(cfg, "krbtgt")`, **not equality with `netresolve.netbios(cfg)`**. Following the stated test literally would require an invalid DCSync account argument.

**3. Sprint split and additive behavior**

- **HIGH — S2 changes resolver precedence and can break the carrier path.** Unconditionally adding `--dns-server` bypasses NetExec’s system resolver, including `/etc/hosts`. I reproduced this using the installed resolver function: a system-resolvable, DNS-absent hostname succeeds without the flag and fails with it; there is no system fallback. Thus plan lines 91 and 106–108 cannot establish compatibility by calling the flags “additive.” Define how existing system/hosts answers survive explicit DNS wiring and test that case. [NetExec resolver implementation](https://raw.githubusercontent.com/Pennyw0rth/NetExec/89d25017ad40afa70551b6e8d006c2956ef4b282/nxc/connection.py)

  The dependency order S1 → S2 → S3 is reasonable. Reverts require the reverse dependency order or compatibility measures; S1 cannot independently disappear while downstream imports remain.

**4. Test plan, RED proofs, and Phase 8**

- **HIGH — The gates prove implementation fragments, not the promised behavior.** Existing executor runners return scripted success largely by executable/subcommand; they do not exercise resolution. Keeping those tests green cannot prove carrier compatibility. Flag-presence assertions also permit wrong values and contradictory duplicate flags.

  Require tests covering actual resolver precedence and child-tool consumption, default versus explicit endpoint values, carrier-only names, host-map-only names, and preflight bypass cases. RED proofs must exercise those properties—for example, remove system fallback, pass the wrong resolver, ignore a resolved address, bypass the executor’s preflight, or discard its diagnostic. The three listed mutants leave these failures untested.

- **HIGH — Phase 8 is measurable only after defining its controls and success predicate.** Removing **realm aliases alone** does not prove operation without target-host carrier entries. Nor do absent KDC flags guarantee failure: usable service tickets can avoid KDC contact. The blanket baseline therefore needs measurement.

  Fix the executor/auth-mode denominator, tool versions, DNS conditions, exact removed aliases, and fresh per-run ticket state. Compare baseline/hardened code with carrier entries present/absent, including a fully carrier-free condition. Count verified terminal success or scored `proved`, not `complete`: [constrained delegation](/srv/share/dev/purplesploit/.claude/worktrees/dnsharden-s1/python/purplesploit/validation/executors/constrained_deleg.py:189) and [GenericAll](/srv/share/dev/purplesploit/.claude/worktrees/dnsharden-s1/python/purplesploit/validation/executors/generic_all.py:691) can report `complete=True` despite failed SMB authentication.

**5. Design attack**

- **HIGH — Resolution results have no defined path into tool connections.** `resolve_host` can succeed through `host_map` or system fallback while the subprocess still receives the original hostname and resolves it independently. The plan wires flags, not `HostResolution.ip`. In the checked NetExec version, Kerberos initialization even replaces the resolved transport address with the supplied hostname before SMB connection setup. Flags alone therefore do not establish carrier-free FQDN operation. [NetExec connection handling](https://raw.githubusercontent.com/Pennyw0rth/NetExec/89d25017ad40afa70551b6e8d006c2956ef4b282/nxc/connection.py), [SMB connection setup](https://raw.githubusercontent.com/Pennyw0rth/NetExec/89d25017ad40afa70551b6e8d006c2956ef4b282/nxc/protocols/smb.py)

  Define per-tool transport-address versus authentication-name handling: retain the intended SPN hostname while passing supported address overrides. Specify case/trailing-dot normalization for map lookup and name comparison. Otherwise preflight can pass while execution still fails.

- **HIGH — Executor-level opt-in does not prevent false inconclusive results.** Once adopted, unconditional KDC reachability rejects valid service-ticket paths, including Silver with an explicit SID and usable service ticket. A FQDN-only resolver can also reject already-usable IP targets. Furthermore, executor “targets” can be AD accounts rather than network endpoints—GenericAll and ShadowCreds are examples. Preflight must derive requirements from the selected pivot, authentication mode, actual connection endpoints, and ticket state.

- **HIGH — SPN, LDAP/LDAPS, and DC/GC discovery remain unspecified.** `use_gc` has no consumer or routing semantics. DNS success and port-88 reachability do not establish a usable SPN or correct directory endpoint. Preserve the existing [ADCS LDAP-scheme override](/srv/share/dev/purplesploit/.claude/worktrees/dnsharden-s1/python/purplesploit/validation/executors/adcs_esc1.py:153), define endpoint selection per tool, and classify discovery failures that occur after preflight. Otherwise these in-scope failures still become opaque technique errors.

- **HIGH — Actionable diagnostics may disappear from the delivered receipt.** `_receipt_from` forwards only known artifact fields, and [proof.normalize_steps](/srv/share/dev/purplesploit/.claude/worktrees/dnsharden-s1/python/purplesploit/validation/proof.py:107) retains only `{name, ok}`. A diagnostic attached as an arbitrary artifact field or step note is lost. Specify its persisted representation and test the final receipt for failed name, attempted resolver, reason, and corrective action; checking `resolution_failed:*` alone is insufficient.

- **HIGH — Calling the module a leaf does not eliminate the import-cycle risk.** Making `config.netbios` delegate introduces `config → netresolve`; the stated runtime import introduces `netresolve → config`. Importing `ValidationConfig` before its definition then breaks initialization. Require type-only config imports, a dependency-free interface, or deferred imports, with cold-import checks for config, netresolve, and the executor registry.