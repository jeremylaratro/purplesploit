VERDICT: FIX-FIRST

- **HIGH — [netresolve.py:76](/srv/share/dev/purplesploit/.claude/worktrees/dnsharden-s1/python/purplesploit/validation/netresolve.py:76):** The broad `kdc … cannot` regex misclassifies Impacket’s `KDC_ERR_BADOPTION(KDC cannot accommodate requested option)` as `resolution_failed:realm_kdc`. Reproduced directly. A constrained-delegation request rejected by a reachable KDC receives misleading “KDC not found/unreachable” guidance. Restrict matching to discovery/resolution failures and add a regression asserting this error returns `None`.

The 19 new tests pass but miss this case. DCSync equivalence and three cold-import orders passed; no existing `config.netbios` callers were found.