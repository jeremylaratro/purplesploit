VERDICT: SHIP

No BLOCKER/HIGH findings in this diff.

Probe argv is not recorded; the resolver note contains only the name/method, and receipts retain only `{name, ok}`. Verified retry/fallback order, caching, override behavior, Kerberos-only handling, exception recovery, composed credentials, and scorer compatibility.

Validation: 30 tests and 15 in-memory dcsync/composition/scorer checks passed.