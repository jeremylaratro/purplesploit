# PS-CONSOLE-02 — startup warning for scan output written to the working directory

**Status:** planned (future sprint, not started). Logged 28 OCT 2026 from the manual
console walkthrough (`docs/reviews/CONSOLE_WALKTHROUGH-28OCT2026.md`, finding #2).
**Owner go required before implementation.**

## Context

Nmap (and other tool modules) use a relative `-oA` basename, so with `RUN_DIR` unset the
scan artifacts (`.nmap`/`.xml`/`.gnmap`) are written to the **current working directory**.
When the console is launched from inside the repo (or any non-engagement dir), those
files litter the working tree. They are already `.gitignore`d (`nmap_*`), so there is **no
accidental-commit risk** — this is clutter / "where did my output go?" friction, not a
correctness or security bug.

**Decision (28 OCT 2026, owner):** do **not** change the default output directory now
(leaving the current behavior intact avoids churn and preserves the familiar "output in
cwd" expectation). Instead, add a small, non-intrusive **startup warning** so the operator
is never surprised about where scan output lands.

## Scope (small, self-contained)

A short startup cycle in the console boot path (`ui/console.py` `start()`, after the
banner/stats, before the REPL loop) that:

1. Determines the effective default scan-output location (the directory relative `-oA`
   output would resolve against — i.e. the process cwd, since `RUN_DIR` defaults unset).
2. Prints **one** dim informational line when that location is the cwd (optionally only
   when the cwd looks like a VCS checkout — `.git` present — or is otherwise not a
   dedicated engagement/output dir), e.g.:
   `◆ Scan output will be written to the current directory (<cwd>). Set RUN_DIR or run from an engagement dir to change this.`
3. Is quiet and bounded: at most one line at startup, no per-command noise, no prompt,
   suppressible via an env var (e.g. `PURPLESPLOIT_NO_STARTUP_HINTS=true`) for scripted/
   headless use.

Explicitly **out of scope:** changing the default output directory, moving output under
`~/.purplesploit/`, or adding an engagement-directory concept — those are larger changes
deferred separately if ever wanted.

## Acceptance

- Launching the console from a directory with a `.git` (or the configured trigger)
  prints exactly one startup line naming the cwd and the `RUN_DIR` escape hatch.
- Launching with `PURPLESPLOIT_NO_STARTUP_HINTS=true` (or equivalent) prints no such line.
- No change to any scan's actual output path or to existing tests; the REPL and banner
  are otherwise unchanged.

## Relationship to PS-CONSOLE-01

Independent. PS-CONSOLE-01 (background-scan job tracking + child reaping) is the MEDIUM
fix being implemented now; PS-CONSOLE-02 is this low-priority startup hint and can land
any time after owner go.
