# PurpleSploit interactive console — manual walkthrough (28 OCT 2026)

**Build:** PurpleSploit 7.0.0 (editable install, `build/venv-plan002`), prompt_toolkit
3.0.53. Driven through a real TTY under `tmux` (220×55). Host tools present: `nmap`,
`ssh`, `feroxbuster`, `sqlmap`; **absent:** `nxc`/`netexec`/`crackmapexec`.
**Scope:** localhost (`127.0.0.1`) only + the `scanme.nmap.org` hostname as an unscanned
target label. This is a UX/robustness shakedown, not a security audit.

## Method

Exercised the live REPL end to end: `help`, target add/list/switch, credential add,
module load/switch/`back`, `options`, `set`/`unset`, interactive `run` picker, an
inline scan and a background scan, XML `parse` import, `services`/`hosts`/`findings`/
`graph`/`stats`/`history`/`info`, tool-missing execution, and error/edge cases
(unknown command, bad module, `set` with no args). Clean `exit`.

## What works well

- **Banner + stats** load cleanly; 46 modules / 11 categories.
- **`help`** renders a complete, well-organized rich panel layout.
- **Quick workflow** (`target <ip>`, `cred <user:pass>`) is smooth; credential password
  is masked as `set` in `creds list`.
- **`options` command-preview is live** — `set PORTS 22,80,443` immediately updates the
  previewed `Default Command:` line. Options auto-populate the current target.
- **Interactive `run` picker** (arrows/Enter/Esc) works via prompt_toolkit.
- **Inline scan auto-parses** — `BACKGROUND=false` returns parsed open ports + service
  versions (e.g. `OpenSSH 8.9p1`) directly, no separate import step.
- **`parse <xml>` import** populates targets/services end to end; re-discovered
  `127.0.0.1` is **deduped** against the existing target (stayed at 2, not 3).
- **Tool-missing is graceful** — an `nxc` run returns a clean failed-execution record,
  no traceback, and `argv_display` shows the password as **`[redacted]`**.
- **Error/edge handling is clean** — unknown command, bad module path, and `set` with
  no args all give short, helpful messages; no crashes.
- **`exit`** runs cleanup and the console **reaps its children** (no lingering
  purplesploit-parented processes after exit).
- The grouped **"Detected Services by Host"** table prints the host once per group then
  blanks it on following rows — verified this is intentional grouping, *not* a missing
  value.

## Findings (bugs / quirks), most to least material

### 1. Background scan is an unmanaged detached subprocess → zombie + invisible to `jobs`
Running `run` with `BACKGROUND=true` (the default) reports `Command running in
background (PID …)` but:
- `jobs` shows **"No jobs"** and the execution record has `job_id = None`. The
  background scan is **not registered with the job manager**; there is no in-REPL way to
  track, poll, or cancel it.
- The spawned child is **not reaped** — after completion the nmap process became
  `[nmap] <defunct>` (`STAT Zs`). Over a session with many background scans these
  **zombies accumulate** until the console exits.

**Impact:** medium. The headline "background scans" capability is effectively
fire-and-forget: no job tracking, and a process-table leak for the session's lifetime.
**Suggested fix:** route background execution through the existing job manager (assign a
real `job_id`, make it visible/cancellable in `jobs`) and `waitpid`/reap on completion.

### 2. Scan output written to the current working directory (repo root) by default
`-oA` uses a relative basename (`nmap_127.0.0.1`, `nmap_targets`), so `.nmap/.xml/.gnmap`
land in **cwd = the repo root**. `RUN_DIR` ("Directory for relative Nmap output paths")
defaults unset. **Mitigated:** `nmap_*` is already in `.gitignore`, so there is no
accidental-commit risk — but the repo working tree gets littered with scan artifacts.
**Suggested fix:** default `RUN_DIR`/output under `~/.purplesploit/` (or an engagement
dir), not cwd.

### 3. `operation_name` is `None` in execution records even when an operation ran
Both the nmap op (Fast Scan) and the nxc_ssh op 1 (Test Authentication) produced
execution records with `operation_name = None`. The selected operation's name is not
threaded into the `ExecutionResult`.
**Impact:** low — observability/reporting gap (findings and job records can't name the
operation that produced them).

### 4. Current target / credential is not marked in `targets`/`creds` list views
`targets` and `targets list` render no indicator of which target is current, even
though the framework tracks it (`targets set 0` → "Current target set to: 127.0.0.1").
**Impact:** low (UX). **Suggested fix:** mark the active row (`*`/highlight).

### 5. Primary target + `TARGETS` overlap is not deduped at scan time
With current target `127.0.0.1` **and** `TARGETS=127.0.0.1`, the inline scan reported
**"Hosts Discovered: 2"** and `nmap_targets.xml` contained **two `<host>` elements, both
`127.0.0.1`** — the one unique host counted twice.
**Impact:** low–medium — inflates host counts / produces duplicate host records when the
primary target also appears in `TARGETS`. (Note: the `parse`-import path *does* dedupe;
this is the live-scan target-assembly path.) **Suggested fix:** dedupe the assembled
target set (primary ∪ `TARGETS`) before invoking nmap.

### 6. `hosts` maps a hostname target to itself (`name → name`)
`hosts` generated `scanme.nmap.org  scanme.nmap.org` — a hostname target with no
resolved IP yields a useless `/etc/hosts` entry (should be `IP → hostname`, or be
skipped until resolved). `127.0.0.1 → 127.0.0.1` is harmless.
**Impact:** low.

### 7. Attack graph is not populated from scan/`parse` imports
After importing 1 host + 8 services, `graph` still showed `Hosts 0 / Services 0` — the
attack graph is a separate store requiring `auto <target>` / `graph add`.
**Impact:** low, but a discoverability gap: a user who imported a scan may expect the
graph to reflect it. Worth either auto-linking or a one-line hint in `services`/`parse`
output ("run `auto` to add these to the graph").

## Minor / cosmetic

- **`run` group ordering:** nmap operations print **ADVANCED → SPECIALIZED → STANDARD**
  (alphabetical by group), so the common STANDARD scans (1–3) appear last. Consider a
  deliberate order (STANDARD first).
- **`set PORTS` is silently ignored by a named operation** — picking "Fast Scan" used
  its own `--top-ports 100`, discarding a user-set `PORTS=22,80,443`. Expected (canned
  profiles), but a surprise; a note in `options` would help.
- **`search <term>` auto-loads a single match**, changing the current module as a
  side-effect of searching. Convenient but surprising.
- **Operation-list render differs across modules** (nmap uses grouped sections; nxc_ssh
  uses a plain table) — minor inconsistency.
- **`set` with no module loaded** returns `Usage: set …` rather than "load a module
  first".

## Not reproduced / verified-OK

- Service-table "empty host column" was **not** a bug (intentional per-host grouping).
- Target dedup on `parse` import works.
- No credential leakage in displayed commands (`[redacted]`).
- No crash on any malformed input tried.

## Follow-up candidates (if a fix sprint is opened)

Finding **#1** (background job tracking + child reaping) is the only medium-severity
item and the clearest candidate for a fix. **#2** (output dir) and **#5** (target
dedup) are small, self-contained changes. The rest are low/cosmetic UX polish.

**Disposition (28 OCT 2026, owner):**
- **#1 → PS-CONSOLE-01** — being fixed now (background scans registered with a Framework
  registry, surfaced in `jobs`, and reaped on list/run/exit so no zombies; `job_id`
  populated).
- **#2 → PS-CONSOLE-02** (planned, `docs/plans/PS-CONSOLE-02-28OCT2026-startup-output-dir-warning.md`)
  — default output dir intentionally left as-is; a small startup warning about cwd output
  is logged as a future sprint (owner go required).
- #3–#7 and the minor/cosmetic items remain open UX polish, unscheduled.
