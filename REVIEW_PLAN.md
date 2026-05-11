# REVIEW_PLAN.md — PurpleSploit Phased Code Review

## 1. Overview

This document defines a phased, multi-agent code review of the **PurpleSploit** offensive security framework located at `/home/user/purplesploit/`. Three independent Sonnet executor agents will each own one phase, working in parallel from the briefs in sections 4-6, and produce findings using the rubric in section 2 and the template in section 3. A consolidation step (section 8) merges their outputs into a single `FINDINGS.md`.

The review covers three orthogonal dimensions:

- **SCOPE** — Does the project deliver what it claims? Charter vs. reality, feature completeness, version/doc consistency, dependency hygiene, legal posture.
- **IMPLEMENTATION** — Code quality, security, correctness, architecture. Given this is a pentesting framework, security posture and dangerous-tool handling are weighted heavily.
- **DISPLAY** — CLI UX, web UI, API response shape, generated reports, error messages, accessibility, consistency.

Each phase brief is self-contained and gives its executor: (a) the precise files to read, (b) the questions to answer, (c) anti-patterns to look for, and (d) the output format. Executors must NOT modify code — they only read, analyze, and report.

Pre-recon notes (confirmed before writing this plan):
- `python/purplesploit/api/server.py` has zero authentication on every route (no `Depends`, no token check) and runs `subprocess.run(..., shell=True)` on caller-supplied strings at lines 491 and 520.
- `python/purplesploit/web/dashboard.py` uses `allow_origins=["*"]` together with `allow_credentials=True` (a CORS anti-pattern).
- License is **CC BY-NC-SA 4.0** in `LICENSE` but `python/setup.py` line 26 declares `"License :: OSI Approved :: MIT License"` — a legal inconsistency.
- Version mismatch: `README.md` header reads `v6.8.1`, `python/setup.py` line 14 and `python/purplesploit/__init__.py` line 19 both say `6.9.1`, but `python/purplesploit/main.py` line 48 hard-codes `--version` output as `6.8.1`.
- `shell=True` appears in 10 distinct call sites across api/server.py, ui/commands.py, ui/command_mixins/utility_commands.py, core/module.py, modules/web/wfuzz.py, modules/recon/auto_enum.py.

These are starter findings — executors are expected to confirm, locate exactly, and expand on them.

---

## 2. Severity Rubric

All three executors apply the rubric uniformly. When in doubt between two tiers, pick the higher tier and justify.

### CRITICAL
Direct exploitability or catastrophic data/safety loss. Examples for this codebase:
- Unauthenticated remote code execution (e.g., `/api/execute` running `shell=True` on caller input with no auth).
- Hard-coded secrets, API keys, or default credentials shipped in the repo.
- SQL injection via string-formatted queries on user input.
- Path traversal that reaches sensitive files (e.g., `../../etc/passwd` via unsanitized filename).
- Authentication or authorization bypass on any privileged endpoint.
- Insecure deserialization (`pickle.loads`, `yaml.load` without SafeLoader) on caller input.
- XXE on parsed XML originating from network input where `defusedxml` is bypassed.
- License/legal blockers that prevent lawful distribution (e.g., GPL code copied into a CC-NC project).

### HIGH
Significant security weakness, data-integrity bug, or correctness defect that requires a non-trivial precondition to exploit. Examples:
- Permissive CORS (`allow_origins=["*"]` with `allow_credentials=True`).
- Missing rate limiting on a sensitive endpoint where slowapi is wired up but the decorator is absent.
- Credential at-rest storage in plaintext in SQLite without disclosure to the user.
- Broad `except Exception: pass` that masks security-relevant failures in auth or crypto code.
- Race conditions on shared SQLite writes that can corrupt findings/credentials.
- Cross-site scripting in a Jinja2 template via `|safe` on user data.
- Stale or contradictory feature documentation (claim of a capability that is not implemented).
- Test coverage gap for a security-critical module (e.g., `credential_spray` has no negative tests).

### MEDIUM
Maintainability problems, correctness issues with limited blast radius, UX defects that hinder normal use. Examples:
- Tight coupling between layers (e.g., `Framework` reaching into `db_manager` internals).
- Silent exception swallowing in non-security code paths.
- Inconsistent error response shapes between sibling API endpoints.
- Hard-coded magic numbers / paths that should be configurable.
- Inconsistent CLI verb ordering (`module select` vs. `select module`) that confuses users.
- Dead or stub modules under `modules/*` that look real but never produce results.
- Dependency versions in `setup.py` that conflict with what is actually imported.
- Version string mismatch across `README.md`, `setup.py`, `__init__.py`, and `--version` CLI output.

### LOW
Cosmetic, stylistic, or documentation-only issues that do not affect correctness. Examples:
- Missing docstrings on public functions.
- Inconsistent capitalization in user-facing strings.
- Unused imports.
- Minor typos in CLI help text or report templates.
- Inconsistent quote style across modules.
- Banner ASCII art that drifts from one variant to the next.

Executors must justify each rating in two sentences max — citing the rubric category and the concrete precondition for exploit/impact.

---

## 3. Findings Format

Each finding must use exactly this template (Markdown):

```
### F-<PHASE>-<NNN>: <short title>

- **Severity:** CRITICAL | HIGH | MEDIUM | LOW
- **Category:** Scope | Security | Architecture | Database | Web/API | Module Subsystem | Integrations | Tests | CLI UX | Web UX | Reporting | Docs | Legal | Dependencies
- **Location:** `<absolute path>:<line>` (additional refs as bullet list if multiple sites)
- **Description:** What is wrong. 1-3 sentences.
- **Impact:** Concrete consequence. What an attacker / user / maintainer experiences. Reference rubric criterion.
- **Recommendation:** Specific, actionable fix. Reference the file/function to change. Do NOT include code patches — the review is read-only.
- **Confidence:** High | Medium | Low (how sure the executor is the issue is real)
```

`<PHASE>` is `S` (Scope), `I` (Implementation), or `D` (Display). `<NNN>` is a 3-digit sequence number unique within the phase (e.g., `F-I-014`). Executors must cite `file:line` for every finding — never just a filename. If the issue spans many lines, cite the function definition line plus the relevant inner line(s).

---

## 4. Phase 1 — Scope Review

**Executor:** Sonnet agent #1. **Mode:** read-only.

### Objective
Determine whether PurpleSploit delivers on its stated charter. Identify drift between documentation, packaging, and implementation. Identify dead code, stub modules, dependency hygiene problems, version inconsistencies, and legal posture defects.

### Required reading (in this order)
1. `/home/user/purplesploit/README.md` — claimed features, quick-start commands, workflow examples.
2. `/home/user/purplesploit/QUICKSTART.md` — installation and getting-started promises.
3. `/home/user/purplesploit/CHANGELOG.md` — recent versions and claimed fixes.
4. `/home/user/purplesploit/LICENSE` — actual license terms.
5. `/home/user/purplesploit/python/setup.py` — declared name, version, license classifier, install_requires, entry_points.
6. `/home/user/purplesploit/python/purplesploit/__init__.py` — `__version__` declaration.
7. `/home/user/purplesploit/python/purplesploit/main.py` — `--version` argparse string at line 48.
8. `/home/user/purplesploit/docs/ARCHITECTURE.md` — claimed architecture.
9. `/home/user/purplesploit/docs/API.md` — documented API endpoints, then cross-check against `python/purplesploit/api/server.py` route table.
10. `/home/user/purplesploit/docs/DISCLAIMER.md` — claimed legal stance.
11. `/home/user/purplesploit/docs/DOCUMENTATION_AUDIT-23JAN2026.md` — known doc gaps already identified by maintainers; cross-check whether they were actually fixed.
12. `/home/user/purplesploit/python/purplesploit/modules/` — enumerate every `*.py` under `ad/`, `ai/`, `c2/`, `deploy/`, `impacket/`, `network/`, `osint/`, `recon/`, `smb/`, `utility/`, `web/`. For each, decide: does it have a real implementation, or is it a stub/skeleton?
13. `/home/user/purplesploit/python/tests/` — enumerate unit/integration/benchmark test files. Cross-reference against subpackages: which subpackages have zero tests?
14. `/home/user/purplesploit/.github/workflows/ci.yml` — does CI actually run the test suite that the CHANGELOG claims (e.g., "3,835 unit tests passing")?

### Questions to answer
1. **Version consistency** — Does every version string agree? README, setup.py, __init__.py, main.py `--version`, CHANGELOG. The pre-recon confirmed mismatch — file at least one MEDIUM finding with exact `file:line` for each occurrence.
2. **License coherence** — `LICENSE` says CC BY-NC-SA 4.0, `setup.py:26` declares MIT. Which is authoritative? Are any vendored third-party files under incompatible licenses? Pip metadata visible on PyPI would mislead users. Severity: at least HIGH.
3. **Feature claims vs. reality** — For every feature bullet in `README.md`, confirm an implementation exists. Examples to check: "AI-powered attack path analysis" (does `ai/attack_paths.py` actually compute something or is it a stub?), "Distributed task execution" (`distributed/`), "Plugin repository" (`plugins/repository.py`), "Jira/Slack/Teams/SIEM integration" (`integrations/`), "PDF reporting" (`reporting/pdf.py`).
4. **Stub / dead code** — Grep for functions that contain only `pass`, `return None`, `raise NotImplementedError`, or one-line stubs in production paths. Report each as MEDIUM (LOW if clearly experimental).
5. **Dependency hygiene** — Does every package in `setup.py:install_requires` get imported somewhere? Does every package that is actually imported appear in `install_requires` (or stdlib)? Are version pins reasonable? Specifically check `weasyprint`, `textual`, `matplotlib`, `seaborn`, `pandas` — heavy deps that may be unused at runtime.
6. **Docs vs. API drift** — Enumerate routes in `python/purplesploit/api/server.py` (grep `@app\.` lines). Cross-reference with `docs/API.md`. Report routes that exist but are undocumented, and routes documented but missing.
7. **Test coverage scope** — For each top-level subpackage (`core`, `modules`, `ui`, `web`, `api`, `ai`, `distributed`, `reporting`, `plugins`, `integrations`, `analysis`), confirm at least one test file exists. Missing coverage for `credential_spray.py`, `auto_enum.py`, or `attack_graph.py` is at least HIGH given they manipulate credentials and live targets.
8. **CHANGELOG honesty** — Does CHANGELOG 6.9.0 entry's "3,835 unit tests passing" match a count derived from `find tests/unit -name "test_*.py" | xargs grep -c "def test_"`? Off-by-one is LOW, large drift is MEDIUM.
9. **Legal posture** — Does `DISCLAIMER.md` cover authorized-use, jurisdictional caveats, and explicit prohibition of unauthorized targeting? Is there a `SECURITY.md`? Is there a clear vulnerability-disclosure process?
10. **Repository hygiene** — Loose files at the repo root (`my_sessions.json`, `delete_small_files.sh`, `enum_output/`) suggest leaked dev state. Confirm whether any contain real-looking data. CRITICAL if they contain credentials or live IPs from a non-lab range.

### Anti-patterns to flag
- "Coming soon" or "TODO" in README claiming a shipped feature.
- Subpackage `__init__.py` exporting names that don't exist.
- Module file that registers itself with the framework but does nothing in `run()`.
- Docstrings that disagree with function signatures.
- CI workflow that runs `pytest tests/unit` but skips integration with no comment.

### Deliverable
A list of findings in the section-3 template. Aim for 15-40 findings. The phase ends when the executor has walked all 14 required-reading items.

---

## 5. Phase 2 — Implementation Review

**Executor:** Sonnet agent #2. **Mode:** read-only.

### Objective
Audit code quality, security, and correctness. This is the heaviest phase by volume and severity. Sub-areas (a)-(g) are listed below with specific files and questions; the executor should produce findings across all sub-areas.

### Sub-area (a): Security

This is a pentesting framework — security flaws in the framework itself are critical. The pre-recon already surfaced unauthenticated RCE; expect more.

**Files to inspect:**
- `/home/user/purplesploit/python/purplesploit/api/server.py` (full file, 1247 lines) — every `@app.*` route.
- `/home/user/purplesploit/python/purplesploit/web/dashboard.py` — Jinja2 template rendering and CORS.
- `/home/user/purplesploit/python/purplesploit/core/module.py` lines 540-590 — `shell=True` subprocess.
- `/home/user/purplesploit/python/purplesploit/ui/commands.py` lines 1720-1735 and 2160-2175.
- `/home/user/purplesploit/python/purplesploit/ui/command_mixins/utility_commands.py` lines 265-280 and 585-600.
- `/home/user/purplesploit/python/purplesploit/modules/web/wfuzz.py` line 482.
- `/home/user/purplesploit/python/purplesploit/modules/recon/auto_enum.py` line 189.
- `/home/user/purplesploit/python/purplesploit/core/database.py` (raw SQL paths).
- `/home/user/purplesploit/python/purplesploit/models/database.py` (SQLAlchemy models — confirm parameterization, check for `text()` with f-strings).
- `/home/user/purplesploit/python/purplesploit/core/credential_spray.py` — credential handling.

**Questions:**
1. **Authentication** — Confirm: `api/server.py` has zero auth dependencies. Search for `Depends`, `HTTPBearer`, `OAuth2PasswordBearer`, `api_key`, `X-API-Key` — pre-recon found none. CRITICAL given `/api/execute` runs shell commands.
2. **Command injection** — For each `shell=True` site, trace whether the command string interpolates user-controllable input. `/api/execute` (server.py:491) — entire command is from the request body. `/api/scan/nmap` (server.py:520) — interpolates `scan_request.target` and `scan_request.ports` directly into a shell string at line 515. CRITICAL.
3. **Path traversal** — `/api/nmap/upload` (server.py:424) and any `FileResponse`. Does the code call `Path(...).resolve()` and verify it stays under a base directory?
4. **SQL injection** — Walk `core/database.py` and find every `cursor.execute(...)`. Confirm every parameterizes via `?` placeholders, not f-string. Walk `models/database.py` for raw `text()` usage.
5. **CORS** — `api/server.py:37` reads `CORS_ORIGINS` env, defaults to localhost. `web/dashboard.py:32` uses `allow_origins=["*"]` with `allow_credentials=True`. Latter is HIGH.
6. **CSRF** — FastAPI does not add CSRF by default. The web dashboard has mutation routes — are they protected? If the same origin is used by a logged-in browser and there is no token, that compounds the CORS issue.
7. **Rate limiting** — slowapi is wired up at server.py:49 but `enabled=not DEBUG_MODE`. Enumerate which routes have `@limiter.limit(...)` and which do not. `/api/credentials` POST has no limit — HIGH.
8. **Credential storage at rest** — Open `models/database.py` and check `Credential` model: is the password column encrypted or hashed? If plaintext, HIGH — credential-spray reuses these against live targets, so users will store privileged AD creds.
9. **XXE** — Pre-recon confirmed `defusedxml` is imported. Search for `xml.etree`, `lxml.etree.parse`, `xml.dom.minidom` elsewhere — any non-defused parser on network input is CRITICAL.
10. **Deserialization** — Pre-recon found no `pickle.loads` or unsafe `yaml.load`. Re-confirm and check `json.loads` on untrusted strings where the result is used as kwargs.
11. **Secrets handling** — `integrations/jira_integration.py`, `slack.py`, `teams.py`, `siem.py`, `github_issues.py` — how are tokens obtained? Env vars? Config files committed to the repo? Logged in plaintext?
12. **Error leakage** — `sanitize_error` at server.py:40 hides details unless `DEBUG_MODE`. Confirm every `HTTPException(..., detail=...)` and every `raise` in API paths routes through it.
13. **DEBUG_MODE side effects** — server.py:49 disables rate limiting when debug is on. Document any other safety dropped by DEBUG. MEDIUM-HIGH.
14. **Insecure defaults** — Does any module ship with default credentials, default targets, or default endpoints pointing at real third-party services?

### Sub-area (b): Architecture

**Files:**
- `/home/user/purplesploit/python/purplesploit/core/framework.py` (559 lines) — central orchestrator.
- `/home/user/purplesploit/python/purplesploit/core/module.py` — base classes.
- `/home/user/purplesploit/python/purplesploit/core/session.py` and `session_manager.py`.
- `/home/user/purplesploit/python/purplesploit/core/workflow.py`, `findings.py`, `attack_graph.py`, `parameters.py`.

**Questions:**
1. Does `Framework` know too much (god-object smell)? Note lazy-loading hack at framework.py:58-62 — what does this say about coupling to `models/database.py`?
2. Dual database stack: `core/database.py` (raw sqlite3) + `models/database.py` (SQLAlchemy). Pre-recon confirmed both are loaded simultaneously (framework.py:60-96 syncs targets across them). Why two? Is one canonical? Risk of divergence — HIGH if findings drift between stores.
3. Exception handling: grep for `except Exception:\s*pass` and `except:\s*pass`. Each is at least MEDIUM in non-test code; in security paths it is HIGH.
4. Layering: does `core/` import from `ui/`, `web/`, `api/`? It must not.
5. Circular imports: any `from purplesploit.X import` inside a function body is a sign of one — flag and explain.

### Sub-area (c): Database

**Files:**
- `/home/user/purplesploit/python/purplesploit/core/database.py` (964 lines).
- `/home/user/purplesploit/python/purplesploit/models/database.py`.

**Questions:**
1. Schema integrity — are foreign keys declared and enabled (`PRAGMA foreign_keys=ON`)?
2. Migrations — `_migrate_database()` at database.py:59 is called. Is it idempotent? Versioned? Does it back up before destructive changes?
3. Concurrency — pre-recon confirmed WAL mode + RLock + `check_same_thread=False`. Walk every cursor use and confirm it goes through `_get_cursor()` context manager.
4. Transactions — long-running operations: are they wrapped? Are partial writes possible on crash?
5. Cache — `_cache` / `_cache_ttl` (database.py:54-56) — is invalidation correct on writes? Stale-read risk in credential/target reads is HIGH.

### Sub-area (d): Web / API

**Files:**
- `/home/user/purplesploit/python/purplesploit/api/server.py` — all 1247 lines.
- `/home/user/purplesploit/python/purplesploit/web/dashboard.py`.
- `/home/user/purplesploit/python/purplesploit/web/templates/dashboard.html`, `targets.html`, `credentials.html`.
- `/home/user/purplesploit/python/purplesploit/web/static/index.html`, `c2.html`, `exploits.html`, `target.html`, `targets.html`.

**Questions:**
1. Route inventory — list all routes (pre-recon showed 30+ routes). For each: auth? rate-limit? input validation via Pydantic? error sanitization?
2. WebSocket — server.py imports `WebSocket, WebSocketDisconnect`. Find every `@app.websocket(...)` and check auth and message validation.
3. Input validation — Pydantic models like `CommandRequest` (server.py:160) accept arbitrary `command: str`. No length cap, no allowlist.
4. CORS — see sub-area (a). Cross-reference with web/dashboard.py.
5. Static file serving — server.py:75-99 `find_static_dir` tries three paths. Could a misconfiguration serve from a writable temp dir?
6. Template injection — every `{{ ... }}` in templates: does it touch user data without `|e`? Any `|safe`?
7. The dashboard module mounts its own FastAPI app — does it conflict with the API server's app? Are they ever both running on the same port?

### Sub-area (e): Module Subsystem

**Files:**
- `/home/user/purplesploit/python/purplesploit/core/module.py` — `BaseModule`, `ExternalToolModule`.
- `/home/user/purplesploit/python/purplesploit/core/parameters.py`.
- `/home/user/purplesploit/python/purplesploit/core/credential_spray.py`.
- `/home/user/purplesploit/python/purplesploit/core/auto_enum.py`.
- `/home/user/purplesploit/python/purplesploit/modules/recon/auto_enum.py` (note: there are TWO auto_enum files — confirm this isn't a name collision bug).
- Sample modules across each category: pick 2-3 from `modules/ad/`, `modules/c2/`, `modules/web/`, `modules/recon/`, `modules/smb/`.

**Questions:**
1. Metasploit-style module loading via `importlib.util` (framework.py:9). Is the search path locked down or could a writable directory inject modules?
2. Parameter handling — when a module reads options from session/context, are types validated before passing to subprocess?
3. `credential_spray.py` — does it implement lockout-avoidance (delay, threshold)? Without it, the framework will lock out AD users en masse — at least HIGH UX/Safety.
4. `auto_enum.py` — when chaining external tools, are intermediate outputs sanitized before being substituted into the next command line?
5. Two `auto_enum.py` files at different paths — naming collision risk. Confirm both are intentional and serve different scopes.

### Sub-area (f): Integrations

**Files:** every file under `/home/user/purplesploit/python/purplesploit/integrations/`.

**Questions:**
1. Where do secrets (Jira API tokens, Slack webhooks, Teams webhooks, SIEM API keys, GitHub PATs) come from? Env vars are acceptable; committed config files are CRITICAL.
2. Are webhook URLs validated against SSRF (e.g., refused if pointing at metadata services, localhost, RFC1918)?
3. TLS verification — any `verify=False` on `requests`/`httpx` calls? At least HIGH.
4. Outbound rate limiting — does each integration handle 429s gracefully?

### Sub-area (g): Tests

**Files:**
- `/home/user/purplesploit/python/tests/conftest.py`.
- All files under `python/tests/unit/`, `python/tests/integration/`, `python/tests/benchmarks/`.

**Questions:**
1. Are tests deterministic? Any reliance on network, current time, or `~/.purplesploit`?
2. Do security-sensitive modules have negative tests (e.g., `/api/execute` rejects without auth — *should* but currently can't because no auth exists)?
3. Are fixtures reused across tests in a way that could mask test pollution (per CHANGELOG 6.9.1 fix notes)?
4. CI: does `.github/workflows/ci.yml` actually run the integration + benchmark suites, or only unit?
5. Skipped tests — grep for `@pytest.mark.skip` / `skipif` and report each with the justification (or lack thereof).

### Deliverable
40-80 findings expected across sub-areas (a)-(g). The Security sub-area alone should produce 10+ findings given pre-recon results.

---

## 6. Phase 3 — Display / UX Review

**Executor:** Sonnet agent #3. **Mode:** read-only.

### Objective
Audit every surface where PurpleSploit talks back to a human: interactive CLI, web pages, API JSON shape, generated reports, error messages, log output. Look for inconsistency, ambiguity, accessibility regressions, and security/UX collisions (e.g., a secret rendered into the page DOM).

### Files to inspect

**CLI:**
- `/home/user/purplesploit/python/purplesploit/ui/interactive.py`.
- `/home/user/purplesploit/python/purplesploit/ui/commands.py` (5696 lines — sample heavily, look at command registration, help strings, prompt rendering).
- `/home/user/purplesploit/python/purplesploit/ui/console.py`.
- `/home/user/purplesploit/python/purplesploit/ui/display.py`.
- `/home/user/purplesploit/python/purplesploit/ui/banner.py`.
- `/home/user/purplesploit/python/purplesploit/ui/command_mixins/base.py`, `context_commands.py`, `module_commands.py`, `utility_commands.py`.

**Web:**
- `/home/user/purplesploit/python/purplesploit/web/templates/dashboard.html`.
- `/home/user/purplesploit/python/purplesploit/web/templates/credentials.html`.
- `/home/user/purplesploit/python/purplesploit/web/templates/targets.html`.
- `/home/user/purplesploit/python/purplesploit/web/static/index.html`.
- `/home/user/purplesploit/python/purplesploit/web/static/c2.html`.
- `/home/user/purplesploit/python/purplesploit/web/static/exploits.html`.
- `/home/user/purplesploit/python/purplesploit/web/static/target.html`.
- `/home/user/purplesploit/python/purplesploit/web/static/targets.html`.
- `/home/user/purplesploit/python/purplesploit/web/static/css/` and `js/` — scan filenames, sample 1-2 each.

**API responses (presentation aspect — schemas, error shapes, naming):**
- `/home/user/purplesploit/python/purplesploit/api/server.py` Pydantic response models.

**Reporting:**
- `/home/user/purplesploit/python/purplesploit/reporting/markdown.py`.
- `/home/user/purplesploit/python/purplesploit/reporting/html.py`.
- `/home/user/purplesploit/python/purplesploit/reporting/pdf.py`.
- `/home/user/purplesploit/python/purplesploit/reporting/xlsx.py`.
- `/home/user/purplesploit/python/purplesploit/reporting/generator.py`.
- `/home/user/purplesploit/python/purplesploit/reporting/templates/` — any Jinja2 templates here.

### Questions to answer

1. **CLI consistency** — README example uses `targets select`, `creds select`, `module select`, `search`, `use`, `run op#`. Confirm every documented verb actually exists in `ui/commands.py` and that the order (`noun verb` vs. `verb noun`) is consistent across the surface. Inconsistency is MEDIUM.
2. **Help strings** — every command's `--help` / `?` text: present, accurate, free of TODOs. Missing help on a command is LOW; misleading help is MEDIUM.
3. **Prompt safety** — when prompting for a password or token, is input masked? Walk `prompt_toolkit` usage for `is_password=True` on credential entry. Plain echo of a password is HIGH (UX-security).
4. **Color/contrast** — `rich` tables: are status colors hard-coded such that they're unreadable on light terminals? LOW unless documented as a requirement.
5. **Banner drift** — `ui/banner.py` has 8 variants (per server.py:240). Do they all render at the same width? Do they all show the correct version (cross-link to scope finding)? LOW.
6. **Error messages — security leakage** — when a module fails, does the error display a full traceback to the user (including paths, credentials in argv)? HIGH if credentials surface; MEDIUM if just paths.
7. **Web — XSS surface** — every `{{ var }}` in Jinja2 templates: is `var` ever a target IP, hostname, scan output, or service banner? Auto-escape is on by default in `Jinja2Templates`, but `|safe` filters or `Markup(...)` calls bypass it. CRITICAL if so on user data; HIGH on data the framework writes (because that data originated from target).
8. **Web — credentials in DOM** — does `credentials.html` render the password column verbatim into the rendered HTML? Even with auto-escape, this means anyone with a screen can read; LOW for shoulder-surfing but MEDIUM combined with the missing-auth finding.
9. **Web — accessibility** — every `<img>` has `alt`? Every `<button>` has accessible text? Every form field has a `<label>`? Tab order sensible? LOW for individual misses, MEDIUM for systemic absence.
10. **Web — CSP / security headers** — are response headers set anywhere (`X-Frame-Options`, `Content-Security-Policy`)? Cross-link to Phase 2 finding.
11. **API response shape consistency** — for every route, is the success/error envelope consistent? Some routes return `{"message": "..."}`, some raise `HTTPException`, some return a model directly. MEDIUM.
12. **API naming** — `/api/credentials` (plural) vs. any singular route? `/api/c2/module/{path}` vs. `/api/c2/modules/{category}` — confirm pluralization rules and parameter style are consistent.
13. **Reporting — completeness** — does `markdown.py` cover every finding type that `findings.py` can produce? Do `html.py` and `pdf.py` agree (PDF is rendered from HTML in weasyprint?)? Missing field is MEDIUM; data corruption is HIGH.
14. **Reporting — sensitive data redaction** — does the report include cleartext credentials/hashes? If yes, is there a redaction switch? Reports are commonly mailed/shared — HIGH if no redaction option.
15. **Reporting — template injection** — Jinja2 templates in `reporting/templates/` rendering attacker-controlled strings (banners, service output): is autoescape on? `.md` and `.html` outputs should be safe by construction.
16. **`xlsx.py` formula injection** — values starting with `=`, `+`, `-`, `@` in Excel cells become formulas. Common when an nmap banner happens to start with `=`. HIGH.
17. **Spinner / progress UX** — does long-running module output (e.g., `auto_enum`) show progress, or just hang? MEDIUM if hang.
18. **Internationalization / encoding** — does the CLI handle non-ASCII hostnames? Do reports? LOW unless an exception is thrown.

### Deliverable
20-40 findings. Display findings often correlate with implementation findings (e.g., missing CORS protection is Phase 2; the same root cause showing as missing CSP header is Phase 3). Cross-reference where applicable using the finding ID.

---

## 7. Execution Instructions for Sonnet Executors

These instructions apply to all three executors. Each executor is briefed with **only its own phase** plus sections 1-3 and section 7.

1. **You are READ-ONLY.** Do not run any command that changes state. Use `Read`, `find`, `grep`, `ls`, `wc`, `head`, `tail`, `cat` only. Do not create files, modify files, install packages, or commit anything.
2. **Cite `file:line` for every finding.** A finding without an exact line number must be downgraded by one severity tier or dropped. The only exception: documentation-level findings may cite `file:section-name`.
3. **Walk the entire "Required reading" list for your phase.** Do not stop early. If a file referenced in the brief does not exist, that is itself a finding.
4. **Apply the rubric in section 2 uniformly.** When a finding could land in two tiers, pick the higher and justify with one sentence referencing the rubric example.
5. **Use the finding template in section 3 exactly.** Sequence numbers within your phase, prefix `F-S-` / `F-I-` / `F-D-`.
6. **Group findings by sub-area** (within Phase 2 only). For Phases 1 and 3, group by category.
7. **No remediation code.** State the recommendation as prose pointing at the file/function. Do not provide patches.
8. **No speculation beyond the codebase.** If you cannot determine exploitability without running the code, mark Confidence: Low and explain what would be needed to confirm.
9. **Output a single Markdown document** named `findings-phase-<N>.md` (phase 1, 2, or 3). Top of document: total finding count by severity. Then findings in severity order CRITICAL → HIGH → MEDIUM → LOW, with sub-area subheadings.
10. **Time-box.** Aim for 60-90 minutes of execution. Phase 2 is allowed up to 2 hours given volume. Stop early if you've covered the brief — comprehensiveness over volume.
11. **Do not coordinate with the other executors.** Duplicates will be resolved at consolidation. Independence preserves coverage.

---

## 8. Consolidation Step

After all three phases complete, a coordinator (human or fourth agent) produces the final `/home/user/purplesploit/FINDINGS.md` as follows:

1. **Concatenate** `findings-phase-1.md`, `findings-phase-2.md`, `findings-phase-3.md`.
2. **Deduplicate.** Two findings are duplicates if they cite the same `file:line` AND the same root cause. Keep the higher-severity copy and append the other phase's ID as a cross-reference (`See also: F-D-007`). If severity ties, keep the Phase 2 (Implementation) copy by convention since it usually has the most precise root cause; mention the others.
3. **Re-number** the merged findings sequentially: `F-001` ... `F-NNN`, ordering by:
   - Severity descending (CRITICAL first).
   - Within severity, by phase (Scope, Implementation, Display).
   - Within phase, by original sequence number.
4. **Prepend a summary table** at the top of `FINDINGS.md`:

   | Severity | Phase 1 (Scope) | Phase 2 (Impl) | Phase 3 (Display) | Total |
   |---|---|---|---|---|
   | CRITICAL | n | n | n | n |
   | HIGH | n | n | n | n |
   | MEDIUM | n | n | n | n |
   | LOW | n | n | n | n |
   | **Total** | n | n | n | **n** |

5. **Prepend an executive summary** (5-10 bullets) above the table calling out the top CRITICALs and any cross-phase patterns (e.g., "Three findings independently identify the auth gap on FastAPI from different angles").
6. **Append an Appendix A** listing every file inspected per phase (paths only), so coverage is auditable.
7. **Sanity check** — at least one CRITICAL finding is expected based on pre-recon (unauthenticated `/api/execute`). If the merged document has zero CRITICALs, the consolidation has gone wrong; rerun the relevant phase.
8. **Do not edit individual findings during consolidation** other than renumbering and adding cross-references. The integrity of executor analysis is preserved.

The final `FINDINGS.md` is the deliverable. No code changes accompany this review.
