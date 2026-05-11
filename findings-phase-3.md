# Phase 3 — Display / UX Review Findings

## Summary of Findings by Severity and Surface

| Severity | CLI | Web | API Responses | Reporting | Total |
|----------|-----|-----|---------------|-----------|-------|
| CRITICAL | 0   | 0   | 0             | 0         | 0     |
| HIGH     | 3   | 3   | 1             | 2         | 9     |
| MEDIUM   | 6   | 5   | 4             | 3         | 18    |
| LOW      | 6   | 4   | 1             | 2         | 13    |
| **Total**| 15  | 12  | 6             | 7         | **40** |

---

## CLI Surface

### F-D-001: Password Entered in Plaintext via `input()` — Credential Manager

- **Severity:** HIGH
- **Category:** CLI UX
- **Location:** `/home/user/purplesploit/python/purplesploit/ui/commands.py:1194`
- **Description:** When `creds select` opens the "Add New Credential" flow, the password is collected using the standard `input("Password: ")` call. Python's `input()` echoes every character to the terminal in plain text, so the password is visible to shoulder-surfers, screen-sharing software, and terminal recordings.
- **Impact:** Any plaintext password entry in a security tool is a critical UX-security collision. Operators commonly record terminal sessions or work in open-plan environments; any captured password is directly usable against live AD targets. The rubric identifies plain echo of a password as HIGH.
- **Recommendation:** Replace `input("Password: ")` at `commands.py:1194` with `prompt_toolkit.prompt("Password: ", is_password=True)` or Python's stdlib `getpass.getpass("Password: ")`. Apply the same fix to the `domain`, `dcip`, and `dns` prompts that follow (lines 1195-1197).
- **Confidence:** High

---

### F-D-002: `traceback.print_exc()` Leaks Full Stack Traces to CLI — Multiple Sites

- **Severity:** HIGH
- **Category:** CLI UX
- **Location:**
  - `/home/user/purplesploit/python/purplesploit/ui/commands.py:178-179`
  - `/home/user/purplesploit/python/purplesploit/ui/commands.py:1704-1705`
  - `/home/user/purplesploit/python/purplesploit/ui/commands.py:1750-1751`
  - `/home/user/purplesploit/python/purplesploit/ui/commands.py:1960-1961`
  - `/home/user/purplesploit/python/purplesploit/ui/commands.py:2354-2355`
  - `/home/user/purplesploit/python/purplesploit/ui/commands.py:4164-4165`
  - `/home/user/purplesploit/python/purplesploit/ui/commands.py:4915-4916`
  - `/home/user/purplesploit/python/purplesploit/ui/console.py:157-158`
- **Description:** Every broad `except Exception` handler in the CLI calls `traceback.print_exc()` unconditionally. Python tracebacks include the full call stack with local variable values. When a module fails while a credential or target is in scope, the traceback can include subprocess argument strings that embed passwords, file paths, or connection strings.
- **Impact:** A module crash during credential-spray or nmap execution can print the full command string including credentials to stderr/stdout. Anyone viewing or recording the session sees credentials in cleartext. The rubric rates HIGH when credentials surface in error output.
- **Recommendation:** Gate `traceback.print_exc()` behind a `DEBUG_MODE` environment variable check (consistent with the flag already used in `api/server.py:36`). For production use, catch exceptions at the top level in `commands.py:execute()` (~line 155) and display only a sanitized one-liner; log the full traceback to `~/.purplesploit/logs/`.
- **Confidence:** High

---

### F-D-003: Password Echo in C2 Session History — `cred` Command Returns Cleartext Password

- **Severity:** HIGH
- **Category:** CLI UX
- **Location:** `/home/user/purplesploit/python/purplesploit/api/server.py:1088-1089`
- **Description:** The `cred` command handler in `execute_framework_command()` returns `f"Added credential: {username}:{password}"`. This string is appended to the in-memory session history at line 856 and sent over the WebSocket to the browser terminal. Any credential added via the C2 web interface is stored in cleartext in the session history dict and returned to the browser.
- **Impact:** The plaintext `username:password` appears in the browser terminal output, can be retrieved via `GET /api/c2/session/{session_id}` (unauthenticated per Phase 2 findings), and is stored in `localStorage` if the terminal exports its session. Combined with the missing-auth finding (Phase 2), any attacker who queries the session endpoint receives all credentials in cleartext. HIGH per rubric.
- **Recommendation:** In `execute_framework_command()` at `server.py:1088`, return `f"Added credential: {username}"` only, omitting the password from the confirmation string. Ensure credential objects stored in session history are redacted before persistence.
- **Confidence:** High

---

### F-D-004: Inconsistent CLI Verb Order (`targets add` vs. `target <ip>` vs. `cred <user:pass>`)

- **Severity:** MEDIUM
- **Category:** CLI UX
- **Location:**
  - `/home/user/purplesploit/python/purplesploit/ui/commands.py:94-95` (quick shortcut registration)
  - `/home/user/purplesploit/python/purplesploit/ui/commands.py:214-222` (help text)
- **Description:** The framework uses two distinct paradigms side-by-side: noun-first subcommand syntax (`targets add`, `creds list`, `module select`) and verb-shortcut syntax (`target <ip>`, `cred <user:pass>`). The singular `target` adds and sets a target while `targets` manages the collection. This split is not documented as intentional aliasing and is easy to misuse — typing `target list` instead of `targets list` produces incorrect results.
- **Impact:** New operators repeatedly use the wrong form. Rubric: inconsistent CLI verb ordering is MEDIUM.
- **Recommendation:** Add a `target list` sub-path delegating to `targets list`, and cross-document the relationship in help text. Alternatively, consolidate on the `noun subcommand` pattern throughout.
- **Confidence:** High

---

### F-D-005: `creds select` "Add New Credential" Uses Raw `input()` Inside prompt_toolkit REPL

- **Severity:** MEDIUM
- **Category:** CLI UX
- **Location:** `/home/user/purplesploit/python/purplesploit/ui/commands.py:1189-1197`
- **Description:** When the fzf interactive selector returns "Add New Credential", the code falls back to plain `input()` calls for username, domain, DC IP, and DNS. Unlike `InteractiveSelector._simple_select_*` methods (which open `/dev/tty` directly), these `input()` calls go to `sys.stdin`, which may conflict with prompt_toolkit's event loop and produce undefined behaviour.
- **Impact:** In a prompt_toolkit REPL, raw `input()` can block indefinitely or consume unintended keystrokes. Users may experience a frozen terminal with no error message.
- **Recommendation:** Replace the `input()` calls at lines 1189-1197 with `prompt_toolkit.prompt()` calls (with `is_password=True` for the password field), or open `/dev/tty` directly as the other fallback methods do.
- **Confidence:** High

---

### F-D-006: `display.py` Hard-Codes `Version 6.7.0` — Mismatches All Other Declared Versions

- **Severity:** MEDIUM
- **Category:** CLI UX
- **Location:** `/home/user/purplesploit/python/purplesploit/ui/display.py:46`
- **Description:** The `print_banner()` method hard-codes `"Version 6.7.0 - Python Edition"`. This does not agree with `setup.py` (6.9.1), `__init__.py` (6.9.1), `main.py` (6.8.1), `README.md` (6.8.1), or web static files (v2.0.0/v6.2.0). This is a fifth distinct version string.
- **Impact:** Operators and support teams cannot determine which version is installed. Combined with the pre-recon version mismatch confirmed in Phase 1, the CLI surface adds yet another conflicting value. Rubric: MEDIUM.
- **Recommendation:** Replace the hard-coded string at `display.py:46` with a reference to `purplesploit.__version__` imported from `purplesploit/__init__.py`.
- **Confidence:** High

---

### F-D-007: `display.py` — `print_credentials_table()` Renders Passwords in Cleartext

- **Severity:** HIGH
- **Category:** CLI UX
- **Location:** `/home/user/purplesploit/python/purplesploit/ui/display.py:187-229`
- **Description:** `print_credentials_table()` renders a Rich table with a "Password" column and writes the raw password value without masking, truncation, or redaction. Any `creds list` or `show creds` command prints all stored passwords to the terminal in cleartext.
- **Impact:** Terminal scrollback buffers, screen-sharing tools, CI logs, and shoulder-viewers will see all stored AD credentials in plaintext. For a credential-spray tool storing privileged AD domain accounts, this is a significant operational-security exposure. HIGH per rubric: credentials surfaced in display output.
- **Recommendation:** Replace `password` display in `print_credentials_table()` at line ~220 with a masked value (e.g., `"*" * min(len(password or ""), 8)` or `"<set>"` / `"<not set>"`). Add a `--reveal` flag to `creds list` for cases where a human must verify the stored value.
- **Confidence:** High

---

### F-D-008: Banner Width Inconsistency — BANNER_VARIANT_1 Exceeds 120 Characters; Variants 2, 5 Are Very Narrow

- **Severity:** LOW
- **Category:** CLI UX
- **Location:** `/home/user/purplesploit/python/purplesploit/ui/banner.py:11-20`
- **Description:** `BANNER_VARIANT_1` contains lines approaching or exceeding 120 characters, while the console uses `width=120` (`display.py:35`) with `no_wrap=True` causing truncation on narrower terminals. Variants 2 and 5 are far narrower (<30 chars). Random variant selection produces unpredictable visual results.
- **Impact:** On terminals narrower than 120 columns (SSH sessions, tmux panes), BANNER_VARIANT_1 is truncated. LOW cosmetic issue.
- **Recommendation:** Normalize all banner widths or add a `width` metadata field to each variant for adaptive selection.
- **Confidence:** High

---

### F-D-009: `Console.start()` — Uncaught Exceptions Dump Full Traceback to REPL

- **Severity:** MEDIUM
- **Category:** CLI UX
- **Location:** `/home/user/purplesploit/python/purplesploit/ui/console.py:155-158`
- **Description:** The main REPL loop's top-level exception handler calls `traceback.print_exc()` unconditionally. Any unhandled exception from a command dumps a full Python traceback to the user's terminal, potentially exposing paths and variable values including credentials. This is the last-resort handler and should never leak internals.
- **Impact:** Same path-disclosure and potential credential-in-traceback risk as F-D-002. Because this is the REPL guard it catches everything not caught lower.
- **Recommendation:** Replace `traceback.print_exc()` at `console.py:158` with a conditional gated by `DEBUG_MODE`. Log full tracebacks to `~/.purplesploit/logs/errors.log`.
- **Confidence:** High

---

### F-D-010: Help Text Uses Emoji Icon Prefixes — Renders Broken on Non-Unicode Terminals

- **Severity:** LOW
- **Category:** CLI UX
- **Location:** `/home/user/purplesploit/python/purplesploit/ui/commands.py:260-287`
- **Description:** `cmd_help()` uses emoji as visual section headers (📦, 🔍, 🎯, etc.). On terminals without full Unicode/emoji support (older PuTTY, certain SSH clients, Windows CMD), these render as replacement characters, breaking the visual layout.
- **Impact:** Cosmetic breakage on common operator terminal environments. LOW.
- **Recommendation:** Provide a `--no-emoji` flag or auto-detect terminal capabilities via `TERM` env var, falling back to ASCII-only section headers.
- **Confidence:** Medium

---

### F-D-011: `recent` Command Underdocumented — No Mention of Session Scope or Entry Limit

- **Severity:** LOW
- **Category:** CLI UX
- **Location:** `/home/user/purplesploit/python/purplesploit/ui/commands.py:208-211`
- **Description:** The help text documents `recent` and `recent select` but does not explain that the recency list is session-scoped (lost on exit) or how many entries it holds. Users seeking modules from a prior session will be confused.
- **Impact:** LOW documentation gap.
- **Recommendation:** Add a help note indicating the list is in-memory and session-scoped. Consider persisting to `~/.purplesploit/recent_modules.json`.
- **Confidence:** Medium

---

### F-D-012: `cred` Quick Shortcut Help Omits Optional `[domain]` Argument

- **Severity:** LOW
- **Category:** CLI UX
- **Location:** `/home/user/purplesploit/python/purplesploit/ui/commands.py:235`
- **Description:** The help entry for `cred` shows `cred <user:pass>` but the handler at `commands.py:2588` accepts an optional second `[domain]` argument. Users who need to specify an AD domain must use the longer `creds add` flow unnecessarily.
- **Impact:** LOW — functionality still works via `creds add`; users just miss a shortcut.
- **Recommendation:** Update help string to `cred <user:pass> [domain]`.
- **Confidence:** High

---

### F-D-013: `console.py` — Bare `except:` in Auto-Completion Silently Swallows Database Errors

- **Severity:** LOW
- **Category:** CLI UX
- **Location:** `/home/user/purplesploit/python/purplesploit/ui/console.py:86-87` and `91-94`
- **Description:** In `_create_completer()`, both `framework.list_modules()` and `framework.session.targets.list()` are wrapped in bare `except:` blocks with `pass`. If the database is unavailable, auto-completion silently provides no suggestions with no log message or warning.
- **Impact:** LOW — completion silently degrades. Bare except makes debugging harder.
- **Recommendation:** Replace bare `except:` with `except Exception as e:` and log at DEBUG level.
- **Confidence:** High

---

### F-D-014: `display.py` Fixed Width 120 — Prevents Rich from Adapting to Terminal Size

- **Severity:** LOW
- **Category:** CLI UX
- **Location:** `/home/user/purplesploit/python/purplesploit/ui/display.py:35`
- **Description:** `RichConsole(width=120)` hard-codes the console width, preventing Rich from using the actual terminal dimensions.
- **Impact:** On terminals narrower than 120 columns, tables wrap or truncate without proper adaptation. LOW cosmetic issue.
- **Recommendation:** Remove the `width=120` argument to allow Rich to auto-detect terminal width. Keep `no_wrap=True` on banner prints only.
- **Confidence:** High

---

### F-D-015: Auto-Enum and Spray Progress Output Floods Terminal — No In-Place Progress Bar

- **Severity:** LOW
- **Category:** CLI UX
- **Location:**
  - `/home/user/purplesploit/python/purplesploit/ui/commands.py:4101-4104`
  - `/home/user/purplesploit/python/purplesploit/ui/commands.py:4871-4874`
- **Description:** Both `cmd_auto` and `cmd_spray` `on_progress` callbacks call `self.display.console.print()` for each step, producing one scrolling line per step. For long enumeration runs with hundreds of steps, the terminal becomes unusable.
- **Impact:** LOW UX issue — operator cannot see current state without scrolling.
- **Recommendation:** Replace line-per-step output with a Rich `Live` display or `Progress` bar that updates in-place.
- **Confidence:** High

---

## Web Surface

### F-D-016: Jinja2 Template — `onsubmit` JS `confirm()` Embeds Unescaped User Data (targets.html)

- **Severity:** HIGH
- **Category:** Web UX
- **Location:** `/home/user/purplesploit/python/purplesploit/web/templates/targets.html:118`
- **Description:** The delete form contains `onsubmit="return confirm('Delete target {{ target.name }}?');"`. Although Jinja2 auto-escape is on for HTML, the target name is embedded inside a JavaScript string literal within an HTML attribute. HTML escaping does not escape JS metacharacters such as single quotes. A target named `foo'; alert(1)//` closes the JS string and injects arbitrary JavaScript.
- **Impact:** A target name containing a single quote or backslash enables stored XSS. Anyone who adds a target with a crafted name causes XSS for all web dashboard users who navigate to the Targets page. HIGH per rubric: XSS via stored data in a Jinja2 template.
- **Recommendation:** Replace the inline `onsubmit` with a `data-target-name` attribute and a separate JS event listener that builds the confirmation string via JavaScript concatenation, never via Jinja2 interpolation inside JS string literals.
- **Confidence:** High

---

### F-D-017: Jinja2 Template — `onsubmit` JS `confirm()` Embeds Unescaped User Data (credentials.html)

- **Severity:** HIGH
- **Category:** Web UX
- **Location:** `/home/user/purplesploit/python/purplesploit/web/templates/credentials.html:126`
- **Description:** The delete form contains `onsubmit="return confirm('Delete credential {{ cred.username }}?');"`. Identical to F-D-016: a username containing a single quote enables stored XSS. The risk is compounded because JS executing on the credentials page can read the DOM — including rendered credential metadata.
- **Impact:** Stored XSS on the credentials page can exfiltrate all credential entries via DOM traversal. HIGH per rubric.
- **Recommendation:** Same fix as F-D-016: use a data attribute and a separate JS event listener.
- **Confidence:** High

---

### F-D-018: Static HTML Pages — Target/Service/Exploit Data Injected Into `innerHTML` Without Escaping

- **Severity:** HIGH
- **Category:** Web UX
- **Location:**
  - `/home/user/purplesploit/python/purplesploit/web/static/index.html:187-198` (`tbody.innerHTML = targets.map(...)`)
  - `/home/user/purplesploit/python/purplesploit/web/static/targets.html:135-183` (`container.innerHTML = cards.join('')`)
  - `/home/user/purplesploit/python/purplesploit/web/static/exploits.html:183-246` (`container.innerHTML = Object.entries(grouped).map(...)`)
  - `/home/user/purplesploit/python/purplesploit/web/static/target.html:62-231` (`container.innerHTML = ...`)
- **Description:** All four static pages build HTML by string-interpolating API response fields (`target.name`, `target.ip`, `target.description`, `exploit.exploit_title`, `exploit.exploit_path`, `service.version`, `service.service`) directly into `innerHTML` template literals without calling any escaping function. The `Utils.escapeHtml()` helper exists in `app.js:155` but is not used at any of these interpolation sites. `escapeHtml()` is only defined there — never called from these pages.
- **Impact:** A service banner or exploit title containing HTML/JS metacharacters executes as JavaScript. Attack path: (1) attacker controls a service banner on a live target, (2) nmap discovers it, (3) it is stored in the services table, (4) the web UI renders it into innerHTML without escaping, (5) XSS fires for all dashboard users. HIGH per rubric: XSS via data the framework writes, originating from a target-controlled source.
- **Recommendation:** Replace all bare interpolations (`${target.name}`, `${exploit.exploit_title}`, `${service.version}`, etc.) with `${Utils.escapeHtml(target.name)}` etc. in all four static files. Audit all template literal bodies for missed interpolation sites.
- **Confidence:** High

---

### F-D-019: Static HTML Files Display Version `v2.0.0` — Contradicts All Other Version Strings

- **Severity:** MEDIUM
- **Category:** Web UX
- **Location:**
  - `/home/user/purplesploit/python/purplesploit/web/static/index.html:13`
  - `/home/user/purplesploit/python/purplesploit/web/static/targets.html:13`
  - `/home/user/purplesploit/python/purplesploit/web/static/target.html:13`
  - `/home/user/purplesploit/python/purplesploit/web/static/exploits.html:13`
- **Description:** All four static HTML files display `v2.0.0` in the navigation bar. The C2 terminal (`c2.html:15`) shows `v6.2.0`. The API server hard-codes `version="2.0.0"` (`server.py:55`). The JS banner strings in `c2-terminal.js:71` and `:78` hard-code `v6.6.2`. None match the Python package version (6.9.1) or CLI banner (6.7.0). Six distinct version strings exist across the codebase.
- **Impact:** Users cannot determine which version they are running from any single surface. MEDIUM per rubric.
- **Recommendation:** Centralise on `purplesploit.__version__` and inject it into HTML at build time or via a Jinja2 template variable / JS fetch from the API.
- **Confidence:** High

---

### F-D-020: `c2.html` Hard-Codes `v6.2.0` / `c2-terminal.js` Hard-Codes `v6.6.2` — Both Inconsistent

- **Severity:** MEDIUM
- **Category:** Web UX
- **Location:**
  - `/home/user/purplesploit/python/purplesploit/web/static/c2.html:15`
  - `/home/user/purplesploit/python/purplesploit/web/static/js/c2-terminal.js:71`
  - `/home/user/purplesploit/python/purplesploit/web/static/js/c2-terminal.js:78`
- **Description:** The C2 terminal navbar shows `v6.2.0` while the fallback banner text in `c2-terminal.js` hard-codes `v6.6.2`. These two values differ from each other and from all other version strings across the codebase (see F-D-019).
- **Impact:** MEDIUM — part of the systemic version inconsistency. The C2 terminal is the primary web interface, making this particularly visible.
- **Recommendation:** Update to use a dynamic version fetched from `/api/status` or equivalent. Same remediation as F-D-019.
- **Confidence:** High

---

### F-D-021: No Security Headers Set — No CSP, No X-Frame-Options, No X-Content-Type-Options

- **Severity:** MEDIUM
- **Category:** Web UX
- **Location:**
  - `/home/user/purplesploit/python/purplesploit/api/server.py:64-71`
  - `/home/user/purplesploit/python/purplesploit/web/dashboard.py:30-36`
- **Description:** Neither the API server nor the web dashboard sets any HTTP security headers. No `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, or `Permissions-Policy` header is added to responses.
- **Impact:** Without CSP, the XSS vulnerabilities (F-D-016, F-D-017, F-D-018) have no defence-in-depth backstop. Without `X-Frame-Options: DENY`, the dashboard can be embedded in an iframe for clickjacking. MEDIUM per rubric — cross-link to Phase 2 CORS finding.
- **Recommendation:** Add a security headers middleware to both `server.py` and `dashboard.py`. At minimum: `Content-Security-Policy: default-src 'self'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.
- **Confidence:** High

---

### F-D-022: Credentials Dashboard Renders Username/Type in DOM Without Access Control

- **Severity:** MEDIUM
- **Category:** Web UX
- **Location:** `/home/user/purplesploit/python/purplesploit/web/templates/credentials.html:113-124`
- **Description:** The credentials template renders `{{ cred.username }}`, `{{ cred.domain }}`, and credential type (Password/Hash) for all stored credentials. With no access control on the `/credentials` route in `dashboard.py`, all credential metadata is visible to any local user or network peer who can reach the port.
- **Impact:** All stored AD account metadata is enumerable by unauthenticated callers. MEDIUM for display; the auth issue is separately CRITICAL in Phase 2.
- **Recommendation:** Fix authentication first (Phase 2). Then consider a per-row "show details" toggle rather than rendering all usernames in the list view.
- **Confidence:** High

---

### F-D-023: Web UI — Systemic Absence of ARIA Labels on Icon Buttons

- **Severity:** MEDIUM
- **Category:** Web UX
- **Location:**
  - `/home/user/purplesploit/python/purplesploit/web/static/c2.html:39` (refresh-modules button)
  - `/home/user/purplesploit/python/purplesploit/web/static/c2.html:93-94` (clear/export icon buttons)
  - `/home/user/purplesploit/python/purplesploit/web/templates/targets.html:119` (Delete button)
  - `/home/user/purplesploit/python/purplesploit/web/templates/credentials.html:127` (Delete button)
- **Description:** Multiple icon-only and action buttons across the web interface lack `aria-label` attributes. Screen readers will announce these as the text symbol name or generic "button" without context about which resource they operate on.
- **Impact:** MEDIUM systemic accessibility gap. Enterprise security tooling is increasingly required to meet WCAG 2.1 compliance.
- **Recommendation:** Add `aria-label` attributes to all icon-only buttons (e.g., `aria-label="Refresh modules list"`) and context-specific labels to Delete buttons (e.g., `aria-label="Delete target {{ target.name }}"`). Apply same pattern to dynamically-generated buttons in `c2-terminal.js`.
- **Confidence:** High

---

### F-D-024: `dashboard.html` Auto-Refreshes Every 3 Seconds — No User Override

- **Severity:** LOW
- **Category:** Web UX
- **Location:** `/home/user/purplesploit/python/purplesploit/web/templates/dashboard.html:266-268`
- **Description:** `setTimeout(function() { location.reload(); }, 3000)` performs a full page reload every 3 seconds. This disrupts keyboard focus and causes screen flicker. There is no pause or disable button. The static SPA pages use `AutoRefresh(10000)` which is more reasonable.
- **Impact:** LOW UX issue — disruptive for longer-duration dashboard sessions.
- **Recommendation:** Implement AJAX partial-refresh, increase interval to 30s, and provide a toggle button.
- **Confidence:** High

---

### F-D-025: Two Separate Navigation Structures — Jinja2 Routes and Static HTML Routes Not Cross-Linked

- **Severity:** LOW
- **Category:** Web UX
- **Location:**
  - `/home/user/purplesploit/python/purplesploit/web/static/index.html:17-18`
  - `/home/user/purplesploit/python/purplesploit/web/templates/targets.html:90-91`
- **Description:** Static HTML files link to `/static/*.html` paths; Jinja2 templates link to `/targets`, `/credentials` routes. The two navs are not cross-linked. A user at the Jinja2 `/targets` page finds no link to the C2 terminal; a user on the static index finds no link to `/credentials`.
- **Impact:** LOW navigation inconsistency — users cannot navigate between the static SPA and the Jinja2 template surfaces.
- **Recommendation:** Unify the navigation: either all Jinja2 templates or all static pages. Ensure a consistent navigation bar links all functional areas.
- **Confidence:** High

---

### F-D-026: `c2-terminal.js` — `useCredential()` Passes Plaintext Password as JavaScript Function Argument

- **Severity:** LOW
- **Category:** Web UX
- **Location:** `/home/user/purplesploit/python/purplesploit/web/static/js/c2-terminal.js:686`
- **Description:** The credential list is built with `onclick="useCredential('${escapeHtml(cred.username)}', '${escapeHtml(cred.password || '')}', '${escapeHtml(cred.hash || '')}')">`. The plaintext password is embedded as a string argument in an HTML onclick attribute. Even though `escapeHtml()` prevents XSS, the password is visible in the HTML source and in browser developer tools' event listener inspector.
- **Impact:** LOW — any user with browser DevTools access to the dashboard can see plaintext passwords for all stored credentials. Combined with missing auth (Phase 2), this means any web user can extract all passwords.
- **Recommendation:** Instead of passing the password as an onclick argument, store credential IDs and look up the credential via an API call inside `useCredential()`. This keeps plaintext passwords out of the DOM entirely.
- **Confidence:** High

---

## API Responses Surface

### F-D-027: DELETE Endpoints Return `{"message": "..."}` — Inconsistent with All Other Response Shapes

- **Severity:** MEDIUM
- **Category:** Web/API
- **Location:**
  - `/home/user/purplesploit/python/purplesploit/api/server.py:320`
  - `/home/user/purplesploit/python/purplesploit/api/server.py:393`
- **Description:** All GET routes return Pydantic `response_model` list/objects. POST routes return the created object model. DELETE routes return a bare `{"message": "..."}` dict with no declared `response_model`, inconsistent with all other routes. No `response_model=MessageResponse` is declared.
- **Impact:** API clients parsing response bodies rather than status codes need special-case logic for DELETE. MEDIUM per rubric: inconsistent error/success envelope across sibling endpoints.
- **Recommendation:** Define `MessageResponse(BaseModel)` with `message: str` and declare it as `response_model=MessageResponse` on both DELETE endpoints. Alternatively, return HTTP 204 No Content for successful deletes (REST convention).
- **Confidence:** High

---

### F-D-028: `/api/c2/module/{path}` vs. `/api/c2/modules/{category}` — Inconsistent Singular/Plural Naming

- **Severity:** MEDIUM
- **Category:** Web/API
- **Location:**
  - `/home/user/purplesploit/python/purplesploit/api/server.py:754`
  - `/home/user/purplesploit/python/purplesploit/api/server.py:767`
- **Description:** The C2 module routes use `/api/c2/modules/{category}` (plural) to list by category but `/api/c2/module/{module_path:path}` (singular) to get module detail. Additionally, `/api/c2/modules/search` (line 741) may shadow the `{category}` route if `search` is treated as a category name, depending on FastAPI's route resolution order.
- **Impact:** Clients must remember the singular/plural distinction per-route. Potential shadowing of `{category}="search"` could return unexpected results. MEDIUM per rubric: inconsistent naming and parameter style.
- **Recommendation:** Standardise on plural resource nouns: rename `/api/c2/module/{path}` to `/api/c2/modules/{path:path}`. Declare the `/api/c2/modules/search` route before `{category}` to prevent shadowing.
- **Confidence:** High

---

### F-D-029: `/api/c2/command` Returns HTTP 200 for Errors — Inconsistent with All Other Error Paths

- **Severity:** MEDIUM
- **Category:** Web/API
- **Location:** `/home/user/purplesploit/python/purplesploit/api/server.py:868-875`
- **Description:** When `execute_c2_command()` catches an exception, it returns HTTP 200 with `C2CommandResponse(success=False, error=str(e))`. All other API error paths raise `HTTPException` with 4xx/5xx. This is the only route that returns HTTP 200 for an error, and `error=str(e)` leaks raw Python exception messages regardless of `DEBUG_MODE`.
- **Impact:** API clients checking HTTP status codes will not detect C2 command failures. Error monitoring watching for 5xx misses all C2 execution failures. MEDIUM per rubric: inconsistent error envelope. The `str(e)` leakage is a secondary security concern.
- **Recommendation:** Raise `HTTPException(status_code=500, detail=sanitize_error(e))` instead of returning HTTP 200 with `success=False`. Align with the WebSocket C2 path which correctly returns a JSON error type (server.py:1208).
- **Confidence:** High

---

### F-D-030: `/api/status` Leaks Absolute Database File Paths in Unauthenticated Response

- **Severity:** MEDIUM
- **Category:** Web/API
- **Location:** `/home/user/purplesploit/python/purplesploit/api/server.py:221-232`
- **Description:** `/api/status` returns a dict containing full absolute paths to every database file (`db_manager.CREDENTIALS_DB`, `TARGETS_DB`, `WEB_TARGETS_DB`, `AD_TARGETS_DB`, `SERVICES_DB`) in the `"databases"` key. With no authentication, any caller can enumerate the absolute filesystem paths of all sensitive SQLite databases.
- **Impact:** Path disclosure combined with the missing-auth finding (Phase 2) allows an attacker to know the exact locations of databases containing credentials and targets. MEDIUM path disclosure per rubric.
- **Recommendation:** Remove the `"databases"` key from the `/api/status` response, or gate it behind authentication and `DEBUG_MODE`. Return only summary counts.
- **Confidence:** High

---

### F-D-031: `/api/workspaces/{name}` Returns Workspace Variables Including Potential Secrets in Plaintext

- **Severity:** MEDIUM
- **Category:** Web/API
- **Location:** `/home/user/purplesploit/python/purplesploit/api/server.py:569-578`
- **Description:** The workspace endpoint reads `variables.env` and returns all key-value pairs verbatim. If operators store API keys, passwords, or secrets in workspace variable files (the documented intent), these are returned to any unauthenticated caller with no filtering or masking.
- **Impact:** Any secret stored in a workspace variable file is exposed to unauthenticated callers. MEDIUM for the display aspect; the auth gap makes it higher in Phase 2.
- **Recommendation:** Mask values whose keys match patterns like `*_KEY`, `*_TOKEN`, `*_PASSWORD`, `*_SECRET`. Fix authentication first (Phase 2).
- **Confidence:** Medium

---

### F-D-032: API `version` Hard-Coded as `"2.0.0"` in Server Definition — Mismatches Package Version

- **Severity:** LOW
- **Category:** Web/API
- **Location:** `/home/user/purplesploit/python/purplesploit/api/server.py:55`
- **Description:** `FastAPI(version="2.0.0")` hard-codes the API version. The OpenAPI docs at `/api/docs` display `2.0.0` while the installed Python package is `6.9.1`. Additional hard-coded occurrences at `server.py:203` and `server.py:1119`.
- **Impact:** LOW — part of the systemic version inconsistency across surfaces.
- **Recommendation:** Replace `version="2.0.0"` and related hard-coded strings with a reference to `purplesploit.__version__`.
- **Confidence:** High

---

## Reporting Surface

### F-D-033: `xlsx.py` — No Formula Injection Protection for Excel Cells

- **Severity:** HIGH
- **Category:** Reporting
- **Location:**
  - `/home/user/purplesploit/python/purplesploit/reporting/xlsx.py:247-271` (`_create_findings_sheet`)
  - `/home/user/purplesploit/python/purplesploit/reporting/xlsx.py:307-311` (`_create_targets_sheet`)
  - `/home/user/purplesploit/python/purplesploit/reporting/xlsx.py:337-340` (`_create_services_sheet`)
- **Description:** Values written to Excel cells via `ws.cell(..., value=<string>)` are not sanitised for Excel formula injection. If any stored string (finding title, target description, service version, remediation text) begins with `=`, `+`, `-`, or `@`, Excel interprets it as a formula. Service version banners from nmap that happen to start with `=` (or attacker-crafted values) will trigger this.
- **Impact:** A service banner starting with `=` causes Excel to attempt formula evaluation, potentially making outbound network calls (via `=WEBSERVICE()`), executing DDE commands in older Excel versions, or corrupting cells. Reports are routinely sent to clients. HIGH per rubric: formula injection in Excel output.
- **Recommendation:** Before writing any user-controlled string to an Excel cell in `xlsx.py`, check if it starts with `=`, `+`, `-`, or `@` and prefix it with a tab character or single apostrophe to force literal text. Apply to all user-controlled string fields: `finding.title`, `finding.description`, `finding.impact`, `finding.remediation`, `finding.target`, service `version`, target `name`/`description`.
- **Confidence:** High

---

### F-D-034: `generator.py` — Full Credential Objects with Plaintext Passwords Included in Report Data

- **Severity:** HIGH
- **Category:** Reporting
- **Location:** `/home/user/purplesploit/python/purplesploit/reporting/generator.py:114`
- **Description:** `_build_report_data()` calls `db.get_all_credentials()` and passes the full list including plaintext passwords and NT hashes via `credentials=credentials` into `ReportData`. These credential objects reach the HTML template context at `html.py:125`. Any template iterating `credentials` renders plaintext passwords. No redaction switch exists in `ReportConfig`.
- **Impact:** All generated HTML reports (and any template referencing `credentials`) contain plaintext AD credentials and NT hashes. Reports are routinely shared via email, uploaded to ticketing systems, or stored on shared drives — environments without the same access controls as the operator workstation. HIGH per rubric: cleartext credentials in report output with no redaction option.
- **Recommendation:** In `generator.py:114`, redact passwords before including credentials: replace `c.to_dict()` with a function that replaces `password` with `"<redacted>"` and truncates hashes. Add `redact_credentials: bool = True` to `ReportConfig` to make this configurable.
- **Confidence:** High

---

### F-D-035: `markdown.py` — Target/Service Data Injected Into Markdown Tables Without Pipe Escaping

- **Severity:** MEDIUM
- **Category:** Reporting
- **Location:**
  - `/home/user/purplesploit/python/purplesploit/reporting/markdown.py:171-174`
  - `/home/user/purplesploit/python/purplesploit/reporting/markdown.py:183-187`
- **Description:** Target names, IP addresses, descriptions, service version strings, and service names are interpolated directly into Markdown table cells without escaping. Values containing `|` (common in service banners) break Markdown table structure. Values containing backticks or HTML will render as code or HTML in rendered Markdown (GitHub, wikis).
- **Impact:** Markdown table corruption produces a broken report deliverable. HTML injection in rendered Markdown can cause link injection. MEDIUM — data integrity concern for the report format.
- **Recommendation:** Escape `|` and `\` in all values before interpolating into Markdown table cells. Create a helper analogous to `html.py`'s `_escape_html()`.
- **Confidence:** High

---

### F-D-036: Jinja2 Template Directory for HTML Reports is Empty — Silent Fallback to Inline Template

- **Severity:** MEDIUM
- **Category:** Reporting
- **Location:**
  - `/home/user/purplesploit/python/purplesploit/reporting/templates/.gitkeep`
  - `/home/user/purplesploit/python/purplesploit/reporting/html.py:101-105`
- **Description:** `HTMLReportGenerator.__init__()` configures Jinja2 with `FileSystemLoader` pointing at `reporting/templates/`. The directory contains only a `.gitkeep` — no actual HTML templates. Every `generate()` call raises `TemplateNotFound` internally and silently falls back to the inline `_get_default_template()` string with no warning to the user.
- **Impact:** Custom template support is non-functional despite the `template_name` config option and directory structure implying it works. Operators who place custom templates in the directory silently get the default template. MEDIUM — implied feature is broken.
- **Recommendation:** Ship a default `default.html` template in `reporting/templates/`, log a warning when the fallback is used, or document that templates are not yet implemented and remove the `FileSystemLoader` path.
- **Confidence:** High

---

### F-D-037: PDF and XLSX Import Errors Propagate as Unhandled `ImportError` to CLI

- **Severity:** MEDIUM
- **Category:** Reporting
- **Location:** `/home/user/purplesploit/python/purplesploit/reporting/pdf.py:52-56`
- **Description:** `PDFReportGenerator.generate()` raises `ImportError` when WeasyPrint is absent. The CLI `cmd_report` handler needs to catch this and display a user-friendly message. No graceful fallback is implemented ("PDF unavailable; generating HTML instead") and no pre-check at startup.
- **Impact:** An operator running `report pdf` on a system without WeasyPrint sees a Python `ImportError` traceback, which also exposes the internal module structure. MEDIUM UX issue.
- **Recommendation:** In `cmd_report` in `commands.py`, wrap PDF and XLSX generation calls in try/except for `ImportError` and display `display.print_error("PDF generation requires WeasyPrint: pip install weasyprint")`.
- **Confidence:** High

---

### F-D-038: `xlsx.py` — No Credentials Sheet Despite `report_data.credentials` Being Populated

- **Severity:** MEDIUM
- **Category:** Reporting
- **Location:** `/home/user/purplesploit/python/purplesploit/reporting/xlsx.py:85-100`
- **Description:** `generate()` creates four worksheets: Summary, Findings, Targets, Services. The `ReportData` object includes a `credentials` list (populated by `generator.py:114`) and the HTML template context receives it (`html.py:125`). No "Credentials" worksheet is created in XLSX. Credential data is silently dropped from XLSX while potentially being present in HTML reports.
- **Impact:** XLSX consumers will not see credential data that is present in HTML reports — format inconsistency. MEDIUM per rubric: missing field in one format. Note: since F-D-034 recommends redacting credentials from reports, the right fix here is to either add a redacted credentials sheet or intentionally exclude credentials from all formats.
- **Recommendation:** Decide on a policy (exclude credentials from all formats, or include with redaction per F-D-034) and implement it consistently across all report generators.
- **Confidence:** High

---

### F-D-039: Reporting — No Progress Indicator During Long-Running PDF/Excel Generation

- **Severity:** LOW
- **Category:** Reporting
- **Location:** `/home/user/purplesploit/python/purplesploit/reporting/generator.py:124-167`
- **Description:** `ReportGenerator.generate()` performs potentially long operations (PDF rendering via WeasyPrint, large Excel workbooks) with no progress indicator. The CLI will appear to hang after issuing a `report` command.
- **Impact:** LOW UX issue — users may interrupt the process thinking it has frozen.
- **Recommendation:** Add a Rich `Progress` context or spinner around generator calls. For PDF specifically, add a spinner since WeasyPrint can take several seconds.
- **Confidence:** High

---

### F-D-040: `banner.py` — None of the Eight Banner Variants Displays a Version String

- **Severity:** LOW
- **Category:** CLI UX
- **Location:** `/home/user/purplesploit/python/purplesploit/ui/banner.py:103-119`
- **Description:** `show_banner()` and `get_banner_variant()` return raw ASCII art with no version annotation. The API `/api/banner` endpoint also returns just raw art. Web UI consumers never see a version string from the banner. The version is only added by `display.py:print_banner()` as a separate line, and that line contains the wrong version (6.7.0 per F-D-006).
- **Impact:** LOW — part of the systemic version inconsistency. Operators comparing CLI output to web C2 terminal cannot determine version from either banner alone.
- **Recommendation:** In `display.py:print_banner()` at line 43, replace the hard-coded `6.7.0` with `purplesploit.__version__`. Optionally add a `get_version_line()` helper so the web banner endpoint can include it.
- **Confidence:** High
