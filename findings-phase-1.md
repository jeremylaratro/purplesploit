# Phase 1 — Scope Review Findings

## Summary of Findings

| Severity | Count |
|----------|-------|
| CRITICAL | 3     |
| HIGH     | 8     |
| MEDIUM   | 14    |
| LOW      | 8     |
| **Total**| **33**|

---

## CRITICAL Findings

### F-S-001: Real External-Target Scan Data Committed to Repository

- **Severity:** CRITICAL
- **Category:** Legal
- **Location:** `/home/user/purplesploit/enum_output/sri_com_20251206_213824/network/nmap_full.txt:1`
  - `/home/user/purplesploit/enum_output/sri_com_20251206_213824/network/rustscan.txt:1`
- **Description:** The directory `enum_output/sri_com_20251206_213824/` contains live nmap and rustscan output against `www.sri.com` (SRI International), resolving to the public AWS IP `18.190.151.175`. The nmap command embedded in `nmap_full.txt` shows privileged scanning (`--privileged`, `-p-`, `-sV`, `-sC`) executed on 2025-12-06 21:41. The rustscan output includes the full TLS certificate chain for `dft.sri.com` including the full PEM-encoded certificate.
- **Impact:** Publishing real reconnaissance data against a third-party organisation constitutes strong evidence of unauthorized scanning (violating CFAA and analogous statutes cited in DISCLAIMER.md), exposes the developer's IP, toolchain, and scanning timestamp, and demonstrates the repository was used as an active engagement working directory. Meets the CRITICAL rubric criterion for "License/legal blockers that prevent lawful distribution."
- **Recommendation:** Remove `enum_output/` from the repository immediately and add it to `.gitignore`. Audit git history with `git log --all --full-history -- enum_output/` and purge with `git filter-repo` if any history exists. Add `enum_output/`, `*.xml`, and `*.txt` (or specific scan-result patterns) to `.gitignore`.
- **Confidence:** High

---

### F-S-002: License Mismatch — CC BY-NC-SA 4.0 in `LICENSE` vs. MIT Classifier in `setup.py`

- **Severity:** CRITICAL
- **Category:** Legal
- **Location:** `/home/user/purplesploit/LICENSE:1`
  - `/home/user/purplesploit/python/setup.py:26`
- **Description:** `LICENSE` contains the full text of Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International, which prohibits commercial use. `setup.py` line 26 declares the PyPI trove classifier `"License :: OSI Approved :: MIT License"`. MIT is a permissive OSI-approved license with no commercial-use restriction. Any package published to PyPI with this setup.py will advertise MIT terms in its metadata, misrepresenting the actual license to every downstream consumer. README.md line 319 correctly states CC BY-NC-SA 4.0.
- **Impact:** Users installing via PyPI and reading the MIT classifier will deploy the tool commercially without knowing they are violating the actual CC BY-NC-SA 4.0 terms. This is a legal blocker for lawful distribution via PyPI, meeting the CRITICAL rubric criterion.
- **Recommendation:** Change `setup.py:26` to a custom classifier such as `"License :: Other/Proprietary License"` and add `license_files = ["LICENSE"]` to the setup configuration. Legal review is recommended before any PyPI release.
- **Confidence:** High

---

### F-S-003: `purplesploit-report` Entry Point References Non-Existent `purplesploit.reporting.cli:main`

- **Severity:** CRITICAL
- **Category:** Scope
- **Location:** `/home/user/purplesploit/python/setup.py:79`
- **Description:** `setup.py` declares the console script entry point `purplesploit-report=purplesploit.reporting.cli:main`. No file named `cli.py` exists under `python/purplesploit/reporting/` — only `generator.py`, `html.py`, `markdown.py`, `models.py`, `pdf.py`, `xlsx.py`, and a `.gitkeep` placeholder in `templates/`. Invoking `purplesploit-report` after installation raises `ModuleNotFoundError`.
- **Impact:** Any installed copy of PurpleSploit has a broken `purplesploit-report` command that crashes immediately. This indicates the reporting CLI was claimed as implemented but was never written. Meets the CRITICAL rubric criterion for a direct correctness defect — the entry point fails on every invocation.
- **Recommendation:** Either implement `python/purplesploit/reporting/cli.py` with a `main()` function, or remove the `purplesploit-report` entry point from `setup.py:79` until the module exists.
- **Confidence:** High

---

## HIGH Findings

### F-S-004: Four-Way Version String Mismatch Across Seven Files

- **Severity:** HIGH
- **Category:** Docs
- **Location:** `/home/user/purplesploit/README.md:1` — `v6.8.1`
  - `/home/user/purplesploit/QUICKSTART.md:1` — `v6.7.0`
  - `/home/user/purplesploit/QUICKSTART.md:263` — `Version 6.7.0 - Python Edition`
  - `/home/user/purplesploit/python/setup.py:14` — `6.9.1`
  - `/home/user/purplesploit/python/purplesploit/__init__.py:18` — `6.9.1`
  - `/home/user/purplesploit/python/purplesploit/main.py:48` — `PurpleSploit 6.8.1`
  - `/home/user/purplesploit/docs/ARCHITECTURE.md:3` — `6.8.1`
  - `/home/user/purplesploit/docs/API.md:5` — `6.8.1`
- **Description:** Five distinct version strings are active simultaneously. The canonical package version (setup.py, __init__.py) is `6.9.1`. The user-facing `--version` flag hard-codes `6.8.1`. README says `6.8.1`. QUICKSTART says `6.7.0`. Architecture and API docs say `6.8.1`. The DOCUMENTATION_AUDIT-23JAN2026.md claimed this was fixed but the mismatch persists.
- **Impact:** A user running `purplesploit --version` sees `6.8.1` while running `6.9.1` code. Package managers, SBOMs, and vulnerability scanners record incorrect version metadata. Meets the HIGH rubric criterion for "stale or contradictory feature documentation."
- **Recommendation:** Introduce a single source of truth: read `__version__` from `__init__.py` in `main.py:48` via `from purplesploit import __version__`. Update QUICKSTART.md, README.md, ARCHITECTURE.md, and API.md to reflect `6.9.1` consistently.
- **Confidence:** High

---

### F-S-005: No `SECURITY.md` and No Machine-Readable Vulnerability Disclosure Process

- **Severity:** HIGH
- **Category:** Legal
- **Location:** `/home/user/purplesploit/` (repo root — `SECURITY.md` absent)
  - `/home/user/purplesploit/docs/DISCLAIMER.md:102`
- **Description:** The repository contains no `SECURITY.md` at root or under `.github/`. DISCLAIMER.md (lines 102–108) tells users to practice responsible disclosure and follow coordinated disclosure practices, but provides no contact email, GitHub security advisory URL, PGP key, or response timeline for vulnerabilities discovered in PurpleSploit itself. GitHub's private vulnerability reporting requires a `SECURITY.md` to function.
- **Impact:** A researcher discovering a vulnerability in PurpleSploit (which has confirmed unauthenticated RCE, per REVIEW_PLAN.md pre-recon) has no private disclosure path. This increases the risk of zero-day public disclosure. HIGH per rubric for missing security process on a security-critical tool.
- **Recommendation:** Create `.github/SECURITY.md` with a `security@` contact, the GitHub private security advisory link, a response SLA, and a GPG key if available. Reference it from README.md and DISCLAIMER.md.
- **Confidence:** High

---

### F-S-006: CI Security Bandit Scan Silently Skips `shell=True` and SQL-Injection Checks, Always Exits Zero

- **Severity:** HIGH
- **Category:** Scope
- **Location:** `/home/user/purplesploit/.github/workflows/ci.yml:105`
- **Description:** The CI `security` job runs `bandit -r purplesploit/ -ll --skip B404,B603,B602,B607,B608 || true`. B602 detects `subprocess.Popen` with `shell=True`; B608 detects hardcoded SQL injection patterns; B607 detects partial executable paths. These are the exact vulnerability classes known to be present per pre-recon. The `|| true` ensures the job always exits successfully regardless of findings.
- **Impact:** The security CI job is non-functional as a gate: it can never block a PR even if new critical shell-injection vulnerabilities are introduced. Developers see green checkmarks while dangerous patterns accumulate. HIGH per rubric for a security process gap that misleads contributors.
- **Recommendation:** Remove B602, B607, B608 from the `--skip` list. Change `|| true` to `|| exit 1`. Annotate intentional `shell=True` uses inline with `# nosec B602` plus a documented justification.
- **Confidence:** High

---

### F-S-007: `docs/ARCHITECTURE.md` Incorrectly Labels the Web Dashboard as Flask

- **Severity:** HIGH
- **Category:** Docs
- **Location:** `/home/user/purplesploit/docs/ARCHITECTURE.md:372`
  - `/home/user/purplesploit/python/purplesploit/web/dashboard.py:7`
- **Description:** The architecture diagram at ARCHITECTURE.md line 372 labels the web dashboard component as `(Flask)`. The actual implementation imports `from fastapi import FastAPI` (dashboard.py line 7) and uses `FastAPI()`. Flask is not listed in `setup.py:install_requires` and is not present in the codebase.
- **Impact:** Developers extending or debugging the dashboard will look for Flask-specific patterns (Blueprints, `render_template`, `@app.route`) rather than FastAPI patterns (routers, Depends, Pydantic models). This misdirection compounds the security review difficulty. HIGH because architectural documentation for a web-facing component is materially wrong.
- **Recommendation:** Update `docs/ARCHITECTURE.md:372` from `(Flask)` to `(FastAPI)`. Update the entire "Web Interface / Architecture" section to accurately describe the FastAPI-based stack.
- **Confidence:** High

---

### F-S-008: Zero Dedicated Tests for `analysis/`, `models/`, and `utils/` Subpackages

- **Severity:** HIGH
- **Category:** Tests
- **Location:** `/home/user/purplesploit/python/purplesploit/analysis/__init__.py:1` (only file)
  - `/home/user/purplesploit/python/purplesploit/models/__init__.py:1`
  - `/home/user/purplesploit/python/purplesploit/utils/__init__.py:1`
  - `/home/user/purplesploit/python/tests/unit/` (no `analysis/`, `models/`, or `utils/` directories)
- **Description:** Three top-level subpackages (`analysis/`, `models/`, `utils/`) have no dedicated test directories. `models/database.py` contains the SQLAlchemy ORM definitions for Credential, Target, Service, and Exploit — the data structures that underpin the entire framework. `analysis/` is listed as a separate architectural layer. No tests validate these independently.
- **Impact:** Schema regressions in `models/database.py` (particularly the Credential model) propagate silently. HIGH because the credential model is used in live attack operations and untested schema changes could corrupt stored credentials or silently drop fields.
- **Recommendation:** Create `python/tests/unit/models/` with tests for each SQLAlchemy model (especially `Credential`) and `python/tests/unit/analysis/` for the analysis layer. Follow the DOCUMENTATION_AUDIT-23JAN2026.md coverage-gap plan.
- **Confidence:** High

---

### F-S-009: `modules/c2/` and `modules/deploy/` Missing `__init__.py`

- **Severity:** HIGH
- **Category:** Module Subsystem
- **Location:** `/home/user/purplesploit/python/purplesploit/modules/c2/` (no `__init__.py`)
  - `/home/user/purplesploit/python/purplesploit/modules/deploy/` (no `__init__.py`)
- **Description:** All other module subdirectories (`ad/`, `ai/`, `impacket/`, `network/`, `osint/`, `recon/`, `smb/`, `utility/`, `web/`) contain `__init__.py`. The `c2/` directory contains only `ligolo_pivot.py`; `deploy/` contains `c2.py`, `ligolo.py`, and `script.py`. Without `__init__.py`, Python's standard import system cannot treat these as packages (e.g., `from purplesploit.modules.c2 import ligolo_pivot` will fail). The framework's custom `os.walk`-based loader avoids this issue but any other import path breaks.
- **Impact:** C2 and deploy modules fail to import via standard Python package mechanics. Integration tests or user scripts using normal imports will get `ImportError`. HIGH because C2 beacon deployment and pivot operations are core offensive capabilities whose breakage would be silent.
- **Recommendation:** Add empty `__init__.py` files to `python/purplesploit/modules/c2/` and `python/purplesploit/modules/deploy/` to match all sibling directories.
- **Confidence:** High

---

### F-S-010: DOCUMENTATION_AUDIT-23JAN2026.md Claims Applied Fixes That Were Not Applied

- **Severity:** HIGH
- **Category:** Docs
- **Location:** `/home/user/purplesploit/docs/DOCUMENTATION_AUDIT-23JAN2026.md:50`
  - `/home/user/purplesploit/QUICKSTART.md:1` — still reads `v6.7.0`
  - `/home/user/purplesploit/QUICKSTART.md:263` — still reads `Version 6.7.0 - Python Edition`
  - `/home/user/purplesploit/README.md:27` — still reads `[Wiki](wiki/)`
- **Description:** The audit report (Section 2, Issue 2 and Issue 3) marks as applied: "Updated title to 'PurpleSploit v6.8.1 Quick Start Guide'", "Updated footer to 'Version 6.8.1 - Python Edition'", and "Replaced dead wiki links with existing documentation links." All three items remain unfixed in the current files. The audit's completion checklist marks all items `[x]` done.
- **Impact:** The official audit report creates false confidence that known documentation issues were resolved. Maintainers and future auditors reading the audit will believe the repository is in a clean state when it is not. HIGH because a false audit record undermines all remediation tracking.
- **Recommendation:** Apply the documented fixes to QUICKSTART.md (lines 1 and 263) and README.md (line 27). Update the audit completion checklist to reflect actual state, or close it with a follow-up ticket for each unresolved item.
- **Confidence:** High

---

### F-S-011: `textual`, `matplotlib`, `seaborn`, `click`, `python-docx`, and `cryptography` in `install_requires` Are Unused in Production Code

- **Severity:** HIGH
- **Category:** Dependencies
- **Location:** `/home/user/purplesploit/python/setup.py:47–58`
- **Description:** `setup.py install_requires` mandates `textual>=0.40.0`, `matplotlib>=3.7.0`, `seaborn>=0.12.0`, `click>=8.1.0`, `python-docx>=1.0.0`, and `cryptography>=41.0.0`. A full search of `python/purplesploit/**/*.py` (excluding test files) finds zero production imports of `textual`, `matplotlib`, `seaborn`, `click`, `python-docx`, or `cryptography`. These packages add ~300 MB of transitive dependencies (matplotlib+seaborn include compiled extensions; weasyprint requires Cairo/Pango system libraries; cryptography requires Rust-compiled OpenSSL bindings).
- **Impact:** Every installation forces users to download ~300 MB of unused code and native libraries. On constrained systems (VPS, containers, Kali minimal installs) this is prohibitive. Unused cryptography and matplotlib also expand the supply-chain attack surface. HIGH per rubric for dependency hygiene.
- **Recommendation:** Move unused packages to `extras_require` groups (e.g., `extras_require={"reporting": ["weasyprint", "python-docx", "matplotlib", "seaborn"], "tui": ["textual"], "crypto": ["cryptography"]}`) or remove them. Keep only packages actually imported in production code in `install_requires`.
- **Confidence:** High

---

## MEDIUM Findings

### F-S-012: `--version` CLI Flag Hard-Codes `6.8.1` Instead of Reading `__version__`

- **Severity:** MEDIUM
- **Category:** Scope
- **Location:** `/home/user/purplesploit/python/purplesploit/main.py:48`
- **Description:** The argparse `--version` action at line 48 hard-codes the string `'PurpleSploit 6.8.1'`. The actual package version in `__init__.py:18` is `6.9.1`. Any version bump to `setup.py` / `__init__.py` requires a manual update to `main.py` or the `--version` output becomes stale.
- **Impact:** Users, scripts, and CI pipelines relying on `purplesploit --version` to select version-specific behaviour will be misled. MEDIUM per rubric for version string mismatch.
- **Recommendation:** Import `__version__` at the top of `main.py` and replace the string literal with `f'PurpleSploit {__version__}'`.
- **Confidence:** High

---

### F-S-013: API.md Incorrect Version and Inaccurate Rate Limiting Claim

- **Severity:** MEDIUM
- **Category:** Docs
- **Location:** `/home/user/purplesploit/docs/API.md:5`
  - `/home/user/purplesploit/docs/API.md:1041`
- **Description:** API.md header states `**Package Version:** 6.8.1` while the package is `6.9.1`. The "Rate Limiting" section at line 1041 states "Currently no rate limiting is implemented." However, `setup.py:37` lists `slowapi>=0.1.9` as a required dependency and `server.py` imports and wires up slowapi (per REVIEW_PLAN.md pre-recon note at lines 49 referencing `enabled=not DEBUG_MODE`).
- **Impact:** API consumers will not know that rate limiting infrastructure exists (even if inactive on most routes) and will not plan accordingly for production hardening. MEDIUM for stale documentation.
- **Recommendation:** Update API.md version to `6.9.1`. Update the Rate Limiting section to describe the slowapi configuration and list which routes have `@limiter.limit()` decorators.
- **Confidence:** High

---

### F-S-014: QUICKSTART.md and README.md Dead Links to Non-Existent `wiki/` Directory

- **Severity:** MEDIUM
- **Category:** Docs
- **Location:** `/home/user/purplesploit/QUICKSTART.md:241`
  - `/home/user/purplesploit/QUICKSTART.md:242`
  - `/home/user/purplesploit/README.md:27`
- **Description:** QUICKSTART.md lines 241-242 link to `wiki/Commands-Reference.md` and `wiki/Framework-Guide.md`. README.md line 27 links to `wiki/`. No `wiki/` directory exists in the repository. These links were listed as fixed in DOCUMENTATION_AUDIT-23JAN2026.md but remain broken.
- **Impact:** New users reach dead links at the most critical "Next Steps" section of the quick start guide. MEDIUM per rubric for documentation correctness.
- **Recommendation:** Replace the `wiki/` links in QUICKSTART.md lines 241-242 with links to existing documentation (e.g., `docs/ARCHITECTURE.md`, `docs/API.md`). Remove `[Wiki](wiki/)` from README.md line 27.
- **Confidence:** High

---

### F-S-015: `ARCHITECTURE.md` Labels "WebSocket Notifications" as Current Architecture When It Is Planned

- **Severity:** MEDIUM
- **Category:** Docs
- **Location:** `/home/user/purplesploit/docs/ARCHITECTURE.md:398`
- **Description:** The "Real-time Updates" section at line 398 states "WebSocket notifications (planned)" inside a current architecture document dated 23 January 2026. The actual real-time sync mechanism (shared SQLite polling) differs from what is implied. The C2 WebSocket endpoint (`/ws/c2/{session_id}`) does exist in `server.py:1157` but the dashboard-to-core WebSocket sync is not implemented.
- **Impact:** Developers and users reading ARCHITECTURE.md cannot distinguish shipped from planned features. MEDIUM per rubric for stale documentation.
- **Recommendation:** Clearly mark the "WebSocket notifications" item as `[planned]` or move it to `ROADMAP.md`. Document the actual sync mechanism (shared SQLite, periodic polling) accurately.
- **Confidence:** High

---

### F-S-016: `openai` / `anthropic` Declared Optional (`extras_require["ai"]`) but Imported Without a Guard in `ai_automation.py`

- **Severity:** MEDIUM
- **Category:** Dependencies
- **Location:** `/home/user/purplesploit/python/purplesploit/modules/ai/ai_automation.py:179`
  - `/home/user/purplesploit/python/purplesploit/modules/ai/ai_automation.py:182`
  - `/home/user/purplesploit/python/setup.py:70–73`
- **Description:** `openai` and `anthropic` are `extras_require["ai"]` (optional). However, `ai_automation.py` performs bare `from openai import OpenAI` (line 179) and `import anthropic` (line 182) inside an operation handler. A user who installs without `[ai]` extras and loads the AI Automation module gets an unhandled `ImportError` at runtime.
- **Impact:** The AI module crashes at operation-dispatch time rather than failing gracefully. MEDIUM per rubric for dependency/correctness mismatch.
- **Recommendation:** Wrap the AI imports in a `try/except ImportError` block and raise a clear user-facing error (e.g., "Install AI extras: `pip install purplesploit[ai]`") before executing AI operations.
- **Confidence:** High

---

### F-S-017: `pyyaml` Mandatory Dependency but Used Only Via Lazy Import in One Method

- **Severity:** MEDIUM
- **Category:** Dependencies
- **Location:** `/home/user/purplesploit/python/setup.py:57`
  - `/home/user/purplesploit/python/purplesploit/plugins/repository.py:359`
- **Description:** `pyyaml>=6.0` is in `install_requires` (mandatory) but is imported in only a single `try: import yaml` inside one method of `PluginRepository`. The plugin repository feature is optional and most users will never invoke it. Additionally, `yaml.load` without `Loader=SafeLoader` is a known deserialization risk that warrants Phase 2 review.
- **Impact:** Users who never use the plugin repository system are forced to install pyyaml. If `yaml.load` is called on untrusted plugin manifests without SafeLoader, this escalates to HIGH security. MEDIUM per rubric for dependency hygiene.
- **Recommendation:** Move `pyyaml` to `extras_require["plugins"]`. Confirm in `repository.py:359` that `yaml.load` uses `Loader=yaml.SafeLoader`.
- **Confidence:** High

---

### F-S-018: CHANGELOG 6.9.0 "All 3,835 Unit Tests Passing" Is Off-by-One and Inconsistent with Prior Failure History

- **Severity:** MEDIUM
- **Category:** Docs
- **Location:** `/home/user/purplesploit/CHANGELOG.md:16`
  - `/home/user/purplesploit/docs/DOCUMENTATION_AUDIT-23JAN2026.md:155`
- **Description:** CHANGELOG 6.9.0 states "All 3,835 unit tests passing." The actual `def test_` count in `python/tests/unit/` is 3,834 (off-by-one). DOCUMENTATION_AUDIT-23JAN2026.md recorded 3,464 passing out of 3,692 with 112 failures and 93 errors at the 6.8.2 baseline. CHANGELOG 6.8.2 showed 54 remaining failures. The jump from 3,571 passing (54 failures) to "all 3,835 passing" in a single release — while adding 155 new tests — is unverified by independent CI run.
- **Impact:** If the "all passing" claim is inaccurate, defects are being shipped under a false "green" badge. MEDIUM per rubric for CHANGELOG honesty.
- **Recommendation:** Record actual CI pass/fail counts from GitHub Actions runs in the CHANGELOG. Publish a CI badge linking directly to the Actions workflow.
- **Confidence:** Medium

---

### F-S-019: Reporting Templates Directory Contains Only `.gitkeep` — No Templates Shipped

- **Severity:** MEDIUM
- **Category:** Scope
- **Location:** `/home/user/purplesploit/python/purplesploit/reporting/templates/.gitkeep`
  - `/home/user/purplesploit/python/setup.py:85`
- **Description:** `setup.py:85` declares `"purplesploit.reporting": ["templates/*.html", "templates/*.jinja2"]` as package data. The actual `reporting/templates/` directory contains only `.gitkeep`. If any reporting generator attempts to load a Jinja2 template file from this directory, it will raise `TemplateNotFound`. The ARCHITECTURE.md documents Jinja2 templates as part of reporting.
- **Impact:** Any reporting function that uses file-based templates will fail at runtime for all installed users. MEDIUM for feature completeness gap.
- **Recommendation:** Populate `reporting/templates/` with the required HTML/Jinja2 template files, or remove the `package_data` glob if generators use inline strings. Remove `.gitkeep` once real templates exist.
- **Confidence:** Medium

---

### F-S-020: QUICKSTART.md Installation Commands Omit the Python Package Installation Step

- **Severity:** MEDIUM
- **Category:** Docs
- **Location:** `/home/user/purplesploit/QUICKSTART.md:7–20`
- **Description:** QUICKSTART.md's Installation section shows `apt install fzf ripgrep python3` and `git clone`, but includes no `pip install -e .` or `pip install purplesploit` step. Users following only QUICKSTART.md will have the repository cloned but the Python package not installed, so the `purplesploit` entry point and `import purplesploit` will both fail.
- **Impact:** New users will have a broken installation with no clear error pointing them to the missing step. MEDIUM for correctness defect in first-contact documentation.
- **Recommendation:** Add `cd purplesploit/python && pip install -e .` (or equivalent) to the QUICKSTART.md Setup section immediately after the `git clone` step.
- **Confidence:** High

---

### F-S-021: AI Subpackage (`purplesploit/ai/`) Is Absent from README and User Documentation

- **Severity:** MEDIUM
- **Category:** Scope
- **Location:** `/home/user/purplesploit/python/purplesploit/ai/` (full directory)
  - `/home/user/purplesploit/README.md` (no mention of `ai/` library subpackage)
- **Description:** `python/purplesploit/ai/` contains `attack_paths.py`, `nlp.py`, and `recommender.py` — components for AI-powered attack path analysis, NLP queries, and module recommendations. These are distinct from the `modules/ai/` CLI wrappers. README.md does not mention the `ai/` library. ARCHITECTURE.md documents both but does not clarify their relationship.
- **Impact:** A documented architectural component is invisible to users. Features not mentioned in the README are effectively undiscoverable. MEDIUM for feature documentation drift.
- **Recommendation:** Add a section to README.md describing the `ai/` subpackage capabilities. Update ARCHITECTURE.md to clearly explain the distinction between `ai/` (library components) and `modules/ai/` (CLI modules that use the library).
- **Confidence:** High

---

### F-S-022: `ARCHITECTURE.md` Database Paths Contradict `main.py` Default Path

- **Severity:** MEDIUM
- **Category:** Docs
- **Location:** `/home/user/purplesploit/docs/ARCHITECTURE.md:354–355`
  - `/home/user/purplesploit/python/purplesploit/main.py:64–67`
- **Description:** ARCHITECTURE.md states the databases are at `~/.purplesploit/session.db` and `~/.purplesploit/purplesploit.db`. However, `main.py` lines 64-67 set the default database path to `<project_root>/.data/purplesploit.db` (the project directory, not the user home). Users following ARCHITECTURE.md to locate their database for backup or inspection will look in the wrong directory.
- **Impact:** Mislocated database causes failed backup/restore and data loss scenarios. MEDIUM for documentation incorrectness.
- **Recommendation:** Update ARCHITECTURE.md "Database Files" section to reflect the actual default path `<project_root>/.data/purplesploit.db`, and document the `--db` flag and `PURPLESPLOIT_DB` environment variable.
- **Confidence:** High

---

### F-S-023: `delete_small_files.sh` Developer Utility Committed at Repository Root

- **Severity:** MEDIUM
- **Category:** Scope
- **Location:** `/home/user/purplesploit/delete_small_files.sh:1`
- **Description:** A standalone developer utility shell script is committed at the repository root. It has no connection to PurpleSploit's user-facing functionality. Its presence alongside `enum_output/` and `my_sessions.json` confirms the repository root was used as a general engagement working directory, which is the root cause behind the scan data leak in F-S-001.
- **Impact:** Loose developer tools at root signal poor hygiene practices and increase the risk of future accidental data leakage into version control. MEDIUM for repository hygiene.
- **Recommendation:** Move `delete_small_files.sh` to `scripts/` if it has legitimate project utility, or remove it. Add comprehensive `.gitignore` patterns for engagement artifacts.
- **Confidence:** High

---

### F-S-024: All CI Linting, Security, and Type-Check Jobs Use `|| true` (Always Exit Zero)

- **Severity:** MEDIUM
- **Category:** Scope
- **Location:** `/home/user/purplesploit/.github/workflows/ci.yml:78`
  - `/home/user/purplesploit/.github/workflows/ci.yml:83`
  - `/home/user/purplesploit/.github/workflows/ci.yml:105`
  - `/home/user/purplesploit/.github/workflows/ci.yml:137`
- **Description:** The `lint` job (`ruff check || true`, `ruff format --check || true`), `security` job (`bandit ... || true`), and `type-check` job (`mypy ... || true`) all append `|| true` to their primary commands. The `test` job is the only effective gate. Every quality and security check always produces a green status in CI.
- **Impact:** Linting regressions, security issues, and type errors accumulate with no friction to contributors. MEDIUM for CI governance failure.
- **Recommendation:** Remove `|| true` from all four commands. Establish a baseline suppression list for existing known issues using `# noqa` and `# nosec` inline annotations, then enforce clean output for all new code.
- **Confidence:** High

---

### F-S-025: `my_sessions.json` Empty File at Repository Root Indicates Engagement Data Risk

- **Severity:** MEDIUM
- **Category:** Scope
- **Location:** `/home/user/purplesploit/my_sessions.json:1`
- **Description:** `my_sessions.json` is a zero-byte file tracked at the repository root. Its name strongly suggests it was created to hold live session state (targets, credentials, history). It is currently empty, but its presence in version control means it was either created before data was written or emptied before commit.
- **Impact:** If session state had been written before `git commit`, live engagement credentials and targets would be in the git history. The pattern mirrors the confirmed scan data leak in F-S-001. MEDIUM for repository hygiene risk.
- **Recommendation:** Run `git log --all --full-history -- my_sessions.json` to verify no prior non-empty commit exists. Add `my_sessions.json` to `.gitignore` and remove it from tracking with `git rm --cached my_sessions.json`.
- **Confidence:** High

---

## LOW Findings

### F-S-026: README.md Installation Section Contains Nested Fenced Code Blocks (Malformed Markdown)

- **Severity:** LOW
- **Category:** Docs
- **Location:** `/home/user/purplesploit/README.md:265–278`
- **Description:** The `## 📦 Installation` section opens a `\`\`\`bash` block at line 265, then opens another `\`\`\`bash` block inside it at line 271 without closing the first. Most Markdown renderers display the installation instructions with broken formatting.
- **Impact:** The installation instructions render incorrectly on GitHub and documentation sites. LOW cosmetic issue but affects first impressions.
- **Recommendation:** Fix the nested fenced code block at README.md:265–278 so all prerequisite lists render correctly as separate code blocks.
- **Confidence:** High

---

### F-S-027: QUICKSTART.md Footer Still References `v6.0.0` for Auto-Completion Feature

- **Severity:** LOW
- **Category:** Docs
- **Location:** `/home/user/purplesploit/QUICKSTART.md:99`
- **Description:** Line 99 reads "PurpleSploit v6.0.0 includes an enhanced dropdown auto-completion menu." The current release is 6.9.1. This stale version reference was not updated during any of the documented fixes.
- **Impact:** LOW cosmetic inconsistency in user documentation.
- **Recommendation:** Update the version reference at QUICKSTART.md:99 to refer to the current version or remove the specific version number entirely.
- **Confidence:** High

---

### F-S-028: `DISCLAIMER.md` Uses Its Own Versioning Scheme (`Version: 3.3`) Unrelated to Package Versioning

- **Severity:** LOW
- **Category:** Docs
- **Location:** `/home/user/purplesploit/docs/DISCLAIMER.md:167`
- **Description:** The DISCLAIMER footer reads `*Version: 3.3*` and `*Last Updated: 2025-11-08*`. This version number has no documented relationship to the package version scheme (6.x). Users and auditors cannot determine whether the current DISCLAIMER reflects the legal terms for package version 6.9.1.
- **Impact:** LOW documentation inconsistency; legal disclaimer currency is unclear.
- **Recommendation:** Adopt the package version numbering for DISCLAIMER.md or add a note explaining the separate versioning. Update the "Last Updated" date when content changes.
- **Confidence:** High

---

### F-S-029: `ARCHITECTURE.md` Security Considerations Claim "Input Validation Before Shell Execution" — Factually Incorrect

- **Severity:** LOW
- **Category:** Docs
- **Location:** `/home/user/purplesploit/docs/ARCHITECTURE.md:539`
- **Description:** The "Security Considerations / Tool Execution" section at line 539 states "Input validation before shell execution." Pre-recon confirmed that `api/server.py` runs `subprocess.run(..., shell=True)` on caller-supplied strings at lines 491 and 520 with no allowlist or sanitization. The documentation states a security control the implementation does not provide.
- **Impact:** This inaccurate claim could lead security reviewers to consider the attack surface mitigated. LOW as a Scope finding — the underlying code issue is CRITICAL and will be reported in Phase 2. Noted here because the documentation actively misleads.
- **Recommendation:** Update ARCHITECTURE.md:539 to accurately state that input validation for shell execution is a known gap. Reference the relevant Phase 2 findings when available.
- **Confidence:** High

---

### F-S-030: `ARCHITECTURE.md` Listed as Newly Created in Documentation Audit but Version Shows `6.8.1` at Publication

- **Severity:** LOW
- **Category:** Docs
- **Location:** `/home/user/purplesploit/docs/ARCHITECTURE.md:3`
- **Description:** DOCUMENTATION_AUDIT-23JAN2026.md lists ARCHITECTURE.md as a newly created document (Section "New Documentation Created"). The version header shows `6.8.1` rather than the current `6.9.1`. This is the same staleness captured in F-S-004 and F-S-028 but the file-level manifestation.
- **Impact:** LOW — subsumed by F-S-004. Noted separately for completeness.
- **Recommendation:** Update ARCHITECTURE.md:3 to `6.9.1` as part of the version-string normalization recommended in F-S-004.
- **Confidence:** High

---

### F-S-031: `docs/DISCLAIMER.md` Responsible Disclosure Section Lacks Any Contact Mechanism

- **Severity:** LOW
- **Category:** Legal
- **Location:** `/home/user/purplesploit/docs/DISCLAIMER.md:102–108`
- **Description:** The "Responsible Disclosure" section advises users to report vulnerabilities responsibly and follow coordinated disclosure practices, but provides no email address, URL, or other contact mechanism for reporting vulnerabilities in PurpleSploit itself. Mentioning responsible disclosure without a contact point renders the guidance actionless.
- **Impact:** LOW in isolation (HIGH manifestation is F-S-005 re: missing SECURITY.md); noted here as a documentation-level deficiency.
- **Recommendation:** Add a contact URL or email to DISCLAIMER.md lines 102–108, pointing to the SECURITY.md to be created per F-S-005.
- **Confidence:** High

---

### F-S-032: `QUICKSTART.md` References `./purplesploit-python` Launcher Without Explaining Its Function

- **Severity:** LOW
- **Category:** Docs
- **Location:** `/home/user/purplesploit/QUICKSTART.md:34`
- **Description:** QUICKSTART.md line 34 instructs users to run `./purplesploit-python` as an alternative launcher. The file exists at the repository root, but there is no documentation of what it does, whether it handles Python path setup, or when to prefer it over `python3 -m purplesploit.main`.
- **Impact:** LOW usability issue; users may be unsure which launch method to use.
- **Recommendation:** Add a brief inline note explaining the purpose of `purplesploit-python` and when to use it (e.g., "Sets up Python path for development use without `pip install`").
- **Confidence:** Medium

---

### F-S-033: `ARCHITECTURE.md` Integration Configuration Example References Hard-Coded Webhook URL Pattern

- **Severity:** LOW
- **Category:** Docs
- **Location:** `/home/user/purplesploit/docs/ARCHITECTURE.md:456`
- **Description:** The "Integration Configuration" YAML example at line 456 shows `webhook_url: "https://hooks.slack.com/..."` inline in what appears to be a framework config block. While clearly an example, this pattern may encourage users to commit actual webhook URLs to their config files (a credential-leakage risk). No note warns against hard-coding secrets.
- **Impact:** LOW in isolation; the SSRF and secrets-in-config risks for integrations are addressed in Phase 2. Noted here as a documentation-level guidance gap.
- **Recommendation:** Add a comment to the integration configuration example in ARCHITECTURE.md warning that webhook URLs must be sourced from environment variables (`os.environ["SLACK_WEBHOOK_URL"]`) rather than committed to config files.
- **Confidence:** Medium

---

*End of Phase 1 Scope Review Findings*
