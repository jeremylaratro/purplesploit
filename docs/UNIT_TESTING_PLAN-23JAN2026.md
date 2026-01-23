# PurpleSploit Comprehensive Unit Testing Plan

**Target Coverage:** 98%
**Date:** 23 January 2026
**Current Coverage:** 70% (18,993 statements, 5,680 missed)

---

## Executive Summary

This document outlines the testing strategy to achieve 98% code coverage for the PurpleSploit framework. Based on automated analysis of the codebase, the plan identifies coverage gaps, prioritizes testing efforts, and provides actionable implementation steps.

### Current Test Health
| Metric | Value |
|--------|-------|
| Total Tests | 3,692 |
| Passing | 3,464 |
| Failed | 112 (fixture issues) |
| Errors | 93 (setup issues) |
| Skipped | 23 |
| Source Files | 85 Python modules |
| Existing Test Files | 81 |

---

## Coverage Analysis by Priority

### Priority 1: Critical Coverage Gaps (0-25%)

These modules have minimal or no test coverage and represent the highest priority:

| File | Current | Target | Statements Missed | Effort |
|------|---------|--------|-------------------|--------|
| `purplesploit/main.py` | 0% | 90%+ | 35/35 | 1-2 hrs |
| `integrations/github_issues.py` | 19% | 75%+ | 149/184 | 3-4 hrs |
| `integrations/manager.py` | 23% | 75%+ | 129/168 | 2-3 hrs |
| `modules/ai/ai_automation.py` | 20% | 70%+ | 148/184 | 3-4 hrs |
| `modules/c2/ligolo_pivot.py` | 17% | 70%+ | 175/210 | 4-5 hrs |
| `modules/web/wpscan.py` | 18% | 70%+ | 215/262 | 3-4 hrs |
| `modules/recon/dns.py` | 23% | 75%+ | 124/161 | 2-3 hrs |
| `modules/recon/nuclei.py` | 24% | 75%+ | 146/191 | 3-4 hrs |
| `modules/utility/module_creator.py` | 23% | 75%+ | 110/142 | 2-3 hrs |
| `reporting/xlsx.py` | 14% | 80%+ | 171/198 | 2-3 hrs |

### Priority 2: Medium Coverage Gaps (26-60%)

| File | Current | Target | Statements Missed | Effort |
|------|---------|--------|-------------------|--------|
| `ui/commands.py` | 39% | 85%+ | 2047/3336 | 8-10 hrs |
| `plugins/manager.py` | 54% | 85%+ | 114/248 | 3-4 hrs |
| `plugins/repository.py` | 33% | 80%+ | 120/178 | 2-3 hrs |
| `modules/ai/methodology.py` | 42% | 75%+ | 119/204 | 3-4 hrs |
| `modules/smb/vulnerability.py` | 42% | 75%+ | 46/79 | 2-3 hrs |
| `modules/network/nxc_mssql.py` | 48% | 80%+ | 36/69 | 1-2 hrs |
| `modules/network/nxc_rdp.py` | 50% | 80%+ | 30/60 | 1-2 hrs |
| `modules/network/nxc_ldap.py` | 51% | 80%+ | 38/77 | 2-3 hrs |
| `modules/smb/execution.py` | 51% | 75%+ | 32/65 | 2-3 hrs |
| `modules/smb/credentials.py` | 54% | 75%+ | 28/61 | 1-2 hrs |
| `modules/network/nxc_winrm.py` | 54% | 80%+ | 28/61 | 1-2 hrs |
| `modules/smb/authentication.py` | 58% | 80%+ | 27/65 | 1-2 hrs |
| `modules/impacket/wmiexec.py` | 58% | 80%+ | 20/48 | 1-2 hrs |
| `modules/impacket/kerberoast.py` | 58% | 80%+ | 24/57 | 1-2 hrs |
| `modules/impacket/asreproast.py` | 59% | 80%+ | 25/61 | 1-2 hrs |

### Priority 3: Moderate Coverage Gaps (61-80%)

| File | Current | Target | Statements Missed | Effort |
|------|---------|--------|-------------------|--------|
| `modules/impacket/psexec.py` | 62% | 90%+ | 18/48 | 1 hr |
| `modules/impacket/smbclient.py` | 63% | 90%+ | 19/52 | 1 hr |
| `modules/web/feroxbuster.py` | 65% | 85%+ | 72/203 | 2-3 hrs |
| `modules/osint/shodan.py` | 67% | 85%+ | 89/266 | 2-3 hrs |
| `modules/smb/enumeration.py` | 69% | 85%+ | 20/65 | 1-2 hrs |
| `modules/network/nxc_smb.py` | 71% | 90%+ | 65/226 | 2-3 hrs |
| `modules/network/nxc_ssh.py` | 73% | 90%+ | 15/55 | 1 hr |
| `models/database.py` | 74% | 90%+ | 68/257 | 2-3 hrs |
| `modules/recon/nmap.py` | 77% | 90%+ | 63/279 | 2-3 hrs |
| `ui/command_mixins/context_commands.py` | 77% | 90%+ | 133/569 | 3-4 hrs |
| `ui/command_mixins/module_commands.py` | 79% | 90%+ | 87/420 | 2-3 hrs |
| `core/framework.py` | 81% | 95%+ | 39/202 | 2-3 hrs |
| `core/database.py` | 82% | 95%+ | 54/302 | 2-3 hrs |

---

## Test Files Required

### New Test Files to Create

```
tests/unit/test_main.py
tests/unit/integrations/test_github_issues.py
tests/unit/integrations/test_manager.py
tests/unit/modules/ai/test_ai_automation.py
tests/unit/modules/c2/test_ligolo_pivot.py
tests/unit/modules/web/test_wpscan.py
tests/unit/modules/recon/test_dns.py
tests/unit/modules/recon/test_nuclei.py
tests/unit/modules/utility/test_module_creator.py
tests/unit/modules/smb/test_vulnerability.py
tests/unit/modules/smb/test_execution.py
tests/unit/modules/smb/test_credentials.py
tests/unit/modules/smb/test_authentication.py
tests/unit/modules/network/test_nxc_mssql.py
tests/unit/modules/network/test_nxc_rdp.py
tests/unit/modules/network/test_nxc_ldap.py
tests/unit/modules/network/test_nxc_winrm.py
tests/unit/modules/impacket/test_wmiexec.py
tests/unit/modules/impacket/test_kerberoast.py
tests/unit/modules/impacket/test_asreproast.py
tests/unit/modules/impacket/test_psexec.py
tests/unit/modules/impacket/test_smbclient.py
```

---

## Existing Test Failures to Fix

### 1. UI Command Test Failures (112 failures)

**Location:** `tests/unit/ui/test_commands_*.py`

**Root Cause:** Mock fixtures don't match current implementation

**Example Error:**
```
AssertionError: Expected 'list_sessions' to have been called once. Called 0 times.
```

**Fix Strategy:** Update mock fixtures to match current `session_manager` implementation.

### 2. Integration Test Fixture Errors (93 errors)

**Location:** `tests/integration/test_workflow.py`

**Root Cause:** Patching non-existent attributes

**Example Error:**
```
AttributeError: <module 'purplesploit.core.framework'> does not have the attribute 'db_manager'
```

**Fix:** Update fixtures in `tests/integration/test_workflow.py` line 37 to remove invalid patches.

---

## Mock/Stub Strategies

### 1. External Tool Execution

```python
from unittest.mock import patch, MagicMock

@patch('subprocess.run')
def test_external_tool_execution(mock_run):
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout=b'Tool output',
        stderr=b''
    )
    # Test module execution
```

### 2. HTTP/API Calls

```python
@patch('requests.get')
@patch('requests.post')
def test_api_integration(mock_post, mock_get):
    mock_get.return_value = MagicMock(status_code=200, json=lambda: {"data": []})
    mock_post.return_value = MagicMock(status_code=201)
```

### 3. File System Operations

```python
def test_file_operations(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    # Test file-based operations
```

### 4. Optional Dependencies (openpyxl, etc.)

```python
def test_missing_optional_dependency():
    with patch.dict('sys.modules', {'openpyxl': None}):
        # Test ImportError handling
```

---

## Test Frameworks and Tools

### Currently Installed
- **pytest** 9.0.2
- **pytest-cov** 7.0.0
- **pytest-mock** 3.15.1
- **pytest-asyncio** 1.3.0

### Recommended Additions
```bash
pip install pytest-xdist  # Parallel test execution
pip install responses     # HTTP mocking
```

---

## Implementation Schedule

### Week 1: Foundation and Quick Wins
1. Fix 93 fixture errors in integration/benchmark tests
2. Fix 112 failing unit tests
3. Add tests for `main.py` (0% to 90%+)
4. Add tests for nmap variant modules
5. Infrastructure improvements (fixtures, test data)

### Week 2: High-Impact Modules
1. `ui/commands.py` - highest LOC impact (39% to 85%+)
2. `plugins/manager.py` and `plugins/repository.py`
3. Impacket modules (psexec, wmiexec, smbclient)
4. SMB modules (authentication, credentials, execution)

### Week 3: Module Coverage
1. Network modules (nxc_*)
2. Recon modules (dns, nuclei, nmap)
3. Integration modules (github_issues, manager)
4. AI modules (ai_automation, methodology)

### Week 4: Polish and Verification
1. Reporting modules (xlsx)
2. C2 modules (ligolo_pivot)
3. Web modules (wpscan, feroxbuster)
4. Final coverage audit
5. Documentation of any permanently uncovered code

---

## Effort Estimation Summary

| Priority | Coverage Range | Files | Estimated Hours |
|----------|----------------|-------|-----------------|
| 1 | 0-25% | 10 | 25-35 hours |
| 2 | 26-60% | 15 | 25-35 hours |
| 3 | 61-80% | 16 | 20-30 hours |
| Fix Failures | - | - | 8-12 hours |
| Infrastructure | - | - | 4-6 hours |

**Total Estimated Effort:** 82-118 hours

---

## Code Refactoring Recommendations

### 1. Split `ui/commands.py` (5,696 lines)

This monolithic file should be split for better testability:
- `commands/module_commands.py`
- `commands/context_commands.py`
- `commands/utility_commands.py`
- `commands/integration_commands.py`
- `commands/shell_commands.py`

### 2. Extract Common Module Patterns

Create base classes for common module types:
- `NmapVariantModule` - shared nmap behavior
- `NetExecModule` - shared nxc behavior
- `ImpacketModule` - shared Impacket behavior

---

## Running Tests

### Full Test Suite
```bash
cd /home/jay/Documents/cyber/dev/purplesploit/python
pytest tests/ -v
```

### With Coverage Report
```bash
pytest --cov=purplesploit --cov-report=html --cov-report=term-missing
```

### Parallel Execution (after installing pytest-xdist)
```bash
pytest tests/ -n auto
```

### Specific Module Tests
```bash
pytest tests/unit/modules/network/ -v
pytest tests/unit/core/ -v
pytest tests/integration/ -v
```

---

## Success Criteria

1. **All tests pass:** `pytest tests/ -v` returns exit code 0
2. **Coverage threshold:** `pytest --cov=purplesploit --cov-fail-under=98`
3. **No test pollution:** Tests pass in any order
4. **Fast execution:** Full suite completes in under 5 minutes

---

## Progress Tracking

| Milestone | Status | Coverage |
|-----------|--------|----------|
| Baseline Assessment | Complete | 70% |
| Fix Existing Failures | Pending | - |
| Priority 1 Tests | Pending | Target: 80% |
| Priority 2 Tests | Pending | Target: 90% |
| Priority 3 Tests | Pending | Target: 95% |
| Final Polish | Pending | Target: 98% |

---

## Appendix: Test Commands Reference

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/unit/core/test_session.py -v

# Run tests matching pattern
pytest -k "test_nmap" -v

# Run with coverage
pytest --cov=purplesploit --cov-report=term-missing

# Generate HTML coverage report
pytest --cov=purplesploit --cov-report=html

# Run in parallel (requires pytest-xdist)
pytest -n auto

# Run only fast tests (exclude slow integration tests)
pytest -m "not slow"

# Run with print output visible
pytest -v -s

# Run and stop at first failure
pytest -x

# Run last failed tests only
pytest --lf
```
