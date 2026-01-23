# Test Fix Plan - Phase 2: Mock Logic Updates

**Date:** 23 January 2026
**Status:** PARTIALLY COMPLETE

**Reviewer:** critagent
**Review Result:** APPROVE WITH MODIFICATIONS
**Modifications Incorporated:** Recategorized failures by actual error type, split Category 4

---

## Execution Results

### Progress Summary

| Metric | Before Phase 2 | After Phase 2 | Change |
|--------|----------------|---------------|--------|
| Errors | 0 | 0 | No change |
| Failures | 73 | 54 | -19 (26% fixed) |
| Passing | 3,552 | 3,571 | +19 |
| Total Issues | 73 | 54 | -19 |

**Total since start of test fix effort:**
| Metric | Original | Current | Change |
|--------|----------|---------|--------|
| Errors | 93 | 0 | -93 (100% fixed) |
| Failures | 112 | 54 | -58 (52% fixed) |
| Passing | 3,464 | 3,571 | +107 |
| Total Issues | 205 | 54 | -151 (74% fixed) |

### Tests Fixed in Phase 2

**test_commands_advanced.py (19 tests fixed):**
- 12 FindingsCommand tests (dict → object attributes)
- 6 WorkflowCommand tests (internal manager pre-assignment)
- 7 PluginCommand tests (correct method names + proper mock structure)
- Partial: Auto, Graph, Spray tests still failing

### Changes Applied

1. **Added helper function `create_mock_finding()`** for creating properly-structured Finding mock objects

2. **Fixed FindingsManager method names:**
   - `get_finding()` → `get()`
   - `update_status()` → `transition_status()`

3. **Fixed mock return structures:**
   - Findings: Added `.severity`, `.status`, `.cvss_score`, `.target` attributes
   - Workflows: Added `.status.value`, `.steps`, `.tags` attributes
   - Plugins: Added `.manifest.category.value`, `.manifest.description` attributes

4. **Fixed input mocking:**
   - Several tests used `interactive.get_input()` but implementation uses `input()`
   - Added `patch('builtins.input')` where needed

### Remaining Failures (54 tests)

The remaining failures fall into these categories:

1. **Session manager tests (18 tests)** - `test_commands_shell.py`, `test_commands_interactive.py`
   - Need to pre-assign `_session_manager`

2. **Webserver tests (8 tests)** - uvicorn inline import issue
   - Need to use `sys.modules` patching

3. **Export/Extended tests (15 tests)** - Various issues
   - JSON serialization, stdin capture, KeyError issues

4. **Graph/Auto/Spray tests (7 tests)** - Internal manager issues
   - Need to pre-assign `_attack_graph`, `_auto_pipeline`, `_spray_engine`

5. **Database migration test (1 test)** - Schema conflict

6. **Benchmark tests (44 errors)** - Require `pytest-benchmark` package

## Overview

This plan addresses the remaining 73 test failures that were NOT caused by patch location issues (fixed in Phase 1). These failures are caused by:

1. **Mock return type mismatches** - Tests return dictionaries but code expects objects with attributes
2. **Internal session manager creation** - Tests mock `framework.session_manager` but code creates `_session_manager` internally
3. **Inline import patching** - Tests patch at wrong location for imports inside functions (uvicorn, etc.)
4. **Mock method expectations** - Tests expect methods to be called on mocked objects that are bypassed

---

## Failure Categories (Revised After Verification)

### Actual Failure Breakdown by Error Type:

| Error Type | Count | Root Cause |
|------------|-------|------------|
| `AttributeError: 'dict' object has no attribute X` | 1 | Mock returns dict, code uses `.attribute` |
| `KeyError: 'by_status'` / `KeyError: X` | 3 | Mock return structure missing keys |
| `AssertionError: Expected 'X' to be called` | 45+ | Internal manager creation bypasses mock |
| `AttributeError: module has no attribute 'uvicorn'` | 8 | Inline import patching |
| `TypeError: write() argument must be str` | 2 | Mock JSON data issues |
| `sqlite3.OperationalError` | 1 | Database migration test |

---

### Category 1: Dictionary vs Object Mock Returns (1 test)

**Affected Files:**
- `tests/unit/ui/test_commands_advanced.py` (most failures)

**Root Cause:** Tests return dictionaries but implementation iterates with attribute access:

```python
# Test returns:
mock_manager.list_findings.return_value = [
    {"id": "1", "title": "SQL Injection", "severity": "high"}
]

# But code uses:
for finding in findings:
    finding.severity  # AttributeError: 'dict' has no attribute 'severity'
    finding.id
    finding.title
```

**Fix Strategy:** Create proper mock objects with attributes:

```python
# FIXED:
mock_finding = MagicMock()
mock_finding.id = "1"
mock_finding.title = "SQL Injection"
mock_finding.severity = Severity.HIGH
mock_finding.cvss_score = 8.5
mock_finding.status = FindingStatus.OPEN
mock_finding.target = "192.168.1.1"
mock_manager.list_findings.return_value = [mock_finding]
```

**Tests Affected:**
- `test_findings_list_with_findings`
- `test_findings_show`
- `test_findings_show_not_found`
- `test_findings_add`
- `test_findings_update`
- `test_findings_evidence`
- `test_findings_stats`
- `test_findings_clear`
- `test_workflow_list`
- `test_workflow_templates`
- `test_workflow_create`
- `test_workflow_run`
- `test_workflow_delete`
- `test_plugin_list`
- `test_plugin_search`
- `test_plugin_install`
- `test_plugin_uninstall`
- `test_plugin_enable`
- `test_plugin_disable`
- `test_auto_with_target`
- `test_graph_stats`
- `test_graph_export_json`
- `test_graph_export_dot`
- `test_spray_generate_passwords`
- `test_report_missing_dependencies`

---

### Category 2: Internal Session Manager Creation (18 tests)

**Affected Files:**
- `tests/unit/ui/test_commands_shell.py`
- `tests/unit/ui/test_commands_interactive.py`

**Root Cause:** Tests mock `framework.session_manager` but implementation creates its own `_session_manager`:

```python
# In cmd_sessions():
if not hasattr(self, '_session_manager') or self._session_manager is None:
    self._session_manager = create_session_manager(self.framework)  # Creates new manager
manager = self._session_manager  # Uses internal manager, not framework.session_manager
```

**Fix Strategy:** Patch `create_session_manager` to return the mock, OR pre-set `_session_manager`:

```python
# Option 1: Patch the factory function
with patch('purplesploit.core.session_manager.create_session_manager') as mock_create:
    mock_manager = MagicMock()
    mock_create.return_value = mock_manager
    mock_manager.list_sessions.return_value = []

    result = command_handler.cmd_sessions(["list"])
    mock_manager.list_sessions.assert_called_once()

# Option 2: Pre-set the internal attribute (simpler)
command_handler._session_manager = mock_framework.session_manager
result = command_handler.cmd_sessions(["list"])
mock_framework.session_manager.list_sessions.assert_called_once()
```

**Tests Affected:**
- `test_sessions_list_empty`
- `test_sessions_kill`
- `test_sessions_info`
- `test_sessions_upgrade`
- `test_sessions_default_to_list`
- `test_interact_with_session_id`
- `test_interact_select_from_list`
- `test_module_select_with_modules`
- `test_module_select_cancelled`
- `test_module_list`
- `test_go_with_module`
- `test_target_add_interactive`
- `test_creds_add_interactive`
- `test_creds_select_interactive`
- `test_target_select_interactive`
- `test_sessions_export_custom_file`
- `test_sessions_export_error`
- `test_sessions_export_default`

---

### Category 3: Inline Import Patching (10 tests)

**Affected Files:**
- `tests/unit/ui/test_commands_shell.py`

**Root Cause:** Tests try to patch `purplesploit.ui.commands.uvicorn` but uvicorn is imported inside `cmd_webserver()`:

```python
# In cmd_webserver():
try:
    import uvicorn  # Import happens INSIDE method
    import fastapi
except ImportError as e:
```

**Fix Strategy:** Patch at the actual import location:

```python
# WRONG:
with patch('purplesploit.ui.commands.uvicorn'):  # Module doesn't have uvicorn at top level

# CORRECT:
with patch.dict('sys.modules', {'uvicorn': MagicMock(), 'fastapi': MagicMock()}):
    # OR
with patch('builtins.__import__', side_effect=mock_import):
```

**Tests Affected:**
- `test_webserver_start`
- `test_webserver_start_with_custom_port`
- `test_webserver_start_missing_dependencies`
- `test_webserver_start_failed`
- `test_webserver_default_to_start`
- `test_webserver_start_with_host`
- `test_webserver_lifecycle`
- `test_webserver_port_in_use`

---

### Category 4: Export/Import Tests (10 tests)

**Affected Files:**
- `tests/unit/ui/test_commands_export.py`
- `tests/unit/ui/test_commands_extended.py`

**Root Cause:** Mix of mock return type issues and method signature mismatches.

**Tests Affected:**
- `test_hosts_sudo`
- `test_graph_export_json_to_stdout`
- `test_graph_export_cytoscape`
- `test_parse_nmap_xml_success`
- `test_parse_invalid_xml`
- `test_graph_export_write_error`
- `test_parse_malformed_xml`
- `test_graph_export_formats[cytoscape-.json]`
- `test_run_with_module`
- `test_run_module_exception`
- `test_targets_remove`
- `test_creds_remove`
- `test_stats_detailed`
- `test_stats_export`
- `test_stats_session_info`
- `test_clear_console`
- `test_services_add_invalid_port`
- `test_wordlists_add_nonexistent_file`
- `test_exploit_alias`

---

### Category 5: Database Migration Test (1 test)

**Affected Files:**
- `tests/unit/core/test_database.py`

**Root Cause:** Test creates a pre-migration schema, but the Database constructor calls `_create_tables()` which requires the `status` column.

**Test Affected:**
- `test_migration_adds_status_column`

**Fix Strategy:** Use a different approach to test migrations that doesn't conflict with auto-table creation.

---

## Implementation Plan

### Step 1: Fix Category 1 - Dictionary vs Object Returns

Create helper function for mock finding objects:

```python
def create_mock_finding(id="1", title="Test", severity="high", **kwargs):
    """Create a mock Finding object with proper attributes."""
    from purplesploit.core.findings import Severity, FindingStatus

    finding = MagicMock()
    finding.id = id
    finding.title = title
    finding.severity = Severity[severity.upper()] if isinstance(severity, str) else severity
    finding.status = kwargs.get('status', FindingStatus.OPEN)
    finding.cvss_score = kwargs.get('cvss_score', 7.5)
    finding.target = kwargs.get('target', '192.168.1.1')
    finding.description = kwargs.get('description', 'Test description')
    return finding
```

Apply to all affected tests in `test_commands_advanced.py`.

### Step 2: Fix Category 2 - Session Manager

Add pre-assignment of `_session_manager` before calling session-related commands:

```python
def test_sessions_list_empty(self, command_handler, mock_framework):
    """Test listing sessions when none exist."""
    mock_framework.session_manager.list_sessions.return_value = []

    # Pre-assign the session manager
    command_handler._session_manager = mock_framework.session_manager

    result = command_handler.cmd_sessions(["list"])

    assert result is True
    mock_framework.session_manager.list_sessions.assert_called_once()
```

Apply to all affected tests in `test_commands_shell.py` and `test_commands_interactive.py`.

### Step 3: Fix Category 3 - Webserver Tests

Replace uvicorn patching with sys.modules patching:

```python
def test_webserver_start(self, command_handler):
    """Test starting web server."""
    mock_uvicorn = MagicMock()
    mock_fastapi = MagicMock()

    with patch.dict('sys.modules', {'uvicorn': mock_uvicorn, 'fastapi': mock_fastapi}):
        with patch('multiprocessing.Process') as mock_process:
            mock_proc = MagicMock()
            mock_proc.is_alive.return_value = True
            mock_process.return_value = mock_proc

            result = command_handler.cmd_webserver(["start"])

            assert result is True
```

### Step 4: Fix Category 4 - Export Tests

Review and fix each test individually based on the specific failure mode.

### Step 5: Fix Category 5 - Database Migration

Modify test to avoid auto-table creation conflict:

```python
def test_migration_adds_status_column(self, tmp_path):
    """Test that migration properly adds status column."""
    db_path = tmp_path / "test.db"

    # Create a minimal database with old schema (without status column)
    import sqlite3
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS targets (
            id TEXT PRIMARY KEY,
            address TEXT NOT NULL
            -- status column intentionally missing
        )
    """)
    conn.commit()
    conn.close()

    # Test migration detection separately from Database initialization
    # ... migration test logic
```

---

## Files to Modify

| File | Category | Tests to Fix |
|------|----------|--------------|
| `tests/unit/ui/test_commands_advanced.py` | 1 | 25 tests |
| `tests/unit/ui/test_commands_shell.py` | 2, 3 | 18 tests |
| `tests/unit/ui/test_commands_interactive.py` | 2 | 7 tests |
| `tests/unit/ui/test_commands_export.py` | 4 | 13 tests |
| `tests/unit/ui/test_commands_extended.py` | 4 | 12 tests |
| `tests/unit/core/test_database.py` | 5 | 1 test |

---

## Validation Commands

After each fix category:

```bash
# Category 1 validation
pytest tests/unit/ui/test_commands_advanced.py -v --tb=short

# Category 2 validation
pytest tests/unit/ui/test_commands_shell.py tests/unit/ui/test_commands_interactive.py -v --tb=short

# Category 3 validation
pytest tests/unit/ui/test_commands_shell.py::TestWebserverCommand -v --tb=short

# Full validation
pytest tests/unit/ui/ tests/unit/core/test_database.py -v --tb=short
```

---

## Risk Assessment

**Medium Risk:** These changes modify test logic, not production code. However:

- Changes must preserve test intent (what behavior is being verified)
- Mock objects must accurately reflect real object interfaces
- Pre-assigning internal attributes could mask real initialization bugs

**Mitigation:**
- Review each change to ensure test intent is preserved
- Use real enum values where possible (Severity, FindingStatus)
- Document any tests that need interface updates if production code changes
