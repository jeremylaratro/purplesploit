# PurpleSploit Test Implementation Plan

## Overview
This plan outlines the systematic approach to improving test coverage across the PurpleSploit codebase. The phases are ordered by priority and dependency.

---

## Phase 1: Core Module Test Coverage
**Target Files:**
- `purplesploit/core/framework.py` (24% → 70%+)
- `purplesploit/core/session.py` (31% → 75%+)
- `purplesploit/core/module.py` (45% → 80%+)

**Test Focus:**
- Framework initialization and module registry
- Session state management (targets, credentials, services)
- Module lifecycle (load, configure, validate, execute)
- Module option handling and validation

**Deliverables:**
- `tests/unit/core/test_framework.py`
- `tests/unit/core/test_session.py`
- `tests/unit/core/test_module.py`

---

## Phase 2: Integration Tests
**Target Workflows:**
- Full workflow: search → use → set options → run
- Target/credential persistence across sessions
- Module chaining scenarios
- Multi-module operations

**Test Focus:**
- End-to-end command execution
- State persistence validation
- Cross-component interactions
- Real-world usage patterns

**Deliverables:**
- `tests/integration/test_workflow.py`
- `tests/integration/test_persistence.py`
- `tests/integration/test_module_chaining.py`

---

## Phase 3: External Tool Module Tests
**Target Files:**
- `purplesploit/modules/web/wfuzz.py` (23% → 70%+)
- `purplesploit/modules/web/feroxbuster.py` (39% → 75%+)
- `purplesploit/modules/network/nxc_smb.py` (32% → 70%+)

**Test Focus:**
- Command building with various option combinations
- Output parsing and result extraction
- Tool availability detection
- Subprocess management

**Deliverables:**
- `tests/unit/modules/test_wfuzz_extended.py`
- `tests/unit/modules/test_feroxbuster_extended.py`
- `tests/unit/modules/test_nxc_smb_extended.py`

---

## Phase 4: Error Handling Tests
**Target Scenarios:**
- Network timeouts during module execution
- Malformed tool output
- Permission errors (file access, execution)
- Missing dependencies/tools
- Invalid user input

**Test Focus:**
- Exception handling paths
- Graceful degradation
- User feedback on errors
- Recovery mechanisms

**Deliverables:**
- `tests/unit/core/test_error_handling.py`
- `tests/unit/modules/test_error_scenarios.py`

---

## Phase 5: Parsers Testing
**Target Files:**
- `purplesploit/parsers/nmap_parser.py` (0% → 80%+)
- `purplesploit/parsers/nxc_parser.py` (0% → 80%+)
- Service detection parsers

**Test Focus:**
- Valid output parsing
- Edge cases (empty output, partial data)
- Malformed input handling
- Data extraction accuracy

**Deliverables:**
- `tests/unit/parsers/test_nmap_parser.py`
- `tests/unit/parsers/test_nxc_parser.py`
- `tests/unit/parsers/test_service_parsers.py`

---

## Phase 6: Database Layer Testing
**Target Files:**
- `purplesploit/models/database.py` (19% → 75%+)
- `purplesploit/core/database.py` (33% → 75%+)

**Test Focus:**
- CRUD operations for all entities
- Query edge cases
- Data integrity constraints
- Migration handling
- Connection management

**Deliverables:**
- `tests/unit/models/test_database.py`
- `tests/unit/core/test_database.py`

---

## Phase 7: Configuration Testing
**Target Files:**
- `purplesploit/core/config.py`

**Test Focus:**
- Config file loading (valid/invalid)
- Default value handling
- Environment variable overrides
- Config validation
- Path resolution

**Deliverables:**
- `tests/unit/core/test_config.py`

---

## Phase 8: Documentation
**Deliverables:**
- Add docstrings to all public functions in tested modules
- Create `tests/README.md` with test patterns and conventions
- Document mock patterns for contributors
- Add inline comments for complex test scenarios

---

## Progress Tracking

| Phase | Status | Tests Added | Coverage Change |
|-------|--------|-------------|-----------------|
| 1     | **Complete** | 161 | framework: 24%→74%, session: 31%→94%, module: 45%→87% |
| 2     | **Complete** | 102 | Integration coverage for workflows, persistence, chaining |
| 3     | **Complete** | 155 | wfuzz: 30%→77%, feroxbuster: 20%→64%, nxc_smb: 0%→new tests |
| 4     | **Complete** | 64 | Error handling for core and module components |
| 5     | **Complete** | 65 | nmap_parser, impacket output parsers |
| 6     | **Complete** | 45 | Database CRUD, thread safety, migrations |
| 7     | **Skipped** | - | No config.py exists in codebase |
| 8     | **Complete** | - | tests/README.md with patterns and conventions |

**Total Tests: 1403 (all passing)**

---

## Success Criteria
- Overall test coverage: 60%+ (from current ~42%)
- Core modules: 75%+ coverage
- All critical paths have tests
- Zero test failures on main branch
- Documentation complete for test patterns

---

## Notes
- Each phase should be completed with passing tests before moving to the next
- Integration tests (Phase 2) may reveal issues that require revisiting Phase 1
- Parser tests (Phase 5) require sample output files for realistic testing
