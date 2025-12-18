# PurpleSploit Test Coverage Improvement Plan

## Current State
- **Total Tests**: 1403 (100% passing)
- **Overall Coverage**: 50%
- **Core Coverage**: 75-98% (excellent)
- **Module Coverage**: 9-99% (varies widely)

---

## 5-Step Improvement Plan

### Step 1: Fill Critical Coverage Gaps (0-25% Coverage)
**Target Files:**
| File | Current Coverage | Target |
|------|-----------------|--------|
| `api/server.py` | 0% | 60%+ |
| `modules/deploy/script.py` | 9% | 50%+ |
| `modules/recon/auto_enum.py` | 12% | 50%+ |
| `modules/deploy/c2.py` | 15% | 50%+ |
| `modules/deploy/ligolo.py` | 16% | 50%+ |
| `modules/c2/ligolo_pivot.py` | 17% | 50%+ |
| `ui/commands.py` | 18% | 40%+ |
| `modules/ai/ai_automation.py` | 20% | 40%+ |
| `modules/utility/module_creator.py` | 23% | 50%+ |

**Approach:**
- Mock external dependencies (FastAPI, subprocess, AI APIs)
- Focus on core logic paths and error handling
- Use existing fixture patterns from conftest.py

### Step 2: Execute Full Test Suite
**Tasks:**
- Run `pytest` with coverage reporting
- Identify any failing or flaky tests
- Verify test isolation (no side effects)
- Document baseline metrics

**Commands:**
```bash
cd python && pytest --cov=purplesploit --cov-report=term-missing -v
```

### Step 3: Add Tests for Low-Coverage Modules (25-50%)
**Target Files:**
| File | Current Coverage | Target |
|------|-----------------|--------|
| `modules/smb/shares.py` | 31% | 60%+ |
| `modules/smb/vulnerability.py` | 42% | 60%+ |
| `modules/network/nxc_mssql.py` | 48% | 65%+ |
| `modules/network/nxc_rdp.py` | 50% | 65%+ |
| `modules/network/nxc_ldap.py` | 51% | 65%+ |
| `ui/command_mixins/utility_commands.py` | 50% | 70%+ |

**Approach:**
- Add edge case tests
- Test error handling paths
- Add credential and authentication scenarios
- Test complex enumeration workflows

### Step 4: Add Integration Tests for End-to-End Workflows
**New Integration Tests:**
1. **Full Reconnaissance Pipeline**
   - nmap → auto_enum → service detection → target registration

2. **SMB Attack Chain**
   - SMB enumeration → credential testing → shares access → code execution

3. **Web Application Testing Flow**
   - httpx → feroxbuster → wfuzz → sqlmap

4. **Credential Management Workflow**
   - Credential discovery → storage → reuse across modules

5. **Session Persistence**
   - Full session save/restore with all managers

**Location:** `tests/integration/test_advanced_workflows.py`

### Step 5: Generate Coverage Report & Document Improvements
**Tasks:**
- Generate HTML coverage report
- Compare before/after metrics
- Update IMPLEMENTATION_PLAN.md with results
- Document any remaining gaps
- Create recommendations for future testing

**Commands:**
```bash
pytest --cov=purplesploit --cov-report=html --cov-report=term
```

---

## Success Criteria
- [ ] Overall coverage increased from 50% to 60%+
- [ ] No files with 0% coverage (except entry points)
- [ ] All critical paths have tests
- [ ] All 1403+ tests passing
- [ ] Documentation updated

---

## Priority Order
1. **Critical**: API server, deploy modules (security-critical code)
2. **High**: SMB/NXC modules (core functionality)
3. **Medium**: UI commands (user-facing features)
4. **Lower**: AI automation (optional feature)

---

## Estimated New Tests
- Step 1: ~150-200 new tests
- Step 3: ~100-150 new tests
- Step 4: ~30-50 new integration tests
- **Total**: ~280-400 new tests
