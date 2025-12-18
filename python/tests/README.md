# PurpleSploit Test Suite

This directory contains the comprehensive test suite for PurpleSploit.

## Test Statistics

| Category | Tests | Coverage |
|----------|-------|----------|
| Core Module Tests | 161 | framework: 74%, session: 94%, module: 87% |
| Integration Tests | 102 | Full workflow coverage |
| External Tool Module Tests | 155 | wfuzz: 77%, feroxbuster: 64%, nxc_smb: new |
| Error Handling Tests | 64 | Core and module error paths |
| Parser Tests | 65 | nmap, impacket output parsing |
| Database Tests | 45 | core/database.py CRUD operations |
| **Total** | **1403** | |

## Directory Structure

```
tests/
├── conftest.py           # Shared fixtures
├── README.md             # This file
├── unit/                 # Unit tests
│   ├── core/             # Core component tests
│   │   ├── test_framework.py
│   │   ├── test_session.py
│   │   ├── test_module.py
│   │   ├── test_database.py
│   │   └── test_error_handling.py
│   ├── modules/          # Module-specific tests
│   │   ├── test_wfuzz_extended.py
│   │   ├── test_feroxbuster_extended.py
│   │   ├── test_nxc_smb.py
│   │   └── test_error_scenarios.py
│   ├── parsers/          # Output parser tests
│   │   ├── test_nmap_parser.py
│   │   └── test_impacket_parsers.py
│   └── ui/               # UI component tests
│       └── test_interactive.py
└── integration/          # Integration tests
    ├── test_workflow.py
    ├── test_persistence.py
    └── test_module_chaining.py
```

## Running Tests

### Run all tests
```bash
python -m pytest tests/ -v
```

### Run with coverage
```bash
python -m pytest tests/ --cov=purplesploit --cov-report=html
```

### Run specific test category
```bash
# Core tests only
python -m pytest tests/unit/core/ -v

# Module tests only
python -m pytest tests/unit/modules/ -v

# Integration tests only
python -m pytest tests/integration/ -v
```

### Run single test file
```bash
python -m pytest tests/unit/core/test_framework.py -v
```

### Run specific test
```bash
python -m pytest tests/unit/core/test_framework.py::TestFrameworkInit::test_framework_initialization -v
```

## Writing Tests

### Fixture Pattern

Use the shared fixtures in `conftest.py` for consistency:

```python
@pytest.fixture
def mock_framework_minimal():
    """Create a minimal mock framework for testing."""
    framework = MagicMock()
    framework.session = MagicMock()
    framework.database = MagicMock()
    framework.log = MagicMock()
    return framework

@pytest.fixture
def framework(tmp_path):
    """Create a real framework for integration tests."""
    from purplesploit.core.framework import Framework
    db_path = str(tmp_path / "test.db")
    modules_path = Path(__file__).parent / "purplesploit" / "modules"
    
    with patch('purplesploit.core.framework.db_manager'):
        fw = Framework(modules_path=str(modules_path), db_path=db_path)
    yield fw
    fw.cleanup()
```

### Mock Pattern for External Tools

```python
def test_tool_execution(self, module):
    """Test tool execution with mocked subprocess."""
    with patch.object(module, 'execute_command') as mock_exec:
        mock_exec.return_value = {
            "success": True,
            "output": "sample output",
            "return_code": 0
        }
        result = module.run()
        assert result["success"] is True
```

### Test Class Structure

Organize tests by functionality:

```python
class TestModuleOperations:
    """Tests for module CRUD operations."""
    
    def test_add_module(self, framework):
        """Test adding a module."""
        pass
    
    def test_remove_module(self, framework):
        """Test removing a module."""
        pass
```

### Error Handling Tests

Test both success and failure paths:

```python
def test_handle_timeout(self, module):
    """Test timeout error handling."""
    with patch('subprocess.run') as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="test", timeout=30)
        result = module.execute_command("slow_command", timeout=30)
        assert result["success"] is False
        assert "timeout" in result.get("error", "").lower()
```

### Database Test Pattern

Use tmp_path fixture for isolated database tests:

```python
@pytest.fixture
def database(tmp_path):
    """Create a test database."""
    from purplesploit.core.database import Database
    db_path = str(tmp_path / "test.db")
    db = Database(db_path)
    yield db
    db.close()
```

## Test Categories

### Unit Tests
Test individual functions and classes in isolation.
- Use mocks for external dependencies
- Focus on single functionality
- Fast execution

### Integration Tests
Test component interactions.
- Real framework instances
- Multi-step workflows
- State persistence

### Error Handling Tests
Test failure scenarios.
- Network timeouts
- Permission errors
- Invalid input
- Tool not found

### Parser Tests
Test output parsing.
- Valid output
- Malformed output
- Edge cases

## Fixtures Reference

| Fixture | Description |
|---------|-------------|
| `mock_framework_minimal` | Minimal MagicMock framework |
| `framework` | Real Framework instance |
| `database` | Isolated Database instance |
| `tmp_path` | Temporary directory (pytest built-in) |
| `wfuzz_module` | WfuzzModule instance |
| `feroxbuster_module` | FeroxbusterModule instance |
| `nxc_module` | NXCSMBModule instance |

## Coverage Goals

- Core modules: 75%+
- External tool modules: 70%+
- Overall: 60%+

## Notes

- Tests should be independent and not rely on execution order
- Use `pytest.mark.slow` for tests that take >1 second
- Clean up any resources in fixture teardown
- Avoid testing third-party libraries directly
