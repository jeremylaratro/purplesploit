# PurpleSploit Development Context

## Project Overview
PurpleSploit is a Python-based penetration testing framework (v6.7.0) with CLI and web interfaces. It wraps external security tools (nmap, wfuzz, netexec, impacket, etc.) in a unified module system with persistent session state.

## Architecture

### Core Components
- **`core/module.py`**: `BaseModule` (abstract) and `ExternalToolModule` (for tool wrappers)
- **`core/session.py`**: `Session` with `TargetManager`, `CredentialManager`, `ServiceManager`, `WordlistManager`
- **`core/parameters.py`**: Centralized `Parameter` validation with `ParameterProfile` groupings
- **`core/database.py`**: SQLite persistence for targets, credentials, services, findings, module history

### Module Pattern
```python
class MyModule(ExternalToolModule):
    tool_name = "mytool"

    @property
    def name(self) -> str: return "My Module"
    @property
    def category(self) -> str: return "recon"  # web|network|recon|impacket|c2|post|ai

    @property
    def parameter_profiles(self) -> List[str]:
        return ["target_basic", "auth_basic"]  # Use existing profiles

    def build_command(self) -> str:
        return f"mytool --target {self.get_option('RHOST')}"

    def run(self) -> Dict[str, Any]:
        return self.execute_command(self.build_command())
```

## Development Guidelines

### Testing (CRITICAL)
```bash
cd python && pytest tests/ -v              # Run all tests
pytest tests/unit/ -v                       # Unit tests only
pytest tests/integration/ -v                # Integration tests
pytest --cov=purplesploit --cov-report=html # Coverage report
```

**Test structure:**
- `tests/unit/core/` - Core module tests
- `tests/unit/modules/` - Tool module tests
- `tests/integration/` - End-to-end workflow tests
- `tests/conftest.py` - Shared fixtures (`mock_framework`, `test_database`, etc.)

**Write tests for:**
1. All new modules (command building, output parsing)
2. All new parameters/profiles
3. All database operations
4. Session manager operations

### Code Quality
- Run `black .` for formatting
- Run `flake8` for linting
- Run `mypy` for type checking
- Type hints on all public methods

### Modularity Principles
1. **Single Responsibility**: Each module wraps ONE tool or performs ONE function
2. **Use Parameter Profiles**: Don't duplicate parameter definitions; use/extend `ProfileRegistry`
3. **Inherit Appropriately**: Use `ExternalToolModule` for tool wrappers, `BaseModule` for custom logic
4. **Context Aware**: Use `auto_set_from_context()` pattern for session integration
5. **Parse Output**: Implement `parse_output()` or `parse_xml_output()` for structured results

### Version Control
```bash
git checkout -b feature/my-feature      # Feature branches
git commit -m "type: concise message"   # Conventional commits
# Types: feat|fix|refactor|test|docs|chore
```

**Before committing:**
1. Run full test suite: `pytest tests/ -v`
2. Check for regressions in core functionality
3. Update tests if changing existing behavior
4. Add tests for new functionality

### Adding New Modules

1. Create module file in appropriate category: `modules/{category}/{name}.py`
2. Inherit from `ExternalToolModule` (for external tools) or `BaseModule`
3. Implement required properties: `name`, `description`, `author`, `category`
4. Define `parameter_profiles` or custom options
5. Implement `build_command()` and optionally `parse_output()`
6. Create test file: `tests/unit/modules/test_{name}.py`
7. Test command building with various option combinations
8. Test output parsing with sample outputs

### Key Files Reference
| File | Purpose |
|------|---------|
| `core/module.py:30` | BaseModule definition |
| `core/module.py:485` | ExternalToolModule definition |
| `core/parameters.py:102` | ParameterRegistry (all params) |
| `core/parameters.py:434` | ProfileRegistry (param groups) |
| `core/session.py:14` | Session class |
| `core/database.py:18` | Database class |

### Common Patterns

**Adding a parameter:**
```python
# In parameters.py ParameterRegistry._register_all_parameters()
self.register(Parameter(
    name="MY_PARAM",
    description="Description",
    param_type=ParameterType.STRING,
    required=False
))
```

**Adding a profile:**
```python
# In parameters.py ProfileRegistry._register_default_profiles()
self.register(ParameterProfile(
    name="my_profile",
    description="My profile description",
    parameters=["RHOST", "MY_PARAM", "USERNAME"]
))
```

**Module with operations/submenu:**
```python
def get_operations(self) -> List[Dict[str, Any]]:
    return [
        {"name": "Op 1", "description": "...", "handler": "op_one", "subcategory": "basic"},
        {"name": "Op 2", "description": "...", "handler": "op_two", "subcategory": "advanced"},
    ]

def op_one(self) -> Dict[str, Any]:
    # Set specific options for this operation
    self.set_option("SCAN_TYPE", "fast")
    return self.run()
```

## Quick Commands
```bash
# Development
cd python && pip install -e ".[dev]"    # Install with dev deps
pytest tests/ -v --tb=short             # Run tests
pytest tests/ -k "test_parameter"       # Run specific tests
black . && flake8                       # Format and lint

# Running
python -m purplesploit.main             # CLI
python scripts/start-web-portal.py      # Web UI
```
