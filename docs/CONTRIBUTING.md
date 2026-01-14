# Contributing to PurpleSploit

Thank you for your interest in contributing to PurpleSploit! This document provides guidelines for contributing to the project.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Module Development](#module-development)
- [Code Style](#code-style)
- [Testing](#testing)
- [Pull Request Guidelines](#pull-request-guidelines)

## Getting Started

### Reporting Issues

If you find a bug or have a feature request:

1. Check existing issues to avoid duplicates
2. Create a new issue with a clear title and description
3. Include steps to reproduce (for bugs)
4. Specify your environment (OS, Python version, etc.)

### Code Contributions

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature-name`)
3. Make your changes following our code style guidelines
4. Test your changes thoroughly
5. Commit with clear, descriptive messages
6. Push and create a Pull Request

## Development Setup

### Prerequisites

```bash
# System dependencies
sudo apt install python3 python3-pip python3-venv fzf ripgrep

# Clone the repository
git clone https://github.com/jeremylaratro/purplesploit.git
cd purplesploit/python
```

### Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install with development dependencies
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=purplesploit --cov-report=html

# Run specific test file
pytest tests/unit/core/test_session.py -v
```

## Module Development

PurpleSploit uses a Python module system. All modules inherit from `BaseModule` or `ExternalToolModule`.

### Module Structure

```
purplesploit/modules/
├── web/               # Web application testing
│   ├── feroxbuster.py
│   ├── sqlmap.py
│   └── wfuzz.py
├── network/           # Network protocol testing
│   ├── nxc_smb.py
│   ├── nxc_ldap.py
│   └── nxc_ssh.py
├── recon/             # Reconnaissance
│   ├── nmap.py
│   └── nuclei.py
├── impacket/          # Impacket tools
│   ├── secretsdump.py
│   └── psexec.py
├── osint/             # OSINT modules
├── ai/                # AI-assisted modules
└── deploy/            # Deployment modules
```

### Creating a Basic Module

```python
"""
Example Module for PurpleSploit

Brief description of what the module does.
"""

from purplesploit.core.module import BaseModule
from typing import Dict, Any, List


class ExampleModule(BaseModule):
    """
    Example module demonstrating module structure.
    """

    def __init__(self, framework):
        super().__init__(framework)

    @property
    def name(self) -> str:
        return "Example Module"

    @property
    def description(self) -> str:
        return "Brief description of module functionality"

    @property
    def author(self) -> str:
        return "Your Name"

    @property
    def category(self) -> str:
        # Valid: web, network, recon, impacket, osint, ai, deploy, c2
        return "recon"

    def run(self) -> Dict[str, Any]:
        """
        Main execution method.

        Returns:
            Dictionary with 'success' key and results
        """
        return {"success": True, "output": "Module completed"}
```

### Creating an External Tool Module

For modules that wrap external tools like nmap, feroxbuster, etc.:

```python
from purplesploit.core.module import ExternalToolModule
from typing import Dict, Any, List


class ToolWrapper(ExternalToolModule):
    """
    Wrapper for external-tool command.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "external-tool"

    @property
    def name(self) -> str:
        return "External Tool Wrapper"

    @property
    def description(self) -> str:
        return "Wrapper for external-tool functionality"

    @property
    def author(self) -> str:
        return "Your Name"

    @property
    def category(self) -> str:
        return "web"

    @property
    def parameter_profiles(self) -> List[str]:
        """Use predefined parameter profiles."""
        return ["web_scan_basic"]  # Or other profiles

    def get_operations(self) -> List[Dict[str, Any]]:
        """
        Define available operations.

        Returns:
            List of operation dictionaries
        """
        return [
            {
                "name": "Basic Scan",
                "description": "Basic scan operation",
                "handler": "op_basic_scan"
            },
            {
                "name": "Deep Scan",
                "description": "Deep scan with more options",
                "handler": "op_deep_scan"
            },
        ]

    def op_basic_scan(self) -> Dict[str, Any]:
        """Basic scan operation handler."""
        target = self.get_option("RHOST") or self.get_option("URL")
        if not target:
            return {"success": False, "error": "Target required"}

        cmd = f"{self.tool_name} --target {target}"
        return self.execute_command(cmd)

    def op_deep_scan(self) -> Dict[str, Any]:
        """Deep scan operation handler."""
        target = self.get_option("RHOST") or self.get_option("URL")
        cmd = f"{self.tool_name} --target {target} --deep"
        return self.execute_command(cmd)

    def run(self) -> Dict[str, Any]:
        """Default run uses basic scan."""
        return self.op_basic_scan()
```

### Parameter Profiles

Use parameter profiles for consistent options across modules:

```python
@property
def parameter_profiles(self) -> List[str]:
    return ["network_basic"]  # Provides RHOST, RPORT, TIMEOUT
```

Available profiles:
- `network_basic` - Basic network parameters (RHOST, RPORT)
- `auth_password` - Password authentication (USERNAME, PASSWORD, DOMAIN)
- `auth_hash` - Hash authentication (USERNAME, HASH, HASH_TYPE)
- `web_scan_basic` - Basic web scanning (URL, THREADS)
- `web_scan_advanced` - Advanced web scanning (URL, WORDLIST, EXTENSIONS)

### Module Options

Access and set module options:

```python
# Get option value
target = self.get_option("RHOST")

# Set option value
self.set_option("RHOST", "192.168.1.100")

# Check if required options are set
if not self.check_required():
    return {"success": False, "error": "Required options not set"}
```

### Logging

Use the built-in logging:

```python
self.log("Starting scan...", "info")
self.log("Found vulnerability!", "success")
self.log("Error occurred", "error")
self.log("This might be risky", "warning")
```

### Command Execution

For external tools:

```python
# Synchronous execution
result = self.execute_command("nmap -sV target", timeout=300)

# Background execution
result = self.execute_command("long-running-scan", background=True)
```

## Code Style

### Python Guidelines

- Follow PEP 8 style guide
- Use type hints for function parameters and returns
- Use docstrings for classes and public methods
- Maximum line length: 100 characters

### Example

```python
def process_results(self, raw_output: str) -> Dict[str, Any]:
    """
    Process raw command output into structured results.

    Args:
        raw_output: Raw string output from command execution

    Returns:
        Dictionary containing parsed results with keys:
        - success: Boolean indicating success
        - data: Parsed data structure
        - errors: Any error messages
    """
    results = {"success": True, "data": [], "errors": []}
    # Processing logic...
    return results
```

### Naming Conventions

- Classes: `CamelCase` (e.g., `NmapModule`)
- Functions/methods: `snake_case` (e.g., `process_results`)
- Constants: `UPPER_SNAKE_CASE` (e.g., `DEFAULT_TIMEOUT`)
- Private methods: `_leading_underscore` (e.g., `_parse_output`)

## Testing

### Test Structure

```
tests/
├── unit/
│   ├── core/           # Core functionality tests
│   ├── modules/        # Module-specific tests
│   ├── ui/             # UI component tests
│   └── reporting/      # Report generation tests
└── integration/        # Integration tests
```

### Writing Tests

```python
import pytest
from purplesploit.modules.web.feroxbuster import FeroxbusterModule


class TestFeroxbusterModule:
    """Tests for Feroxbuster module."""

    @pytest.fixture
    def module(self, mock_framework):
        """Create module instance for testing."""
        return FeroxbusterModule(mock_framework)

    def test_module_name(self, module):
        """Test module has correct name."""
        assert module.name == "Feroxbuster"

    def test_module_category(self, module):
        """Test module has correct category."""
        assert module.category == "web"

    def test_operations_exist(self, module):
        """Test module defines operations."""
        ops = module.get_operations()
        assert len(ops) > 0
        assert all("name" in op for op in ops)
```

### Running Specific Tests

```bash
# Run module tests
pytest tests/unit/modules/ -v

# Run with print output
pytest tests/unit/modules/test_feroxbuster.py -v -s

# Run tests matching pattern
pytest -k "test_nmap" -v
```

## Pull Request Guidelines

### PR Title Format

```
[Type] Brief description

Types: feat, fix, docs, refactor, test, chore
```

Examples:
- `[feat] Add DNS enumeration module`
- `[fix] Correct nmap parsing for IPv6`
- `[docs] Update module development guide`

### PR Description Template

```markdown
## Summary
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Code refactoring
- [ ] Test improvements

## Testing
Describe testing performed

## Checklist
- [ ] Code follows project style
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] All tests pass locally
```

### Before Submitting

1. Run the full test suite: `pytest`
2. Check code style: `flake8 purplesploit/`
3. Run type checking: `mypy purplesploit/`
4. Update documentation if needed

## Areas for Contribution

### High Priority
- Tests for uncovered modules (core/findings.py, core/workflow.py)
- API documentation for FastAPI endpoints
- Integration tests for module workflows

### Medium Priority
- New tool integrations (additional OSINT modules, web scanners)
- Performance improvements in parsing
- Enhanced error handling

### Nice to Have
- Additional AI-assisted features
- Report template improvements
- Dashboard enhancements

## Security

**IMPORTANT**: Only contribute features for authorized security testing. Do not submit:
- Malicious code or exploits designed to harm
- Credential harvesting tools without authorization context
- Features that bypass security controls maliciously

All contributions must be for defensive security purposes.

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (CC BY-NC-SA 4.0).

---

**Thank you for contributing to PurpleSploit!**
