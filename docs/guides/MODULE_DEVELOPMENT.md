# Module Development Guide

This guide provides comprehensive instructions for developing custom modules in PurpleSploit. Learn how to create, test, and integrate new security testing modules into the framework.

## Table of Contents

- [Overview](#overview)
- [Module Architecture](#module-architecture)
- [Quick Start Tutorial](#quick-start-tutorial)
- [Module Lifecycle](#module-lifecycle)
- [Required Metadata](#required-metadata)
- [Module Types](#module-types)
- [Parameter System](#parameter-system)
- [Operations System](#operations-system)
- [Testing Your Module](#testing-your-module)
- [Best Practices](#best-practices)
- [Common Pitfalls](#common-pitfalls)
- [Example Modules](#example-modules)

## Overview

PurpleSploit modules are Python classes that inherit from `BaseModule` or one of its subclasses. Modules integrate external security tools, implement custom testing logic, or automate complex workflows.

### Module Capabilities

- Execute external security tools (nmap, feroxbuster, NetExec, etc.)
- Integrate with framework services (targets, credentials, findings)
- Parse and store results in the database
- Support background execution for long-running scans
- Provide multiple operations for different use cases
- Use parameter profiles for consistent configuration

## Module Architecture

### Base Classes Hierarchy

```
BaseModule (abstract)
├── ExternalToolModule (for wrapping CLI tools)
├── ImpacketModule (for Impacket-based tools)
└── Custom modules (for pure Python implementations)
```

### Core Components

1. **Metadata Properties**: Name, description, author, category
2. **Options/Parameters**: Configuration values for the module
3. **Operations**: Different execution modes or sub-commands
4. **Run Method**: Main execution logic
5. **Parsing Logic**: Extract and structure results

## Quick Start Tutorial

### Step 1: Create Module File

Create a new Python file in the appropriate category directory:

```bash
touch python/purplesploit/modules/<category>/<tool_name>.py
```

Categories:
- `recon/` - Reconnaissance and scanning
- `web/` - Web application testing
- `network/` - Network protocol testing (NXC)
- `impacket/` - Impacket tools
- `smb/` - SMB-specific operations
- `ad/` - Active Directory testing
- `osint/` - Open-source intelligence
- `ai/` - AI-powered automation

### Step 2: Basic Module Template

```python
"""
<Tool Name> Module

Brief description of what this module does.
"""

from purplesploit.core.module import ExternalToolModule
from typing import Dict, Any, List


class MyToolModule(ExternalToolModule):
    """
    <Tool Name> - One-line description.

    Detailed description of the module's capabilities,
    what it tests, and when to use it.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "mytool"  # Binary name to check

    @property
    def name(self) -> str:
        return "My Tool"

    @property
    def description(self) -> str:
        return "Brief description for module list"

    @property
    def author(self) -> str:
        return "Your Name"

    @property
    def category(self) -> str:
        return "recon"  # Choose appropriate category

    def _init_options(self):
        """Initialize module-specific options."""
        super()._init_options()

        self.options.update({
            "RHOST": {
                "value": None,
                "required": True,
                "description": "Target host IP address",
                "default": None
            },
            "CUSTOM_OPTION": {
                "value": "default_value",
                "required": False,
                "description": "Custom option description",
                "default": "default_value"
            },
        })

    def build_command(self) -> str:
        """
        Build the command to execute.

        Returns:
            Command string to execute
        """
        rhost = self.get_option("RHOST")
        custom = self.get_option("CUSTOM_OPTION")

        cmd = f"{self.tool_name} {rhost}"

        if custom:
            cmd += f" --option {custom}"

        return cmd

    def run(self) -> Dict[str, Any]:
        """
        Execute the module.

        Returns:
            Dictionary with results
        """
        # ExternalToolModule.run() handles:
        # - Tool installation check
        # - Command building via build_command()
        # - Command execution
        # - Output parsing via parse_output()
        return super().run()

    def parse_output(self, output: str) -> Dict[str, Any]:
        """
        Parse command output.

        Args:
            output: Command stdout

        Returns:
            Parsed results dictionary
        """
        results = {
            "findings": [],
            "summary": {}
        }

        # Parse the output
        for line in output.split('\n'):
            # Your parsing logic here
            pass

        return results
```

### Step 3: Register Module

Modules are auto-discovered if placed in the correct directory. Ensure your module file follows the naming convention and is in:

```
python/purplesploit/modules/<category>/<module_name>.py
```

## Module Lifecycle

### 1. Initialization Phase

```python
def __init__(self, framework):
    super().__init__(framework)
    self.tool_name = "tool"
    # Set up any instance variables
    self._init_options()  # Called automatically
    self._init_parameters()  # Called automatically
```

**What happens:**
- Framework reference stored
- Options initialized (legacy) or parameters loaded (new)
- Default values loaded from database
- Module registered with framework

### 2. Configuration Phase

```python
# User sets options
module.set_option("RHOST", "192.168.1.100")
module.set_option("THREADS", 50)

# Validate options
if not module.validate_options():
    # Missing required options
    pass
```

**Available during configuration:**
- `self.get_option(name)` - Get option value
- `self.set_option(name, value)` - Set option value
- `self.validate_options()` - Check required options
- `self.show_options()` - Display all options

### 3. Execution Phase

```python
# User runs the module
result = module.run()
```

**Execution flow for ExternalToolModule:**

1. `run()` called
2. Check if tool installed: `check_tool_installed()`
3. Validate required options: `validate_options()`
4. Build command: `build_command()`
5. Execute command: `execute_command()`
6. Parse output: `parse_output()`
7. Store results in database (optional)
8. Return result dictionary

### 4. Post-Execution Phase

```python
# Results available
if result.get("success"):
    print(result.get("output"))
    parsed = result.get("parsed")
```

**Result dictionary structure:**

```python
{
    "success": True,
    "command": "nmap -p- 192.168.1.100",
    "output": "raw command output",
    "parsed": {
        "findings": [...],
        "summary": {...}
    },
    "exit_code": 0,
    "execution_time": 45.2
}
```

## Required Metadata

### Essential Properties

All modules MUST implement these abstract properties:

```python
@property
def name(self) -> str:
    """Display name shown in module list"""
    return "Nmap Scan"

@property
def description(self) -> str:
    """Brief description (1-2 sentences)"""
    return "Network scanning and service detection"

@property
def author(self) -> str:
    """Module author or team"""
    return "PurpleSploit Team"

@property
def category(self) -> str:
    """Module category for organization"""
    return "recon"
```

### Optional Metadata

```python
@property
def required_options(self) -> List[str]:
    """List of option keys that must be set"""
    return ["RHOST", "WORDLIST"]

@property
def parameter_profiles(self) -> List[str]:
    """Parameter profiles to use (new system)"""
    return ["web_scan_basic", "web_scan_advanced"]

@property
def custom_parameters(self) -> List[str]:
    """Additional parameters beyond profiles"""
    return ["CUSTOM_PARAM"]
```

## Module Types

### 1. External Tool Module (Recommended)

Wraps external CLI tools (nmap, feroxbuster, etc.)

```python
from purplesploit.core.module import ExternalToolModule

class MyToolModule(ExternalToolModule):
    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "mytool"  # Tool to check/install

    def build_command(self) -> str:
        """Build command string"""
        return f"{self.tool_name} {self.get_option('RHOST')}"

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse tool output"""
        return {"findings": []}
```

**Features:**
- Automatic tool installation checking
- Background execution support
- Command execution with timeout
- Output capture and parsing

### 2. Impacket Module

For Impacket-based protocol tools:

```python
from purplesploit.core.module import ImpacketModule

class SecretsDumpModule(ImpacketModule):
    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "secretsdump"

    def build_command(self) -> str:
        """Build impacket command"""
        return self._build_impacket_command(
            tool_name="secretsdump.py",
            target=self.get_option("RHOST"),
            extra_args="-just-dc"
        )
```

### 3. Pure Python Module

Custom implementations without external tools:

```python
from purplesploit.core.module import BaseModule

class CustomModule(BaseModule):
    def run(self) -> Dict[str, Any]:
        """Custom execution logic"""
        target = self.get_option("RHOST")

        # Your custom Python logic
        results = self.do_custom_scan(target)

        return {
            "success": True,
            "results": results
        }

    def do_custom_scan(self, target):
        """Implement your logic"""
        pass
```

## Parameter System

### Modern Parameter Profiles (Recommended)

Use parameter profiles for consistent configuration:

```python
@property
def parameter_profiles(self) -> List[str]:
    """Use existing parameter profiles"""
    return ["web_scan_advanced"]  # Loads URL, WORDLIST, THREADS, etc.
```

**Available profiles:**
- `web_scan_basic` - URL, basic web options
- `web_scan_advanced` - Extended web scanning options
- `smb_auth` - SMB authentication (USERNAME, PASSWORD, DOMAIN)
- `smb_shares` - SMB share operations
- `ldap_query` - LDAP query parameters

### Legacy Options System

For backward compatibility or custom options:

```python
def _init_options(self):
    super()._init_options()

    self.options.update({
        "RHOST": {
            "value": None,              # Current value
            "required": True,           # Required before run?
            "description": "Target IP", # Help text
            "default": None             # Default value
        },
        "THREADS": {
            "value": 10,
            "required": False,
            "description": "Number of threads",
            "default": 10
        }
    })
```

### Accessing Options

```python
# Get option value
target = self.get_option("RHOST")
threads = self.get_option("THREADS")

# Set option value
self.set_option("RHOST", "192.168.1.100")

# Check if option is set
if self.get_option("RHOST"):
    # Option has a value
    pass
```

## Operations System

Operations allow multiple execution modes within a single module.

### Defining Operations

```python
def get_operations(self) -> List[Dict[str, Any]]:
    """Define available operations"""
    return [
        {
            "name": "Basic Scan",
            "description": "Standard scan with default options",
            "handler": "op_basic_scan",
            "subcategory": "standard"
        },
        {
            "name": "Aggressive Scan",
            "description": "Aggressive scan with OS detection",
            "handler": "op_aggressive_scan",
            "subcategory": "advanced"
        },
        {
            "name": "Stealth Scan",
            "description": "Slow stealth scan",
            "handler": "op_stealth_scan",
            "subcategory": "advanced"
        }
    ]
```

### Operation Handlers

```python
def op_basic_scan(self) -> Dict[str, Any]:
    """Execute basic scan operation"""
    # Set operation-specific options
    self.set_option("SCAN_TYPE", "sCV")
    self.set_option("TIMING", "4")

    # Run with these settings
    return self.run()

def op_aggressive_scan(self) -> Dict[str, Any]:
    """Execute aggressive scan operation"""
    self.set_option("SCAN_TYPE", "sCV")
    self.set_option("OS_DETECTION", "true")
    self.set_option("TIMING", "4")

    return self.run()
```

### Using Operations

```python
# List operations
operations = module.get_operations()

# Run specific operation
result = module.op_basic_scan()

# Or via framework
framework.run_module_operation(module, "op_aggressive_scan")
```

## Testing Your Module

### 1. Unit Testing

Create test file: `python/tests/unit/modules/<category>/test_<module>.py`

```python
import pytest
from purplesploit.modules.recon.mytool import MyToolModule


class TestMyToolModule:
    """Test suite for MyTool module"""

    @pytest.fixture
    def module(self, mock_framework):
        """Create module instance"""
        return MyToolModule(mock_framework)

    def test_module_metadata(self, module):
        """Test module metadata"""
        assert module.name == "My Tool"
        assert module.category == "recon"
        assert module.author

    def test_options_initialization(self, module):
        """Test options are initialized"""
        assert "RHOST" in module.options
        assert module.options["RHOST"]["required"] is True

    def test_build_command(self, module):
        """Test command building"""
        module.set_option("RHOST", "192.168.1.100")
        cmd = module.build_command()

        assert "mytool" in cmd
        assert "192.168.1.100" in cmd

    def test_parse_output(self, module):
        """Test output parsing"""
        sample_output = """
        Finding: Port 80 open
        Finding: Port 443 open
        """

        parsed = module.parse_output(sample_output)

        assert "findings" in parsed
        assert len(parsed["findings"]) >= 0

    def test_operations_defined(self, module):
        """Test operations are defined"""
        ops = module.get_operations()
        assert len(ops) > 0
        assert all("name" in op for op in ops)
```

### 2. Integration Testing

Test with actual framework instance:

```python
def test_module_execution(framework):
    """Test actual module execution"""
    module = framework.load_module("recon/mytool")
    module.set_option("RHOST", "192.168.1.100")

    result = module.run()

    assert result.get("success") is not None
    if result["success"]:
        assert "output" in result
```

### 3. Manual Testing

```bash
# Start PurpleSploit
python -m purplesploit.ui.cli

# Load your module
use recon/mytool

# Show options
options

# Set options
set RHOST 192.168.1.100

# Run module
run

# Test operations
operations
run op_basic_scan
```

## Best Practices

### Code Organization

1. **Keep modules focused** - One tool/purpose per module
2. **Use clear naming** - Module name should match tool name
3. **Document thoroughly** - Docstrings for all methods
4. **Handle errors gracefully** - Return error dicts, don't crash

### Command Building

```python
def build_command(self) -> str:
    """Always quote paths and values containing spaces"""
    rhost = self.get_option("RHOST")
    wordlist = self.get_option("WORDLIST")

    # Good: Quoted paths
    cmd = f"mytool -t {rhost} -w '{wordlist}'"

    # Bad: Unquoted paths will break
    # cmd = f"mytool -t {rhost} -w {wordlist}"

    return cmd
```

### Output Parsing

```python
def parse_output(self, output: str) -> Dict[str, Any]:
    """Parse robustly with error handling"""
    results = {"findings": [], "errors": []}

    try:
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue

            # Parse with regex or string methods
            if "Found:" in line:
                results["findings"].append(line)

    except Exception as e:
        self.log(f"Parse error: {e}", "error")
        results["errors"].append(str(e))

    return results
```

### Database Integration

```python
def run(self) -> Dict[str, Any]:
    """Store results in database"""
    result = super().run()

    if result.get("success"):
        parsed = result.get("parsed", {})

        # Store findings
        for finding in parsed.get("findings", []):
            self.framework.database.add_finding(
                target=self.get_option("RHOST"),
                title=finding.get("title"),
                severity=finding.get("severity"),
                description=finding.get("description")
            )

        # Store scan results
        self.framework.database.save_scan_results(
            scan_name=self.name,
            target=self.get_option("RHOST"),
            results=parsed
        )

    return result
```

### Background Execution

```python
def run(self) -> Dict[str, Any]:
    """Support background execution"""
    background = self.get_option("BACKGROUND")
    run_in_bg = background and str(background).lower() == "true"

    if run_in_bg:
        cmd = self.build_command()
        result = self.execute_command(cmd, background=True)

        if result.get("success"):
            result["message"] = f"Scan started (PID: {result.get('pid')})"

        return result
    else:
        return super().run()
```

## Common Pitfalls

### 1. Not Checking Tool Installation

```python
# Bad: Assumes tool is installed
def run(self):
    cmd = self.build_command()
    return self.execute_command(cmd)

# Good: Check tool first
def run(self):
    if not self.check_tool_installed():
        return {
            "success": False,
            "error": f"{self.tool_name} not installed"
        }
    return super().run()
```

### 2. Hardcoded Paths

```python
# Bad: Hardcoded paths
cmd = "/usr/bin/nmap -p- target"

# Good: Use tool_name
cmd = f"{self.tool_name} -p- {target}"
```

### 3. Not Validating Options

```python
# Bad: Assuming options are set
rhost = self.get_option("RHOST")
cmd = f"tool {rhost}"  # rhost might be None!

# Good: Validate first
if not self.validate_options():
    return {"success": False, "error": "Missing required options"}

rhost = self.get_option("RHOST")
cmd = f"tool {rhost}"
```

### 4. Ignoring Background Mode

```python
# Bad: Forces foreground execution
def run(self):
    cmd = self.build_command()
    return self.execute_command(cmd, timeout=600)

# Good: Respect BACKGROUND option
def run(self):
    background = self.get_option("BACKGROUND")
    bg = background and str(background).lower() == "true"

    cmd = self.build_command()
    return self.execute_command(cmd, background=bg, timeout=600)
```

### 5. Poor Error Handling

```python
# Bad: Crashes on error
def parse_output(self, output):
    data = json.loads(output)  # Might fail!
    return data["results"]

# Good: Handle errors gracefully
def parse_output(self, output):
    try:
        data = json.loads(output)
        return data.get("results", {})
    except json.JSONDecodeError as e:
        self.log(f"Failed to parse JSON: {e}", "error")
        return {"error": "Invalid JSON output"}
```

## Example Modules

### Example 1: Simple Port Scanner

```python
"""
Simple Port Scanner Module
Demonstrates basic external tool wrapping.
"""

from purplesploit.core.module import ExternalToolModule
from typing import Dict, Any


class SimplePortScanModule(ExternalToolModule):
    """Simple port scanner using netcat"""

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "nc"

    @property
    def name(self) -> str:
        return "Simple Port Scan"

    @property
    def description(self) -> str:
        return "Basic port scanning with netcat"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "recon"

    def _init_options(self):
        super()._init_options()
        self.options.update({
            "RHOST": {
                "value": None,
                "required": True,
                "description": "Target IP",
                "default": None
            },
            "PORTS": {
                "value": "1-1000",
                "required": False,
                "description": "Port range",
                "default": "1-1000"
            }
        })

    def build_command(self) -> str:
        rhost = self.get_option("RHOST")
        ports = self.get_option("PORTS")
        return f"nc -zv {rhost} {ports}"

    def parse_output(self, output: str) -> Dict[str, Any]:
        open_ports = []

        for line in output.split('\n'):
            if "open" in line.lower():
                # Extract port number
                parts = line.split()
                for part in parts:
                    if part.isdigit():
                        open_ports.append(int(part))
                        break

        return {
            "open_ports": open_ports,
            "count": len(open_ports)
        }
```

### Example 2: Web Module with Operations

```python
"""
Web Directory Scanner
Demonstrates operations and parameter profiles.
"""

from purplesploit.core.module import ExternalToolModule
from typing import Dict, Any, List


class WebDirScanModule(ExternalToolModule):
    """Web directory scanner with multiple scan types"""

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "dirb"

    @property
    def name(self) -> str:
        return "Web Directory Scanner"

    @property
    def description(self) -> str:
        return "Directory bruteforcing with multiple modes"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "web"

    @property
    def parameter_profiles(self) -> List[str]:
        return ["web_scan_basic"]

    def get_operations(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "Quick Scan",
                "description": "Fast scan with common paths",
                "handler": "op_quick_scan"
            },
            {
                "name": "Deep Scan",
                "description": "Comprehensive scan",
                "handler": "op_deep_scan"
            }
        ]

    def op_quick_scan(self) -> Dict[str, Any]:
        """Quick scan with small wordlist"""
        self.set_option("WORDLIST", "/usr/share/dirb/wordlists/common.txt")
        return self.run()

    def op_deep_scan(self) -> Dict[str, Any]:
        """Deep scan with large wordlist"""
        self.set_option("WORDLIST", "/usr/share/dirb/wordlists/big.txt")
        return self.run()

    def build_command(self) -> str:
        url = self.get_option("URL")
        wordlist = self.get_option("WORDLIST")
        return f"dirb {url} {wordlist} -S"

    def parse_output(self, output: str) -> Dict[str, Any]:
        found = []

        for line in output.split('\n'):
            if line.startswith("+ "):
                found.append(line[2:].strip())

        return {
            "found_paths": found,
            "count": len(found)
        }
```

### Example 3: Custom Python Module

```python
"""
Custom Hash Cracker
Demonstrates pure Python implementation.
"""

from purplesploit.core.module import BaseModule
from typing import Dict, Any
import hashlib


class HashCrackerModule(BaseModule):
    """Simple hash cracker using wordlist"""

    @property
    def name(self) -> str:
        return "Hash Cracker"

    @property
    def description(self) -> str:
        return "Crack hashes using wordlist"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "post"

    def _init_options(self):
        self.options = {
            "HASH": {
                "value": None,
                "required": True,
                "description": "Hash to crack",
                "default": None
            },
            "WORDLIST": {
                "value": "/usr/share/wordlists/rockyou.txt",
                "required": True,
                "description": "Wordlist path",
                "default": "/usr/share/wordlists/rockyou.txt"
            },
            "HASH_TYPE": {
                "value": "md5",
                "required": False,
                "description": "Hash type (md5, sha1, sha256)",
                "default": "md5"
            }
        }

    def run(self) -> Dict[str, Any]:
        target_hash = self.get_option("HASH")
        wordlist = self.get_option("WORDLIST")
        hash_type = self.get_option("HASH_TYPE")

        try:
            with open(wordlist, 'r', encoding='latin-1') as f:
                for i, line in enumerate(f):
                    password = line.strip()

                    # Compute hash
                    if hash_type == "md5":
                        computed = hashlib.md5(password.encode()).hexdigest()
                    elif hash_type == "sha1":
                        computed = hashlib.sha1(password.encode()).hexdigest()
                    elif hash_type == "sha256":
                        computed = hashlib.sha256(password.encode()).hexdigest()
                    else:
                        return {"success": False, "error": "Invalid hash type"}

                    # Check match
                    if computed == target_hash:
                        return {
                            "success": True,
                            "password": password,
                            "attempts": i + 1
                        }

                    # Progress every 10000 attempts
                    if (i + 1) % 10000 == 0:
                        self.log(f"Tried {i + 1} passwords...", "info")

            return {
                "success": False,
                "error": "Password not found in wordlist"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
```

## Conclusion

Module development in PurpleSploit is straightforward and flexible. Follow this guide to create robust, well-integrated security testing modules. For additional examples, review existing modules in the `python/purplesploit/modules/` directory.

### Key Takeaways

1. Inherit from appropriate base class (ExternalToolModule recommended)
2. Implement all required abstract properties
3. Use parameter profiles for consistent configuration
4. Provide operations for different execution modes
5. Parse and store results properly
6. Handle errors gracefully
7. Support background execution
8. Write comprehensive tests

### Getting Help

- Review existing modules for patterns
- Check framework documentation at `docs/API.md`
- Ask questions in the project repository
- Contribute your modules back to the project

Happy module development!
