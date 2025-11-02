# PurpleSploit Framework v2.0 - Full Edition

## Overview

PurpleSploit Framework is a **Metasploit-style pentesting framework** designed for maximum scalability and ease of use. It provides a unified interface for running popular pentesting tools with:

- **Universal variable system** - Set variables once, use everywhere
- **Modular architecture** - Easy to add new tools
- **Workspace management** - Organize targets by engagement
- **Command templating** - Automatic variable substitution
- **Interactive CLI** - Familiar Metasploit-like interface

## Quick Start

### Launch the Framework

```bash
./purplesploit-framework.sh
```

### Basic Workflow

```bash
# 1. Search for a module
purplesploit> search nmap

# 2. Select a module
purplesploit> use recon/nmap/quick_scan

# 3. View module options
purplesploit(recon/nmap/quick_scan)> show options

# 4. Set required variables
purplesploit(recon/nmap/quick_scan)> set RHOST 192.168.1.100

# 5. Run the module
purplesploit(recon/nmap/quick_scan)> run
```

## Core Concepts

### 1. Modules

Modules are self-contained tool configurations stored in `.psm` files. Each module defines:

- Tool to execute
- Required and optional variables
- Command template with variable placeholders
- Module metadata (category, description, author)

**Example module location:**
```
modules/web/feroxbuster/basic_scan.psm
modules/network/nxc/smb/auth_test.psm
modules/recon/nmap/quick_scan.psm
```

### 2. Variables

Variables are the core of the framework's flexibility. Set once, use across multiple modules.

**Standard variables:**
- `RHOST` - Remote host (IP or hostname)
- `RPORT` - Remote port
- `RHOSTS` - Multiple hosts (comma-separated or CIDR)
- `LHOST` - Local host (for callbacks)
- `LPORT` - Local port (for listeners)
- `USERNAME` - Username for authentication
- `PASSWORD` - Password for authentication
- `DOMAIN` - Domain name
- `HASH` - Password hash
- `TARGET_URL` - Web target URL
- `THREADS` - Number of threads
- `WORDLIST` - Wordlist file path
- `OUTPUT_DIR` - Output directory

### 3. Workspaces

Workspaces organize targets and variables by engagement or project.

```bash
# List workspaces
purplesploit> workspace

# Create new workspace
purplesploit> workspace -a client_pentest_2024

# Switch workspace
purplesploit> workspace client_pentest_2024

# Add targets to workspace
purplesploit> targets -a 192.168.1.0/24
purplesploit> targets -a 10.10.10.50
```

## Commands Reference

### Module Commands

| Command | Description |
|---------|-------------|
| `use <module>` | Select a module to use |
| `back` | Deselect current module |
| `search <keyword>` | Search for modules |
| `info [module]` | Show module information |
| `show modules` | List all available modules |
| `show categories` | List module categories |

### Variable Commands

| Command | Description |
|---------|-------------|
| `set <VAR> <value>` | Set a variable |
| `setg <VAR> <value>` | Set a global variable |
| `unset <VAR>` | Unset a variable |
| `show options` | Show current module options |
| `show vars` | Show all variables |

### Execution Commands

| Command | Description |
|---------|-------------|
| `run` | Execute current module |
| `run -y` | Execute without confirmation |
| `run -j` | Execute in background (job) |
| `check` | Preview command without executing |

### Workspace Commands

| Command | Description |
|---------|-------------|
| `workspace` | List all workspaces |
| `workspace <name>` | Switch to workspace |
| `workspace -a <name>` | Create new workspace |
| `workspace -d <name>` | Delete workspace |
| `workspace -i [name]` | Show workspace info |

### Target Commands

| Command | Description |
|---------|-------------|
| `targets` | List targets in workspace |
| `targets -a <target>` | Add target to workspace |
| `targets -r <target>` | Remove target from workspace |
| `targets -i <file>` | Import targets from file |
| `targets -e <file>` | Export targets to file |

### Job Commands

| Command | Description |
|---------|-------------|
| `jobs` | List background jobs |
| `jobs -k <id>` | Kill a background job |

### Other Commands

| Command | Description |
|---------|-------------|
| `status` | Show framework status |
| `help` | Show help |
| `history [count]` | Show command history |
| `history -s <keyword>` | Search command history |
| `clear` | Clear screen |
| `exit` | Exit framework |

## Example Usage Scenarios

### Scenario 1: Web Application Testing

```bash
# Start framework
./purplesploit-framework.sh

# Create workspace for this engagement
purplesploit> workspace -a acme_webapp

# Set target
purplesploit> set TARGET_URL https://acme.example.com

# Run directory discovery
purplesploit> use web/feroxbuster/basic_scan
purplesploit(web/feroxbuster/basic_scan)> run

# Switch to API discovery
purplesploit(web/feroxbuster/basic_scan)> use web/feroxbuster/api_discovery
purplesploit(web/feroxbuster/api_discovery)> run

# Test for SQL injection
purplesploit(web/feroxbuster/api_discovery)> use web/sqlmap/basic_injection
purplesploit(web/sqlmap/basic_injection)> run
```

### Scenario 2: Internal Network Assessment

```bash
# Create workspace
purplesploit> workspace -a internal_pentest

# Import targets from file
purplesploit> targets -i /path/to/targets.txt

# Quick port scan
purplesploit> use recon/nmap/quick_scan
purplesploit(recon/nmap/quick_scan)> set RHOST 192.168.1.100
purplesploit(recon/nmap/quick_scan)> run

# Test SMB authentication
purplesploit(recon/nmap/quick_scan)> use network/nxc/smb/auth_test
purplesploit(network/nxc/smb/auth_test)> set USERNAME administrator
purplesploit(network/nxc/smb/auth_test)> set PASSWORD P@ssw0rd
purplesploit(network/nxc/smb/auth_test)> run

# Enumerate shares
purplesploit(network/nxc/smb/auth_test)> use network/nxc/smb/enum_shares
purplesploit(network/nxc/smb/enum_shares)> run
```

### Scenario 3: Active Directory Assessment

```bash
# Set domain credentials
purplesploit> set DOMAIN corp.local
purplesploit> set USERNAME pentester
purplesploit> set PASSWORD Password123
purplesploit> set RHOST 192.168.1.10

# Enumerate domain via LDAP
purplesploit> use network/nxc/ldap/enum_domain
purplesploit(network/nxc/ldap/enum_domain)> run

# Enumerate domain users via SMB
purplesploit(network/nxc/ldap/enum_domain)> use network/nxc/smb/enum_users
purplesploit(network/nxc/smb/enum_users)> run
```

## Adding Custom Modules

### Module File Format (.psm)

Create a new `.psm` file in the appropriate category directory:

```bash
#!/bin/bash
# Module Description

MODULE_NAME="category/tool/action"
MODULE_CATEGORY="category"
MODULE_DESCRIPTION="Description of what this module does"
MODULE_AUTHOR="Your Name"
MODULE_TOOL="tool_binary_name"

# Required variables (comma-separated)
REQUIRED_VARS="RHOST,USERNAME"

# Optional variables with defaults (format: VAR:default,VAR2:default2)
OPTIONAL_VARS="THREADS:10,TIMEOUT:30"

# Command template with ${VAR} placeholders
COMMAND_TEMPLATE="tool --host \${RHOST} -u \${USERNAME} -t \${THREADS}"
```

### Example: Adding a Custom Nikto Module

**File:** `modules/web/nikto/basic_scan.psm`

```bash
#!/bin/bash
# Nikto Basic Web Scan

MODULE_NAME="web/nikto/basic_scan"
MODULE_CATEGORY="web"
MODULE_DESCRIPTION="Basic Nikto web vulnerability scan"
MODULE_AUTHOR="Custom Module"
MODULE_TOOL="nikto"

REQUIRED_VARS="TARGET_URL"
OPTIONAL_VARS="TIMEOUT:30"

COMMAND_TEMPLATE="nikto -h \${TARGET_URL} -Tuning 123 -timeout \${TIMEOUT}"
```

The module will automatically be discovered on next framework launch!

## Architecture

```
purplesploit/
├── purplesploit-framework.sh    # Main entry point
│
├── framework/                   # Framework core
│   ├── core/
│   │   ├── engine.sh            # Main framework engine
│   │   ├── variable_manager.sh  # Variable system
│   │   ├── module_registry.sh   # Module discovery
│   │   ├── command_engine.sh    # Command execution
│   │   └── workspace_manager.sh # Workspace management
│   │
│   └── lib/                     # Additional libraries (future)
│
└── modules/                     # Tool modules (.psm files)
    ├── recon/
    │   ├── nmap/
    │   └── masscan/
    ├── web/
    │   ├── feroxbuster/
    │   ├── sqlmap/
    │   ├── httpx/
    │   └── wfuzz/
    └── network/
        ├── nxc/
        │   ├── smb/
        │   ├── ldap/
        │   └── winrm/
        └── impacket/
```

## Benefits Over "Lite" Version

| Feature | Lite Version | Framework Version |
|---------|--------------|-------------------|
| Interface | Menu-driven TUI | Metasploit-style CLI |
| Variables | Per-tool settings | Universal variable system |
| Adding Tools | Edit multiple files | Drop in a .psm file |
| Workspaces | Basic | Full workspace management |
| Command Editing | Limited | Full interactive editing |
| History | None | Complete command history |
| Background Jobs | None | Full job management |
| Scalability | Medium | Extremely high |
| Learning Curve | Low | Medium (Metasploit users: Low) |

## Data Storage

- **Workspaces:** `~/.purplesploit/workspaces/`
- **Command History:** `~/.purplesploit/command_history`
- **Output Files:** `~/.purplesploit/workspaces/<workspace>/output/`
- **Job Logs:** `~/.purplesploit/jobs/`

## Tips and Tricks

### 1. Quick Variable Setting

Set multiple variables quickly:
```bash
purplesploit> set RHOST 192.168.1.100
purplesploit> set USERNAME admin
purplesploit> set PASSWORD P@ssw0rd
```

Variables persist across modules!

### 2. Command Preview

Always check what will be executed:
```bash
purplesploit(module)> check
```

### 3. Background Jobs

Run long scans in background:
```bash
purplesploit(recon/nmap/full_scan)> run -j
[+] Job 1 started (PID: 12345)

purplesploit(recon/nmap/full_scan)> jobs
Job ID    PID       Status     Command
1         12345     Running    nmap -sV -sC -p- ...
```

### 4. Import Multiple Targets

Create a targets file and import:
```bash
# targets.txt
192.168.1.0/24
10.10.10.50
10.10.10.75

purplesploit> targets -i targets.txt
```

### 5. Search for Modules

Find modules quickly:
```bash
purplesploit> search smb
purplesploit> search enum
purplesploit> search nmap
```

## Troubleshooting

### Module Not Found

If a module doesn't appear:
1. Ensure the .psm file has correct MODULE_NAME
2. Check file is in correct directory under modules/
3. Restart the framework to re-scan modules

### Variable Not Substituted

If ${VAR} appears in command:
1. Check variable is set: `show vars`
2. Ensure variable name matches exactly (case-sensitive)
3. Set the variable: `set VAR value`

### Command Execution Fails

If a command fails:
1. Check the tool is installed
2. Preview the command: `check`
3. Verify variable values are correct
4. Test the command manually

## Future Enhancements

- Output parsers for automatic result extraction
- Session management for persistent shells
- Report generation
- Plugin system for custom functionality
- API for programmatic access
- Multi-target batch execution
- Credential database integration
- Result correlation across modules

## Contributing

To contribute a module:

1. Create a `.psm` file in the appropriate category
2. Follow the module format specifications
3. Test the module thoroughly
4. Submit a pull request

## License

MIT License - See LICENSE file

## Credits

- **Framework:** PurpleSploit Team
- **Tools:** Respective tool authors (nmap, feroxbuster, nxc, etc.)
- **Inspired by:** Metasploit Framework

---

**Happy Hacking!** 🟣
