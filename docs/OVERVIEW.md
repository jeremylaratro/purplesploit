# PurpleSploit - Core Overview

**Version 6.7.0 - Pure Python Pentesting Framework**

## What is PurpleSploit?

PurpleSploit is a **pure Python offensive security framework** designed to streamline penetration testing workflows through automation, persistent context management, and powerful search capabilities. Think of it as a Metasploit-inspired framework focused on **workflow efficiency** rather than payload generation.

### Core Philosophy

1. **Search. Select. Exploit.** - No menu diving, no memorizing commands
2. **Set Once, Use Everywhere** - Persistent context (targets, credentials, workspaces)
3. **Automation Over Manual** - Let tools do the heavy lifting
4. **Modular Architecture** - Easy to extend with new tools and operations

---

## Architecture Overview

### Framework Components

```
PurpleSploit
│
├── Core Framework (framework.py)
│   ├── Module Registry - Discovers and loads all modules
│   ├── Session Manager - Maintains persistent state
│   └── Database - Stores targets, creds, scan results
│
├── UI Layer (console.py, commands.py)
│   ├── Enhanced Auto-Completion - Context-aware dropdown menus
│   ├── Command Handler - Processes all user commands
│   └── Interactive Selectors - fzf-powered fuzzy search
│
├── Module System (module.py)
│   ├── BaseModule - Abstract base for all modules
│   ├── ExternalToolModule - Wraps external pentesting tools
│   └── Operations - Granular sub-functions within modules
│
└── Modules (modules/*)
    ├── Network (NXC) - SMB, LDAP, WinRM, MSSQL, RDP, SSH
    ├── Impacket - PSExec, WMIExec, SecretsDump, Kerberoast
    ├── Web - Feroxbuster, SQLMap, Wfuzz, HTTPx
    └── Recon - Nmap with auto-service detection
```

### Key Design Patterns

- **Persistent Context**: Target, credentials, workspace persist across commands
- **Auto-Population**: Modules automatically inherit context values
- **Service Detection**: Nmap results mark relevant modules active
- **Granular Operations**: Single module = multiple operations (e.g., SMB module has 40+ operations)

---

## Core Features Deep Dive

### 1. Search vs Ops - Understanding the Difference

#### `search <query>` - Module Search
**What it does**: Searches across module **names, descriptions, categories, and paths**

**Use when**: You want to find and load a specific module/tool

**Example**:
```bash
purplesploit> search smb
# Results:
# 1. network/nxc_smb - Comprehensive SMB testing
# 2. impacket/smbclient - SMB client operations
# 3. smb/authentication - SMB auth module
```

**Output**: List of **modules** you can load with `use <number>`

**Why useful**:
- Quick discovery of relevant modules
- No need to remember exact module paths
- Auto-loads if only one result found

---

#### `ops <query>` - Operations Search
**What it does**: Searches across **all operations** inside **all modules**

**Use when**: You know what action you want (e.g., "dump secrets"), but don't know which module/category contains it

**Example**:
```bash
purplesploit> ops secretsdump
# Results:
# ▸ Impacket SecretsDump (impacket/secretsdump)
#   1. Domain Secrets - Dump NTDS.dit from Domain Controller
#   2. LSA Secrets - Extract LSA secrets from registry
#
# ▸ NetExec SMB (network/nxc_smb)
#   3. Dump SAM - Dump local SAM database
#   4. Dump LSA - Dump LSA secrets via SMB
```

**Output**: List of **operations** from multiple modules, grouped by module

**Why useful**:
- Cross-category search (finds operations in network, impacket, smb categories)
- See all ways to accomplish a task
- Direct execution with `run <number>`

---

#### Real-World Scenario

```bash
# Scenario: You want to extract credentials from a Windows target

# Approach 1: Module search (if you know the tool)
purplesploit> search secretsdump
# Loads impacket/secretsdump module

# Approach 2: Operation search (if you don't know which tool)
purplesploit> ops dump credentials
# Shows ALL credential dumping operations:
# - Impacket SecretsDump
# - NXC SAM/LSA dump
# - NXC lsassy
# - Mimikatz operations
# Pick the one that fits your situation
```

**Key Insight**: `search` = find modules, `ops` = find actions

---

### 2. Select Commands - Interactive Fuzzy Selection

PurpleSploit uses **fzf** (fuzzy finder) for interactive selection. Nearly every command supports the `select` subcommand.

#### Core Select Commands

| Command | What It Does | Why It's Useful |
|---------|-------------|-----------------|
| `module select` | Browse all modules + operations in tree view | Visual exploration of entire framework |
| `target select` | Pick from saved targets | No retyping IPs |
| `cred select` | Pick from credential database | Quickly switch between credential sets |
| `ops select` | Interactive selection from last ops search | Visual picking after broad search |
| `search select` | Interactive selection from last search | Visual picking after broad search |
| `wordlists select <category>` | Pick wordlist by category (web_dir, passwords, etc.) | Category-organized wordlist management |
| `services select` | Pick from detected services (from nmap) | Target specific detected services |

#### How Select Works

```bash
# Without select - manual typing
purplesploit> targets add 192.168.1.100
purplesploit> targets set 192.168.1.100

# With select - interactive
purplesploit> targets select
# Opens fzf menu with all targets:
# > 192.168.1.100 (DC01)
#   192.168.1.50 (WEBSERVER)
#   10.10.10.25 (DATABASE)
# [Type to filter, arrows to navigate, Enter to select]
```

**Benefits**:
- **Visual browsing** - See all options at once
- **Fuzzy matching** - Type partial matches ("dc" finds "DC01")
- **Keyboard navigation** - Fast selection without mouse
- **No memorization** - Don't need to remember exact names/IPs

---

### 3. Context Management - Set Once, Use Everywhere

PurpleSploit maintains **persistent context** that all modules inherit.

#### Context Components

**Targets**:
```bash
# Quick add and set
purplesploit> target 192.168.1.100

# Add with name for organization
purplesploit> targets add 192.168.1.100 DC01

# All modules now auto-populate RHOST
purplesploit> use network/nxc_smb
purplesploit(nxc_smb)> options
# RHOST = 192.168.1.100 (auto-set!)
```

**Credentials**:
```bash
# Quick add credential
purplesploit> cred admin:Password123 CORP

# Modules auto-populate USERNAME, PASSWORD, DOMAIN
purplesploit> use network/nxc_ldap
purplesploit(nxc_ldap)> options
# USERNAME = admin (auto-set!)
# PASSWORD = ******** (auto-set!)
# DOMAIN = CORP (auto-set!)
```

**Workspaces**:
```bash
# Organize by engagement
purplesploit> workspace create pentest-acme-corp
purplesploit> workspace acme-corp

# All data (targets, creds, results) stored separately
# Database: ~/.purplesploit/workspaces/acme-corp/
```

**Why Context Matters**:
- **No Repetition**: Set target once, all 50+ modules use it
- **Fast Switching**: Change targets/creds globally with one command
- **Engagement Isolation**: Workspaces keep client data separate

---

### 4. Module Operations System

PurpleSploit modules can have **multiple granular operations** instead of being single-purpose.

#### Traditional vs Operations Model

**Traditional (Metasploit-style)**:
```
smb_auth_module      → Only tests auth
smb_shares_module    → Only lists shares
smb_users_module     → Only enumerates users
# Load 3 different modules for 3 tasks
```

**PurpleSploit Operations Model**:
```
network/nxc_smb → 40+ operations organized by category:
  ├─ Authentication (5 ops)
  ├─ Enumeration (12 ops)
  ├─ Shares (8 ops)
  ├─ Execution (6 ops)
  ├─ Credentials (7 ops)
  └─ Vulnerability (5 ops)
# Load 1 module, pick from menu
```

#### Example: SMB Module Operations

```bash
purplesploit> use network/nxc_smb
purplesploit(nxc_smb)> run

# Interactive menu shows grouped operations:
═══ AUTHENTICATION ═══
1. Test Authentication
2. Test with Domain
3. Pass-the-Hash (PTH)
4. Password Spray
5. Local Auth Test

═══ ENUMERATION ═══
6. Enumerate Users
7. Enumerate Groups
8. Enumerate Shares
9. Enumerate Sessions
10. Check Admin Access
[... 30+ more operations]

# Select operation by number or name
purplesploit(nxc_smb)> run 9
# Executes "Enumerate Sessions"
```

#### Benefits of Operations

1. **Logical Grouping**: Related functions in one module
2. **Context Sharing**: All operations use same target/creds
3. **Faster Workflow**: No module switching between related tasks
4. **Subcategory Filtering**:
   ```bash
   purplesploit> use smb auth
   # Loads SMB module, shows only authentication operations

   purplesploit> l shares
   # Lists only share-related operations
   ```

---

## Smart Features

### Auto-Service Detection

After running an nmap scan, PurpleSploit **automatically**:
1. Parses nmap output
2. Identifies services (SMB on 445, LDAP on 389, etc.)
3. Marks relevant modules with indicators
4. Populates web targets for discovered HTTP services

```bash
purplesploit> use recon/nmap
purplesploit(nmap)> run

# Scan completes, framework analyzes:
# ✓ Detected SMB on 192.168.1.100:445
# ✓ Detected LDAP on 192.168.1.100:389
# ✓ Detected HTTP on 192.168.1.100:80

purplesploit> search relevant
# Shows only modules for detected services:
# ● network/nxc_smb
# ● network/nxc_ldap
# ● web/feroxbuster
```

### Auto-Completion System

**Dynamic context-aware completions**:
- Module paths: `use net[TAB]` → suggests all network/* modules
- Targets: `target [TAB]` → shows saved IPs
- Commands: `tar[TAB]` → target, targets
- History: Previous commands appear as grayed suggestions

### Quick Shortcuts

Fast commands for common workflows:

```bash
# Quick target/cred setting
purplesploit> target 192.168.1.100
purplesploit> cred admin:pass DOMAIN

# All-in-one workflow
purplesploit> go 192.168.1.100 admin:pass
# Sets target + cred, shows available operations

# Module shortcuts
purplesploit> quick smb auth
# Loads SMB module with auth operations

# External tool integration
purplesploit> ligolo          # Launch ligolo-ng proxy
purplesploit> shell           # Drop to localhost shell
```

---

## Typical Workflow Examples

### External Pentest Workflow

```bash
# 1. Start framework
python3 -m purplesploit.main

# 2. Initial recon
purplesploit> target 10.10.10.100
purplesploit> use recon/nmap
purplesploit(nmap)> run
# [Nmap runs, detects SMB, LDAP, HTTP]

# 3. Web enumeration (auto-populated from nmap)
purplesploit> use web/feroxbuster
purplesploit(feroxbuster)> run
# [Directory bruteforce against detected web services]

# 4. SMB authentication test
purplesploit> cred guest:
purplesploit> ops smb shares
purplesploit> run 1
# [Tests guest access, enumerates shares]

# 5. Found creds? Test across all services
purplesploit> cred admin:Password123 CORP
purplesploit> ops password spray
# Shows spray operations across SMB, LDAP, WinRM, etc.
```

### Internal Network Assessment

```bash
# 1. Setup workspace
purplesploit> workspace create internal-2024

# 2. Add subnet target
purplesploit> target 192.168.1.0/24

# 3. Credential testing
purplesploit> cred admin:Winter2024!
purplesploit> use network/nxc_smb
purplesploit(nxc_smb)> run
# Select "Password Spray" → tests across entire subnet

# 4. Kerberoasting
purplesploit> ops kerberoast
purplesploit> run 1

# 5. Bloodhound collection
purplesploit> ops bloodhound
purplesploit> run 1
```

### CTF / OSCP Workflow

```bash
# 1. Quick enumeration
purplesploit> target 10.10.10.100
purplesploit> search nmap
purplesploit> use 1
purplesploit(nmap)> run

# 2. Find vulnerability
purplesploit> ops zerologon
purplesploit> ops ms17-010
purplesploit> ops eternalblue

# 3. Exploit + dump
purplesploit> use impacket/secretsdump
purplesploit(secretsdump)> run
```

---

## Module Structure

### Module Categories

| Category | Purpose | Example Tools |
|----------|---------|---------------|
| **network** | Network protocol operations | NXC (SMB, LDAP, WinRM, MSSQL, RDP, SSH) |
| **impacket** | Windows protocol tools | PSExec, WMIExec, SecretsDump, Kerberoast |
| **web** | Web application testing | Feroxbuster, SQLMap, Wfuzz, HTTPx |
| **recon** | Reconnaissance and scanning | Nmap, Nmap Parser |
| **smb** | SMB-specific operations | Authentication, Execution, Enumeration |
| **ai** | AI-assisted automation | AI module automation |
| **utility** | Helper tools | Module creator, etc. |

### Creating Custom Modules

```python
# python/purplesploit/modules/custom/my_scanner.py
from purplesploit.core.module import ExternalToolModule

class MyScanner(ExternalToolModule):
    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "my-tool"

    @property
    def name(self) -> str:
        return "My Custom Scanner"

    @property
    def description(self) -> str:
        return "Custom scanning module"

    @property
    def category(self) -> str:
        return "custom"

    def get_operations(self):
        return [
            {
                "name": "Quick Scan",
                "description": "Fast scan",
                "handler": "op_quick_scan",
                "subcategory": "scanning"
            }
        ]

    def op_quick_scan(self):
        target = self.get_option('RHOST')
        return self.execute_command(f'my-tool -t {target}')
```

Framework auto-discovers and registers the module on startup.

---

## Why PurpleSploit?

### Problems It Solves

**❌ Traditional Pentesting Pain Points**:
- Switching between 10+ separate tools
- Retyping targets/credentials for each tool
- Remembering exact command syntax
- Losing track of what you've tested
- Manual note-taking for each command

**✅ PurpleSploit Solutions**:
- Unified interface for 50+ operations
- Persistent context across all tools
- Search/ops commands for discovery
- Database tracks all executions
- Auto-populated commands and logging

### Use Cases

**Perfect For**:
- External penetration tests
- Internal network assessments
- Active Directory enumeration
- CTF competitions (OSCP, HTB)
- Red team engagements
- Security research

**Not For**:
- Payload generation (use Metasploit)
- Pure exploit development
- Web app source code analysis
- Passive reconnaissance only

---

## Key Takeaways

### Core Concepts
1. **Search** finds modules, **ops** finds actions across modules
2. **Select** commands enable interactive fuzzy selection
3. **Context** (targets, creds, workspace) persists across all modules
4. **Operations** provide granular control within modules
5. **Auto-completion** and **auto-population** reduce manual work

### Command Cheat Sheet

```bash
# Discovery
search <query>          # Find modules
ops <query>             # Find operations globally
module select           # Browse all modules

# Context
target <ip>             # Quick set target
cred <user:pass>        # Quick set credential
workspace <name>        # Switch workspace

# Selection
target select           # Pick from targets
cred select             # Pick from credentials
wordlists select <cat>  # Pick wordlist

# Execution
use <module>            # Load module
run                     # Interactive operation menu
run <number>            # Direct execution

# Utility
ligolo                  # Launch pivoting proxy
shell                   # Localhost shell
help                    # Full command reference
```

---

## Database & Persistence

All data stored in `~/.purplesploit/`:
- **Targets**: Persisted across sessions
- **Credentials**: Encrypted storage
- **Services**: Discovered from scans
- **Results**: All module executions logged
- **Workspaces**: Separate databases per engagement

---

## External Tool Integration

PurpleSploit **wraps** external tools, it doesn't replace them:

- **NetExec (NXC)**: Network protocol testing
- **Impacket**: Windows protocol operations
- **Nmap**: Network scanning
- **Feroxbuster**: Web directory enumeration
- **SQLMap**: SQL injection testing
- **Wfuzz**: Web fuzzing
- **HTTPx**: HTTP probing
- **Ligolo-ng**: Network pivoting

---

## Performance Features

- **Pure Python**: v6.0.0 removed bash dependencies
- **Fuzzy Search (fzf)**: Lightning-fast module/operation discovery
- **Smart Caching**: Recent modules, search results cached
- **Background Jobs**: Long-running scans in background
- **Modular Loading**: Only loads modules when needed

---

## Summary

**PurpleSploit is a workflow automation framework** that:
- Brings 50+ pentesting tools under one unified interface
- Uses persistent context to eliminate repetitive tasks
- Provides powerful search (modules) and ops (operations) discovery
- Enables interactive selection through fuzzy search
- Organizes modules into granular operations
- Auto-detects services and suggests relevant tools

**The goal**: Spend less time typing commands, more time finding vulnerabilities.

**Philosophy**: Search. Select. Exploit.

---

## Next Steps

- **[Quick Start Guide](QUICKSTART.md)** - Get started in 5 minutes
- **[Full README](README.md)** - Complete feature documentation
- **[Console Guide](docs/console-mode/README.md)** - Advanced commands and techniques
- **[Contributing Guide](docs/CONTRIBUTING.md)** - Add your own modules
- **[Architecture Docs](docs/ARCHITECTURE.md)** - Deep dive into internals

---

*Built for red teamers, by red teamers. Version 6.7.0 - Pure Python Edition.*
