# PurpleSploit Framework Guide

Complete guide to understanding and using the PurpleSploit framework.

---

## What is PurpleSploit?

**PurpleSploit** is a pure Python offensive security framework designed to streamline penetration testing workflows through automation, persistent context management, and powerful search capabilities.

### Philosophy
1. **Search. Select. Exploit.** - No menu diving, no memorizing commands
2. **Set Once, Use Everywhere** - Persistent context (targets, credentials, workspaces)
3. **Automation Over Manual** - Let tools do the heavy lifting
4. **Modular Architecture** - Easy to extend with new tools and operations

---

## Architecture

```
PurpleSploit
├── Core Framework
│   ├── Module Registry - Discovers and loads all modules
│   ├── Session Manager - Maintains persistent state
│   └── Database - Stores targets, creds, scan results
│
├── UI Layer
│   ├── Enhanced Auto-Completion - Context-aware dropdown menus
│   ├── Command Handler - Processes all user commands
│   └── Interactive Selectors - fzf-powered fuzzy search
│
├── Module System
│   ├── BaseModule - Abstract base for all modules
│   ├── ExternalToolModule - Wraps external pentesting tools
│   └── Operations - Granular sub-functions within modules
│
└── Modules
    ├── Network (NXC) - SMB, LDAP, WinRM, MSSQL, RDP, SSH
    ├── Impacket - PSExec, WMIExec, SecretsDump, Kerberoast
    ├── Web - Feroxbuster, SQLMap, Wfuzz, HTTPx
    └── Recon - Nmap with auto-service detection
```

---

## Core Concepts

### 1. Modules vs Operations

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

### 2. Search vs Ops

#### `search <query>` - Module Search
- Searches module names, descriptions, categories, paths
- Use when: You want to find and load a specific module/tool
- Returns: List of modules you can load with `use <number>`

```bash
purplesploit> search smb
# Results:
# 1. network/nxc_smb - Comprehensive SMB testing
# 2. impacket/smbclient - SMB client operations
```

#### `ops <query>` - Operations Search
- Searches all operations inside all modules globally
- Use when: You know what action you want, but not which module contains it
- Returns: List of operations from multiple modules

```bash
purplesploit> ops secretsdump
# Results:
# ▸ Impacket SecretsDump (impacket/secretsdump)
#   1. Domain Secrets - Dump NTDS.dit from Domain Controller
#   2. LSA Secrets - Extract LSA secrets from registry
#
# ▸ NetExec SMB (network/nxc_smb)
#   3. Dump SAM - Dump local SAM database
```

**Key Insight**: `search` = find modules, `ops` = find actions

### 3. Interactive Selection with `select`

Nearly every command supports the `select` subcommand for interactive fuzzy search:

```bash
module select      # Browse all modules
targets select     # Pick from saved targets
creds select       # Pick from credentials
ops select         # Pick from operation search results
search select      # Pick from module search results
wordlists select   # Pick wordlist by category
services select    # Pick from detected services
recent select      # Pick from recently used modules
```

**Benefits**:
- Visual browsing - See all options at once
- Fuzzy matching - Type partial matches
- Keyboard navigation - Fast selection without mouse
- No memorization - Don't need to remember exact names

---

## Context Management

### Persistent Context

PurpleSploit maintains persistent context that all modules inherit:

**Targets**:
```bash
# Quick add and set
purplesploit> target 192.168.1.100

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
- No Repetition: Set target once, all 50+ modules use it
- Fast Switching: Change targets/creds globally with one command
- Engagement Isolation: Workspaces keep client data separate

---

## Smart Features

### Auto-Service Detection

After running an nmap scan, PurpleSploit automatically:
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
# Shows only modules for detected services
```

### Auto-Completion

- Module paths: `use net[TAB]` → suggests all network/* modules
- Targets: `target [TAB]` → shows saved IPs
- Commands: `tar[TAB]` → target, targets
- History: Previous commands appear as grayed suggestions

---

## Typical Workflows

### External Pentest
```bash
# 1. Initial recon
target 10.10.10.100
use recon/nmap
run

# 2. Web enumeration (auto-populated from nmap)
use web/feroxbuster
run

# 3. SMB authentication test
cred guest:
ops smb shares
run 1

# 4. Found creds? Test across all services
cred admin:Password123 CORP
ops password spray
```

### Internal Assessment
```bash
# 1. Setup workspace
workspace create internal-2024

# 2. Add subnet target
target 192.168.1.0/24

# 3. Credential testing
cred admin:Winter2024!
use network/nxc_smb
run  # Select "Password Spray"

# 4. Kerberoasting
ops kerberoast
run 1

# 5. Bloodhound collection
ops bloodhound
run 1
```

### CTF / OSCP
```bash
# 1. Quick enumeration
target 10.10.10.100
use recon/nmap
run

# 2. Find vulnerability
ops zerologon
ops ms17-010

# 3. Exploit + dump
use impacket/secretsdump
run
```

---

## Module Categories

| Category | Purpose | Example Tools |
|----------|---------|---------------|
| **network** | Network protocol operations | NXC (SMB, LDAP, WinRM, MSSQL, RDP, SSH) |
| **impacket** | Windows protocol tools | PSExec, WMIExec, SecretsDump, Kerberoast |
| **web** | Web application testing | Feroxbuster, SQLMap, Wfuzz, HTTPx |
| **recon** | Reconnaissance and scanning | Nmap, Nmap Parser |
| **utility** | Helper tools | Module creator, etc. |

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

PurpleSploit wraps external tools, it doesn't replace them:

- **NetExec (NXC)**: Network protocol testing
- **Impacket**: Windows protocol operations
- **Nmap**: Network scanning
- **Feroxbuster**: Web directory enumeration
- **SQLMap**: SQL injection testing
- **Wfuzz**: Web fuzzing
- **HTTPx**: HTTP probing
- **Ligolo-ng**: Network pivoting

---

## Key Takeaways

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
targets select          # Pick from targets
creds select           # Pick from credentials
wordlists select <cat>  # Pick wordlist

# Execution
use <module>            # Load module
run                     # Interactive operation menu
run <number>            # Direct execution

# Utility
ligolo                  # Launch pivoting proxy
shell                   # Localhost shell
webserver start         # Start web dashboard
help                    # Full command reference
```

---

## Why PurpleSploit?

### Problems It Solves

**Traditional Pain Points**:
- Switching between 10+ separate tools
- Retyping targets/credentials for each tool
- Remembering exact command syntax
- Losing track of what you've tested
- Manual note-taking for each command

**PurpleSploit Solutions**:
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

**Last Updated**: v6.7.1

**Philosophy**: Search. Select. Exploit.
