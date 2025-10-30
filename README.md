# PurpleSploit Framework v2.0

<div align="center">

```
╔═══════════════════════════════════════════════════════════════════════════╗
║   ██████╗ ██╗   ██╗██████╗ ██████╗ ██╗     ███████╗███████╗██████╗       ║
║   ██╔══██╗██║   ██║██╔══██╗██╔══██╗██║     ██╔════╝██╔════╝██╔══██╗      ║
║   ██████╔╝██║   ██║██████╔╝██████╔╝██║     █████╗  ███████╗██████╔╝      ║
║   ██╔═══╝ ██║   ██║██╔══██╗██╔═══╝ ██║     ██╔══╝  ╚════██║██╔═══╝       ║
║   ██║     ╚██████╔╝██║  ██║██║     ███████╗███████╗███████║██║           ║
║   ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚══════╝╚═╝           ║
║                                                                           ║
║         ███████╗██████╗  █████╗ ███╗   ███╗███████╗██╗    ██╗ ██████╗    ║
║         ██╔════╝██╔══██╗██╔══██╗████╗ ████║██╔════╝██║    ██║██╔═══██╗   ║
║         █████╗  ██████╔╝███████║██╔████╔██║█████╗  ██║ █╗ ██║██║   ██║   ║
║         ██╔══╝  ██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝  ██║███╗██║██║   ██║   ║
║         ██║     ██║  ██║██║  ██║██║ ╚═╝ ██║███████╗╚███╔███╔╝╚██████╔╝   ║
║         ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ╚══╝╚══╝  ╚═════╝    ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

**Metasploit-Style Pentesting Framework with Intelligent Module Selection**

[Quick Start](#quick-start) • [Features](#features) • [Documentation](#documentation) • [Installation](#installation)

</div>

---

## Overview

PurpleSploit Framework is a **Metasploit-inspired pentesting framework** that unifies popular security tools under a single, intelligent interface. It combines CLI power with FZF-driven menu selection and **smart service analysis** to show only relevant modules for your targets.

### Why PurpleSploit?

- 🎯 **Smart Module Selection** - Automatically detects services and shows only relevant modules
- 🔍 **FZF Integration** - Interactive menus meet Metasploit-style CLI
- 🔐 **Multi-Credential Management** - Store and switch between credential sets
- 🎯 **Multi-Target Tracking** - Organize targets per workspace
- 🚀 **Mythic C2 Integration** - Automated agent deployment
- 📦 **Modular Architecture** - Add new tools by dropping a `.psm` file
- 🔧 **Universal Variables** - Set once, use everywhere

---

## Quick Start

### Launch Framework

```bash
./purplesploit-framework.sh
```

### Basic Workflow

```bash
# 1. Set your target
purplesploit> set RHOST 192.168.1.100

# 2. Run a quick scan
purplesploit> use recon/nmap/quick_scan
purplesploit(recon/nmap/quick_scan)> run

[+] Detected 5 services on 192.168.1.100
[*] Run 'search relevant' to see applicable modules

# 3. Search for ONLY relevant modules (smart!)
purplesploit> search relevant

[FZF menu shows only modules for detected services]
- web/feroxbuster/basic_scan ✓ (HTTP detected)
- network/nxc/smb/enum_shares ✓ (SMB detected)
- network/nxc/rdp/screenshot ✓ (RDP detected)
[SSH/LDAP/MSSQL modules NOT shown - not detected]

# 4. Select credentials (FZF)
purplesploit> credentials
[Select from saved credentials]

# 5. Run the module
purplesploit> run
```

### Interactive Features

All with FZF menus for point-and-click selection:

```bash
search          # Interactive module search
search relevant # Smart: only modules for detected services
browse          # Browse by category
targets         # Select target from workspace
credentials     # Select and load credentials
workspace       # Switch workspaces
vars            # Edit variables interactively
history         # Browse and re-run commands
```

---

## Features

### 🎯 Intelligent Service Analysis

Automatically analyzes nmap scans and filters modules:

```bash
# After running nmap scan:
purplesploit> services

Detected Services:
Target               Port     Service
192.168.1.100        80       http
192.168.1.100        445      microsoft-ds
192.168.1.100        3389     rdp

# Smart search shows ONLY relevant modules
purplesploit> search relevant
[Only web, SMB, and RDP modules shown]
```

**[Read more: Service Analysis Guide](docs/SERVICE_ANALYSIS.md)**

### 🔍 FZF-Powered Menus

Metasploit CLI + Interactive menus:

- **Module Search** - Type keyword, select from filtered results
- **Category Browser** - Browse modules organized by category
- **Target Selection** - Click to select targets (with live ping)
- **Credential Selection** - Click to load saved credentials
- **Workspace Selection** - Quick workspace switching
- **Variable Editor** - Select and edit any variable
- **History Browser** - Select previous commands to re-run

**[Read more: Features Guide](docs/FEATURES.md)**

### 🔐 Multi-Credential Management

Store unlimited credential sets:

```bash
# Add credentials
credentials -a
Username: administrator
Password: [hidden]
Domain: CORP.LOCAL

# Select with FZF (click from list)
credentials
[Arrow keys, Enter to select]

# Credentials auto-populate in modules
use network/nxc/smb/enum_shares
run  # Uses loaded credentials automatically
```

### 🚀 Mythic C2 Integration

Deploy agents via NXC and Impacket:

```bash
# Configure once
mythic configure
Server: https://mythic.example.com
API Key: abc123...

# Deploy agent
use c2/mythic/deploy_smb
set MYTHIC_PAYLOAD /tmp/agent.exe
run

[+] Payload deployed - check Mythic for callback!
```

**[Read more: Mythic Integration](docs/FEATURES.md#-mythic-c2-integration)**

### 📦 Module System

**19 Built-in Modules:**

#### Reconnaissance
- `recon/nmap/quick_scan` - Fast port scan with auto-analysis
- `recon/nmap/full_scan` - Full scan with service detection
- `recon/nmap/vuln_scan` - Vulnerability scanning

#### Web Testing
- `web/feroxbuster/basic_scan` - Directory discovery
- `web/feroxbuster/deep_scan` - Deep scan with extensions
- `web/feroxbuster/api_discovery` - API endpoint discovery
- `web/httpx/probe_urls` - HTTP probing
- `web/sqlmap/basic_injection` - SQL injection testing
- `web/sqlmap/database_dump` - Database dumping

#### Network (NXC)
- `network/nxc/smb/*` - SMB authentication, enumeration, shares, credentials
- `network/nxc/ldap/*` - LDAP enumeration
- `network/nxc/winrm/*` - WinRM operations
- `network/nxc/rdp/*` - RDP operations

#### C2 Deployment
- `c2/mythic/deploy_smb` - Deploy via SMB
- `c2/mythic/deploy_winrm` - Deploy via WinRM
- `c2/mythic/deploy_psexec` - Deploy via PSExec
- `c2/mythic/deploy_wmiexec` - Deploy via WMIExec

**Add your own:** Drop a `.psm` file in `modules/`, framework auto-discovers it!

**[Module Template](MODULE_TEMPLATE.psm)** | **[Full Module List](docs/FRAMEWORK_README.md#example-modules)**

---

## Installation

### Prerequisites

```bash
# Required
- bash 4.0+
- fzf (for interactive menus)

# Optional (for specific modules)
- nmap
- feroxbuster
- sqlmap
- httpx
- netexec (nxc)
- impacket
- mythic (for C2 integration)
```

### Install FZF (Recommended)

```bash
# Debian/Ubuntu
sudo apt install fzf

# macOS
brew install fzf

# Or manual install
git clone --depth 1 https://github.com/junegunn/fzf.git ~/.fzf
~/.fzf/install
```

### Clone Repository

```bash
git clone https://github.com/jeremylaratro/purplesploit.git
cd purplesploit
chmod +x purplesploit-framework.sh
```

### Launch

```bash
./purplesploit-framework.sh
```

---

## Documentation

### Core Documentation

- **[Framework Guide](docs/FRAMEWORK_README.md)** - Complete framework documentation
- **[Features Guide](docs/FEATURES.md)** - FZF, credentials, Mythic C2
- **[Service Analysis](docs/SERVICE_ANALYSIS.md)** - Smart module selection guide
- **[Module Template](MODULE_TEMPLATE.psm)** - Create your own modules

### Legacy (Lite Version)

The "lite" version (TUI-based) is preserved in `purplesploit.sh`:

```bash
./purplesploit.sh  # Launch lite version
```

- **[Legacy Documentation](docs/legacy/)** - Original lite version docs

---

## Command Reference

### Module Commands

| Command | Description |
|---------|-------------|
| `use <module>` | Select a module |
| `search [keyword]` | 🔍 Interactive search |
| `search relevant` | 🎯 Smart: modules for detected services |
| `browse` | 🔍 Browse by category |
| `back` | Deselect module |
| `info` | Show module details |

### Smart Analysis

| Command | Description |
|---------|-------------|
| `search relevant` | Show only modules for detected services |
| `services` | List detected services |
| `services -t` | Services on current target |

### Target & Credential Management

| Command | Description |
|---------|-------------|
| `targets` | 🔍 Select target (FZF) |
| `targets -a <ip>` | Add target |
| `credentials` | 🔍 Select credentials (FZF) |
| `credentials -a` | Add new credential |
| `workspace` | 🔍 Select workspace (FZF) |

### Execution

| Command | Description |
|---------|-------------|
| `run` | Execute module |
| `run -y` | Execute without confirmation |
| `run -j` | Execute in background |
| `check` | Preview command |

### Variables

| Command | Description |
|---------|-------------|
| `set <VAR> <value>` | Set variable |
| `vars` | 🔍 Interactive editor |
| `show options` | Module options |
| `show vars` | All variables |

**Full command list:** Type `help` in framework

---

## Usage Examples

### Scenario 1: Quick Web Assessment

```bash
purplesploit> set TARGET_URL https://target.com
purplesploit> search ferox
[Select web/feroxbuster/deep_scan from menu]
purplesploit> vars  # Edit THREADS, WORDLIST, etc.
purplesploit> run
```

### Scenario 2: Internal Network Pentest

```bash
# Create workspace
purplesploit> workspace -a acme_internal

# Add targets
purplesploit> targets -i targets.txt

# Scan target
purplesploit> targets  # FZF select first target
purplesploit> use recon/nmap/full_scan
purplesploit> run

# Smart module selection
purplesploit> search relevant
[Only shows modules for detected services]

# Load credentials and attack
purplesploit> credentials  # FZF select admin creds
purplesploit> run
```

### Scenario 3: Automated C2 Deployment

```bash
# Configure Mythic once
purplesploit> mythic configure

# Deploy to target
purplesploit> use c2/mythic/deploy_smb
purplesploit> set RHOST 192.168.1.100
purplesploit> set MYTHIC_PAYLOAD /tmp/agent.exe
purplesploit> credentials  # Select domain admin
purplesploit> run

[+] Payload deployed via SMB
[*] Check Mythic for callback
```

---

## Architecture

```
purplesploit/
├── purplesploit-framework.sh    # Main entry point (Full version)
├── purplesploit.sh              # Lite version (legacy)
├── MODULE_TEMPLATE.psm          # Template for new modules
│
├── framework/                   # Framework core
│   └── core/
│       ├── engine.sh            # Main engine
│       ├── variable_manager.sh  # Universal variables
│       ├── module_registry.sh   # Module discovery
│       ├── command_engine.sh    # Command execution
│       ├── workspace_manager.sh # Workspace management
│       ├── fzf_integration.sh   # FZF menus
│       ├── credential_manager.sh# Credential database
│       ├── mythic_integration.sh# Mythic C2 support
│       └── service_analyzer.sh  # Smart service detection
│
├── modules/                     # Tool modules (.psm files)
│   ├── recon/
│   │   └── nmap/
│   ├── web/
│   │   ├── feroxbuster/
│   │   ├── sqlmap/
│   │   └── httpx/
│   ├── network/
│   │   └── nxc/
│   └── c2/
│       └── mythic/
│
└── docs/                        # Documentation
    ├── FRAMEWORK_README.md      # Full framework guide
    ├── FEATURES.md              # Feature documentation
    ├── SERVICE_ANALYSIS.md      # Service analysis guide
    └── legacy/                  # Old lite version docs
```

---

## Creating Custom Modules

Add any tool in 5 minutes:

**1. Create module file:** `modules/category/tool/action.psm`

```bash
#!/bin/bash
MODULE_NAME="web/nuclei/basic_scan"
MODULE_CATEGORY="web"
MODULE_DESCRIPTION="Nuclei vulnerability scan"
MODULE_AUTHOR="Your Name"
MODULE_TOOL="nuclei"

REQUIRED_VARS="TARGET_URL"
OPTIONAL_VARS="THREADS:50,TEMPLATES:"

COMMAND_TEMPLATE="nuclei -u \${TARGET_URL} -t \${TEMPLATES} -c \${THREADS}"
```

**2. Restart framework** - Auto-discovered!

**3. Use it:**

```bash
purplesploit> search nuclei
purplesploit> use web/nuclei/basic_scan
purplesploit> run
```

**[Full Module Creation Guide](docs/FRAMEWORK_README.md#adding-custom-modules)**

---

## Data Storage

### Locations

- **Workspaces:** `~/.purplesploit/workspaces/`
- **Credentials:** `~/.purplesploit/credentials.db`
- **Services:** `~/.purplesploit/workspaces/<workspace>/services.db`
- **Command History:** `~/.purplesploit/command_history`
- **Mythic Config:** `~/.purplesploit/mythic_config`
- **Job Logs:** `~/.purplesploit/jobs/`

### Per-Workspace Structure

```
~/.purplesploit/workspaces/<workspace>/
├── targets/
│   └── hosts.txt           # Target list
├── services.db             # Detected services
├── output/                 # Module outputs
├── logs/                   # Execution logs
├── data/                   # Misc data
└── vars.conf               # Workspace variables
```

---

## Lite vs Full Version

| Feature | Lite (purplesploit.sh) | Full (purplesploit-framework.sh) |
|---------|------------------------|----------------------------------|
| Interface | TUI menus | Metasploit CLI + FZF |
| Variables | Per-tool | Universal system |
| Adding Tools | Edit multiple files | Drop 1 .psm file |
| Service Analysis | Manual | Automatic |
| Smart Search | No | Yes (search relevant) |
| Credentials | Basic | Multi-credential DB |
| Mythic C2 | No | Yes |
| Scalability | Medium | Extremely high |

**Both versions available!** Use `purplesploit.sh` for TUI or `purplesploit-framework.sh` for full features.

---

## Contributing

See **[CONTRIBUTING.md](docs/CONTRIBUTING.md)** for guidelines.

**Ways to contribute:**
- Add new modules (drop a `.psm` file!)
- Improve service detection mappings
- Add output parsers
- Report bugs
- Improve documentation

---

## Troubleshooting

### FZF Not Working

**Problem:** Commands fall back to basic mode

**Solution:**
```bash
sudo apt install fzf  # or brew install fzf
```

### No Services Detected

**Problem:** `search relevant` says no services

**Solution:**
```bash
# Run nmap scan first
use recon/nmap/quick_scan
set RHOST <target>
run

# Then search
search relevant
```

### Module Not Found

**Problem:** Custom module not appearing

**Solution:**
```bash
# Check module file name ends in .psm
# Check MODULE_NAME is set correctly
# Restart framework to re-scan modules
```

**[Full Troubleshooting Guide](docs/FEATURES.md#-troubleshooting)**

---

## Credits

- **Framework:** PurpleSploit Team
- **Tools:** nmap, feroxbuster, sqlmap, NetExec, Impacket, Mythic, and respective authors
- **Inspired by:** Metasploit Framework

---

## License

MIT License - See LICENSE file

---

<div align="center">

**🟣 Happy Hacking! 🟣**

[Documentation](docs/) • [GitHub Issues](https://github.com/jeremylaratro/purplesploit/issues) • [Module Template](MODULE_TEMPLATE.psm)

</div>
