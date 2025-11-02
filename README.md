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

**Comprehensive Visual Pentesting Framework with Hybrid Architecture**

[Quick Start](#quick-start) • [Features](#features) • [Documentation](#documentation) • [Architecture](#architecture)

</div>

---

## Overview

PurpleSploit is a **visual, menu-driven pentesting framework** that combines the best of both worlds:
- **Visual FZF-based TUI** for easy navigation and discovery
- **Scalable framework backend** with workspaces, modules, and service analysis
- **Comprehensive tool coverage** including NXC, Impacket, web tools, and more

### Why PurpleSploit?

- 🎯 **Visual Interface** - See all options at once, navigate with arrow keys
- ⭐ **Service Detection** - Automatically highlights relevant tools for your target
- 🔐 **Multi-Credential Management** - Store and switch between credential sets
- 📁 **Workspace Organization** - Organize targets per-engagement
- ⚡ **Background Jobs** - Run long scans without blocking
- 🎨 **Hybrid Architecture** - Framework scalability + comprehensive tool coverage
- 🚀 **Quick Keybinds** - Single-key shortcuts for common tasks

---

## Quick Start

### Launch PurpleSploit

```bash
./purplesploit-tui.sh
```

That's it! The visual menu will guide you through everything.

### Quick Workflow

1. **Press `[s]`** → Select/switch target
2. **Press `[c]`** → Select credentials
3. **Navigate menu** → Use arrow keys to browse tools
4. **Look for `●` markers** → These tools match detected services on your target
5. **Select a tool** → Press Enter to see submenu options
6. **Run and profit** → Tools execute and output appears

---

## Main Menu Categories

### 🌐 WEB TESTING
- **Feroxbuster** - Directory/file discovery (7 modes)
- **WFUZZ** - Fuzzing (7 modes)
- **SQLMap** - SQL injection (10 modes)
- **HTTPX** - HTTP probing (8 modes)

### 🔒 NETWORK TESTING - NXC
- **SMB** - Auth, Enum, Shares, Exec, Creds, Vulns (40+ options)
- **LDAP** - Enumeration, BloodHound (13 options)
- **WinRM** - Operations (7 options)
- **MSSQL** - Operations (7 options)
- **RDP, SSH** - Protocol-specific operations

### 📦 NETWORK TESTING - IMPACKET
- **Execution** - PSExec, WMIExec, SMBExec, ATExec, DcomExec
- **Credentials** - SecretsDump, Kerberoasting, AS-REP Roasting
- **Utilities** - Enumeration, SMB Client, Services, Registry

### 📂 SESSIONS (WORKSPACES & JOBS)
- **Workspaces** - Per-engagement organization
- **Background Jobs** - Run tools in background, monitor output

### ⚙️ SETTINGS
- **Targets** - Web targets, AD targets, standard targets
- **Credentials** - Multi-credential database
- **Run Mode** - Single vs. all targets
- **Database** - Reset/clear operations

---

## Key Features

### Visual Service Detection

When you run an nmap scan, PurpleSploit automatically detects services and marks relevant tools with `●`:

```
┌ NETWORK TESTING - NXC ─────────────────
● SMB Authentication          ← SMB detected!
● SMB Enumeration            ← These are relevant
● SMB Shares
  LDAP Enumeration           ← No LDAP service detected
  WinRM Operations           ← No WinRM detected
```

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `t` | Manage targets |
| `c` | Manage credentials |
| `w` | Manage web targets |
| `d` | Manage AD targets |
| `a` | Switch authentication |
| `s` | Switch target |
| `j` | Sessions (workspaces/jobs) |
| `m` | Toggle run mode |

### Workspaces

Organize your work per-engagement:

```bash
# Access via [j] key or menu
Sessions Management → Create New Workspace
Enter name: client-acme-2025

# Everything is now organized:
~/.purplesploit/workspaces/client-acme-2025/
├── targets.txt
├── credentials.db
├── services.db
└── output/
```

### Background Jobs

Run long scans without blocking:

1. Select a tool (e.g., "Full Nmap Scan")
2. Configure options
3. Run in background
4. Press `[j]` → List Running Jobs
5. View output anytime

---

## Architecture

### Hybrid Design

PurpleSploit combines two proven systems:

```
┌─────────────────────────────────────┐
│      Hybrid TUI (Main)              │
│  purplesploit-tui.sh                │
├─────────────────────────────────────┤
│                                     │
│  ┌──────────────┐  ┌──────────────┐│
│  │  Framework   │  │   Lite       ││
│  │  Backend     │  │   Handlers   ││
│  ├──────────────┤  ├──────────────┤│
│  │ • Workspaces │  │ • NXC tools  ││
│  │ • Modules    │  │ • Impacket   ││
│  │ • Services   │  │ • Web tools  ││
│  │ • Variables  │  │ • Proven UX  ││
│  └──────────────┘  └──────────────┘│
│                                     │
│         Best of both worlds         │
└─────────────────────────────────────┘
```

**Framework Backend** provides:
- Universal variable system (${VAR})
- Workspace management
- Service analysis & smart filtering
- Background job execution
- Module auto-discovery (.psm files)

**Lite Handlers** provide:
- Comprehensive tool coverage (50+ categories)
- Battle-tested implementations
- Rich submenu options
- Interactive modes

---

## Alternative Interfaces

While the TUI is the main interface, alternative interfaces are available in `bin/`:

**Metasploit-Style CLI:**
```bash
./bin/purplesploit-framework.sh
```
Command-line interface for power users who prefer typing commands.

**Original Lite Version:**
```bash
./bin/purplesploit.sh
```
The original lite version for backwards compatibility.

See [docs/INTERFACES.md](docs/INTERFACES.md) for detailed comparison.

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/FRAMEWORK_README.md](docs/FRAMEWORK_README.md) | Framework architecture details |
| [docs/FEATURES.md](docs/FEATURES.md) | FZF integration, credentials, Mythic C2 |
| [docs/SERVICE_ANALYSIS.md](docs/SERVICE_ANALYSIS.md) | Service detection and smart filtering |
| [docs/INTERFACES.md](docs/INTERFACES.md) | Interface comparison guide |
| [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) | Contribution guidelines |
| [MODULE_TEMPLATE.psm](MODULE_TEMPLATE.psm) | Template for creating new modules |

---

## Installation

### Prerequisites

```bash
# Core tools
apt install fzf ripgrep

# Pentesting tools (install as needed)
apt install nmap feroxbuster sqlmap
pipx install netexec impacket
```

### Setup

```bash
git clone <repository>
cd purplesploit
chmod +x purplesploit-tui.sh
./purplesploit-tui.sh
```

---

## Creating Custom Modules

Add new tools by dropping a `.psm` file in `modules/`:

```bash
# modules/recon/custom/my_scan.psm
MODULE_NAME="recon/custom/my_scan"
MODULE_CATEGORY="recon"
MODULE_DESCRIPTION="My custom scan"
MODULE_TOOL="nmap"
REQUIRED_VARS="RHOST"
COMMAND_TEMPLATE="nmap -sV ${RHOST}"
```

Framework auto-discovers and loads it!

---

## Troubleshooting

### FZF not found
```bash
apt install fzf
```

### Database errors
Press `[j]` → Sessions Management → Database Management → Reset/Clear

### Module not loading
```bash
# Check syntax
bash -n modules/path/to/module.psm

# Check permissions
chmod +x modules/path/to/module.psm
```

---

## Project Structure

```
purplesploit/
├── purplesploit-tui.sh      # Main hybrid TUI (start here!)
├── MODULE_TEMPLATE.psm      # Template for new modules
├── README.md                # This file
├── bin/                     # Alternative interfaces
│   ├── purplesploit-framework.sh  # CLI interface
│   ├── purplesploit.sh            # Original lite
│   └── purplesploit-tui-simple.sh # Framework-only TUI
├── docs/                    # Documentation
├── framework/               # Framework backend
│   └── core/               # Core framework components
├── modules/                 # Tool modules (.psm files)
│   ├── recon/
│   ├── web/
│   ├── network/
│   └── c2/
├── core/                    # Lite version core
├── lib/                     # Lite version libraries
└── modules/*.sh             # Lite version tool handlers
```

---

## Contributing

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for:
- Code style guidelines
- How to add new tools
- How to create modules
- Pull request process

---

## License

MIT License - See LICENSE file for details

---

## Credits

Built with:
- [FZF](https://github.com/junegunn/fzf) - Fuzzy finder
- [NetExec](https://github.com/Pennyw0rth/NetExec) - Network execution tool
- [Impacket](https://github.com/fortra/impacket) - Network protocols toolkit
- And many more excellent open-source tools

---

<div align="center">

**Happy Hacking! 🎯**

[Report Issue](https://github.com/your-repo/issues) • [Request Feature](https://github.com/your-repo/issues)

</div>
