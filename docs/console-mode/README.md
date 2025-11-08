# PurpleSploit Console Mode

<div align="center">

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║     ██████╗ ██╗   ██╗██████╗ ██████╗ ██╗     ███████╗███████╗██████╗         ║
║     ██╔══██╗██║   ██║██╔══██╗██╔══██╗██║     ██╔════╝██╔════╝██╔══██╗        ║
║     ██████╔╝██║   ██║██████╔╝██████╔╝██║     █████╗  ███████╗██████╔╝        ║
║     ██╔═══╝ ██║   ██║██╔══██╗██╔═══╝ ██║     ██╔══╝  ╚════██║██╔═══╝         ║
║     ██║     ╚██████╔╝██║  ██║██║     ███████╗███████╗███████║██║             ║
║     ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚══════╝╚═╝             ║
║                                                                               ║
║           ███████╗██████╗ ██╗      ██████╗ ██╗████████╗                      ║
║           ██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝                      ║
║           ███████╗██████╔╝██║     ██║   ██║██║   ██║                         ║
║           ╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║                         ║
║           ███████║██║     ███████╗╚██████╔╝██║   ██║                         ║
║           ╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝                         ║
║                                                                               ║
║              Metasploit-Style Offensive Security Framework                   ║
║                         Version 3.0 - Console Mode                           ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

**Metasploit-inspired command-line interface for offensive security operations**

[Features](#features) • [Quick Start](#quick-start) • [Commands](#commands) • [Workflows](#workflows) • [Examples](#examples)

</div>

---

## 📖 Overview

PurpleSploit Console Mode provides a Metasploit-style command-line interface for offensive security testing. It combines the power and flexibility of a command-line interface with modern features like interactive fuzzy search (fzf), smart context management, and operation submenus.

### Why Console Mode?

- **Metasploit-familiar interface** - If you know Metasploit, you already know PurpleSploit Console
- **Scriptable & automatable** - Perfect for automation and custom workflows
- **Fast keyboard-driven workflow** - No mouse required, optimized for speed
- **Interactive fuzzy search** - fzf integration for lightning-fast module/operation selection
- **Smart context tracking** - Automatically manages targets, credentials, and module state

---

## ✨ Features

### Core Features
- 🎯 **Smart Module System** - Browse modules with operations in tree view
- 🔍 **Interactive Selection** - fzf-powered fuzzy search for all commands
- 📋 **Context Management** - Track targets, credentials, and session state
- ⚡ **Quick Shortcuts** - Rapid workflows with `quick`, `go`, and `target` commands
- 🔄 **Operation Submenus** - Navigate module operations interactively
- 📊 **Rich Output** - Beautiful tables and formatted output

### Module Categories
- **Network** - SMB, LDAP, WinRM, RDP, MSSQL, SSH
- **Web** - Feroxbuster, SQLMap, Wfuzz, HTTPx
- **Impacket** - PSExec, WMIExec, SecretsDump, Kerberoasting
- **Recon** - Nmap, Service Detection

---

## 🚀 Quick Start

### Launch Console Mode

```bash
cd /path/to/purplesploit
python3 -m purplesploit.main
```

### Basic Workflow

```bash
# Search for modules
search smb

# Use interactive module selection
module select
  → Select "network/nxc_smb"
  → Select operation "List Shares"

# Or load directly
use network/nxc_smb

# Set target and credentials
target 192.168.1.100
cred administrator:Password123

# Run module with interactive operation selection
run
```

---

## 📚 Command Reference

### Module Commands

| Command | Description | Example |
|---------|-------------|---------|
| `search <query>` | Search for modules | `search smb` |
| `search select` | Interactive search results selection | `search smb` → `search select` |
| `module select` | Interactive module + operation browsing | `module select` |
| `use <module>` | Load a module | `use network/nxc_smb` |
| `use <number>` | Load from search results | `use 1` |
| `back` | Unload current module | `back` |
| `info` | Show module information | `info` |
| `options` | Show module options | `options` |
| `set <opt> <val>` | Set module option | `set RHOST 192.168.1.100` |
| `run` | Execute module (interactive) | `run` |
| `run <number>` | Execute specific operation | `run 1` |

### Smart Search Commands

| Command | Description | Example |
|---------|-------------|---------|
| `ops <query>` | Search operations globally | `ops bloodhound` |
| `ops select` | Interactive operation selection | `ops auth` → `ops select` |
| `recent` | Show recently used modules | `recent` |
| `recent select` | Interactive recent selection | `recent select` |

### Context Commands

| Command | Description | Example |
|---------|-------------|---------|
| `targets add <ip>` | Add a target | `targets add 192.168.1.100` |
| `targets list` | List all targets | `targets list` |
| `targets select` | Interactive target selection (fzf) | `targets select` |
| `creds add <u:p>` | Add credentials | `creds add admin:pass` |
| `creds select` | Interactive credential selection (fzf) | `creds select` |
| `services` | View detected services | `services` |
| `services select` | Interactive service selection (fzf) | `services select` |

### Quick Shortcuts

| Command | Description | Example |
|---------|-------------|---------|
| `target <ip>` | Quick add and set target | `target 192.168.1.100` |
| `cred <u:p>` | Quick add and set credential | `cred admin:pass` |
| `quick <mod>` | Quick load with auto-populate | `quick smb` |
| `go <tgt> <cred>` | All-in-one workflow | `go 192.168.1.100 admin:pass` |

### Show Commands

| Command | Description |
|---------|-------------|
| `show modules` | List all modules with operations (tree view) |
| `show targets` | List all targets |
| `show creds` | List all credentials |
| `show services` | List detected services |

---

## 🎯 Workflows

### 1. Interactive Module Browsing

```bash
# Launch interactive module browser with submenu navigation
module select

# Workflow:
# 1. Fuzzy search modules (type to filter)
# 2. Select module → automatically shows operations
# 3. Select operation → executes immediately
```

### 2. Quick SMB Enumeration

```bash
# One-liner approach
quick smb shares

# Or step-by-step
use network/nxc_smb
target 192.168.1.100
cred domain/user:password
run
  → Select "List Shares"
```

### 3. Search and Execute Operations

```bash
# Find all bloodhound-related operations
ops bloodhound

# Interactive selection from results
ops select
  → Selects and loads the module
```

### 4. Target-Credential-Execute

```bash
# Ultimate quick workflow
go 192.168.1.100 admin:Password123

# If module already loaded, runs operation
# Otherwise sets context for next module
```

---

## 🔍 Interactive Selection

All `select` commands use **fzf** when available for powerful fuzzy searching:

### Features
- ⌨️ **Type to filter** - Fuzzy search matches anywhere in text
- ⬆️⬇️ **Navigate** - Arrow keys or Ctrl+J/K
- 🖱️ **Mouse support** - Click to select
- ESC **Cancel** - Exit selection without choosing

### Example: Module Select Flow

```
module select
  → Shows all modules with fzf
  → Type "smb auth" to filter
  → Select "network/nxc_smb"
  → Automatically shows SMB operations
  → Select "Test Authentication"
  → Executes immediately
```

---

## 💡 Pro Tips

1. **Tab Completion** - Module paths support tab completion
2. **Number Selection** - After `search` or `show modules`, use `use <number>`
3. **Tree View** - `show modules` displays all operations indented under modules
4. **Context Persistence** - Targets and creds persist across module changes
5. **Quick Workflows** - Combine `target`, `cred`, and `quick` for rapid testing
6. **History** - Use `history` to see recent commands

---

## 🎨 Visual Enhancements

- ✨ Beautiful Rich-powered tables
- 🎨 Color-coded output (success=green, error=red, info=blue)
- 📊 Formatted module/operation trees
- 🔲 Box-drawing characters for clean layouts
- 🎯 Status indicators for all operations

---

## 🔧 Configuration

### Console Width
Default: 120 characters (adjustable in `ui/display.py`)

### Color Themes
Customize in `ui/display.py` using Rich markup

---

## 📖 Examples

### Example 1: SMB Share Enumeration

```bash
purplesploit> search smb
  1. [NETWORK] network/nxc_smb - NetExec SMB operations
     └─ List Shares
     └─ Test Authentication
     └─ Spider Plus

purplesploit> use 1
[+] Loaded module: NetExec SMB

purplesploit(nxc_smb)> target 192.168.1.100
[+] Target set to: 192.168.1.100

purplesploit(nxc_smb)> cred domain/admin:Password123
[+] Credential set: domain/admin

purplesploit(nxc_smb)> run
  → Select "List Shares"
[*] Running: List Shares
[+] Found 5 shares...
```

### Example 2: Global Operation Search

```bash
purplesploit> ops bloodhound
Found 2 operations matching 'bloodhound':
  1. NetExec LDAP
     Operation: Bloodhound Collection
     Collect data for Bloodhound analysis

  2. NetExec SMB
     Operation: Bloodhound Ingestor
     Run Bloodhound ingestor via SMB

purplesploit> ops select
  → Select "NetExec LDAP - Bloodhound Collection"
[*] Loading module: network/nxc_ldap
[+] Loaded module: NetExec LDAP
```

---

## 🤝 Comparison: Console vs TUI Mode

| Feature | Console Mode | TUI Mode |
|---------|--------------|----------|
| Interface | Command-line (like Metasploit) | Full-screen menu |
| Best For | Scripting, automation, power users | Visual navigation, exploration |
| Selection | fzf fuzzy search | Arrow key navigation |
| Speed | ⚡ Lightning fast | 🎯 Point and click |
| Automation | ✅ Excellent | ❌ Manual only |
| Learning Curve | Moderate (Metasploit-like) | Easy (visual) |

---

## 📝 Notes

- Console mode is the primary interface for automation and scripting
- All modules support both Console and TUI modes
- Context (targets/creds) is shared between modes
- Use `interactive` or `i` command to switch to TUI mode

---

## 🔗 See Also

- [TUI Mode Documentation](../tui-mode/README.md)
- [Module Development](../ARCHITECTURE.md)
- [Smart Features](../../SMART_FEATURES.md)
- [Quick Start Guide](../../README.md)

---

<div align="center">

**PurpleSploit Console Mode** - Command-line offensive security, simplified.

*For menu-driven interface, see [TUI Mode](../tui-mode/README.md)*

</div>
