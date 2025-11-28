# PurpleSploit v6.7.0 Quick Start Guide

Get started with PurpleSploit in 5 minutes! Pure Python edition with enhanced auto-completion.

## 🚀 Installation

### Prerequisites
```bash
# Core dependencies
apt install fzf ripgrep python3

# Pentesting tools (recommended: Kali or Parrot)
apt install netexec impacket-scripts nmap feroxbuster sqlmap wfuzz httpx
```

### Setup
```bash
git clone https://github.com/jeremylaratro/purplesploit.git
cd purplesploit
```

---

## 🎯 Starting the Framework

### Launch PurpleSploit
**Pure Python interface with enhanced dropdown auto-completion**

```bash
# Using Python module
python3 -m purplesploit.main

# Or using the launcher script
./purplesploit-python
```

### Recent Updates
- **Mobile-Friendly Web Dashboard** (v6.7.0): Responsive design for tablets and phones
- **Enhanced Auto-Completion**: Context-aware dropdown menu with suggestions
- **Pure Python**: All bash/TUI components removed for better performance
- **Dynamic Suggestions**: Includes modules, targets, operations, and common commands
- **Improved History**: Better command history with auto-suggestions

---

## 📋 Framework Workflow

### Basic Commands

```bash
# Start console
python3 -m purplesploit.main

# Search for modules
purplesploit> search smb

# Load a module
purplesploit> use network/nxc_smb

# Set target and credentials
purplesploit(nxc_smb)> target 192.168.1.100
purplesploit(nxc_smb)> cred admin:password123

# Run with interactive operation selection
purplesploit(nxc_smb)> run
```

### Power Features

```bash
# Interactive fuzzy search (uses fzf)
purplesploit> module select

# Search operations across all modules
purplesploit> ops bloodhound

# Quick target + cred + execute
purplesploit> go 192.168.1.100 admin:pass
```

### Essential Commands

| Command | Description |
|---------|-------------|
| `search <term>` | Find modules |
| `use <module>` | Load module |
| `target <ip>` | Set target |
| `cred <user:pass>` | Set credentials |
| `run` | Execute (shows menu) |
| `info` | Module details |
| `help` | Full command list |

---

## 🎨 Enhanced Auto-Completion

### Dropdown Menu Features

PurpleSploit v6.0.0 includes an enhanced dropdown auto-completion menu:

- **Context-Aware**: Suggestions based on current state
- **Module Paths**: Auto-complete all available module paths
- **Target IPs**: Suggests previously added targets
- **Common Operations**: auth, enum, shares, dump, spray, etc.
- **Real-Time Updates**: Completer updates as you add targets/modules

### Using Auto-Completion

```bash
# Start typing and press TAB to see suggestions
purplesploit> tar[TAB]
  → target, targets

# Tab through module paths
purplesploit> use net[TAB]
  → network/nxc_smb, network/nxc_ldap, network/nxc_winrm...

# Auto-suggest from history
purplesploit> [Type previous command]
  → Grayed suggestion appears automatically
```

---

## 🎬 Example Workflows

### Quick SMB Enumeration

```bash
purplesploit> target 10.10.10.100
purplesploit> cred guest:
purplesploit> search smb shares
purplesploit> use 1
purplesploit(nxc_smb)> run
```

### Domain Enumeration

```bash
purplesploit> target 10.10.10.100
purplesploit> cred DOMAIN/user:password
purplesploit> ops bloodhound
purplesploit> ops select    # Pick LDAP Bloodhound
```

### Password Spraying

```bash
purplesploit> target 10.10.10.0/24
purplesploit> cred admin:Winter2024!
purplesploit> use network/nxc_smb
purplesploit(nxc_smb)> run
  → Select "Password Spray"
```

### Using Ligolo-ng for Pivoting

```bash
purplesploit> ligolo
# Full ligolo-ng interface launches
# Press CTRL+D to return to PurpleSploit
```

### Quick Shell Access

```bash
purplesploit> shell
# Drops to localhost shell
# Press CTRL+D to return to PurpleSploit
```

---

## 💡 Pro Tips

### Power User Features
1. **Interactive Selection**: Use `select` for interactive menus: `targets select`, `creds select`, `module select`
2. **Tab Completion**: Works for module paths, commands, and operations
3. **Recent Modules**: `recent` shows recently used modules
4. **Workspaces**: `workspace <name>` organizes engagement data
5. **Quick Commands**: `ligolo` for pivoting, `shell` for localhost shell

### Auto-Completion Tips
1. Press TAB to see all available options
2. Start typing to filter suggestions
3. Use arrow keys to navigate dropdown menu
4. ESC to cancel selection
5. Completer updates dynamically as you work

### Workflow Optimization
1. Workspaces keep engagement data separate
2. All data stored in `~/.purplesploit/`
3. Scan results auto-populate service detection
4. Use Kali/Parrot for best tool compatibility
5. Command history persists across sessions

---

## 🔍 Fuzzy Search Power

PurpleSploit uses **fzf** for lightning-fast fuzzy search:

```bash
# In console mode
purplesploit> search <query>     # Fuzzy find modules
purplesploit> ops <query>        # Search operations
purplesploit> module select      # Interactive browser
purplesploit> targets select     # Pick from targets
purplesploit> creds select       # Pick from creds
```

**Type to filter** - Matches anywhere in text
**↑↓ or Ctrl+J/K** - Navigate results
**Enter** - Select
**Esc** - Cancel

---

## 🆘 Troubleshooting

### "Command not found" errors
Install missing tools:
```bash
apt install netexec impacket-scripts
```

### "Module not loaded" in console
Use `use <module>` before running operations

### TUI seems frozen
Press `q` to quit, check for background processes

### Scans not working
Ensure you're running as root/sudo for network scans

---

## 📚 Next Steps

- **[Full README](README.md)** - Complete feature list
- **[Console Guide](docs/console-mode/README.md)** - Advanced commands
- **[Contributing](docs/CONTRIBUTING.md)** - Add your own Python modules
- **[Architecture](docs/ARCHITECTURE.md)** - Framework internals

---

## ⚠️ Legal Notice

**For authorized testing only.** See [DISCLAIMER.md](DISCLAIMER.md) for full terms.

- Only test systems you own or have written permission to test
- Unauthorized access to computer systems is illegal
- Users are responsible for compliance with all laws

---

<div align="center">

**Happy Hacking! 🎯**

*Pure Python. Enhanced Auto-Completion. Built for Speed.*

**Version 6.7.0 - Python Edition**

</div>
