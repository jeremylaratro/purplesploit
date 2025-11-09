# PurpleSploit Quick Start Guide

Get started with PurpleSploit in 5 minutes! Choose your preferred interface:

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

## 🎯 Choose Your Interface

PurpleSploit offers two interfaces:

### Console Mode (Metasploit-Style CLI)
**Best for:** Power users, scripting, automation

```bash
python3 -m purplesploit.main
```

### TUI Mode (Full-Screen Menu)
**Best for:** Visual exploration, beginners, interactive workflows

```bash
bash purplesploit-tui.sh
```

---

## 📋 Console Mode Workflow

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

## 🖥️ TUI Mode Workflow

### Navigation

```bash
# Start TUI
bash purplesploit-tui.sh

# Navigation keys:
# - Numbers (1-9) to select menu items
# - 'b' or 'back' to go back
# - 'q' or 'quit' to exit
```

### First Steps

1. **Configure Settings** → Select "Settings" from main menu
2. **Add Target** → Manage Targets → (a)dd → Enter IP
3. **Set Credentials** → Manage Credentials → (u)sername/password
4. **Run Scan** → Run Service Scan → Choose scan type
5. **Execute Tools** → Back to main menu → Select tool category

### Service Detection

After scanning, TUI highlights relevant tools:
- 🗄️ **SMB** - Green when detected
- 📁 **LDAP** - Service-aware highlighting
- 🖥️ **WinRM** - Auto-detected protocols
- 🗃️ **MSSQL** - Focus on available services

---

## 🎬 Example Workflows

### Quick SMB Enumeration

**Console Mode:**
```bash
purplesploit> target 10.10.10.100
purplesploit> cred guest:
purplesploit> search smb shares
purplesploit> use 1
purplesploit(nxc_smb)> run
```

**TUI Mode:**
1. Settings → Manage Targets → Add `10.10.10.100`
2. Settings → Manage Credentials → guest (no password)
3. Main Menu → SMB Operations → List Shares

### Domain Enumeration

**Console Mode:**
```bash
purplesploit> target 10.10.10.100
purplesploit> cred DOMAIN/user:password
purplesploit> ops bloodhound
purplesploit> ops select    # Pick LDAP Bloodhound
```

**TUI Mode:**
1. Settings → Add target + domain credentials
2. Settings → Run Service Scan
3. Main Menu → LDAP Operations → Bloodhound Collection

### Password Spraying

**Console Mode:**
```bash
purplesploit> target 10.10.10.0/24
purplesploit> cred admin:Winter2024!
purplesploit> use network/nxc_smb
purplesploit(nxc_smb)> run
  → Select "Password Spray"
```

**TUI Mode:**
1. Settings → Manage Targets → Add CIDR range
2. Settings → Set credential
3. Main Menu → SMB Operations → Password Spray

---

## 💡 Pro Tips

### Console Mode
1. Use `{}` for interactive selection: `target {}`, `cred {}`, `run {}`
2. Tab completion works for module paths
3. `recent` shows recently used modules
4. `workspace <name>` organizes engagement data

### TUI Mode
1. Service icons turn green when detected - focus there!
2. Context panel (top) always shows current target/creds
3. Press `i` to switch to console mode anytime
4. Use `back` repeatedly to navigate up menu tree

### Both Modes
1. Workspaces keep engagement data separate
2. All data stored in `~/.purplesploit/`
3. Scan results auto-populate service detection
4. Use Kali/Parrot for best tool compatibility

---

## 🔍 Fuzzy Search Power

PurpleSploit uses **fzf** for lightning-fast fuzzy search:

```bash
# In console mode
purplesploit> search <query>     # Fuzzy find modules
purplesploit> ops <query>        # Search operations
purplesploit> module select      # Interactive browser
purplesploit> target {}          # Pick from targets
purplesploit> cred {}            # Pick from creds
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
- **[Console Mode Guide](docs/console-mode/README.md)** - Advanced commands
- **[TUI Mode Guide](docs/tui-mode/README.md)** - Menu reference
- **[Contributing](docs/CONTRIBUTING.md)** - Add your own modules

---

## ⚠️ Legal Notice

**For authorized testing only.** See [DISCLAIMER.md](DISCLAIMER.md) for full terms.

- Only test systems you own or have written permission to test
- Unauthorized access to computer systems is illegal
- Users are responsible for compliance with all laws

---

<div align="center">

**Happy Hacking! 🎯**

*Choose your weapon: Console for speed, TUI for exploration*

</div>
