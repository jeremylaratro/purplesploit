# PurpleSploit Interfaces

PurpleSploit Framework now offers **two different user interfaces** using the same powerful backend:

## 🎯 FZF TUI Interface (Recommended for Visual Navigation)

**Launch:** `./purplesploit-tui.sh`

### Features:
- **Visual menu-driven interface** - See all options at once
- **Service detection highlighting** - Starred (★) items are relevant to detected services
- **Quick keybinds** - Press single keys for common actions
- **Full-screen navigation** - Easy to browse and discover features
- **Context-aware** - Header shows current workspace, target, and credentials

### Keybinds:
- `t` - Targets menu
- `c` - Credentials menu
- `w` - Workspace menu
- `s` - View services
- `v` - Variables editor
- `q` - Quit

### Best For:
- Visual learners
- Quick navigation
- Discovering available modules
- Seeing context at a glance
- Users who prefer menu-driven tools

---

## ⌨️ Metasploit-Style CLI Interface

**Launch:** `./purplesploit-framework.sh`

### Features:
- **Command-line interface** - Type commands like Metasploit
- **Powerful command syntax** - Full control with text commands
- **Tab completion** - Fast for experienced users
- **Scriptable** - Can be automated
- **Familiar** - Similar to msfconsole

### Common Commands:
```bash
use <module>          # Select a module
set RHOST <target>    # Set target
show options          # View module options
run                   # Execute module
search <keyword>      # Find modules
help                  # Show all commands
```

### Quick Keybinds (also available):
- `s` - Select target
- `c` - Credentials menu
- `t` - Target help
- `v` - Variables editor

### Best For:
- Power users
- Automation/scripting
- Metasploit veterans
- Keyboard-first workflows
- Precise control

---

## Framework Backend (Both Use Same Features)

Both interfaces use the same powerful framework backend:

✅ **Universal Variable System** - ${VAR} substitution across all tools
✅ **Module Registry** - Auto-discovery of .psm modules
✅ **Workspace Management** - Per-engagement organization
✅ **Credential Database** - Multi-credential storage
✅ **Service Analysis** - Smart module recommendations based on nmap scans
✅ **Mythic C2 Integration** - Deploy agents via SMB, WinRM, PSExec, WMIExec
✅ **Background Jobs** - Run modules in background
✅ **Command History** - Browse and re-run commands
✅ **FZF Integration** - Interactive menus in both interfaces

---

## Switching Between Interfaces

You can use both! They share:
- Same workspaces
- Same credentials database
- Same targets
- Same scan results
- Same service detection data

Just launch the one you prefer for your current task.

---

## Recommendations

### Start with TUI if you:
- Are new to the framework
- Want to see all available options
- Prefer visual navigation
- Want quick access to common tasks

### Use CLI if you:
- Know exactly what module you want
- Prefer typing commands
- Are familiar with Metasploit
- Need to automate tasks
- Want minimal visual overhead

### Mix Both:
- Use TUI for discovery and quick tasks
- Use CLI for precise control and automation
- Switch as needed - they complement each other!
