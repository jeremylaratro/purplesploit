# PurpleSploit TUI Mode

<div align="center">

```
 ██▓███   █    ██  ██▀███   ██▓███   ██▓    ▓█████   ██████  ██▓███   ██▓     ▒█████   ██▓▄▄▄█████▓
▓██░  ██▒ ██  ▓██▒▓██ ▒ ██▒▓██░  ██▒▓██▒    ▓█   ▀ ▒██    ▒ ▓██░  ██▒▓██▒    ▒██▒  ██▒▓██▒▓  ██▒ ▓▒
▓██░ ██▓▒▓██  ▒██░▓██ ░▄█ ▒▓██░ ██▓▒▒██░    ▒███   ░ ▓██▄   ▓██░ ██▓▒▒██░    ▒██░  ██▒▒██▒▒ ▓██░ ▒░
▒██▄█▓▒ ▒▓▓█  ░██░▒██▀▀█▄  ▒██▄█▓▒ ▒▒██░    ▒▓█  ▄   ▒   ██▒▒██▄█▓▒ ▒▒██░    ▒██   ██░░██░░ ▓██▓ ░
▒██▒ ░  ░▒▒█████▓ ░██▓ ▒██▒▒██▒ ░  ░░██████▒░▒████▒▒██████▒▒▒██▒ ░  ░░██████▒░ ████▓▒░░██░  ▒██▒ ░
▒▓▒░ ░  ░░▒▓▒ ▒ ▒ ░ ▒▓ ░▒▓░▒▓▒░ ░  ░░ ▒░▓  ░░░ ▒░ ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░░ ▒░▓  ░░ ▒░▒░▒░ ░▓    ▒ ░░
░▒ ░     ░░▒░ ░ ░   ░▒ ░ ▒░░▒ ░     ░ ░ ▒  ░ ░ ░  ░░ ░▒  ░ ░░▒ ░     ░ ░ ▒  ░  ░ ▒ ▒░  ▒ ░    ░
░░        ░░░ ░ ░   ░░   ░ ░░         ░ ░      ░   ░  ░  ░  ░░         ░ ░   ░ ░ ░ ▒   ▒ ░  ░
            ░        ░                  ░  ░   ░  ░      ░               ░  ░    ░ ░   ░

                      Full-Screen TUI Mode | Version 3.8
```

**Full-screen terminal interface for interactive offensive security operations**

[Features](#features) • [Quick Start](#quick-start) • [Navigation](#navigation) • [Menus](#menus) • [Examples](#examples)

</div>

---

## 📖 Overview

PurpleSploit TUI Mode provides a full-screen, menu-driven terminal interface for offensive security testing. Perfect for exploration, learning, and visual workflow management with mouse and keyboard support.

### Why TUI Mode?

- **Visual & Interactive** - See all options at a glance with organized menus
- **Mouse & Keyboard** - Point-and-click or keyboard navigation
- **Guided Workflows** - Organized menus guide you through operations
- **Context Awareness** - Visual display of targets, credentials, and workspace
- **Service Detection** - Automatic service detection with visual indicators
- **No Command Memorization** - Everything is menu-driven

---

## ✨ Features

### Core Features
- 🖥️ **Full-Screen Interface** - Organized category-based menus
- 🖱️ **Mouse Support** - Click to navigate and select
- ⌨️ **Keyboard Navigation** - Arrow keys, numbers, or vim-style (h/j/k/l)
- 🎨 **Rich Theming** - Color-coded menus and status indicators
- 📊 **Context Panel** - Always-visible workspace, target, and credential status
- 🔍 **Service Icons** - Visual service detection (SMB 🗄️, LDAP 📁, HTTP 🌐, etc.)

### Menu Categories
- **Web Testing** - Feroxbuster, SQLMap, Wfuzz, HTTPx
- **Network (NXC)** - SMB, LDAP, WinRM, RDP, MSSQL, SSH
- **Impacket** - PSExec, WMIExec, SecretsDump, Kerberoasting, ASREProast
- **Quick Access** - Direct shortcuts to SMB, LDAP, WinRM, MSSQL, RDP, SSH
- **AI Automation** - Automated workflow suggestions
- **Settings** - Workspace, target, credential, and variable management

---

## 🚀 Quick Start

### Launch TUI Mode

```bash
cd /path/to/purplesploit
bash purplesploit-tui.sh

# Or from Console mode
purplesploit> interactive
# or
purplesploit> i
```

### Basic Workflow

1. **Configure Settings**
   - Select "⚙️ Settings"
   - Set target: `192.168.1.100`
   - Set credentials: `administrator:Password123`

2. **Select Tool**
   - Navigate to "Network (NXC)" → "SMB"
   - Or use Quick Access → "SMB"

3. **Choose Operation**
   - Browse submenu (e.g., SMB Shares, Authentication)
   - Select desired operation
   - View real-time execution

---

## 🎯 Navigation

### Keyboard Controls

| Key | Action |
|-----|--------|
| **↑/↓** or **j/k** | Navigate menu items |
| **Enter** or **Space** | Select menu item |
| **Number (1-9)** | Quick select by number |
| **Esc** or **b** | Go back / Cancel |
| **q** | Quit (from main menu) |

### Mouse Controls

| Action | Result |
|--------|--------|
| **Click** | Select menu item |
| **Scroll** | Navigate long menus |

---

## 📋 Menu Structure

### Main Menu

```
╔════════════════════════════════════════════════════════╗
║              PurpleSploit Main Menu                    ║
╠════════════════════════════════════════════════════════╣
║                                                        ║
║  [1] 🌐 Web Testing                                   ║
║  [2] 🔧 Network (NXC)                                 ║
║  [3] 🎯 Impacket Suite                                ║
║  [4] 🗄️  SMB (Quick Access)                           ║
║  [5] 📁 LDAP (Quick Access)                           ║
║  [6] 🖥️  WinRM (Quick Access)                         ║
║  [7] 🗃️  MSSQL (Quick Access)                         ║
║  [8] 🖱️  RDP (Quick Access)                           ║
║  [9] 🔐 SSH (Quick Access)                            ║
║  [a] 🤖 AI Automation                                 ║
║  [s] ⚙️  Settings                                      ║
║  [q] ❌ Exit                                           ║
║                                                        ║
╚════════════════════════════════════════════════════════╝
```

### Context Panel

Always visible at the top of the screen:

```
╔════════════════════════════════════════════════════════╗
║  Workspace: default        Target: 192.168.1.100      ║
║  User: administrator       Domain: CORP               ║
║  Services: SMB ●  LDAP ●  HTTP ●  SSH ○               ║
╚════════════════════════════════════════════════════════╝
```

---

## 🔧 Menus in Detail

### 1. Web Testing Menu

```
╔════════════════════════════════════════════════════════╗
║                    Web Testing                         ║
╠════════════════════════════════════════════════════════╣
║  [1] 🔍 Feroxbuster - Directory Brute-forcing         ║
║  [2] 💉 SQLMap - SQL Injection                        ║
║  [3] 🔧 Wfuzz - Web Fuzzer                            ║
║  [4] 🌐 HTTPx - HTTP Probe                            ║
║  [b] ← Back                                            ║
╚════════════════════════════════════════════════════════╝
```

### 2. Network (NXC) Menu

```
╔════════════════════════════════════════════════════════╗
║              NetExec (NXC) Modules                     ║
╠════════════════════════════════════════════════════════╣
║  [1] 🗄️  SMB - File Sharing & Authentication          ║
║  [2] 📁 LDAP - Directory Services                     ║
║  [3] 🖥️  WinRM - Windows Remote Management            ║
║  [4] 🗃️  MSSQL - Database Server                      ║
║  [5] 🖱️  RDP - Remote Desktop                         ║
║  [6] 🔐 SSH - Secure Shell                            ║
║  [b] ← Back                                            ║
╚════════════════════════════════════════════════════════╝
```

### 3. SMB Submenu Example

```
╔════════════════════════════════════════════════════════╗
║                  SMB Operations                        ║
╠════════════════════════════════════════════════════════╣
║  SMB Shares                                            ║
║  [1] List Shares                                       ║
║  [2] Spider Plus (Deep Enumeration)                    ║
║                                                        ║
║  SMB Authentication                                    ║
║  [3] Test Authentication                               ║
║  [4] Password Spray                                    ║
║                                                        ║
║  SMB Sessions                                          ║
║  [5] List Sessions                                     ║
║  [6] List Logged-On Users                              ║
║                                                        ║
║  [b] ← Back                                            ║
╚════════════════════════════════════════════════════════╝
```

### 4. Settings Menu

```
╔════════════════════════════════════════════════════════╗
║                     Settings                           ║
╠════════════════════════════════════════════════════════╣
║  [1] 💼 Manage Workspaces                             ║
║  [2] 🎯 Manage Targets                                ║
║  [3] 🔑 Manage Credentials                            ║
║  [4] ⚙️  Set Variables (LHOST, etc.)                  ║
║  [5] 🔍 Run Service Scan                              ║
║  [6] 📋 Show Variables                                ║
║  [b] ← Back                                            ║
╚════════════════════════════════════════════════════════╝
```

---

## 🎨 Visual Features

### Service Detection Icons

| Service | Icon | Status |
|---------|------|--------|
| SMB | 🗄️ | Detected: ●  Not Found: ○ |
| LDAP | 📁 | Detected: ●  Not Found: ○ |
| WinRM | 🖥️ | Detected: ●  Not Found: ○ |
| MSSQL | 🗃️ | Detected: ●  Not Found: ○ |
| RDP | 🖱️ | Detected: ●  Not Found: ○ |
| SSH | 🔐 | Detected: ●  Not Found: ○ |
| HTTP | 🌐 | Detected: ●  Not Found: ○ |
| HTTPS | 🔒 | Detected: ●  Not Found: ○ |

### Color Coding

- **Primary (Magenta)** - Headers and borders
- **Secondary (Cyan)** - Menu items and highlights
- **Success (Green)** - Successful operations, detected services
- **Warning (Yellow)** - Warnings and important info
- **Danger (Red)** - Errors and critical issues
- **Info (Blue)** - Informational messages

---

## 💡 Workflows

### Workflow 1: SMB Enumeration

1. Launch TUI: `bash purplesploit-tui.sh`
2. Select **⚙️ Settings**
3. Choose **🎯 Manage Targets** → Add `192.168.1.100`
4. Choose **🔑 Manage Credentials** → Add `admin:Password123`
5. Return to main menu
6. Select **🗄️ SMB (Quick Access)**
7. Choose **List Shares**
8. View results in real-time

### Workflow 2: Web Testing with Service Detection

1. Launch TUI
2. **⚙️ Settings** → **🎯 Manage Targets** → `https://example.com`
3. **⚙️ Settings** → **🔍 Run Service Scan**
4. View detected services in context panel
5. Return to main menu
6. Select **🌐 Web Testing** → **🔍 Feroxbuster**
7. Execute directory brute-force

### Workflow 3: LDAP Bloodhound Collection

1. Set target domain controller
2. Configure credentials
3. Navigate: **🔧 Network (NXC)** → **📁 LDAP**
4. Select **Bloodhound Collection**
5. View collection progress
6. Export to Bloodhound

---

## 🔍 Service Detection

The TUI automatically detects services when you set a target:

```bash
# In Settings menu
[5] 🔍 Run Service Scan
  → Choose scan type: quick, full, or vuln
  → Results update context panel
  → Icons show detected services
```

Detected services appear with **●** (green dot)
Undetected services show **○** (gray dot)

---

## 💻 Advanced Features

### Workspace Management

- Create separate workspaces for different engagements
- Switch between workspaces
- Workspace-specific targets and credentials

### Variable Management

Set global variables:
- `LHOST` - Your IP address
- `THREADS` - Concurrent threads
- `TIMEOUT` - Operation timeout
- Custom variables

### AI Automation

Experimental AI-powered workflow suggestions:
- Analyzes current context (target, services)
- Suggests next steps
- Automates common workflows

---

## 🎯 Pro Tips

1. **Quick Access** - Use number keys for instant menu selection
2. **Service Scan First** - Run service scan to populate context panel
3. **Workspace per Target** - Create workspace for each engagement
4. **Keyboard Shortcuts** - Learn vim keys (j/k) for faster navigation
5. **Context Panel** - Always check context panel before running tools
6. **Direct Access** - Use Quick Access menus for common tools

---

## 🔧 Customization

### Theme Customization

Edit `python/purplesploit/tui/themes.py`:

```python
PURPLESPLOIT_THEME = Theme({
    "primary": "bold magenta",      # Change primary color
    "secondary": "bold cyan",        # Change secondary color
    # ... more customization options
})
```

### Menu Customization

Edit `python/purplesploit/tui/interactive_menu.py` to add or modify menus.

---

## 📖 Examples

### Example 1: First-Time Setup

```bash
# Launch TUI
bash purplesploit-tui.sh

# You see:
╔════════════════════════════════════════════════════════╗
║  Workspace: default        Target: Not Set            ║
║  User: Not Set             Domain: Not Set            ║
╚════════════════════════════════════════════════════════╝

# Press 's' or select [s] ⚙️ Settings
# Press '2' for Manage Targets
# Type: 192.168.1.100
# Press 'b' to go back
# Press '3' for Manage Credentials
# Enter username: administrator
# Enter password: Password123
# Press 'b' to return to main menu

# Now context shows:
╔════════════════════════════════════════════════════════╗
║  Workspace: default        Target: 192.168.1.100      ║
║  User: administrator       Domain:                    ║
╚════════════════════════════════════════════════════════╝
```

### Example 2: SMB Share Enumeration

```bash
# From main menu
# Press '4' for SMB (Quick Access)

# SMB submenu appears:
╔════════════════════════════════════════════════════════╗
║                  SMB Operations                        ║
╠════════════════════════════════════════════════════════╣
║  SMB Shares                                            ║
║  [1] List Shares                                       ║
║  [2] Spider Plus                                       ║
║  ...                                                   ║
╚════════════════════════════════════════════════════════╝

# Press '1' for List Shares
# Watch real-time output
# Press Enter when done to return to menu
```

---

## 🤝 Comparison: TUI vs Console Mode

| Feature | TUI Mode | Console Mode |
|---------|----------|--------------|
| Interface | Full-screen menus | Command-line (Metasploit-style) |
| Best For | Exploration, visual workflows | Scripting, automation, power users |
| Navigation | Mouse + keyboard | Keyboard only |
| Learning Curve | Easy (visual) | Moderate (commands to learn) |
| Context Display | Always visible panel | Query with commands |
| Service Icons | ✅ Visual indicators | ❌ Text only |
| Automation | ❌ Manual only | ✅ Scriptable |
| Speed | 🎯 Point and click | ⚡ Lightning fast (for experts) |

---

## 🔗 Switching Between Modes

### From Console to TUI

```bash
purplesploit> interactive
# or
purplesploit> i
```

### From TUI to Console

```bash
# Press 'q' to exit TUI
# Launch console:
python3 -m purplesploit.main
```

**Note:** Context (targets, credentials, workspace) is shared between modes!

---

## 📝 Notes

- TUI mode is perfect for learning and exploration
- All operations are also available in Console mode
- Context persists across mode switches
- Use TUI for visual feedback, Console for automation

---

## 🔗 See Also

- [Console Mode Documentation](../console-mode/README.md)
- [Module Development](../ARCHITECTURE.md)
- [Visual Enhancements](../VISUAL_ENHANCEMENTS.md)
- [Quick Start Guide](../../README.md)

---

<div align="center">

**PurpleSploit TUI Mode** - Visual offensive security, simplified.

*For command-line interface, see [Console Mode](../console-mode/README.md)*

</div>
