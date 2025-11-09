# PurpleSploit Framework v3.5

<div align="center">

```
    ╔═══════════════════════════════════════════════════════════════════════════════╗
    ║                                                                               ║
 ██▓███   █    ██  ██▀███   ██▓███   ██▓    ▓█████   ██████  ██▓███   ██▓     ▒█████   ██▓▄▄▄█████▓
▓██░  ██▒ ██  ▓██▒▓██ ▒ ██▒▓██░  ██▒▓██▒    ▓█   ▀ ▒██    ▒ ▓██░  ██▒▓██▒    ▒██▒  ██▒▓██▒▓  ██▒ ▓▒
▓██░ ██▓▒▓██  ▒██░▓██ ░▄█ ▒▓██░ ██▓▒▒██░    ▒███   ░ ▓██▄   ▓██░ ██▓▒▒██░    ▒██░  ██▒▒██▒▒ ▓██░ ▒░
▒██▄█▓▒ ▒▓▓█  ░██░▒██▀▀█▄  ▒██▄█▓▒ ▒▒██░    ▒▓█  ▄   ▒   ██▒▒██▄█▓▒ ▒▒██░    ▒██   ██░░██░░ ▓██▓ ░ 
▒██▒ ░  ░▒▒█████▓ ░██▓ ▒██▒▒██▒ ░  ░░██████▒░▒████▒▒██████▒▒▒██▒ ░  ░░██████▒░ ████▓▒░░██░  ▒██▒ ░ 
▒▓▒░ ░  ░░▒▓▒ ▒ ▒ ░ ▒▓ ░▒▓░▒▓▒░ ░  ░░ ▒░▓  ░░░ ▒░ ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░░ ▒░▓  ░░ ▒░▒░▒░ ░▓    ▒ ░░   
░▒ ░     ░░▒░ ░ ░   ░▒ ░ ▒░░▒ ░     ░ ░ ▒  ░ ░ ░  ░░ ░▒  ░ ░░▒ ░     ░ ░ ▒  ░  ░ ▒ ▒░  ▒ ░    ░    
░░        ░░░ ░ ░   ░░   ░ ░░         ░ ░      ░   ░  ░  ░  ░░         ░ ░   ░ ░ ░ ▒   ▒ ░  ░      
            ░        ░                  ░  ░   ░  ░      ░               ░  ░    ░ ░   ░          
    ║                                                                               ║
    ║                  Automation Framework with Dual Interface                     ║
    ║                                 By d0sf3t                                     ║
    ║                          Search. Select. Exploit.                             ║
    ║                                                                               ║
    ╚═══════════════════════════════════════════════════════════════════════════════╝
```

**Metasploit-inspired framework for tool/workflow efficiency, with an emphasis on usability**

[Quick Start](#-quick-start) • [Key Features](#-the-power-trio) • [Installation](#-installation) • [Docs](docs/)

</div>

> **⚠️ LEGAL DISCLAIMER**: This tool is for **authorized security testing and educational purposes only**. Unauthorized access to computer systems is illegal. See [DISCLAIMER.md](DISCLAIMER.md) for full terms. Use responsibly and ethically.

#### Tools included

| Category | Tools |
|----------|-------|
| **Web** | Feroxbuster, SQLMap, Wfuzz, HTTPx |
| **Network (NXC)** | SMB, LDAP, WinRM, RDP, MSSQL, SSH |
| **Impacket** | PSExec, WMIExec, SecretsDump, Kerberoast |
| **Recon** | Nmap with auto-service detection |

**50+ operations** across all categories. Add your own with `.psm` modules.


#### What it does TL;DR
- makes workflow efficient - no typing commands, credential application across all tools, auto analysis of scans

#### Usage TL;DR:
search {item} - main search items
ops {items} - search individual run items
{item} select - interactive search with keyboard/mouse selection

#### Command workflow TL;DR
target select -- add and select new target
creds select - add and select creds
module select - select a module
options - verify info
run

#### Test workflow example TL;DR: 
- run nmap scan - tool parses it, identifies existing services and web services
    - auto adds all web ip:port pairs to web module dictionary to choose from
    - auto identifies running services, then run "search relevant" and only the discovered service modules will appear
- run relevant modules
- continue

Interactive selection use select keyword:
```bash
{keyword} select 
```

---

## 🎯 Main Features

### 1. 🔍 `search` - Find Anything Instantly
Fuzzy search across **all** modules and operations using fzf:

```bash
purplesploit> search smb enum
# Instantly finds:
# - network/nxc/smb/enum_users
# - network/nxc/smb/enum_shares
# - network/nxc/smb/enum_sessions
# ... and more
```

### 2. ⚡ `ops` - Cross-Category Operation Search
Search operations across **all categories** at once:

```bash
purplesploit> ops secretsdump
# Finds operations in multiple categories:
# [IMPACKET] SecretsDump - Domain Secrets
# [IMPACKET] SecretsDump - LSA Secrets
# [NXC/SMB] Dump SAM/Secrets
```

Type. Search. Execute. No menu diving.

### 3. 🎯 `{} select` - Interactive Selection Everywhere
**Every command** supports interactive selection with `{}`:

```bash
# Browse all modules interactively
purplesploit> module select {}

# Pick from all targets
purplesploit> target {}

# Choose credentials
purplesploit> cred {}

# Select any operation
purplesploit> run {}

# Works with EVERYTHING
purplesploit> workspace {}
```

**No typing, no memorizing** - just press `{}` and pick.

---

## 🚀 Quick Start

### Console Mode (Recommended)
```bash
# Start the framework
python3 -m purplesploit.main

# Workflow example
purplesploit> target 192.168.1.100
purplesploit> cred admin:password123
purplesploit> search smb shares        # Fuzzy search
purplesploit> run {}                   # Interactive select
```

### TUI Mode (Full-Screen Menu)
```bash
bash purplesploit-tui.sh
```
- Visual menu navigation
- Keyboard shortcuts (`t`=targets, `c`=creds, `j`=jobs)
- Service detection highlighting
- Switch to console anytime with `i`

---

## ✨ Core Features

### 🔄 Unified Context
Set once, use everywhere:
```bash
purplesploit> target 10.10.10.100
purplesploit> cred admin:pass
purplesploit> workspace pentest-2025
# Now ALL modules use these settings
```

### 🎭 Smart Service Detection
Scan with nmap → Framework highlights relevant tools:
```
● SMB Authentication     ← Detected SMB on target
● SMB Enumeration       ← These are now relevant
  LDAP Operations       ← Not detected, no marker
```

### 📂 Workspaces & Jobs
```bash
purplesploit> workspace create client-acme
purplesploit> jobs                    # Background execution
purplesploit> jobs list              # Monitor running scans
```


---

## 🎪 Example Workflows

### Quick SMB Enumeration
```bash
purplesploit> target 10.10.10.100
purplesploit> cred guest:
purplesploit> search smb enum
# Pick "Enumerate Shares" from results
```

### Multi-Target Testing
```bash
purplesploit> target add 10.10.10.0/24
purplesploit> cred admin:Winter2024!
purplesploit> run mode all           # Run against ALL targets
purplesploit> ops password spray     # Search and execute
```

### Interactive Browsing
```bash
purplesploit> module select {}       # Opens module tree
# Navigate: network → nxc → smb → [pick operation]
purplesploit> run                     # Execute selected module
```

---

## 📦 Installation

### Prerequisites
```bash
# Core dependencies
apt install fzf ripgrep python3

# Pentesting tools  - recommended use with kali or parrot. Tools used include:
```bash
netexec
wfuzz
sqlmap
feroxbuster
nmap
impacket
httpx
```

### Setup
```bash
git clone https://github.com/jeremylaratro/purplesploit.git
cd purplesploit

# Console mode
python3 -m purplesploit.main

# OR TUI mode
bash purplesploit-tui.sh
```

---

## 🎓 Quick Command Reference

| Command | What It Does | Example |
|---------|--------------|---------|
| `search <term>` | Fuzzy search modules/ops | `search kerberos` |
| `ops <term>` | Search operations only | `ops dump` |
| `module select {}` | Browse module tree | Interactive picker |
| `target {}` | Select/add targets | Pick from list |
| `cred {}` | Select credentials | Pick from database |
| `run {}` | Execute with selection | Choose operation |
| `workspace {}` | Switch workspace | Select workspace |
| `jobs list` | List background jobs | Monitor scans |
| `help` | Full command list | All commands |

**Pro tip**: Add `{}` to ANY command for interactive selection!

---

## 🎨 Interface Comparison

| Feature | Console Mode | TUI Mode |
|---------|--------------|----------|
| **Best For** | Power users, automation | Visual exploration |
| **Navigation** | Type commands | Menu + keyboard |
| **Speed** | Instant (if you know it) | Visual guidance |
| **Scripting** | Yes | No |
| **Search** | `search`, `ops`, `{}` | Built-in menus |

**Switch anytime**: Use `interactive` command in console or `q` to exit TUI.

---

## 📚 Documentation

- **[Quick Start Guide](QUICKSTART.md)** - Get started in 5 minutes
- **[Console Mode Guide](docs/console-mode/README.md)** - Metasploit-style CLI reference
- **[TUI Mode Guide](docs/tui-mode/README.md)** - Full-screen menu interface
- **[Contributing Guide](docs/CONTRIBUTING.md)** - Add your own modules
- **[Full Documentation](docs/)** - Complete guides and architecture

---

## 🔧 Creating Custom Modules

Drop a `.psm` file in `modules/` and it auto-loads:

```bash
# modules/custom/my_tool.psm
MODULE_NAME="custom/my_tool"
MODULE_CATEGORY="custom"
MODULE_DESCRIPTION="My custom scanner"
MODULE_TOOL="nmap"
REQUIRED_VARS="RHOST"
COMMAND_TEMPLATE="nmap -sV -p- ${RHOST}"
```

See [MODULE_TEMPLATE.psm](MODULE_TEMPLATE.psm) for full examples.

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for:
- Adding new tools and modules
- Improving existing operations
- Documentation updates
- Bug reports and features

---

## 📜 License

**CC BY-NC-SA 4.0** (Non-Commercial) - See [LICENSE](LICENSE) for details.

Free to use, modify, and share for non-commercial purposes. Commercial use requires permission.

---

## 🙏 Credits

Built with excellent open-source tools:
- [FZF](https://github.com/junegunn/fzf) - Fuzzy finder magic
- [NetExec](https://github.com/Pennyw0rth/NetExec) - Network execution
- [Impacket](https://github.com/fortra/impacket) - Protocol implementations
- And many more!

---

<div align="center">

**Happy Hacking! 🎯**

[Report Issue](https://github.com/jeremylaratro/purplesploit/issues) • [Documentation](docs/) • [Discussions](https://github.com/jeremylaratro/purplesploit/discussions)

*Built for red teamers, by red teamers*

</div>
