# PurpleSploit Framework v6.7.0

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

**Pure Python pentesting framework for tool/workflow efficiency, with an emphasis on usability**

[Quick Start](#-quick-start) • [Key Features](#-key-features) • [Installation](#-installation) • [Docs](docs/)

</div>

### Why?
This project is the result of multiple personal objectives that converged, having been wanting to make something that:
1. is highly useful - something that I would realistically use every day whether for pentesting profesionally or for CTFs.
2. automates, or makes a real world process that I use more efficient.
3. involves architecting a modular, scalable tool or framework.
The result is purplesploit, a tool based off the concept of metasploit but focused on efficiency and automation of pentesting workflows.     

> **⚠️ LEGAL DISCLAIMER**: This tool is for **authorized security testing and educational purposes only**. Unauthorized access to computer systems is illegal. See [DISCLAIMER.md](docs/DISCLAIMER.md) for full terms. Use responsibly and ethically.

#### Tools included

| Category | Tools |
|----------|-------|
| **Web** | Feroxbuster, SQLMap, Wfuzz, HTTPx |
| **Network (NXC)** | SMB, LDAP, WinRM, RDP, MSSQL, SSH |
| **Impacket** | PSExec, WMIExec, SecretsDump, Kerberoast |
| **Recon** | Nmap with auto-service detection |

**50+ operations** across all categories.


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

### 3. 🎯 `select` - Interactive Selection Everywhere
**Most commands** support interactive selection with `select`:

```bash
# Browse all modules interactively
purplesploit> module select

# Pick from all targets
purplesploit> targets select

# Choose credentials
purplesploit> creds select

# Select operations from search results
purplesploit> ops bloodhound
purplesploit> ops select

# Select from recent modules
purplesploit> recent select
```

**No typing, no memorizing** - just add `select` and pick from a menu.

---

## 🚀 Quick Start

### Start the Framework
```bash
# Start the Python framework
python3 -m purplesploit.main

# Or use the launcher script
./purplesploit-python

# Workflow example
purplesploit> target 192.168.1.100
purplesploit> cred admin:password123
purplesploit> search smb shares        # Fuzzy search
purplesploit> run {}                   # Interactive select
```

### Key Features (v6.7.0)
- **Mobile-Friendly Web Dashboard**: Responsive web interface optimized for tablets and phones at `http://localhost:5000`
- **Enhanced Context Management**: Comprehensive target/credential management with modify, clear, and bulk operations
- **Webserver Command**: Launch web portal in background with `webserver start` - continue using CLI while server runs
- **Real-time Database Sync**: Changes in CLI instantly appear in web portal and vice versa
- **Smart Auto-Completion**: Context-aware command suggestions with enhanced dropdown menu
- **Pure Python**: Completely rewritten in Python for better performance and maintainability
- **Interactive Selection**: fzf-powered fuzzy search for all commands with `select` subcommands
- **Ligolo Integration**: Seamless proxy tunneling with `ligolo` command
- **Shell Access**: Quick localhost shell access with `shell` command

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

# Start web portal in background
purplesploit> webserver start
```

---

## 🎓 Quick Command Reference

| Command | What It Does | Example |
|---------|--------------|---------|
| `search <term>` | Fuzzy search modules/ops | `search kerberos` |
| `ops <term>` | Search operations only | `ops dump` |
| `module select` | Browse module tree | Interactive picker |
| `targets select` | Select/add targets | Pick from list |
| `creds select` | Select credentials | Pick from database |
| `run` | Execute with selection | Choose operation |
| `workspace <name>` | Switch workspace | Select workspace |
| `webserver start/stop` | Control web portal | Manage dashboard |
| `help` | Full command list | All commands |

**Pro tip**: Most commands support `select` for interactive fuzzy search!

---

## 🎨 Interface Features

| Feature | Description |
|---------|-------------|
| **Auto-Completion** | Enhanced dropdown menu with context-aware suggestions |
| **Navigation** | Type commands or use interactive selectors with `{}` |
| **Speed** | Instant command execution with fuzzy search |
| **Scripting** | Full Python API for automation |
| **Search** | `search`, `ops`, `{}` for finding anything |
| **History** | Command history with suggestions from past commands |

---

## 📚 Documentation

- **[Quick Start Guide](QUICKSTART.md)** - Get started in 5 minutes
- **[Console Guide](docs/console-mode/README.md)** - Complete CLI reference
- **[Web Portal Guide](docs/WEB_PORTAL_GUIDE.md)** - Web interface documentation
- **[Contributing Guide](docs/CONTRIBUTING.md)** - Add your own modules
- **[Overview](docs/OVERVIEW.md)** - Framework architecture and design
- **[Full Documentation](docs/)** - Complete guides and API reference

---

## 🔧 Creating Custom Modules

Create Python modules that integrate seamlessly:

```python
# python/purplesploit/modules/custom/my_scanner.py
from purplesploit.core.module import ExternalToolModule

class MyScanner(ExternalToolModule):
    def __init__(self, framework):
        super().__init__(framework)
        self.name = "Custom Scanner"
        self.description = "My custom scanning tool"
        self.category = "custom"

        # Define options
        self.options = {
            'RHOST': {'value': None, 'required': True, 'description': 'Target host'},
        }

    def run(self):
        target = self.get_option('RHOST')
        return self.execute_command(f'nmap -sV {target}')
```

See [Contributing Guide](docs/CONTRIBUTING.md) for full module development guide.

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
