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
> What it does TL;DR
- makes workflow efficient - no typing commands, credential application across all tools, auto analysis of scans
# PurpleSploit Walkthrough

## Overview

> PurpleSploit is a modular offensive security framework with both CLI and a web interface, largely modeled off metasploit framework, with many similar, common/shared commands for ease of use and familiarity. 

## Example workflow

Given targets and/or credentials:
```
Step A. Add targeting:
	1. `targets select` --> `creds select` 
	2. `targets add` --> `creds add` 
Step B. Select a command to run:
	3. `module select` -> `run op#`
	4. `search {object}` --> `use {module}` --> `run op#`
```
From 0-point (no targets, no creds):
```
Step A. Target Discovery: `module select` --> type `nmap` --> select scan & run
	Step B. Target Selection: `services` --> pick a target from scan results --> `targets select`
		Step C. Target Enumeration: `module select` -> `run op#` OR `search {object}` --> `use {module}` --> `run op#`
```
---
# Menu Items
### Search and Select

<img width="1015" height="349" alt="help_first" src="https://github.com/user-attachments/assets/fe01ec68-ce6a-48db-a888-f72b39af2d0e" />


**Key Commands**
Like metasploit, but with fzf for interactive select menus. To search for and select modules, you can use the traditional msf method, or use the interactive menu by adding select at the end of the command:

---
## Context Management
Add and manage targets, credentials, and wordlists. The context manager is made up of a series of sqlite databases that manages the context for the entire framework. No more "set RHOST" per modules. Select a target, select a credential, and **it will be applied to all modules automatically**. 

<img width="514" height="364" alt="management" src="https://github.com/user-attachments/assets/d4e0b0ad-afa0-43bc-a52b-4d5656f6bf3f" />

Context items can be added, modified, selected, and cleared. For example:

Simply type ```{command} clear``` to clear the database. 

----
## Credential and Target Management
Credentials and targets can be added, modified, listed, and selected interactively by appending the command after (ex. creds modify, targets select, etc.)

<img width="882" height="226" alt="creds" src="https://github.com/user-attachments/assets/28ea190f-478d-4895-9041-80ca891607e8" />

**Add Targets or Credentials:**

```bash
purplesploit > creds add username password domain

purplesploit > targets add IP_addr
```

**Modify Target or Credential:**

```bash
purplesploit > creds/targets modify

```

**List Targets or Credentials:**

```bash
purplesploit > creds/targets list
```


---
## Interactive Selection
Targets, credentials, and modules can be selected interactively with fzf. This feature includes type search, so you can either select by navigating with keyboard/mouse or by typing keywords:

<img width="527" height="314" alt="typingselect" src="https://github.com/user-attachments/assets/9ec797ce-3f23-4df2-a0c0-385bb93363e6" />

<img width="1231" height="473" alt="module_select" src="https://github.com/user-attachments/assets/f03137ae-db86-4c35-84ff-5cee3372a110" />

<img width="919" height="429" alt="creds_select" src="https://github.com/user-attachments/assets/2a868c08-6515-4257-a180-0d017b4d99c0" />

<img width="638" height="244" alt="targetselect" src="https://github.com/user-attachments/assets/b9bc0ac0-c11a-4704-873f-3cdb508d13e5" />

Use arrow keys to navigate, Enter to select. 

----
## Utilities

<img width="991" height="280" alt="utilities" src="https://github.com/user-attachments/assets/5dd4d462-d8b1-4e57-86e3-1d119e7edb45" />

**Available Commands:**

- `clear` - Clear screen
- `history` - Command history
- `stats` - Framework statistics
- `defaults <cmd>` - Manage default options
- `deploy` - Show deployment modules
- `deploy <type>` - Load specific deployment
- `webserver start/stop/status` - Web portal control
- `ligolo` - Launch ligolo-ng (Ctrl+D to return)
- `shell` - Local shell (Ctrl+D to return)

### Key Features 

**Deployment Utility** 
The deployment utility offers an automated method of deploying C2 beacons, ligolo agents, and scripts (ex. LinPEAS, WinPEAS, etc.).

**Ligolo**
Typing `ligolo` will drop you into a ligolo proxy shell. Press CTRL+D to go back to purplesploit cli. 

---
# Modules & Operations
Purplesploit diverges from metasploit by using a two-tier structure with modules and operations.  Modules represent the broader category, while operations are the switch-level differences within similar commands (ex. nxc_ssh module, individual ssh command differences are operations). Purplesploit was architected in this way to declutter while providing the largest amount of options.
## Module Search & Usage

<img width="693" height="455" alt="context_automation_ssh" src="https://github.com/user-attachments/assets/f98238e0-bfd3-444c-aaec-b3cac4551638" />

**Context Awareness**
If a search results in only one result, that result is automatically selected as the current module. 

**Workflows**:
1. Search for module or operation--> `use module` --> ops --> `run op#` 
2. `module select` --> type term --> scroll --> Enter --> ops --> `run op#`

**Usage**
To select modules:
```bash
use module_name
use {# of module}
```
Then:
```bash
run {# of operation}
```

Searching can be performed at the operation level as well, by typing:
```bash
ops {term}
ops smb auth
```
 

---
## Module Operations
Operations will be shown when selecting a module, but can shown again by typing `ops`

<img width="476" height="231" alt="ops" src="https://github.com/user-attachments/assets/514de91f-a096-475b-b915-8aa471747b06" />

Execute with: `run <number>` or `run <operation_name>`

---
## Show Categories
All context objects can be listed by running `show {command}` - ex. `show modules`:

<img width="952" height="972" alt="modularity" src="https://github.com/user-attachments/assets/da76fdff-c2dd-4767-835f-e07df882d12d" />

and growing!

---
## Service Detection
### Detection and Parsing
Purplesploit features an automated nmap parsing and detection capability. After running a scan, the results are parsed and added to purplesploit's database as targets and services.

<img width="770" height="926" alt="services" src="https://github.com/user-attachments/assets/bd0ce238-85b1-4739-96d7-bab2b77b1dea" />

IPs with open ports will automatically be added to the targets list, and services will be logged and viewable by typing:
```bash
show services
```


---
# Web Interface
### Target Dashboard

<img width="931" height="860" alt="webtargets" src="https://github.com/user-attachments/assets/ae3eb004-891b-4873-ac92-0d451a62eb4d" />

### Detailed Service View
<img width="688" height="850" alt="webtargets2" src="https://github.com/user-attachments/assets/4f0160a3-4c72-4a80-b002-040cf4c46fce" />

### Credential Manager

<img width="579" height="488" alt="webcredmanager" src="https://github.com/user-attachments/assets/c9fae726-fa3a-46f1-bc98-6b87e69eb6b3" />

### Web Sidebar
<img width="277" height="875" alt="websidebar" src="https://github.com/user-attachments/assets/e3d7f97a-a7ac-4483-867f-061a7b4e8e26" />

### Web Terminal
<img width="465" height="769" alt="webterminal" src="https://github.com/user-attachments/assets/53a7a528-e065-4dd6-9760-36e3d09972e9" />

Full terminal interface accessible via browser, showing same CLI commands and workflow.

---
## Quick Workflows

**Quick module loading:**

```bash
purplesploit > quick <module>
```

**All-in-one workflow:**

```bash
purplesploit > go <tgt> <cred>
```

**Show statistics:**

```bash
purplesploit > stats
```

Displays counts for modules, categories, targets, and credentials.

---

### Enhanced Features (v6.2.0)
- **Web Portal & API Server**: Comprehensive web interface with real-time target visualization at `http://localhost:5000`
- **Webserver Command**: Launch web portal in background with `webserver start` - continue using CLI while server runs
- **Real-time Database Sync**: Changes in CLI instantly appear in web portal and vice versa
- **Dropdown Auto-Completion**: Context-aware command suggestions with enhanced dropdown menu
- **Pure Python**: Completely rewritten in Python for better performance and maintainability
- **Dynamic Completions**: Auto-complete includes modules, targets, and common operations
- **Ligolo Integration**: Seamless proxy tunneling with `ligolo` command
- **Shell Access**: Quick localhost shell access with `shell` command

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

See [Contributing Guide](docs/CONTRIBUTING.md) for full module development guide.

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for:
- Adding new tools and modules
- Improving existing operations
- Documentation updates
- Bug reports and features

---

## License

**CC BY-NC-SA 4.0** (Non-Commercial) - See [LICENSE](LICENSE) for details.

Free to use, modify, and share for non-commercial purposes. Commercial use requires permission.

---

## Credits
Built with excellent open-source tools:
- [FZF](https://github.com/junegunn/fzf) - Fuzzy finder magic
- [NetExec](https://github.com/Pennyw0rth/NetExec) - Network execution
- [Impacket](https://github.com/fortra/impacket) - Protocol implementations
- And many more!

---

<div align="center">

[Report Issue](https://github.com/jeremylaratro/purplesploit/issues) • [Documentation](docs/) • [Discussions](https://github.com/jeremylaratro/purplesploit/discussions)


</div>
