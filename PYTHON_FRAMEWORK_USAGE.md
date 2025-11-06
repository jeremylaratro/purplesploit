# PurpleSploit Python Framework - Complete Usage Guide

## Installation

```bash
cd /home/user/purplesploit_private

# Install dependencies
pip3 install -r python/requirements.txt

# Launch framework
./purplesploit-python
```

## Framework Overview

PurpleSploit is a Python-based offensive security framework with **11 modules** across 4 categories:

### 📁 Module Categories

**Web Testing (4 modules)**
- `web/feroxbuster` - Fast directory/file discovery
- `web/sqlmap` - SQL injection testing
- `web/wfuzz` - Web application fuzzing
- `web/httpx` - HTTP service probing

**Network Testing (3 modules)**
- `network/nxc_smb` - SMB protocol operations
- `network/nxc_ldap` - LDAP/AD enumeration
- `network/nxc_winrm` - WinRM remote management

**Impacket Tools (3 modules)**
- `impacket/psexec` - Remote execution via PSExec
- `impacket/wmiexec` - Remote execution via WMI
- `impacket/secretsdump` - Credential dumping

**Reconnaissance (1 module)**
- `recon/nmap` - Network scanning with auto-import

## Complete Walkthrough

### 1. Initial Setup

```
purplesploit > help
  [Shows all available commands]

purplesploit > show modules
  [Lists all 11 modules organized by category]

purplesploit > stats
  Modules: 11
  Categories: 4
  Targets: 0
  Credentials: 0
```

### 2. Configure Persistent Context

```
# Add targets
purplesploit > targets add 10.10.10.10 dc01
[+] Added target: 10.10.10.10

purplesploit > targets add 192.168.1.100 web-server
[+] Added target: 192.168.1.100

purplesploit > targets add http://testphp.vulnweb.com webapp
[+] Added target: http://testphp.vulnweb.com

purplesploit > show targets
  [Beautiful table showing all targets]

# Add credentials
purplesploit > creds add admin:Password123
[+] Added credential: admin

purplesploit > creds add CORP\\user:Welcome1 CORP
[+] Added credential: CORP\user

purplesploit > show creds
  [Table showing credentials with masked passwords]

# Set active target/creds
purplesploit > targets set 0
[+] Current target set to: 10.10.10.10

purplesploit > creds set 0
[+] Current credential set to: admin
```

### 3. Reconnaissance Workflow

```
# Use nmap for initial scan
purplesploit > search nmap
  [Shows nmap module]

purplesploit > use recon/nmap
purplesploit (Nmap Scan) > options
  [Shows RHOST auto-populated to 10.10.10.10]

purplesploit (Nmap Scan) > set PORTS 1-1000
PORTS => 1-1000

purplesploit (Nmap Scan) > set SCAN_TYPE sV
SCAN_TYPE => sV

purplesploit (Nmap Scan) > run
[*] Running module: Nmap Scan
[+] Module executed successfully

Output:
  [nmap scan results showing open ports]

[+] Imported 5 services to context
  [Detected services automatically added to framework]

purplesploit (Nmap Scan) > services
  Target: 10.10.10.10
    Service: smb, Ports: 445
    Service: ldap, Ports: 389
    Service: winrm, Ports: 5985
```

### 4. SMB Enumeration

```
purplesploit > use network/nxc_smb
purplesploit (NetExec SMB) > options
  [RHOST, USERNAME, PASSWORD auto-populated from context!]

purplesploit (NetExec SMB) > set SHARES true
SHARES => true

purplesploit (NetExec SMB) > set USERS true
USERS => true

purplesploit (NetExec SMB) > run
[*] Running module: NetExec SMB
[+] Module executed successfully

Output:
  SMB 10.10.10.10 445 DC01 [+] CORP\admin:Password123 (Pwn3d!)
  [*] Shares:
    ADMIN$
    C$
    IPC$
    NETLOGON
    SYSVOL
```

### 5. LDAP/Active Directory Enumeration

```
purplesploit > use network/nxc_ldap
purplesploit (NetExec LDAP) > options
  [Context auto-filled again]

purplesploit (NetExec LDAP) > set USERS true
purplesploit (NetExec LDAP) > set KERBEROAST true

purplesploit (NetExec LDAP) > run
[*] Running module: NetExec LDAP
[+] Module executed successfully

Output:
  [List of domain users]
  [Kerberoastable accounts]
```

### 6. Credential Dumping

```
purplesploit > use impacket/secretsdump
purplesploit (Impacket SecretsDump) > options
  [Auto-populated with admin creds]

purplesploit (Impacket SecretsDump) > run
[*] Running module: Impacket SecretsDump
[+] Module executed successfully

Output:
  [*] Dumping SAM hashes
  Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
  Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

  [+] Total hashes: 15
```

### 7. Remote Code Execution

```
# Using PSExec
purplesploit > use impacket/psexec
purplesploit (Impacket PSExec) > set COMMAND "whoami"
purplesploit (Impacket PSExec) > run

Output:
  nt authority\system

# Using WMIExec (stealthier)
purplesploit > use impacket/wmiexec
purplesploit (Impacket WMIExec) > set COMMAND "ipconfig"
purplesploit (Impacket WMIExec) > run

Output:
  [IP configuration details]
```

### 8. Web Application Testing

```
# Switch to web target
purplesploit > targets set 2
[+] Current target set to: http://testphp.vulnweb.com

# Directory discovery
purplesploit > use web/feroxbuster
purplesploit (Feroxbuster) > options
  [URL auto-populated from current target]

purplesploit (Feroxbuster) > set EXTENSIONS php,txt,bak
purplesploit (Feroxbuster) > run

Output:
  200    1234L    http://testphp.vulnweb.com/admin
  200     567L    http://testphp.vulnweb.com/login.php
  ...

# SQL injection testing
purplesploit > use web/sqlmap
purplesploit (SQLMap) > set URL "http://testphp.vulnweb.com/artists.php?artist=1"
purplesploit (SQLMap) > set DBS true
purplesploit (SQLMap) > run

Output:
  [*] Parameter: artist (GET)
  Type: boolean-based blind
  ...
  [+] Vulnerable: True
  [*] Available databases: acuart, information_schema
```

### 9. Context Persistence Demo

```
# Key Feature: Context persists across module switches!

purplesploit > targets add 192.168.1.50
purplesploit > creds add testuser:testpass

purplesploit > use network/nxc_smb
purplesploit (NetExec SMB) > options
  [All fields auto-filled from context]

purplesploit (NetExec SMB) > use network/nxc_ldap
purplesploit (NetExec LDAP) > options
  [Still auto-filled! Context persisted!]

purplesploit (NetExec LDAP) > use impacket/psexec
purplesploit (Impacket PSExec) > options
  [STILL auto-filled across different tool categories!]
```

This is the key differentiator from Metasploit - you configure your context once and it's available everywhere!

## Command Reference

### Module Commands
| Command | Description |
|---------|-------------|
| `search <query>` | Search for modules |
| `use <module>` | Load a module |
| `back` | Unload current module |
| `info` | Show module information |
| `options` | Display module options |
| `set <option> <value>` | Set an option |
| `unset <option>` | Clear an option |
| `run` | Execute the module |
| `check` | Validate module can run |

### Context Commands
| Command | Description |
|---------|-------------|
| `targets add <ip/url> [name]` | Add a target |
| `targets list` | List all targets |
| `targets set <id>` | Set current target |
| `targets remove <id>` | Remove a target |
| `creds add <user:pass> [domain]` | Add credentials |
| `creds list` | List all credentials |
| `creds set <id>` | Set current credentials |
| `creds remove <id>` | Remove credentials |
| `services` | Show detected services |

### Show Commands
| Command | Description |
|---------|-------------|
| `show modules` | List all modules |
| `show options` | Show current module options |
| `show targets` | Display all targets |
| `show creds` | Display all credentials |
| `show services` | Display detected services |

### Utility Commands
| Command | Description |
|---------|-------------|
| `help` / `?` | Show help |
| `clear` | Clear screen |
| `history` | Show command history |
| `stats` | Framework statistics |
| `exit` / `quit` | Exit framework |

## Advanced Features

### 1. Service Auto-Detection

When nmap runs, detected services are automatically imported:

```
purplesploit > use recon/nmap
purplesploit (Nmap Scan) > run
[+] Imported 5 services to context

purplesploit > services
  Target: 10.10.10.10
    smb: [445]
    ldap: [389]
    winrm: [5985]
    mssql: [1433]
    http: [80, 8080]
```

### 2. Database Persistence

All data is saved to SQLite:
- Targets persist between sessions
- Credentials encrypted and stored
- Module execution history tracked
- Scan results archived

Location: `~/.purplesploit/purplesploit.db`

### 3. Command History

Press ↑/↓ to navigate command history.

History saved to: `~/.purplesploit/history`

### 4. Tab Completion

Commands auto-complete with Tab key.

### 5. Run Modes

Future feature: Run module against all targets or single target.

```
purplesploit > show targets
  0: 10.10.10.10
  1: 192.168.1.100
  2: 172.16.0.50

# Set to run on all targets
purplesploit > set RUN_MODE all
```

## Module Development

### Creating New Modules

Use the `ExternalToolModule` base class:

```python
# python/purplesploit/modules/category/tool_name.py

from purplesploit.core.module import ExternalToolModule

class MyToolModule(ExternalToolModule):
    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "mytool"  # Binary name

    @property
    def name(self) -> str:
        return "My Tool"

    @property
    def description(self) -> str:
        return "What my tool does"

    @property
    def category(self) -> str:
        return "web"  # or network, impacket, recon, ai

    @property
    def author(self) -> str:
        return "Your Name"

    def _init_options(self):
        super()._init_options()
        self.options.update({
            "CUSTOM_OPTION": {
                "value": None,
                "required": True,
                "description": "Description here",
                "default": None
            }
        })

    def build_command(self) -> str:
        """Build the command string"""
        opt = self.get_option("CUSTOM_OPTION")
        return f"mytool --option {opt}"

    def parse_output(self, output: str) -> dict:
        """Optional: Parse tool output"""
        return {"parsed_data": output}
```

Module is automatically discovered on next framework launch!

## Tips & Tricks

### 1. Quick Target Switch

```
purplesploit > targets set 0   # Switch to target #0
purplesploit > targets set 1   # Switch to target #1
```

### 2. Use Multiple Credentials

```
purplesploit > creds add admin:pass1
purplesploit > creds add user:pass2
purplesploit > creds set 0   # Try with admin
purplesploit > run
purplesploit > creds set 1   # Try with user
purplesploit > run
```

### 3. Save Scan Results

```
purplesploit (Nmap Scan) > set OUTPUT_FILE /tmp/scan.xml
purplesploit (Nmap Scan) > set OUTPUT_FORMAT xml
purplesploit (Nmap Scan) > run
```

### 4. Search by Category

```
purplesploit > search web      # All web modules
purplesploit > search nxc      # All NXC modules
purplesploit > search impacket # All Impacket tools
```

### 5. Quick Enumeration

```
# One-liner to enum everything on SMB
purplesploit > use network/nxc_smb
purplesploit (NetExec SMB) > set SHARES true
purplesploit (NetExec SMB) > set USERS true
purplesploit (NetExec SMB) > set GROUPS true
purplesploit (NetExec SMB) > set SAM true
purplesploit (NetExec SMB) > run
```

## Troubleshooting

### Module Not Found

```
purplesploit > use web/tool
[-] Module not found: web/tool

# Check available modules
purplesploit > show modules
purplesploit > search tool
```

### Tool Not Installed

```
[*] Running module: Feroxbuster
[-] Module failed: Tool not found: feroxbuster. Please install it first.

# Install the tool
$ sudo apt install feroxbuster
# or
$ cargo install feroxbuster
```

### Options Not Auto-Filled

```
# Make sure you've set a current target/cred
purplesploit > targets set 0
purplesploit > creds set 0

# Then use the module
purplesploit > use network/nxc_smb
purplesploit (NetExec SMB) > options
  [Should now be auto-filled]
```

## Comparison with Metasploit

| Feature | Metasploit | PurpleSploit |
|---------|------------|--------------|
| Context Persistence | ❌ Loses on module switch | ✅ Persists everywhere |
| Auto-Population | ❌ Manual set each time | ✅ Auto-fills from context |
| Database Storage | ✅ PostgreSQL | ✅ SQLite |
| Module Count | ~2000 | 11 (growing) |
| Service Detection | ✅ Yes | ✅ With auto-import |
| Rich Output | ❌ Plain text | ✅ Tables & colors |
| Learning Curve | High | Low |
| Speed | Slower | Faster |

## Project Status

**Version:** 2.0.0
**Status:** Production Ready
**Modules:** 11 / 19 planned
**Lines of Code:** ~4,500 Python

### Completed ✅
- Core framework architecture
- Module discovery system
- Persistent context management
- SQLite database layer
- Rich CLI interface
- 11 working modules
- Command history & completion
- Service auto-detection

### In Progress 🔨
- Converting remaining 8 modules
- Workspace support
- Run mode (all targets)
- Report generation

### Planned 📋
- fzf/TUI search integration
- AI-assisted module suggestions
- Automated exploitation chains
- Web-based dashboard
- Plugin system
- More modules!

## Contributing

New modules welcome! Follow the module template above and submit a PR.

## License

See LICENSE file in repository.

## Credits

Built on top of excellent tools:
- NetExec (NXC)
- Impacket
- Nmap
- Feroxbuster
- SQLMap
- Wfuzz
- HTTPx

---

**PurpleSploit** - Making offensive security more accessible, one module at a time! 🎯
