# PurpleSploit

A comprehensive penetration testing framework that combines NetExec (NXC) with an interactive command-line interface for network reconnaissance, Active Directory assessment, and web application testing.

## Overview

PurpleSploit provides a unified testing platform that integrates:
- **NetExec (NXC)**: Powerful network service exploitation and enumeration
- **Navi**: Interactive cheatsheet system for quick command access
- **Unified CLI**: Menu-driven interface for managing targets, credentials, and automated testing workflows

## Features

### Core Capabilities

- **Multi-Protocol Support**: SMB, LDAP, WinRM, MSSQL, RDP, SSH, FTP
- **Credential Management**: Store and manage multiple credential sets
- **Target Management**: Organize network targets, web targets, and AD environments
- **Interactive Commands**: Quick access to 200+ NXC commands via searchable cheatsheet
- **Automated Workflows**: Execute common testing scenarios with minimal input
- **Session Persistence**: Remember credentials and targets across sessions

### Testing Categories

#### Network Testing
- Authentication testing (pass-the-hash, pass-the-ticket, etc.)
- Share enumeration and file discovery
- User and group enumeration
- Remote command execution
- Credential dumping (SAM, LSA, NTDS)

#### Active Directory Testing
- Domain enumeration
- BloodHound data collection
- Trust enumeration
- Certificate Services (ADCS) discovery
- Group Policy Object (GPO) analysis
- Kerberos attacks

#### Vulnerability Checks
- MS17-010 (EternalBlue)
- Zerologon (CVE-2020-1472)
- PetitPotam
- NoPac
- SMBGhost
- PrintNightmare

#### Web Application Testing
- URL/target management
- Integration with web testing tools

## Installation

### Prerequisites

- Linux (Debian/Ubuntu/Kali) or macOS
- Python 3.8+
- Git
- Bash

### Quick Install

```bash
# Clone the repository
git clone https://github.com/jeremylaratro/purplesploit.git
cd purplesploit

# Run the setup script
./setup-nxc-navi.sh
```

The setup script will:
1. Install Navi (interactive cheatsheet tool)
2. Install NetExec if not present
3. Configure NXC cheatsheet for Navi
4. Setup shell integration (Ctrl+G keyboard shortcut)
5. Create configuration files

### Manual Installation

If you prefer manual installation:

```bash
# Install NetExec
pipx install netexec
# or
pip install netexec

# Install Navi
bash <(curl -sL https://raw.githubusercontent.com/denisidoro/navi/master/scripts/install)

# Setup Navi cheatsheet
mkdir -p ~/.config/navi/cheats
cp nxc-fixed.cheat ~/.config/navi/cheats/nxc.cheat

# Add shell integration to ~/.bashrc or ~/.zshrc
eval "$(navi widget bash)"  # for bash
eval "$(navi widget zsh)"   # for zsh
```

## Usage

### Interactive Framework (plat02.sh)

Launch the main interactive interface:

```bash
./plat02.sh
```

#### Main Menu Options

1. **Credential Management**
   - Add/edit/delete credential sets
   - View stored credentials
   - Select active credentials

2. **Target Management**
   - Add network targets (IPs, ranges, subnets)
   - Add web targets (URLs)
   - Add AD targets (domains, DCs)
   - Import targets from files

3. **Quick Actions**
   - Test authentication
   - Enumerate users/groups/shares
   - Dump credentials
   - Execute commands
   - Check vulnerabilities

4. **Advanced Testing**
   - Custom NXC commands
   - Multi-target scanning
   - Automated workflows

### Navi Cheatsheet

Access the interactive command cheatsheet:

```bash
# Launch Navi
navi

# Or use keyboard shortcut anywhere in terminal
Ctrl+G
```

#### Searching Commands

```bash
# Search by keyword
navi
> smb enumeration

# Search by protocol
navi --tag-rules nxc,ldap

# Direct query
navi --query "dump credentials"

# List all SMB commands
navi --tag-rules nxc,smb
```

#### Common Workflows

**Authenticate to Target:**
```bash
navi
> Search: "test authentication"
> Select: smb/ldap/winrm
> Fill in: target, username, password
> Execute
```

**Enumerate Domain Users:**
```bash
navi
> Search: "enumerate users"
> Fill in: credentials
> Execute
```

**Dump Credentials:**
```bash
navi
> Search: "dump"
> Select: SAM, LSA, or NTDS
> Execute
```

**Check for Vulnerabilities:**
```bash
navi
> Search: "ms17-010" or "zerologon"
> Fill in: target
> Execute
```

## Command Reference

### Authentication Methods

```bash
# Password authentication
nxc smb <target> -u <username> -p <password>

# Domain authentication
nxc smb <target> -u <username> -p <password> -d <domain>

# Pass-the-hash
nxc smb <target> -u <username> -H <ntlm_hash>

# Local authentication
nxc smb <target> -u <username> -p <password> --local-auth

# Anonymous/null session
nxc smb <target> -u '' -p ''
```

### Enumeration

```bash
# List shares
nxc smb <target> -u <user> -p <pass> --shares

# Enumerate users
nxc smb <target> -u <user> -p <pass> --users

# Enumerate groups
nxc smb <target> -u <user> -p <pass> --groups

# Get password policy
nxc smb <target> -u <user> -p <pass> --pass-pol

# List logged-on users
nxc smb <target> -u <user> -p <pass> --loggedon-users
```

### Credential Dumping

```bash
# Dump SAM database
nxc smb <target> -u <user> -p <pass> --sam

# Dump LSA secrets
nxc smb <target> -u <user> -p <pass> --lsa

# Dump NTDS.dit (Domain Controller)
nxc smb <target> -u <user> -p <pass> --ntds

# Extract with lsassy module
nxc smb <target> -u <user> -p <pass> -M lsassy
```

### Remote Execution

```bash
# Execute command
nxc smb <target> -u <user> -p <pass> -x 'whoami'

# Execute PowerShell
nxc smb <target> -u <user> -p <pass> -X 'Get-Process'

# WinRM execution
nxc winrm <target> -u <user> -p <pass> -x 'systeminfo'
```

### Advanced Features

```bash
# Spider shares for files
nxc smb <target> -u <user> -p <pass> -M spider_plus

# Collect BloodHound data
nxc ldap <target> -u <user> -p <pass> -d <domain> -M bloodhound -o COLLECTION=All

# Check for MS17-010
nxc smb <target> -M ms17-010

# Scan subnet
nxc smb 192.168.1.0/24 -u <user> -p <pass>

# Generate relay target list
nxc smb <subnet> --gen-relay-list relay_targets.txt
```

## Configuration

### Database Files

PurpleSploit stores data in your home directory:

- `~/.pentest-credentials.db` - Stored credentials
- `~/.pentest-targets.db` - Network targets
- `~/.pentest-web-targets.db` - Web targets
- `~/.pentest-ad-targets.db` - Active Directory targets

### Navi Configuration

- Config: `~/.config/navi/config.yaml`
- Cheatsheet: `~/.config/navi/cheats/nxc.cheat`

Edit cheatsheet:
```bash
nano ~/.config/navi/cheats/nxc.cheat
```

### Shell Integration

Add to your shell RC file for Ctrl+G keyboard shortcut:

```bash
# Bash (~/.bashrc)
eval "$(navi widget bash)"

# Zsh (~/.zshrc)
eval "$(navi widget zsh)"

# Fish (~/.config/fish/config.fish)
navi widget fish | source
```

## Examples

### Example 1: Domain Enumeration

```bash
# Launch framework
./plat02.sh

# Add credentials
> Add New Credential
  Name: DomainAdmin
  Username: administrator
  Password: P@ssw0rd123
  Domain: CORP

# Add target
> Add New Target
  Name: DC01
  Target: 192.168.1.10

# Select and test
> Select credential and target
> Run: Enumerate Users
```

### Example 2: Credential Dumping

```bash
# Use Navi for quick command
navi

# Search
> "dump credentials"

# Select option
> nxc smb <target> -u <user> -p <pass> --sam --lsa

# Fill in values and execute
```

### Example 3: Subnet Scanning

```bash
nxc smb 192.168.1.0/24 -u administrator -p 'P@ssw0rd123' --shares
```

### Example 4: BloodHound Collection

```bash
nxc ldap 192.168.1.10 -u administrator -p 'P@ssw0rd123' -d CORP.LOCAL -M bloodhound -o COLLECTION=All
```

## Keyboard Shortcuts

### Navi Shortcuts
- `Ctrl+G` - Open Navi from anywhere in terminal
- `Ctrl+R` - Alternative shortcut (if configured)
- `Ctrl+C` - Cancel/Exit
- `Tab` - Navigate between input fields
- `Enter` - Execute command
- `Esc` - Go back

### Framework Shortcuts
- Arrow keys - Navigate menus
- Enter - Select option
- `q` or Ctrl+C - Exit/Back

## Troubleshooting

### Navi not found
```bash
# Reload shell configuration
source ~/.bashrc  # or ~/.zshrc

# Or restart your terminal
```

### Cheatsheet not showing
```bash
# Check if cheatsheet exists
ls ~/.config/navi/cheats/nxc.cheat

# Browse navi repositories
navi repo browse
```

### Ctrl+G not working
```bash
# Add to your shell RC file
echo 'eval "$(navi widget bash)"' >> ~/.bashrc
source ~/.bashrc
```

### NetExec not found
```bash
# Install with pipx (recommended)
pipx install netexec

# Or with pip
pip install netexec --break-system-packages
```

### Permission denied on database files
```bash
# Fix permissions
chmod 600 ~/.pentest-*.db
```

## Best Practices

### Security
- Store credentials securely - database files are chmod 600
- Clear credential history after engagements
- Use dedicated testing systems
- Follow responsible disclosure practices

### Workflow
- Document findings as you go
- Use descriptive names for targets and credentials
- Leverage session persistence for efficiency
- Validate results with multiple methods

### Performance
- Use specific protocols when possible
- Limit concurrent connections for stability
- Use smaller target ranges for initial testing
- Save output to files for later analysis

## Advanced Usage

### Custom Modules

Add custom NXC modules to your cheatsheet:

```bash
nano ~/.config/navi/cheats/nxc.cheat
```

Format:
```
% nxc, custom, tag

# Description of command
nxc <protocol> <target> -u <username> -p <password> -M <module>

$ target: echo "192.168.1.10"
$ username: echo "admin"
$ password: echo "password"
$ module: echo "custom_module"
```

### Scripting

Use the framework in scripts:

```bash
#!/bin/bash
# Automated domain assessment

# Source the framework functions
source plat02.sh

# Add target programmatically
echo "DC01|192.168.1.10" >> ~/.pentest-targets.db

# Run NXC commands
nxc smb 192.168.1.10 -u admin -p pass --users > users.txt
nxc smb 192.168.1.10 -u admin -p pass --groups > groups.txt
```

### Output Management

```bash
# Log to file
nxc smb <target> -u <user> -p <pass> --log output.log

# Export to CSV
nxc smb <target> -u <user> -p <pass> --shares --export shares.csv

# Verbose output
nxc smb <target> -u <user> -p <pass> -v

# Debug mode
nxc smb <target> -u <user> -p <pass> -vv
```

## Documentation

- **QUICKSTART.txt** - Quick reference guide for Navi commands
- **nxc-fixed.cheat** - Complete NXC command cheatsheet
- **setup-nxc-navi.sh** - Installation script source code

## Resources

### Official Documentation
- [NetExec Wiki](https://www.netexec.wiki/)
- [NetExec GitHub](https://github.com/Pennyw0rth/NetExec)
- [Navi GitHub](https://github.com/denisidoro/navi)

### Learning Resources
- Windows Active Directory fundamentals
- Network penetration testing methodologies
- SMB protocol and authentication mechanisms
- LDAP and Kerberos authentication

## Contributing

Contributions are welcome! Areas for contribution:
- Additional NXC command templates
- New modules for plat02.sh
- Documentation improvements
- Bug fixes
- Feature requests

## License

This project is for educational and authorized testing purposes only. Users are responsible for ensuring they have proper authorization before testing any systems.

## Disclaimer

**IMPORTANT**: This tool is designed for authorized security testing only. Use of this tool for attacking targets without prior mutual consent is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

Only use this tool on systems you own or have explicit written permission to test.

## Author

Jeremy Laratro

## Version

Current Version: 4.0

## Changelog

### v4.0
- Integrated web testing and network testing frameworks
- Added Active Directory target management
- Enhanced credential management
- Added keyboard shortcuts
- Improved menu navigation

### v3.0
- Added Navi integration
- Created comprehensive NXC cheatsheet
- Added automated setup script

### v2.0
- Initial unified CLI framework
- Basic target and credential management

### v1.0
- Initial release

---

**Happy Testing!** Press `Ctrl+G` to start using the interactive cheatsheet, or run `./plat02.sh` to launch the framework.
