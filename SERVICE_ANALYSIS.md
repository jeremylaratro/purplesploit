# Service Analysis & Smart Module Selection

## Overview

The Service Analysis feature automatically detects services from nmap scans and intelligently suggests relevant modules. This makes pentesting workflows faster by showing only applicable tools for your target.

## How It Works

1. **Run an nmap scan** - Framework auto-analyzes results
2. **Services detected** - Stored in workspace database
3. **Type `search relevant`** - See only modules for detected services
4. **Select and run** - Use FZF to pick the right module

## Quick Start

### Step 1: Scan Target

```bash
purplesploit> set RHOST 192.168.1.100
purplesploit> use recon/nmap/quick_scan
purplesploit(recon/nmap/quick_scan)> run

# Framework automatically analyzes results
[+] Detected 6 services on 192.168.1.100
[*] Run 'search relevant' to see applicable modules
```

### Step 2: View Detected Services

```bash
purplesploit> services

Detected Services:
================================================================================
Target               Port     Protocol   Service              Version
--------------------------------------------------------------------------------
192.168.1.100        22       tcp        ssh                  OpenSSH 7.6p1
192.168.1.100        80       tcp        http                 Apache httpd 2.4.29
192.168.1.100        445      tcp        microsoft-ds         Samba smbd 4.7.6
192.168.1.100        3389     tcp        rdp                  Microsoft Terminal Services
================================================================================
```

### Step 3: Search Relevant Modules

```bash
purplesploit> search relevant

[*] Found 12 relevant modules based on detected services

# FZF menu appears showing ONLY:
# - web/feroxbuster/* (because HTTP detected)
# - web/sqlmap/* (because HTTP detected)
# - network/nxc/smb/* (because SMB detected)
# - network/nxc/rdp/* (because RDP detected)
# [NO SSH/LDAP/etc modules shown since not detected]
```

### Step 4: Select and Run

```bash
# Use arrow keys in FZF menu, press Enter
[Selected: network/nxc/smb/enum_shares]

purplesploit> credentials  # Select creds via FZF
purplesploit> run
```

## Commands

| Command | Description |
|---------|-------------|
| `search relevant` | 🎯 Show modules for detected services only |
| `services` | List all detected services |
| `services -t` | Show services on current target (RHOST) |
| `services -c` | Clear service database |
| `services -i <file>` | Import from nmap output file |

## Supported Service Detection

The framework automatically maps detected services to relevant module categories:

| Detected Service | Modules Shown |
|------------------|---------------|
| `http`, `https`, `http-proxy` | Web testing (feroxbuster, sqlmap, httpx, wfuzz) |
| `microsoft-ds`, `smb`, `netbios-ssn` | SMB modules (NXC, Impacket) |
| `ldap`, `ldaps` | LDAP enumeration, BloodHound |
| `winrm`, `wsman` | WinRM operations |
| `rdp`, `ms-term-serv` | RDP modules |
| `ssh` | SSH operations |
| `ms-sql`, `mssql` | MSSQL modules |
| `mysql` | MySQL modules |
| `postgresql` | PostgreSQL modules |
| `ftp`, `ftps` | FTP modules |
| `kerberos`, `kdc` | Kerberos attacks |

## Auto-Analysis

Nmap modules automatically analyze results:
- `recon/nmap/quick_scan` ✅ Auto-analyzes
- `recon/nmap/full_scan` ✅ Auto-analyzes
- `recon/nmap/vuln_scan` ✅ Auto-analyzes

No manual import needed! Just run the scan.

## Manual Import

Import existing nmap results:

```bash
# From file
purplesploit> services -i /path/to/nmap_scan.gnmap
[+] Found 8 open services on 192.168.1.50

# Or from XML
purplesploit> services -i /path/to/nmap_scan.xml
```

## Example Workflow

### Scenario: Internal Network Assessment

```bash
# 1. Add targets to workspace
purplesploit> workspace -a client_internal
purplesploit> targets -a 192.168.1.100
purplesploit> targets -a 192.168.1.101
purplesploit> targets -a 192.168.1.102

# 2. Scan first target
purplesploit> targets        # FZF select 192.168.1.100
purplesploit> use recon/nmap/full_scan
purplesploit> run

[+] Detected 5 services on 192.168.1.100
  - http (80/tcp)
  - https (443/tcp)
  - microsoft-ds (445/tcp)
  - ldap (389/tcp)
  - rdp (3389/tcp)
[*] Run 'search relevant' to see applicable modules

# 3. See what's applicable
purplesploit> search relevant

# FZF shows only relevant modules:
# ✓ web/feroxbuster/basic_scan
# ✓ web/feroxbuster/api_discovery
# ✓ network/nxc/smb/enum_shares
# ✓ network/nxc/ldap/enum_domain
# ✓ network/nxc/rdp/screenshot
# ✗ network/nxc/ssh/* (not shown - no SSH)
# ✗ network/nxc/mssql/* (not shown - no MSSQL)

# 4. Quick enumeration
purplesploit> use network/nxc/smb/enum_shares
purplesploit> credentials   # FZF select creds
purplesploit> run

purplesploit> use web/feroxbuster/basic_scan
purplesploit> run

# 5. Scan next target
purplesploit> targets        # FZF select 192.168.1.101
purplesploit> use recon/nmap/full_scan
purplesploit> run

# 6. Search relevant for THIS target
purplesploit> search relevant
# Shows modules for services on .101
```

## Service Database

### Location
Per-workspace: `~/.purplesploit/workspaces/<workspace>/services.db`

### Format
```
target|port|protocol|service|version|state
192.168.1.100|80|tcp|http|Apache httpd 2.4.29|open
192.168.1.100|445|tcp|microsoft-ds|Samba smbd 4.7.6|open
```

### Persistence
- Services tracked per workspace
- Survives framework restarts
- Cleared when changing workspaces (workspace-specific)
- Manual clear: `services -c`

## Benefits

### Before (Without Service Analysis)
```bash
purplesploit> search smb
# Shows 20 SMB modules
# But target doesn't have SMB!
# Waste time trying SMB attacks
```

### After (With Service Analysis)
```bash
purplesploit> search relevant
# Only shows 8 modules
# All applicable to detected services
# Focus on what actually works!
```

## Tips & Best Practices

### 1. Always Scan First
Run nmap scan before exploring. Framework needs service data.

```bash
# DO THIS:
use recon/nmap/quick_scan → run → search relevant

# NOT THIS:
search relevant (no services detected yet!)
```

### 2. Use Multiple Workspaces
Different engagement = different workspace = different service database

```bash
workspace -a client_A
[scan and attack client A targets]

workspace -a client_B
[scan and attack client B targets]
# Services are separate!
```

### 3. Combine with Other FZF Features

```bash
# Full workflow with FZF:
targets          # FZF select target
[run nmap scan]
search relevant  # FZF relevant modules
credentials      # FZF select creds
run
```

### 4. Import Existing Scans

Already have nmap scans? Import them!

```bash
services -i old_nmap_scan.gnmap
search relevant  # Works with imported data
```

### 5. Check Services Anytime

```bash
# All services across all targets
services

# Just current target
services -t

# Re-scan if services changed
use recon/nmap/quick_scan
run
# Updates service database automatically
```

## Troubleshooting

### "No services detected yet"

**Problem:** Running `search relevant` before scanning

**Solution:**
```bash
# Scan first
use recon/nmap/quick_scan
set RHOST <target>
run

# Then search
search relevant
```

### "No relevant modules found"

**Problem:** Services detected but no matching modules

**Solution:** Check what was detected:
```bash
services
# If unusual services, may not have modules yet
# Use regular 'search <keyword>' instead
```

### Services Not Auto-Detected

**Problem:** Ran nmap but services not showing

**Solution:**
```bash
# Check nmap output was saved
show vars  # Look at OUTPUT_DIR

# Manually import
services -i <nmap_output_file>
```

### Wrong Services Shown

**Problem:** Service database has old/wrong data

**Solution:**
```bash
# Clear and re-scan
services -c
use recon/nmap/full_scan
run
```

## Advanced: Custom Service Mapping

The service-to-module mapping is in `framework/core/service_analyzer.sh`.

To add custom mappings, edit the `service_to_module_category()` function:

```bash
case "$service" in
    # Your custom service
    my-custom-service)
        echo "custom_category"
        ;;
```

Then create modules with matching names/categories.

---

**Smart pentesting starts here!** 🎯
