# NXC Modules

This directory contains modularized NetExec (NXC) functionality extracted from the main plat02.sh script.

## SMB Module

**File:** `smb.sh`
**Lines:** 526 lines
**Size:** 20KB

### Overview

The SMB module contains all SMB-related operations for NetExec, organized into 6 main functional areas:

### Functions

#### Main Handler
- `handle_smb(submenu_type)` - Main dispatcher that routes to appropriate sub-handler

#### Sub-Handlers
1. **`handle_smb_auth()`** - SMB Authentication Operations
   - Test Authentication
   - Test with Domain
   - Pass-the-Hash
   - Local Authentication

2. **`handle_smb_enum()`** - SMB Enumeration Operations
   - List Shares
   - Enumerate Users (local and domain)
   - Enumerate Groups
   - Password Policy
   - Active Sessions
   - Logged On Users
   - RID Bruteforce
   - List Disks
   - Full Enumeration (All)

3. **`handle_smb_shares()`** - SMB Shares Operations
   - Browse & Download Files (Interactive)
   - Download All Files (Recursive)
   - Download Files by Pattern
   - Spider & List Only (No Download)
   - Spider Specific Share
   - Parse Spider Results (integration with parse_spider_plus.py)
   - Download Specific File (Manual Path)
   - Upload File

4. **`handle_smb_exec()`** - SMB Execution Operations
   - Execute Command (CMD)
   - Execute PowerShell
   - Get System Info
   - List Processes
   - Network Configuration
   - List Administrators
   - Check Privileges

5. **`handle_smb_creds()`** - SMB Credentials Dumping
   - Dump SAM Database
   - Dump LSA Secrets
   - Dump NTDS (Domain Controller)
   - Dump All (SAM+LSA+NTDS)
   - Lsassy (Memory Dump)
   - Nanodump
   - WiFi Passwords

6. **`handle_smb_vulns()`** - SMB Vulnerabilities Scanning
   - MS17-010 (EternalBlue)
   - Zerologon (CVE-2020-1472)
   - PetitPotam
   - NoPac (CVE-2021-42278)
   - SMBGhost (CVE-2020-0796)
   - PrintNightmare
   - All Vulnerability Checks

### Dependencies

The module relies on the following functions from the main script:
- `build_auth()` - Builds authentication string from credentials
- `get_target_for_command()` - Gets target from database/selection
- `run_command()` - Executes command with logging
- `show_menu()` - Displays menu using fzf
- `show_downloads()` - Displays downloaded files

### Global Variables

The module uses these global variables (should be sourced from config.sh):
- **Colors:** RED, GREEN, YELLOW, BLUE, CYAN, MAGENTA, NC
- **Credentials:** USERNAME, PASSWORD, DOMAIN, HASH
- **Target Info:** TARGET, RUN_MODE
- **Databases:** CREDS_DB, TARGETS_DB

### Integration with parse_spider_plus.py

The SMB Shares module includes full integration with the `parse_spider_plus.py` parser:
- Located at `/home/user/purplesploit/parse_spider_plus.py`
- Parses JSON output from spider_plus module
- Supports sorting by share, size, or name
- Can parse specific IP or all results

### Usage Example

```bash
#!/bin/bash

# Source the module
source /home/user/purplesploit/modules/nxc/smb.sh

# Use the main handler with a submenu type
handle_smb "SMB Authentication"
handle_smb "SMB Enumeration"
handle_smb "SMB Shares"

# Or call specific handlers directly
handle_smb_auth
handle_smb_enum
handle_smb_shares
handle_smb_exec
handle_smb_creds
handle_smb_vulns
```

### Integration into plat02.sh

To integrate this module into the main script, replace the SMB case statements with:

```bash
# Source the SMB module
source "./modules/nxc/smb.sh"

# In the main menu loop, replace the SMB case statements:
case "$choice" in
    "SMB Authentication"|"SMB Enumeration"|"SMB Shares"|"SMB Execution"|"SMB Credentials"|"SMB Vulnerabilities")
        handle_smb "$choice"
        ;;
    # ... other cases ...
esac
```

### Extracted from plat02.sh

**Original locations in plat02.sh:**
- SMB Authentication: Lines 1645-1665
- SMB Enumeration: Lines 1666-1702
- SMB Shares: Lines 1703-1967 (includes extensive spider_plus integration)
- SMB Execution: Lines 1968-1997
- SMB Credentials: Lines 1998-2025
- SMB Vulnerabilities: Lines 2026-2053

**Total lines extracted:** ~400 lines of SMB functionality
**Module size:** 526 lines (with documentation and structure)

### Testing

Syntax validation:
```bash
bash -n /home/user/purplesploit/modules/nxc/smb.sh
```

All functions are exported and ready for use in other scripts.
