# Handler Function Quick Reference

This document provides a quick lookup table for all menu choices and their corresponding handler functions.

## Format

```
"Menu Choice Text" → handler_function_name() [module_file.sh]
```

## Management Operations

```bash
"Switch Credentials"                → select_credentials()      [lib/credentials.sh]
"Switch Target"                     → select_target()           [lib/targets.sh]
"Toggle Run Mode (Single/All)"      → toggle_run_mode()         [lib/utils.sh]
"Manage Credentials"                → manage_credentials()      [lib/credentials.sh]
"Manage Targets"                    → manage_targets()          [lib/targets.sh]
"Manage Web Targets"                → manage_web_targets()      [lib/web_targets.sh]
"Manage AD Targets"                 → manage_ad_targets()       [lib/ad_targets.sh]
"Select AD Target"                  → select_ad_target()        [lib/ad_targets.sh]
```

## Web Testing Tools

```bash
"Feroxbuster (Directory/File Discovery)" → handle_feroxbuster()   [modules/web/feroxbuster.sh]
"WFUZZ (Fuzzing)"                        → handle_wfuzz()          [modules/web/wfuzz.sh]
"SQLMap (SQL Injection)"                 → handle_sqlmap()         [modules/web/sqlmap.sh]
"HTTPX (HTTP Probing)"                   → handle_httpx()          [modules/web/httpx.sh]
```

## NXC SMB Operations

```bash
"SMB Authentication"    → handle_smb_auth()    [modules/nxc/smb.sh]
"SMB Enumeration"       → handle_smb_enum()    [modules/nxc/smb.sh]
"SMB Shares"            → handle_smb_shares()  [modules/nxc/smb.sh]
"SMB Execution"         → handle_smb_exec()    [modules/nxc/smb.sh]
"SMB Credentials"       → handle_smb_creds()   [modules/nxc/smb.sh]
"SMB Vulnerabilities"   → handle_smb_vulns()   [modules/nxc/smb.sh]
```

## NXC LDAP Operations

```bash
"LDAP Enumeration"  → handle_ldap()        [modules/nxc/ldap.sh]
"LDAP BloodHound"   → handle_bloodhound()  [modules/nxc/ldap.sh]
```

## NXC Other Protocols

```bash
"WinRM Operations"  → handle_winrm()     [modules/nxc/winrm.sh]
"MSSQL Operations"  → handle_mssql()     [modules/nxc/mssql.sh]
"RDP Operations"    → handle_rdp()       [modules/nxc/rdp.sh]
"SSH Operations"    → handle_ssh()       [modules/nxc/ssh.sh]
"Network Scanning"  → handle_scanning()  [modules/nxc/scanning.sh]
```

## Impacket Execution Tools

```bash
"Impacket PSExec"   → handle_psexec()    [modules/impacket/execution.sh]
"Impacket WMIExec"  → handle_wmiexec()   [modules/impacket/execution.sh]
"Impacket SMBExec"  → handle_smbexec()   [modules/impacket/execution.sh]
"Impacket ATExec"   → handle_atexec()    [modules/impacket/execution.sh]
"Impacket DcomExec" → handle_dcomexec()  [modules/impacket/execution.sh]
```

## Impacket Credentials

```bash
"Impacket SecretsDump"         → handle_secretsdump()  [modules/impacket/credentials.sh]
"Impacket SAM/LSA/NTDS Dump"   → handle_secretsdump()  [modules/impacket/credentials.sh]
```

## Impacket Kerberos Tools

```bash
"Kerberoasting (GetUserSPNs)"  → handle_kerberoast()   [modules/impacket/kerberos.sh]
"AS-REP Roasting (GetNPUsers)" → handle_asreproast()   [modules/impacket/kerberos.sh]
"Golden/Silver Tickets"        → handle_tickets()      [modules/impacket/kerberos.sh]
```

## Impacket Other Tools

```bash
"Impacket Enumeration"  → handle_enum()       [modules/impacket/enumeration.sh]
"Impacket SMB Client"   → handle_smbclient()  [modules/impacket/smbclient.sh]
"Service Management"    → handle_services()   [modules/impacket/services.sh]
"Registry Operations"   → handle_registry()   [modules/impacket/registry.sh]
```

## Keyboard Shortcuts

```bash
Key 't'  → manage_targets()       [lib/targets.sh]
Key 'c'  → manage_credentials()   [lib/credentials.sh]
Key 'w'  → manage_web_targets()   [lib/web_targets.sh]
Key 'd'  → manage_ad_targets()    [lib/ad_targets.sh]
Key 'a'  → select_credentials()   [lib/credentials.sh]
Key 's'  → select_target()        [lib/targets.sh]
Key 'm'  → toggle_run_mode()      [lib/utils.sh]
```

## Adding New Handlers

### Step 1: Create Handler Function

Choose the appropriate module file based on category:
- Web tools → `modules/web/`
- NXC tools → `modules/nxc/`
- Impacket tools → `modules/impacket/`

```bash
# modules/category/toolname.sh

handle_toolname() {
    # Get auth if needed
    auth=$(build_auth)

    # Get target if needed
    target=$(get_target_for_command) || return 1

    # Show submenu
    subchoice=$(show_menu "menu_key" "Select Operation: ")

    # Handle choice
    case "$subchoice" in
        "Option 1")
            run_command "command here"
            ;;
        "Option 2")
            run_command "another command"
            ;;
    esac
}
```

### Step 2: Source the Module

Add to `purplesploit.sh`:

```bash
source "${SCRIPT_DIR}/modules/category/toolname.sh"
```

### Step 3: Add Menu Case

Add to `main_menu()` in `purplesploit.sh`:

```bash
"Your Menu Choice")
    handle_toolname
    ;;
```

### Step 4: Add Menu Definition

Add to `show_menu()` in `core/ui.sh`:

```bash
"menu_key")
    menu_items=(
        "Option 1"
        "Option 2"
        "Back"
    )
    ;;
```

## Module Template

Save this as a template for new modules:

```bash
#!/bin/bash
#
# Tool Name Module - Brief Description
# Part of PurpleSploit Framework
#
# This module handles all <tool>-related operations including:
# - Feature 1
# - Feature 2
# - Feature 3
#
# Dependencies:
# - toolname (must be installed)
# - Global functions: build_auth, get_target_for_command, run_command, show_menu
# - Global variables: Colors, USERNAME, PASSWORD, DOMAIN, HASH, TARGET, RUN_MODE
#

# Main handler function
handle_toolname() {
    # Get dependencies
    auth=$(build_auth)
    target=$(get_target_for_command) || return 1

    # Show submenu
    subchoice=$(show_menu "toolname_menu" "Select Operation: ")

    # Exit if user pressed ESC or selected Back
    [[ -z "$subchoice" || "$subchoice" == "Back" ]] && return 0

    # Handle operations
    case "$subchoice" in
        "Basic Operation")
            echo -e "${CYAN}Running basic operation${NC}"
            run_command "toolname $target $auth"
            ;;

        "Advanced Operation")
            read -p "Enter parameter: " param
            echo -e "${CYAN}Running advanced operation${NC}"
            run_command "toolname $target $auth --option '$param'"
            ;;

        "Custom Operation")
            read -p "Enter custom flags: " flags
            run_command "toolname $target $auth $flags"
            ;;

        *)
            echo -e "${RED}Unknown option: $subchoice${NC}"
            sleep 2
            ;;
    esac
}

# Export function (optional, but recommended for clarity)
export -f handle_toolname
```

## Common Patterns

### Pattern 1: Simple Menu with Direct Commands

```bash
handle_simple() {
    target=$(get_target_for_command) || return 1

    subchoice=$(show_menu "simple_menu" "Select: ")

    case "$subchoice" in
        "Scan")
            run_command "nmap -sS $target"
            ;;
        "Enumerate")
            run_command "enum4linux $target"
            ;;
    esac
}
```

### Pattern 2: Menu with User Input

```bash
handle_with_input() {
    target=$(get_target_for_command) || return 1

    subchoice=$(show_menu "input_menu" "Select: ")

    case "$subchoice" in
        "Custom Scan")
            read -p "Ports: " ports
            run_command "nmap -p $ports $target"
            ;;
    esac
}
```

### Pattern 3: Nested Menu Loop

```bash
handle_nested() {
    while true; do
        subchoice=$(show_menu "nested_menu" "Select: ")
        [[ -z "$subchoice" || "$subchoice" == "Back" ]] && break

        case "$subchoice" in
            "Option 1")
                run_command "command1"
                ;;
            "Option 2")
                run_command "command2"
                ;;
        esac
    done
}
```

### Pattern 4: With Authentication

```bash
handle_with_auth() {
    auth=$(build_auth)
    target=$(get_target_for_command) || return 1

    subchoice=$(show_menu "auth_menu" "Select: ")

    case "$subchoice" in
        "Authenticate")
            run_command "tool $target $auth"
            ;;
    esac
}
```

### Pattern 5: Conditional Options

```bash
handle_conditional() {
    target=$(get_target_for_command) || return 1

    subchoice=$(show_menu "conditional_menu" "Select: ")

    case "$subchoice" in
        "Single Target Only")
            if [[ "$RUN_MODE" == "all" ]]; then
                echo -e "${YELLOW}This option only works with single target.${NC}"
                sleep 2
                return 1
            fi
            run_command "interactive-tool $target"
            ;;
    esac
}
```

## Available Helper Functions

### From lib/credentials.sh
- `select_credentials()` - Interactive credential selection
- `manage_credentials()` - Add/edit/delete credentials
- `load_creds(name)` - Load specific credentials
- `build_auth()` - Build auth string for nxc

### From lib/targets.sh
- `select_target()` - Interactive target selection
- `manage_targets()` - Add/edit/delete targets
- `get_target_for_command()` - Get target based on run mode
- `list_target_names()` - List all target names

### From lib/web_targets.sh
- `select_web_target()` - Interactive web target selection
- `manage_web_targets()` - Add/edit/delete web targets
- `get_web_target_url()` - Get web target URL

### From lib/ad_targets.sh
- `select_ad_target()` - Interactive AD target selection
- `manage_ad_targets()` - Add/edit/delete AD targets

### From lib/utils.sh
- `toggle_run_mode()` - Toggle single/all target mode
- `show_downloads()` - Show downloaded files

### From core/ui.sh
- `show_menu(key, prompt)` - Display fzf menu
- `run_command(cmd)` - Execute command with preview/confirmation

### From core/database.sh
- `init_creds_db()` - Initialize credentials database
- `init_targets_db()` - Initialize targets database
- `init_web_targets_db()` - Initialize web targets database
- `init_ad_targets_db()` - Initialize AD targets database

## Global Variables

### Colors
```bash
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'  # No Color
```

### Credentials
```bash
USERNAME              # Current username
PASSWORD              # Current password
DOMAIN                # Current domain
HASH                  # Current NTLM hash
CURRENT_CRED_NAME     # Name of current credential set
```

### Targets
```bash
TARGET                # Current target (single IP or file)
RUN_MODE              # "single" or "all"
CURRENT_TARGET_NAME   # Name of current target
```

### Databases
```bash
CREDS_DB              # Path to credentials database
TARGETS_DB            # Path to targets database
WEB_TARGETS_DB        # Path to web targets database
AD_TARGETS_DB         # Path to AD targets database
```

### Paths
```bash
SCRIPT_DIR            # Directory where script is located
```

## Tips and Best Practices

1. **Always check for empty subchoice**
   ```bash
   [[ -z "$subchoice" || "$subchoice" == "Back" ]] && return 0
   ```

2. **Use return 1 on errors**
   ```bash
   target=$(get_target_for_command) || return 1
   ```

3. **Provide user feedback**
   ```bash
   echo -e "${CYAN}Running scan...${NC}"
   echo -e "${GREEN}Scan complete!${NC}"
   echo -e "${RED}Error occurred!${NC}"
   echo -e "${YELLOW}Warning: May take a while${NC}"
   ```

4. **Use read -p for input**
   ```bash
   read -p "Enter port: " port
   [[ -z "$port" ]] && port="80"  # Default value
   ```

5. **Validate file existence**
   ```bash
   if [[ ! -f "$wordlist" ]]; then
       echo -e "${RED}File not found!${NC}"
       sleep 2
       return 1
   fi
   ```

6. **Quote variables in commands**
   ```bash
   run_command "tool -u '$url' -p '$password'"
   ```

7. **Add descriptive module headers**
   ```bash
   #
   # Module Name - Brief Description
   # Part of PurpleSploit Framework
   #
   ```

8. **Document dependencies**
   ```bash
   # Dependencies:
   # - tool (must be installed)
   # - Global functions: build_auth, get_target_for_command
   ```
