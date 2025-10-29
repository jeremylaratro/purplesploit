# SMB Module Integration Guide

## How to integrate the SMB module into plat02.sh

### Option 1: Source and Use Main Handler (Recommended)

Add this near the top of plat02.sh, after variable declarations:

```bash
# Source NXC modules
if [[ -f "./modules/nxc/smb.sh" ]]; then
    source "./modules/nxc/smb.sh"
fi
```

Then replace the SMB case statements (lines 1645-2053) with:

```bash
"SMB Authentication"|"SMB Enumeration"|"SMB Shares"|"SMB Execution"|"SMB Credentials"|"SMB Vulnerabilities")
    handle_smb "$choice"
    ;;
```

### Option 2: Use Individual Handlers

If you want more control, you can call the sub-handlers directly:

```bash
"SMB Authentication")
    handle_smb_auth
    ;;
"SMB Enumeration")
    handle_smb_enum
    ;;
"SMB Shares")
    handle_smb_shares
    ;;
"SMB Execution")
    handle_smb_exec
    ;;
"SMB Credentials")
    handle_smb_creds
    ;;
"SMB Vulnerabilities")
    handle_smb_vulns
    ;;
```

### Before and After Comparison

**BEFORE (in plat02.sh):**
```bash
case "$choice" in
    "SMB Authentication")
        auth=$(build_auth)
        target=$(get_target_for_command) || continue
        subchoice=$(show_menu "smb_auth" "Select Auth Method: ")
        case "$subchoice" in
            "Test Authentication")
                run_command "nxc smb $target $auth"
                ;;
            # ... 20+ more lines ...
        esac
        ;;
    "SMB Enumeration")
        # ... 40+ lines ...
        ;;
    "SMB Shares")
        # ... 260+ lines including spider_plus ...
        ;;
    # ... etc for 400+ total lines ...
esac
```

**AFTER (in plat02.sh):**
```bash
case "$choice" in
    "SMB Authentication"|"SMB Enumeration"|"SMB Shares"|"SMB Execution"|"SMB Credentials"|"SMB Vulnerabilities")
        handle_smb "$choice"
        ;;
    # All other cases remain the same
esac
```

### Benefits

1. **Code Organization**: Reduces plat02.sh from 2738 lines to ~2338 lines
2. **Maintainability**: SMB logic is in one dedicated file
3. **Reusability**: Can source the module in other scripts
4. **Testing**: Can test SMB functionality independently
5. **Modularity**: Easy to add more protocol modules (LDAP, MSSQL, etc.)

### Testing the Module Independently

Create a test script:

```bash
#!/bin/bash

# Source dependencies and module
source /home/user/purplesploit/plat02.sh  # Get helper functions
source /home/user/purplesploit/modules/nxc/smb.sh

# Test individual handlers
handle_smb_auth
# or
handle_smb "SMB Authentication"
```

### Verification Steps

1. **Syntax Check:**
   ```bash
   bash -n /home/user/purplesploit/modules/nxc/smb.sh
   ```

2. **Function Export Check:**
   ```bash
   source /home/user/purplesploit/modules/nxc/smb.sh
   declare -F | grep handle_smb
   ```

3. **Full Integration Test:**
   - Source the module in plat02.sh
   - Run plat02.sh
   - Select any SMB menu option
   - Verify functionality works as before

### Rollback Plan

If issues arise, you can easily rollback by:
1. Removing the `source "./modules/nxc/smb.sh"` line
2. Restoring the original SMB case statements from git history

### Future Enhancements

Once the SMB module is integrated, you can create similar modules for:
- LDAP operations
- MSSQL operations
- WinRM operations
- SSH operations
- RDP operations

Each protocol can have its own module file following the same pattern.
