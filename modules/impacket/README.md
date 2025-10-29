# Impacket Modules

This directory contains modularized Impacket functions extracted from the main plat02.sh script for better organization and maintainability.

## Module Files

### 1. execution.sh (6.9K)
Remote code execution tools for Windows systems.

**Functions:**
- `handle_psexec()` - PSExec operations (service-based execution)
  - Execute commands
  - Interactive shell
  - Execute as SYSTEM
  - Upload and execute files
  - Custom service names

- `handle_wmiexec()` - WMIExec operations (WMI-based execution)
  - Execute commands
  - Interactive shell
  - Execute with output control
  - Silent execution

- `handle_smbexec()` - SMBExec operations (SMB-based execution)
  - Execute commands
  - Interactive shell
  - Custom share execution
  - Execute without cleanup

- `handle_atexec()` - ATExec operations (scheduled task execution)
  - Execute via scheduled tasks
  - Custom task names
  - Wait for output

- `handle_dcomexec()` - DcomExec operations (DCOM-based execution)
  - ShellWindows method
  - ShellBrowserWindow method
  - MMC20 method

### 2. credentials.sh (2.7K)
Credential dumping and extraction tools.

**Functions:**
- `handle_secretsdump()` - SecretsDump operations
  - Dump all (SAM+LSA+NTDS)
  - SAM database only
  - LSA secrets only
  - NTDS.dit (Domain Controller)
  - Specific hash dumping
  - Offline file extraction

### 3. kerberos.sh (7.1K)
Kerberos attack and ticket manipulation tools.

**Functions:**
- `handle_kerberoast()` - Kerberoasting (GetUserSPNs)
  - Request TGS for all SPNs
  - Target specific users
  - Hashcat output format
  - John the Ripper format

- `handle_asreproast()` - AS-REP Roasting (GetNPUsers)
  - Roast all users
  - User list file support
  - Hashcat/John output
  - Check specific users
  - Works with null authentication

- `handle_tickets()` - Golden/Silver ticket operations
  - Create golden tickets (krbtgt)
  - Create silver tickets (service accounts)
  - Request TGT
  - Export/import ccache tickets

### 4. enumeration.sh (2.5K)
Active Directory and network enumeration tools.

**Functions:**
- `handle_enum()` - Impacket enumeration operations
  - GetADUsers (enumerate AD users)
  - lookupsid (SID enumeration)
  - rpcdump (RPC endpoints)
  - samrdump (SAM enumeration)
  - smbclient (share listing)
  - Domain information

### 5. smbclient.sh (2.8K)
Interactive SMB client operations.

**Functions:**
- `handle_smbclient()` - SMB client operations
  - Interactive SMB browsing
  - List shares
  - Download files
  - Upload files
  - Execute commands via SMB

### 6. services.sh (2.3K)
Windows service management.

**Functions:**
- `handle_services()` - Service management operations
  - List services
  - Start/stop services
  - Create services
  - Delete services
  - Query service status

### 7. registry.sh (3.1K)
Windows registry operations.

**Functions:**
- `handle_registry()` - Registry operations
  - Query registry keys
  - Read registry values
  - Write registry values
  - Backup registry hives
  - Save SAM hive
  - Save SYSTEM hive

## Usage

Each module is designed to be sourced from the main plat02.sh script. The modules expect certain global variables and helper functions to be available:

### Required Global Variables:
- `DOMAIN` - Domain name
- `USERNAME` - Username for authentication
- `PASSWORD` - Password for authentication
- `HASH` - NTLM hash for pass-the-hash
- `TARGET` - Target IP or hostname
- `RUN_MODE` - Execution mode (single/all)
- `CURRENT_CRED_NAME` - Current credential name (for null auth detection)

### Required Helper Functions:
- `get_target_for_command()` - Gets target(s) based on run mode
- `show_menu()` - Displays menu using fzf
- `run_command()` - Executes command with preview and confirmation

### Color Variables:
- `RED`, `GREEN`, `YELLOW`, `BLUE`, `CYAN`, `MAGENTA`, `NC`

## Integration

To use these modules in plat02.sh, source them at the beginning of the script:

```bash
# Source Impacket modules
source "$HOME/purplesploit/modules/impacket/execution.sh"
source "$HOME/purplesploit/modules/impacket/credentials.sh"
source "$HOME/purplesploit/modules/impacket/kerberos.sh"
source "$HOME/purplesploit/modules/impacket/enumeration.sh"
source "$HOME/purplesploit/modules/impacket/smbclient.sh"
source "$HOME/purplesploit/modules/impacket/services.sh"
source "$HOME/purplesploit/modules/impacket/registry.sh"
```

Then replace the inline case statements with function calls:

```bash
# Old (inline):
"Impacket PSExec")
    target=$(get_target_for_command) || continue
    subchoice=$(show_menu "impacket_psexec" "Select PSExec Operation: ")
    # ... rest of code ...
    ;;

# New (modular):
"Impacket PSExec")
    handle_psexec
    ;;
```

## Benefits of Modularization

1. **Better Organization** - Related functions grouped together
2. **Easier Maintenance** - Changes isolated to specific modules
3. **Reusability** - Modules can be sourced independently
4. **Cleaner Main Script** - Reduced file size and complexity
5. **Documentation** - Each module has clear purpose and documentation
6. **Testing** - Individual modules can be tested in isolation

## Line References (Original plat02.sh)

- Execution tools: lines 2226-2377
- Credentials: lines 2378-2418
- Kerberos: lines 2420-2544
- Enumeration: lines 2557-2580
- SMB Client: lines 2583-2628
- Services: lines 2629-2665
- Registry: lines 2666-2711

## Total Size

Total module size: ~29K (compared to 31082 tokens in original file)
