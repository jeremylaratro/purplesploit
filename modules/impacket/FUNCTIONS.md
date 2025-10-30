# Impacket Functions Quick Reference

## Execution Module (execution.sh)

### handle_psexec()
PSExec remote execution via Windows services
- Execute commands remotely
- Interactive shell access
- Execute as SYSTEM
- Upload and execute binaries
- Custom service name support

**Impacket Tool:** `impacket-psexec`

---

### handle_wmiexec()
WMI-based remote execution
- Execute commands via WMI
- Interactive shell
- Control output (with/without)
- Silent execution mode

**Impacket Tool:** `impacket-wmiexec`

---

### handle_smbexec()
SMB-based remote execution
- Execute commands via SMB
- Interactive shell
- Custom share support
- Execute without cleanup

**Impacket Tool:** `impacket-smbexec`

---

### handle_atexec()
Scheduled task-based execution
- Execute via Windows Task Scheduler
- Custom task names
- Wait for output

**Impacket Tool:** `impacket-atexec`

---

### handle_dcomexec()
DCOM-based remote execution
- ShellWindows method
- ShellBrowserWindow method
- MMC20 method

**Impacket Tool:** `impacket-dcomexec`

---

## Credentials Module (credentials.sh)

### handle_secretsdump()
Credential dumping from Windows systems
- Dump SAM database (local users)
- Dump LSA secrets
- Dump NTDS.dit (Domain Controller)
- Offline credential extraction
- Specific hash dumping options

**Impacket Tool:** `impacket-secretsdump`

**Output:** NTLM hashes, Kerberos keys, cached credentials

---

## Kerberos Module (kerberos.sh)

### handle_kerberoast()
Kerberoasting attack (service account cracking)
- Request TGS tickets for all SPNs
- Target specific users
- Hashcat output format
- John the Ripper format

**Impacket Tool:** `impacket-GetUserSPNs`

**Attack Type:** Request TGS tickets, crack offline (hashcat -m 13100)

---

### handle_asreproast()
AS-REP Roasting (pre-auth disabled accounts)
- Enumerate users without Kerberos pre-auth
- Works with null authentication
- User list file support
- Hashcat/John output formats

**Impacket Tool:** `impacket-GetNPUsers`

**Attack Type:** Request AS-REP, crack offline (hashcat -m 18200)

---

### handle_tickets()
Kerberos ticket manipulation
- Create golden tickets (domain admin persistence)
- Create silver tickets (service-specific access)
- Request TGT
- Export/import ccache tickets

**Impacket Tools:** `impacket-ticketer`, `impacket-getTGT`

**Use Case:** Persistence, privilege escalation, lateral movement

---

## Enumeration Module (enumeration.sh)

### handle_enum()
Active Directory and network enumeration
- Enumerate AD users (GetADUsers)
- SID enumeration (lookupsid)
- RPC endpoints (rpcdump)
- SAM enumeration (samrdump)
- Share listing (smbclient)
- Domain information gathering

**Impacket Tools:** `impacket-GetADUsers`, `impacket-lookupsid`, `impacket-rpcdump`, `impacket-samrdump`

---

## SMB Client Module (smbclient.sh)

### handle_smbclient()
Interactive SMB client operations
- Interactive browsing (shares, ls, cd, get, put)
- List shares
- Download files
- Upload files
- Execute commands via SMB

**Impacket Tool:** `impacket-smbclient`

**Note:** Single target mode only (not compatible with "all targets" mode)

---

## Services Module (services.sh)

### handle_services()
Windows service management
- List all services
- Start/stop services
- Create new services
- Delete services
- Query service status

**Impacket Tool:** `impacket-services`

**Use Case:** Persistence, privilege escalation, service manipulation

---

## Registry Module (registry.sh)

### handle_registry()
Windows registry operations
- Query registry keys
- Read registry values
- Write registry values
- Backup registry hives
- Save SAM hive (for offline extraction)
- Save SYSTEM hive (for offline extraction)

**Impacket Tool:** `impacket-reg`

**Use Case:** Configuration changes, credential extraction, persistence

---

## Authentication Formats

All functions support two authentication methods:

1. **Password-based:**
   ```
   DOMAIN/USERNAME:'PASSWORD'@target
   ```

2. **Pass-the-Hash:**
   ```
   DOMAIN/USERNAME@target -hashes :NTLM_HASH
   ```

## Common Options

- `-hashes` - Use NTLM hash for authentication
- `-dc-ip` - Specify Domain Controller IP
- `-no-pass` - No password (null authentication)
- `-outputfile` - Save output to file

## Attack Chain Examples

### 1. Initial Access → Credential Dumping
```
handle_psexec()         # Get initial shell
↓
handle_secretsdump()    # Dump credentials
↓
handle_kerberoast()     # Extract service tickets
```

### 2. Enumeration → Lateral Movement
```
handle_enum()           # Enumerate users/shares
↓
handle_asreproast()     # Find vulnerable accounts
↓
handle_wmiexec()        # Execute on discovered targets
```

### 3. Persistence
```
handle_tickets()        # Create golden ticket
↓
handle_services()       # Create persistent service
↓
handle_registry()       # Modify Run keys
```

## Function Call Matrix

| Module       | Function              | Auth Required | DC Required | Output Format |
|-------------|-----------------------|---------------|-------------|---------------|
| execution   | handle_psexec         | ✓             | ✗           | Interactive   |
| execution   | handle_wmiexec        | ✓             | ✗           | Interactive   |
| execution   | handle_smbexec        | ✓             | ✗           | Interactive   |
| execution   | handle_atexec         | ✓             | ✗           | Output        |
| execution   | handle_dcomexec       | ✓             | ✗           | Output        |
| credentials | handle_secretsdump    | ✓             | ✗           | Hashes        |
| kerberos    | handle_kerberoast     | ✓             | ✓           | Hashes        |
| kerberos    | handle_asreproast     | ✗ (optional)  | ✓           | Hashes        |
| kerberos    | handle_tickets        | ✓             | ✓           | ccache        |
| enumeration | handle_enum           | ✓             | ✗           | Text          |
| smbclient   | handle_smbclient      | ✓             | ✗           | Interactive   |
| services    | handle_services       | ✓             | ✗           | Text          |
| registry    | handle_registry       | ✓             | ✗           | Text/Binary   |
