# PurpleSploit Smart Features & Improvements

## Overview
The Python framework now includes intelligent search, auto-loading, quick shortcuts, and operation filtering to make it as fast and efficient as the original TUI.

---

## 🚀 Smart Features

### 1. **Auto-Load Single Search Results**

No more extra steps! If your search returns only one module, it auto-loads:

```bash
purplesploit> search feroxbuster
# Automatically loads if only one match found
✓ Loaded module: Feroxbuster
```

**Before**: `search` → `use 1` → view operations (3 steps)
**After**: `search` → auto-loaded! (1 step)

---

### 2. **Smart Use with Operation Filtering**

Load a module and filter to specific operations in one command:

```bash
# Load SMB module and show only authentication operations
purplesploit> use smb auth

✓ Loaded module: NetExec SMB

Showing operations matching 'auth':
  #  Operation               Description
  1  Test Authentication     Test basic SMB authentication
  2  Test with Domain        Test authentication with domain
  3  Pass-the-Hash          Authenticate using NTLM hash
  4  Local Authentication    Test local authentication (--local-auth)
```

**Works with any keyword**:
```bash
use smb enum        # Show enumeration operations
use smb dump        # Show credential dumping operations
use smb vuln        # Show vulnerability checks
use ferox api       # Show API-related operations
```

---

### 3. **Global Operation Search**

Search across ALL module operations with the `ops` command:

```bash
purplesploit> ops authentication

Found 8 operations matching 'authentication':

  1. NetExec SMB
     Operation: Test Authentication
     Test basic SMB authentication
     Path: network/nxc_smb

  2. NetExec SMB
     Operation: Test with Domain
     Test authentication with domain
     Path: network/nxc_smb

  3. NetExec SMB
     Operation: Local Authentication
     Test local authentication (--local-auth)
     Path: network/nxc_smb
```

Find what you need across the entire framework instantly!

---

### 4. **Quick Target Command**

Set target with one command instead of verbose `set RHOST`:

```bash
# Old way
purplesploit(nxc_smb)> set RHOST 192.168.1.100

# New way
purplesploit> target 192.168.1.100
✓ Target set to: 192.168.1.100
  → Set RHOST = 192.168.1.100   # Auto-sets in current module!
```

**Auto-detects type**:
- IP address → Sets as network target (RHOST)
- URL → Sets as web target (URL)

**Auto-populates current module**:
- If you have a module loaded, it automatically sets the appropriate option

---

### 5. **Quick Credential Command**

Set credentials fast:

```bash
# Set username and password
purplesploit> cred administrator:P@ssw0rd
✓ Credential set: administrator
  → Set USERNAME = administrator
  → Set PASSWORD = ****

# With domain
purplesploit> cred admin:pass CORP
✓ Credential set: admin
  → Set USERNAME = admin
  → Set PASSWORD = ****
  → Set DOMAIN = CORP
```

**Auto-populates current module** with USERNAME, PASSWORD, and DOMAIN options.

---

### 6. **Recent Modules**

Quick access to your recently used modules:

```bash
purplesploit> recent

Recently Used Modules:

  1. network/nxc_smb - Comprehensive SMB testing with 42 operations
  2. web/feroxbuster - Directory and file discovery with 7 scan types
  3. network/nxc_ldap - LDAP enumeration and BloodHound collection

Tip: Use 'use <module_path>' to load a module
```

---

### 7. **Number-Based Selection Everywhere**

Select modules by number from search results:

```bash
purplesploit> search smb

#  Category  Module Path      Description
1  NETWORK   network/nxc_smb  Comprehensive SMB testing...
2  NETWORK   network/nxc_ldap LDAP enumeration...

purplesploit> use 1
✓ Loaded module: NetExec SMB
```

Select operations by number:

```bash
purplesploit(nxc_smb)> run 5
Running: List Shares
[Executes operation #5]
```

---

## 📋 Complete Workflow Examples

### Example 1: Fast SMB Enumeration

```bash
# Ultra-fast workflow - 4 commands total
purplesploit> search smb                    # Auto-loads if 1 result
purplesploit> target 192.168.1.100          # Quick target set
purplesploit> cred admin:P@ssw0rd          # Quick cred set
purplesploit(nxc_smb)> run 5               # Run operation #5 (List Shares)
```

### Example 2: Find and Run Specific Operation

```bash
# Find all authentication operations
purplesploit> ops authentication

# Pick one and load its module
purplesploit> use network/nxc_smb

# Or use smart filtering
purplesploit> use smb auth
purplesploit(nxc_smb)> target 10.10.10.10
purplesploit(nxc_smb)> run 1               # Test Authentication
```

### Example 3: Web Application Testing

```bash
purplesploit> search ferox                  # Auto-loads single result
purplesploit> target http://10.10.11.94
purplesploit(feroxbuster)> run 2           # Deep Scan with Extensions
Extensions: php,asp,aspx,txt
[Scan runs...]
```

---

## 🎯 Efficiency Comparison

### Original Workflow (Without Smart Features):
```
1. search smb
2. use network/nxc_smb
3. show options
4. set RHOST 192.168.1.100
5. set USERNAME administrator
6. set PASSWORD P@ssw0rd
7. run
8. [pick from menu]
```
**8 commands minimum**

### Smart Workflow (With Smart Features):
```
1. search smb           # Auto-loads
2. target 192.168.1.100 # Auto-sets RHOST
3. cred admin:P@ssw0rd  # Auto-sets USERNAME/PASSWORD
4. run 5                # Direct operation selection
```
**4 commands total - 50% fewer steps!**

---

## 🔍 Smart Search Details

Search is intelligent and looks at:
- Module path (`network/nxc_smb`)
- Module name (`NetExec SMB`)
- Module description
- Module category (`network`, `web`, etc.)

Examples:
```bash
search smb          # Finds all SMB-related modules
search web          # Finds all web testing modules
search nxc          # Finds all NetExec modules
search directory    # Finds directory enumeration tools
```

---

## 💡 Pro Tips

1. **Use `ops` when you know what you want to do but not which module**:
   ```bash
   ops dump credentials    # Find all credential dumping operations
   ops spider             # Find all file enumeration operations
   ops vulnerability      # Find all vuln scanning operations
   ```

2. **Combine smart use with filtering**:
   ```bash
   use smb shares         # Load SMB, show share operations
   use smb creds          # Load SMB, show credential operations
   ```

3. **Use quick commands in sequence**:
   ```bash
   target 192.168.1.100 && cred admin:pass && run 1
   ```

4. **Check recent modules when switching contexts**:
   ```bash
   recent                 # See what you used recently
   ```

5. **Let auto-load work for you**:
   ```bash
   search feroxbuster     # Auto-loads if unique
   # No need to type 'use 1'
   ```

---

## 📊 Feature Summary

| Feature | Command | Benefit |
|---------|---------|---------|
| Auto-load single result | `search <query>` | Skip `use` command |
| Operation filtering | `use smb auth` | Jump to relevant ops |
| Global op search | `ops <query>` | Find across all modules |
| Quick target | `target <ip>` | Faster than `set RHOST` |
| Quick cred | `cred user:pass` | Faster than multiple sets |
| Recent modules | `recent` | Quick access to history |
| Number selection | `use 1`, `run 5` | No typing long names |

---

## 🚦 Migration Guide

If you're used to the old workflow, here's how to adapt:

| Old Command | New Smart Command | Notes |
|-------------|-------------------|-------|
| `search smb` then `use 1` | `search smb` | Auto-loads if 1 result |
| `set RHOST 192.168.1.1` | `target 192.168.1.1` | Also sets in module |
| `set USERNAME admin` then `set PASSWORD pass` | `cred admin:pass` | One command |
| Search then navigate menus | `use smb auth` | Direct to operations |
| Browse all modules | `ops <what_you_want>` | Find by operation |

---

This smart system makes PurpleSploit as fast as the original TUI while keeping all the power of the Python framework!
