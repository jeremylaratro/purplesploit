# PurpleSploit Commands Reference

Complete command reference for all PurpleSploit operations.

---

## Module Discovery & Management

| Command | Description | Example |
|---------|-------------|---------|
| `search <query>` | Search modules by name/description | `search smb enum` |
| `search select` | Interactive selection from search results | `search smb` then `search select` |
| `module select` | Browse all modules interactively (fzf) | `module select` |
| `use <module>` | Load a module | `use network/nxc_smb` |
| `use <number>` | Load from search results by number | `use 1` |
| `back` | Unload current module | `back` |
| `info` | Show current module information | `info` |
| `options` | Display module options and values | `options` |
| `set <opt> <val>` | Set module option | `set RHOST 192.168.1.100` |
| `unset <opt>` | Clear module option | `unset RHOST` |
| `check` | Verify module can run with current options | `check` |
| `run` | Execute module (interactive operation menu) | `run` |
| `run <number>` | Execute specific operation by number | `run 1` |
| `run <name>` | Execute operation by name | `run auth` |

---

## Operation Search

| Command | Description | Example |
|---------|-------------|---------|
| `ops` | Show current module operations | `ops` |
| `ops <query>` | Search operations across all modules | `ops bloodhound` |
| `ops select` | Interactive selection from ops results | `ops dump` then `ops select` |
| `recent` | Show recently used modules | `recent` |
| `recent select` | Interactive selection from recent modules | `recent select` |

---

## Target Management

| Command | Description | Example |
|---------|-------------|---------|
| **Quick Actions** |
| `target <ip\|url>` | Quick add and set target | `target 192.168.1.100` |
| **Full Commands** |
| `targets` | List all targets (default) | `targets` |
| `targets list` | List all targets | `targets list` |
| `targets add <ip\|url> [name]` | Add target to database | `targets add 192.168.1.100 DC01` |
| `targets select` | Pick target interactively (fzf) | `targets select` |
| `targets set <index\|id>` | Set current target | `targets set 0` |
| `targets remove <id>` | Remove target by identifier | `targets remove 192.168.1.100` |
| `targets modify` | Modify target interactively | `targets modify` |
| `targets <idx> modify <k=v>...` | Modify by index/key-value | `targets 0 modify name=WebServer` |
| `targets clear` | Clear all targets | `targets clear` |
| `targets <idx\|range> clear` | Clear by index or range | `targets 0-5 clear` or `targets 2 clear` |

---

## Credential Management

| Command | Description | Example |
|---------|-------------|---------|
| **Quick Actions** |
| `cred <user:pass> [domain]` | Quick add and set credential | `cred admin:pass123 CORP` |
| **Full Commands** |
| `creds` | List all credentials (default) | `creds` |
| `creds list` | List all credentials | `creds list` |
| `creds add <user:pass> [domain]` | Add credential | `creds add admin:password DOMAIN` |
| `creds select` | Pick credential interactively (fzf) | `creds select` |
| `creds set <index\|username>` | Set current credential | `creds set 0` |
| `creds remove <id>` | Remove credential | `creds remove admin` |
| `creds modify` | Modify credential interactively | `creds modify` |
| `creds <idx> modify <k=v>...` | Modify by index/key-value | `creds 0 modify password=newpass` |
| `creds clear` | Clear all credentials | `creds clear` |
| `creds <idx\|range> clear` | Clear by index or range | `creds 0-2 clear` |

---

## Wordlist Management

| Command | Description | Example |
|---------|-------------|---------|
| `wordlists` | List all wordlists by category | `wordlists` |
| `wordlists list` | List all wordlists | `wordlists list` |
| `wordlists add <cat> <path> [name]` | Add wordlist by category | `wordlists add web_dir /usr/share/wordlists/dirb/common.txt` |
| `wordlists select <category>` | Pick wordlist for category (fzf) | `wordlists select password` |
| `wordlists set <cat> <id>` | Set current wordlist for category | `wordlists set username 0` |
| `wordlists remove <cat> <id>` | Remove wordlist from category | `wordlists remove web_dir common.txt` |

**Categories:** `web_dir`, `dns_vhost`, `username`, `password`, `subdomain`, `parameter`, `api`, `general`

---

## Service Detection

| Command | Description | Example |
|---------|-------------|---------|
| `services` | View detected services from scans | `services` |
| `services select` | Pick from detected services (fzf) | `services select` |
| `services clear` | Clear all detected services | `services clear` |

---

## Display Commands

| Command | Description | Example |
|---------|-------------|---------|
| `show modules` | List all modules in tree view | `show modules` |
| `show targets` | List all targets | `show targets` |
| `show creds` | List all credentials | `show creds` |
| `show services` | List detected services | `show services` |

---

## Analysis & Results

| Command | Description | Example |
|---------|-------------|---------|
| `analysis` | View web scan results dashboard | `analysis` |
| `stats` | Display framework statistics | `stats` |
| `history` | Show command history | `history` |

---

## Quick Workflows

| Command | Description | Example |
|---------|-------------|---------|
| `quick <module> [filter]` | Load module with auto-population | `quick smb auth` |
| `go <target> [cred] [op]` | All-in-one: set target, cred, run | `go 192.168.1.100 admin:pass` |

---

## Utility Commands

| Command | Description | Example |
|---------|-------------|---------|
| `clear` | Clear the screen | `clear` |
| `defaults <cmd>` | Manage module default options | `defaults` |
| `deploy` | Show deployment modules (ligolo, c2, script) | `deploy` |
| `deploy <type>` | Load deployment module | `deploy ligolo` |
| `webserver start` | Start web portal in background | `webserver start` |
| `webserver stop` | Stop web portal | `webserver stop` |
| `webserver status` | Check web portal status | `webserver status` |
| `ligolo` | Launch ligolo-ng proxy (Ctrl+D to return) | `ligolo` |
| `shell` | Drop to localhost shell (Ctrl+D to return) | `shell` |
| `hosts` | Generate /etc/hosts entries from targets | `hosts` |
| `help` | Show detailed help menu | `help` |
| `exit` / `quit` | Exit framework | `exit` |

---

## Workspace Management

| Command | Description | Example |
|---------|-------------|---------|
| `workspace <name>` | Switch to or create workspace | `workspace pentest-2025` |
| `workspace list` | List all workspaces | `workspace list` |

---

## Common Workflows

### Quick Enumeration
```bash
targets select
creds select
module select
# Navigate to desired module/operation
run
```

### Search-Driven Workflow
```bash
search smb enum
use 1
target 192.168.1.100
cred admin:password
run
```

### Operation-First Workflow
```bash
ops bloodhound
ops select
# Sets target/cred if needed, then runs
```

### Zero-to-Pwn Workflow
```bash
# 1. Discovery
target 192.168.1.0/24
use recon/nmap
run

# 2. Select from discovered services
services select

# 3. Enumerate
module select  # Pick appropriate module
run

# 4. Exploit
ops dump
run
```

---

## Keyboard Shortcuts

### In fzf Interactive Menus
- **Type**: Filter results (fuzzy matching)
- **↑/↓ or Ctrl+J/K**: Navigate results
- **Enter**: Select
- **Esc**: Cancel
- **Mouse Click**: Select (if mouse enabled)

### In Console
- **Tab**: Auto-complete commands, module paths
- **Ctrl+C**: Cancel current operation
- **Ctrl+D**: Exit (or return from ligolo/shell)
- **↑/↓**: Navigate command history

---

## Tips

1. **Context Persistence**: Targets and credentials persist across module changes
2. **Auto-Population**: Modules auto-fill from current target/cred
3. **Number Shortcuts**: After `search` or `show modules`, use `use <number>`
4. **Interactive Everything**: Most commands support `select` for fzf menus
5. **Range Operations**: Use ranges for bulk operations (e.g., `targets 0-10 clear`)
6. **Background Execution**: Web scans can run in background, check with `analysis`

---

**Last Updated**: v6.7.1
