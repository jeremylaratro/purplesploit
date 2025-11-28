# PurpleSploit Core Commands

Quick reference for essential commands.

## Discovery

| Command | Description |
|---------|-------------|
| `search <query>` | Find modules by name, description, or category |
| `ops` | Show operations for current module (when in a module) |
| `ops <query>` | Search operations across all modules globally |
| `module select` | Browse all modules interactively with fzf |
| `ops select` | Interactive selection from last ops search results |
| `recent` | Show recently used modules |

## Module Management

| Command | Description |
|---------|-------------|
| `use <module>` | Load a module (e.g., `use network/nxc_smb`) |
| `use <number>` | Load module from search results by number |
| `back` | Unload current module |
| `info` | Show current module information |
| `options` | Display module options and current values |

## Context Management

### Targets

| Command | Description |
|---------|-------------|
| `target <ip>` | Quick add and set target |
| `targets add <ip\|url> [name]` | Add target to database |
| `targets list` | List all targets (default) |
| `targets select` | Pick target interactively (fzf) |
| `targets set <index\|identifier>` | Set current target |
| `targets remove <identifier>` | Remove target by identifier |
| `targets modify` | Modify target interactively |
| `targets <idx> modify <k=v>...` | Modify target by index (e.g., `targets 1 modify name=Server ip=10.0.0.1`) |
| `targets clear` | Clear all targets |
| `targets <idx\|range> clear` | Clear by index or range (e.g., `targets 1-5 clear` or `targets 3 clear`) |

### Credentials

| Command | Description |
|---------|-------------|
| `cred <user:pass>` | Quick add and set credential |
| `creds add <user:pass> [domain]` | Add credential to database |
| `creds list` | List all credentials (default) |
| `creds select` | Pick credential interactively (fzf) |
| `creds set <index\|username>` | Set current credential |
| `creds remove <identifier>` | Remove credential |
| `creds modify` | Modify credential interactively |
| `creds <idx> modify <k=v>...` | Modify credential by index (e.g., `creds 1 modify password=newpass`) |
| `creds clear` | Clear all credentials |
| `creds <idx\|range> clear` | Clear by index or range (e.g., `creds 1-3 clear`) |

### Wordlists

| Command | Description |
|---------|-------------|
| `wordlists list` | List all wordlists by category (default) |
| `wordlists add <cat> <path> [name]` | Add wordlist by category |
| `wordlists select <category>` | Pick wordlist for category interactively |
| `wordlists set <cat> <path\|name\|idx>` | Set current wordlist for category |
| `wordlists remove <cat> <identifier>` | Remove wordlist from category |

**Categories**: web_dir, dns_vhost, username, password, subdomain, parameter, api, general

### Services

| Command | Description |
|---------|-------------|
| `services` | View detected services from scans |
| `services select` | Pick from detected services interactively |
| `services clear` | Clear all detected services |

### Other

| Command | Description |
|---------|-------------|
| `analysis` | View web scan results dashboard |
| `workspace <name>` | Switch to or create workspace |

## Execution

| Command | Description |
|---------|-------------|
| `run` | Execute module (interactive operation menu) |
| `run <number>` | Execute specific operation by number |
| `run <name>` | Execute operation by name |
| `set <option> <value>` | Set module option |
| `check` | Verify module can run with current options |

## Information

| Command | Description |
|---------|-------------|
| `show modules` | List all modules in tree view |
| `show targets` | List all saved targets |
| `show creds` | List all saved credentials |
| `show services` | List detected services from scans |
| `services select` | Pick from detected services interactively |
| `stats` | Display framework statistics |

## Utility

| Command | Description |
|---------|-------------|
| `ligolo` | Launch ligolo-ng proxy (CTRL+D to return) |
| `shell` | Drop to localhost shell (CTRL+D to return) |
| `hosts` | Generate /etc/hosts entries from targets |
| `history` | Show command history |
| `clear` | Clear the screen |
| `help` | Show detailed help |
| `exit` | Exit framework |

## Quick Workflows

| Command | Description |
|---------|-------------|
| `go <target> [cred] [op]` | Quick workflow: set target, cred, run operation |
| `quick <module> [filter]` | Load module with auto-population from context |

## Key Concepts

**search** = Find modules
**ops** = Context-aware: Show current module's operations (no args) or search globally (with args)
**select** = Interactive fuzzy selection with fzf
**Context** = Targets, creds, workspace persist across all modules
