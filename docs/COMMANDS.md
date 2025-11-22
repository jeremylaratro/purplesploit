# PurpleSploit Core Commands

Quick reference for essential commands.

## Discovery

| Command | Description |
|---------|-------------|
| `search <query>` | Find modules by name, description, or category |
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

| Command | Description |
|---------|-------------|
| `target <ip>` | Quick add and set target |
| `cred <user:pass>` | Quick add and set credential |
| `targets add <ip> [name]` | Add target to database |
| `targets select` | Pick target interactively |
| `creds add <user:pass> [domain]` | Add credential to database |
| `creds select` | Pick credential interactively |
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
**ops** = Find operations (actions) across all modules
**select** = Interactive fuzzy selection with fzf
**Context** = Targets, creds, workspace persist across all modules
