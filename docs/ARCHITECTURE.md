# PurpleSploit Architecture

## Overview

PurpleSploit is a hybrid pentesting framework combining modular architecture with comprehensive tool coverage. It features a visual TUI interface, AI automation capabilities, and extensive support for modern pentesting tools.

**Version:** 2.0
**Architecture:** Hybrid (Framework Backend + Tool Handlers)
**Primary Interface:** Interactive TUI with FZF

## Project Structure

```
purplesploit/
├── purplesploit-tui.sh          # Main entry point (LAUNCH THIS)
├── README.md                     # User documentation
├── .gitignore                    # Git ignore rules
│
├── bin/                          # Alternative interfaces & utilities
│   ├── purplesploit.sh          # Original lite version
│   ├── purplesploit-framework.sh # CLI framework interface
│   ├── purplesploit-tui-simple.sh # Framework-only TUI
│   ├── setup-nxc-navi.sh        # NXC setup utility
│   └── nxc-fixed.cheat          # NXC cheat sheet
│
├── core/                         # Core system components
│   ├── config.sh                # Global configuration
│   ├── database.sh              # SQLite database layer
│   └── ui.sh                    # UI components & menus
│
├── lib/                          # Library modules
│   ├── credentials.sh           # Credential management
│   ├── targets.sh               # Network target management
│   ├── web_targets.sh           # Web target management
│   ├── ad_targets.sh            # Active Directory targets
│   ├── services.sh              # Service detection
│   └── database_management.sh   # Database operations
│
├── modules/                      # Tool modules
│   ├── web/                     # Web testing tools
│   │   ├── feroxbuster.sh       # Directory/file discovery
│   │   ├── wfuzz.sh             # Web fuzzing
│   │   ├── sqlmap.sh            # SQL injection
│   │   └── httpx.sh             # HTTP probing
│   │
│   ├── nxc/                     # NetExec (NXC) modules
│   │   ├── smb.sh               # SMB operations (auth, enum, shares, exec, creds, vulns, utils)
│   │   ├── ldap.sh              # LDAP enumeration
│   │   ├── winrm.sh             # WinRM operations
│   │   ├── mssql.sh             # MSSQL operations
│   │   ├── rdp.sh               # RDP operations
│   │   ├── ssh.sh               # SSH operations
│   │   └── scanning.sh          # Network scanning
│   │
│   ├── impacket/                # Impacket tool wrappers
│   │   ├── psexec.sh            # PSExec operations
│   │   ├── wmiexec.sh           # WMIExec operations
│   │   ├── smbexec.sh           # SMBExec operations
│   │   ├── atexec.sh            # ATExec operations
│   │   ├── dcomexec.sh          # DCOMExec operations
│   │   ├── secretsdump.sh       # Credential dumping
│   │   ├── kerberoast.sh        # Kerberoasting
│   │   ├── asreproast.sh        # AS-REP roasting
│   │   ├── tickets.sh           # Kerberos tickets
│   │   ├── enum.sh              # Enumeration tools
│   │   ├── smbclient.sh         # SMB client
│   │   ├── services.sh          # Service management
│   │   └── registry.sh          # Registry operations
│   │
│   └── ai_automation.sh         # AI automation handler
│
├── framework/                    # Framework backend (modular architecture)
│   └── core/
│       ├── engine.sh            # Framework lifecycle
│       ├── variable_manager.sh  # Variable substitution
│       ├── module_registry.sh   # Module discovery
│       ├── command_engine.sh    # Command processing
│       ├── workspace_manager.sh # Workspace management
│       ├── fzf_integration.sh   # FZF interactive selection
│       ├── credential_manager.sh # Credential system
│       ├── mythic_integration.sh # Mythic C2 integration
│       └── service_analyzer.sh  # Service detection & filtering
│
├── tools/                        # Standalone tools & scripts
│   ├── ai_kali_client.py        # AI MCP client (OpenAI/Claude)
│   ├── parse_nmap.py            # Nmap output parser
│   └── parse_spider_plus.py     # Spider_plus result parser
│
└── docs/                         # Documentation
    ├── AI_AUTOMATION.md         # AI automation guide
    ├── FEATURES.md              # Feature documentation
    ├── FRAMEWORK_README.md      # Framework architecture
    ├── SERVICE_ANALYSIS.md      # Service detection docs
    ├── INTERFACES.md            # Interface comparison
    ├── CONTRIBUTING.md          # Contribution guide
    ├── legacy/                  # Legacy documentation
    └── examples/                # Examples & templates
        └── MODULE_TEMPLATE.psm  # Module template
```

## Architecture Layers

### Layer 1: Entry Point
**File:** `purplesploit-tui.sh`

The main TUI interface that users launch. Provides:
- Visual menu navigation with FZF
- Service detection highlighting
- Keyboard shortcuts (CTRL+key combinations)
- Session management
- Direct access to all tools

### Layer 2: Hybrid Backend
**Components:** Framework core + Tool handlers

**Framework Backend:**
- Variable management (universal ${VAR} substitution)
- Workspace organization (per-engagement isolation)
- Module registry (.psm file discovery)
- Background job management
- Service-aware module filtering

**Tool Handlers:**
- Direct tool integration (NXC, Impacket, Web tools)
- Submenu generation with FZF
- Command preview before execution
- Comprehensive option coverage

### Layer 3: Core Libraries
**Location:** `lib/` and `core/`

Provides:
- SQLite database for persistent storage
- Credential management (sets, null auth, guest)
- Target management (network, web, AD)
- Service detection and tracking
- Configuration management
- UI component generation

### Layer 4: Tool Modules
**Location:** `modules/`

Self-contained tool wrappers:
- Web testing (Feroxbuster, WFUZZ, SQLMap, HTTPX)
- Network testing (NXC for SMB, LDAP, WinRM, MSSQL, RDP, SSH)
- Windows exploitation (Impacket suite)
- AI automation (OpenAI/Claude integration)

Each module exports functions and integrates with the TUI.

### Layer 5: Framework Engine
**Location:** `framework/core/`

Advanced features:
- .psm module system (Metasploit-inspired)
- Variable substitution engine
- Workspace isolation
- FZF integration for interactive selection
- Mythic C2 integration
- Service analyzer with smart filtering

## Data Flow

### Command Execution Flow

```
User Selection (TUI)
       ↓
Menu Handler (core/ui.sh)
       ↓
Tool Module (modules/*/tool.sh)
       ↓
show_menu() → Build submenu with FZF
       ↓
User Selects Option
       ↓
run_command() → Preview command
       ↓
User Confirms
       ↓
eval → Execute command
       ↓
Display Output
       ↓
Wait for user (Press Enter)
       ↓
Return to submenu
```

### Service Detection Flow

```
Target Selected
       ↓
Check ~/.purplesploit/nmap_scans/
       ↓
Parse with parse_nmap.py
       ↓
Extract service info (SMB, LDAP, HTTP, etc.)
       ↓
Store in service database
       ↓
Highlight relevant menu items with ●
       ↓
Filter module list (framework mode)
```

### AI Automation Flow

```
User Query (Natural Language)
       ↓
ai_kali_client.py (tools/)
       ↓
OpenAI/Claude API
       ↓
Function Calling Decision
       ↓
MCP Server (HTTP API)
       ↓
execute_shell_command() or run_nmap()
       ↓
Command Execution on Kali
       ↓
Return Results to AI
       ↓
AI Analysis & Response
       ↓
Display to User
```

## Key Design Patterns

### 1. Hybrid Architecture
Combines two proven approaches:
- **Framework Backend:** Modular, extensible, workspace-aware
- **Lite Handlers:** Direct tool integration, comprehensive coverage

Benefits:
- Best of both worlds
- Backwards compatible
- Easy to extend
- Fast execution

### 2. FZF-Driven Interface
All menus use FZF for:
- Full-screen visual navigation
- Fuzzy searching
- Keyboard shortcuts
- Context display in headers
- Service highlighting

### 3. Service-Aware Menus
Dynamic menu highlighting based on detected services:
```bash
● SMB Authentication    # ● indicates SMB detected on target
  LDAP Enumeration      # No marker = service not detected
```

### 4. Variable Substitution
Universal variable system:
```bash
${RHOST}  → Current target IP
${DOMAIN} → Domain name
${USERNAME} → Current credentials
```

Used in:
- Module commands (.psm files)
- Manual command entry
- AI automation context

### 5. Workspace Isolation
Per-engagement organization:
```
~/.purplesploit/workspaces/
├── default/
│   ├── variables.env
│   └── output/
├── client-pentest/
│   ├── variables.env
│   └── output/
└── lab-testing/
    ├── variables.env
    └── output/
```

### 6. Database-Backed Storage
SQLite databases for:
- Credentials (sets with username/password/hash)
- Targets (network, web, AD)
- Services (detected from nmap)
- Nmap results (scan history)

Location: `~/.purplesploit/*.db`

## Component Details

### Core Configuration (core/config.sh)
- Global variables (colors, paths, defaults)
- Database initialization
- Default credential sets (Null Auth, Guest)
- Directory structure creation

### UI System (core/ui.sh)
- `show_menu()` - Generate FZF menus by category
- `run_command()` - Command preview and execution
- `highlight_if_active()` - Service-based highlighting
- Dynamic header generation

### Credential System (lib/credentials.sh)
```sql
CREATE TABLE credentials (
    name TEXT PRIMARY KEY,
    username TEXT,
    password TEXT,
    domain TEXT,
    hash TEXT
);
```

Functions:
- `add_credential()` - Store credentials
- `list_cred_names()` - List available sets
- `select_credentials()` - Interactive selection
- `build_auth()` - Build NXC auth string

### Target Management (lib/targets.sh)
```sql
CREATE TABLE targets (
    name TEXT PRIMARY KEY,
    ip TEXT,
    description TEXT
);
```

Functions:
- `add_target()` - Add network target
- `list_target_names()` - List all targets
- `select_target()` - Interactive selection
- `get_target_for_command()` - Get current target with fallback

### Service Detection (lib/services.sh)
```sql
CREATE TABLE services (
    target TEXT,
    service TEXT,
    port INTEGER,
    version TEXT
);
```

Detects:
- SMB (445)
- LDAP (389, 636)
- WinRM (5985, 5986)
- MSSQL (1433)
- RDP (3389)
- SSH (22)
- HTTP/HTTPS (80, 443, 8080, 8443)

### Module System (framework/core/module_registry.sh)
Discovers .psm files in `modules/` directories:

```bash
# MODULE_NAME.psm
MODULE_NAME="recon/nmap/quick_scan"
MODULE_DESCRIPTION="Fast nmap scan"
MODULE_AUTHOR="PurpleSploit"
MODULE_CATEGORY="reconnaissance"
COMMAND_TEMPLATE="nmap -sV -T4 ${RHOST}"
REQUIRED_VARS="RHOST"
```

Registry functions:
- `module_registry_init()` - Discover all .psm files
- `module_load_metadata()` - Parse module headers
- `module_search()` - Search by name/category
- `module_use()` - Load module for execution

### Workspace System (framework/core/workspace_manager.sh)
```bash
~/.purplesploit/workspaces/
└── <workspace-name>/
    ├── variables.env      # Saved variables
    └── output/            # Command output logs
```

Functions:
- `workspace_init()` - Initialize system
- `workspace_create()` - Create new workspace
- `workspace_switch()` - Change active workspace
- `workspace_list()` - List all workspaces
- `var_save_workspace()` - Save current state
- `var_load_workspace()` - Load workspace state

### AI Automation (tools/ai_kali_client.py)
Python-based MCP client supporting:
- OpenAI GPT-4 (gpt-4o)
- Claude Sonnet (claude-sonnet-4-20250514)

Function calling:
- `execute_shell_command()` - Run any command
- `run_nmap()` - Specialized nmap execution

Configuration:
```bash
~/.purplesploit/ai_config
```

## Interface Comparison

### purplesploit-tui.sh (Recommended)
**Type:** Hybrid TUI
**Features:**
- ✅ Full visual menu (50+ categories)
- ✅ Service detection highlighting
- ✅ Framework backend (workspaces, variables)
- ✅ Lite handlers (all tools)
- ✅ CTRL+key shortcuts
- ✅ Session management
- ✅ AI automation

**Use case:** Primary interface for all pentesting

### bin/purplesploit.sh
**Type:** Original lite version
**Features:**
- ✅ Full menu coverage
- ✅ Proven stability
- ❌ No workspaces
- ❌ No variable system
- ❌ Single-letter keybinds

**Use case:** Fallback if hybrid TUI has issues

### bin/purplesploit-framework.sh
**Type:** CLI framework
**Features:**
- ✅ Metasploit-style CLI
- ✅ Module system (.psm files)
- ✅ Variable substitution
- ✅ Workspaces
- ❌ No direct tool integration
- ❌ Command-line only

**Use case:** Scripting, automation, advanced users

### bin/purplesploit-tui-simple.sh
**Type:** Framework-only TUI
**Features:**
- ✅ Visual menu
- ✅ Framework backend only
- ✅ Module system
- ❌ Limited tool coverage (~20 modules)
- ❌ No lite handlers

**Use case:** Testing framework features

## Database Schema

### Location
```
~/.purplesploit/
├── credentials.db
├── targets.db
├── web_targets.db
├── ad_targets.db
└── services.db
```

### credentials.db
```sql
CREATE TABLE credentials (
    name TEXT PRIMARY KEY,
    username TEXT,
    password TEXT,
    domain TEXT,
    hash TEXT
);
```

Default entries:
- Null Auth (empty credentials)
- Guest Account (guest/guest)

### targets.db
```sql
CREATE TABLE targets (
    name TEXT PRIMARY KEY,
    ip TEXT,
    description TEXT
);
```

### web_targets.db
```sql
CREATE TABLE web_targets (
    name TEXT PRIMARY KEY,
    url TEXT,
    description TEXT
);
```

### ad_targets.db
```sql
CREATE TABLE ad_targets (
    name TEXT PRIMARY KEY,
    domain TEXT,
    dc_ip TEXT,
    description TEXT
);
```

### services.db
```sql
CREATE TABLE services (
    target TEXT,
    service TEXT,
    port INTEGER,
    version TEXT,
    PRIMARY KEY (target, service, port)
);
```

## Extensibility

### Adding a New Tool Module

1. Create handler script:
```bash
modules/category/tool.sh
```

2. Implement handler function:
```bash
handle_toolname() {
    while true; do
        subchoice=$(show_menu "toolname" "Select Operation: ")
        [[ -z "$subchoice" ]] && break

        case "$subchoice" in
            "Option 1")
                run_command "tool command here"
                ;;
        esac
    done
}

export -f handle_toolname
```

3. Add menu definition to `core/ui.sh`:
```bash
"toolname")
    echo "Option 1
Option 2
Back" | fzf --prompt="Tool: "
    ;;
```

4. Source in TUI:
```bash
# purplesploit-tui.sh
source "$SCRIPT_DIR/modules/category/tool.sh"
```

5. Add menu item:
```bash
# purplesploit-tui.sh - show_main_menu()
New Tool Name
```

6. Add handler case:
```bash
# purplesploit-tui.sh - main()
"New Tool Name") handle_toolname ;;
```

### Adding a Framework Module

1. Create .psm file:
```bash
docs/examples/my_module.psm
```

2. Define metadata:
```bash
MODULE_NAME="category/subcategory/module_name"
MODULE_DESCRIPTION="What this module does"
MODULE_AUTHOR="Your Name"
MODULE_CATEGORY="reconnaissance|exploitation|post-exploitation"
MODULE_PLATFORM="linux|windows|network"
COMMAND_TEMPLATE="tool ${RHOST} -p ${RPORT}"
REQUIRED_VARS="RHOST,RPORT"
OPTIONAL_VARS="LHOST"
```

3. Copy to modules directory:
```bash
mkdir -p modules/category/subcategory/
cp my_module.psm modules/category/subcategory/
```

4. Module auto-discovered on framework init

### Adding a New Service

1. Edit `lib/services.sh`:
```bash
detect_service_from_nmap() {
    # Add new service pattern
    if echo "$nmap_output" | grep -q "9999/tcp.*open.*myservice"; then
        add_service "$target" "myservice" "9999"
    fi
}
```

2. Add to service list:
```bash
service_check() {
    local service=$2
    case "$service" in
        myservice)
            # Detection logic
            ;;
    esac
}
```

3. Use in menus:
```bash
$(highlight_if_active "$target" "myservice" "My Service Operations")
```

## Performance Considerations

### Database Optimization
- SQLite with WAL mode
- Indexed primary keys
- Cached queries where possible

### FZF Performance
- Limited history depth
- Efficient string matching
- Preview disabled for large lists

### Background Jobs
- Process management with PIDs
- Output streaming to files
- Kill signals for cleanup

### Variable Substitution
- Sed-based replacement (fast)
- Cached variable state
- Lazy loading of workspaces

## Security Considerations

### Credential Storage
- SQLite database (file permissions 600)
- No encryption (assumes trusted system)
- Hashes stored as-is (NTLM, etc.)

### Command Injection
- Variables used in `eval` context
- User responsible for safe input
- Preview before execution

### API Keys
- Environment variables only
- Never logged
- Separate config file (mode 600)

### MCP Server
- HTTP communication (use localhost)
- No authentication by default
- Isolated execution environment recommended

## Testing

### Manual Testing Checklist
- [ ] Launch TUI
- [ ] Navigate all menus
- [ ] Test CTRL+key shortcuts
- [ ] Add credentials
- [ ] Add targets
- [ ] Run nmap scan
- [ ] Verify service detection
- [ ] Test workspace switching
- [ ] Launch AI assistant
- [ ] Execute NXC command
- [ ] Check database persistence

### Module Testing
```bash
# Source module
source modules/web/feroxbuster.sh

# Test function
handle_feroxbuster
```

### Framework Testing
```bash
# Launch framework CLI
./bin/purplesploit-framework.sh

# Test commands
search nmap
use recon/nmap/quick_scan
set RHOST 192.168.1.100
run
```

## Troubleshooting

### Common Issues

**Issue:** TUI crashes on launch
**Solution:** Check `~/.purplesploit/` exists, verify database permissions

**Issue:** Modules not loading
**Solution:** Source `core/ui.sh`, check function exports

**Issue:** Service detection not working
**Solution:** Run nmap scan, check `~/.purplesploit/nmap_scans/`, verify `parse_nmap.py`

**Issue:** AI automation fails
**Solution:** Check API keys, verify MCP server, test dependencies

**Issue:** Variables not substituting
**Solution:** Check workspace loaded, verify `variables.env` exists

### Debug Mode
```bash
# Enable bash debugging
bash -x ./purplesploit-tui.sh

# Check database
sqlite3 ~/.purplesploit/credentials.db ".tables"
sqlite3 ~/.purplesploit/targets.db "SELECT * FROM targets;"

# Verify functions loaded
declare -F | grep handle_
```

## Future Enhancements

### Planned Features
- [ ] Report generation (HTML/PDF)
- [ ] Automated exploitation workflows
- [ ] Credential spraying module
- [ ] Bloodhound integration
- [ ] C2 framework integrations (Sliver, Havoc)
- [ ] Multi-target batch operations
- [ ] Session recording/playback
- [ ] Plugin marketplace

### Architecture Improvements
- [ ] Module dependency management
- [ ] Version control for modules
- [ ] Encrypted credential storage
- [ ] REST API for external tools
- [ ] Web-based TUI alternative
- [ ] Team collaboration features

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:
- Code style
- Module structure
- Testing requirements
- Documentation standards
- Pull request process

## References

- [NetExec Documentation](https://github.com/Pennyw0rth/NetExec)
- [Impacket Examples](https://github.com/fortra/impacket)
- [FZF Documentation](https://github.com/junegunn/fzf)
- [SQLite Documentation](https://www.sqlite.org/docs.html)

---

**Last Updated:** 2025-11-03
**Version:** 2.0
**Architecture:** Hybrid TUI
