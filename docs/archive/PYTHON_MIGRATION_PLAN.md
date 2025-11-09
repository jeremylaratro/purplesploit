# PurpleSploit Python Migration Plan

## Overview
Converting PurpleSploit from Bash to Python with a hybrid framework/TUI approach modeled after Quantsploit, with key differentiators from Metasploit.

## Architecture Overview

### Core Components (✅ COMPLETE)

1. **framework.py** - Main framework engine
   - Module registry and discovery
   - Module lifecycle management
   - Session management
   - Database integration
   - Context management (targets, creds, services)

2. **module.py** - Base module classes
   - `BaseModule` - Abstract base for all modules
   - `ExternalToolModule` - Base for tool wrappers
   - Option management system
   - Validation and execution

3. **session.py** - Persistent context
   - `Session` - Main session state
   - `TargetManager` - Persistent targets
   - `CredentialManager` - Persistent credentials
   - `ServiceManager` - Detected services
   - **Key Feature**: Context persists across module switches

4. **database.py** - SQLite storage
   - Module execution history
   - Targets and credentials
   - Service detection results
   - Scan results and findings
   - Workspaces

### UI Components (🔨 IN PROGRESS)

5. **display.py** - Rich text output
   - Status messages (success, error, warning, info)
   - Tables (targets, creds, modules, options)
   - Results rendering
   - Color-coded output

6. **commands.py** - Command handlers
   - Module commands (search, use, run, info, options, set)
   - Context commands (targets, creds, services)
   - Utility commands (help, show, clear, history, exit)
   - **TUI Integration**: search with fzf for visual selection

7. **console.py** - Main REPL
   - Interactive prompt
   - Command parsing and dispatch
   - Context-aware prompt display
   - History and completion

### Module System (📋 TODO)

8. **Modules Directory Structure**
   ```
   python/purplesploit/modules/
   ├── web/
   │   ├── feroxbuster.py
   │   ├── sqlmap.py
   │   ├── wfuzz.py
   │   └── httpx.py
   ├── network/
   │   ├── nxc_smb.py
   │   ├── nxc_ldap.py
   │   ├── nxc_winrm.py
   │   ├── nxc_mssql.py
   │   ├── nxc_rdp.py
   │   └── nxc_ssh.py
   ├── impacket/
   │   ├── psexec.py
   │   ├── wmiexec.py
   │   ├── secretsdump.py
   │   ├── kerberoast.py
   │   └── asreproast.py
   ├── recon/
   │   ├── nmap_scan.py
   │   └── service_detection.py
   └── ai/
       └── ai_automation.py
   ```

## Key Differentiators from Metasploit

### 1. Persistent Context
- **Metasploit**: Loses context when switching modules
- **PurpleSploit**: Targets, creds, and detected services persist
- **Implementation**: Session.targets, Session.credentials, Session.services

### 2. TUI Search
- **Metasploit**: `search smb` returns text list
- **PurpleSploit**: `search smb` opens fzf/TUI for visual selection
- **Implementation**: `search` command integrates with fzf

### 3. Auto-Context Loading
- **Metasploit**: Must manually set RHOST every time
- **PurpleSploit**: Auto-loads from current target
- **Implementation**: `auto_set_from_context()` in BaseModule

### 4. Service-Aware Modules
- **Metasploit**: Static module list
- **PurpleSploit**: Modules highlighted when service detected
- **Implementation**: ServiceManager tracks detected services

## Workflow Comparison

### Metasploit Workflow
```
msf6 > search smb
  [text list of modules]

msf6 > use exploit/windows/smb/psexec
msf6 exploit(psexec) > set RHOST 10.10.10.10
msf6 exploit(psexec) > set USERNAME admin
msf6 exploit(psexec) > set PASSWORD pass123
msf6 exploit(psexec) > run

msf6 exploit(psexec) > use auxiliary/scanner/smb/smb_version
msf6 auxiliary(smb_version) > set RHOST 10.10.10.10  # Must set again!
msf6 auxiliary(smb_version) > run
```

### PurpleSploit Workflow
```
purplesploit > targets add 10.10.10.10
[+] Target added: 10.10.10.10

purplesploit > creds add admin:pass123
[+] Credential added: admin

purplesploit > search smb
  [fzf TUI opens with visual selection]
  [user selects "nxc_smb" with arrow keys]

purplesploit (nxc_smb) > options
  [shows RHOST auto-populated from target]
  [shows USERNAME/PASSWORD auto-populated from creds]

purplesploit (nxc_smb) > run
  [executes with context]

purplesploit (nxc_smb) > back
purplesploit > use impacket/psexec
  [RHOST and credentials automatically set!]

purplesploit (psexec) > run
  [executes without manual configuration]
```

## Implementation Status

### ✅ Completed
- Core framework architecture
- Module base classes
- Session and context management
- Database layer with SQLite
- Persistent targets, credentials, services

### 🔨 In Progress
- UI display module
- Command handlers
- Console REPL
- fzf integration for search

### 📋 Pending
- Module conversions (19 modules to convert)
- Entry point (main.py)
- Example modules
- Testing and validation
- Documentation

## Module Conversion Strategy

### Tool Wrapper Pattern
Most modules wrap external tools. Use `ExternalToolModule` base class:

```python
from purplesploit.core.module import ExternalToolModule

class FeroxbusterModule(ExternalToolModule):
    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "feroxbuster"

    @property
    def name(self) -> str:
        return "Feroxbuster"

    @property
    def description(self) -> str:
        return "Fast directory and file discovery tool"

    @property
    def category(self) -> str:
        return "web"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    def _init_options(self):
        super()._init_options()
        self.options.update({
            "EXTENSIONS": {
                "value": "php,html,js,txt",
                "required": False,
                "description": "File extensions to search for"
            },
            "WORDLIST": {
                "value": "/usr/share/wordlists/dirb/common.txt",
                "required": False,
                "description": "Wordlist path"
            },
            "PROXY": {
                "value": "http://127.0.0.1:8080",
                "required": False,
                "description": "Proxy URL for Burp integration"
            }
        })

    def build_command(self) -> str:
        url = self.get_option("URL")
        exts = self.get_option("EXTENSIONS")
        wordlist = self.get_option("WORDLIST")
        proxy = self.get_option("PROXY")

        cmd = f"feroxbuster -u '{url}' --thorough --methods GET,POST"

        if exts:
            cmd += f" -x '{exts}'"
        if wordlist:
            cmd += f" -w '{wordlist}'"
        if proxy:
            cmd += f" --proxy '{proxy}'"

        return cmd
```

### Module Priority Order

**Phase 1: Core Tools** (High Priority)
1. web/feroxbuster.py
2. network/nxc_smb.py
3. recon/nmap_scan.py

**Phase 2: Network Tools**
4. network/nxc_ldap.py
5. network/nxc_winrm.py
6. network/nxc_mssql.py
7. network/nxc_rdp.py
8. network/nxc_ssh.py

**Phase 3: Impacket**
9. impacket/psexec.py
10. impacket/wmiexec.py
11. impacket/secretsdump.py
12. impacket/kerberoast.py

**Phase 4: Remaining**
13-19. Other web and auxiliary modules

## Command Reference

### Module Commands
- `search <query>` - Search modules (opens fzf TUI)
- `use <module>` - Load a module
- `run` / `exploit` - Execute current module
- `back` - Unload current module
- `info` - Show module information
- `options` / `show options` - Display module options
- `set <option> <value>` - Set an option
- `unset <option>` - Clear an option
- `check` - Test if module can run

### Context Commands
- `targets` / `show targets` - List targets
- `targets add <ip/url>` - Add target
- `targets set <id/ip>` - Set current target
- `targets remove <id/ip>` - Remove target
- `creds` / `show creds` - List credentials
- `creds add <username>:<password>` - Add credential
- `creds set <id>` - Set current credential
- `services` / `show services` - List detected services
- `services scan` - Run service detection

### Utility Commands
- `help` / `?` - Show help
- `show <modules|categories|targets|creds|services>` - Display information
- `history` - Show command history
- `clear` - Clear screen
- `exit` / `quit` - Exit framework

## Installation & Usage

### Setup
```bash
cd /home/user/purplesploit_private

# Install dependencies
pip install -r python/requirements.txt

# Run framework
python3 -m purplesploit.main
```

### First Run Example
```bash
purplesploit > help
  [shows command list]

purplesploit > targets add 10.10.10.10
purplesploit > creds add admin:Password123
purplesploit > search ferox
  [fzf selection opens]
purplesploit (Feroxbuster) > set URL http://10.10.10.10
purplesploit (Feroxbuster) > run
  [output displayed]
```

## Testing Plan

### Unit Tests
- Test module loading and registration
- Test option validation
- Test context management
- Test database operations

### Integration Tests
- Test full workflow with real modules
- Test context persistence
- Test command execution
- Test search and TUI

### Migration Testing
- Run equivalent commands in bash vs Python
- Verify output matches
- Ensure all tools are accessible
- Validate performance

## Migration Timeline

### Week 1: Foundation
- ✅ Core framework (Complete)
- ✅ Session management (Complete)
- ✅ Database layer (Complete)
- 🔨 UI components (In progress)

### Week 2: Modules
- Convert Phase 1 modules (feroxbuster, nxc_smb, nmap)
- Test basic workflows
- Implement fzf search integration

### Week 3: Expansion
- Convert Phase 2 & 3 modules
- Add error handling and logging
- Performance optimization

### Week 4: Polish
- Convert remaining modules
- Documentation
- Testing and bug fixes
- User acceptance testing

## Success Criteria

1. ✅ All 19 modules converted and working
2. ✅ Persistent context across module switches
3. ✅ fzf/TUI search working
4. ✅ Auto-population of options from context
5. ✅ Service detection integration
6. ✅ Database persistence working
7. ✅ Command history and session export
8. ✅ Comprehensive documentation
9. ✅ All existing functionality preserved
10. ✅ User feedback positive

## Next Steps

1. Complete UI components (display, commands, console)
2. Create main entry point
3. Implement fzf search integration
4. Convert first 3 modules (feroxbuster, nxc_smb, nmap)
5. Test end-to-end workflow
6. Iterate based on testing
7. Convert remaining modules
8. Documentation and cleanup
