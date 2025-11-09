# PurpleSploit Rich TUI

A beautiful, modern terminal user interface for PurpleSploit built with the Python Rich library.

## Overview

The Rich TUI is a complete UI refactoring that provides:
- **Beautiful Visual Design**: Rich library for gorgeous terminal output with colors, tables, and panels
- **Interactive Menus**: Clean, organized menu system with service detection highlighting
- **Autocomplete**: Tab completion and command suggestions using prompt_toolkit
- **Context Display**: Always visible workspace, target, and credential information
- **Service Detection**: Visual indicators showing which services are detected on targets
- **Bash Backend**: Keeps all existing bash scripts intact - Python just provides the UI layer

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- All existing PurpleSploit bash dependencies

### Install Python Dependencies

From the project root:

```bash
cd python
pip3 install -r requirements.txt
```

Or install just the TUI requirements:

```bash
pip3 install rich prompt_toolkit
```

### Install as Package (Optional)

For system-wide installation:

```bash
cd python
pip3 install -e .
```

This will install the `purplesploit-rich` and `purplesploit-pro` commands.

## Usage

### Launching the Rich TUI

**Option 1: Direct script execution**
```bash
./bin/purplesploit-rich
```

**Option 2: Python module**
```bash
python3 -m purplesploit.tui.app
```

**Option 3: If installed as package**
```bash
purplesploit-rich
# or
purplesploit-pro
```

### Interactive CLI Mode

For a command-line interface with autocomplete:

```bash
./bin/purplesploit-rich --interactive
# or
./bin/purplesploit-rich -i
```

## Features

### 1. Beautiful ASCII Banner

The Rich TUI displays a stunning ASCII art banner on startup with the PurpleSploit logo in vivid colors.

### 2. Context Panel

Always-visible context information showing:
- **Workspace**: Current workspace name
- **Target**: Currently selected target IP/hostname
- **Credentials**: Active credentials (username/domain/auth type)

### 3. Service Detection Indicators

Tools are marked with colored service icons (🗄️, 📁, 🖥️, etc.) that change color based on detection:
- **Green icons**: Service detected on target
- **Red/dim icons**: Service not detected

This helps you quickly identify which tools are relevant for your current target.

### 4. Category-Based Menus

Tools are organized into logical categories:
- **Web Testing** - feroxbuster, sqlmap, wfuzz, httpx
- **SMB Operations** - All SMB-related tools
- **LDAP Operations** - Active Directory enumeration
- **WinRM Operations** - Windows Remote Management
- **MSSQL Operations** - SQL Server testing
- **RDP Operations** - Remote Desktop testing
- **SSH Operations** - SSH operations
- **Reconnaissance** - Nmap and scanning tools
- **Network Testing - NXC** - NetExec tools
- **Network Testing - Impacket** - Impacket toolkit
- **C2 & Command Control** - Mythic C2 deployment
- **AI Automation** - AI-assisted pentesting

### 5. Interactive Settings Menu

Access settings to:
- **Manage Workspaces**: Create, switch, list workspaces
- **Manage Targets**: Add, set, list targets
- **Manage Credentials**: Set username/password or NTLM hash
- **Set Variables**: Configure framework variables (LHOST, LPORT, etc.)
- **Run Service Scan**: Execute nmap scan on current target
- **View Variables**: Display all configured variables

### 6. Autocomplete

The interactive mode features intelligent autocomplete for:
- Commands (workspace, target, set, scan, etc.)
- Variable names (RHOST, LPORT, USERNAME, etc.)
- Workspace names
- Target IPs
- Tool categories

### 7. Beautiful Output

All output uses Rich formatting:
- **Tables**: Clean, bordered tables for data display
- **Panels**: Organized panels with titles and borders
- **Syntax Highlighting**: Colored output for better readability
- **Progress Indicators**: Spinners for long-running operations
- **Status Messages**: Color-coded success/error/info/warning messages

## Architecture

### Component Overview

```
python/purplesploit/tui/
├── __init__.py           # Package initialization
├── app.py                # Main TUI application
├── themes.py             # Colors, styling, ASCII art
├── bash_executor.py      # Execute bash scripts from Python
├── context.py            # Workspace/target/credential management
├── service_detector.py   # Service detection integration
├── menu.py               # Rich-based menu system
└── completer.py          # Autocomplete functionality
```

### How It Works

1. **Python UI Layer**: All visual elements use Rich library
2. **Bash Backend**: Original bash scripts remain unchanged
3. **BashExecutor**: Python wrapper executes bash commands via subprocess
4. **Context Management**: Syncs with framework variable system
5. **Service Detection**: Reads from framework's service database

### Integration with Bash Backend

The Rich TUI doesn't replace the bash backend - it enhances it:

- **Bash scripts stay the same**: All tool modules remain in `modules/`
- **Framework intact**: Uses existing framework core
- **Database sharing**: Reads from same SQLite databases
- **Variable system**: Integrates with bash variable manager
- **Workspace compatibility**: Works with existing workspaces

You can switch between the bash TUI and Rich TUI seamlessly - they share all data.

## Menu Navigation

### Main Menu Controls

- **Number keys (1-9)**: Select menu option
- **b** or **back**: Return to previous menu
- **q** or **quit**: Exit application
- **Ctrl+C**: Cancel current operation

### Interactive Mode Commands

```bash
# Workspace management
workspace list
workspace switch <name>
workspace create <name>

# Target management
target list
target set <ip>
target add <ip>

# Variable management
set <VAR> <value>
get <VAR>
show variables

# Scanning
scan quick
scan full
scan vuln

# Navigation
menu          # Return to menu mode
clear         # Clear screen
help          # Show help
exit          # Quit
```

## Color Theme

The PurpleSploit theme uses:
- **Magenta**: Primary color, headers, workspace
- **Cyan**: Secondary color, menus, borders
- **Green**: Success messages, active services, targets
- **Yellow**: Warnings, credentials, highlights
- **Red**: Errors, inactive services
- **Blue**: Info messages

## Examples

### Basic Workflow

1. **Launch the TUI**
   ```bash
   ./bin/purplesploit-rich
   ```

2. **Set up context** (via Settings menu)
   - Create/switch workspace
   - Add and set target
   - Set credentials

3. **Run service scan**
   - Select "Run Service Scan" from Settings
   - Choose scan type (quick/full/vuln)
   - Wait for results

4. **Execute tools**
   - Return to main menu
   - Tools with detected services are highlighted
   - Select category and tool
   - Tool executes using bash backend

### Setting Variables

Via Settings menu:
1. Select "Set Variables"
2. Enter variable name (e.g., `LHOST`)
3. Enter value (e.g., `10.10.14.5`)

### Managing Credentials

Via Settings menu:
1. Select "Manage Credentials"
2. Choose:
   - **(u)** Username/password auth
   - **(h)** NTLM hash auth
   - **(c)** Clear credentials

## Customization

### Themes

Edit `python/purplesploit/tui/themes.py` to customize:
- Colors
- Icons
- ASCII banner
- Status indicators

### Menu Structure

Edit `python/purplesploit/tui/menu.py` to:
- Add new categories
- Change menu organization
- Customize menu items

### Service Icons

Add or modify service icons in `themes.py`:

```python
SERVICE_ICONS = {
    "smb": "🗄️",
    "ldap": "📁",
    # Add your own...
}
```

## Troubleshooting

### Import Errors

If you see `ModuleNotFoundError: No module named 'rich'`:

```bash
pip3 install rich prompt_toolkit
```

### Bash Scripts Not Found

Ensure you're running from the project root:

```bash
cd /path/to/purplesploit_private
./bin/purplesploit-rich
```

### Framework Initialization Failed

Check that bash framework components exist:

```bash
ls framework/core/engine.sh
ls modules/
```

### Service Detection Not Working

Run a scan first:
1. Set a target
2. Select "Run Service Scan" from Settings
3. Choose scan type

### Permission Issues

If scripts aren't executable:

```bash
chmod +x bin/purplesploit-rich
```

## Comparison with Original TUI

| Feature | Original TUI | Rich TUI |
|---------|-------------|----------|
| **Technology** | Bash + FZF | Python + Rich |
| **Visual Style** | Basic terminal | Beautiful tables/panels |
| **Autocomplete** | FZF search | Prompt_toolkit autocomplete |
| **Service Detection** | Text markers (●) | Colored icons |
| **Context Display** | Header text | Rich panels |
| **Menu Navigation** | FZF selection | Number + keyboard |
| **Backend** | Bash scripts | Same bash scripts |
| **Data Sharing** | Native | Via subprocess |
| **Speed** | Very fast | Fast (slight overhead) |
| **Dependencies** | fzf, bash | Python, rich, prompt_toolkit |

## Development

### Adding New Features

1. **New menu item**: Edit `menu.py` → `create_category_menu()`
2. **New command**: Edit `completer.py` → add to commands list
3. **New service icon**: Edit `themes.py` → `SERVICE_ICONS`
4. **New theme color**: Edit `themes.py` → `PURPLESPLOIT_THEME`

### Testing

Run the component tests:

```bash
python3 test_rich_tui.py
```

### Code Structure

- **app.py**: Main application logic and menu handlers
- **menu.py**: Menu rendering and selection
- **bash_executor.py**: Bash integration
- **context.py**: State management
- **themes.py**: Visual styling
- **completer.py**: Autocomplete logic
- **service_detector.py**: Service detection

## Future Enhancements

Potential improvements:
- [ ] Real-time output streaming
- [ ] Command history search
- [ ] Saved command templates
- [ ] Module favorites/bookmarks
- [ ] Multi-target operations
- [ ] Report generation integration
- [ ] Live status dashboard
- [ ] Keyboard shortcuts customization

## Credits

- **Rich**: [Textualize/rich](https://github.com/Textualize/rich)
- **Prompt Toolkit**: [prompt-toolkit](https://github.com/prompt-toolkit/python-prompt-toolkit)
- **PurpleSploit**: Original framework by PurpleSploit Team

## License

Same as PurpleSploit main project.
