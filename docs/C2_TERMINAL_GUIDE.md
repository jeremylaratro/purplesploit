# PurpleSploit C2 Terminal Guide

## Overview

The PurpleSploit C2 Terminal provides a world-class command and control interface for the pentesting framework, featuring real-time command execution, module browsing, and session management through an intuitive web-based terminal.

## Features

### 🎯 Core Capabilities

- **Real-time Command Execution**: WebSocket-based terminal with instant feedback
- **Module Browser**: Searchable sidebar with categorized modules
- **Session Management**: Persistent command history and context tracking
- **Context-Aware Operations**: Automatic target and credential management
- **Modern Dark UI**: Professional C2-style interface inspired by elite pentesting tools

### 💻 Terminal Commands

| Command | Description | Example |
|---------|-------------|---------|
| `help` | Show available commands | `help` |
| `search <query>` | Search for modules | `search smb enum` |
| `use <module>` | Load a module | `use network/nxc_smb` |
| `show modules` | List all modules | `show modules` |
| `show options` | Show module options | `show options` |
| `set <opt> <val>` | Set module option | `set RHOST 10.10.10.100` |
| `run` | Execute current module | `run` |
| `back` | Unload current module | `back` |
| `target <ip>` | Set target | `target 192.168.1.100` |
| `targets` | List targets | `targets` |
| `cred <user:pass>` | Add credential | `cred admin:password123` |
| `creds` | List credentials | `creds` |
| `stats` | Show statistics | `stats` |
| `clear` | Clear terminal | `clear` |

### 🔌 API Endpoints

#### C2 Command Execution
```bash
POST /api/c2/command
{
  "command": "search smb",
  "session_id": "default"
}
```

#### Module Management
```bash
GET  /api/c2/modules              # List all modules
GET  /api/c2/modules/search?query=smb  # Search modules
GET  /api/c2/module/{path}        # Get module details
POST /api/c2/module/execute       # Execute a module
```

#### Session Management
```bash
GET    /api/c2/session/{id}       # Get session info
GET    /api/c2/sessions            # List all sessions
DELETE /api/c2/session/{id}       # Clear session
```

#### WebSocket
```bash
WS /ws/c2/{session_id}             # Real-time terminal
```

## Usage Examples

### Example 1: Basic Enumeration Workflow

```bash
# Set target
purplesploit > target 10.10.10.100

# Search for SMB modules
purplesploit > search smb enum

# Load a module
purplesploit > use network/nxc_smb

# View options
purplesploit > show options

# Set credentials
purplesploit > cred guest:

# Execute
purplesploit > run
```

### Example 2: Module Execution via API

```python
import requests

# Execute a command
response = requests.post('http://localhost:5000/api/c2/command', json={
    'command': 'search smb',
    'session_id': 'my_session'
})

# Execute a module
response = requests.post('http://localhost:5000/api/c2/module/execute', json={
    'module_path': 'network/nxc_smb',
    'options': {
        'RHOST': '10.10.10.100',
        'USERNAME': 'admin',
        'PASSWORD': 'password123'
    },
    'session_id': 'my_session'
})
```

### Example 3: WebSocket Terminal

```javascript
const ws = new WebSocket('ws://localhost:5000/ws/c2/my_session');

ws.onopen = () => {
    // Send command
    ws.send(JSON.stringify({ command: 'show modules' }));
};

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log('Output:', data.output);
};
```

## Architecture

### Components

1. **Frontend (C2 Terminal)**
   - `/static/c2.html` - Terminal interface
   - `/static/css/c2.css` - Dark theme styling
   - `/static/js/c2-terminal.js` - Terminal logic and WebSocket handling

2. **Backend (API Server)**
   - `/api/c2/*` - C2-specific endpoints
   - WebSocket handler for real-time communication
   - Session management and command routing
   - Framework integration for module execution

3. **Framework Integration**
   - Direct access to PurpleSploit framework
   - Module discovery and execution
   - Target and credential management
   - Result storage and history tracking

### Data Flow

```
User Input (Terminal)
    ↓
WebSocket / HTTP
    ↓
API Server (Command Parser)
    ↓
Framework (Module Execution)
    ↓
Output (Real-time Display)
```

## Access the Terminal

1. **Start the API Server**:
   ```bash
   cd /home/user/purplesploit/python
   PYTHONPATH=/home/user/purplesploit/python python3 -m purplesploit.api.server
   ```

2. **Open Browser**:
   - Navigate to: `http://localhost:5000/static/c2.html`
   - Or click "C2 Terminal" from the main dashboard

3. **Start Using**:
   - Type `help` to see available commands
   - Browse modules in the sidebar
   - Click modules to view details
   - Execute commands in the terminal

## Security Considerations

⚠️ **Important**: This C2 terminal is designed for authorized penetration testing only.

- **Network Security**: Ensure the API server is only accessible within trusted networks
- **Authentication**: Consider implementing authentication mechanisms in production
- **Session Management**: Sessions are stored in memory and persist until server restart
- **Command Validation**: All commands are parsed and validated before execution
- **Logging**: All commands and outputs are logged for audit purposes

## Troubleshooting

### WebSocket Connection Issues

If the WebSocket connection fails, the terminal will automatically fall back to HTTP API mode:

```
System: Using HTTP API fallback mode
```

To fix WebSocket issues:
1. Check that port 5000 is accessible
2. Verify no firewall is blocking WebSocket connections
3. Ensure the server is running with WebSocket support enabled

### Module Loading Issues

If modules don't appear in the sidebar:
1. Verify the framework discovered modules at startup
2. Check the console for error messages
3. Try refreshing the page or clicking the refresh button

### Command Execution Errors

If commands fail:
1. Check the terminal output for error messages
2. Verify required options are set (use `show options`)
3. Ensure targets and credentials are configured
4. Check server logs for detailed error information

## Advanced Features

### Custom Module Development

Modules automatically appear in the C2 terminal once added to the framework. See the main documentation for module development guidelines.

### Session Export

Export your session history for documentation or replay:
```bash
# Click the export button in the terminal header
# Or use the API
GET /api/c2/session/{session_id}
```

### Multi-Session Support

Create multiple sessions for different targets or campaigns:
```javascript
// Each browser tab gets its own unique session ID
// Sessions are automatically created and managed
```

## Integration with Main Framework

The C2 terminal fully integrates with the main PurpleSploit framework:

- **Shared Database**: All targets, credentials, and results sync with CLI
- **Module Registry**: Same modules available in both CLI and web interface
- **Live Updates**: Changes in one interface reflect in the other
- **Session Persistence**: Command history and context maintained across requests

## Performance

- **WebSocket**: Real-time, low-latency communication
- **Async Operations**: Non-blocking command execution
- **Efficient Rendering**: Terminal optimized for large outputs
- **Session Caching**: Fast context retrieval and updates

## Future Enhancements

Planned features for future releases:

- [ ] Multi-tab terminal with workspace isolation
- [ ] Command autocomplete and syntax highlighting
- [ ] Interactive module configuration wizard
- [ ] Real-time collaboration (multi-user sessions)
- [ ] Terminal recording and playback
- [ ] Custom color themes and preferences
- [ ] Advanced search with filters and sorting
- [ ] Module bookmarks and favorites
- [ ] Command aliases and macros

---

**Happy Hacking! 💻**

For more information, see the main [PurpleSploit documentation](../README.md).
