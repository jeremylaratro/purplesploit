# PurpleSploit Architecture

**Version:** 6.8.1
**Last Updated:** 23 January 2026

This document provides an overview of the PurpleSploit framework architecture, including component relationships, data flow, and design patterns.

---

## Table of Contents

1. [High-Level Architecture](#high-level-architecture)
2. [Directory Structure](#directory-structure)
3. [Core Components](#core-components)
4. [Module System](#module-system)
5. [Data Flow](#data-flow)
6. [Database Architecture](#database-architecture)
7. [Web Interface](#web-interface)
8. [Plugin System](#plugin-system)
9. [Integration Points](#integration-points)

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        PurpleSploit Framework                        │
├─────────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │   CLI/TUI    │    │  Web Portal  │    │      REST API        │  │
│  │  (ui/)       │    │  (web/)      │    │      (api/)          │  │
│  └──────┬───────┘    └──────┬───────┘    └──────────┬───────────┘  │
│         │                   │                       │               │
│         └───────────────────┼───────────────────────┘               │
│                             │                                       │
│                    ┌────────▼────────┐                              │
│                    │    Framework    │                              │
│                    │    (core/)      │                              │
│                    └────────┬────────┘                              │
│                             │                                       │
│         ┌───────────────────┼───────────────────┐                   │
│         │                   │                   │                   │
│  ┌──────▼──────┐    ┌───────▼───────┐   ┌──────▼──────┐            │
│  │   Session   │    │    Module     │   │  Database   │            │
│  │   Manager   │    │    Registry   │   │   Layer     │            │
│  └─────────────┘    └───────────────┘   └─────────────┘            │
│                             │                                       │
│                    ┌────────▼────────┐                              │
│                    │     Modules     │                              │
│                    │   (modules/)    │                              │
│                    └─────────────────┘                              │
│                             │                                       │
│  ┌──────────────────────────┼──────────────────────────────────┐   │
│  │  recon │ network │ web │ smb │ impacket │ osint │ ad │ c2  │   │
│  └────────────────────────────────────────────────────────────-┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Directory Structure

```
purplesploit/
├── __init__.py              # Package initialization, version
├── main.py                  # Entry point
│
├── core/                    # Core framework components
│   ├── framework.py         # Main Framework class
│   ├── module.py            # BaseModule, ExternalToolModule
│   ├── session.py           # Session state management
│   ├── parameters.py        # Parameter handling
│   ├── database.py          # Database operations
│   ├── workflow.py          # Workflow automation
│   ├── auto_enum.py         # Auto-enumeration pipeline
│   ├── attack_graph.py      # Attack path visualization
│   ├── credential_spray.py  # Credential spraying engine
│   ├── session_manager.py   # Remote session management
│   └── findings.py          # Security findings tracking
│
├── modules/                 # Security tool modules
│   ├── recon/               # Reconnaissance (nmap, nuclei)
│   ├── network/             # Network protocols (nxc_smb, nxc_ldap)
│   ├── web/                 # Web testing (feroxbuster, sqlmap)
│   ├── smb/                 # SMB-specific modules
│   ├── impacket/            # Impacket tools (psexec, secretsdump)
│   ├── osint/               # OSINT (shodan, crtsh)
│   ├── ad/                  # Active Directory (kerbrute)
│   ├── c2/                  # C2 operations (ligolo)
│   ├── deploy/              # Deployment modules
│   ├── ai/                  # AI-assisted modules
│   └── utility/             # Utility modules
│
├── ui/                      # User interface
│   ├── commands.py          # Command handlers
│   ├── console.py           # Console interface
│   ├── display.py           # Output formatting
│   ├── interactive.py       # Interactive selectors
│   ├── banner.py            # Startup banner
│   └── command_mixins/      # Command handler mixins
│       ├── base_commands.py
│       ├── context_commands.py
│       ├── module_commands.py
│       └── utility_commands.py
│
├── api/                     # REST API
│   └── server.py            # FastAPI server
│
├── web/                     # Web interface
│   ├── dashboard.py         # Dashboard routes
│   ├── templates/           # Jinja2 templates
│   └── static/              # CSS, JS assets
│
├── models/                  # Data models
│   └── database.py          # SQLAlchemy models
│
├── reporting/               # Report generation
│   ├── generator.py         # Report orchestrator
│   ├── pdf.py               # PDF export
│   ├── html.py              # HTML export
│   ├── xlsx.py              # Excel export
│   ├── markdown.py          # Markdown export
│   └── templates/           # Report templates
│
├── plugins/                 # Plugin system
│   ├── manager.py           # Plugin lifecycle
│   ├── repository.py        # Plugin repository
│   └── models.py            # Plugin data models
│
├── integrations/            # External integrations
│   ├── base.py              # Base integration class
│   ├── slack.py             # Slack notifications
│   ├── teams.py             # MS Teams integration
│   ├── jira_integration.py  # JIRA issue tracking
│   ├── siem.py              # SIEM/log forwarding
│   └── manager.py           # Integration orchestrator
│
├── distributed/             # Distributed operations
│   ├── task.py              # Task queue
│   └── transport.py         # Communication layer
│
├── ai/                      # AI/ML components
│   ├── recommender.py       # Module recommendations
│   ├── attack_paths.py      # Attack path analysis
│   └── nlp.py               # Natural language queries
│
└── utils/                   # Utilities
    └── common.py            # Shared utilities
```

---

## Core Components

### Framework (`core/framework.py`)

The central orchestrator that initializes and coordinates all components:

```python
class Framework:
    def __init__(self):
        self.session = Session()           # Context state
        self.module_registry = {}          # Registered modules
        self.current_module = None         # Active module
        self.db = Database()               # Persistence layer
```

**Responsibilities:**
- Module discovery and registration
- Session lifecycle management
- Database initialization
- Module execution coordination

### Session (`core/session.py`)

Manages persistent context across module operations:

```python
class Session:
    targets: TargetManager          # IP addresses, subnets
    credentials: CredentialManager  # Username/password pairs
    services: ServiceManager        # Discovered services
    wordlists: WordlistManager      # Wordlist paths
```

**Key Feature:** Context persists when switching modules, unlike Metasploit.

### Module (`core/module.py`)

Base classes for all security modules:

```python
class BaseModule:
    """Base for all modules"""
    name: str
    description: str
    category: str
    options: Dict[str, Parameter]

    def run(self) -> Dict[str, Any]: ...
    def get_operations(self) -> List[Dict]: ...

class ExternalToolModule(BaseModule):
    """For modules wrapping external CLI tools"""
    tool_name: str

    def execute_command(self, cmd: str) -> Dict: ...
    def parse_output(self, output: str) -> Dict: ...
```

---

## Module System

### Module Categories

| Category | Purpose | Examples |
|----------|---------|----------|
| `recon` | Reconnaissance | nmap, nuclei, masscan |
| `network` | Network protocols | nxc_smb, nxc_ldap, nxc_ssh |
| `web` | Web application testing | feroxbuster, sqlmap, wfuzz |
| `smb` | SMB-specific operations | shares, enumeration |
| `impacket` | Impacket tools | psexec, secretsdump |
| `osint` | Open-source intelligence | shodan, crtsh |
| `ad` | Active Directory | kerbrute, bloodhound |
| `c2` | Command & control | ligolo, beacon |
| `deploy` | Tool deployment | script upload, C2 agents |
| `ai` | AI-assisted | methodology, automation |
| `utility` | Utilities | module_creator |

### Module Operations

Modules expose multiple operations (sub-commands):

```python
def get_operations(self) -> List[Dict[str, Any]]:
    return [
        {
            "name": "SMB Authentication",
            "description": "Test SMB credentials",
            "handler": "op_smb_auth"
        },
        {
            "name": "Enumerate Shares",
            "description": "List available shares",
            "handler": "op_enum_shares"
        }
    ]
```

### Parameter Profiles

Standardized parameter sets for consistency:

| Profile | Parameters |
|---------|------------|
| `network_basic` | RHOST, RPORT, TIMEOUT |
| `auth_password` | USERNAME, PASSWORD, DOMAIN |
| `auth_hash` | USERNAME, HASH, HASH_TYPE |
| `web_scan_basic` | URL, THREADS |
| `web_scan_advanced` | URL, WORDLIST, EXTENSIONS |

---

## Data Flow

### Command Execution Flow

```
User Input
    │
    ▼
┌──────────────┐
│  UI Parser   │  (commands.py)
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Framework   │  (framework.py)
└──────┬───────┘
       │
       ▼
┌──────────────┐     ┌──────────────┐
│   Session    │────►│   Context    │
│   Manager    │     │  (targets,   │
└──────┬───────┘     │  credentials)│
       │             └──────────────┘
       ▼
┌──────────────┐
│    Module    │  (BaseModule)
└──────┬───────┘
       │
       ▼
┌──────────────┐     ┌──────────────┐
│   External   │────►│   Output     │
│    Tool      │     │   Parser     │
└──────┬───────┘     └──────┬───────┘
       │                    │
       ▼                    ▼
┌──────────────┐     ┌──────────────┐
│   Database   │     │   Display    │
│   Storage    │     │   Output     │
└──────────────┘     └──────────────┘
```

### Context Propagation

When a module runs, context automatically populates options:

```
Session.targets.current → Module.options["RHOST"]
Session.credentials.current → Module.options["USERNAME"], ["PASSWORD"]
Session.services → Module.options["RPORT"]
```

---

## Database Architecture

### SQLite Schema

```
┌────────────────┐     ┌────────────────┐
│    targets     │     │  credentials   │
├────────────────┤     ├────────────────┤
│ id             │     │ id             │
│ ip             │     │ username       │
│ hostname       │     │ password       │
│ status         │     │ domain         │
│ notes          │     │ hash           │
│ created_at     │     │ dcip           │
└────────────────┘     │ dns            │
                       │ created_at     │
                       └────────────────┘

┌────────────────┐     ┌────────────────┐
│   services     │     │   findings     │
├────────────────┤     ├────────────────┤
│ id             │     │ id             │
│ host_id (FK)   │     │ title          │
│ port           │     │ severity       │
│ protocol       │     │ description    │
│ name           │     │ target         │
│ version        │     │ evidence       │
│ banner         │     │ status         │
└────────────────┘     │ cvss_score     │
                       │ mitre_id       │
                       └────────────────┘
```

### Database Files

- **Session DB:** `~/.purplesploit/session.db` - Current session state
- **Models DB:** `~/.purplesploit/purplesploit.db` - Persistent data

---

## Web Interface

### Architecture

```
┌─────────────────────────────────────────┐
│              Web Browser                │
└────────────────┬────────────────────────┘
                 │
        ┌────────┴────────┐
        │                 │
┌───────▼───────┐  ┌──────▼──────┐
│   Dashboard   │  │  REST API   │
│   (Flask)     │  │  (FastAPI)  │
└───────┬───────┘  └──────┬──────┘
        │                 │
        └────────┬────────┘
                 │
        ┌────────▼────────┐
        │    Framework    │
        │      Core       │
        └─────────────────┘
```

### Routes

| Route | Purpose |
|-------|---------|
| `/` | Dashboard home |
| `/targets` | Target management |
| `/credentials` | Credential management |
| `/services` | Discovered services |
| `/modules` | Module browser |
| `/api/*` | REST API endpoints |

### Real-time Updates

The web interface syncs with CLI changes via:
- Shared SQLite database
- WebSocket notifications (planned)

---

## Plugin System

### Plugin Structure

```
my_plugin/
├── plugin.json          # Manifest
├── __init__.py          # Plugin entry
├── modules/             # Custom modules
│   └── my_module.py
└── templates/           # Optional templates
```

### Plugin Lifecycle

```
Discovery → Validation → Loading → Registration → Execution
```

### Repository Integration

```python
# Install from repository
plugin install my_plugin

# Enable/disable
plugin enable my_plugin
plugin disable my_plugin

# List installed
plugin list
```

---

## Integration Points

### External Integrations

| Integration | Purpose | Protocol |
|-------------|---------|----------|
| **Slack** | Notifications | Webhook |
| **MS Teams** | Notifications | Webhook |
| **JIRA** | Issue tracking | REST API |
| **SIEM** | Log forwarding | Syslog/CEF |
| **GitHub Issues** | Bug tracking | REST API |

### Integration Configuration

```python
# In framework config
integrations:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/..."
    notify_on: ["critical_finding", "scan_complete"]
  jira:
    enabled: true
    url: "https://company.atlassian.net"
    project_key: "SEC"
```

---

## Advanced Features

### Auto-Enumeration Pipeline

Intelligent service-based module chaining:

```
Target Discovery → Service Detection → Module Selection → Execution
```

**Scopes:** passive, light, normal, aggressive, stealth

### Attack Graph

Visual representation of infrastructure and attack paths:

```
Node Types: host, service, credential, vulnerability, user, group
Edge Types: has_service, has_vuln, trusts, admin_of, connects_to
```

### Credential Spray Intelligence

Smart credential spraying with lockout protection:

```
Protocols: SMB, LDAP, WinRM, SSH, RDP, MSSQL, Kerberos, HTTP
Patterns: low_and_slow, depth_first, breadth_first, random, smart
```

### Session Management

Centralized management of remote sessions:

```
Types: shell, reverse_shell, ssh, meterpreter, beacon, vnc, rdp
Features: routing, port forwarding, health monitoring
```

---

## Design Patterns

### Patterns Used

| Pattern | Usage |
|---------|-------|
| **Registry** | Module discovery and registration |
| **Strategy** | Different authentication methods |
| **Observer** | Event notifications (findings, progress) |
| **Factory** | Module instantiation |
| **Mixin** | Command handler organization |
| **Facade** | Framework as unified interface |

### Code Conventions

- **Type hints** on all public methods
- **Docstrings** for classes and public methods
- **Async** for I/O operations where beneficial
- **Dependency injection** for testability

---

## Security Considerations

### Credential Handling

- Credentials stored in SQLite (local only)
- No plaintext transmission over network
- Session isolation per engagement

### Tool Execution

- Subprocess calls with timeout
- Input validation before shell execution
- Sandboxed output parsing

---

## Extending PurpleSploit

### Adding a New Module

1. Create file in appropriate `modules/` subdirectory
2. Inherit from `BaseModule` or `ExternalToolModule`
3. Implement required properties and methods
4. Module auto-discovered on startup

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guide.

### Adding an Integration

1. Create file in `integrations/`
2. Inherit from `BaseIntegration`
3. Implement notification methods
4. Register in integration manager

---

## References

- [Quick Start Guide](../QUICKSTART.md)
- [Contributing Guide](CONTRIBUTING.md)
- [Module Development](guides/MODULE_DEVELOPMENT.md)
- [API Documentation](API.md)
- [Python API](PYTHON_API.md)
