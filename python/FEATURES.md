# PurpleSploit Advanced Features

This document provides comprehensive documentation for PurpleSploit's advanced automation and management features.

---

## Table of Contents

1. [Smart Auto-Enumeration Pipeline](#smart-auto-enumeration-pipeline)
2. [Attack Graph Visualization](#attack-graph-visualization)
3. [Credential Spray Intelligence](#credential-spray-intelligence)
4. [Session & Shell Management](#session--shell-management)

---

## Smart Auto-Enumeration Pipeline

**Module:** `purplesploit/core/auto_enum.py`
**Command:** `auto`
**Test Coverage:** 25 tests

### Overview

The auto-enumeration pipeline provides intelligent, service-driven module chaining. Instead of manually running individual tools, the pipeline analyzes discovered services and automatically recommends and executes appropriate modules in the correct order.

### Enumeration Phases

The pipeline operates in four distinct phases:

| Phase | Description | Example Modules |
|-------|-------------|-----------------|
| **Discovery** | Initial target identification | nmap, masscan |
| **Enumeration** | Service-specific information gathering | nxc_smb, ldapsearch, nikto |
| **Exploitation** | Vulnerability exploitation | sqlmap, secretsdump |
| **Post-Exploitation** | Lateral movement, persistence | mimikatz, bloodhound |

### Scope Levels

Control aggressiveness with scope settings:

| Scope | Description | Use Case |
|-------|-------------|----------|
| `passive` | No direct interaction | Initial reconnaissance |
| `light` | Minimal scanning | Stealthy assessments |
| `normal` | Standard enumeration | Regular pentests |
| `aggressive` | Full exploitation attempts | Authorized full-scope tests |
| `stealth` | Evasion-focused | Red team operations |

### Service Rules

The pipeline includes 15+ pre-configured service rules:

```python
# Example service rules
ServiceRule(service="smb", module="network/nxc_smb", phase=ENUMERATION, priority=1)
ServiceRule(service="ldap", module="network/nxc_ldap", phase=ENUMERATION, priority=1)
ServiceRule(service="http", module="recon/httpx", phase=ENUMERATION, priority=1)
ServiceRule(service="ssh", module="network/ssh_audit", phase=ENUMERATION, priority=2)
ServiceRule(service="mssql", module="network/nxc_mssql", phase=ENUMERATION, priority=2)
ServiceRule(service="rdp", module="network/rdp_check", phase=ENUMERATION, priority=3)
```

### CLI Usage

```bash
# Start enumeration with default scope
auto start 192.168.1.0/24

# Start with aggressive scope
auto start 10.0.0.1 --scope aggressive

# Preview what would run without executing
auto dry-run 192.168.1.100

# Check detected services
auto services 192.168.1.100

# Monitor progress
auto status

# View results
auto results

# Stop running enumeration
auto stop
```

### Programmatic Usage

```python
from purplesploit.core.auto_enum import AutoEnumPipeline, EnumScope, create_auto_enum

# Create pipeline
pipeline = create_auto_enum(framework=my_framework)

# Start enumeration
result = pipeline.start(
    target="192.168.1.100",
    scope=EnumScope.NORMAL
)

# Check progress
progress = pipeline.get_progress()
print(f"Phase: {progress.current_phase}")
print(f"Progress: {progress.completed_modules}/{progress.total_modules}")

# Get results
for finding in result.findings:
    print(f"[{finding.severity}] {finding.title}")
```

### Callbacks

Register callbacks for real-time updates:

```python
pipeline.on_module_start = lambda module, target: print(f"Starting {module}")
pipeline.on_module_complete = lambda module, result: print(f"Completed {module}")
pipeline.on_finding = lambda finding: print(f"Found: {finding.title}")
pipeline.on_progress = lambda progress: print(f"{progress.percent_complete}%")
```

---

## Attack Graph Visualization

**Module:** `purplesploit/core/attack_graph.py`
**Command:** `graph`
**Test Coverage:** 43 tests

### Overview

The attack graph provides a visual representation of discovered infrastructure, relationships, and attack paths. It helps identify lateral movement opportunities and understand the overall attack surface.

### Node Types

| Type | Description | Example |
|------|-------------|---------|
| `host` | Network host/system | `host:192.168.1.100` |
| `service` | Running service | `service:smb:192.168.1.100:445` |
| `credential` | Username/password pair | `cred:admin:P@ssw0rd` |
| `vulnerability` | Discovered vulnerability | `vuln:MS17-010` |
| `user` | Domain/local user | `user:DOMAIN\\jsmith` |
| `group` | Security group | `group:Domain Admins` |
| `share` | Network share | `share:\\\\DC01\\SYSVOL` |
| `session` | Active session | `session:sess_12345` |

### Edge Types

| Type | Description |
|------|-------------|
| `has_service` | Host → Service |
| `has_vuln` | Host/Service → Vulnerability |
| `has_cred` | Source → Credential |
| `trusts` | Domain trust relationship |
| `admin_of` | User/Group → Host (admin access) |
| `member_of` | User → Group membership |
| `connects_to` | Network connection |
| `pivots_through` | Pivot relationship |
| `exploits` | Exploit → Vulnerability |

### Node Status

Track progression through the attack:

| Status | Description |
|--------|-------------|
| `unknown` | Not yet assessed |
| `discovered` | Found but not tested |
| `exploited` | Successfully exploited |
| `compromised` | Partial access obtained |
| `owned` | Full control achieved |

### CLI Usage

```bash
# View current graph
graph show

# Add nodes
graph add host 192.168.1.100 --data os=Windows --data hostname=DC01
graph add service smb:192.168.1.100:445 --data version=SMBv3

# Connect nodes
graph connect 192.168.1.100 smb:192.168.1.100:445 has_service
graph connect smb:192.168.1.100:445 MS17-010 has_vuln

# Find attack paths
graph paths 192.168.1.50 192.168.1.100

# Export for visualization
graph export cytoscape /tmp/network.json
graph export graphviz /tmp/network.dot

# View statistics
graph stats

# Clear graph
graph clear
```

### Programmatic Usage

```python
from purplesploit.core.attack_graph import (
    AttackGraph, NodeType, EdgeType, NodeStatus, create_attack_graph
)

# Create graph
graph = create_attack_graph()

# Add nodes
dc01 = graph.add_node(
    node_id="host:192.168.1.100",
    node_type=NodeType.HOST,
    label="DC01",
    data={"os": "Windows Server 2019", "hostname": "DC01"}
)

smb_service = graph.add_node(
    node_id="service:smb:192.168.1.100:445",
    node_type=NodeType.SERVICE,
    label="SMB",
    data={"port": 445, "version": "SMBv3"}
)

# Create relationship
graph.add_edge(
    source_id=dc01.id,
    target_id=smb_service.id,
    edge_type=EdgeType.HAS_SERVICE
)

# Update node status
graph.update_node_status("host:192.168.1.100", NodeStatus.COMPROMISED)

# Find attack paths
paths = graph.find_paths("host:192.168.1.50", "host:192.168.1.100")
for path in paths:
    print(f"Path length: {path.length}")
    for node in path.nodes:
        print(f"  -> {node.label}")

# Export
cytoscape_json = graph.to_cytoscape()
graphviz_dot = graph.to_graphviz()
```

### Building from Discovery Results

```python
# Automatically build graph from nmap results
graph.build_from_discovery({
    "hosts": [
        {
            "ip": "192.168.1.100",
            "hostname": "DC01",
            "os": "Windows",
            "services": [
                {"port": 445, "name": "smb", "version": "SMBv3"},
                {"port": 389, "name": "ldap", "version": "Microsoft LDAP"}
            ]
        }
    ]
})
```

### Visualization

Export to Cytoscape for interactive visualization:

```bash
graph export cytoscape /tmp/network.json
# Open in Cytoscape or Cytoscape.js web viewer
```

Export to GraphViz for static diagrams:

```bash
graph export graphviz /tmp/network.dot
dot -Tpng /tmp/network.dot -o network.png
```

---

## Credential Spray Intelligence

**Module:** `purplesploit/core/credential_spray.py`
**Command:** `spray`
**Test Coverage:** 43 tests

### Overview

Intelligent credential spraying with built-in lockout protection, smart password generation, and support for multiple authentication protocols.

### Supported Protocols

| Protocol | Target Service | Module Used |
|----------|---------------|-------------|
| `smb` | Windows SMB | network/nxc_smb |
| `ldap` | Active Directory | network/nxc_ldap |
| `winrm` | Windows Remote Management | network/nxc_winrm |
| `ssh` | SSH servers | network/ssh |
| `rdp` | Remote Desktop | network/rdp |
| `mssql` | Microsoft SQL Server | network/nxc_mssql |
| `kerberos` | Kerberos authentication | ad/kerberoast |
| `http_basic` | HTTP Basic Auth | web/http_auth |
| `http_ntlm` | HTTP NTLM Auth | web/http_auth |
| `http_form` | HTTP Form Auth | web/http_auth |
| `ftp` | FTP servers | network/ftp |
| `owa` | Outlook Web Access | web/owa |
| `o365` | Office 365 | cloud/o365 |

### Spray Patterns

| Pattern | Description | Use Case |
|---------|-------------|----------|
| `breadth_first` | One password against all users | Default, lockout-safe |
| `depth_first` | All passwords against one user | When lockout isn't a concern |
| `low_and_slow` | Timed delays between attempts | Evading detection |
| `random` | Randomized attempt order | Avoiding patterns |
| `smart` | AI-driven optimization | Advanced scenarios |

### Lockout Protection

The spray engine tracks per-user attempts to prevent account lockouts:

```python
# Default lockout policy
LockoutPolicy(
    threshold=5,           # Max attempts before lockout
    observation_window=30, # Window in minutes
    lockout_duration=30,   # Lockout duration in minutes
    safe_attempts=3        # Stay below threshold
)

# Conservative policy for sensitive environments
policy = LockoutPolicy.conservative()  # threshold=3, safe_attempts=1

# Create from AD policy
ad_policy = {"lockoutThreshold": 10, "lockoutObservationWindow": 60}
policy = LockoutPolicy.from_ad_policy(ad_policy)
```

### CLI Usage

```bash
# Basic spray
spray start 192.168.1.100 --users users.txt --passwords passwords.txt

# Spray with protocol selection
spray start dc01.corp.local --users users.txt --passwords passwords.txt --protocol ldap

# Use breadth-first pattern (safest)
spray start 10.0.0.0/24 --users users.txt --passwords common.txt --pattern breadth_first

# Stop on first success
spray start 192.168.1.100 --users admins.txt --passwords admin_pass.txt --stop-on-success

# Generate smart wordlist
spray generate --company AcmeCorp --usernames users.txt --seasonal --year 2024

# Configure lockout policy
spray policy --threshold 5 --window 30 --safe 3

# Check status
spray status

# View results
spray results
spray results --id spray:abc123
```

### Programmatic Usage

```python
from purplesploit.core.credential_spray import (
    CredentialSpray, SprayProtocol, SprayPattern, LockoutPolicy,
    PasswordGenerator, create_credential_spray
)

# Create sprayer with custom policy
policy = LockoutPolicy(threshold=5, safe_attempts=3)
spray = create_credential_spray(lockout_policy=policy)

# Set up callbacks
spray.on_success = lambda attempt: print(f"SUCCESS: {attempt.username}:{attempt.password}")
spray.on_lockout = lambda user: print(f"LOCKOUT: {user}")
spray.on_progress = lambda progress: print(f"Progress: {progress}%")

# Execute spray
result = spray.spray(
    targets=["192.168.1.100", "192.168.1.101"],
    users=["admin", "administrator", "jsmith"],
    passwords=["Password1", "Summer2024!", "Welcome1"],
    protocol=SprayProtocol.SMB,
    pattern=SprayPattern.BREADTH_FIRST,
    stop_on_success=False
)

# Check results
print(f"Total attempts: {result.total_attempts}")
print(f"Successful: {result.successful_attempts}")
for cred in result.valid_credentials:
    print(f"  {cred['username']}:{cred['password']}")
```

### Password Generator

Generate smart password lists:

```python
from purplesploit.core.credential_spray import PasswordGenerator

# Top passwords from breach databases
top_100 = PasswordGenerator.get_top_passwords(100)

# Seasonal passwords
seasonal = PasswordGenerator.generate_seasonal(2024)
# ['Spring2024', 'Spring2024!', 'Summer2024', 'Summer2024!', ...]

# Company-based passwords
company = PasswordGenerator.generate_company_variants("AcmeCorp")
# ['AcmeCorp1', 'AcmeCorp123', 'Acmecorp!', 'acmecorp2024', ...]

# Username-based passwords
user_based = PasswordGenerator.generate_username_based("jsmith")
# ['jsmith1', 'jsmith123', 'Jsmith1', 'Jsmith!', ...]

# Comprehensive wordlist
wordlist = PasswordGenerator.build_wordlist(
    include_common=True,
    include_seasonal=True,
    company_name="AcmeCorp",
    usernames=["admin", "jsmith", "awalker"],
    year=2024
)
```

---

## Session & Shell Management

**Module:** `purplesploit/core/session_manager.py`
**Commands:** `sessions`, `interact`
**Test Coverage:** 50 tests

### Overview

Centralized management for all remote sessions, shells, routes, and port forwards. Track session state, privilege levels, and enable pivoting through compromised hosts.

### Session Types

| Type | Description | Example |
|------|-------------|---------|
| `shell` | Generic command shell | Basic cmd/bash shell |
| `reverse_shell` | Inbound connection | nc -e /bin/bash |
| `bind_shell` | Listening shell | Bind on target port |
| `ssh` | SSH session | ssh user@host |
| `meterpreter` | Metasploit Meterpreter | Full-featured shell |
| `beacon` | C2 beacon | Cobalt Strike, Sliver |
| `vnc` | VNC connection | GUI access |
| `rdp` | Remote Desktop | Windows RDP |
| `winrm` | Windows Remote Management | PowerShell remoting |
| `wmi` | WMI connection | Windows management |

### Privilege Levels

| Level | Description |
|-------|-------------|
| `none` | No privileges (connection only) |
| `user` | Standard user privileges |
| `admin` | Local administrator |
| `system` | NT AUTHORITY\SYSTEM |
| `root` | Unix root user |

### Session States

| State | Description |
|-------|-------------|
| `active` | Connected and responsive |
| `idle` | Connected but inactive |
| `disconnected` | Temporarily disconnected |
| `dead` | Connection lost |
| `upgrading` | Being upgraded |

### CLI Usage

```bash
# List sessions
sessions list
sessions list --type meterpreter
sessions list --alive

# Get session info
sessions info sess_12345

# Kill a session
sessions kill sess_12345

# Upgrade session (e.g., shell to meterpreter)
sessions upgrade sess_12345

# Add route through session (for pivoting)
sessions route add sess_12345 10.10.10.0/24
sessions route list

# Set up port forward
sessions forward sess_12345 8080:10.10.10.100:80

# Tag sessions for organization
sessions tag sess_12345 domain_admin
sessions tag sess_67890 pivot

# Interact with session
interact sess_12345
```

### Programmatic Usage

```python
from purplesploit.core.session_manager import (
    SessionManager, SessionType, SessionState, SessionPrivilege,
    create_session_manager
)

# Create manager
manager = create_session_manager(framework=my_framework)

# Register a new session
session = manager.register_session(
    session_type=SessionType.METERPRETER,
    target_host="192.168.1.100",
    target_port=4444,
    username="CORP\\admin",
    privilege=SessionPrivilege.ADMIN,
    data={"arch": "x64", "os": "Windows 10"}
)

print(f"Session ID: {session.id}")

# List active sessions
for sess in manager.list_sessions(alive_only=True):
    print(f"{sess.id}: {sess.target_host} ({sess.privilege.value})")

# Add route for pivoting
manager.add_route(
    session_id=session.id,
    subnet="10.10.10.0/24"
)

# Set up port forward
manager.add_port_forward(
    session_id=session.id,
    local_port=8080,
    remote_host="10.10.10.100",
    remote_port=80
)

# Execute command through session
result = manager.execute(session.id, "whoami")
print(result.output)

# Get session for a target
sess = manager.get_session_for_target("192.168.1.100")

# Health check
health = manager.health_check()
print(f"Active: {health['active']}, Dead: {health['dead']}")

# Clean up dead sessions
manager.cleanup_dead_sessions()
```

### Routing and Pivoting

Use sessions as pivots to reach internal networks:

```python
# Add route through compromised host
manager.add_route("sess_pivot", "10.10.10.0/24")

# All traffic to 10.10.10.0/24 will go through sess_pivot
# Framework modules will automatically use this route

# List current routes
for route in manager.list_routes():
    print(f"{route.subnet} -> {route.session_id}")

# Remove route
manager.remove_route("sess_pivot", "10.10.10.0/24")
```

### Port Forwarding

Forward local ports through sessions:

```python
# Local port forward: localhost:8080 -> 10.10.10.100:80 via session
manager.add_port_forward(
    session_id="sess_12345",
    local_port=8080,
    remote_host="10.10.10.100",
    remote_port=80,
    forward_type="local"
)

# Now curl http://localhost:8080 reaches 10.10.10.100:80

# List forwards
for fwd in manager.list_port_forwards():
    print(f"{fwd.local_port} -> {fwd.remote_host}:{fwd.remote_port}")

# Remove forward
manager.remove_port_forward("sess_12345", 8080)
```

### Session Callbacks

```python
manager.on_session_open = lambda s: print(f"New session: {s.id}")
manager.on_session_close = lambda s: print(f"Session closed: {s.id}")
manager.on_session_upgrade = lambda s: print(f"Upgraded: {s.id}")
manager.on_privilege_change = lambda s, old, new: print(f"Priv: {old} -> {new}")
```

---

## Integration Examples

### Full Engagement Workflow

```python
from purplesploit.core.auto_enum import create_auto_enum, EnumScope
from purplesploit.core.attack_graph import create_attack_graph
from purplesploit.core.credential_spray import create_credential_spray, SprayProtocol
from purplesploit.core.session_manager import create_session_manager

# Initialize components
pipeline = create_auto_enum(framework)
graph = create_attack_graph()
spray = create_credential_spray()
sessions = create_session_manager(framework)

# Phase 1: Discovery and Enumeration
result = pipeline.start("192.168.1.0/24", scope=EnumScope.NORMAL)

# Build attack graph from discoveries
for finding in result.findings:
    if finding.type == "host":
        graph.add_node(f"host:{finding.target}", NodeType.HOST)
    elif finding.type == "service":
        graph.add_node(f"service:{finding.service}", NodeType.SERVICE)

# Phase 2: Credential Spraying
users = ["admin", "administrator", "svc_sql", "backup"]
passwords = PasswordGenerator.build_wordlist(
    include_common=True,
    company_name="TargetCorp"
)

spray_result = spray.spray(
    targets="192.168.1.100",
    users=users,
    passwords=passwords,
    protocol=SprayProtocol.SMB
)

# Add valid credentials to graph
for cred in spray_result.valid_credentials:
    graph.add_node(
        f"cred:{cred['username']}",
        NodeType.CREDENTIAL,
        data=cred
    )

# Phase 3: Exploitation and Session Management
# (After gaining shell via exploit)
session = sessions.register_session(
    session_type=SessionType.METERPRETER,
    target_host="192.168.1.100",
    privilege=SessionPrivilege.ADMIN
)

# Set up pivot
sessions.add_route(session.id, "10.10.10.0/24")

# Find attack paths to high-value targets
paths = graph.find_paths("host:192.168.1.50", "host:10.10.10.100")
```

---

## Troubleshooting

### Auto-Enumeration Issues

**Problem:** No modules recommended for discovered services
**Solution:** Check that service rules are configured for the detected service type

**Problem:** Enumeration stops unexpectedly
**Solution:** Check `auto status` for errors; verify target is reachable

### Attack Graph Issues

**Problem:** Path finding returns no results
**Solution:** Ensure edges connect source to target; check node IDs match exactly

**Problem:** Export fails
**Solution:** Verify write permissions on output path; check graph isn't empty

### Credential Spray Issues

**Problem:** Spray stops after few attempts
**Solution:** Check lockout policy settings; may need to increase `safe_attempts`

**Problem:** All accounts showing as locked
**Solution:** Wait for observation window to pass; check actual AD lockout policy

### Session Management Issues

**Problem:** Session shows as dead but host is up
**Solution:** Session handler may have crashed; try re-establishing connection

**Problem:** Routes not working
**Solution:** Verify pivot session is active; check route subnet format

---

## Configuration

All advanced features respect global framework configuration:

```python
# In purplesploit config
{
    "auto_enum": {
        "default_scope": "normal",
        "parallel_modules": 3,
        "timeout": 300
    },
    "attack_graph": {
        "auto_build": true,
        "max_nodes": 10000
    },
    "credential_spray": {
        "default_pattern": "breadth_first",
        "delay_between_attempts": 1.0,
        "lockout_policy": {
            "threshold": 5,
            "safe_attempts": 3
        }
    },
    "session_manager": {
        "health_check_interval": 30,
        "auto_cleanup_dead": true
    }
}
```
