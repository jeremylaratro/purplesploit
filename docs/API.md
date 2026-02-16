# PurpleSploit REST API Documentation

This document provides comprehensive documentation for the PurpleSploit REST API server. The API provides HTTP endpoints for interacting with the PurpleSploit pentesting framework, managing targets, credentials, and executing modules.

**Package Version:** 6.8.1
**API Version:** 2.0.0
**Base URL:** `http://localhost:5000`
**OpenAPI/Swagger Docs:** `http://localhost:5000/api/docs`
**ReDoc:** `http://localhost:5000/api/redoc`

## Table of Contents

- [Getting Started](#getting-started)
- [Authentication](#authentication)
- [Health and Status](#health-and-status)
- [Credentials API](#credentials-api)
- [Targets API](#targets-api)
- [Services API](#services-api)
- [Exploits API](#exploits-api)
- [Target Analysis API](#target-analysis-api)
- [Nmap Integration](#nmap-integration)
- [Workspaces API](#workspaces-api)
- [Statistics API](#statistics-api)
- [C2 Command and Control API](#c2-command-and-control-api)
- [WebSocket API](#websocket-api)
- [Error Handling](#error-handling)
- [Data Models](#data-models)

---

## Getting Started

### Starting the API Server

```bash
# From the python directory
cd python

# Run the API server
python -m purplesploit.api.server

# Or with specific host/port
python -c "from purplesploit.api.server import main; main(host='127.0.0.1', port=8000)"
```

The server starts on `http://0.0.0.0:5000` by default.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PURPLESPLOIT_DB` | Custom database path | `~/.purplesploit/purplesploit.db` |

### CORS Configuration

The API enables CORS with the following settings:
- **Allowed Origins:** All (`*`) - Configure for production
- **Allowed Methods:** All
- **Allowed Headers:** All
- **Credentials:** Enabled

---

## Authentication

**Current Status:** No authentication required.

The API currently operates without authentication. For production deployments, implement authentication middleware as needed.

---

## Health and Status

### GET /api/health

Health check endpoint for monitoring.

**Response:**
```json
{
  "status": "healthy"
}
```

**Status Codes:**
- `200 OK` - Server is healthy

---

### GET /api/status

Get system status including database information.

**Response:**
```json
{
  "targets_count": 5,
  "credentials_count": 3,
  "databases": {
    "credentials": "/home/user/.purplesploit/credentials.db",
    "targets": "/home/user/.purplesploit/targets.db",
    "web_targets": "/home/user/.purplesploit/web_targets.db",
    "ad_targets": "/home/user/.purplesploit/ad_targets.db",
    "services": "/home/user/.purplesploit/services.db"
  }
}
```

---

### GET /api/banner

Get an ASCII art banner.

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `variant` | int (optional) | Specific banner variant (0-7). Random if omitted. |

**Response:**
```json
{
  "banner": "[ASCII art banner text]",
  "variant": 3
}
```

---

## Credentials API

Manage stored credentials for penetration testing activities.

### GET /api/credentials

List all credentials.

**Response:**
```json
[
  {
    "name": "admin_cred",
    "username": "administrator",
    "password": "P@ssw0rd",
    "domain": "CORP",
    "dcip": "10.10.10.1",
    "dns": "dc.corp.local",
    "hash": null
  }
]
```

---

### POST /api/credentials

Create a new credential.

**Request Body:**
```json
{
  "name": "new_cred",
  "username": "user1",
  "password": "secret123",
  "domain": "TESTDOMAIN",
  "dcip": "192.168.1.10",
  "dns": "dc.testdomain.local",
  "hash": null
}
```

**Required Fields:** `name`

**Optional Fields:** `username`, `password`, `domain`, `dcip`, `dns`, `hash`

**Response:** Returns the created credential object.

**Status Codes:**
- `200 OK` - Credential created
- `400 Bad Request` - Invalid data

---

### GET /api/credentials/{name}

Get a specific credential by name.

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Credential name |

**Response:** Credential object

**Status Codes:**
- `200 OK` - Found
- `404 Not Found` - Credential not found

---

### PUT /api/credentials/{name}

Update an existing credential.

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Credential name to update |

**Request Body:** Same as POST

**Status Codes:**
- `200 OK` - Updated
- `404 Not Found` - Credential not found

---

### DELETE /api/credentials/{name}

Delete a credential.

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Credential name to delete |

**Response:**
```json
{
  "message": "Credential 'admin_cred' deleted"
}
```

**Status Codes:**
- `200 OK` - Deleted
- `404 Not Found` - Credential not found

---

## Targets API

Manage network targets for scanning and exploitation.

### GET /api/targets

List all targets.

**Response:**
```json
[
  {
    "name": "web_server",
    "ip": "192.168.1.100",
    "description": "Main web server"
  }
]
```

---

### POST /api/targets

Create a new target.

**Request Body:**
```json
{
  "name": "new_target",
  "ip": "10.10.10.50",
  "description": "Database server"
}
```

**Required Fields:** `name`, `ip`

**Optional Fields:** `description`

**Status Codes:**
- `200 OK` - Created
- `400 Bad Request` - Invalid data

---

### GET /api/targets/{name}

Get a specific target by name.

**Status Codes:**
- `200 OK` - Found
- `404 Not Found` - Target not found

---

### PUT /api/targets/{name}

Update an existing target.

**Status Codes:**
- `200 OK` - Updated
- `404 Not Found` - Target not found

---

### DELETE /api/targets/{name}

Delete a target.

**Response:**
```json
{
  "message": "Target 'web_server' deleted"
}
```

**Status Codes:**
- `200 OK` - Deleted
- `404 Not Found` - Target not found

---

## Services API

Query discovered services from scanning activities.

### GET /api/services

List all detected services.

**Response:**
```json
[
  {
    "id": 1,
    "target": "192.168.1.100",
    "service": "ssh",
    "port": 22,
    "version": "OpenSSH 8.2p1"
  },
  {
    "id": 2,
    "target": "192.168.1.100",
    "service": "http",
    "port": 80,
    "version": "nginx 1.18.0"
  }
]
```

---

### GET /api/services/{target}

Get services for a specific target.

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string | Target IP address |

**Example:** `GET /api/services/192.168.1.100`

**Response:** List of services for the target

---

## Exploits API

Query discovered exploits and vulnerabilities.

### GET /api/exploits

List all exploits.

**Response:**
```json
[
  {
    "id": 1,
    "target": "192.168.1.100",
    "service": "ssh",
    "port": 22,
    "version": "OpenSSH 7.2p2",
    "exploit_title": "OpenSSH 7.2p2 - Username Enumeration",
    "exploit_path": "/usr/share/exploitdb/exploits/linux/remote/40136.py",
    "edb_id": "40136",
    "platform": "linux",
    "exploit_type": "remote",
    "created_at": "2024-01-15T10:30:00"
  }
]
```

---

### GET /api/exploits/target/{target}

Get exploits for a specific target.

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string | Target IP address |

---

## Target Analysis API

Get comprehensive analysis of targets including services and exploits.

### GET /api/analysis/{target}

Get complete analysis for a target.

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string | Target IP address |

**Response:**
```json
{
  "target": {
    "name": "web_server",
    "ip": "192.168.1.100",
    "description": "Main web server"
  },
  "services": [
    {
      "id": 1,
      "target": "192.168.1.100",
      "service": "ssh",
      "port": 22,
      "version": "OpenSSH 8.2p1"
    }
  ],
  "exploits": [],
  "exploit_count": 0,
  "service_count": 1,
  "critical_services": ["ssh:22"]
}
```

**Critical Services Detected:** `smb`, `rdp`, `mssql`, `ssh`, `telnet`, `ftp`

**Status Codes:**
- `200 OK` - Analysis returned
- `404 Not Found` - Target not found

---

## Nmap Integration

### POST /api/scan/nmap

Execute an nmap scan.

**Request Body:**
```json
{
  "target": "192.168.1.0/24",
  "scan_type": "-sV",
  "ports": "22,80,443,445"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `target` | string | Yes | Target IP, hostname, or CIDR range |
| `scan_type` | string | No | Nmap scan type flags (default: `-sV`) |
| `ports` | string | No | Port specification |

**Response:**
```json
{
  "success": true,
  "stdout": "[nmap output]",
  "stderr": "",
  "return_code": 0
}
```

**Timeout:** 600 seconds (10 minutes)

---

### POST /api/nmap/upload

Upload and parse nmap XML scan results.

**Content-Type:** `multipart/form-data`

**Request:** Upload XML file

**Example using curl:**
```bash
curl -X POST "http://localhost:5000/api/nmap/upload" \
  -F "file=@scan_results.xml"
```

**Response:**
```json
{
  "success": true,
  "message": "Successfully imported 15 hosts",
  "hosts_discovered": 15,
  "total_scanned": 254,
  "filename": "scan_results.xml"
}
```

**Status Codes:**
- `200 OK` - Import successful
- `400 Bad Request` - Not an XML file
- `500 Internal Server Error` - Processing error

---

## Workspaces API

Manage workspaces for organizing penetration test activities.

### GET /api/workspaces

List all workspaces.

**Response:**
```json
[
  {
    "name": "client_engagement",
    "path": "/home/user/.purplesploit/workspaces/client_engagement"
  }
]
```

---

### GET /api/workspaces/{name}

Get workspace details including variables.

**Response:**
```json
{
  "name": "client_engagement",
  "path": "/home/user/.purplesploit/workspaces/client_engagement",
  "variables": {
    "TARGET_NETWORK": "10.10.10.0/24",
    "DOMAIN": "corp.local"
  }
}
```

**Status Codes:**
- `200 OK` - Found
- `404 Not Found` - Workspace not found

---

## Statistics API

### GET /api/stats/overview

Get overview statistics.

**Response:**
```json
{
  "total_targets": 25,
  "total_credentials": 8,
  "total_services": 142,
  "services_by_type": {
    "ssh": 15,
    "http": 45,
    "smb": 10,
    "rdp": 5
  },
  "targets_with_services": 20
}
```

---

## C2 Command and Control API

The C2 API provides framework control capabilities for module management and execution.

### GET /api/c2/modules

List all available modules.

**Response:**
```json
[
  {
    "path": "recon/nmap",
    "name": "Nmap Scanner",
    "category": "recon",
    "description": "Network mapper and port scanner",
    "author": "PurpleSploit Team"
  }
]
```

---

### GET /api/c2/modules/search

Search for modules.

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `query` | string | Search term |

**Example:** `GET /api/c2/modules/search?query=smb`

---

### GET /api/c2/modules/{category}

Get modules by category.

**Categories:** `recon`, `network`, `web`, `impacket`, `osint`, `ai`, `deploy`, `c2`, `ad`

**Example:** `GET /api/c2/modules/recon`

---

### GET /api/c2/module/{module_path}

Get detailed module information.

**Example:** `GET /api/c2/module/recon/nmap`

**Response:**
```json
{
  "path": "recon/nmap",
  "name": "Nmap Scanner",
  "category": "recon",
  "description": "Network mapper and port scanner",
  "author": "PurpleSploit Team",
  "options": {
    "RHOST": {
      "value": "",
      "required": true,
      "description": "Target host"
    },
    "PORTS": {
      "value": "",
      "required": false,
      "description": "Port specification"
    }
  }
}
```

**Status Codes:**
- `200 OK` - Module found
- `404 Not Found` - Module not found

---

### POST /api/c2/module/execute

Execute a module with options.

**Request Body:**
```json
{
  "module_path": "recon/nmap",
  "options": {
    "RHOST": "192.168.1.100",
    "PORTS": "1-1000"
  },
  "session_id": "default"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `module_path` | string | Yes | Module path |
| `options` | object | No | Module options |
| `session_id` | string | No | Session identifier (default: "default") |

**Response:**
```json
{
  "success": true,
  "output": "{\"hosts\": [...], \"ports\": [...]}",
  "error": null,
  "timestamp": "2024-01-15T10:30:00",
  "session_id": "default"
}
```

**Status Codes:**
- `200 OK` - Execution complete
- `404 Not Found` - Module not found
- `500 Internal Server Error` - Execution error

---

### POST /api/c2/command

Execute a framework command (CLI-style).

**Request Body:**
```json
{
  "command": "search smb",
  "session_id": "default"
}
```

**Available Commands:**

| Command | Description | Example |
|---------|-------------|---------|
| `help` | Show available commands | `help` |
| `search <query>` | Search for modules | `search smb` |
| `use <module>` | Load a module | `use smb/authentication` |
| `show modules` | List all modules | `show modules` |
| `show options` | Show module options | `show options` |
| `show targets` | List targets | `show targets` |
| `show creds` | List credentials | `show creds` |
| `set <opt> <val>` | Set module option | `set RHOST 10.10.10.100` |
| `run` | Execute current module | `run` |
| `exploit` | Alias for run | `exploit` |
| `back` | Unload current module | `back` |
| `target <ip>` | Set/add target | `target 10.10.10.0/24` |
| `targets` | List targets | `targets` |
| `cred <user:pass>` | Add credential | `cred admin:password123` |
| `creds` | List credentials | `creds` |
| `stats` | Show statistics | `stats` |
| `info` | Framework information | `info` |
| `clear` | Clear screen | `clear` |

**Response:**
```json
{
  "success": true,
  "output": "Found 5 module(s):\n\n  1. [exploit] SMB Authentication...",
  "error": null,
  "timestamp": "2024-01-15T10:30:00",
  "session_id": "default"
}
```

---

### GET /api/c2/sessions

List all active sessions.

**Response:**
```json
{
  "sessions": ["default", "engagement_1", "test_session"],
  "count": 3
}
```

---

### GET /api/c2/session/{session_id}

Get session information and history.

**Response:**
```json
{
  "history": [
    {
      "type": "command",
      "command": "search smb",
      "output": "Found 5 modules...",
      "timestamp": "2024-01-15T10:30:00"
    }
  ],
  "created_at": "2024-01-15T10:00:00",
  "current_module": "smb/authentication",
  "current_target": "10.10.10.100",
  "current_credential": "admin:password"
}
```

**Status Codes:**
- `200 OK` - Session found
- `404 Not Found` - Session not found

---

### DELETE /api/c2/session/{session_id}

Clear session history.

**Response:**
```json
{
  "message": "Session default cleared"
}
```

**Status Codes:**
- `200 OK` - Cleared
- `404 Not Found` - Session not found

---

## WebSocket API

Real-time communication for interactive C2 operations.

### WebSocket: /ws/c2/{session_id}

Connect to a C2 session via WebSocket.

**Connection URL:** `ws://localhost:5000/ws/c2/{session_id}`

**Initial Message (from server):**
```json
{
  "type": "connected",
  "message": "Connected to PurpleSploit C2",
  "session_id": "my_session"
}
```

**Send Command:**
```json
{
  "command": "search nmap"
}
```

**Response (success):**
```json
{
  "type": "output",
  "command": "search nmap",
  "output": "Found 2 module(s)...",
  "success": true,
  "timestamp": "2024-01-15T10:30:00"
}
```

**Response (error):**
```json
{
  "type": "error",
  "command": "invalid_cmd",
  "error": "Unknown command: invalid_cmd",
  "success": false,
  "timestamp": "2024-01-15T10:30:00"
}
```

**Example JavaScript Client:**
```javascript
const ws = new WebSocket('ws://localhost:5000/ws/c2/my_session');

ws.onopen = () => {
  console.log('Connected to C2');
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Received:', data);
};

ws.send(JSON.stringify({ command: 'help' }));
```

---

## Command Execution API

### POST /api/execute

Execute a shell command.

**Request Body:**
```json
{
  "command": "whoami",
  "timeout": 300
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `command` | string | Yes | Shell command to execute |
| `timeout` | int | No | Timeout in seconds (default: 300) |

**Response:**
```json
{
  "success": true,
  "stdout": "root\n",
  "stderr": "",
  "return_code": 0
}
```

**Status Codes:**
- `200 OK` - Command executed (check `success` field)
- `408 Request Timeout` - Command timed out
- `500 Internal Server Error` - Execution error

**Security Note:** This endpoint executes commands directly on the server. Use with caution and appropriate access controls.

---

## Error Handling

All API errors follow a consistent format:

```json
{
  "detail": "Error message describing what went wrong"
}
```

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| `200` | Success |
| `400` | Bad Request - Invalid input |
| `404` | Not Found - Resource doesn't exist |
| `408` | Request Timeout - Operation timed out |
| `422` | Unprocessable Entity - Validation error |
| `500` | Internal Server Error |

---

## Data Models

### Credential

```typescript
interface Credential {
  name: string;           // Primary key
  username?: string;
  password?: string;
  domain?: string;
  dcip?: string;         // Domain Controller IP
  dns?: string;
  hash?: string;         // NTLM/Kerberos hash
}
```

### Target

```typescript
interface Target {
  name: string;           // Primary key
  ip: string;
  description?: string;
}
```

### Service

```typescript
interface Service {
  id: number;             // Auto-generated
  target: string;         // IP address
  service: string;        // Service name (ssh, http, etc.)
  port: number;
  version?: string;
}
```

### Exploit

```typescript
interface Exploit {
  id: number;
  target: string;
  service: string;
  port: number;
  version?: string;
  exploit_title: string;
  exploit_path?: string;
  edb_id?: string;        // Exploit-DB ID
  platform?: string;
  exploit_type?: string;
  created_at?: string;    // ISO 8601 timestamp
}
```

### Module

```typescript
interface Module {
  path: string;
  name: string;
  category: string;
  description: string;
  author: string;
  options?: Record<string, ModuleOption>;
}

interface ModuleOption {
  value: any;
  required: boolean;
  description: string;
}
```

### CommandResponse

```typescript
interface CommandResponse {
  success: boolean;
  stdout: string;
  stderr: string;
  return_code: number;
}
```

### C2CommandResponse

```typescript
interface C2CommandResponse {
  success: boolean;
  output: string;
  error?: string;
  timestamp: string;      // ISO 8601
  session_id: string;
}
```

---

## Rate Limiting

Currently no rate limiting is implemented. For production use, consider implementing rate limiting middleware.

---

## Changelog

### Version 2.0.0
- Initial REST API implementation
- Full CRUD for credentials, targets, services
- C2 module execution API
- WebSocket support for real-time C2
- Nmap XML import support
- Workspace management
- Statistics endpoints

---

## See Also

- [CONTRIBUTING.md](./CONTRIBUTING.md) - Contribution guidelines
- [Module Development Guide](./CONTRIBUTING.md#module-development) - Creating modules
- [DISCLAIMER.md](./DISCLAIMER.md) - Legal disclaimer
