# Web Scanning Guide

This guide covers the re-integrated web scanning features from the original bash TUI version, now enhanced with Python implementation.

## Features

### 1. Web Service Selection

When running web modules (like feroxbuster), you now have three options for selecting targets:

#### Option 1: Select from Database
- Automatically discovers web services from nmap scan results
- Presents all discovered web servers (IP:port pairs) in an FZF menu
- Shows protocol (http/https), service name, and port information

#### Option 2: Use Selected Target
- Uses the currently selected target from the framework
- Automatically adds `http://` protocol prefix
- Quick and convenient for single-target scanning

#### Option 3: Manual Entry
- Enter any URL manually
- Supports both http:// and https://
- Automatically adds http:// if no protocol is specified

### 2. Background Execution

Web scans can now run in the background:

```bash
# Use the "Background Basic Scan" operation in feroxbuster
use web/feroxbuster
run
# Select "Background Basic Scan" from the operations menu
```

When running in background:
- Scan runs as a background process with PID tracking
- You can continue working while the scan runs
- Results are automatically saved to log files
- Check status using the `analysis` command

### 3. Results Dashboard

View all web scan results organized by target:

```bash
analysis
```

The dashboard shows:
- **Target Organization**: Results grouped by target URL
- **Scan History**: All scans per target with timestamps
- **Status Tracking**: Shows running vs completed scans
- **Findings Summary**: Number of paths found and interesting discoveries
- **Log File References**: Direct links to detailed log files

Example output:
```
═══ Web Scan Analysis Results ═══

┌─ http://192.168.1.100 ─────────────────────────┐
│ Target: http://192.168.1.100                   │
│ Total Scans: 2                                 │
│                                                 │
│ ╭───────────────┬──────────────────┬──────────╮│
│ │ Scan Type     │ Timestamp        │ Findings ││
│ ├───────────────┼──────────────────┼──────────┤│
│ │ feroxbuster   │ 2025-11-27 10:30 │ 42 paths ││
│ │ feroxbuster   │ 2025-11-27 11:15 │ Running  ││
│ ╰───────────────┴──────────────────┴──────────╯│
└─────────────────────────────────────────────────┘
```

### 4. Log File Management

All web scan results are saved to log files:

**Location**: `~/.purplesploit/logs/web/`

**Naming Format**: `feroxbuster_<target>_<timestamp>.txt`

Example:
```
~/.purplesploit/logs/web/feroxbuster_http_192.168.1.100_20251127_103045.txt
```

Each log file contains:
- Complete feroxbuster output
- All discovered paths with status codes
- Response sizes and metadata
- Filtered results (200, 301, 302, 403, etc.)

### 5. Automatic Result Parsing

The system automatically parses feroxbuster output and extracts:
- **Found Paths**: All discovered URLs with status codes
- **Interesting Finds**: Automatically flags:
  - 200 OK responses (accessible resources)
  - 301/302/307/308 redirects
  - 403 Forbidden (potential restricted areas)
- **Statistics**: Total requests, status code distribution

## Workflow Examples

### Example 1: Scan Web Services from Nmap Results

```bash
# 1. Run nmap scan
use recon/nmap
set RHOST 192.168.1.0/24
run

# 2. Parse results to populate services database
parse nmap_results.xml

# 3. Run web scan with database selection
use web/feroxbuster
run
# Choose option 1: Select web target from database
# Select target from FZF menu

# 4. View results
analysis
```

### Example 2: Quick Scan of Current Target

```bash
# 1. Set target
target 192.168.1.100

# 2. Run web scan
use web/feroxbuster
run
# Choose option 2: Use selected target from framework

# 3. View results in real-time or check analysis later
analysis
```

### Example 3: Background Scanning

```bash
# 1. Start background scan
use web/feroxbuster
run
# Select "Background Basic Scan"
# Choose target using any of the 3 options

# 2. Continue working on other tasks
use network/nxc_smb
# ... do other work ...

# 3. Check web scan status later
analysis
# Shows "Running" status with PID

# 4. When complete, view detailed results
analysis
# Shows findings summary

# 5. Check log file for full output
cat ~/.purplesploit/logs/web/feroxbuster_*.txt
```

## Database Integration

### Web Service Detection

The system automatically detects web services from nmap scans based on:

**Service Names**:
- http, https
- http-proxy, http-alt
- ssl/http, ssl/https

**Common Web Ports**:
- 80, 443 (standard HTTP/HTTPS)
- 8080, 8443 (alternate HTTP/HTTPS)
- 8000, 8888, 9090 (development servers)
- 3000, 5000, 9000 (application servers)
- 8001, 8008, 4443, 8081, 8082, 9443 (other common web ports)

### Querying Web Services

You can query discovered web services programmatically:

```python
# Get all web services from database
web_services = framework.database.get_web_services()

# Each service contains:
# - target: IP address
# - port: Port number
# - service: Service name
# - protocol: http or https
# - url: Formatted URL (http://ip:port or https://ip:port)
```

## Available Web Modules

All web modules support the new web service selection workflow:

- **feroxbuster**: Directory and file discovery
- **wfuzz**: Web fuzzing
- **httpx**: HTTP probing and analysis
- **sqlmap**: SQL injection testing

## Tips and Best Practices

1. **Run Nmap First**: Always run nmap scans before web scanning to populate the services database

2. **Use Background Scans**: For long-running scans (like deep directory enumeration), use background mode

3. **Check Analysis Regularly**: Use the `analysis` command to monitor scan progress and review findings

4. **Save Log Files**: Log files are automatically saved, but you can archive them for later reference

5. **Combine with Other Modules**: Use web scanning results to inform other attack modules

## Troubleshooting

### No Web Services Found

**Problem**: "No web services found in database" when selecting option 1

**Solution**:
- Run an nmap scan first: `use recon/nmap`
- Parse nmap results: `parse <xml_file>`
- Or manually add services to database

### Background Scan Not Showing Results

**Problem**: Background scan shows "Running" for a long time

**Solution**:
- Check if the process is still running: `ps aux | grep feroxbuster`
- Check log file for progress: `tail -f ~/.purplesploit/logs/web/feroxbuster_*.txt`
- The scan may still be in progress (feroxbuster can take a while)

### FZF Menu Not Appearing

**Problem**: Simple menu appears instead of FZF

**Solution**:
- Install fzf: `apt-get install fzf` (Debian/Ubuntu) or `brew install fzf` (macOS)
- Restart purplesploit after installation

## Migration from Bash TUI

If you used the original bash TUI version, here's what changed:

### What's the Same
- Web service selection from database
- FZF-based interactive selection
- Automatic web service detection from nmap

### What's New
- **Background execution**: Run scans without blocking
- **Results dashboard**: Organized view of all scan results
- **Automatic parsing**: Extracts interesting findings automatically
- **Log file management**: Organized storage with timestamps
- **Python integration**: Better database integration and extensibility

### What's Different
- No separate web_targets.sh file - integrated into module
- URL selection is now part of module execution, not a separate step
- Results stored in SQLite database instead of flat files
- Enhanced analysis with rich formatting and panels
