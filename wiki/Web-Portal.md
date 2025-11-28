# PurpleSploit Web Portal

Guide to using the web-based interface for visual target management and real-time collaboration.

---

## Overview

The PurpleSploit web portal provides a mobile-friendly, visual interface for:
- Target and credential management
- Service detection visualization
- Real-time database sync with CLI
- Web scan results dashboard
- Background scan monitoring

---

## Starting the Web Portal

### From CLI (Recommended)
```bash
# Launch PurpleSploit
python3 -m purplesploit.main

# Start web server in background
purplesploit> webserver start

# Check status
purplesploit> webserver status

# Stop when done
purplesploit> webserver stop
```

### Manual Start
```bash
# From repository root
cd /path/to/purplesploit
python scripts/start-web-portal.py

# Or using module
PYTHONPATH=python python -m purplesploit.api.server
```

### Access
- **Dashboard**: http://localhost:5000
- **Targets**: http://localhost:5000/targets
- **Credentials**: http://localhost:5000/credentials
- **Services**: http://localhost:5000/services

---

## Features

### Target Dashboard
- View all targets with type (network/web)
- See detected services per target
- Add/edit/delete targets
- Mobile-responsive design

### Credential Manager
- Store credentials with domain information
- Organize by engagement/workspace
- Quick copy-to-clipboard
- Password visibility toggle

### Service Detection
- Auto-populated from nmap scans
- Filter by service type (SMB, LDAP, HTTP, etc.)
- Port and banner information
- Quick target selection from services

### Web Scan Results
View web enumeration results:
```bash
# In CLI, run web scans
purplesploit> use web/feroxbuster
purplesploit(feroxbuster)> run

# View results in dashboard
purplesploit> analysis
# Or visit http://localhost:5000/analysis
```

**Dashboard Features**:
- Organized by target IP:port
- Discovered directories and files
- Status codes and sizes
- Background scan status

---

## Background Scanning

### Starting Background Scans
```bash
# Example with feroxbuster
use web/feroxbuster
run
# Select "Background Basic Scan" from operations

# Continue working while scan runs
use network/nxc_smb
run
```

### Monitoring
```bash
# Check status in CLI
analysis

# Or view in web dashboard
# http://localhost:5000/analysis
```

**Features**:
- PID tracking
- Auto-saved log files
- Real-time progress (in dashboard)
- Multiple concurrent scans

---

## Real-Time Sync

Changes in CLI instantly appear in web portal and vice versa:

```bash
# Add target in CLI
purplesploit> target 192.168.1.100

# Immediately visible in web dashboard
# http://localhost:5000/targets
```

```bash
# Add credential in web portal
# Immediately available in CLI
purplesploit> creds list
```

### Database Locations
- `~/.purplesploit/credentials.db`
- `~/.purplesploit/targets.db`
- `~/.purplesploit/services.db`
- `~/.purplesploit/workspaces/`

---

## Web Service Selection

When running web modules, three options for selecting targets:

### Option 1: Select from Database
- Auto-discovers web services from nmap results
- FZF menu shows all discovered web servers (IP:port pairs)
- Displays protocol (http/https), service name, port

### Option 2: Use Selected Target
- Uses currently selected framework target
- Auto-adds `http://` protocol prefix
- Quick for single-target scanning

### Option 3: Manual Entry
- Enter any URL manually
- Supports both http:// and https://
- Auto-adds http:// if no protocol specified

```bash
use web/feroxbuster
run
# Prompted to choose:
# 1. Select from database (discovered web services)
# 2. Use current target
# 3. Enter URL manually
```

---

## Mobile Interface

The web portal is optimized for tablets and phones:

- **Responsive Design**: Adapts to screen size
- **Touch-Friendly**: Large tap targets
- **Sidebar Navigation**: Collapsible on mobile
- **Table Scrolling**: Horizontal scroll for large tables
- **Quick Actions**: Swipe gestures supported

### Recommended Workflow
1. Run CLI on desktop/laptop
2. Monitor dashboard on tablet
3. Collaborate with team via web interface

---

## API Endpoints

For custom integrations and automation:

### Targets
```bash
GET  /api/targets              # List all targets
POST /api/targets              # Create target
GET  /api/targets/{id}         # Get specific target
PUT  /api/targets/{id}         # Update target
DELETE /api/targets/{id}       # Delete target
```

### Credentials
```bash
GET  /api/credentials          # List all credentials
POST /api/credentials          # Create credential
DELETE /api/credentials/{id}   # Delete credential
```

### Services
```bash
GET  /api/services             # List all services
GET  /api/services/{target}    # Get services for target
```

### Scan Results
```bash
GET  /api/analysis             # Get web scan results
```

### System
```bash
GET  /api/health               # Health check
GET  /api/stats/overview       # Framework statistics
```

---

## Security Notes

**Default Configuration**:
- Runs on `localhost:5000` only
- No authentication (localhost only)
- Not exposed to network

**For Team Collaboration**:
```bash
# ⚠️ Only on trusted networks
python -m purplesploit.api.server --host 0.0.0.0 --port 5000

# Access from other machines:
# http://<your-ip>:5000
```

**Production Deployment**:
- Add authentication (JWT/OAuth)
- Enable HTTPS
- Restrict CORS origins
- Use reverse proxy (nginx/Apache)

---

## Troubleshooting

### Port Already in Use
```bash
# Change port
purplesploit> webserver start --port 8000
```

### Database Locked
Ensure no other PurpleSploit instances are accessing the database simultaneously.

### Results Not Updating
- Check web server is running: `webserver status`
- Refresh browser (Ctrl+F5)
- Check browser console for errors

---

## Tips

1. **Run in Background**: Use `webserver start` to keep CLI available
2. **Monitor Scans**: Use web dashboard for long-running scans
3. **Team Collaboration**: Share web URL on trusted network
4. **Mobile Monitoring**: Check progress from tablet/phone
5. **Export Data**: Use API endpoints to export targets/creds

---

**Last Updated**: v6.7.1
