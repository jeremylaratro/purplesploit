# PurpleSploit Web Portal Quick Start Guide

## 🌐 Running the Web Portal

The PurpleSploit web portal provides a modern, visual interface for analyzing targets, services, and exploits discovered during reconnaissance.

---

## Starting the Server

### Method 1: From Repository Root (Recommended)

```bash
# From the purplesploit repository root
cd /path/to/purplesploit

# Run the launcher script
python start-web-portal.py
```

### Method 2: Using Python Module

```bash
# From the purplesploit repository root
cd /path/to/purplesploit

# Add python directory to PYTHONPATH and run
PYTHONPATH=python python -m purplesploit.api.server
```

### Method 3: From Python Directory

```bash
# Navigate to python directory
cd /path/to/purplesploit/python

# Run the module
python -m purplesploit.api.server
```

### Method 4: If Installed as Package

```bash
# If you've run: pip install -e ./python
purplesploit-api
```

---

## Accessing the Portal

Once the server is running, you'll see:

```
🔮 PurpleSploit Web Portal & API Server
======================================================================
Starting server...
Web Portal: http://localhost:5000
API Docs:   http://localhost:5000/api/docs

Press Ctrl+C to stop
======================================================================

[INFO] Serving web portal from: /path/to/purplesploit/python/purplesploit/web/static
INFO:     Started server process [12345]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:5000 (Press CTRL+C to quit)
```

Open your browser to: **http://localhost:5000**

---

## What You'll See

### Main Dashboard (`/`)
- Overview statistics (targets, services, exploits, credentials)
- Service distribution chart
- Recent targets with service/exploit counts
- Latest exploit discoveries

### Targets Browser (`/static/targets.html`)
- All discovered targets in grid view
- Filter by service type
- Search by IP, name, or description
- Critical services highlighting

### Target Analysis (`/static/target.html?ip=X.X.X.X`)
- Detailed target analysis
- All discovered services with versions
- Potential exploits with EDB links
- Security recommendations

### Exploits Browser (`/static/exploits.html`)
- All discovered exploits
- Filter by target, service, or platform
- Links to Exploit-DB
- Copy exploit paths

---

## Usage Workflow

### 1. Run a Scan and Parse Results

```bash
# Run nmap scan
nmap -sV -oX scan.xml 192.168.1.0/24

# Parse with PurpleSploit
cd /path/to/purplesploit/python
python -m purplesploit.main

# In the console:
purplesploit> use recon/nmap_parser
purplesploit(nmap_parser)> set XML_FILE /path/to/scan.xml
purplesploit(nmap_parser)> run
```

### 2. Start the Web Portal

```bash
# From repo root
cd /path/to/purplesploit
python start-web-portal.py
```

### 3. View Results

Open browser to http://localhost:5000 and explore:
- Dashboard shows overview
- Click any target to see detailed analysis
- Browse exploits by service type
- Get security recommendations

---

## API Endpoints

The web portal uses these API endpoints (also available for direct access):

### Statistics
- `GET /api/stats/overview` - Overview statistics
- `GET /api/health` - Health check

### Targets
- `GET /api/targets` - List all targets
- `GET /api/analysis/{target}` - Comprehensive target analysis

### Services
- `GET /api/services` - All services
- `GET /api/services/{target}` - Services for specific target

### Exploits
- `GET /api/exploits` - All exploits
- `GET /api/exploits/target/{target}` - Exploits for specific target

### Documentation
- `GET /api/docs` - Interactive API documentation (Swagger)
- `GET /api/redoc` - Alternative API documentation

---

## Troubleshooting

### Static Files Not Found

If you see: `[WARNING] Web portal static files not found`

**Solution**: Make sure you're running from the correct directory:
```bash
cd /path/to/purplesploit
python start-web-portal.py
```

The static files are located at: `python/purplesploit/web/static/`

### Port Already in Use

If port 5000 is already in use, modify the port in `python/purplesploit/api/server.py`:

```python
def main():
    import uvicorn
    uvicorn.run(
        "purplesploit.api.server:app",
        host="0.0.0.0",
        port=5001,  # Change this
        reload=True,
        log_level="info"
    )
```

### No Data Showing

Make sure you have:
1. Run nmap scans and parsed them
2. Data is stored in `~/.purplesploit/` databases
3. Server is accessing the correct database files

---

## Features

### ✅ Real-time Updates
Data loads asynchronously without page reloads

### ✅ Search & Filter
Filter targets by service, search exploits by keyword

### ✅ Mobile Responsive
Works on desktop, tablet, and mobile devices

### ✅ Professional Theme
Dark theme optimized for security professionals

### ✅ Exploit Integration
Direct links to Exploit-DB for verified exploits

### ✅ Zero Configuration
Works immediately with existing data

---

## Security Notes

⚠️ **For Internal Use Only**: This web portal is designed for internal pentesting use

⚠️ **No Authentication**: The current version has no authentication. Do not expose to untrusted networks.

⚠️ **Production Deployment**: For production use, add:
- Authentication (JWT, OAuth)
- HTTPS/TLS
- Rate limiting
- CORS restrictions

---

## Need Help?

- Check the API docs: http://localhost:5000/api/docs
- Review the main README.md
- Check GitHub issues: https://github.com/jeremylaratro/purplesploit/issues

---

**Enjoy your new visual target analysis interface! 🔮**
