# PurpleSploit Python Components

## Hybrid Architecture - Python Advanced Features

This directory contains the Python components of PurpleSploit, providing advanced features while maintaining compatibility with the existing Bash core.

## 🏗️ Architecture

```
Bash TUI (purplesploit-tui.sh)
         │
         ├──> Executes tools directly
         │
         └──> Reads/Writes SQLite databases
                    ↕
Python Components (this package)
         │
         ├──> REST API Server (FastAPI)
         ├──> Web Dashboard (FastAPI + Jinja2)
         ├──> Report Generation (PDF/HTML)
         ├──> Data Analysis (pandas/matplotlib)
         └──> Advanced TUI (Textual)
```

## 📦 Installation

### Quick Install

```bash
cd python
pip install -e .
```

### Development Install

```bash
cd python
pip install -e ".[dev,ai]"
```

### Requirements Only

```bash
cd python
pip install -r requirements.txt
```

## 🚀 Usage

### 1. REST API Server

Start the API server:

```bash
purplesploit-api
```

Or manually:

```bash
python -m purplesploit.api.server
```

Access the API:
- Swagger UI: http://localhost:5000/api/docs
- ReDoc: http://localhost:5000/api/redoc
- API Base: http://localhost:5000/api/

**Example API Calls:**

```bash
# Get all targets
curl http://localhost:5000/api/targets

# Get all credentials
curl http://localhost:5000/api/credentials

# Get services for a target
curl http://localhost:5000/api/services/192.168.1.100

# Execute command
curl -X POST http://localhost:5000/api/execute \
  -H "Content-Type: application/json" \
  -d '{"command": "whoami"}'

# Run nmap scan
curl -X POST http://localhost:5000/api/scan/nmap \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.100", "scan_type": "-sV"}'
```

### 2. Web Dashboard

Start the web dashboard:

```bash
purplesploit-web
```

Or manually:

```bash
python -m purplesploit.web.dashboard
```

Access the dashboard:
- Dashboard: http://localhost:8000
- Targets: http://localhost:8000/targets
- Credentials: http://localhost:8000/credentials
- Services: http://localhost:8000/services
- Workspaces: http://localhost:8000/workspaces
- Reports: http://localhost:8000/reports

### 3. Python Library Usage

Use PurpleSploit as a Python library:

```python
from purplesploit.models.database import db_manager

# Get all targets
targets = db_manager.get_all_targets()
for target in targets:
    print(f"Target: {target.name} ({target.ip})")

# Get services for a target
services = db_manager.get_services_for_target("192.168.1.100")
for service in services:
    print(f"  - {service.service} on port {service.port}")

# Add a new target
from purplesploit.models.database import TargetCreate
new_target = TargetCreate(
    name="test-server",
    ip="192.168.1.200",
    description="Test web server"
)
db_manager.add_target(new_target)
```

## 📚 Components

### 1. Database Models (`purplesploit.models`)

SQLAlchemy ORM models that map to existing SQLite databases:

- **Credential** - Credential storage
- **Target** - Network targets
- **WebTarget** - Web application targets
- **ADTarget** - Active Directory targets
- **Service** - Detected services

**Example:**

```python
from purplesploit.models.database import db_manager, CredentialCreate

# Add credential
cred = CredentialCreate(
    name="admin",
    username="administrator",
    password="Password123!",
    domain="CORP"
)
db_manager.add_credential(cred)

# Query credentials
all_creds = db_manager.get_all_credentials()
```

### 2. REST API (`purplesploit.api`)

FastAPI-based REST API providing:

**Endpoints:**

- `GET /api/health` - Health check
- `GET /api/status` - System status
- `GET /api/credentials` - List credentials
- `POST /api/credentials` - Create credential
- `GET /api/targets` - List targets
- `POST /api/targets` - Create target
- `GET /api/services` - List all services
- `GET /api/services/{target}` - Get target services
- `POST /api/execute` - Execute command
- `POST /api/scan/nmap` - Run nmap scan
- `GET /api/workspaces` - List workspaces
- `GET /api/stats/overview` - Get statistics

**Authentication:** Currently none (add JWT/OAuth for production)

### 3. Web Dashboard (`purplesploit.web`)

Beautiful web interface showing:

- Real-time statistics
- Target management
- Credential management
- Service detection overview
- Workspace management
- Report generation

**Tech Stack:**
- FastAPI
- Jinja2 templates
- CSS Grid layout
- Responsive design

### 4. Report Generation (`purplesploit.reporting`)

Generate professional reports:

```python
from purplesploit.reporting.generator import ReportGenerator

# Generate PDF report
generator = ReportGenerator()
generator.generate_pdf(
    workspace="client-pentest",
    output="report.pdf"
)

# Generate HTML report
generator.generate_html(
    workspace="client-pentest",
    output="report.html"
)
```

**Features:**
- PDF reports (WeasyPrint)
- HTML reports (Jinja2)
- Word documents (python-docx)
- Excel exports (openpyxl)
- Custom templates
- Charts and graphs

### 5. Data Analysis (`purplesploit.analysis`)

Analyze scan data:

```python
from purplesploit.analysis.analyzer import ScanAnalyzer

analyzer = ScanAnalyzer()

# Analyze services
service_stats = analyzer.analyze_services()

# Find vulnerabilities
vulns = analyzer.find_vulnerabilities()

# Generate charts
analyzer.plot_service_distribution("services.png")
analyzer.plot_timeline("timeline.png")
```

**Features:**
- pandas DataFrames
- matplotlib/seaborn charts
- Statistical analysis
- Vulnerability correlation
- Timeline visualization

## 🔧 Development

### Running Tests

```bash
pytest
```

### Code Quality

```bash
# Format code
black purplesploit/

# Check style
flake8 purplesploit/

# Type checking
mypy purplesploit/

# Sort imports
isort purplesploit/
```

### Project Structure

```
python/
├── purplesploit/
│   ├── __init__.py
│   ├── api/              # REST API server
│   │   ├── __init__.py
│   │   └── server.py
│   ├── web/              # Web dashboard
│   │   ├── __init__.py
│   │   ├── dashboard.py
│   │   ├── templates/    # HTML templates
│   │   └── static/       # CSS/JS/images
│   ├── reporting/        # Report generation
│   │   ├── __init__.py
│   │   └── generator.py
│   ├── analysis/         # Data analysis
│   │   ├── __init__.py
│   │   └── analyzer.py
│   ├── models/           # Database models
│   │   ├── __init__.py
│   │   └── database.py
│   └── utils/            # Utilities
│       └── __init__.py
├── setup.py
├── requirements.txt
└── README.md
```

## 🔗 Integration with Bash

The Python components read/write the same SQLite databases as the Bash scripts:

**Database Locations:**
- `~/.purplesploit/credentials.db`
- `~/.purplesploit/targets.db`
- `~/.purplesploit/web_targets.db`
- `~/.purplesploit/ad_targets.db`
- `~/.purplesploit/services.db`

**Workspaces:**
- `~/.purplesploit/workspaces/`

**Compatibility:**
- ✅ Read Bash-created data
- ✅ Write data readable by Bash
- ✅ Same database schema
- ✅ No migration needed

## 📖 API Documentation

After starting the API server, visit:

- **Swagger UI:** http://localhost:5000/api/docs
  - Interactive API testing
  - Request/response examples
  - Schema documentation

- **ReDoc:** http://localhost:5000/api/redoc
  - Clean, readable documentation
  - Code examples
  - Download OpenAPI spec

## 🎨 Customization

### Custom Templates

Add your own report templates:

```
purplesploit/reporting/templates/
├── default.html.jinja2
├── executive-summary.html.jinja2
└── custom-template.html.jinja2
```

### API Extensions

Add custom endpoints:

```python
# purplesploit/api/custom.py
from fastapi import APIRouter

router = APIRouter(prefix="/api/custom")

@router.get("/my-endpoint")
async def my_custom_endpoint():
    return {"custom": "data"}
```

## 🚦 Production Deployment

### Security

1. **Add authentication:**
   ```python
   from fastapi import Depends, HTTPException
   from fastapi.security import HTTPBearer
   ```

2. **Enable HTTPS:**
   ```bash
   uvicorn purplesploit.api.server:app \
     --host 0.0.0.0 \
     --port 443 \
     --ssl-keyfile=/path/to/key.pem \
     --ssl-certfile=/path/to/cert.pem
   ```

3. **Restrict CORS origins:**
   ```python
   app.add_middleware(
       CORSMiddleware,
       allow_origins=["https://yourdomain.com"],
       ...
   )
   ```

### Performance

1. **Use production ASGI server:**
   ```bash
   gunicorn purplesploit.api.server:app \
     -w 4 \
     -k uvicorn.workers.UvicornWorker
   ```

2. **Enable caching:**
   ```python
   from fastapi_cache import FastAPICache
   from fastapi_cache.backends.redis import RedisBackend
   ```

3. **Database connection pooling:**
   ```python
   from sqlalchemy.pool import QueuePool
   ```

## 🐛 Troubleshooting

### ImportError: No module named 'purplesploit'

```bash
cd python
pip install -e .
```

### Database locked error

Ensure no Bash scripts are accessing the database simultaneously.

### Port already in use

Change the port:

```bash
uvicorn purplesploit.api.server:app --port 5001
uvicorn purplesploit.web.dashboard:app --port 8001
```

## 📄 License

Same as PurpleSploit main project.

## 🤝 Contributing

See main project CONTRIBUTING.md

## 📞 Support

- GitHub Issues: [Report bugs]
- Documentation: See main README.md
- API Docs: http://localhost:5000/api/docs (when running)

---

**Version:** 2.0.0
**Python:** >= 3.8
**Status:** Beta - Active Development
