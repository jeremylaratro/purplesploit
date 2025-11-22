"""
Web Dashboard
Interactive web interface for PurpleSploit
"""

from pathlib import Path
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

from purplesploit.core.database import Database

# Get template directory
TEMPLATE_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"

# Create FastAPI app
app = FastAPI(title="PurpleSploit Dashboard")

# Mount static files
STATIC_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Setup templates
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database with shared PERSISTENT path
# Use /var/lib/purplesploit for cross-user compatibility and persistence across reboots
# Unlike /tmp, this location persists data permanently until manually cleared
import os
db_path = os.getenv('PURPLESPLOIT_DB', '/var/lib/purplesploit/purplesploit.db')
db = Database(db_path=db_path)


# ============================================================================
# Routes
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def dashboard_home(request: Request):
    """Main dashboard page"""
    # Get statistics from core database
    raw_targets = db.get_targets()
    credentials = db.get_credentials()
    raw_services = db.get_services()

    # Transform targets to match template expectations (use identifier as ip)
    targets = []
    for t in raw_targets:
        target_data = {
            'name': t.get('name') or t.get('identifier'),
            'ip': t.get('identifier'),
            'description': t.get('metadata', {}).get('description', '') if isinstance(t.get('metadata'), dict) else ''
        }
        targets.append(type('obj', (object,), target_data))

    # Transform services to match template expectations
    services = []
    for s in raw_services:
        service_data = {
            'target': s.get('target'),
            'service': s.get('service'),
            'port': s.get('port'),
            'version': s.get('version')
        }
        services.append(type('obj', (object,), service_data))

    # Group services by type
    service_counts = {}
    for service in raw_services:
        service_type = service.get('service', 'unknown')
        service_counts[service_type] = service_counts.get(service_type, 0) + 1

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "total_targets": len(targets),
        "total_credentials": len(credentials),
        "total_services": len(services),
        "service_counts": service_counts,
        "targets": targets[:10],  # Show top 10
        "services": services[:20],  # Show top 20
    })


@app.get("/targets", response_class=HTMLResponse)
async def targets_page(request: Request):
    """Targets management page"""
    raw_targets = db.get_targets()

    # Transform targets to match template expectations
    targets = []
    for t in raw_targets:
        target_data = {
            'name': t.get('name') or t.get('identifier'),
            'ip': t.get('identifier'),
            'description': t.get('metadata', {}).get('description', '') if isinstance(t.get('metadata'), dict) else ''
        }
        targets.append(type('obj', (object,), target_data))

    # Get services for each target
    target_services = {}
    for i, target in enumerate(raw_targets):
        target_id = target.get('identifier', target.get('name', ''))
        target_name = target.get('name', target_id)
        raw_services = db.get_services(target=target_id)
        # Transform services
        services = []
        for s in raw_services:
            service_data = {
                'target': s.get('target'),
                'service': s.get('service'),
                'port': s.get('port'),
                'version': s.get('version')
            }
            services.append(type('obj', (object,), service_data))
        target_services[target_name] = services

    return templates.TemplateResponse("targets.html", {
        "request": request,
        "targets": targets,
        "target_services": target_services,
    })


@app.get("/credentials", response_class=HTMLResponse)
async def credentials_page(request: Request):
    """Credentials management page"""
    credentials = db.get_credentials()

    return templates.TemplateResponse("credentials.html", {
        "request": request,
        "credentials": credentials,
    })


@app.get("/services", response_class=HTMLResponse)
async def services_page(request: Request):
    """Services overview page"""
    raw_services = db.get_services()

    # Transform services and group by target
    services_by_target = {}
    for s in raw_services:
        target = s.get('target', 'unknown')
        service_data = {
            'target': s.get('target'),
            'service': s.get('service'),
            'port': s.get('port'),
            'version': s.get('version')
        }
        service_obj = type('obj', (object,), service_data)

        if target not in services_by_target:
            services_by_target[target] = []
        services_by_target[target].append(service_obj)

    return templates.TemplateResponse("services.html", {
        "request": request,
        "services_by_target": services_by_target,
        "total_services": len(raw_services),
    })


@app.get("/workspaces", response_class=HTMLResponse)
async def workspaces_page(request: Request):
    """Workspaces management page"""
    workspaces_dir = Path.home() / ".purplesploit" / "workspaces"
    workspaces = []

    if workspaces_dir.exists():
        for workspace_path in workspaces_dir.iterdir():
            if workspace_path.is_dir():
                variables_file = workspace_path / "variables.env"
                var_count = 0
                if variables_file.exists():
                    var_count = len([l for l in variables_file.read_text().splitlines() if "=" in l])

                workspaces.append({
                    "name": workspace_path.name,
                    "path": str(workspace_path),
                    "variable_count": var_count,
                })

    return templates.TemplateResponse("workspaces.html", {
        "request": request,
        "workspaces": workspaces,
    })


@app.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request):
    """Reports page"""
    return templates.TemplateResponse("reports.html", {
        "request": request,
    })


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Run the web dashboard"""
    import uvicorn
    uvicorn.run(
        "purplesploit.web.dashboard:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )


if __name__ == "__main__":
    main()
