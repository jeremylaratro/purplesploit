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

from purplesploit.models.database import db_manager

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


# ============================================================================
# Routes
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def dashboard_home(request: Request):
    """Main dashboard page"""
    # Get statistics from models database
    raw_targets = db_manager.get_all_targets()
    raw_credentials = db_manager.get_all_credentials()
    raw_services = db_manager.get_all_services()

    # Transform targets to match template expectations
    targets = []
    for t in raw_targets:
        target_dict = t.to_dict()
        target_data = {
            'name': target_dict.get('name', ''),
            'ip': target_dict.get('ip', ''),
            'description': target_dict.get('description', '')
        }
        targets.append(type('obj', (object,), target_data))

    # Transform services to match template expectations
    services = []
    for s in raw_services:
        service_dict = s.to_dict()
        service_data = {
            'target': service_dict.get('target', ''),
            'service': service_dict.get('service', ''),
            'port': service_dict.get('port', 0),
            'version': service_dict.get('version', '')
        }
        services.append(type('obj', (object,), service_data))

    # Group services by type
    service_counts = {}
    for s in raw_services:
        service_dict = s.to_dict()
        service_type = service_dict.get('service', 'unknown')
        service_counts[service_type] = service_counts.get(service_type, 0) + 1

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "total_targets": len(targets),
        "total_credentials": len(raw_credentials),
        "total_services": len(services),
        "service_counts": service_counts,
        "targets": targets[:10],  # Show top 10
        "services": services[:20],  # Show top 20
    })


@app.get("/targets", response_class=HTMLResponse)
async def targets_page(request: Request):
    """Targets management page"""
    raw_targets = db_manager.get_all_targets()

    # Transform targets to match template expectations
    targets = []
    for i, t in enumerate(raw_targets):
        target_dict = t.to_dict()
        target_data = {
            'index': i,
            'name': target_dict.get('name', ''),
            'ip': target_dict.get('ip', ''),
            'description': target_dict.get('description', '')
        }
        targets.append(type('obj', (object,), target_data))

    # Get services for each target
    target_services = {}
    for i, target in enumerate(raw_targets):
        target_dict = target.to_dict()
        target_ip = target_dict.get('ip', '')
        target_name = target_dict.get('name', target_ip)
        raw_services = db_manager.get_services_for_target(target_ip)
        # Transform services
        services = []
        for s in raw_services:
            service_dict = s.to_dict()
            service_data = {
                'target': service_dict.get('target', ''),
                'service': service_dict.get('service', ''),
                'port': service_dict.get('port', 0),
                'version': service_dict.get('version', '')
            }
            services.append(type('obj', (object,), service_data))
        target_services[target_name] = services

    return templates.TemplateResponse("targets.html", {
        "request": request,
        "targets": targets,
        "target_services": target_services,
    })


@app.post("/targets/delete/{identifier}")
async def delete_target_web(identifier: str):
    """Delete a target via web interface"""
    # Note: For now, we'll skip deletion as it requires more complex logic
    # with the models database. The API endpoints should be used instead.
    return RedirectResponse(url="/targets", status_code=303)


@app.get("/credentials", response_class=HTMLResponse)
async def credentials_page(request: Request):
    """Credentials management page"""
    raw_credentials = db_manager.get_all_credentials()

    # Add index to credentials
    credentials = []
    for i, c in enumerate(raw_credentials):
        cred_dict = c.to_dict()
        cred_dict['index'] = i
        credentials.append(cred_dict)

    return templates.TemplateResponse("credentials.html", {
        "request": request,
        "credentials": credentials,
    })


@app.post("/credentials/delete/{cred_id}")
async def delete_credential_web(cred_id: int):
    """Delete a credential via web interface"""
    # Note: For now, we'll skip deletion as it requires more complex logic
    # with the models database. The API endpoints should be used instead.
    return RedirectResponse(url="/credentials", status_code=303)


@app.get("/services", response_class=HTMLResponse)
async def services_page(request: Request):
    """Services overview page"""
    raw_services = db_manager.get_all_services()

    # Transform services and group by target
    services_by_target = {}
    for s in raw_services:
        service_dict = s.to_dict()
        target = service_dict.get('target', 'unknown')
        service_data = {
            'target': service_dict.get('target', ''),
            'service': service_dict.get('service', ''),
            'port': service_dict.get('port', 0),
            'version': service_dict.get('version', '')
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
