"""
REST API Server
FastAPI server providing HTTP API for PurpleSploit
"""

import subprocess
from typing import List, Optional
from pathlib import Path

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from purplesploit.models.database import (
    db_manager,
    Credential, Target, WebTarget, ADTarget, Service, Exploit,
    CredentialCreate, CredentialResponse,
    TargetCreate, TargetResponse,
    ServiceResponse
)

# Create FastAPI app
app = FastAPI(
    title="PurpleSploit API",
    description="REST API for PurpleSploit pentesting framework",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify allowed origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files for web portal
# Try multiple paths to support both installed package and running from repo
def find_static_dir():
    """Find the static files directory"""
    # Path 1: Installed package or running from python/ directory
    static_dir = Path(__file__).parent.parent / "web" / "static"
    if static_dir.exists():
        return static_dir

    # Path 2: Running from repo root (e.g., python -m purplesploit.api.server from repo root)
    repo_static = Path(__file__).parent.parent.parent.parent / "python" / "purplesploit" / "web" / "static"
    if repo_static.exists():
        return repo_static

    # Path 3: Check if we're in the repo's python directory
    alt_static = Path(__file__).parent.parent / "web" / "static"
    if alt_static.exists():
        return alt_static

    return None

STATIC_DIR = find_static_dir()
if STATIC_DIR:
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    print(f"[INFO] Serving web portal from: {STATIC_DIR}")
else:
    print("[WARNING] Web portal static files not found. API-only mode enabled.")



# ============================================================================
# Request/Response Models
# ============================================================================

class CommandRequest(BaseModel):
    """Request model for command execution"""
    command: str
    timeout: Optional[int] = 300


class CommandResponse(BaseModel):
    """Response model for command execution"""
    success: bool
    stdout: str
    stderr: str
    return_code: int


class ScanRequest(BaseModel):
    """Request model for nmap scan"""
    target: str
    scan_type: Optional[str] = "-sV"
    ports: Optional[str] = None


class WorkspaceInfo(BaseModel):
    """Workspace information"""
    name: str
    path: str
    target_count: int
    cred_count: int


# ============================================================================
# Health & Status
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the main web portal dashboard"""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    else:
        # Fallback to API info if static files not available
        return JSONResponse({
            "name": "PurpleSploit API",
            "version": "2.0.0",
            "status": "operational",
            "docs": "/api/docs",
            "web_portal": "Static files not found. Run from installed package."
        })


@app.get("/api/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy"}


@app.get("/api/status")
async def status():
    """Get system status"""
    targets = db_manager.get_all_targets()
    credentials = db_manager.get_all_credentials()

    return {
        "targets_count": len(targets),
        "credentials_count": len(credentials),
        "databases": {
            "credentials": str(db_manager.CREDENTIALS_DB),
            "targets": str(db_manager.TARGETS_DB),
            "web_targets": str(db_manager.WEB_TARGETS_DB),
            "ad_targets": str(db_manager.AD_TARGETS_DB),
            "services": str(db_manager.SERVICES_DB),
        }
    }


# ============================================================================
# Credentials API
# ============================================================================

@app.get("/api/credentials", response_model=List[CredentialResponse])
async def get_credentials():
    """Get all credentials"""
    creds = db_manager.get_all_credentials()
    return [CredentialResponse.from_orm(c) for c in creds]


@app.post("/api/credentials", response_model=CredentialResponse)
async def create_credential(cred: CredentialCreate):
    """Create a new credential"""
    try:
        db_cred = db_manager.add_credential(cred)
        return CredentialResponse.from_orm(db_cred)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/credentials/{name}", response_model=CredentialResponse)
async def get_credential(name: str):
    """Get a specific credential"""
    session = db_manager.get_credentials_session()
    try:
        cred = session.query(Credential).filter(Credential.name == name).first()
        if not cred:
            raise HTTPException(status_code=404, detail="Credential not found")
        return CredentialResponse.from_orm(cred)
    finally:
        session.close()


@app.delete("/api/credentials/{name}")
async def delete_credential(name: str):
    """Delete a credential"""
    session = db_manager.get_credentials_session()
    try:
        cred = session.query(Credential).filter(Credential.name == name).first()
        if not cred:
            raise HTTPException(status_code=404, detail="Credential not found")
        session.delete(cred)
        session.commit()
        return {"message": f"Credential '{name}' deleted"}
    finally:
        session.close()


# ============================================================================
# Targets API
# ============================================================================

@app.get("/api/targets", response_model=List[TargetResponse])
async def get_targets():
    """Get all targets"""
    targets = db_manager.get_all_targets()
    return [TargetResponse.from_orm(t) for t in targets]


@app.post("/api/targets", response_model=TargetResponse)
async def create_target(target: TargetCreate):
    """Create a new target"""
    try:
        db_target = db_manager.add_target(target)
        return TargetResponse.from_orm(db_target)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/targets/{name}", response_model=TargetResponse)
async def get_target(name: str):
    """Get a specific target"""
    session = db_manager.get_targets_session()
    try:
        target = session.query(Target).filter(Target.name == name).first()
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        return TargetResponse.from_orm(target)
    finally:
        session.close()


@app.delete("/api/targets/{name}")
async def delete_target(name: str):
    """Delete a target"""
    session = db_manager.get_targets_session()
    try:
        target = session.query(Target).filter(Target.name == name).first()
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        session.delete(target)
        session.commit()
        return {"message": f"Target '{name}' deleted"}
    finally:
        session.close()


# ============================================================================
# Services API
# ============================================================================

@app.get("/api/services", response_model=List[ServiceResponse])
async def get_all_services():
    """Get all detected services"""
    session = db_manager.get_services_session()
    try:
        services = session.query(Service).all()
        return [ServiceResponse.from_orm(s) for s in services]
    finally:
        session.close()


@app.get("/api/services/{target}", response_model=List[ServiceResponse])
async def get_target_services(target: str):
    """Get services for a specific target"""
    services = db_manager.get_services_for_target(target)
    return [ServiceResponse.from_orm(s) for s in services]


# ============================================================================
# Command Execution API
# ============================================================================

@app.post("/api/execute", response_model=CommandResponse)
async def execute_command(request: CommandRequest):
    """Execute a shell command"""
    try:
        result = subprocess.run(
            request.command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=request.timeout
        )

        return CommandResponse(
            success=result.returncode == 0,
            stdout=result.stdout,
            stderr=result.stderr,
            return_code=result.returncode
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Command timed out")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan/nmap")
async def scan_nmap(request: ScanRequest, background_tasks: BackgroundTasks):
    """Run nmap scan"""
    command = f"nmap {request.scan_type} {request.target}"
    if request.ports:
        command += f" -p {request.ports}"

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=600
        )

        return CommandResponse(
            success=result.returncode == 0,
            stdout=result.stdout,
            stderr=result.stderr,
            return_code=result.returncode
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Workspaces API
# ============================================================================

@app.get("/api/workspaces")
async def get_workspaces():
    """List all workspaces"""
    workspaces_dir = Path.home() / ".purplesploit" / "workspaces"
    if not workspaces_dir.exists():
        return []

    workspaces = []
    for workspace_path in workspaces_dir.iterdir():
        if workspace_path.is_dir():
            workspaces.append({
                "name": workspace_path.name,
                "path": str(workspace_path)
            })

    return workspaces


@app.get("/api/workspaces/{name}")
async def get_workspace(name: str):
    """Get workspace information"""
    workspace_dir = Path.home() / ".purplesploit" / "workspaces" / name
    if not workspace_dir.exists():
        raise HTTPException(status_code=404, detail="Workspace not found")

    variables_file = workspace_dir / "variables.env"
    variables = {}
    if variables_file.exists():
        for line in variables_file.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                variables[key.strip()] = value.strip()

    return {
        "name": name,
        "path": str(workspace_dir),
        "variables": variables
    }


# ============================================================================
# Statistics API
# ============================================================================

@app.get("/api/stats/overview")
async def get_stats_overview():
    """Get overview statistics"""
    targets = db_manager.get_all_targets()
    credentials = db_manager.get_all_credentials()

    session = db_manager.get_services_session()
    try:
        services = session.query(Service).all()

        # Group services by type
        service_counts = {}
        for service in services:
            service_type = service.service
            service_counts[service_type] = service_counts.get(service_type, 0) + 1

        return {
            "total_targets": len(targets),
            "total_credentials": len(credentials),
            "total_services": len(services),
            "services_by_type": service_counts,
            "targets_with_services": len(set(s.target for s in services))
        }
    finally:
        session.close()


# ============================================================================
# Target Analysis API
# ============================================================================

class ExploitResponse(BaseModel):
    """Response model for exploits"""
    id: int
    target: str
    service: str
    port: int
    version: Optional[str]
    exploit_title: str
    exploit_path: Optional[str]
    edb_id: Optional[str]
    platform: Optional[str]
    exploit_type: Optional[str]
    created_at: Optional[str]

    class Config:
        from_attributes = True


class TargetAnalysisResponse(BaseModel):
    """Complete analysis of a target"""
    target: TargetResponse
    services: List[ServiceResponse]
    exploits: List[ExploitResponse]
    exploit_count: int
    service_count: int
    critical_services: List[str]


@app.get("/api/analysis/{target}", response_model=TargetAnalysisResponse)
async def get_target_analysis(target: str):
    """Get comprehensive analysis of a target including services and exploits"""
    # Get target info
    target_session = db_manager.get_targets_session()
    try:
        db_target = target_session.query(Target).filter(Target.ip == target).first()
        if not db_target:
            raise HTTPException(status_code=404, detail="Target not found")
        target_info = TargetResponse.from_orm(db_target)
    finally:
        target_session.close()

    # Get services for target
    services = db_manager.get_services_for_target(target)
    services_list = [ServiceResponse.from_orm(s) for s in services]

    # Get exploits for target
    exploits = db_manager.get_exploits_for_target(target)
    exploits_list = [ExploitResponse.from_orm(e) for e in exploits]

    # Identify critical services
    critical_services = []
    critical_service_names = ['smb', 'rdp', 'mssql', 'ssh', 'telnet', 'ftp']
    for service in services:
        if service.service in critical_service_names:
            critical_services.append(f"{service.service}:{service.port}")

    return TargetAnalysisResponse(
        target=target_info,
        services=services_list,
        exploits=exploits_list,
        exploit_count=len(exploits_list),
        service_count=len(services_list),
        critical_services=critical_services
    )


@app.get("/api/exploits", response_model=List[ExploitResponse])
async def get_all_exploits():
    """Get all exploits"""
    exploits = db_manager.get_all_exploits()
    return [ExploitResponse.from_orm(e) for e in exploits]


@app.get("/api/exploits/target/{target}", response_model=List[ExploitResponse])
async def get_exploits_for_target(target: str):
    """Get all exploits for a specific target"""
    exploits = db_manager.get_exploits_for_target(target)
    return [ExploitResponse.from_orm(e) for e in exploits]


# ============================================================================
# Main Entry Point
# ============================================================================

def main(host="0.0.0.0", port=5000, reload=False):
    """
    Run the API server

    Args:
        host: Host to bind to (default: 0.0.0.0)
        port: Port to bind to (default: 5000)
        reload: Enable auto-reload on code changes (default: False)
    """
    import uvicorn

    # Only use reload with workers if explicitly enabled
    # This avoids multiprocessing issues when called programmatically
    uvicorn.run(
        "purplesploit.api.server:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info"
    )


if __name__ == "__main__":
    main()
