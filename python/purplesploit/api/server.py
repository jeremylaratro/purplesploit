"""
REST API Server
FastAPI server providing HTTP API for PurpleSploit
"""

import subprocess
from typing import List, Optional
from pathlib import Path

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel

from purplesploit.models.database import (
    db_manager,
    Credential, Target, WebTarget, ADTarget, Service,
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

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "PurpleSploit API",
        "version": "2.0.0",
        "status": "operational",
        "docs": "/api/docs"
    }


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
# Main Entry Point
# ============================================================================

def main():
    """Run the API server"""
    import uvicorn
    uvicorn.run(
        "purplesploit.api.server:app",
        host="0.0.0.0",
        port=5000,
        reload=True,
        log_level="info"
    )


if __name__ == "__main__":
    main()
