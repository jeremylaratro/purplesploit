"""
REST API Server
FastAPI server providing HTTP API for PurpleSploit
"""

import subprocess
import asyncio
import json
import ipaddress
import os
from typing import List, Optional, Dict, Any
from pathlib import Path
from datetime import datetime

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import defusedxml.ElementTree as ET  # XXE-safe XML parsing

from purplesploit.models.database import (
    db_manager,
    Credential, Target, WebTarget, ADTarget, Service, Exploit,
    CredentialCreate, CredentialResponse,
    TargetCreate, TargetResponse,
    ServiceResponse
)
from purplesploit.core.framework import Framework
from purplesploit.ui.banner import show_banner

# Security configuration via environment variables
DEBUG_MODE = os.getenv('PURPLESPLOIT_DEBUG', 'false').lower() == 'true'
CORS_ORIGINS = os.getenv('PURPLESPLOIT_CORS_ORIGINS', 'http://localhost:5000,http://127.0.0.1:5000').split(',')


def sanitize_error(e: Exception) -> str:
    """Sanitize error messages based on debug mode."""
    if DEBUG_MODE:
        return str(e)
    # In production, hide internal details
    return "An internal error occurred"


# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address, enabled=not DEBUG_MODE)

# Create FastAPI app
app = FastAPI(
    title="PurpleSploit API",
    description="REST API for PurpleSploit pentesting framework",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# Register rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Enable CORS with configurable origins (defaults to localhost only)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
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

# Initialize Framework for C2 operations
# Use project-local database path
if os.getenv('PURPLESPLOIT_DB'):
    db_path = os.getenv('PURPLESPLOIT_DB')
else:
    project_root = Path(__file__).parent.parent.parent.parent
    data_dir = project_root / '.data'
    data_dir.mkdir(exist_ok=True)
    db_path = str(data_dir / 'purplesploit.db')

framework = Framework(db_path=db_path)
module_count = framework.discover_modules()
print(f"[INFO] Discovered {module_count} modules")

# Session storage for command history
sessions: Dict[str, Dict] = {}


# ============================================================================
# Utility Functions
# ============================================================================

def expand_cidr(target: str) -> List[str]:
    """
    Expand CIDR notation into individual IP addresses.

    Args:
        target: IP address or CIDR notation (e.g., "10.10.10.0/24")

    Returns:
        List of IP addresses as strings
    """
    try:
        # Try to parse as CIDR network
        network = ipaddress.ip_network(target, strict=False)

        # For large networks, limit the expansion
        if network.num_addresses > 256:
            # For /16 and larger, return the network notation itself
            # Modules should handle this appropriately
            return [str(network)]

        # For smaller networks, expand to individual IPs
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        # Not CIDR notation, treat as single IP/hostname
        return [target]


def is_cidr_notation(target: str) -> bool:
    """Check if target is in CIDR notation."""
    return '/' in target



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


@app.get("/api/banner")
async def get_banner(variant: Optional[int] = None):
    """Get a random or specific ASCII banner"""
    import random
    if variant is None:
        variant = random.randint(0, 7)
    banner_text = show_banner(variant)
    return {
        "banner": banner_text,
        "variant": variant
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


@app.put("/api/credentials/{name}")
async def update_credential(name: str, cred: CredentialCreate):
    """Update a credential"""
    session = db_manager.get_credentials_session()
    try:
        db_cred = session.query(Credential).filter(Credential.name == name).first()
        if not db_cred:
            raise HTTPException(status_code=404, detail="Credential not found")

        # Update fields
        if hasattr(cred, 'name') and cred.name:
            db_cred.name = cred.name
        if hasattr(cred, 'username') and cred.username:
            db_cred.username = cred.username
        if hasattr(cred, 'password') and cred.password:
            db_cred.password = cred.password
        if hasattr(cred, 'domain') and cred.domain:
            db_cred.domain = cred.domain
        if hasattr(cred, 'hash') and cred.hash:
            db_cred.hash = cred.hash

        session.commit()
        session.refresh(db_cred)
        return CredentialResponse.from_orm(db_cred)
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


@app.put("/api/targets/{name}")
async def update_target(name: str, target: TargetCreate):
    """Update a target"""
    session = db_manager.get_targets_session()
    try:
        db_target = session.query(Target).filter(Target.name == name).first()
        if not db_target:
            raise HTTPException(status_code=404, detail="Target not found")

        # Update fields
        if hasattr(target, 'name') and target.name:
            db_target.name = target.name
        if hasattr(target, 'ip') and target.ip:
            db_target.ip = target.ip
        if hasattr(target, 'description') and target.description:
            db_target.description = target.description

        session.commit()
        session.refresh(db_target)
        return TargetResponse.from_orm(db_target)
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
# Nmap Import/Upload API
# ============================================================================

@app.post("/api/nmap/upload")
async def upload_nmap_results(file: UploadFile = File(...)):
    """
    Upload and parse nmap XML scan results.

    Automatically imports discovered hosts with open ports to targets and services tables.
    """
    if not file.filename.endswith('.xml'):
        raise HTTPException(status_code=400, detail="Only XML files are supported")

    try:
        # Save uploaded file temporarily
        import tempfile
        # Note: XML parsing uses defusedxml (imported at module level) to prevent XXE attacks

        with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            tmp_path = tmp_file.name

        # Parse XML using nmap module
        from purplesploit.modules.recon.nmap import NmapModule

        # Create framework instance
        framework = get_framework()
        nmap_module = NmapModule(framework)

        # Parse XML
        parsed_xml = nmap_module.parse_xml_output(tmp_path)

        if not parsed_xml.get("hosts"):
            # Clean up temp file
            Path(tmp_path).unlink()
            return {
                "success": True,
                "message": "No hosts with open ports found in scan results",
                "hosts_discovered": 0,
                "total_scanned": parsed_xml.get("total_hosts", 0)
            }

        # Process discovered hosts
        nmap_module.process_discovered_hosts(parsed_xml)

        # Clean up temp file
        Path(tmp_path).unlink()

        return {
            "success": True,
            "message": f"Successfully imported {len(parsed_xml.get('hosts', []))} hosts",
            "hosts_discovered": len(parsed_xml.get("hosts", [])),
            "total_scanned": parsed_xml.get("total_hosts", 0),
            "filename": file.filename
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing nmap results: {sanitize_error(e)}")


# ============================================================================
# Command Execution API
# ============================================================================

@app.post("/api/execute", response_model=CommandResponse)
@limiter.limit("10/minute")
async def execute_command(request: Request, cmd_request: CommandRequest):
    """Execute a shell command (rate limited: 10/minute)"""
    try:
        result = subprocess.run(
            cmd_request.command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=cmd_request.timeout
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
        raise HTTPException(status_code=500, detail=sanitize_error(e))


@app.post("/api/scan/nmap")
@limiter.limit("30/minute")
async def scan_nmap(request: Request, scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """Run nmap scan (rate limited: 30/minute)"""
    command = f"nmap {scan_request.scan_type} {scan_request.target}"
    if scan_request.ports:
        command += f" -p {scan_request.ports}"

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
        raise HTTPException(status_code=500, detail=sanitize_error(e))


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
    version: Optional[str] = None
    exploit_title: str
    exploit_path: Optional[str] = None
    edb_id: Optional[str] = None
    platform: Optional[str] = None
    exploit_type: Optional[str] = None
    created_at: Optional[str] = None

    model_config = {"from_attributes": True}


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
# C2 Command & Control API
# ============================================================================

class C2CommandRequest(BaseModel):
    """Request model for C2 command execution"""
    command: str
    session_id: Optional[str] = "default"

class C2CommandResponse(BaseModel):
    """Response model for C2 command execution"""
    success: bool
    output: str
    error: Optional[str] = None
    timestamp: str
    session_id: str

class ModuleListResponse(BaseModel):
    """Response model for module list"""
    path: str
    name: str
    category: str
    description: str
    author: str

class ModuleExecuteRequest(BaseModel):
    """Request model for module execution"""
    module_path: str
    options: Optional[Dict[str, Any]] = None
    session_id: Optional[str] = "default"


@app.get("/api/c2/modules")
async def list_modules():
    """List all available modules"""
    modules = framework.list_modules()
    return [{
        "path": m.path,
        "name": m.name,
        "category": m.category,
        "description": m.description,
        "author": m.author
    } for m in modules]


@app.get("/api/c2/modules/search")
async def search_modules(query: str):
    """Search modules by name, description, or category"""
    results = framework.search_modules(query)
    return [{
        "path": m.path,
        "name": m.name,
        "category": m.category,
        "description": m.description,
        "author": m.author
    } for m in results]


@app.get("/api/c2/modules/{category}")
async def get_modules_by_category(category: str):
    """Get modules by category"""
    modules = framework.list_modules(category=category)
    return [{
        "path": m.path,
        "name": m.name,
        "category": m.category,
        "description": m.description,
        "author": m.author
    } for m in modules]


@app.get("/api/c2/module/{module_path:path}")
async def get_module_info(module_path: str):
    """Get detailed module information"""
    metadata = framework.get_module(module_path)
    if not metadata:
        raise HTTPException(status_code=404, detail="Module not found")

    # Instantiate to get options
    module_instance = metadata.instance(framework)

    return {
        "path": metadata.path,
        "name": metadata.name,
        "category": metadata.category,
        "description": metadata.description,
        "author": metadata.author,
        "options": module_instance.show_options()
    }


@app.post("/api/c2/module/execute")
@limiter.limit("30/minute")
async def execute_module(request: Request, module_request: ModuleExecuteRequest):
    """Execute a module with provided options (rate limited: 30/minute)"""
    try:
        # Load module
        module = framework.use_module(module_request.module_path)
        if not module:
            raise HTTPException(status_code=404, detail="Module not found")

        # Set options if provided
        if module_request.options:
            for key, value in module_request.options.items():
                module.set_option(key, value)

        # Run module
        results = framework.run_module(module)

        # Store in session history
        session_id = module_request.session_id
        if session_id not in sessions:
            sessions[session_id] = {
                "history": [],
                "created_at": datetime.now().isoformat(),
                "current_module": None,
                "current_target": None,
                "current_credential": None
            }

        sessions[session_id]["history"].append({
            "type": "module_execution",
            "module": module_request.module_path,
            "timestamp": datetime.now().isoformat(),
            "results": results
        })

        return {
            "success": results.get("success", False),
            "output": json.dumps(results, indent=2),
            "error": results.get("error"),
            "timestamp": datetime.now().isoformat(),
            "session_id": session_id
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=sanitize_error(e))


@app.post("/api/c2/command")
async def execute_c2_command(request: C2CommandRequest):
    """Execute a framework command"""
    try:
        command = request.command.strip()
        session_id = request.session_id

        # Initialize session if needed
        if session_id not in sessions:
            sessions[session_id] = {
                "history": [],
                "created_at": datetime.now().isoformat(),
                "current_module": None,
                "current_target": None,
                "current_credential": None
            }

        # Parse and execute command
        output = await execute_framework_command(command, session_id)

        # Store in history
        sessions[session_id]["history"].append({
            "type": "command",
            "command": command,
            "output": output,
            "timestamp": datetime.now().isoformat()
        })

        return C2CommandResponse(
            success=True,
            output=output,
            timestamp=datetime.now().isoformat(),
            session_id=session_id
        )
    except Exception as e:
        return C2CommandResponse(
            success=False,
            output="",
            error=str(e),
            timestamp=datetime.now().isoformat(),
            session_id=request.session_id
        )


async def execute_framework_command(command: str, session_id: str) -> str:
    """Execute a framework command and return output (non-blocking)"""
    parts = command.split()
    if not parts:
        return ""

    cmd = parts[0].lower()
    args = parts[1:] if len(parts) > 1 else []

    # Run blocking operations in executor to prevent WebSocket blocking
    loop = asyncio.get_event_loop()

    # Handle different commands
    if cmd == "help":
        return """Available Commands:
  search <query>       - Search for modules
  use <module>         - Load a module
  show modules         - List all modules
  show options         - Show module options
  set <opt> <val>      - Set module option
  run                  - Execute current module
  back                 - Unload current module
  targets              - List targets
  target <ip|subnet>   - Set target (supports CIDR notation)
  creds                - List credentials
  cred <user:pass>     - Add credential
  stats                - Show statistics
  info                 - Show framework information
  clear                - Clear screen

Examples:
  search smb                 - Find SMB-related modules
  use smb/authentication     - Load SMB auth module
  target 10.10.10.100        - Set single target
  target 10.10.10.0/24       - Add entire subnet (/24 expands to 254 IPs)
  target 192.168.0.0/16      - Add large subnet (kept as range)
  set RHOST 10.10.10.100     - Set target option
  run                        - Execute the module
"""

    elif cmd == "search":
        if not args:
            return "Usage: search <query>"
        query = " ".join(args)
        # Run in executor to avoid blocking
        results = await loop.run_in_executor(None, framework.search_modules, query)
        if not results:
            return f"No modules found matching '{query}'"
        output = f"Found {len(results)} module(s):\n\n"
        for i, m in enumerate(results, 1):
            output += f"  {i}. [{m.category}] {m.name}\n"
            output += f"     {m.path}\n"
            output += f"     {m.description}\n\n"
        return output

    elif cmd == "use":
        if not args:
            return "Usage: use <module_path>"
        module_path = " ".join(args)
        # Run in executor to avoid blocking
        module = await loop.run_in_executor(None, framework.use_module, module_path)
        if module:
            sessions[session_id]["current_module"] = module_path
            return f"Loaded module: {module.name}\nUse 'show options' to see available options."

        # Module not found - provide helpful suggestions
        output = f"Module not found: {module_path}\n\n"

        # Try to find similar modules
        search_results = await loop.run_in_executor(None, framework.search_modules, module_path.split('/')[-1])
        if search_results:
            output += "Did you mean one of these?\n\n"
            for i, m in enumerate(search_results[:5], 1):
                output += f"  {i}. {m.path}\n"
                output += f"     {m.name} - {m.description}\n\n"
            output += f"Use 'search {module_path}' to find more modules."
        else:
            output += "Use 'show modules' to see all available modules.\n"
            output += f"Or use 'search <keyword>' to find specific modules."

        return output

    elif cmd == "show":
        if not args:
            return "Usage: show [modules|options|targets|creds]"

        subcmd = args[0].lower()

        if subcmd == "modules":
            modules = await loop.run_in_executor(None, framework.list_modules)
            output = f"Available Modules ({len(modules)}):\n\n"
            current_category = None
            for m in modules:
                if m.category != current_category:
                    output += f"\n[{m.category.upper()}]\n"
                    current_category = m.category
                output += f"  {m.path}\n"
            return output

        elif subcmd == "options":
            if not sessions[session_id].get("current_module"):
                return "No module loaded. Use 'use <module>' first."
            module = await loop.run_in_executor(None, framework.use_module, sessions[session_id]["current_module"])
            if not module:
                return "Error loading current module"
            options = await loop.run_in_executor(None, module.show_options)
            output = "Module Options:\n\n"
            for key, opt in options.items():
                required = "[*]" if opt.get('required') else "   "
                value = opt.get('value', '')
                desc = opt.get('description', '')
                output += f"  {required} {key:15} {str(value):20} {desc}\n"
            return output

        elif subcmd == "targets":
            targets = framework.session.targets.list()
            if not targets:
                return "No targets configured"
            output = "Targets:\n"
            for t in targets:
                output += f"  • {t.get('name', 'N/A')} - {t.get('ip', t.get('url', 'N/A'))}\n"
            return output

        elif subcmd == "creds":
            creds = framework.session.credentials.list()
            if not creds:
                return "No credentials configured"
            output = "Credentials:\n"
            for c in creds:
                domain = f"{c.get('domain')}/" if c.get('domain') else ""
                output += f"  • {domain}{c.get('username')}:{c.get('password', '[hash]')}\n"
            return output

        return f"Unknown show command: {subcmd}"

    elif cmd == "set":
        if len(args) < 2:
            return "Usage: set <option> <value>"
        if not sessions[session_id].get("current_module"):
            return "No module loaded. Use 'use <module>' first."

        module = await loop.run_in_executor(None, framework.use_module, sessions[session_id]["current_module"])
        if not module:
            return "Error loading current module"

        option = args[0]
        value = " ".join(args[1:])
        await loop.run_in_executor(None, module.set_option, option, value)
        return f"Set {option} => {value}"

    elif cmd == "run" or cmd == "exploit":
        if not sessions[session_id].get("current_module"):
            return "No module loaded. Use 'use <module>' first."

        module = await loop.run_in_executor(None, framework.use_module, sessions[session_id]["current_module"])
        if not module:
            return "Error loading current module"

        results = await loop.run_in_executor(None, framework.run_module, module)
        output = "Module Execution Results:\n\n"
        output += json.dumps(results, indent=2)
        return output

    elif cmd == "back":
        sessions[session_id]["current_module"] = None
        return "Unloaded current module"

    elif cmd == "target":
        if not args:
            # Show current target
            current = await loop.run_in_executor(None, framework.session.targets.get_current)
            if current:
                return f"Current target: {current.get('name')} - {current.get('ip', current.get('url'))}"
            return "No target set"

        # Add/set target (non-blocking)
        target_input = args[0]

        # Check if it's CIDR notation
        if is_cidr_notation(target_input):
            # Add subnet as-is, don't expand
            await loop.run_in_executor(None, framework.add_target, "network", target_input, target_input)
            # Update session
            sessions[session_id]["current_target"] = target_input
            return f"Target subnet added: {target_input}\n(Subnet will be expanded when hosts are verified via scanning)"
        else:
            # Single IP/hostname
            await loop.run_in_executor(None, framework.add_target, "network", target_input, target_input)
            # Update session
            sessions[session_id]["current_target"] = target_input
            return f"Target set: {target_input}"

    elif cmd == "targets":
        targets = framework.session.targets.list()
        if not targets:
            return "No targets configured"
        output = "Targets:\n"
        for t in targets:
            output += f"  • {t.get('name', 'N/A')} - {t.get('ip', t.get('url', 'N/A'))}\n"
        return output

    elif cmd == "cred":
        if not args:
            return "Usage: cred <username:password>"

        cred_str = args[0]
        if ":" in cred_str:
            username, password = cred_str.split(":", 1)
            await loop.run_in_executor(None, framework.add_credential, username, password)
            # Update session
            sessions[session_id]["current_credential"] = f"{username}:{password}"
            return f"Added credential: {username}:{password}"
        return "Invalid format. Use: username:password"

    elif cmd == "creds":
        creds = framework.session.credentials.list()
        if not creds:
            return "No credentials configured"
        output = "Credentials:\n"
        for c in creds:
            domain = f"{c.get('domain')}/" if c.get('domain') else ""
            output += f"  • {domain}{c.get('username')}:{c.get('password', '[hash]')}\n"
        return output

    elif cmd == "stats":
        stats = await loop.run_in_executor(None, framework.get_stats)
        output = "Framework Statistics:\n\n"
        output += f"  Modules:     {stats['modules']}\n"
        output += f"  Categories:  {stats['categories']}\n"
        output += f"  Targets:     {stats['targets']}\n"
        output += f"  Credentials: {stats['credentials']}\n"
        if stats['current_module']:
            output += f"  Current:     {stats['current_module']}\n"
        return output

    elif cmd == "clear":
        return "\x1b[2J\x1b[H"  # ANSI clear screen

    elif cmd == "info":
        # Show framework info
        output = "Framework Information:\n\n"
        output += f"  Version:     2.0.0\n"
        output += f"  Modules:     {len(framework.modules)}\n"
        output += f"  Categories:  {len(framework.get_categories())}\n"
        output += f"  Database:    {framework.database.db_path}\n"
        if sessions[session_id].get("current_module"):
            output += f"\n  Current Module: {sessions[session_id]['current_module']}\n"
        return output

    else:
        return f"Unknown command: {cmd}\nType 'help' for available commands."


@app.get("/api/c2/session/{session_id}")
async def get_session(session_id: str):
    """Get session information and history"""
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    return sessions[session_id]


@app.get("/api/c2/sessions")
async def list_sessions():
    """List all active sessions"""
    return {
        "sessions": list(sessions.keys()),
        "count": len(sessions)
    }


@app.delete("/api/c2/session/{session_id}")
async def clear_session(session_id: str):
    """Clear session history"""
    if session_id in sessions:
        sessions[session_id]["history"] = []
        return {"message": f"Session {session_id} cleared"}
    raise HTTPException(status_code=404, detail="Session not found")


@app.websocket("/ws/c2/{session_id}")
async def websocket_c2(websocket: WebSocket, session_id: str):
    """WebSocket endpoint for real-time C2 communication"""
    await websocket.accept()

    # Initialize session
    if session_id not in sessions:
        sessions[session_id] = {
            "history": [],
            "created_at": datetime.now().isoformat(),
            "current_module": None,
            "current_target": None,
            "current_credential": None
        }

    try:
        await websocket.send_json({
            "type": "connected",
            "message": "Connected to PurpleSploit C2",
            "session_id": session_id
        })

        while True:
            # Receive command from client
            data = await websocket.receive_json()
            command = data.get("command", "").strip()

            if not command:
                continue

            # Execute command
            try:
                output = await execute_framework_command(command, session_id)

                # Store in history
                sessions[session_id]["history"].append({
                    "type": "command",
                    "command": command,
                    "output": output,
                    "timestamp": datetime.now().isoformat()
                })

                # Send response
                await websocket.send_json({
                    "type": "output",
                    "command": command,
                    "output": output,
                    "success": True,
                    "timestamp": datetime.now().isoformat()
                })
            except Exception as e:
                await websocket.send_json({
                    "type": "error",
                    "command": command,
                    "error": str(e),
                    "success": False,
                    "timestamp": datetime.now().isoformat()
                })

    except WebSocketDisconnect:
        print(f"Client disconnected from session {session_id}")


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
