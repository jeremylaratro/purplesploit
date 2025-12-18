"""
Session and Shell Management Module.

Provides centralized management of remote shells, sessions, and pivoting
capabilities for maintaining access during penetration tests.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable
from datetime import datetime
import uuid
import threading
import time
import hashlib
import subprocess
import os


class SessionType(Enum):
    """Types of sessions/shells."""
    SHELL = "shell"           # Basic command shell
    METERPRETER = "meterpreter"  # Metasploit meterpreter
    BEACON = "beacon"         # C2 beacon (Cobalt Strike, etc.)
    SSH = "ssh"               # SSH session
    WINRM = "winrm"           # WinRM session
    SMB_EXEC = "smb_exec"     # SMB execution (psexec, etc.)
    WMI = "wmi"               # WMI execution
    DCOM = "dcom"             # DCOM execution
    LIGOLO = "ligolo"         # Ligolo-ng tunnel
    CHISEL = "chisel"         # Chisel tunnel
    SOCKS = "socks"           # SOCKS proxy
    PORT_FORWARD = "port_forward"  # Port forwarding


class SessionState(Enum):
    """State of a session."""
    PENDING = "pending"       # Being established
    ACTIVE = "active"         # Currently active
    DORMANT = "dormant"       # Sleeping/checkin interval
    DISCONNECTED = "disconnected"  # Lost connection
    CLOSED = "closed"         # Intentionally closed
    ERROR = "error"           # Error state


class SessionPrivilege(Enum):
    """Privilege level of session."""
    LOW = "low"               # Standard user
    MEDIUM = "medium"         # Elevated user
    HIGH = "high"             # Administrator/root
    SYSTEM = "system"         # SYSTEM/root
    DOMAIN_ADMIN = "domain_admin"  # Domain Administrator


@dataclass
class SessionInfo:
    """Information about a session."""
    id: str
    session_type: SessionType
    target_host: str
    target_port: int | None = None
    username: str | None = None
    domain: str | None = None
    privilege: SessionPrivilege = SessionPrivilege.LOW
    state: SessionState = SessionState.PENDING
    os: str | None = None
    arch: str | None = None
    process_name: str | None = None
    process_id: int | None = None
    established_at: datetime = field(default_factory=datetime.now)
    last_checkin: datetime | None = None
    checkin_interval: int = 0  # seconds, 0 = interactive
    local_port: int | None = None  # For tunnels/proxies
    remote_port: int | None = None
    notes: str = ""
    tags: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "type": self.session_type.value,
            "target_host": self.target_host,
            "target_port": self.target_port,
            "username": self.username,
            "domain": self.domain,
            "privilege": self.privilege.value,
            "state": self.state.value,
            "os": self.os,
            "arch": self.arch,
            "process_name": self.process_name,
            "process_id": self.process_id,
            "established_at": self.established_at.isoformat(),
            "last_checkin": self.last_checkin.isoformat() if self.last_checkin else None,
            "checkin_interval": self.checkin_interval,
            "local_port": self.local_port,
            "remote_port": self.remote_port,
            "notes": self.notes,
            "tags": self.tags,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SessionInfo":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            session_type=SessionType(data["type"]),
            target_host=data["target_host"],
            target_port=data.get("target_port"),
            username=data.get("username"),
            domain=data.get("domain"),
            privilege=SessionPrivilege(data.get("privilege", "low")),
            state=SessionState(data.get("state", "pending")),
            os=data.get("os"),
            arch=data.get("arch"),
            process_name=data.get("process_name"),
            process_id=data.get("process_id"),
            established_at=datetime.fromisoformat(data["established_at"]) if "established_at" in data else datetime.now(),
            last_checkin=datetime.fromisoformat(data["last_checkin"]) if data.get("last_checkin") else None,
            checkin_interval=data.get("checkin_interval", 0),
            local_port=data.get("local_port"),
            remote_port=data.get("remote_port"),
            notes=data.get("notes", ""),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
        )

    @property
    def display_name(self) -> str:
        """Get display name for session."""
        parts = [self.session_type.value]
        if self.username:
            if self.domain:
                parts.append(f"{self.domain}\\{self.username}")
            else:
                parts.append(self.username)
        parts.append(f"@{self.target_host}")
        return " ".join(parts)

    @property
    def is_active(self) -> bool:
        """Check if session is active."""
        return self.state in [SessionState.ACTIVE, SessionState.DORMANT]

    @property
    def is_elevated(self) -> bool:
        """Check if session is elevated."""
        return self.privilege in [
            SessionPrivilege.HIGH,
            SessionPrivilege.SYSTEM,
            SessionPrivilege.DOMAIN_ADMIN
        ]


@dataclass
class Route:
    """Network route through a session."""
    id: str
    session_id: str
    subnet: str
    netmask: str = "255.255.255.0"
    gateway: str | None = None
    active: bool = True
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "session_id": self.session_id,
            "subnet": self.subnet,
            "netmask": self.netmask,
            "gateway": self.gateway,
            "active": self.active,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class PortForward:
    """Port forwarding configuration."""
    id: str
    session_id: str | None
    local_host: str = "127.0.0.1"
    local_port: int = 0
    remote_host: str = ""
    remote_port: int = 0
    direction: str = "local"  # "local" or "remote"
    active: bool = False
    process: Any = None
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "session_id": self.session_id,
            "local_host": self.local_host,
            "local_port": self.local_port,
            "remote_host": self.remote_host,
            "remote_port": self.remote_port,
            "direction": self.direction,
            "active": self.active,
            "created_at": self.created_at.isoformat(),
        }


class SessionManager:
    """
    Centralized session and shell management.

    Features:
    - Track multiple sessions across targets
    - Manage pivoting and routing
    - Port forwarding management
    - Session health monitoring
    - Auto-reconnection for lost sessions
    """

    def __init__(self, framework=None):
        """
        Initialize session manager.

        Args:
            framework: Reference to PurpleSploit framework
        """
        self.framework = framework
        self.sessions: dict[str, SessionInfo] = {}
        self.routes: dict[str, Route] = {}
        self.port_forwards: dict[str, PortForward] = {}
        self._current_session_id: str | None = None

        # Callbacks
        self.on_session_opened: Callable[[SessionInfo], None] | None = None
        self.on_session_closed: Callable[[SessionInfo], None] | None = None
        self.on_session_lost: Callable[[SessionInfo], None] | None = None
        self.on_privilege_change: Callable[[SessionInfo], None] | None = None

        # Monitoring
        self._monitor_thread: threading.Thread | None = None
        self._monitor_running: bool = False

    def _generate_id(self, prefix: str = "sess") -> str:
        """Generate unique session ID."""
        return f"{prefix}:{uuid.uuid4().hex[:8]}"

    def create_session(
        self,
        session_type: SessionType | str,
        target_host: str,
        target_port: int | None = None,
        username: str | None = None,
        domain: str | None = None,
        privilege: SessionPrivilege | str = SessionPrivilege.LOW,
        os: str | None = None,
        arch: str | None = None,
        **kwargs,
    ) -> SessionInfo:
        """
        Create a new session.

        Args:
            session_type: Type of session
            target_host: Target hostname/IP
            target_port: Target port
            username: Username for session
            domain: Domain name
            privilege: Privilege level
            os: Operating system
            arch: Architecture
            **kwargs: Additional session properties

        Returns:
            Created SessionInfo
        """
        if isinstance(session_type, str):
            session_type = SessionType(session_type.lower())
        if isinstance(privilege, str):
            privilege = SessionPrivilege(privilege.lower())

        session_id = self._generate_id()

        session = SessionInfo(
            id=session_id,
            session_type=session_type,
            target_host=target_host,
            target_port=target_port,
            username=username,
            domain=domain,
            privilege=privilege,
            state=SessionState.ACTIVE,
            os=os,
            arch=arch,
            **kwargs,
        )

        self.sessions[session_id] = session

        if self.on_session_opened:
            self.on_session_opened(session)

        return session

    def get_session(self, session_id: str) -> SessionInfo | None:
        """Get session by ID."""
        return self.sessions.get(session_id)

    def get_sessions_by_host(self, host: str) -> list[SessionInfo]:
        """Get all sessions for a host."""
        return [s for s in self.sessions.values() if s.target_host == host]

    def get_sessions_by_type(self, session_type: SessionType) -> list[SessionInfo]:
        """Get all sessions of a type."""
        return [s for s in self.sessions.values() if s.session_type == session_type]

    def get_active_sessions(self) -> list[SessionInfo]:
        """Get all active sessions."""
        return [s for s in self.sessions.values() if s.is_active]

    def get_elevated_sessions(self) -> list[SessionInfo]:
        """Get all elevated sessions."""
        return [s for s in self.sessions.values() if s.is_elevated and s.is_active]

    @property
    def current_session(self) -> SessionInfo | None:
        """Get currently selected session."""
        if self._current_session_id:
            return self.sessions.get(self._current_session_id)
        return None

    def select_session(self, session_id: str) -> bool:
        """Select a session as current."""
        if session_id in self.sessions:
            self._current_session_id = session_id
            return True
        return False

    def close_session(self, session_id: str) -> bool:
        """Close a session."""
        session = self.sessions.get(session_id)
        if not session:
            return False

        session.state = SessionState.CLOSED

        if self._current_session_id == session_id:
            self._current_session_id = None

        if self.on_session_closed:
            self.on_session_closed(session)

        return True

    def update_session(
        self,
        session_id: str,
        state: SessionState | None = None,
        privilege: SessionPrivilege | None = None,
        **kwargs,
    ) -> bool:
        """Update session properties."""
        session = self.sessions.get(session_id)
        if not session:
            return False

        old_privilege = session.privilege

        if state:
            session.state = state
        if privilege:
            session.privilege = privilege

        for key, value in kwargs.items():
            if hasattr(session, key):
                setattr(session, key, value)

        if privilege and privilege != old_privilege and self.on_privilege_change:
            self.on_privilege_change(session)

        return True

    def checkin(self, session_id: str) -> bool:
        """Record a session checkin."""
        session = self.sessions.get(session_id)
        if not session:
            return False

        session.last_checkin = datetime.now()
        if session.state == SessionState.DORMANT:
            session.state = SessionState.ACTIVE

        return True

    def add_tag(self, session_id: str, tag: str) -> bool:
        """Add tag to session."""
        session = self.sessions.get(session_id)
        if not session:
            return False

        if tag not in session.tags:
            session.tags.append(tag)
        return True

    def remove_tag(self, session_id: str, tag: str) -> bool:
        """Remove tag from session."""
        session = self.sessions.get(session_id)
        if not session:
            return False

        if tag in session.tags:
            session.tags.remove(tag)
        return True

    def get_sessions_by_tag(self, tag: str) -> list[SessionInfo]:
        """Get sessions with specific tag."""
        return [s for s in self.sessions.values() if tag in s.tags]

    # =========================================================================
    # Routing and Pivoting
    # =========================================================================

    def add_route(
        self,
        session_id: str,
        subnet: str,
        netmask: str = "255.255.255.0",
        gateway: str | None = None,
    ) -> Route | None:
        """Add a route through a session."""
        session = self.sessions.get(session_id)
        if not session or not session.is_active:
            return None

        route_id = self._generate_id("route")
        route = Route(
            id=route_id,
            session_id=session_id,
            subnet=subnet,
            netmask=netmask,
            gateway=gateway,
        )

        self.routes[route_id] = route
        return route

    def remove_route(self, route_id: str) -> bool:
        """Remove a route."""
        if route_id in self.routes:
            del self.routes[route_id]
            return True
        return False

    def get_routes_for_session(self, session_id: str) -> list[Route]:
        """Get all routes through a session."""
        return [r for r in self.routes.values() if r.session_id == session_id]

    def get_route_for_target(self, target: str) -> Route | None:
        """Find a route that can reach a target."""
        import ipaddress

        try:
            target_ip = ipaddress.ip_address(target)
        except ValueError:
            return None

        for route in self.routes.values():
            if not route.active:
                continue

            try:
                network = ipaddress.ip_network(f"{route.subnet}/{route.netmask}", strict=False)
                if target_ip in network:
                    return route
            except ValueError:
                continue

        return None

    # =========================================================================
    # Port Forwarding
    # =========================================================================

    def create_port_forward(
        self,
        local_port: int,
        remote_host: str,
        remote_port: int,
        session_id: str | None = None,
        local_host: str = "127.0.0.1",
        direction: str = "local",
    ) -> PortForward:
        """Create a port forward."""
        forward_id = self._generate_id("fwd")

        forward = PortForward(
            id=forward_id,
            session_id=session_id,
            local_host=local_host,
            local_port=local_port,
            remote_host=remote_host,
            remote_port=remote_port,
            direction=direction,
        )

        self.port_forwards[forward_id] = forward
        return forward

    def start_port_forward(self, forward_id: str) -> bool:
        """Start a port forward."""
        forward = self.port_forwards.get(forward_id)
        if not forward:
            return False

        # In a real implementation, this would start the actual forwarding
        forward.active = True
        return True

    def stop_port_forward(self, forward_id: str) -> bool:
        """Stop a port forward."""
        forward = self.port_forwards.get(forward_id)
        if not forward:
            return False

        forward.active = False
        if forward.process:
            try:
                forward.process.terminate()
            except Exception:
                pass
            forward.process = None

        return True

    def remove_port_forward(self, forward_id: str) -> bool:
        """Remove a port forward."""
        self.stop_port_forward(forward_id)
        if forward_id in self.port_forwards:
            del self.port_forwards[forward_id]
            return True
        return False

    # =========================================================================
    # Session Monitoring
    # =========================================================================

    def start_monitoring(self, interval: int = 30):
        """Start session health monitoring."""
        if self._monitor_running:
            return

        self._monitor_running = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval,),
            daemon=True,
        )
        self._monitor_thread.start()

    def stop_monitoring(self):
        """Stop session health monitoring."""
        self._monitor_running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
            self._monitor_thread = None

    def _monitor_loop(self, interval: int):
        """Monitor loop for checking session health."""
        while self._monitor_running:
            for session in list(self.sessions.values()):
                if session.state == SessionState.ACTIVE:
                    if session.checkin_interval > 0 and session.last_checkin:
                        elapsed = (datetime.now() - session.last_checkin).total_seconds()
                        if elapsed > session.checkin_interval * 2:
                            session.state = SessionState.DISCONNECTED
                            if self.on_session_lost:
                                self.on_session_lost(session)

            time.sleep(interval)

    # =========================================================================
    # Statistics and Export
    # =========================================================================

    def get_statistics(self) -> dict:
        """Get session statistics."""
        active = [s for s in self.sessions.values() if s.is_active]
        elevated = [s for s in active if s.is_elevated]

        by_type = {}
        for session in self.sessions.values():
            t = session.session_type.value
            by_type[t] = by_type.get(t, 0) + 1

        by_host = {}
        for session in self.sessions.values():
            h = session.target_host
            by_host[h] = by_host.get(h, 0) + 1

        return {
            "total_sessions": len(self.sessions),
            "active_sessions": len(active),
            "elevated_sessions": len(elevated),
            "total_routes": len(self.routes),
            "active_routes": len([r for r in self.routes.values() if r.active]),
            "port_forwards": len(self.port_forwards),
            "active_forwards": len([f for f in self.port_forwards.values() if f.active]),
            "by_type": by_type,
            "by_host": by_host,
        }

    def to_dict(self) -> dict:
        """Export all sessions to dict."""
        return {
            "sessions": [s.to_dict() for s in self.sessions.values()],
            "routes": [r.to_dict() for r in self.routes.values()],
            "port_forwards": [f.to_dict() for f in self.port_forwards.values()],
            "current_session": self._current_session_id,
            "statistics": self.get_statistics(),
        }

    def to_json(self, indent: int | None = 2) -> str:
        """Export to JSON string."""
        import json
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def clear(self):
        """Clear all sessions."""
        # Close all active port forwards
        for fwd_id in list(self.port_forwards.keys()):
            self.stop_port_forward(fwd_id)

        self.sessions.clear()
        self.routes.clear()
        self.port_forwards.clear()
        self._current_session_id = None


class SessionInteraction:
    """
    Helper class for interacting with sessions.

    Provides common operations like command execution,
    file transfer, etc.
    """

    def __init__(self, session: SessionInfo, framework=None):
        """Initialize interaction helper."""
        self.session = session
        self.framework = framework
        self.command_history: list[dict] = []

    def execute(self, command: str, timeout: int = 30) -> dict:
        """
        Execute command in session.

        Args:
            command: Command to execute
            timeout: Timeout in seconds

        Returns:
            Dict with output, error, return_code
        """
        result = {
            "command": command,
            "output": "",
            "error": "",
            "return_code": -1,
            "timestamp": datetime.now().isoformat(),
        }

        # This would integrate with actual session handlers
        # For now, simulate for testing
        if self.session.session_type == SessionType.SHELL:
            result["output"] = f"[simulated] Would execute: {command}"
            result["return_code"] = 0
        else:
            result["error"] = f"Command execution not supported for {self.session.session_type.value}"

        self.command_history.append(result)
        return result

    def upload(self, local_path: str, remote_path: str) -> bool:
        """Upload file to session."""
        # Placeholder for actual implementation
        return False

    def download(self, remote_path: str, local_path: str) -> bool:
        """Download file from session."""
        # Placeholder for actual implementation
        return False

    def screenshot(self) -> bytes | None:
        """Take screenshot (if supported)."""
        # Placeholder for actual implementation
        return None

    def keylog_start(self) -> bool:
        """Start keylogger (if supported)."""
        # Placeholder for actual implementation
        return False

    def keylog_dump(self) -> str:
        """Dump keylogger output."""
        # Placeholder for actual implementation
        return ""

    def hashdump(self) -> list[dict]:
        """Dump password hashes (if elevated)."""
        if not self.session.is_elevated:
            return []
        # Placeholder for actual implementation
        return []

    def get_system_info(self) -> dict:
        """Get system information."""
        # Placeholder - would query session
        return {
            "hostname": self.session.target_host,
            "os": self.session.os,
            "arch": self.session.arch,
            "username": self.session.username,
            "domain": self.session.domain,
            "privilege": self.session.privilege.value,
        }


def create_session_manager(framework=None) -> SessionManager:
    """Factory function to create session manager."""
    return SessionManager(framework)
