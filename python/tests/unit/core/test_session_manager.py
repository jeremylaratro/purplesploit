"""
Tests for purplesploit.core.session_manager module.
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta
import json

from purplesploit.core.session_manager import (
    SessionManager,
    SessionInfo,
    SessionType,
    SessionState,
    SessionPrivilege,
    Route,
    PortForward,
    SessionInteraction,
    create_session_manager,
)


class TestSessionType:
    """Tests for SessionType enum."""

    def test_all_types_exist(self):
        """Test all expected session types exist."""
        expected = [
            "shell", "meterpreter", "beacon", "ssh", "winrm",
            "smb_exec", "wmi", "dcom", "ligolo", "chisel",
            "socks", "port_forward"
        ]
        for t in expected:
            assert SessionType(t) is not None


class TestSessionState:
    """Tests for SessionState enum."""

    def test_all_states_exist(self):
        """Test all expected states exist."""
        expected = ["pending", "active", "dormant", "disconnected", "closed", "error"]
        for s in expected:
            assert SessionState(s) is not None


class TestSessionPrivilege:
    """Tests for SessionPrivilege enum."""

    def test_all_privileges_exist(self):
        """Test all expected privileges exist."""
        expected = ["low", "medium", "high", "system", "domain_admin"]
        for p in expected:
            assert SessionPrivilege(p) is not None


class TestSessionInfo:
    """Tests for SessionInfo dataclass."""

    def test_basic_session(self):
        """Test creating a basic session."""
        session = SessionInfo(
            id="sess:abc123",
            session_type=SessionType.SHELL,
            target_host="192.168.1.100",
        )

        assert session.id == "sess:abc123"
        assert session.session_type == SessionType.SHELL
        assert session.target_host == "192.168.1.100"
        assert session.state == SessionState.PENDING

    def test_session_with_credentials(self):
        """Test session with username/domain."""
        session = SessionInfo(
            id="sess:test",
            session_type=SessionType.SSH,
            target_host="10.0.0.1",
            target_port=22,
            username="admin",
            domain="CORP",
            privilege=SessionPrivilege.HIGH,
        )

        assert session.username == "admin"
        assert session.domain == "CORP"
        assert session.privilege == SessionPrivilege.HIGH

    def test_session_display_name(self):
        """Test display name generation."""
        session = SessionInfo(
            id="sess:test",
            session_type=SessionType.SHELL,
            target_host="192.168.1.1",
            username="admin",
            domain="CORP",
        )

        assert "shell" in session.display_name.lower()
        assert "CORP\\admin" in session.display_name
        assert "192.168.1.1" in session.display_name

    def test_session_is_active(self):
        """Test is_active property."""
        session = SessionInfo(
            id="sess:test",
            session_type=SessionType.SHELL,
            target_host="10.0.0.1",
        )

        session.state = SessionState.ACTIVE
        assert session.is_active is True

        session.state = SessionState.DORMANT
        assert session.is_active is True

        session.state = SessionState.CLOSED
        assert session.is_active is False

    def test_session_is_elevated(self):
        """Test is_elevated property."""
        session = SessionInfo(
            id="sess:test",
            session_type=SessionType.SHELL,
            target_host="10.0.0.1",
        )

        session.privilege = SessionPrivilege.LOW
        assert session.is_elevated is False

        session.privilege = SessionPrivilege.HIGH
        assert session.is_elevated is True

        session.privilege = SessionPrivilege.SYSTEM
        assert session.is_elevated is True

        session.privilege = SessionPrivilege.DOMAIN_ADMIN
        assert session.is_elevated is True

    def test_session_to_dict(self):
        """Test converting session to dict."""
        session = SessionInfo(
            id="sess:xyz",
            session_type=SessionType.METERPRETER,
            target_host="192.168.1.50",
            username="SYSTEM",
            privilege=SessionPrivilege.SYSTEM,
            state=SessionState.ACTIVE,
        )

        data = session.to_dict()

        assert data["id"] == "sess:xyz"
        assert data["type"] == "meterpreter"
        assert data["privilege"] == "system"
        assert data["state"] == "active"

    def test_session_from_dict(self):
        """Test creating session from dict."""
        data = {
            "id": "sess:restored",
            "type": "ssh",
            "target_host": "10.0.0.5",
            "target_port": 22,
            "username": "root",
            "privilege": "high",
            "state": "active",
            "established_at": "2024-01-01T12:00:00",
        }

        session = SessionInfo.from_dict(data)

        assert session.id == "sess:restored"
        assert session.session_type == SessionType.SSH
        assert session.target_port == 22
        assert session.privilege == SessionPrivilege.HIGH


class TestRoute:
    """Tests for Route dataclass."""

    def test_basic_route(self):
        """Test creating a basic route."""
        route = Route(
            id="route:abc",
            session_id="sess:xyz",
            subnet="10.10.10.0",
            netmask="255.255.255.0",
        )

        assert route.subnet == "10.10.10.0"
        assert route.active is True

    def test_route_to_dict(self):
        """Test converting route to dict."""
        route = Route(
            id="route:test",
            session_id="sess:1",
            subnet="192.168.100.0",
        )

        data = route.to_dict()

        assert data["subnet"] == "192.168.100.0"
        assert data["session_id"] == "sess:1"


class TestPortForward:
    """Tests for PortForward dataclass."""

    def test_basic_forward(self):
        """Test creating a basic port forward."""
        forward = PortForward(
            id="fwd:abc",
            session_id="sess:xyz",
            local_port=8080,
            remote_host="192.168.1.1",
            remote_port=80,
        )

        assert forward.local_port == 8080
        assert forward.remote_port == 80
        assert forward.active is False

    def test_forward_to_dict(self):
        """Test converting forward to dict."""
        forward = PortForward(
            id="fwd:test",
            session_id=None,
            local_port=9050,
            remote_host="10.0.0.1",
            remote_port=1080,
            direction="local",
        )

        data = forward.to_dict()

        assert data["local_port"] == 9050
        assert data["direction"] == "local"


class TestSessionManagerInit:
    """Tests for SessionManager initialization."""

    def test_init_default(self):
        """Test default initialization."""
        manager = SessionManager()

        assert len(manager.sessions) == 0
        assert len(manager.routes) == 0
        assert len(manager.port_forwards) == 0

    def test_init_with_framework(self):
        """Test initialization with framework."""
        mock_framework = Mock()
        manager = SessionManager(framework=mock_framework)

        assert manager.framework == mock_framework

    def test_factory_function(self):
        """Test factory function."""
        manager = create_session_manager()

        assert isinstance(manager, SessionManager)


class TestSessionManagerSessions:
    """Tests for session management."""

    def test_create_session(self):
        """Test creating a session."""
        manager = SessionManager()

        session = manager.create_session(
            session_type=SessionType.SHELL,
            target_host="192.168.1.100",
            username="admin",
        )

        assert session.id in manager.sessions
        assert session.target_host == "192.168.1.100"
        assert session.state == SessionState.ACTIVE

    def test_create_session_string_type(self):
        """Test creating session with string type."""
        manager = SessionManager()

        session = manager.create_session(
            session_type="ssh",
            target_host="10.0.0.1",
            target_port=22,
        )

        assert session.session_type == SessionType.SSH

    def test_get_session(self):
        """Test getting session by ID."""
        manager = SessionManager()

        session = manager.create_session(
            session_type=SessionType.SHELL,
            target_host="10.0.0.1",
        )

        retrieved = manager.get_session(session.id)
        assert retrieved == session

        assert manager.get_session("nonexistent") is None

    def test_get_sessions_by_host(self):
        """Test getting sessions by host."""
        manager = SessionManager()

        manager.create_session(SessionType.SHELL, "10.0.0.1")
        manager.create_session(SessionType.SSH, "10.0.0.1")
        manager.create_session(SessionType.SHELL, "10.0.0.2")

        sessions = manager.get_sessions_by_host("10.0.0.1")
        assert len(sessions) == 2

    def test_get_sessions_by_type(self):
        """Test getting sessions by type."""
        manager = SessionManager()

        manager.create_session(SessionType.SHELL, "10.0.0.1")
        manager.create_session(SessionType.SSH, "10.0.0.2")
        manager.create_session(SessionType.SHELL, "10.0.0.3")

        shell_sessions = manager.get_sessions_by_type(SessionType.SHELL)
        assert len(shell_sessions) == 2

    def test_get_active_sessions(self):
        """Test getting active sessions."""
        manager = SessionManager()

        session1 = manager.create_session(SessionType.SHELL, "10.0.0.1")
        session2 = manager.create_session(SessionType.SSH, "10.0.0.2")

        # Close one session
        manager.close_session(session1.id)

        active = manager.get_active_sessions()
        assert len(active) == 1
        assert active[0].id == session2.id

    def test_get_elevated_sessions(self):
        """Test getting elevated sessions."""
        manager = SessionManager()

        manager.create_session(
            SessionType.SHELL, "10.0.0.1",
            privilege=SessionPrivilege.LOW
        )
        manager.create_session(
            SessionType.SHELL, "10.0.0.2",
            privilege=SessionPrivilege.SYSTEM
        )
        manager.create_session(
            SessionType.SSH, "10.0.0.3",
            privilege=SessionPrivilege.HIGH
        )

        elevated = manager.get_elevated_sessions()
        assert len(elevated) == 2


class TestSessionManagerSelection:
    """Tests for session selection."""

    def test_select_session(self):
        """Test selecting a session."""
        manager = SessionManager()

        session = manager.create_session(SessionType.SHELL, "10.0.0.1")

        assert manager.current_session is None

        result = manager.select_session(session.id)
        assert result is True
        assert manager.current_session == session

    def test_select_nonexistent(self):
        """Test selecting nonexistent session."""
        manager = SessionManager()

        result = manager.select_session("nonexistent")
        assert result is False


class TestSessionManagerLifecycle:
    """Tests for session lifecycle."""

    def test_close_session(self):
        """Test closing a session."""
        manager = SessionManager()

        session = manager.create_session(SessionType.SHELL, "10.0.0.1")
        manager.select_session(session.id)

        result = manager.close_session(session.id)

        assert result is True
        assert session.state == SessionState.CLOSED
        assert manager.current_session is None

    def test_update_session(self):
        """Test updating session properties."""
        manager = SessionManager()

        session = manager.create_session(SessionType.SHELL, "10.0.0.1")

        result = manager.update_session(
            session.id,
            state=SessionState.DORMANT,
            privilege=SessionPrivilege.HIGH,
        )

        assert result is True
        assert session.state == SessionState.DORMANT
        assert session.privilege == SessionPrivilege.HIGH

    def test_checkin(self):
        """Test session checkin."""
        manager = SessionManager()

        session = manager.create_session(SessionType.BEACON, "10.0.0.1")
        session.state = SessionState.DORMANT

        result = manager.checkin(session.id)

        assert result is True
        assert session.last_checkin is not None
        assert session.state == SessionState.ACTIVE

    def test_callback_on_session_opened(self):
        """Test callback when session opens."""
        manager = SessionManager()
        callback = Mock()
        manager.on_session_opened = callback

        session = manager.create_session(SessionType.SHELL, "10.0.0.1")

        callback.assert_called_once_with(session)

    def test_callback_on_session_closed(self):
        """Test callback when session closes."""
        manager = SessionManager()
        callback = Mock()
        manager.on_session_closed = callback

        session = manager.create_session(SessionType.SHELL, "10.0.0.1")
        manager.close_session(session.id)

        callback.assert_called_once()


class TestSessionManagerTags:
    """Tests for session tagging."""

    def test_add_tag(self):
        """Test adding a tag."""
        manager = SessionManager()

        session = manager.create_session(SessionType.SHELL, "10.0.0.1")
        result = manager.add_tag(session.id, "dc")

        assert result is True
        assert "dc" in session.tags

    def test_remove_tag(self):
        """Test removing a tag."""
        manager = SessionManager()

        session = manager.create_session(SessionType.SHELL, "10.0.0.1")
        manager.add_tag(session.id, "dc")
        result = manager.remove_tag(session.id, "dc")

        assert result is True
        assert "dc" not in session.tags

    def test_get_sessions_by_tag(self):
        """Test getting sessions by tag."""
        manager = SessionManager()

        session1 = manager.create_session(SessionType.SHELL, "10.0.0.1")
        session2 = manager.create_session(SessionType.SHELL, "10.0.0.2")

        manager.add_tag(session1.id, "important")
        manager.add_tag(session2.id, "important")
        manager.add_tag(session2.id, "dc")

        important = manager.get_sessions_by_tag("important")
        assert len(important) == 2

        dc = manager.get_sessions_by_tag("dc")
        assert len(dc) == 1


class TestSessionManagerRouting:
    """Tests for routing management."""

    def test_add_route(self):
        """Test adding a route."""
        manager = SessionManager()

        session = manager.create_session(SessionType.SHELL, "10.0.0.1")
        session.state = SessionState.ACTIVE

        route = manager.add_route(session.id, "192.168.100.0")

        assert route is not None
        assert route.subnet == "192.168.100.0"
        assert route.id in manager.routes

    def test_add_route_inactive_session(self):
        """Test adding route to inactive session fails."""
        manager = SessionManager()

        session = manager.create_session(SessionType.SHELL, "10.0.0.1")
        session.state = SessionState.CLOSED

        route = manager.add_route(session.id, "192.168.100.0")
        assert route is None

    def test_remove_route(self):
        """Test removing a route."""
        manager = SessionManager()

        session = manager.create_session(SessionType.SHELL, "10.0.0.1")
        route = manager.add_route(session.id, "192.168.100.0")

        result = manager.remove_route(route.id)
        assert result is True
        assert route.id not in manager.routes

    def test_get_routes_for_session(self):
        """Test getting routes for a session."""
        manager = SessionManager()

        session = manager.create_session(SessionType.SHELL, "10.0.0.1")
        manager.add_route(session.id, "192.168.100.0")
        manager.add_route(session.id, "192.168.200.0")

        routes = manager.get_routes_for_session(session.id)
        assert len(routes) == 2

    def test_get_route_for_target(self):
        """Test finding route for a target."""
        manager = SessionManager()

        session = manager.create_session(SessionType.SHELL, "10.0.0.1")
        manager.add_route(session.id, "192.168.100.0", "255.255.255.0")

        route = manager.get_route_for_target("192.168.100.50")
        assert route is not None
        assert route.subnet == "192.168.100.0"

        route = manager.get_route_for_target("10.10.10.1")
        assert route is None


class TestSessionManagerPortForwarding:
    """Tests for port forwarding."""

    def test_create_port_forward(self):
        """Test creating a port forward."""
        manager = SessionManager()

        forward = manager.create_port_forward(
            local_port=8080,
            remote_host="192.168.1.1",
            remote_port=80,
        )

        assert forward is not None
        assert forward.id in manager.port_forwards
        assert forward.local_port == 8080

    def test_start_port_forward(self):
        """Test starting a port forward."""
        manager = SessionManager()

        forward = manager.create_port_forward(8080, "192.168.1.1", 80)
        result = manager.start_port_forward(forward.id)

        assert result is True
        assert forward.active is True

    def test_stop_port_forward(self):
        """Test stopping a port forward."""
        manager = SessionManager()

        forward = manager.create_port_forward(8080, "192.168.1.1", 80)
        manager.start_port_forward(forward.id)
        result = manager.stop_port_forward(forward.id)

        assert result is True
        assert forward.active is False

    def test_remove_port_forward(self):
        """Test removing a port forward."""
        manager = SessionManager()

        forward = manager.create_port_forward(8080, "192.168.1.1", 80)
        result = manager.remove_port_forward(forward.id)

        assert result is True
        assert forward.id not in manager.port_forwards


class TestSessionManagerStatistics:
    """Tests for statistics."""

    def test_get_statistics(self):
        """Test getting statistics."""
        manager = SessionManager()

        session1 = manager.create_session(SessionType.SHELL, "10.0.0.1")
        session2 = manager.create_session(
            SessionType.SSH, "10.0.0.2",
            privilege=SessionPrivilege.HIGH
        )
        manager.close_session(session1.id)

        manager.add_route(session2.id, "192.168.100.0")
        manager.create_port_forward(8080, "10.0.0.1", 80)

        stats = manager.get_statistics()

        assert stats["total_sessions"] == 2
        assert stats["active_sessions"] == 1
        assert stats["elevated_sessions"] == 1
        assert stats["total_routes"] == 1


class TestSessionManagerExport:
    """Tests for export functionality."""

    def test_to_dict(self):
        """Test exporting to dict."""
        manager = SessionManager()

        manager.create_session(SessionType.SHELL, "10.0.0.1")

        data = manager.to_dict()

        assert "sessions" in data
        assert "routes" in data
        assert "port_forwards" in data
        assert "statistics" in data
        assert len(data["sessions"]) == 1

    def test_to_json(self):
        """Test exporting to JSON."""
        manager = SessionManager()

        manager.create_session(SessionType.SHELL, "10.0.0.1")

        json_str = manager.to_json()
        data = json.loads(json_str)

        assert "sessions" in data
        assert len(data["sessions"]) == 1


class TestSessionManagerClear:
    """Tests for clearing."""

    def test_clear(self):
        """Test clearing all sessions."""
        manager = SessionManager()

        session = manager.create_session(SessionType.SHELL, "10.0.0.1")
        manager.add_route(session.id, "192.168.100.0")
        manager.create_port_forward(8080, "10.0.0.1", 80)

        manager.clear()

        assert len(manager.sessions) == 0
        assert len(manager.routes) == 0
        assert len(manager.port_forwards) == 0


class TestSessionInteraction:
    """Tests for SessionInteraction helper."""

    def test_init(self):
        """Test initialization."""
        session = SessionInfo(
            id="sess:test",
            session_type=SessionType.SHELL,
            target_host="10.0.0.1",
        )

        interaction = SessionInteraction(session)

        assert interaction.session == session
        assert len(interaction.command_history) == 0

    def test_execute(self):
        """Test command execution."""
        session = SessionInfo(
            id="sess:test",
            session_type=SessionType.SHELL,
            target_host="10.0.0.1",
        )

        interaction = SessionInteraction(session)
        result = interaction.execute("whoami")

        assert result["command"] == "whoami"
        assert "output" in result
        assert len(interaction.command_history) == 1

    def test_get_system_info(self):
        """Test getting system info."""
        session = SessionInfo(
            id="sess:test",
            session_type=SessionType.SHELL,
            target_host="10.0.0.1",
            username="admin",
            os="Windows 10",
        )

        interaction = SessionInteraction(session)
        info = interaction.get_system_info()

        assert info["hostname"] == "10.0.0.1"
        assert info["os"] == "Windows 10"
        assert info["username"] == "admin"
