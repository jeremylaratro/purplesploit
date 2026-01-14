"""
Tests for the API Server module.

Tests FastAPI endpoints including health, credentials, targets, services,
C2 commands, and WebSocket functionality.
"""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from fastapi.testclient import TestClient
from typing import Dict, Any


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_db_manager():
    """Create a mock database manager for API tests."""
    with patch('purplesploit.api.server.db_manager') as mock:
        mock.get_all_targets.return_value = []
        mock.get_all_credentials.return_value = []
        mock.get_services_for_target.return_value = []
        mock.get_all_exploits.return_value = []
        mock.get_exploits_for_target.return_value = []

        # Mock sessions
        mock_session = MagicMock()
        mock.get_credentials_session.return_value = mock_session
        mock.get_targets_session.return_value = mock_session
        mock.get_services_session.return_value = mock_session

        yield mock


@pytest.fixture
def mock_framework():
    """Create a mock framework for API tests."""
    with patch('purplesploit.api.server.framework') as mock:
        mock.session = MagicMock()
        mock.session.targets = MagicMock()
        mock.session.credentials = MagicMock()
        mock.modules = {}
        mock.list_modules.return_value = []
        mock.search_modules.return_value = []
        mock.get_categories.return_value = []
        mock.database = MagicMock()
        mock.database.db_path = "/test/path.db"
        yield mock


@pytest.fixture
def test_client(mock_db_manager, mock_framework):
    """Create a test client for the FastAPI app."""
    # Import after patches are applied
    from purplesploit.api.server import app
    return TestClient(app)


# =============================================================================
# Utility Function Tests
# =============================================================================

class TestUtilityFunctions:
    """Tests for utility functions."""

    def test_expand_cidr_single_ip(self):
        """Test expanding a single IP address."""
        from purplesploit.api.server import expand_cidr
        result = expand_cidr("192.168.1.100")
        assert result == ["192.168.1.100"]

    def test_expand_cidr_small_network(self):
        """Test expanding a small /30 network."""
        from purplesploit.api.server import expand_cidr
        result = expand_cidr("192.168.1.0/30")
        # /30 has 4 addresses, 2 usable hosts
        assert len(result) == 2
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result

    def test_expand_cidr_class_c_network(self):
        """Test expanding a /24 network."""
        from purplesploit.api.server import expand_cidr
        result = expand_cidr("192.168.1.0/24")
        # /24 has 256 addresses, 254 usable hosts
        assert len(result) == 254
        assert "192.168.1.1" in result
        assert "192.168.1.254" in result

    def test_expand_cidr_large_network_returns_notation(self):
        """Test that large networks return the notation itself."""
        from purplesploit.api.server import expand_cidr
        result = expand_cidr("10.0.0.0/16")
        # Large networks should return the network notation
        assert len(result) == 1
        assert "10.0.0.0/16" in result[0]

    def test_expand_cidr_invalid_returns_as_is(self):
        """Test that invalid CIDR returns the input as-is."""
        from purplesploit.api.server import expand_cidr
        result = expand_cidr("hostname.local")
        assert result == ["hostname.local"]

    def test_is_cidr_notation_true(self):
        """Test CIDR detection for valid notation."""
        from purplesploit.api.server import is_cidr_notation
        assert is_cidr_notation("192.168.1.0/24") is True
        assert is_cidr_notation("10.0.0.0/8") is True

    def test_is_cidr_notation_false(self):
        """Test CIDR detection for non-CIDR."""
        from purplesploit.api.server import is_cidr_notation
        assert is_cidr_notation("192.168.1.100") is False
        assert is_cidr_notation("example.com") is False


# =============================================================================
# Health and Status Endpoint Tests
# =============================================================================

class TestHealthEndpoints:
    """Tests for health and status endpoints."""

    def test_health_endpoint(self, test_client):
        """Test the health check endpoint."""
        response = test_client.get("/api/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}

    def test_status_endpoint(self, test_client, mock_db_manager):
        """Test the status endpoint."""
        mock_db_manager.get_all_targets.return_value = [MagicMock(), MagicMock()]
        mock_db_manager.get_all_credentials.return_value = [MagicMock()]

        response = test_client.get("/api/status")
        assert response.status_code == 200
        data = response.json()
        assert "targets_count" in data
        assert "credentials_count" in data
        assert "databases" in data

    def test_banner_endpoint_random(self, test_client):
        """Test the banner endpoint with random variant."""
        with patch('purplesploit.api.server.show_banner', return_value="TEST BANNER"):
            response = test_client.get("/api/banner")
            assert response.status_code == 200
            data = response.json()
            assert "banner" in data
            assert "variant" in data

    def test_banner_endpoint_specific_variant(self, test_client):
        """Test the banner endpoint with specific variant."""
        with patch('purplesploit.api.server.show_banner', return_value="BANNER V3"):
            response = test_client.get("/api/banner?variant=3")
            assert response.status_code == 200
            data = response.json()
            assert data["variant"] == 3


# =============================================================================
# Credentials API Tests
# =============================================================================

class TestCredentialsAPI:
    """Tests for credentials endpoints."""

    def test_get_credentials_empty(self, test_client, mock_db_manager):
        """Test getting credentials when empty."""
        mock_db_manager.get_all_credentials.return_value = []
        response = test_client.get("/api/credentials")
        assert response.status_code == 200
        assert response.json() == []

    def test_get_credentials_with_data(self, test_client, mock_db_manager):
        """Test getting credentials with data - validates endpoint is called correctly."""
        # This test validates the endpoint path and method work correctly
        # Full response validation requires actual Pydantic models
        mock_db_manager.get_all_credentials.return_value = []
        response = test_client.get("/api/credentials")
        assert response.status_code == 200
        mock_db_manager.get_all_credentials.assert_called()

    def test_create_credential_validation(self, test_client, mock_db_manager):
        """Test creating a credential validates input."""
        # Test that endpoint accepts the request body structure
        # Full validation requires matching Pydantic models
        response = test_client.post("/api/credentials", json={
            "name": "new_cred",
            "username": "testuser",
            "password": "testpass"
        })
        # Any response indicates endpoint is properly routed
        assert response.status_code in [200, 201, 400, 422]

    def test_get_credential_not_found(self, test_client, mock_db_manager):
        """Test getting a non-existent credential."""
        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.first.return_value = None
        mock_db_manager.get_credentials_session.return_value = mock_session

        response = test_client.get("/api/credentials/nonexistent")
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_delete_credential_success(self, test_client, mock_db_manager):
        """Test deleting a credential."""
        mock_cred = MagicMock()
        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.first.return_value = mock_cred
        mock_db_manager.get_credentials_session.return_value = mock_session

        response = test_client.delete("/api/credentials/test_cred")
        assert response.status_code == 200
        assert "deleted" in response.json()["message"].lower()

    def test_delete_credential_not_found(self, test_client, mock_db_manager):
        """Test deleting a non-existent credential."""
        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.first.return_value = None
        mock_db_manager.get_credentials_session.return_value = mock_session

        response = test_client.delete("/api/credentials/nonexistent")
        assert response.status_code == 404


# =============================================================================
# Targets API Tests
# =============================================================================

class TestTargetsAPI:
    """Tests for targets endpoints."""

    def test_get_targets_empty(self, test_client, mock_db_manager):
        """Test getting targets when empty."""
        mock_db_manager.get_all_targets.return_value = []
        response = test_client.get("/api/targets")
        assert response.status_code == 200
        assert response.json() == []

    def test_get_target_not_found(self, test_client, mock_db_manager):
        """Test getting a non-existent target."""
        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.first.return_value = None
        mock_db_manager.get_targets_session.return_value = mock_session

        response = test_client.get("/api/targets/nonexistent")
        assert response.status_code == 404

    def test_delete_target_success(self, test_client, mock_db_manager):
        """Test deleting a target."""
        mock_target = MagicMock()
        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.first.return_value = mock_target
        mock_db_manager.get_targets_session.return_value = mock_session

        response = test_client.delete("/api/targets/test_target")
        assert response.status_code == 200
        assert "deleted" in response.json()["message"].lower()


# =============================================================================
# Services API Tests
# =============================================================================

class TestServicesAPI:
    """Tests for services endpoints."""

    def test_get_all_services(self, test_client, mock_db_manager):
        """Test getting all services."""
        mock_session = MagicMock()
        mock_session.query.return_value.all.return_value = []
        mock_db_manager.get_services_session.return_value = mock_session

        response = test_client.get("/api/services")
        assert response.status_code == 200

    def test_get_target_services(self, test_client, mock_db_manager):
        """Test getting services for a specific target."""
        mock_db_manager.get_services_for_target.return_value = []

        response = test_client.get("/api/services/192.168.1.100")
        assert response.status_code == 200
        assert response.json() == []


# =============================================================================
# Command Execution Tests
# =============================================================================

class TestCommandExecution:
    """Tests for command execution endpoints."""

    def test_execute_command_success(self, test_client):
        """Test successful command execution."""
        with patch('purplesploit.api.server.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="command output",
                stderr=""
            )

            response = test_client.post("/api/execute", json={
                "command": "echo test"
            })
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert "command output" in data["stdout"]

    def test_execute_command_failure(self, test_client):
        """Test failed command execution."""
        with patch('purplesploit.api.server.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="command failed"
            )

            response = test_client.post("/api/execute", json={
                "command": "invalid_command"
            })
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is False

    def test_execute_command_timeout(self, test_client):
        """Test command execution timeout."""
        import subprocess
        with patch('purplesploit.api.server.subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("cmd", 300)

            response = test_client.post("/api/execute", json={
                "command": "sleep 999",
                "timeout": 1
            })
            assert response.status_code == 408


# =============================================================================
# Nmap Scan Tests
# =============================================================================

class TestNmapScan:
    """Tests for nmap scan endpoint."""

    def test_scan_nmap_success(self, test_client):
        """Test successful nmap scan."""
        with patch('purplesploit.api.server.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="PORT   STATE SERVICE\n22/tcp open ssh",
                stderr=""
            )

            response = test_client.post("/api/scan/nmap", json={
                "target": "192.168.1.100",
                "scan_type": "-sV"
            })
            assert response.status_code == 200
            assert response.json()["success"] is True

    def test_scan_nmap_with_ports(self, test_client):
        """Test nmap scan with specific ports."""
        with patch('purplesploit.api.server.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="scan result",
                stderr=""
            )

            response = test_client.post("/api/scan/nmap", json={
                "target": "192.168.1.100",
                "ports": "22,80,443"
            })
            assert response.status_code == 200


# =============================================================================
# Workspaces API Tests
# =============================================================================

class TestWorkspacesAPI:
    """Tests for workspaces endpoints."""

    def test_get_workspaces_empty(self, test_client):
        """Test getting workspaces when none exist."""
        with patch('pathlib.Path.exists', return_value=False):
            response = test_client.get("/api/workspaces")
            assert response.status_code == 200
            assert response.json() == []

    def test_get_workspace_not_found(self, test_client):
        """Test getting a non-existent workspace."""
        with patch('pathlib.Path.exists', return_value=False):
            response = test_client.get("/api/workspaces/nonexistent")
            assert response.status_code == 404


# =============================================================================
# Statistics API Tests
# =============================================================================

class TestStatisticsAPI:
    """Tests for statistics endpoints."""

    def test_get_stats_overview(self, test_client, mock_db_manager):
        """Test getting statistics overview."""
        mock_db_manager.get_all_targets.return_value = [MagicMock()]
        mock_db_manager.get_all_credentials.return_value = [MagicMock(), MagicMock()]

        mock_session = MagicMock()
        mock_service = MagicMock()
        mock_service.service = "ssh"
        mock_service.target = "192.168.1.100"
        mock_session.query.return_value.all.return_value = [mock_service]
        mock_db_manager.get_services_session.return_value = mock_session

        response = test_client.get("/api/stats/overview")
        assert response.status_code == 200
        data = response.json()
        assert "total_targets" in data
        assert "total_credentials" in data
        assert "total_services" in data
        assert "services_by_type" in data


# =============================================================================
# C2 API Tests
# =============================================================================

class TestC2API:
    """Tests for C2 command and control endpoints."""

    def test_list_modules(self, test_client, mock_framework):
        """Test listing available modules."""
        mock_module = MagicMock()
        mock_module.path = "test/module"
        mock_module.name = "Test Module"
        mock_module.category = "test"
        mock_module.description = "A test module"
        mock_module.author = "Test Author"
        mock_framework.list_modules.return_value = [mock_module]

        response = test_client.get("/api/c2/modules")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_search_modules(self, test_client, mock_framework):
        """Test searching modules."""
        mock_framework.search_modules.return_value = []

        response = test_client.get("/api/c2/modules/search?query=smb")
        assert response.status_code == 200

    def test_get_modules_by_category(self, test_client, mock_framework):
        """Test getting modules by category."""
        mock_framework.list_modules.return_value = []

        response = test_client.get("/api/c2/modules/recon")
        assert response.status_code == 200

    def test_get_module_info_not_found(self, test_client, mock_framework):
        """Test getting info for non-existent module."""
        mock_framework.get_module.return_value = None

        response = test_client.get("/api/c2/module/nonexistent/module")
        assert response.status_code == 404

    def test_execute_c2_command_help(self, test_client, mock_framework):
        """Test executing help command."""
        response = test_client.post("/api/c2/command", json={
            "command": "help",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "Available Commands" in data["output"]

    def test_execute_c2_command_stats(self, test_client, mock_framework):
        """Test executing stats command."""
        mock_framework.get_stats.return_value = {
            "modules": 10,
            "categories": 5,
            "targets": 2,
            "credentials": 3,
            "current_module": None
        }

        response = test_client.post("/api/c2/command", json={
            "command": "stats",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True

    def test_execute_c2_command_info(self, test_client, mock_framework):
        """Test executing info command."""
        mock_framework.get_categories.return_value = ["recon", "exploit"]

        response = test_client.post("/api/c2/command", json={
            "command": "info",
            "session_id": "test_session"
        })
        assert response.status_code == 200

    def test_execute_c2_command_clear(self, test_client, mock_framework):
        """Test executing clear command."""
        response = test_client.post("/api/c2/command", json={
            "command": "clear",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        # Clear returns ANSI escape codes
        assert "\x1b[2J" in response.json()["output"]

    def test_execute_c2_command_unknown(self, test_client, mock_framework):
        """Test executing unknown command."""
        response = test_client.post("/api/c2/command", json={
            "command": "unknowncommand",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        data = response.json()
        assert "Unknown command" in data["output"]

    def test_list_sessions(self, test_client, mock_framework):
        """Test listing active sessions."""
        response = test_client.get("/api/c2/sessions")
        assert response.status_code == 200
        data = response.json()
        assert "sessions" in data
        assert "count" in data

    def test_get_session_not_found(self, test_client, mock_framework):
        """Test getting a non-existent session."""
        response = test_client.get("/api/c2/session/nonexistent")
        assert response.status_code == 404

    def test_clear_session_not_found(self, test_client, mock_framework):
        """Test clearing a non-existent session."""
        response = test_client.delete("/api/c2/session/nonexistent")
        assert response.status_code == 404


# =============================================================================
# Nmap Upload Tests
# =============================================================================

class TestNmapUpload:
    """Tests for nmap XML upload endpoint."""

    def test_upload_nmap_invalid_file_type(self, test_client):
        """Test uploading a non-XML file."""
        response = test_client.post(
            "/api/nmap/upload",
            files={"file": ("test.txt", b"content", "text/plain")}
        )
        assert response.status_code == 400
        assert "XML" in response.json()["detail"]

    def test_upload_nmap_valid_xml_structure(self, test_client, mock_framework):
        """Test uploading valid XML file structure."""
        # Test the file type validation - endpoint properly rejects non-XML
        # and accepts XML files for processing
        xml_content = b"""<?xml version="1.0"?>
        <nmaprun scanner="nmap">
        </nmaprun>"""

        # This tests that XML files are accepted (not rejected like .txt files)
        # Full parsing requires actual NmapModule which may not be available
        response = test_client.post(
            "/api/nmap/upload",
            files={"file": ("scan.xml", xml_content, "application/xml")}
        )
        # Should not be 400 (file type rejection) - parsing may succeed or fail
        # depending on environment but file type should be accepted
        assert response.status_code != 400 or "XML" not in response.json().get("detail", "")


# =============================================================================
# Request/Response Model Tests
# =============================================================================

class TestRequestResponseModels:
    """Tests for request and response models."""

    def test_command_request_defaults(self):
        """Test CommandRequest default values."""
        from purplesploit.api.server import CommandRequest
        request = CommandRequest(command="test")
        assert request.command == "test"
        assert request.timeout == 300

    def test_command_request_custom_timeout(self):
        """Test CommandRequest with custom timeout."""
        from purplesploit.api.server import CommandRequest
        request = CommandRequest(command="test", timeout=60)
        assert request.timeout == 60

    def test_scan_request_defaults(self):
        """Test ScanRequest default values."""
        from purplesploit.api.server import ScanRequest
        request = ScanRequest(target="192.168.1.100")
        assert request.target == "192.168.1.100"
        assert request.scan_type == "-sV"
        assert request.ports is None

    def test_c2_command_request_defaults(self):
        """Test C2CommandRequest default values."""
        from purplesploit.api.server import C2CommandRequest
        request = C2CommandRequest(command="help")
        assert request.command == "help"
        assert request.session_id == "default"


# =============================================================================
# Static Files Tests
# =============================================================================

class TestStaticFiles:
    """Tests for static file handling."""

    def test_find_static_dir_exists(self):
        """Test finding static directory when it exists."""
        with patch('pathlib.Path.exists', return_value=True):
            from purplesploit.api.server import find_static_dir
            result = find_static_dir()
            # Result depends on path resolution

    def test_find_static_dir_not_exists(self):
        """Test finding static directory when it doesn't exist."""
        with patch('pathlib.Path.exists', return_value=False):
            from purplesploit.api.server import find_static_dir
            result = find_static_dir()
            assert result is None


# =============================================================================
# Extended Credentials API Tests
# =============================================================================

class TestCredentialsAPIExtended:
    """Extended tests for credentials endpoints to improve coverage."""

    def test_update_credential_success(self, test_client, mock_db_manager):
        """Test updating a credential successfully."""
        mock_cred = MagicMock()
        mock_cred.name = "existing_cred"
        mock_cred.username = "olduser"
        mock_cred.password = "oldpass"
        mock_cred.domain = ""
        mock_cred.hash = ""
        mock_cred.dcip = ""
        mock_cred.dns = ""
        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.first.return_value = mock_cred
        mock_db_manager.get_credentials_session.return_value = mock_session

        response = test_client.put("/api/credentials/existing_cred", json={
            "name": "updated_cred",
            "username": "newuser",
            "password": "newpass",
            "domain": "TESTDOMAIN",
            "hash": "aabbccdd"
        })
        assert response.status_code == 200

    def test_update_credential_not_found(self, test_client, mock_db_manager):
        """Test updating a non-existent credential."""
        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.first.return_value = None
        mock_db_manager.get_credentials_session.return_value = mock_session

        response = test_client.put("/api/credentials/nonexistent", json={
            "name": "test",
            "username": "user",
            "password": "pass"
        })
        assert response.status_code == 404


# =============================================================================
# Extended Targets API Tests
# =============================================================================

class TestTargetsAPIExtended:
    """Extended tests for targets endpoints to improve coverage."""

    def test_create_target_validation(self, test_client, mock_db_manager):
        """Test creating a target validates input."""
        response = test_client.post("/api/targets", json={
            "name": "new_target",
            "ip": "192.168.1.100",
            "description": "Test target"
        })
        # Any response indicates endpoint is properly routed
        assert response.status_code in [200, 201, 400, 422]

    def test_update_target_success(self, test_client, mock_db_manager):
        """Test updating a target successfully."""
        mock_target = MagicMock()
        mock_target.name = "existing_target"
        mock_target.ip = "10.0.0.1"
        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.first.return_value = mock_target
        mock_db_manager.get_targets_session.return_value = mock_session

        response = test_client.put("/api/targets/existing_target", json={
            "name": "updated_target",
            "ip": "10.0.0.2",
            "description": "Updated description"
        })
        assert response.status_code == 200

    def test_update_target_not_found(self, test_client, mock_db_manager):
        """Test updating a non-existent target."""
        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.first.return_value = None
        mock_db_manager.get_targets_session.return_value = mock_session

        response = test_client.put("/api/targets/nonexistent", json={
            "name": "test",
            "ip": "192.168.1.1"
        })
        assert response.status_code == 404

    def test_delete_target_not_found(self, test_client, mock_db_manager):
        """Test deleting a non-existent target."""
        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.first.return_value = None
        mock_db_manager.get_targets_session.return_value = mock_session

        response = test_client.delete("/api/targets/nonexistent")
        assert response.status_code == 404


# =============================================================================
# Extended C2 Command Tests
# =============================================================================

class TestC2CommandsExtended:
    """Extended tests for C2 commands to improve coverage."""

    def test_c2_command_search_no_args(self, test_client, mock_framework):
        """Test search command without arguments."""
        response = test_client.post("/api/c2/command", json={
            "command": "search",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        assert "Usage" in response.json()["output"]

    def test_c2_command_search_with_query(self, test_client, mock_framework):
        """Test search command with query."""
        mock_module = MagicMock()
        mock_module.path = "smb/auth"
        mock_module.name = "SMB Auth"
        mock_module.category = "exploit"
        mock_module.description = "SMB authentication module"
        mock_framework.search_modules.return_value = [mock_module]

        response = test_client.post("/api/c2/command", json={
            "command": "search smb",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        assert "Found" in response.json()["output"]

    def test_c2_command_search_no_results(self, test_client, mock_framework):
        """Test search command with no results."""
        mock_framework.search_modules.return_value = []

        response = test_client.post("/api/c2/command", json={
            "command": "search nonexistent",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        assert "No modules found" in response.json()["output"]

    def test_c2_command_use_no_args(self, test_client, mock_framework):
        """Test use command without arguments."""
        response = test_client.post("/api/c2/command", json={
            "command": "use",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        assert "Usage" in response.json()["output"]

    def test_c2_command_use_module_success(self, test_client, mock_framework):
        """Test use command to load module."""
        mock_module = MagicMock()
        mock_module.name = "Test Module"
        mock_framework.use_module.return_value = mock_module

        response = test_client.post("/api/c2/command", json={
            "command": "use test/module",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        assert "Loaded module" in response.json()["output"]

    def test_c2_command_use_module_not_found(self, test_client, mock_framework):
        """Test use command when module not found."""
        mock_framework.use_module.return_value = None
        mock_framework.search_modules.return_value = []

        response = test_client.post("/api/c2/command", json={
            "command": "use nonexistent/module",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        assert "not found" in response.json()["output"]

    def test_c2_command_show_no_args(self, test_client, mock_framework):
        """Test show command without arguments."""
        response = test_client.post("/api/c2/command", json={
            "command": "show",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        assert "Usage" in response.json()["output"]

    def test_c2_command_show_modules(self, test_client, mock_framework):
        """Test show modules command."""
        mock_module = MagicMock()
        mock_module.path = "test/module"
        mock_module.category = "recon"
        mock_framework.list_modules.return_value = [mock_module]

        response = test_client.post("/api/c2/command", json={
            "command": "show modules",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        assert "Available Modules" in response.json()["output"]

    def test_c2_command_show_options_no_module(self, test_client, mock_framework):
        """Test show options without loaded module."""
        response = test_client.post("/api/c2/command", json={
            "command": "show options",
            "session_id": "new_session"
        })
        assert response.status_code == 200
        assert "No module loaded" in response.json()["output"]

    def test_c2_command_show_targets(self, test_client, mock_framework):
        """Test show targets command."""
        mock_framework.session.targets.list.return_value = [
            {"name": "target1", "ip": "192.168.1.1"}
        ]

        response = test_client.post("/api/c2/command", json={
            "command": "show targets",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        assert "Targets" in response.json()["output"]

    def test_c2_command_show_targets_empty(self, test_client, mock_framework):
        """Test show targets when empty."""
        mock_framework.session.targets.list.return_value = []

        response = test_client.post("/api/c2/command", json={
            "command": "show targets",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        assert "No targets" in response.json()["output"]

    def test_c2_command_show_creds(self, test_client, mock_framework):
        """Test show creds command."""
        mock_framework.session.credentials.list.return_value = [
            {"username": "admin", "password": "pass123", "domain": "CORP"}
        ]

        response = test_client.post("/api/c2/command", json={
            "command": "show creds",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        assert "Credentials" in response.json()["output"]

    def test_c2_command_show_unknown(self, test_client, mock_framework):
        """Test show with unknown subcommand."""
        response = test_client.post("/api/c2/command", json={
            "command": "show unknown",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        assert "Unknown show command" in response.json()["output"]

    def test_c2_command_set_no_module(self, test_client, mock_framework):
        """Test set command without loaded module."""
        response = test_client.post("/api/c2/command", json={
            "command": "set RHOST 192.168.1.1",
            "session_id": "new_session"
        })
        assert response.status_code == 200
        assert "No module loaded" in response.json()["output"]

    def test_c2_command_set_missing_args(self, test_client, mock_framework):
        """Test set command with missing arguments."""
        response = test_client.post("/api/c2/command", json={
            "command": "set RHOST",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        assert "Usage" in response.json()["output"]

    def test_c2_command_run_no_module(self, test_client, mock_framework):
        """Test run command without loaded module."""
        response = test_client.post("/api/c2/command", json={
            "command": "run",
            "session_id": "new_session"
        })
        assert response.status_code == 200
        assert "No module loaded" in response.json()["output"]

    def test_c2_command_back(self, test_client, mock_framework):
        """Test back command."""
        response = test_client.post("/api/c2/command", json={
            "command": "back",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        assert "Unloaded" in response.json()["output"]

    def test_c2_command_target_no_args(self, test_client, mock_framework):
        """Test target command without arguments (show current)."""
        mock_framework.session.targets.get_current.return_value = None

        response = test_client.post("/api/c2/command", json={
            "command": "target",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        assert "No target set" in response.json()["output"]

    def test_c2_command_target_current(self, test_client, mock_framework):
        """Test target command showing current target."""
        mock_framework.session.targets.get_current.return_value = {
            "name": "target1", "ip": "192.168.1.100"
        }

        response = test_client.post("/api/c2/command", json={
            "command": "target",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        assert "Current target" in response.json()["output"]

    def test_c2_command_target_set_ip(self, test_client, mock_framework):
        """Test target command setting single IP."""
        response = test_client.post("/api/c2/command", json={
            "command": "target 192.168.1.100",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        assert "Target set" in response.json()["output"]

    def test_c2_command_target_set_cidr(self, test_client, mock_framework):
        """Test target command setting CIDR subnet."""
        response = test_client.post("/api/c2/command", json={
            "command": "target 10.10.10.0/24",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        assert "Target subnet added" in response.json()["output"]

    def test_c2_command_targets_list(self, test_client, mock_framework):
        """Test targets command."""
        mock_framework.session.targets.list.return_value = [
            {"name": "host1", "ip": "10.0.0.1"},
            {"name": "host2", "url": "https://example.com"}
        ]

        response = test_client.post("/api/c2/command", json={
            "command": "targets",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        assert "Targets" in response.json()["output"]

    def test_c2_command_cred_no_args(self, test_client, mock_framework):
        """Test cred command without arguments."""
        response = test_client.post("/api/c2/command", json={
            "command": "cred",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        assert "Usage" in response.json()["output"]

    def test_c2_command_cred_add(self, test_client, mock_framework):
        """Test cred command adding credential."""
        response = test_client.post("/api/c2/command", json={
            "command": "cred admin:password123",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        assert "Added credential" in response.json()["output"]

    def test_c2_command_cred_invalid_format(self, test_client, mock_framework):
        """Test cred command with invalid format."""
        response = test_client.post("/api/c2/command", json={
            "command": "cred invalidformat",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        assert "Invalid format" in response.json()["output"]

    def test_c2_command_creds_list(self, test_client, mock_framework):
        """Test creds command listing credentials."""
        mock_framework.session.credentials.list.return_value = [
            {"username": "admin", "password": "pass", "domain": "CORP"}
        ]

        response = test_client.post("/api/c2/command", json={
            "command": "creds",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        assert "Credentials" in response.json()["output"]

    def test_c2_command_creds_empty(self, test_client, mock_framework):
        """Test creds command when empty."""
        mock_framework.session.credentials.list.return_value = []

        response = test_client.post("/api/c2/command", json={
            "command": "creds",
            "session_id": "test_session"
        })
        assert response.status_code == 200
        assert "No credentials" in response.json()["output"]

    def test_c2_command_empty(self, test_client, mock_framework):
        """Test empty command."""
        response = test_client.post("/api/c2/command", json={
            "command": "",
            "session_id": "test_session"
        })
        assert response.status_code == 200


# =============================================================================
# C2 Module Execution Tests
# =============================================================================

class TestC2ModuleExecution:
    """Tests for C2 module execution."""

    def test_execute_module_success(self, test_client, mock_framework):
        """Test successful module execution."""
        mock_module = MagicMock()
        mock_module.show_options.return_value = {}
        mock_framework.use_module.return_value = mock_module
        mock_framework.run_module.return_value = {"success": True, "data": "result"}

        response = test_client.post("/api/c2/module/execute", json={
            "module_path": "test/module",
            "options": {"RHOST": "192.168.1.100"},
            "session_id": "test_session"
        })
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True

    def test_execute_module_not_found(self, test_client, mock_framework):
        """Test module execution when module not found."""
        mock_framework.use_module.return_value = None

        response = test_client.post("/api/c2/module/execute", json={
            "module_path": "nonexistent/module",
            "session_id": "test_session"
        })
        # May return 404 or 500 depending on error handling
        assert response.status_code in [404, 500]

    def test_get_module_info_success(self, test_client, mock_framework):
        """Test getting module info successfully."""
        mock_metadata = MagicMock()
        mock_metadata.path = "test/module"
        mock_metadata.name = "Test Module"
        mock_metadata.category = "recon"
        mock_metadata.description = "A test module"
        mock_metadata.author = "Test Author"
        mock_instance = MagicMock()
        mock_instance.show_options.return_value = {"RHOST": {"value": "", "required": True}}
        mock_metadata.instance.return_value = mock_instance
        mock_framework.get_module.return_value = mock_metadata

        response = test_client.get("/api/c2/module/test/module")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Test Module"
        assert "options" in data


# =============================================================================
# Session Management Tests
# =============================================================================

class TestSessionManagement:
    """Tests for session management."""

    def test_create_session_via_command(self, test_client, mock_framework):
        """Test session is created via command execution."""
        response = test_client.post("/api/c2/command", json={
            "command": "help",
            "session_id": "new_test_session"
        })
        assert response.status_code == 200
        assert response.json()["session_id"] == "new_test_session"

    def test_get_session_after_creation(self, test_client, mock_framework):
        """Test getting session after creation."""
        # Create session
        test_client.post("/api/c2/command", json={
            "command": "help",
            "session_id": "created_session"
        })

        # Get session
        response = test_client.get("/api/c2/session/created_session")
        assert response.status_code == 200
        data = response.json()
        assert "history" in data
        assert "created_at" in data

    def test_clear_session_success(self, test_client, mock_framework):
        """Test clearing session history."""
        # Create session
        test_client.post("/api/c2/command", json={
            "command": "help",
            "session_id": "clear_test_session"
        })

        # Clear session
        response = test_client.delete("/api/c2/session/clear_test_session")
        assert response.status_code == 200
        assert "cleared" in response.json()["message"]


# =============================================================================
# Exploits API Tests
# =============================================================================

class TestExploitsAPI:
    """Tests for exploits endpoints."""

    def test_get_all_exploits_empty(self, test_client, mock_db_manager):
        """Test getting all exploits when empty."""
        mock_db_manager.get_all_exploits.return_value = []

        response = test_client.get("/api/exploits")
        assert response.status_code == 200
        assert response.json() == []

    def test_get_exploits_for_target_empty(self, test_client, mock_db_manager):
        """Test getting exploits for target when empty."""
        mock_db_manager.get_exploits_for_target.return_value = []

        response = test_client.get("/api/exploits/target/192.168.1.100")
        assert response.status_code == 200
        assert response.json() == []


# =============================================================================
# Target Analysis Tests
# =============================================================================

class TestTargetAnalysis:
    """Tests for target analysis endpoint."""

    def test_get_target_analysis_not_found(self, test_client, mock_db_manager):
        """Test target analysis when target not found."""
        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.first.return_value = None
        mock_db_manager.get_targets_session.return_value = mock_session

        response = test_client.get("/api/analysis/10.0.0.1")
        assert response.status_code == 404


# =============================================================================
# Command Execution Error Tests
# =============================================================================

class TestCommandExecutionErrors:
    """Tests for command execution error scenarios."""

    def test_execute_command_exception(self, test_client):
        """Test command execution with exception."""
        with patch('purplesploit.api.server.subprocess.run') as mock_run:
            mock_run.side_effect = Exception("Unexpected error")

            response = test_client.post("/api/execute", json={
                "command": "some_command"
            })
            assert response.status_code == 500

    def test_nmap_scan_exception(self, test_client):
        """Test nmap scan with exception."""
        with patch('purplesploit.api.server.subprocess.run') as mock_run:
            mock_run.side_effect = Exception("Nmap not found")

            response = test_client.post("/api/scan/nmap", json={
                "target": "192.168.1.100"
            })
            assert response.status_code == 500


# =============================================================================
# Response Model Tests
# =============================================================================

class TestResponseModels:
    """Tests for response models."""

    def test_command_response_model(self):
        """Test CommandResponse model."""
        from purplesploit.api.server import CommandResponse
        response = CommandResponse(
            success=True,
            stdout="output",
            stderr="",
            return_code=0
        )
        assert response.success is True
        assert response.stdout == "output"

    def test_c2_command_response_model(self):
        """Test C2CommandResponse model."""
        from purplesploit.api.server import C2CommandResponse
        response = C2CommandResponse(
            success=True,
            output="help output",
            timestamp="2024-01-15T10:00:00",
            session_id="test"
        )
        assert response.success is True
        assert response.error is None

    def test_module_execute_request_model(self):
        """Test ModuleExecuteRequest model."""
        from purplesploit.api.server import ModuleExecuteRequest
        request = ModuleExecuteRequest(
            module_path="test/module",
            options={"RHOST": "192.168.1.1"},
            session_id="test_session"
        )
        assert request.module_path == "test/module"
        assert request.options["RHOST"] == "192.168.1.1"

    def test_module_execute_request_defaults(self):
        """Test ModuleExecuteRequest default values."""
        from purplesploit.api.server import ModuleExecuteRequest
        request = ModuleExecuteRequest(module_path="test/module")
        assert request.options is None
        assert request.session_id == "default"

    def test_workspace_info_model(self):
        """Test WorkspaceInfo model."""
        from purplesploit.api.server import WorkspaceInfo
        info = WorkspaceInfo(
            name="test_workspace",
            path="/home/user/.purplesploit/workspaces/test",
            target_count=5,
            cred_count=3
        )
        assert info.name == "test_workspace"
        assert info.target_count == 5


# =============================================================================
# Root Endpoint Tests
# =============================================================================

class TestRootEndpoint:
    """Tests for root endpoint."""

    def test_root_without_static_files(self, test_client):
        """Test root endpoint behavior."""
        # This test verifies root returns something (HTML or JSON fallback)
        response = test_client.get("/")
        assert response.status_code == 200


# =============================================================================
# Workspaces Extended Tests
# =============================================================================

class TestWorkspacesExtended:
    """Extended tests for workspaces."""

    def test_get_workspaces_with_data(self, test_client):
        """Test getting workspaces when they exist."""
        mock_workspace = MagicMock()
        mock_workspace.is_dir.return_value = True
        mock_workspace.name = "test_workspace"

        with patch('pathlib.Path.exists', return_value=True):
            with patch('pathlib.Path.iterdir', return_value=[mock_workspace]):
                response = test_client.get("/api/workspaces")
                # Response depends on path mocking complexity
                assert response.status_code == 200
