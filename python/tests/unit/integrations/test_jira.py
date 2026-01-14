"""
Unit tests for purplesploit.integrations.jira_integration module.

Tests cover:
- JiraConfig dataclass
- JiraIntegration class:
  - Initialization and configuration
  - _auth_header property
  - _base_url property
  - connect() / disconnect() methods
  - test_connection() API validation
  - send_notification() with issue creation/update
  - _create_issue() issue creation
  - _update_issue() issue updates via comments
  - _build_description() Jira-formatted descriptions
  - create_finding_issue() convenience method
  - attach_file() file attachments
  - transition_issue() workflow transitions
  - search_issues() JQL search
"""

import pytest
import base64
from datetime import datetime
from unittest.mock import patch, MagicMock, mock_open
from typing import Dict, Any

from purplesploit.integrations.base import (
    IntegrationStatus,
    NotificationPayload,
    NotificationPriority,
)
from purplesploit.integrations.jira_integration import (
    JiraConfig,
    JiraIntegration,
    REQUESTS_AVAILABLE,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def jira_config():
    """Create a JIRA config with all required fields."""
    return JiraConfig(
        name="jira_test",
        server_url="https://jira.example.com",
        username="testuser@example.com",
        api_key="test-api-key-12345",
        project_key="SEC",
        issue_type="Bug",
        labels=["security", "purplesploit", "automated"],
        assignee="security-team",
    )


@pytest.fixture
def jira_config_minimal():
    """Create a minimal JIRA config."""
    return JiraConfig(
        name="jira_minimal",
        server_url="https://jira.example.com",
        username="user@example.com",
        api_key="api-key",
        project_key="TEST",
    )


@pytest.fixture
def jira_empty_config():
    """Create a JIRA config with missing fields."""
    return JiraConfig(name="jira_empty")


@pytest.fixture
def notification_payload():
    """Create a sample notification payload."""
    return NotificationPayload(
        title="SQL Injection in Login",
        message="SQL injection vulnerability found in login form parameter 'username'",
        priority=NotificationPriority.HIGH,
        severity="high",
        target="webapp.example.com",
        finding_id="VULN-SQL-001",
        cvss_score=8.5,
        tags=["sqli", "owasp", "critical"],
        extra_data={"affected_endpoint": "/api/login", "parameter": "username"},
    )


@pytest.fixture
def critical_payload():
    """Create a critical notification payload."""
    return NotificationPayload(
        title="Remote Code Execution",
        message="RCE vulnerability in file upload functionality",
        priority=NotificationPriority.CRITICAL,
        severity="critical",
        target="upload.example.com",
        finding_id="VULN-RCE-001",
        cvss_score=10.0,
        tags=["rce", "critical"],
    )


@pytest.fixture
def minimal_payload():
    """Create a minimal notification payload."""
    return NotificationPayload(
        title="Info Alert",
        message="Informational finding",
    )


@pytest.fixture
def jira_integration(jira_config):
    """Create a JIRA integration with config."""
    return JiraIntegration(jira_config)


@pytest.fixture
def jira_minimal_integration(jira_config_minimal):
    """Create a minimal JIRA integration."""
    return JiraIntegration(jira_config_minimal)


# =============================================================================
# JiraConfig Tests
# =============================================================================

class TestJiraConfig:
    """Tests for JiraConfig dataclass."""

    def test_config_default_values(self):
        """Test default values for JiraConfig."""
        config = JiraConfig(name="test")
        assert config.server_url == ""
        assert config.username == ""
        assert config.project_key == ""
        assert config.issue_type == "Bug"
        assert config.assignee is None

    def test_config_default_priority_mapping(self, jira_config):
        """Test default priority mapping."""
        mapping = jira_config.priority_mapping
        assert mapping["critical"] == "Highest"
        assert mapping["high"] == "High"
        assert mapping["medium"] == "Medium"
        assert mapping["low"] == "Low"
        assert mapping["info"] == "Lowest"

    def test_config_default_labels(self, jira_config):
        """Test default labels include expected values."""
        assert "security" in jira_config.labels
        assert "purplesploit" in jira_config.labels

    def test_config_custom_fields(self):
        """Test custom fields configuration."""
        config = JiraConfig(
            name="test",
            custom_fields={"customfield_10001": "security-assessment"}
        )
        assert "customfield_10001" in config.custom_fields

    def test_config_inherits_base_fields(self, jira_config):
        """Test that JiraConfig inherits base IntegrationConfig fields."""
        assert jira_config.enabled is True
        assert jira_config.timeout == 30
        assert jira_config.api_key == "test-api-key-12345"


# =============================================================================
# JiraIntegration Initialization Tests
# =============================================================================

class TestJiraIntegrationInit:
    """Tests for JiraIntegration initialization."""

    def test_init_with_config(self, jira_config):
        """Test initialization with config."""
        integration = JiraIntegration(jira_config)
        assert integration.config == jira_config
        assert integration.jira_config == jira_config

    def test_init_without_config(self):
        """Test initialization without config creates default."""
        integration = JiraIntegration()
        assert integration.config is not None
        assert integration.config.name == "jira"

    def test_init_issue_cache_empty(self, jira_integration):
        """Test issue cache is empty on init."""
        assert jira_integration._issue_cache == {}

    def test_init_status_disconnected(self, jira_integration):
        """Test initial status is DISCONNECTED."""
        assert jira_integration.status == IntegrationStatus.DISCONNECTED


# =============================================================================
# Property Tests
# =============================================================================

class TestJiraProperties:
    """Tests for JiraIntegration properties."""

    def test_auth_header_with_api_key(self, jira_integration):
        """Test auth header is correctly built."""
        header = jira_integration._auth_header
        assert "Authorization" in header
        assert header["Authorization"].startswith("Basic ")

        # Verify encoding
        expected = base64.b64encode(
            f"{jira_integration.jira_config.username}:{jira_integration.jira_config.api_key}".encode()
        ).decode()
        assert expected in header["Authorization"]

    def test_auth_header_no_api_key(self, jira_empty_config):
        """Test auth header is empty without api_key."""
        integration = JiraIntegration(jira_empty_config)
        header = integration._auth_header
        assert header == {}

    def test_base_url(self, jira_integration):
        """Test base URL is correctly built."""
        assert jira_integration._base_url == "https://jira.example.com/rest/api/2"

    def test_base_url_trailing_slash(self):
        """Test base URL strips trailing slash."""
        config = JiraConfig(
            name="test",
            server_url="https://jira.example.com/",
            username="user",
            api_key="key",
        )
        integration = JiraIntegration(config)
        assert integration._base_url == "https://jira.example.com/rest/api/2"


# =============================================================================
# connect() Method Tests
# =============================================================================

class TestJiraConnect:
    """Tests for connect() method."""

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_connect_success(self, jira_integration):
        """Test successful connection."""
        with patch('purplesploit.integrations.jira_integration.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "displayName": "Test User",
                "emailAddress": "test@example.com"
            }
            mock_requests.get.return_value = mock_response

            result = jira_integration.connect()
            assert result is True
            assert jira_integration.status == IntegrationStatus.CONNECTED

    def test_connect_missing_config_fails(self, jira_empty_config):
        """Test connection fails without required config."""
        integration = JiraIntegration(jira_empty_config)
        result = integration.connect()
        assert result is False
        assert integration.status == IntegrationStatus.ERROR
        assert "Missing" in integration._error_message

    def test_connect_requests_not_available(self, jira_config):
        """Test connection fails when requests not available."""
        with patch('purplesploit.integrations.jira_integration.REQUESTS_AVAILABLE', False):
            integration = JiraIntegration(jira_config)
            result = integration.connect()
            assert result is False
            assert integration.status == IntegrationStatus.ERROR


# =============================================================================
# disconnect() Method Tests
# =============================================================================

class TestJiraDisconnect:
    """Tests for disconnect() method."""

    def test_disconnect_success(self, jira_integration):
        """Test successful disconnect."""
        jira_integration.status = IntegrationStatus.CONNECTED
        result = jira_integration.disconnect()
        assert result is True
        assert jira_integration.status == IntegrationStatus.DISCONNECTED


# =============================================================================
# test_connection() Method Tests
# =============================================================================

class TestJiraTestConnection:
    """Tests for test_connection() method."""

    def test_test_connection_requests_not_available(self, jira_integration):
        """Test connection test fails when requests not available."""
        with patch('purplesploit.integrations.jira_integration.REQUESTS_AVAILABLE', False):
            result = jira_integration.test_connection()
            assert result["success"] is False
            assert "requests library" in result["error"]

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_test_connection_success(self, jira_integration):
        """Test successful connection test."""
        with patch('purplesploit.integrations.jira_integration.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "displayName": "Security Bot",
                "emailAddress": "security@example.com"
            }
            mock_requests.get.return_value = mock_response

            result = jira_integration.test_connection()
            assert result["success"] is True
            assert result["user"] == "Security Bot"
            assert result["email"] == "security@example.com"

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_test_connection_failure(self, jira_integration):
        """Test failed connection test."""
        with patch('purplesploit.integrations.jira_integration.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 401
            mock_response.text = "Unauthorized"
            mock_requests.get.return_value = mock_response

            result = jira_integration.test_connection()
            assert result["success"] is False
            assert "401" in result["error"]


# =============================================================================
# send_notification() Method Tests
# =============================================================================

class TestJiraSendNotification:
    """Tests for send_notification() method."""

    def test_send_notification_requests_not_available(
        self, jira_integration, notification_payload
    ):
        """Test notification fails when requests not available."""
        with patch('purplesploit.integrations.jira_integration.REQUESTS_AVAILABLE', False):
            result = jira_integration.send_notification(notification_payload)
            assert result["success"] is False

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_notification_creates_issue(
        self, jira_integration, notification_payload
    ):
        """Test notification creates new issue."""
        with patch('purplesploit.integrations.jira_integration.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 201
            mock_response.json.return_value = {"key": "SEC-123"}
            mock_requests.post.return_value = mock_response

            result = jira_integration.send_notification(notification_payload)
            assert result["success"] is True
            assert result["issue_key"] == "SEC-123"

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_notification_updates_existing_issue(
        self, jira_integration, notification_payload
    ):
        """Test notification updates existing issue via comment."""
        # Pre-cache the issue
        jira_integration._issue_cache["VULN-SQL-001"] = "SEC-100"

        with patch('purplesploit.integrations.jira_integration.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 201
            mock_requests.post.return_value = mock_response

            result = jira_integration.send_notification(notification_payload)
            assert result["success"] is True
            assert result["issue_key"] == "SEC-100"
            assert result["action"] == "updated"

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_notification_rate_limited(
        self, jira_integration, notification_payload
    ):
        """Test notification respects rate limiting."""
        with patch('purplesploit.integrations.jira_integration.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 201
            mock_response.json.return_value = {"key": "SEC-123"}
            mock_requests.post.return_value = mock_response

            # Send up to rate limit
            for i in range(jira_integration.config.rate_limit):
                # Clear cache each time to create new issues
                jira_integration._issue_cache.clear()
                jira_integration.send_notification(notification_payload)

            # Next should be rate limited
            result = jira_integration.send_notification(notification_payload)
            assert result["success"] is False
            assert "Rate limited" in result["error"]


# =============================================================================
# _create_issue() Method Tests
# =============================================================================

class TestJiraCreateIssue:
    """Tests for _create_issue() method."""

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_create_issue_success(self, jira_integration, notification_payload):
        """Test successful issue creation."""
        with patch('purplesploit.integrations.jira_integration.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 201
            mock_response.json.return_value = {"key": "SEC-456"}
            mock_requests.post.return_value = mock_response

            result = jira_integration._create_issue(notification_payload)
            assert result["success"] is True
            assert result["issue_key"] == "SEC-456"
            assert "issue_url" in result

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_create_issue_caches_finding(self, jira_integration, notification_payload):
        """Test issue key is cached for finding_id."""
        with patch('purplesploit.integrations.jira_integration.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 201
            mock_response.json.return_value = {"key": "SEC-789"}
            mock_requests.post.return_value = mock_response

            jira_integration._create_issue(notification_payload)
            assert jira_integration._issue_cache["VULN-SQL-001"] == "SEC-789"

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_create_issue_failure(self, jira_integration, notification_payload):
        """Test failed issue creation."""
        with patch('purplesploit.integrations.jira_integration.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 400
            mock_response.text = "Invalid project"
            mock_requests.post.return_value = mock_response

            result = jira_integration._create_issue(notification_payload)
            assert result["success"] is False
            assert "400" in result["error"]


# =============================================================================
# _update_issue() Method Tests
# =============================================================================

class TestJiraUpdateIssue:
    """Tests for _update_issue() method."""

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_update_issue_success(self, jira_integration, notification_payload):
        """Test successful issue update."""
        with patch('purplesploit.integrations.jira_integration.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 201
            mock_requests.post.return_value = mock_response

            result = jira_integration._update_issue("SEC-100", notification_payload)
            assert result["success"] is True
            assert result["action"] == "updated"

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_update_issue_failure(self, jira_integration, notification_payload):
        """Test failed issue update."""
        with patch('purplesploit.integrations.jira_integration.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_response.text = "Issue not found"
            mock_requests.post.return_value = mock_response

            result = jira_integration._update_issue("SEC-999", notification_payload)
            assert result["success"] is False


# =============================================================================
# _build_description() Method Tests
# =============================================================================

class TestJiraBuildDescription:
    """Tests for _build_description() method."""

    def test_build_description_contains_message(
        self, jira_integration, notification_payload
    ):
        """Test description contains message."""
        desc = jira_integration._build_description(notification_payload)
        assert notification_payload.message in desc

    def test_build_description_contains_details_header(
        self, jira_integration, notification_payload
    ):
        """Test description contains details header."""
        desc = jira_integration._build_description(notification_payload)
        assert "h3. Details" in desc

    def test_build_description_table_format(
        self, jira_integration, notification_payload
    ):
        """Test description uses Jira table format."""
        desc = jira_integration._build_description(notification_payload)
        assert "||Field||Value||" in desc
        assert "|Target|" in desc
        assert "|Severity|" in desc

    def test_build_description_includes_cvss(
        self, jira_integration, notification_payload
    ):
        """Test description includes CVSS score."""
        desc = jira_integration._build_description(notification_payload)
        assert "|CVSS Score|8.5|" in desc

    def test_build_description_includes_finding_id(
        self, jira_integration, notification_payload
    ):
        """Test description includes finding ID."""
        desc = jira_integration._build_description(notification_payload)
        assert "|Finding ID|VULN-SQL-001|" in desc

    def test_build_description_includes_source(
        self, jira_integration, notification_payload
    ):
        """Test description includes source."""
        desc = jira_integration._build_description(notification_payload)
        assert "|Source|purplesploit|" in desc

    def test_build_description_includes_extra_data(
        self, jira_integration, notification_payload
    ):
        """Test description includes extra data in code block."""
        desc = jira_integration._build_description(notification_payload)
        assert "h3. Additional Data" in desc
        assert "{code:json}" in desc
        assert "affected_endpoint" in desc

    def test_build_description_minimal_payload(
        self, jira_integration, minimal_payload
    ):
        """Test description with minimal payload."""
        desc = jira_integration._build_description(minimal_payload)
        assert minimal_payload.message in desc
        # Should not have Target or Severity rows for None values


# =============================================================================
# create_finding_issue() Method Tests
# =============================================================================

class TestJiraCreateFindingIssue:
    """Tests for create_finding_issue() convenience method."""

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_create_finding_issue_success(self, jira_integration):
        """Test creating a finding issue."""
        with patch('purplesploit.integrations.jira_integration.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 201
            mock_response.json.return_value = {"key": "SEC-500"}
            mock_requests.post.return_value = mock_response

            result = jira_integration.create_finding_issue(
                title="Test Finding",
                description="Test description",
                severity="high",
                target="192.168.1.1",
                finding_id="FIND-001",
                cvss_score=7.5,
                remediation="Apply patch XYZ",
                tags=["test"],
            )
            assert result["success"] is True
            assert result["issue_key"] == "SEC-500"

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_create_finding_issue_with_evidence(self, jira_integration):
        """Test creating issue with evidence attachments."""
        with patch('purplesploit.integrations.jira_integration.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 201
            mock_response.json.return_value = {"key": "SEC-501"}
            mock_requests.post.return_value = mock_response

            # Mock attach_file to succeed
            with patch.object(jira_integration, 'attach_file', return_value={"success": True}):
                result = jira_integration.create_finding_issue(
                    title="Evidence Finding",
                    description="Finding with evidence",
                    severity="critical",
                    target="10.0.0.1",
                    evidence=["/path/to/screenshot.png", "/path/to/log.txt"],
                )
                assert result["success"] is True


# =============================================================================
# attach_file() Method Tests
# =============================================================================

class TestJiraAttachFile:
    """Tests for attach_file() method."""

    def test_attach_file_requests_not_available(self, jira_integration):
        """Test attach fails when requests not available."""
        with patch('purplesploit.integrations.jira_integration.REQUESTS_AVAILABLE', False):
            result = jira_integration.attach_file("SEC-123", "/path/to/file.txt")
            assert result["success"] is False

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_attach_file_success(self, jira_integration):
        """Test successful file attachment."""
        with patch('purplesploit.integrations.jira_integration.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = [{"filename": "evidence.png"}]
            mock_requests.post.return_value = mock_response

            with patch('builtins.open', mock_open(read_data=b"file content")):
                result = jira_integration.attach_file("SEC-123", "/path/to/evidence.png")
                assert result["success"] is True
                assert "evidence.png" in result["attachments"]

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_attach_file_failure(self, jira_integration):
        """Test failed file attachment."""
        with patch('purplesploit.integrations.jira_integration.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 403
            mock_response.text = "Forbidden"
            mock_requests.post.return_value = mock_response

            with patch('builtins.open', mock_open(read_data=b"file content")):
                result = jira_integration.attach_file("SEC-123", "/path/to/file.txt")
                assert result["success"] is False

    def test_attach_file_exception(self, jira_integration):
        """Test file attachment with exception."""
        with patch('builtins.open', side_effect=FileNotFoundError("File not found")):
            result = jira_integration.attach_file("SEC-123", "/nonexistent/file.txt")
            assert result["success"] is False


# =============================================================================
# transition_issue() Method Tests
# =============================================================================

class TestJiraTransitionIssue:
    """Tests for transition_issue() method."""

    def test_transition_requests_not_available(self, jira_integration):
        """Test transition fails when requests not available."""
        with patch('purplesploit.integrations.jira_integration.REQUESTS_AVAILABLE', False):
            result = jira_integration.transition_issue("SEC-123", "Done")
            assert result["success"] is False

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_transition_issue_success(self, jira_integration):
        """Test successful issue transition."""
        with patch('purplesploit.integrations.jira_integration.requests') as mock_requests:
            # Mock GET transitions
            transitions_response = MagicMock()
            transitions_response.status_code = 200
            transitions_response.json.return_value = {
                "transitions": [
                    {"id": "11", "name": "In Progress"},
                    {"id": "21", "name": "Done"},
                ]
            }

            # Mock POST transition
            transition_response = MagicMock()
            transition_response.status_code = 204

            mock_requests.get.return_value = transitions_response
            mock_requests.post.return_value = transition_response

            result = jira_integration.transition_issue("SEC-123", "Done")
            assert result["success"] is True
            assert result["transition"] == "Done"

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_transition_issue_not_found(self, jira_integration):
        """Test transition with non-existent transition name."""
        with patch('purplesploit.integrations.jira_integration.requests') as mock_requests:
            transitions_response = MagicMock()
            transitions_response.status_code = 200
            transitions_response.json.return_value = {
                "transitions": [
                    {"id": "11", "name": "In Progress"},
                ]
            }
            mock_requests.get.return_value = transitions_response

            result = jira_integration.transition_issue("SEC-123", "Closed")
            assert result["success"] is False
            assert "not found" in result["error"]
            assert "available" in result

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_transition_issue_case_insensitive(self, jira_integration):
        """Test transition is case insensitive."""
        with patch('purplesploit.integrations.jira_integration.requests') as mock_requests:
            transitions_response = MagicMock()
            transitions_response.status_code = 200
            transitions_response.json.return_value = {
                "transitions": [{"id": "21", "name": "Done"}]
            }

            transition_response = MagicMock()
            transition_response.status_code = 204

            mock_requests.get.return_value = transitions_response
            mock_requests.post.return_value = transition_response

            result = jira_integration.transition_issue("SEC-123", "done")
            assert result["success"] is True


# =============================================================================
# search_issues() Method Tests
# =============================================================================

class TestJiraSearchIssues:
    """Tests for search_issues() method."""

    def test_search_requests_not_available(self, jira_integration):
        """Test search fails when requests not available."""
        with patch('purplesploit.integrations.jira_integration.REQUESTS_AVAILABLE', False):
            result = jira_integration.search_issues()
            assert result["success"] is False

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_search_issues_success(self, jira_integration):
        """Test successful issue search."""
        with patch('purplesploit.integrations.jira_integration.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "total": 2,
                "issues": [
                    {
                        "key": "SEC-100",
                        "fields": {
                            "summary": "SQL Injection",
                            "status": {"name": "Open"},
                            "priority": {"name": "High"},
                            "created": "2024-01-15T10:00:00.000+0000"
                        }
                    },
                    {
                        "key": "SEC-101",
                        "fields": {
                            "summary": "XSS Vulnerability",
                            "status": {"name": "In Progress"},
                            "priority": {"name": "Medium"},
                            "created": "2024-01-16T11:00:00.000+0000"
                        }
                    }
                ]
            }
            mock_requests.get.return_value = mock_response

            result = jira_integration.search_issues()
            assert result["success"] is True
            assert result["total"] == 2
            assert len(result["issues"]) == 2

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_search_issues_with_custom_jql(self, jira_integration):
        """Test search with custom JQL."""
        with patch('purplesploit.integrations.jira_integration.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"total": 0, "issues": []}
            mock_requests.get.return_value = mock_response

            result = jira_integration.search_issues(jql="status = Done")
            assert result["success"] is True
            mock_requests.get.assert_called()

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_search_issues_by_finding_id(self, jira_integration):
        """Test search by finding ID."""
        with patch('purplesploit.integrations.jira_integration.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"total": 1, "issues": []}
            mock_requests.get.return_value = mock_response

            result = jira_integration.search_issues(finding_id="VULN-001")
            assert result["success"] is True

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_search_issues_by_target(self, jira_integration):
        """Test search by target."""
        with patch('purplesploit.integrations.jira_integration.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"total": 1, "issues": []}
            mock_requests.get.return_value = mock_response

            result = jira_integration.search_issues(target="192.168.1.100")
            assert result["success"] is True


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestJiraErrorHandling:
    """Tests for error handling."""

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_create_issue_exception(self, jira_integration, notification_payload):
        """Test exception handling in _create_issue."""
        with patch('purplesploit.integrations.jira_integration.requests') as mock_requests:
            mock_requests.post.side_effect = Exception("Network error")

            result = jira_integration.send_notification(notification_payload)
            assert result["success"] is False

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_transition_exception(self, jira_integration):
        """Test exception handling in transition_issue."""
        with patch('purplesploit.integrations.jira_integration.requests') as mock_requests:
            mock_requests.get.side_effect = Exception("Connection refused")

            result = jira_integration.transition_issue("SEC-123", "Done")
            assert result["success"] is False


# =============================================================================
# Integration Tests
# =============================================================================

class TestJiraIntegrationWorkflow:
    """Integration tests for complete workflows."""

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_full_workflow(self, jira_integration, notification_payload):
        """Test complete workflow."""
        with patch('purplesploit.integrations.jira_integration.requests') as mock_requests:
            # Mock connection test
            connect_response = MagicMock()
            connect_response.status_code = 200
            connect_response.json.return_value = {"displayName": "Bot", "emailAddress": "bot@example.com"}

            # Mock issue creation
            create_response = MagicMock()
            create_response.status_code = 201
            create_response.json.return_value = {"key": "SEC-100"}

            # Configure mock to return different responses
            mock_requests.get.return_value = connect_response
            mock_requests.post.return_value = create_response

            # Connect
            assert jira_integration.connect() is True

            # Create issue
            result = jira_integration.send_notification(notification_payload)
            assert result["success"] is True

            # Disconnect
            assert jira_integration.disconnect() is True
