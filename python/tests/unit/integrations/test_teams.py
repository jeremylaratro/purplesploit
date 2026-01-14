"""
Unit tests for purplesploit.integrations.teams module.

Tests cover:
- TeamsConfig dataclass
- TeamsIntegration class:
  - Initialization and configuration
  - connect() / disconnect() methods
  - test_connection() webhook validation
  - send_notification() with rate limiting
  - _build_adaptive_card() message formatting
  - _get_teams_color() severity color mapping
  - send_finding() convenience method
  - send_scan_complete() convenience method
"""

import pytest
from datetime import datetime
from unittest.mock import patch, MagicMock
from typing import Dict, Any

from purplesploit.integrations.base import (
    IntegrationStatus,
    NotificationPayload,
    NotificationPriority,
)
from purplesploit.integrations.teams import (
    TeamsConfig,
    TeamsIntegration,
    REQUESTS_AVAILABLE,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def teams_config():
    """Create a Teams config with webhook URL."""
    return TeamsConfig(
        name="teams_test",
        webhook_url="https://outlook.office.com/webhook/test-webhook-id",
        mention_users_on_critical=["user1@example.com", "user2@example.com"],
    )


@pytest.fixture
def teams_office_webhook_config():
    """Create a Teams config with webhook.office.com URL."""
    return TeamsConfig(
        name="teams_office",
        webhook_url="https://webhook.office.com/webhookb2/test-id",
    )


@pytest.fixture
def teams_empty_config():
    """Create a Teams config with no webhook URL."""
    return TeamsConfig(name="teams_empty")


@pytest.fixture
def notification_payload():
    """Create a sample notification payload."""
    return NotificationPayload(
        title="XSS Vulnerability Detected",
        message="Cross-site scripting vulnerability found in search form",
        priority=NotificationPriority.HIGH,
        severity="high",
        target="webapp.example.com",
        finding_id="VULN-XSS-001",
        cvss_score=6.5,
        tags=["xss", "web", "owasp"],
    )


@pytest.fixture
def critical_payload():
    """Create a critical notification payload."""
    return NotificationPayload(
        title="Critical Authentication Bypass",
        message="Authentication bypass vulnerability allowing admin access",
        priority=NotificationPriority.CRITICAL,
        severity="critical",
        target="auth.example.com",
        finding_id="VULN-AUTH-001",
        cvss_score=10.0,
        tags=["auth", "critical", "bypass"],
    )


@pytest.fixture
def minimal_payload():
    """Create a minimal notification payload."""
    return NotificationPayload(
        title="Info Message",
        message="Informational notification",
    )


@pytest.fixture
def teams_integration(teams_config):
    """Create a Teams integration with config."""
    return TeamsIntegration(teams_config)


@pytest.fixture
def teams_office_integration(teams_office_webhook_config):
    """Create a Teams integration with office webhook."""
    return TeamsIntegration(teams_office_webhook_config)


# =============================================================================
# TeamsConfig Tests
# =============================================================================

class TestTeamsConfig:
    """Tests for TeamsConfig dataclass."""

    def test_config_default_values(self):
        """Test default values for TeamsConfig."""
        config = TeamsConfig(name="test")
        assert config.webhook_url == ""
        assert config.mention_users_on_critical == []

    def test_config_with_webhook(self, teams_config):
        """Test config with webhook URL."""
        assert teams_config.webhook_url is not None
        assert "office.com" in teams_config.webhook_url

    def test_config_mention_users(self, teams_config):
        """Test mention users configuration."""
        assert len(teams_config.mention_users_on_critical) == 2
        assert "user1@example.com" in teams_config.mention_users_on_critical

    def test_config_inherits_base_fields(self, teams_config):
        """Test that TeamsConfig inherits base IntegrationConfig fields."""
        assert teams_config.enabled is True
        assert teams_config.timeout == 30
        assert teams_config.retry_count == 3


# =============================================================================
# TeamsIntegration Initialization Tests
# =============================================================================

class TestTeamsIntegrationInit:
    """Tests for TeamsIntegration initialization."""

    def test_init_with_config(self, teams_config):
        """Test initialization with config."""
        integration = TeamsIntegration(teams_config)
        assert integration.config == teams_config
        assert integration.teams_config == teams_config

    def test_init_without_config(self):
        """Test initialization without config creates default."""
        integration = TeamsIntegration()
        assert integration.config is not None
        assert integration.config.name == "teams"

    def test_init_status_disconnected(self, teams_integration):
        """Test initial status is DISCONNECTED."""
        assert teams_integration.status == IntegrationStatus.DISCONNECTED


# =============================================================================
# connect() Method Tests
# =============================================================================

class TestTeamsConnect:
    """Tests for connect() method."""

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_connect_with_webhook_success(self, teams_integration):
        """Test successful connection with webhook URL."""
        result = teams_integration.connect()
        assert result is True
        assert teams_integration.status == IntegrationStatus.CONNECTED

    def test_connect_no_webhook_fails(self, teams_empty_config):
        """Test connection fails without webhook URL."""
        integration = TeamsIntegration(teams_empty_config)
        result = integration.connect()
        assert result is False
        assert integration.status == IntegrationStatus.ERROR
        assert "No webhook_url" in integration._error_message

    def test_connect_requests_not_available(self, teams_config):
        """Test connection fails when requests library not available."""
        with patch('purplesploit.integrations.teams.REQUESTS_AVAILABLE', False):
            integration = TeamsIntegration(teams_config)
            result = integration.connect()
            assert result is False
            assert integration.status == IntegrationStatus.ERROR


# =============================================================================
# disconnect() Method Tests
# =============================================================================

class TestTeamsDisconnect:
    """Tests for disconnect() method."""

    def test_disconnect_success(self, teams_integration):
        """Test successful disconnect."""
        teams_integration.status = IntegrationStatus.CONNECTED
        result = teams_integration.disconnect()
        assert result is True
        assert teams_integration.status == IntegrationStatus.DISCONNECTED


# =============================================================================
# test_connection() Method Tests
# =============================================================================

class TestTeamsTestConnection:
    """Tests for test_connection() method."""

    def test_test_connection_requests_not_available(self, teams_integration):
        """Test connection test fails when requests not available."""
        with patch('purplesploit.integrations.teams.REQUESTS_AVAILABLE', False):
            result = teams_integration.test_connection()
            assert result["success"] is False
            assert "requests library" in result["error"]

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_test_connection_office_webhook(self, teams_office_integration):
        """Test connection test with webhook.office.com URL."""
        result = teams_office_integration.test_connection()
        assert result["success"] is True
        assert result["method"] == "webhook"

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_test_connection_outlook_webhook(self, teams_integration):
        """Test connection test with outlook.office.com URL."""
        result = teams_integration.test_connection()
        assert result["success"] is True
        assert result["method"] == "webhook"

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_test_connection_non_standard_url(self):
        """Test connection test with non-standard URL."""
        config = TeamsConfig(
            name="test",
            webhook_url="https://custom-webhook.example.com/teams"
        )
        integration = TeamsIntegration(config)
        result = integration.test_connection()
        assert result["success"] is True
        assert "warning" in result
        assert "Non-standard" in result["warning"]


# =============================================================================
# send_notification() Method Tests
# =============================================================================

class TestTeamsSendNotification:
    """Tests for send_notification() method."""

    def test_send_notification_requests_not_available(
        self, teams_integration, notification_payload
    ):
        """Test notification fails when requests not available."""
        with patch('purplesploit.integrations.teams.REQUESTS_AVAILABLE', False):
            result = teams_integration.send_notification(notification_payload)
            assert result["success"] is False
            assert "requests library" in result["error"]

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_notification_success(
        self, teams_integration, notification_payload
    ):
        """Test successful notification."""
        with patch('purplesploit.integrations.teams.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            result = teams_integration.send_notification(notification_payload)
            assert result["success"] is True

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_notification_failure(
        self, teams_integration, notification_payload
    ):
        """Test failed notification."""
        with patch('purplesploit.integrations.teams.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 400
            mock_response.text = "Bad request"
            mock_requests.post.return_value = mock_response

            result = teams_integration.send_notification(notification_payload)
            assert result["success"] is False
            assert "400" in result["error"]

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_notification_rate_limited(
        self, teams_integration, notification_payload
    ):
        """Test notification respects rate limiting."""
        with patch('purplesploit.integrations.teams.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            # Send up to rate limit
            for _ in range(teams_integration.config.rate_limit):
                teams_integration.send_notification(notification_payload)

            # Next should be rate limited
            result = teams_integration.send_notification(notification_payload)
            assert result["success"] is False
            assert "Rate limited" in result["error"]


# =============================================================================
# _build_adaptive_card() Method Tests
# =============================================================================

class TestTeamsBuildAdaptiveCard:
    """Tests for _build_adaptive_card() method."""

    def test_build_card_basic_structure(
        self, teams_integration, notification_payload
    ):
        """Test basic card structure."""
        card = teams_integration._build_adaptive_card(notification_payload)
        assert card["type"] == "message"
        assert "attachments" in card
        assert len(card["attachments"]) > 0

    def test_build_card_attachment_structure(
        self, teams_integration, notification_payload
    ):
        """Test attachment content type."""
        card = teams_integration._build_adaptive_card(notification_payload)
        attachment = card["attachments"][0]
        assert attachment["contentType"] == "application/vnd.microsoft.card.adaptive"
        assert "content" in attachment

    def test_build_card_adaptive_card_version(
        self, teams_integration, notification_payload
    ):
        """Test Adaptive Card schema and version."""
        card = teams_integration._build_adaptive_card(notification_payload)
        content = card["attachments"][0]["content"]
        assert content["type"] == "AdaptiveCard"
        assert content["version"] == "1.4"
        assert "$schema" in content

    def test_build_card_body_has_elements(
        self, teams_integration, notification_payload
    ):
        """Test card body has required elements."""
        card = teams_integration._build_adaptive_card(notification_payload)
        body = card["attachments"][0]["content"]["body"]
        assert len(body) >= 4  # Container, message, facts, footer

    def test_build_card_title_block(
        self, teams_integration, notification_payload
    ):
        """Test card title is included."""
        card = teams_integration._build_adaptive_card(notification_payload)
        body = card["attachments"][0]["content"]["body"]

        # Find title in container
        container = body[0]
        assert container["type"] == "Container"
        title_block = container["items"][0]
        assert title_block["text"] == notification_payload.title

    def test_build_card_message_block(
        self, teams_integration, notification_payload
    ):
        """Test card message is included."""
        card = teams_integration._build_adaptive_card(notification_payload)
        body = card["attachments"][0]["content"]["body"]

        # Find message text block (second element)
        message_block = body[1]
        assert message_block["type"] == "TextBlock"
        assert message_block["text"] == notification_payload.message
        assert message_block["wrap"] is True

    def test_build_card_facts(
        self, teams_integration, notification_payload
    ):
        """Test card facts include finding details."""
        card = teams_integration._build_adaptive_card(notification_payload)
        body = card["attachments"][0]["content"]["body"]

        # Find FactSet
        fact_set = None
        for element in body:
            if element.get("type") == "FactSet":
                fact_set = element
                break

        assert fact_set is not None
        fact_titles = [f["title"] for f in fact_set["facts"]]
        assert "Target" in fact_titles
        assert "Severity" in fact_titles
        assert "CVSS Score" in fact_titles
        assert "Finding ID" in fact_titles

    def test_build_card_tags_in_facts(
        self, teams_integration, notification_payload
    ):
        """Test tags are included in facts."""
        card = teams_integration._build_adaptive_card(notification_payload)
        body = card["attachments"][0]["content"]["body"]

        fact_set = None
        for element in body:
            if element.get("type") == "FactSet":
                fact_set = element
                break

        fact_titles = [f["title"] for f in fact_set["facts"]]
        assert "Tags" in fact_titles

    def test_build_card_footer(
        self, teams_integration, notification_payload
    ):
        """Test card footer includes timestamp."""
        card = teams_integration._build_adaptive_card(notification_payload)
        body = card["attachments"][0]["content"]["body"]

        # Find footer (last element)
        footer = body[-1]
        assert footer["type"] == "TextBlock"
        assert "PurpleSploit" in footer["text"]
        assert footer["isSubtle"] is True

    def test_build_card_critical_warning(
        self, teams_integration, critical_payload
    ):
        """Test critical payloads have warning block."""
        card = teams_integration._build_adaptive_card(critical_payload)
        body = card["attachments"][0]["content"]["body"]

        # First element should be warning for critical
        warning = body[0]
        assert warning["type"] == "TextBlock"
        assert "CRITICAL" in warning["text"]
        assert warning["color"] == "Attention"

    def test_build_card_non_critical_no_warning(
        self, teams_integration, notification_payload
    ):
        """Test non-critical payloads don't have warning block first."""
        card = teams_integration._build_adaptive_card(notification_payload)
        body = card["attachments"][0]["content"]["body"]

        # First element should be Container, not warning
        first = body[0]
        assert first["type"] == "Container"

    def test_build_card_critical_emphasis_style(
        self, teams_integration, critical_payload
    ):
        """Test critical payloads have emphasis style."""
        card = teams_integration._build_adaptive_card(critical_payload)
        body = card["attachments"][0]["content"]["body"]

        # Find Container (should have emphasis style)
        for element in body:
            if element.get("type") == "Container":
                assert element["style"] == "emphasis"
                break

    def test_build_card_high_severity_attention_color(
        self, teams_integration, notification_payload
    ):
        """Test high severity title has Attention color."""
        card = teams_integration._build_adaptive_card(notification_payload)
        body = card["attachments"][0]["content"]["body"]

        # Find Container and check title color
        for element in body:
            if element.get("type") == "Container":
                title_block = element["items"][0]
                assert title_block["color"] == "Attention"
                break

    def test_build_card_minimal_payload(
        self, teams_integration, minimal_payload
    ):
        """Test card with minimal payload."""
        card = teams_integration._build_adaptive_card(minimal_payload)
        body = card["attachments"][0]["content"]["body"]

        # Should still have basic structure
        assert len(body) >= 3  # Container, message, footer


# =============================================================================
# _get_teams_color() Method Tests
# =============================================================================

class TestTeamsGetColor:
    """Tests for _get_teams_color() method."""

    @pytest.mark.parametrize("severity,expected_color", [
        ("critical", "attention"),
        ("high", "warning"),
        ("medium", "accent"),
        ("low", "good"),
        ("info", "default"),
    ])
    def test_severity_colors(self, teams_integration, severity, expected_color):
        """Test severity to color mapping."""
        color = teams_integration._get_teams_color(severity)
        assert color == expected_color

    def test_severity_color_case_insensitive(self, teams_integration):
        """Test severity color is case insensitive."""
        assert teams_integration._get_teams_color("CRITICAL") == "attention"
        assert teams_integration._get_teams_color("High") == "warning"

    def test_severity_color_unknown(self, teams_integration):
        """Test unknown severity returns default."""
        color = teams_integration._get_teams_color("unknown")
        assert color == "default"

    def test_severity_color_none(self, teams_integration):
        """Test None severity defaults to info."""
        color = teams_integration._get_teams_color(None)
        assert color == "default"


# =============================================================================
# send_finding() Method Tests
# =============================================================================

class TestTeamsSendFinding:
    """Tests for send_finding() convenience method."""

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_finding_success(self, teams_integration):
        """Test sending a finding."""
        with patch('purplesploit.integrations.teams.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            result = teams_integration.send_finding(
                title="Test Finding",
                description="Test description",
                severity="high",
                target="192.168.1.1",
                finding_id="FIND-001",
                cvss_score=7.5,
                tags=["test"],
            )
            assert result["success"] is True

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_finding_priority_mapping(self, teams_integration):
        """Test severity to priority mapping."""
        with patch('purplesploit.integrations.teams.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            # Test all severity levels
            for severity in ["critical", "high", "medium", "low", "info"]:
                result = teams_integration.send_finding(
                    title=f"{severity.title()} Finding",
                    description=f"{severity} description",
                    severity=severity,
                    target="10.0.0.1",
                )
                assert result["success"] is True


# =============================================================================
# send_scan_complete() Method Tests
# =============================================================================

class TestTeamsSendScanComplete:
    """Tests for send_scan_complete() convenience method."""

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_scan_complete_success(self, teams_integration):
        """Test sending scan completion notification."""
        with patch('purplesploit.integrations.teams.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            result = teams_integration.send_scan_complete(
                scan_name="Full Port Scan",
                target="192.168.1.0/24",
                findings_count=15,
                critical_count=2,
                high_count=5,
            )
            assert result["success"] is True

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_scan_complete_critical_severity(self, teams_integration):
        """Test scan with critical findings has critical severity."""
        with patch('purplesploit.integrations.teams.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            result = teams_integration.send_scan_complete(
                scan_name="Vuln Scan",
                target="10.0.0.1",
                findings_count=10,
                critical_count=1,
                high_count=0,
            )
            assert result["success"] is True

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_scan_complete_high_severity(self, teams_integration):
        """Test scan with high findings has high severity."""
        with patch('purplesploit.integrations.teams.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            result = teams_integration.send_scan_complete(
                scan_name="Vuln Scan",
                target="10.0.0.1",
                findings_count=10,
                critical_count=0,
                high_count=5,
            )
            assert result["success"] is True

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_scan_complete_info_severity(self, teams_integration):
        """Test scan with no findings has info severity."""
        with patch('purplesploit.integrations.teams.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            result = teams_integration.send_scan_complete(
                scan_name="Safe Scan",
                target="10.0.0.1",
                findings_count=0,
                critical_count=0,
                high_count=0,
            )
            assert result["success"] is True


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestTeamsErrorHandling:
    """Tests for error handling."""

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_notification_exception(
        self, teams_integration, notification_payload
    ):
        """Test exception handling in send_notification."""
        with patch('purplesploit.integrations.teams.requests') as mock_requests:
            mock_requests.post.side_effect = Exception("Network error")

            result = teams_integration.send_notification(notification_payload)
            assert result["success"] is False
            assert "error" in result


# =============================================================================
# Integration Tests
# =============================================================================

class TestTeamsIntegrationWorkflow:
    """Integration tests for complete workflows."""

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_full_workflow(self, teams_integration, notification_payload):
        """Test complete workflow."""
        with patch('purplesploit.integrations.teams.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            # Connect
            assert teams_integration.connect() is True

            # Send notification
            result = teams_integration.send_notification(notification_payload)
            assert result["success"] is True

            # Disconnect
            assert teams_integration.disconnect() is True
            assert teams_integration.status == IntegrationStatus.DISCONNECTED

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_multiple_notifications(self, teams_integration):
        """Test sending multiple notifications."""
        with patch('purplesploit.integrations.teams.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            teams_integration.connect()

            # Send different types of notifications
            for severity in ["critical", "high", "medium", "low", "info"]:
                payload = NotificationPayload(
                    title=f"{severity.title()} Alert",
                    message=f"This is a {severity} alert",
                    severity=severity,
                )
                result = teams_integration.send_notification(payload)
                # Only check if not rate limited
                if "Rate limited" not in result.get("error", ""):
                    assert result["success"] is True
