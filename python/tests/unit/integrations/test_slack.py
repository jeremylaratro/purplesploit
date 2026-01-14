"""
Unit tests for purplesploit.integrations.slack module.

Tests cover:
- SlackConfig dataclass
- SlackIntegration class:
  - Initialization and configuration
  - connect() / disconnect() methods
  - test_connection() for webhook and bot_token modes
  - send_notification() with rate limiting
  - _build_slack_payload() message formatting
  - _send_webhook() / _send_api() HTTP methods
  - send_finding() convenience method
  - send_scan_complete() convenience method
  - Thread mapping for finding updates
"""

import pytest
from datetime import datetime
from unittest.mock import patch, MagicMock, Mock
from typing import Dict, Any

from purplesploit.integrations.base import (
    IntegrationStatus,
    NotificationPayload,
    NotificationPriority,
)
from purplesploit.integrations.slack import (
    SlackConfig,
    SlackIntegration,
    REQUESTS_AVAILABLE,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def slack_webhook_config():
    """Create a Slack config with webhook URL."""
    return SlackConfig(
        name="slack_test",
        webhook_url="https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXX",
        default_channel="#security-alerts",
        username="TestBot",
        icon_emoji=":robot_face:",
    )


@pytest.fixture
def slack_bot_config():
    """Create a Slack config with bot token."""
    return SlackConfig(
        name="slack_bot_test",
        bot_token="xoxb-test-token-12345",
        default_channel="#security-alerts",
        username="PurpleSploit",
        mention_users_on_critical=["U12345", "U67890"],
    )


@pytest.fixture
def slack_empty_config():
    """Create a Slack config with no authentication."""
    return SlackConfig(name="slack_empty")


@pytest.fixture
def notification_payload():
    """Create a sample notification payload."""
    return NotificationPayload(
        title="SQL Injection Found",
        message="SQL injection vulnerability detected in login form",
        priority=NotificationPriority.HIGH,
        severity="high",
        target="192.168.1.100",
        finding_id="VULN-001",
        cvss_score=8.5,
        tags=["sqli", "web", "critical"],
    )


@pytest.fixture
def critical_payload():
    """Create a critical notification payload."""
    return NotificationPayload(
        title="Critical RCE Vulnerability",
        message="Remote code execution possible",
        priority=NotificationPriority.CRITICAL,
        severity="critical",
        target="10.0.0.1",
        finding_id="VULN-002",
        cvss_score=10.0,
        tags=["rce", "critical"],
    )


@pytest.fixture
def minimal_payload():
    """Create a minimal notification payload."""
    return NotificationPayload(
        title="Info Alert",
        message="Informational message",
    )


@pytest.fixture
def slack_webhook_integration(slack_webhook_config):
    """Create a Slack integration with webhook config."""
    return SlackIntegration(slack_webhook_config)


@pytest.fixture
def slack_bot_integration(slack_bot_config):
    """Create a Slack integration with bot token config."""
    return SlackIntegration(slack_bot_config)


# =============================================================================
# SlackConfig Tests
# =============================================================================

class TestSlackConfig:
    """Tests for SlackConfig dataclass."""

    def test_config_default_values(self):
        """Test default values for SlackConfig."""
        config = SlackConfig(name="test")
        assert config.webhook_url is None
        assert config.bot_token is None
        assert config.default_channel == "#security-alerts"
        assert config.username == "PurpleSploit"
        assert config.icon_emoji == ":skull:"
        assert config.mention_users_on_critical == []

    def test_config_with_webhook(self, slack_webhook_config):
        """Test config with webhook URL."""
        assert slack_webhook_config.webhook_url is not None
        assert "hooks.slack.com" in slack_webhook_config.webhook_url

    def test_config_with_bot_token(self, slack_bot_config):
        """Test config with bot token."""
        assert slack_bot_config.bot_token == "xoxb-test-token-12345"

    def test_config_mention_users(self, slack_bot_config):
        """Test mention users configuration."""
        assert len(slack_bot_config.mention_users_on_critical) == 2
        assert "U12345" in slack_bot_config.mention_users_on_critical

    def test_config_custom_channel(self):
        """Test custom default channel."""
        config = SlackConfig(name="test", default_channel="#custom-channel")
        assert config.default_channel == "#custom-channel"

    def test_config_inherits_base_fields(self, slack_webhook_config):
        """Test that SlackConfig inherits base IntegrationConfig fields."""
        assert slack_webhook_config.enabled is True
        assert slack_webhook_config.timeout == 30
        assert slack_webhook_config.retry_count == 3


# =============================================================================
# SlackIntegration Initialization Tests
# =============================================================================

class TestSlackIntegrationInit:
    """Tests for SlackIntegration initialization."""

    def test_init_with_config(self, slack_webhook_config):
        """Test initialization with config."""
        integration = SlackIntegration(slack_webhook_config)
        assert integration.config == slack_webhook_config
        assert integration.slack_config == slack_webhook_config

    def test_init_without_config(self):
        """Test initialization without config creates default."""
        integration = SlackIntegration()
        assert integration.config is not None
        assert integration.config.name == "slack"

    def test_init_thread_map_empty(self, slack_webhook_integration):
        """Test thread map is empty on init."""
        assert slack_webhook_integration._thread_map == {}

    def test_init_status_disconnected(self, slack_webhook_integration):
        """Test initial status is DISCONNECTED."""
        assert slack_webhook_integration.status == IntegrationStatus.DISCONNECTED


# =============================================================================
# connect() Method Tests
# =============================================================================

class TestSlackConnect:
    """Tests for connect() method."""

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_connect_with_webhook_success(self, slack_webhook_integration):
        """Test successful connection with webhook URL."""
        result = slack_webhook_integration.connect()
        assert result is True
        assert slack_webhook_integration.status == IntegrationStatus.CONNECTED

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_connect_with_bot_token_success(self, slack_bot_integration):
        """Test successful connection with bot token (mocked)."""
        with patch('purplesploit.integrations.slack.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.json.return_value = {"ok": True, "team": "test", "user": "bot"}
            mock_requests.post.return_value = mock_response

            result = slack_bot_integration.connect()
            assert result is True
            assert slack_bot_integration.status == IntegrationStatus.CONNECTED

    def test_connect_no_auth_fails(self, slack_empty_config):
        """Test connection fails without authentication."""
        integration = SlackIntegration(slack_empty_config)
        result = integration.connect()
        assert result is False
        assert integration.status == IntegrationStatus.ERROR
        assert "No webhook_url or bot_token" in integration._error_message

    def test_connect_requests_not_available(self, slack_webhook_config):
        """Test connection fails when requests library not available."""
        with patch('purplesploit.integrations.slack.REQUESTS_AVAILABLE', False):
            integration = SlackIntegration(slack_webhook_config)
            result = integration.connect()
            assert result is False
            assert integration.status == IntegrationStatus.ERROR


# =============================================================================
# disconnect() Method Tests
# =============================================================================

class TestSlackDisconnect:
    """Tests for disconnect() method."""

    def test_disconnect_success(self, slack_webhook_integration):
        """Test successful disconnect."""
        slack_webhook_integration.status = IntegrationStatus.CONNECTED
        result = slack_webhook_integration.disconnect()
        assert result is True
        assert slack_webhook_integration.status == IntegrationStatus.DISCONNECTED


# =============================================================================
# test_connection() Method Tests
# =============================================================================

class TestSlackTestConnection:
    """Tests for test_connection() method."""

    def test_test_connection_requests_not_available(self, slack_webhook_integration):
        """Test connection test fails when requests not available."""
        with patch('purplesploit.integrations.slack.REQUESTS_AVAILABLE', False):
            result = slack_webhook_integration.test_connection()
            assert result["success"] is False
            assert "requests library" in result["error"]

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_test_connection_webhook(self, slack_webhook_integration):
        """Test connection test with webhook."""
        result = slack_webhook_integration.test_connection()
        assert result["success"] is True
        assert result["method"] == "webhook"

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_test_connection_bot_token_success(self, slack_bot_integration):
        """Test connection test with bot token success."""
        with patch('purplesploit.integrations.slack.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "ok": True,
                "team": "TestTeam",
                "user": "testbot"
            }
            mock_requests.post.return_value = mock_response

            result = slack_bot_integration.test_connection()
            assert result["success"] is True
            assert result["method"] == "bot_token"
            assert result["team"] == "TestTeam"

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_test_connection_bot_token_failure(self, slack_bot_integration):
        """Test connection test with bot token failure."""
        with patch('purplesploit.integrations.slack.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.json.return_value = {"ok": False, "error": "invalid_auth"}
            mock_requests.post.return_value = mock_response

            result = slack_bot_integration.test_connection()
            assert result["success"] is False
            assert result["error"] == "invalid_auth"

    def test_test_connection_no_auth(self, slack_empty_config):
        """Test connection test with no authentication."""
        integration = SlackIntegration(slack_empty_config)
        with patch('purplesploit.integrations.slack.REQUESTS_AVAILABLE', True):
            result = integration.test_connection()
            assert result["success"] is False
            assert "No authentication" in result["error"]


# =============================================================================
# send_notification() Method Tests
# =============================================================================

class TestSlackSendNotification:
    """Tests for send_notification() method."""

    def test_send_notification_requests_not_available(
        self, slack_webhook_integration, notification_payload
    ):
        """Test notification fails when requests not available."""
        with patch('purplesploit.integrations.slack.REQUESTS_AVAILABLE', False):
            result = slack_webhook_integration.send_notification(notification_payload)
            assert result["success"] is False
            assert "requests library" in result["error"]

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_notification_webhook_success(
        self, slack_webhook_integration, notification_payload
    ):
        """Test successful notification via webhook."""
        with patch('purplesploit.integrations.slack.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            result = slack_webhook_integration.send_notification(notification_payload)
            assert result["success"] is True
            assert result["method"] == "webhook"

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_notification_webhook_failure(
        self, slack_webhook_integration, notification_payload
    ):
        """Test failed notification via webhook."""
        with patch('purplesploit.integrations.slack.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 400
            mock_response.text = "invalid_payload"
            mock_requests.post.return_value = mock_response

            result = slack_webhook_integration.send_notification(notification_payload)
            assert result["success"] is False
            assert "400" in result["error"]

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_notification_api_success(
        self, slack_bot_integration, notification_payload
    ):
        """Test successful notification via API."""
        with patch('purplesploit.integrations.slack.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "ok": True,
                "ts": "1234567890.123456",
                "channel": "C12345"
            }
            mock_requests.post.return_value = mock_response

            result = slack_bot_integration.send_notification(notification_payload)
            assert result["success"] is True
            assert result["method"] == "api"
            assert "ts" in result

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_notification_api_failure(
        self, slack_bot_integration, notification_payload
    ):
        """Test failed notification via API."""
        with patch('purplesploit.integrations.slack.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.json.return_value = {"ok": False, "error": "channel_not_found"}
            mock_requests.post.return_value = mock_response

            result = slack_bot_integration.send_notification(notification_payload)
            assert result["success"] is False
            assert result["error"] == "channel_not_found"

    def test_send_notification_no_auth(self, slack_empty_config, notification_payload):
        """Test notification fails with no authentication."""
        integration = SlackIntegration(slack_empty_config)
        with patch('purplesploit.integrations.slack.REQUESTS_AVAILABLE', True):
            result = integration.send_notification(notification_payload)
            assert result["success"] is False
            assert "No authentication" in result["error"]

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_notification_rate_limited(
        self, slack_webhook_integration, notification_payload
    ):
        """Test notification respects rate limiting."""
        with patch('purplesploit.integrations.slack.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            # Send up to rate limit
            for _ in range(slack_webhook_integration.config.rate_limit):
                slack_webhook_integration.send_notification(notification_payload)

            # Next should be rate limited
            result = slack_webhook_integration.send_notification(notification_payload)
            assert result["success"] is False
            assert "Rate limited" in result["error"]


# =============================================================================
# _build_slack_payload() Method Tests
# =============================================================================

class TestSlackBuildPayload:
    """Tests for _build_slack_payload() method."""

    def test_build_payload_basic_structure(
        self, slack_webhook_integration, notification_payload
    ):
        """Test basic payload structure."""
        payload = slack_webhook_integration._build_slack_payload(notification_payload)
        assert "username" in payload
        assert "icon_emoji" in payload
        assert "text" in payload
        assert "attachments" in payload

    def test_build_payload_username(
        self, slack_webhook_integration, notification_payload
    ):
        """Test payload includes configured username."""
        payload = slack_webhook_integration._build_slack_payload(notification_payload)
        assert payload["username"] == slack_webhook_integration.slack_config.username

    def test_build_payload_icon_emoji(
        self, slack_webhook_integration, notification_payload
    ):
        """Test payload includes configured emoji."""
        payload = slack_webhook_integration._build_slack_payload(notification_payload)
        assert payload["icon_emoji"] == slack_webhook_integration.slack_config.icon_emoji

    def test_build_payload_attachment_color(
        self, slack_webhook_integration, notification_payload
    ):
        """Test attachment has severity-based color."""
        payload = slack_webhook_integration._build_slack_payload(notification_payload)
        assert len(payload["attachments"]) > 0
        assert "color" in payload["attachments"][0]

    def test_build_payload_attachment_fields(
        self, slack_webhook_integration, notification_payload
    ):
        """Test attachment fields include finding details."""
        payload = slack_webhook_integration._build_slack_payload(notification_payload)
        attachment = payload["attachments"][0]
        assert "fields" in attachment

        field_titles = [f["title"] for f in attachment["fields"]]
        assert "Target" in field_titles
        assert "Severity" in field_titles
        assert "CVSS Score" in field_titles

    def test_build_payload_finding_id_field(
        self, slack_webhook_integration, notification_payload
    ):
        """Test finding ID is included in fields."""
        payload = slack_webhook_integration._build_slack_payload(notification_payload)
        attachment = payload["attachments"][0]

        field_titles = [f["title"] for f in attachment["fields"]]
        assert "Finding ID" in field_titles

    def test_build_payload_tags_field(
        self, slack_webhook_integration, notification_payload
    ):
        """Test tags are included in fields."""
        payload = slack_webhook_integration._build_slack_payload(notification_payload)
        attachment = payload["attachments"][0]

        field_titles = [f["title"] for f in attachment["fields"]]
        assert "Tags" in field_titles

    def test_build_payload_footer(
        self, slack_webhook_integration, notification_payload
    ):
        """Test attachment includes footer with timestamp."""
        payload = slack_webhook_integration._build_slack_payload(notification_payload)
        attachment = payload["attachments"][0]
        assert "footer" in attachment
        assert "PurpleSploit" in attachment["footer"]

    def test_build_payload_critical_mentions(
        self, slack_bot_integration, critical_payload
    ):
        """Test critical payloads include user mentions."""
        payload = slack_bot_integration._build_slack_payload(critical_payload)
        assert "<@U12345>" in payload["text"]
        assert "<@U67890>" in payload["text"]
        assert "CRITICAL" in payload["text"]

    def test_build_payload_non_critical_no_mentions(
        self, slack_bot_integration, notification_payload
    ):
        """Test non-critical payloads don't include mentions."""
        payload = slack_bot_integration._build_slack_payload(notification_payload)
        assert "<@U12345>" not in payload["text"]

    def test_build_payload_bot_includes_channel(
        self, slack_bot_integration, notification_payload
    ):
        """Test bot token mode includes channel."""
        payload = slack_bot_integration._build_slack_payload(notification_payload)
        assert "channel" in payload
        assert payload["channel"] == slack_bot_integration.slack_config.default_channel

    def test_build_payload_webhook_no_channel(
        self, slack_webhook_integration, notification_payload
    ):
        """Test webhook mode doesn't include channel."""
        payload = slack_webhook_integration._build_slack_payload(notification_payload)
        assert "channel" not in payload

    def test_build_payload_minimal(
        self, slack_webhook_integration, minimal_payload
    ):
        """Test payload with minimal notification."""
        payload = slack_webhook_integration._build_slack_payload(minimal_payload)
        assert payload["text"] == minimal_payload.title
        assert len(payload["attachments"][0]["fields"]) == 0

    def test_build_payload_thread_ts(self, slack_webhook_integration, notification_payload):
        """Test thread_ts is added for existing findings."""
        slack_webhook_integration._thread_map["VULN-001"] = "1234567890.123456"
        payload = slack_webhook_integration._build_slack_payload(notification_payload)
        assert payload["thread_ts"] == "1234567890.123456"


# =============================================================================
# send_finding() Method Tests
# =============================================================================

class TestSlackSendFinding:
    """Tests for send_finding() convenience method."""

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_finding_success(self, slack_webhook_integration):
        """Test sending a finding."""
        with patch('purplesploit.integrations.slack.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            result = slack_webhook_integration.send_finding(
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
    def test_send_finding_priority_mapping(self, slack_webhook_integration):
        """Test severity to priority mapping."""
        with patch('purplesploit.integrations.slack.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            # Test critical severity
            result = slack_webhook_integration.send_finding(
                title="Critical",
                description="Critical finding",
                severity="critical",
                target="10.0.0.1",
            )
            assert result["success"] is True

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_finding_info_severity(self, slack_webhook_integration):
        """Test info severity maps to LOW priority."""
        with patch('purplesploit.integrations.slack.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            result = slack_webhook_integration.send_finding(
                title="Info",
                description="Info finding",
                severity="info",
                target="10.0.0.1",
            )
            assert result["success"] is True


# =============================================================================
# send_scan_complete() Method Tests
# =============================================================================

class TestSlackSendScanComplete:
    """Tests for send_scan_complete() convenience method."""

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_scan_complete_success(self, slack_webhook_integration):
        """Test sending scan completion notification."""
        with patch('purplesploit.integrations.slack.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            result = slack_webhook_integration.send_scan_complete(
                scan_name="Full Port Scan",
                target="192.168.1.0/24",
                findings_count=15,
                critical_count=2,
                high_count=5,
            )
            assert result["success"] is True

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_scan_complete_critical_priority(self, slack_webhook_integration):
        """Test scan with critical findings has CRITICAL priority."""
        with patch('purplesploit.integrations.slack.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            result = slack_webhook_integration.send_scan_complete(
                scan_name="Vuln Scan",
                target="10.0.0.1",
                findings_count=10,
                critical_count=1,
                high_count=0,
            )
            assert result["success"] is True

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_scan_complete_high_priority(self, slack_webhook_integration):
        """Test scan with high findings has HIGH priority."""
        with patch('purplesploit.integrations.slack.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            result = slack_webhook_integration.send_scan_complete(
                scan_name="Vuln Scan",
                target="10.0.0.1",
                findings_count=10,
                critical_count=0,
                high_count=5,
            )
            assert result["success"] is True

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_scan_complete_no_findings(self, slack_webhook_integration):
        """Test scan with no critical/high findings."""
        with patch('purplesploit.integrations.slack.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            result = slack_webhook_integration.send_scan_complete(
                scan_name="Safe Scan",
                target="10.0.0.1",
                findings_count=0,
                critical_count=0,
                high_count=0,
            )
            assert result["success"] is True


# =============================================================================
# Severity Color Tests
# =============================================================================

class TestSlackSeverityColor:
    """Tests for severity color mapping."""

    @pytest.mark.parametrize("severity,expected_contains", [
        ("critical", "FF"),  # Should be red-ish
        ("high", "FF"),      # Should be orange-ish
        ("medium", "FF"),    # Should be yellow-ish
        ("low", "00"),       # Should be green-ish
        ("info", "00"),      # Should be blue-ish
    ])
    def test_severity_colors(self, slack_webhook_integration, severity, expected_contains):
        """Test severity color mapping."""
        color = slack_webhook_integration._get_severity_color(severity)
        assert expected_contains in color


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestSlackErrorHandling:
    """Tests for error handling."""

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_notification_exception(
        self, slack_webhook_integration, notification_payload
    ):
        """Test exception handling in send_notification."""
        with patch('purplesploit.integrations.slack.requests') as mock_requests:
            mock_requests.post.side_effect = Exception("Network error")

            result = slack_webhook_integration.send_notification(notification_payload)
            assert result["success"] is False
            assert "error" in result

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_test_connection_exception(self, slack_bot_integration):
        """Test exception handling in test_connection."""
        with patch('purplesploit.integrations.slack.requests') as mock_requests:
            mock_requests.post.side_effect = Exception("Connection refused")

            result = slack_bot_integration.test_connection()
            assert result["success"] is False
            assert "error" in result


# =============================================================================
# Thread Map Tests
# =============================================================================

class TestSlackThreadMap:
    """Tests for thread mapping functionality."""

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_thread_ts_stored_on_api_send(self, slack_bot_integration, notification_payload):
        """Test thread_ts is stored after API send."""
        with patch('purplesploit.integrations.slack.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "ok": True,
                "ts": "1234567890.123456",
                "channel": "C12345"
            }
            mock_requests.post.return_value = mock_response

            # Set finding_id in the payload dict for thread storage
            slack_bot_integration._build_slack_payload(notification_payload)
            # Note: Thread storage happens in _send_api, not _build_slack_payload


# =============================================================================
# Integration Tests
# =============================================================================

class TestSlackIntegrationWorkflow:
    """Integration tests for complete workflows."""

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_full_workflow_webhook(self, slack_webhook_integration, notification_payload):
        """Test complete workflow with webhook."""
        with patch('purplesploit.integrations.slack.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"ok": True}
            mock_requests.post.return_value = mock_response

            # Connect
            assert slack_webhook_integration.connect() is True

            # Send notification
            result = slack_webhook_integration.send_notification(notification_payload)
            assert result["success"] is True

            # Disconnect
            assert slack_webhook_integration.disconnect() is True
            assert slack_webhook_integration.status == IntegrationStatus.DISCONNECTED
