"""
Unit tests for purplesploit.integrations.siem module.

Tests cover:
- SIEMConfig dataclass
- SIEMWebhook class (generic webhook integration)
- SplunkConfig and SplunkIntegration (HEC integration)
- ElasticConfig and ElasticIntegration (Elasticsearch integration)
- CEF/event formatting
- Batch operations
- Search functionality
"""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from typing import Dict, Any

from purplesploit.integrations.base import (
    IntegrationStatus,
    NotificationPayload,
    NotificationPriority,
)
from purplesploit.integrations.siem import (
    SIEMConfig,
    SIEMWebhook,
    SplunkConfig,
    SplunkIntegration,
    ElasticConfig,
    ElasticIntegration,
    REQUESTS_AVAILABLE,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def siem_config():
    """Create a basic SIEM webhook config."""
    return SIEMConfig(
        name="siem_test",
        webhook_url="https://siem.example.com/webhook/events",
        source_type="purplesploit",
        index="security",
        verify_ssl=True,
        custom_headers={"X-API-Key": "test-key"},
    )


@pytest.fixture
def siem_config_no_ssl():
    """Create a SIEM config without SSL verification."""
    return SIEMConfig(
        name="siem_no_ssl",
        webhook_url="https://internal-siem.local/events",
        verify_ssl=False,
    )


@pytest.fixture
def splunk_config():
    """Create a Splunk HEC config."""
    return SplunkConfig(
        name="splunk_test",
        hec_url="https://splunk.example.com:8088/services/collector",
        hec_token="12345678-1234-1234-1234-123456789abc",
        source_type="purplesploit:findings",
        index="main",
        verify_ssl=True,
    )


@pytest.fixture
def splunk_config_webhook():
    """Create a Splunk config with webhook_url fallback."""
    return SplunkConfig(
        name="splunk_webhook",
        webhook_url="https://splunk.example.com:8088/services/collector",
        hec_token="test-token",
    )


@pytest.fixture
def elastic_config():
    """Create an Elasticsearch config."""
    return ElasticConfig(
        name="elastic_test",
        webhook_url="https://elasticsearch.example.com:9200",
        api_key="elastic-api-key",
        index_pattern="purplesploit-findings",
        verify_ssl=True,
    )


@pytest.fixture
def elastic_config_with_id_secret():
    """Create an Elasticsearch config with API key ID and secret."""
    return ElasticConfig(
        name="elastic_id_secret",
        webhook_url="https://elastic.example.com:9200",
        api_key_id="key-id",
        api_key_secret="key-secret",
        index_pattern="security-findings",
    )


@pytest.fixture
def notification_payload():
    """Create a sample notification payload."""
    return NotificationPayload(
        title="Unauthorized Access Attempt",
        message="Multiple failed login attempts detected from 192.168.1.50",
        priority=NotificationPriority.HIGH,
        severity="high",
        target="auth-server.example.com",
        finding_id="ALERT-001",
        cvss_score=7.0,
        tags=["brute-force", "authentication"],
        extra_data={"attempts": 50, "timeframe": "5 minutes"},
    )


@pytest.fixture
def critical_payload():
    """Create a critical notification payload."""
    return NotificationPayload(
        title="Active Intrusion Detected",
        message="Malicious activity detected on production server",
        priority=NotificationPriority.CRITICAL,
        severity="critical",
        target="prod-server-01",
        finding_id="INTRUSION-001",
        cvss_score=10.0,
    )


@pytest.fixture
def minimal_payload():
    """Create a minimal notification payload."""
    return NotificationPayload(
        title="Info Event",
        message="Informational event",
    )


@pytest.fixture
def siem_webhook(siem_config):
    """Create a SIEM webhook integration."""
    return SIEMWebhook(siem_config)


@pytest.fixture
def splunk_integration(splunk_config):
    """Create a Splunk integration."""
    return SplunkIntegration(splunk_config)


@pytest.fixture
def elastic_integration(elastic_config):
    """Create an Elasticsearch integration."""
    return ElasticIntegration(elastic_config)


# =============================================================================
# SIEMConfig Tests
# =============================================================================

class TestSIEMConfig:
    """Tests for SIEMConfig dataclass."""

    def test_config_default_values(self):
        """Test default values for SIEMConfig."""
        config = SIEMConfig(name="test")
        assert config.webhook_url == ""
        assert config.source_type == "purplesploit"
        assert config.index == "security"
        assert config.verify_ssl is True
        assert config.custom_headers == {}

    def test_config_with_custom_headers(self, siem_config):
        """Test config with custom headers."""
        assert "X-API-Key" in siem_config.custom_headers
        assert siem_config.custom_headers["X-API-Key"] == "test-key"

    def test_config_ssl_disabled(self, siem_config_no_ssl):
        """Test config with SSL verification disabled."""
        assert siem_config_no_ssl.verify_ssl is False


# =============================================================================
# SIEMWebhook Initialization Tests
# =============================================================================

class TestSIEMWebhookInit:
    """Tests for SIEMWebhook initialization."""

    def test_init_with_config(self, siem_config):
        """Test initialization with config."""
        webhook = SIEMWebhook(siem_config)
        assert webhook.config == siem_config
        assert webhook.siem_config == siem_config

    def test_init_without_config(self):
        """Test initialization without config creates default."""
        webhook = SIEMWebhook()
        assert webhook.config is not None
        assert webhook.config.name == "siem_webhook"

    def test_init_status_disconnected(self, siem_webhook):
        """Test initial status is DISCONNECTED."""
        assert siem_webhook.status == IntegrationStatus.DISCONNECTED


# =============================================================================
# SIEMWebhook connect() Tests
# =============================================================================

class TestSIEMWebhookConnect:
    """Tests for SIEMWebhook connect() method."""

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_connect_success(self, siem_webhook):
        """Test successful connection."""
        result = siem_webhook.connect()
        assert result is True
        assert siem_webhook.status == IntegrationStatus.CONNECTED

    def test_connect_no_url_fails(self):
        """Test connection fails without webhook URL."""
        config = SIEMConfig(name="test")
        webhook = SIEMWebhook(config)
        result = webhook.connect()
        assert result is False
        assert webhook.status == IntegrationStatus.ERROR

    def test_connect_requests_not_available(self, siem_config):
        """Test connection fails when requests not available."""
        with patch('purplesploit.integrations.siem.REQUESTS_AVAILABLE', False):
            webhook = SIEMWebhook(siem_config)
            result = webhook.connect()
            assert result is False
            assert webhook.status == IntegrationStatus.ERROR


# =============================================================================
# SIEMWebhook test_connection() Tests
# =============================================================================

class TestSIEMWebhookTestConnection:
    """Tests for SIEMWebhook test_connection() method."""

    def test_test_connection_requests_not_available(self, siem_webhook):
        """Test connection test fails when requests not available."""
        with patch('purplesploit.integrations.siem.REQUESTS_AVAILABLE', False):
            result = siem_webhook.test_connection()
            assert result["success"] is False

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_test_connection_success(self, siem_webhook):
        """Test successful connection test."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            result = siem_webhook.test_connection()
            assert result["success"] is True
            assert result["status_code"] == 200

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_test_connection_accepts_various_codes(self, siem_webhook):
        """Test connection accepts 200, 201, 202, 204 status codes."""
        for code in [200, 201, 202, 204]:
            with patch('purplesploit.integrations.siem.requests') as mock_requests:
                mock_response = MagicMock()
                mock_response.status_code = code
                mock_requests.post.return_value = mock_response

                result = siem_webhook.test_connection()
                assert result["success"] is True

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_test_connection_failure(self, siem_webhook):
        """Test failed connection test."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 500
            mock_response.text = "Internal Server Error"
            mock_requests.post.return_value = mock_response

            result = siem_webhook.test_connection()
            assert result["success"] is False


# =============================================================================
# SIEMWebhook _get_headers() Tests
# =============================================================================

class TestSIEMWebhookGetHeaders:
    """Tests for SIEMWebhook _get_headers() method."""

    def test_get_headers_includes_content_type(self, siem_webhook):
        """Test headers include Content-Type."""
        headers = siem_webhook._get_headers()
        assert headers["Content-Type"] == "application/json"

    def test_get_headers_includes_user_agent(self, siem_webhook):
        """Test headers include User-Agent."""
        headers = siem_webhook._get_headers()
        assert headers["User-Agent"] == "PurpleSploit/1.0"

    def test_get_headers_includes_custom_headers(self, siem_webhook):
        """Test headers include custom headers from config."""
        headers = siem_webhook._get_headers()
        assert "X-API-Key" in headers
        assert headers["X-API-Key"] == "test-key"


# =============================================================================
# SIEMWebhook send_notification() Tests
# =============================================================================

class TestSIEMWebhookSendNotification:
    """Tests for SIEMWebhook send_notification() method."""

    def test_send_notification_requests_not_available(
        self, siem_webhook, notification_payload
    ):
        """Test notification fails when requests not available."""
        with patch('purplesploit.integrations.siem.REQUESTS_AVAILABLE', False):
            result = siem_webhook.send_notification(notification_payload)
            assert result["success"] is False

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_notification_success(
        self, siem_webhook, notification_payload
    ):
        """Test successful notification."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            result = siem_webhook.send_notification(notification_payload)
            assert result["success"] is True

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_notification_rate_limited(
        self, siem_webhook, notification_payload
    ):
        """Test notification respects rate limiting."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            # Send up to rate limit
            for _ in range(siem_webhook.config.rate_limit):
                siem_webhook.send_notification(notification_payload)

            # Next should be rate limited
            result = siem_webhook.send_notification(notification_payload)
            assert result["success"] is False
            assert "Rate limited" in result["error"]


# =============================================================================
# SIEMWebhook _build_event() Tests
# =============================================================================

class TestSIEMWebhookBuildEvent:
    """Tests for SIEMWebhook _build_event() method."""

    def test_build_event_structure(self, siem_webhook, notification_payload):
        """Test event structure."""
        event = siem_webhook._build_event(notification_payload)

        assert event["event_type"] == "security_finding"
        assert event["source"] == notification_payload.source
        assert event["sourcetype"] == siem_webhook.siem_config.source_type
        assert "timestamp" in event
        assert event["title"] == notification_payload.title
        assert event["message"] == notification_payload.message

    def test_build_event_includes_severity(self, siem_webhook, notification_payload):
        """Test event includes severity."""
        event = siem_webhook._build_event(notification_payload)
        assert event["severity"] == "high"

    def test_build_event_includes_priority(self, siem_webhook, notification_payload):
        """Test event includes priority value."""
        event = siem_webhook._build_event(notification_payload)
        assert event["priority"] == "high"

    def test_build_event_includes_target(self, siem_webhook, notification_payload):
        """Test event includes target."""
        event = siem_webhook._build_event(notification_payload)
        assert event["target"] == "auth-server.example.com"

    def test_build_event_includes_finding_id(self, siem_webhook, notification_payload):
        """Test event includes finding ID."""
        event = siem_webhook._build_event(notification_payload)
        assert event["finding_id"] == "ALERT-001"

    def test_build_event_includes_cvss(self, siem_webhook, notification_payload):
        """Test event includes CVSS score."""
        event = siem_webhook._build_event(notification_payload)
        assert event["cvss_score"] == 7.0

    def test_build_event_includes_tags(self, siem_webhook, notification_payload):
        """Test event includes tags."""
        event = siem_webhook._build_event(notification_payload)
        assert "brute-force" in event["tags"]

    def test_build_event_includes_extra_data(self, siem_webhook, notification_payload):
        """Test event includes extra data."""
        event = siem_webhook._build_event(notification_payload)
        assert event["extra_data"]["attempts"] == 50


# =============================================================================
# SIEMWebhook send_finding() Tests
# =============================================================================

class TestSIEMWebhookSendFinding:
    """Tests for SIEMWebhook send_finding() convenience method."""

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_finding_success(self, siem_webhook):
        """Test sending a finding."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            result = siem_webhook.send_finding(
                title="Test Finding",
                description="Test description",
                severity="high",
                target="192.168.1.1",
                finding_id="FIND-001",
                cvss_score=7.5,
                tags=["test"],
                extra_data={"key": "value"},
            )
            assert result["success"] is True


# =============================================================================
# SIEMWebhook send_scan_event() Tests
# =============================================================================

class TestSIEMWebhookSendScanEvent:
    """Tests for SIEMWebhook send_scan_event() method."""

    def test_send_scan_event_requests_not_available(self, siem_webhook):
        """Test scan event fails when requests not available."""
        with patch('purplesploit.integrations.siem.REQUESTS_AVAILABLE', False):
            result = siem_webhook.send_scan_event(
                event_type="scan_started",
                scan_name="nmap",
                target="192.168.1.0/24",
                status="running",
            )
            assert result["success"] is False

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_scan_event_success(self, siem_webhook):
        """Test successful scan event."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            result = siem_webhook.send_scan_event(
                event_type="scan_completed",
                scan_name="nmap",
                target="192.168.1.0/24",
                status="completed",
                details={"hosts_found": 10, "ports_open": 25},
            )
            assert result["success"] is True


# =============================================================================
# SplunkConfig Tests
# =============================================================================

class TestSplunkConfig:
    """Tests for SplunkConfig dataclass."""

    def test_config_default_values(self):
        """Test default values for SplunkConfig."""
        config = SplunkConfig(name="test")
        assert config.hec_token == ""
        assert config.hec_url == ""

    def test_config_with_hec_settings(self, splunk_config):
        """Test config with HEC settings."""
        assert splunk_config.hec_token is not None
        assert "collector" in splunk_config.hec_url


# =============================================================================
# SplunkIntegration Tests
# =============================================================================

class TestSplunkIntegrationInit:
    """Tests for SplunkIntegration initialization."""

    def test_init_with_config(self, splunk_config):
        """Test initialization with config."""
        integration = SplunkIntegration(splunk_config)
        assert integration.splunk_config == splunk_config

    def test_init_without_config(self):
        """Test initialization without config creates default."""
        integration = SplunkIntegration()
        assert integration.config.name == "splunk"


class TestSplunkIntegrationConnect:
    """Tests for SplunkIntegration connect() method."""

    def test_connect_no_endpoint_fails(self):
        """Test connection fails without HEC URL."""
        config = SplunkConfig(name="test", hec_token="token")
        integration = SplunkIntegration(config)
        result = integration.connect()
        assert result is False

    def test_connect_no_token_fails(self):
        """Test connection fails without HEC token."""
        config = SplunkConfig(name="test", hec_url="https://splunk:8088/services/collector")
        integration = SplunkIntegration(config)
        result = integration.connect()
        assert result is False

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_connect_success(self, splunk_integration):
        """Test successful connection."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.get.return_value = mock_response

            result = splunk_integration.connect()
            assert result is True


class TestSplunkIntegrationGetHeaders:
    """Tests for SplunkIntegration _get_headers() method."""

    def test_get_headers_includes_splunk_auth(self, splunk_integration):
        """Test headers include Splunk authorization."""
        headers = splunk_integration._get_headers()
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Splunk ")
        assert splunk_integration.splunk_config.hec_token in headers["Authorization"]


class TestSplunkIntegrationEndpoint:
    """Tests for SplunkIntegration _endpoint property."""

    def test_endpoint_uses_hec_url(self, splunk_integration):
        """Test endpoint uses hec_url."""
        assert splunk_integration._endpoint == splunk_integration.splunk_config.hec_url

    def test_endpoint_fallback_to_webhook_url(self, splunk_config_webhook):
        """Test endpoint falls back to webhook_url."""
        integration = SplunkIntegration(splunk_config_webhook)
        assert integration._endpoint == splunk_config_webhook.webhook_url


class TestSplunkIntegrationTestConnection:
    """Tests for SplunkIntegration test_connection() method."""

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_test_connection_health_check(self, splunk_integration):
        """Test connection test uses health endpoint."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.get.return_value = mock_response

            result = splunk_integration.test_connection()
            assert result["success"] is True
            assert result["status"] == "healthy"

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_test_connection_fallback_to_test_event(self, splunk_integration):
        """Test connection falls back to test event on health failure."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            # Health check fails
            health_response = MagicMock()
            health_response.status_code = 404

            # Test event succeeds
            event_response = MagicMock()
            event_response.status_code = 200

            mock_requests.get.return_value = health_response
            mock_requests.post.return_value = event_response

            result = splunk_integration.test_connection()
            assert result["success"] is True
            assert result["status"] == "test_event_sent"


class TestSplunkIntegrationSendNotification:
    """Tests for SplunkIntegration send_notification() method."""

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_notification_hec_format(
        self, splunk_integration, notification_payload
    ):
        """Test notification uses Splunk HEC format."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            result = splunk_integration.send_notification(notification_payload)
            assert result["success"] is True

            # Verify HEC format was used
            call_args = mock_requests.post.call_args
            payload = call_args.kwargs.get('json', call_args[1].get('json'))
            assert "event" in payload
            assert "sourcetype" in payload
            assert "index" in payload
            assert "time" in payload


class TestSplunkIntegrationSendBatch:
    """Tests for SplunkIntegration send_batch() method."""

    def test_send_batch_requests_not_available(self, splunk_integration):
        """Test batch send fails when requests not available."""
        with patch('purplesploit.integrations.siem.REQUESTS_AVAILABLE', False):
            events = [
                NotificationPayload(title="Event 1", message="msg1"),
                NotificationPayload(title="Event 2", message="msg2"),
            ]
            result = splunk_integration.send_batch(events)
            assert result["success"] is False

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_batch_success(self, splunk_integration):
        """Test successful batch send."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            events = [
                NotificationPayload(title="Event 1", message="msg1"),
                NotificationPayload(title="Event 2", message="msg2"),
                NotificationPayload(title="Event 3", message="msg3"),
            ]
            result = splunk_integration.send_batch(events)
            assert result["success"] is True
            assert result["events_sent"] == 3


# =============================================================================
# ElasticConfig Tests
# =============================================================================

class TestElasticConfig:
    """Tests for ElasticConfig dataclass."""

    def test_config_default_values(self):
        """Test default values for ElasticConfig."""
        config = ElasticConfig(name="test")
        assert config.cloud_id is None
        assert config.api_key_id is None
        assert config.api_key_secret is None
        assert config.index_pattern == "purplesploit-findings"

    def test_config_with_api_key_id_secret(self, elastic_config_with_id_secret):
        """Test config with API key ID and secret."""
        assert elastic_config_with_id_secret.api_key_id == "key-id"
        assert elastic_config_with_id_secret.api_key_secret == "key-secret"


# =============================================================================
# ElasticIntegration Tests
# =============================================================================

class TestElasticIntegrationInit:
    """Tests for ElasticIntegration initialization."""

    def test_init_with_config(self, elastic_config):
        """Test initialization with config."""
        integration = ElasticIntegration(elastic_config)
        assert integration.elastic_config == elastic_config

    def test_init_without_config(self):
        """Test initialization without config creates default."""
        integration = ElasticIntegration()
        assert integration.config.name == "elasticsearch"


class TestElasticIntegrationGetHeaders:
    """Tests for ElasticIntegration _get_headers() method."""

    def test_get_headers_with_api_key(self, elastic_integration):
        """Test headers include API key authorization."""
        headers = elastic_integration._get_headers()
        assert "Authorization" in headers
        assert "ApiKey" in headers["Authorization"]

    def test_get_headers_with_id_secret(self, elastic_config_with_id_secret):
        """Test headers use ID:secret format."""
        integration = ElasticIntegration(elastic_config_with_id_secret)
        headers = integration._get_headers()
        assert "Authorization" in headers
        assert "ApiKey" in headers["Authorization"]


class TestElasticIntegrationBaseUrl:
    """Tests for ElasticIntegration _base_url property."""

    def test_base_url_strips_trailing_slash(self):
        """Test base URL strips trailing slash."""
        config = ElasticConfig(
            name="test",
            webhook_url="https://elastic.example.com:9200/"
        )
        integration = ElasticIntegration(config)
        assert integration._base_url == "https://elastic.example.com:9200"


class TestElasticIntegrationConnect:
    """Tests for ElasticIntegration connect() method."""

    def test_connect_no_url_fails(self):
        """Test connection fails without URL."""
        config = ElasticConfig(name="test")
        integration = ElasticIntegration(config)
        result = integration.connect()
        assert result is False

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_connect_success(self, elastic_integration):
        """Test successful connection."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "cluster_name": "test-cluster",
                "version": {"number": "8.10.0"}
            }
            mock_requests.get.return_value = mock_response

            result = elastic_integration.connect()
            assert result is True


class TestElasticIntegrationTestConnection:
    """Tests for ElasticIntegration test_connection() method."""

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_test_connection_success(self, elastic_integration):
        """Test successful connection test."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "cluster_name": "security-cluster",
                "version": {"number": "8.10.0"}
            }
            mock_requests.get.return_value = mock_response

            result = elastic_integration.test_connection()
            assert result["success"] is True
            assert result["cluster_name"] == "security-cluster"
            assert result["version"] == "8.10.0"


class TestElasticIntegrationSendNotification:
    """Tests for ElasticIntegration send_notification() method."""

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_notification_success(
        self, elastic_integration, notification_payload
    ):
        """Test successful notification."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 201
            mock_response.json.return_value = {
                "_index": "purplesploit-findings-2024.01.15",
                "_id": "abc123"
            }
            mock_requests.post.return_value = mock_response

            result = elastic_integration.send_notification(notification_payload)
            assert result["success"] is True
            assert "index" in result
            assert "id" in result

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_notification_includes_timestamp(
        self, elastic_integration, notification_payload
    ):
        """Test notification includes @timestamp field."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 201
            mock_response.json.return_value = {"_index": "test", "_id": "123"}
            mock_requests.post.return_value = mock_response

            elastic_integration.send_notification(notification_payload)

            # Verify @timestamp is in the payload
            call_args = mock_requests.post.call_args
            payload = call_args.kwargs.get('json', call_args[1].get('json'))
            assert "@timestamp" in payload


class TestElasticIntegrationSendBulk:
    """Tests for ElasticIntegration send_bulk() method."""

    def test_send_bulk_requests_not_available(self, elastic_integration):
        """Test bulk send fails when requests not available."""
        with patch('purplesploit.integrations.siem.REQUESTS_AVAILABLE', False):
            events = [NotificationPayload(title="Event", message="msg")]
            result = elastic_integration.send_bulk(events)
            assert result["success"] is False

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_bulk_success(self, elastic_integration):
        """Test successful bulk send."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"errors": False}
            mock_requests.post.return_value = mock_response

            events = [
                NotificationPayload(title="Event 1", message="msg1"),
                NotificationPayload(title="Event 2", message="msg2"),
            ]
            result = elastic_integration.send_bulk(events)
            assert result["success"] is True
            assert result["events_sent"] == 2

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_send_bulk_with_errors(self, elastic_integration):
        """Test bulk send with errors."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"errors": True}
            mock_requests.post.return_value = mock_response

            events = [NotificationPayload(title="Event", message="msg")]
            result = elastic_integration.send_bulk(events)
            assert result["success"] is False
            assert result["errors"] is True


class TestElasticIntegrationSearchFindings:
    """Tests for ElasticIntegration search_findings() method."""

    def test_search_requests_not_available(self, elastic_integration):
        """Test search fails when requests not available."""
        with patch('purplesploit.integrations.siem.REQUESTS_AVAILABLE', False):
            result = elastic_integration.search_findings()
            assert result["success"] is False

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_search_findings_success(self, elastic_integration):
        """Test successful search."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "hits": {
                    "total": {"value": 2},
                    "hits": [
                        {"_source": {"title": "Finding 1", "severity": "high"}},
                        {"_source": {"title": "Finding 2", "severity": "medium"}},
                    ]
                }
            }
            mock_requests.post.return_value = mock_response

            result = elastic_integration.search_findings()
            assert result["success"] is True
            assert result["total"] == 2
            assert len(result["findings"]) == 2

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_search_findings_with_query(self, elastic_integration):
        """Test search with query string."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
            mock_requests.post.return_value = mock_response

            result = elastic_integration.search_findings(query="sql injection")
            assert result["success"] is True

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_search_findings_by_severity(self, elastic_integration):
        """Test search by severity."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
            mock_requests.post.return_value = mock_response

            result = elastic_integration.search_findings(severity="critical")
            assert result["success"] is True

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_search_findings_by_target(self, elastic_integration):
        """Test search by target."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
            mock_requests.post.return_value = mock_response

            result = elastic_integration.search_findings(target="192.168.1.100")
            assert result["success"] is True

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_search_findings_from_date(self, elastic_integration):
        """Test search with from_date filter."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
            mock_requests.post.return_value = mock_response

            from_date = datetime.utcnow() - timedelta(days=7)
            result = elastic_integration.search_findings(from_date=from_date)
            assert result["success"] is True


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestSIEMErrorHandling:
    """Tests for error handling across SIEM integrations."""

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_siem_webhook_exception(self, siem_webhook, notification_payload):
        """Test exception handling in SIEM webhook."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            mock_requests.post.side_effect = Exception("Network error")

            result = siem_webhook.send_notification(notification_payload)
            assert result["success"] is False

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_splunk_exception(self, splunk_integration, notification_payload):
        """Test exception handling in Splunk integration."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            mock_requests.post.side_effect = Exception("Connection refused")

            result = splunk_integration.send_notification(notification_payload)
            assert result["success"] is False

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_elastic_exception(self, elastic_integration, notification_payload):
        """Test exception handling in Elasticsearch integration."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            mock_requests.post.side_effect = Exception("Timeout")

            result = elastic_integration.send_notification(notification_payload)
            assert result["success"] is False


# =============================================================================
# Integration Tests
# =============================================================================

class TestSIEMIntegrationWorkflows:
    """Integration tests for complete workflows."""

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_siem_webhook_workflow(self, siem_webhook, notification_payload):
        """Test complete SIEM webhook workflow."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            # Connect
            assert siem_webhook.connect() is True

            # Send notification
            result = siem_webhook.send_notification(notification_payload)
            assert result["success"] is True

            # Disconnect
            assert siem_webhook.disconnect() is True

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_splunk_workflow(self, splunk_integration, notification_payload):
        """Test complete Splunk workflow."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {}
            mock_requests.get.return_value = mock_response
            mock_requests.post.return_value = mock_response

            # Connect
            assert splunk_integration.connect() is True

            # Send notification
            result = splunk_integration.send_notification(notification_payload)
            assert result["success"] is True

            # Disconnect
            assert splunk_integration.disconnect() is True

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    def test_elastic_workflow(self, elastic_integration, notification_payload):
        """Test complete Elasticsearch workflow."""
        with patch('purplesploit.integrations.siem.requests') as mock_requests:
            get_response = MagicMock()
            get_response.status_code = 200
            get_response.json.return_value = {
                "cluster_name": "test",
                "version": {"number": "8.10.0"}
            }

            post_response = MagicMock()
            post_response.status_code = 201
            post_response.json.return_value = {"_index": "test", "_id": "123"}

            mock_requests.get.return_value = get_response
            mock_requests.post.return_value = post_response

            # Connect
            assert elastic_integration.connect() is True

            # Send notification
            result = elastic_integration.send_notification(notification_payload)
            assert result["success"] is True

            # Disconnect
            assert elastic_integration.disconnect() is True
