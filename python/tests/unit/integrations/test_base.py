"""
Unit tests for purplesploit.integrations.base module.

Tests cover:
- IntegrationStatus enum
- NotificationPriority enum
- IntegrationConfig dataclass
- NotificationPayload dataclass (including to_dict serialization)
- BaseIntegration ABC (properties, rate limiting, error handling, status)
- WebhookMixin (_build_webhook_payload, _get_severity_color)
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from typing import Dict, Any

from purplesploit.integrations.base import (
    IntegrationStatus,
    NotificationPriority,
    IntegrationConfig,
    NotificationPayload,
    BaseIntegration,
    WebhookMixin,
)


# =============================================================================
# Concrete Implementations for Testing ABCs
# =============================================================================

class ConcreteTestIntegration(BaseIntegration):
    """Concrete implementation for testing BaseIntegration ABC."""

    def __init__(self, config: IntegrationConfig):
        super().__init__(config)
        self.connect_called = False
        self.disconnect_called = False
        self.test_connection_called = False
        self.send_notification_called = False
        self.last_payload = None

    def connect(self) -> bool:
        self.connect_called = True
        self.status = IntegrationStatus.CONNECTED
        return True

    def disconnect(self) -> bool:
        self.disconnect_called = True
        self.status = IntegrationStatus.DISCONNECTED
        return True

    def test_connection(self) -> Dict[str, Any]:
        self.test_connection_called = True
        return {"success": True, "latency_ms": 50}

    def send_notification(self, payload: NotificationPayload) -> Dict[str, Any]:
        self.send_notification_called = True
        self.last_payload = payload
        if not self._check_rate_limit():
            return {"success": False, "error": "Rate limited"}
        self._record_request()
        return {"success": True, "id": "test-123"}


class WebhookTestIntegration(BaseIntegration, WebhookMixin):
    """Test implementation combining BaseIntegration with WebhookMixin."""

    def connect(self) -> bool:
        self.status = IntegrationStatus.CONNECTED
        return True

    def disconnect(self) -> bool:
        self.status = IntegrationStatus.DISCONNECTED
        return True

    def test_connection(self) -> Dict[str, Any]:
        return {"success": True}

    def send_notification(self, payload: NotificationPayload) -> Dict[str, Any]:
        webhook_payload = self._build_webhook_payload(payload)
        return {"success": True, "payload": webhook_payload}


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def integration_config():
    """Create a basic IntegrationConfig for testing."""
    return IntegrationConfig(
        name="test_integration",
        enabled=True,
        api_key="test-api-key",
        api_url="https://api.example.com",
    )


@pytest.fixture
def disabled_config():
    """Create a disabled IntegrationConfig for testing."""
    return IntegrationConfig(name="disabled_integration", enabled=False)


@pytest.fixture
def notification_payload():
    """Create a sample NotificationPayload for testing."""
    return NotificationPayload(
        title="Test Alert",
        message="This is a test notification",
        priority=NotificationPriority.HIGH,
        finding_id="FINDING-001",
        target="192.168.1.100",
        severity="high",
        cvss_score=7.5,
        tags=["test", "vulnerability"],
    )


@pytest.fixture
def minimal_payload():
    """Create a minimal NotificationPayload for testing."""
    return NotificationPayload(
        title="Minimal Alert",
        message="Minimal message",
    )


@pytest.fixture
def concrete_integration(integration_config):
    """Create a concrete test integration instance."""
    return ConcreteTestIntegration(integration_config)


@pytest.fixture
def webhook_integration(integration_config):
    """Create a webhook test integration instance."""
    return WebhookTestIntegration(integration_config)


# =============================================================================
# IntegrationStatus Enum Tests
# =============================================================================

class TestIntegrationStatus:
    """Tests for IntegrationStatus enum."""

    def test_connected_value(self):
        """Test CONNECTED value."""
        assert IntegrationStatus.CONNECTED.value == "connected"

    def test_disconnected_value(self):
        """Test DISCONNECTED value."""
        assert IntegrationStatus.DISCONNECTED.value == "disconnected"

    def test_error_value(self):
        """Test ERROR value."""
        assert IntegrationStatus.ERROR.value == "error"

    def test_rate_limited_value(self):
        """Test RATE_LIMITED value."""
        assert IntegrationStatus.RATE_LIMITED.value == "rate_limited"

    def test_enum_count(self):
        """Test total enum members."""
        statuses = list(IntegrationStatus)
        assert len(statuses) == 4

    def test_enum_from_value(self):
        """Test creating enum from string value."""
        assert IntegrationStatus("connected") == IntegrationStatus.CONNECTED
        assert IntegrationStatus("error") == IntegrationStatus.ERROR


# =============================================================================
# NotificationPriority Enum Tests
# =============================================================================

class TestNotificationPriority:
    """Tests for NotificationPriority enum."""

    def test_low_value(self):
        """Test LOW value."""
        assert NotificationPriority.LOW.value == "low"

    def test_medium_value(self):
        """Test MEDIUM value."""
        assert NotificationPriority.MEDIUM.value == "medium"

    def test_high_value(self):
        """Test HIGH value."""
        assert NotificationPriority.HIGH.value == "high"

    def test_critical_value(self):
        """Test CRITICAL value."""
        assert NotificationPriority.CRITICAL.value == "critical"

    def test_enum_count(self):
        """Test total enum members."""
        priorities = list(NotificationPriority)
        assert len(priorities) == 4

    def test_enum_from_value(self):
        """Test creating enum from string value."""
        assert NotificationPriority("high") == NotificationPriority.HIGH


# =============================================================================
# IntegrationConfig Dataclass Tests
# =============================================================================

class TestIntegrationConfig:
    """Tests for IntegrationConfig dataclass."""

    def test_config_creation_minimal(self):
        """Test creating config with only required field."""
        config = IntegrationConfig(name="test")
        assert config.name == "test"
        assert config.enabled is True
        assert config.api_key is None
        assert config.api_url is None
        assert config.timeout == 30
        assert config.retry_count == 3
        assert config.rate_limit == 60
        assert config.extra_config == {}

    def test_config_creation_full(self, integration_config):
        """Test creating config with all fields."""
        assert integration_config.name == "test_integration"
        assert integration_config.enabled is True
        assert integration_config.api_key == "test-api-key"
        assert integration_config.api_url == "https://api.example.com"

    def test_config_default_enabled(self):
        """Test default enabled value is True."""
        config = IntegrationConfig(name="test")
        assert config.enabled is True

    def test_config_default_api_key(self):
        """Test default api_key is None."""
        config = IntegrationConfig(name="test")
        assert config.api_key is None

    def test_config_default_api_url(self):
        """Test default api_url is None."""
        config = IntegrationConfig(name="test")
        assert config.api_url is None

    def test_config_default_timeout(self):
        """Test default timeout is 30."""
        config = IntegrationConfig(name="test")
        assert config.timeout == 30

    def test_config_default_retry_count(self):
        """Test default retry_count is 3."""
        config = IntegrationConfig(name="test")
        assert config.retry_count == 3

    def test_config_default_rate_limit(self):
        """Test default rate_limit is 60."""
        config = IntegrationConfig(name="test")
        assert config.rate_limit == 60

    def test_config_extra_config_mutable_default(self):
        """Test extra_config mutable default isolation."""
        config1 = IntegrationConfig(name="test1")
        config2 = IntegrationConfig(name="test2")
        config1.extra_config["key"] = "value"
        assert "key" not in config2.extra_config

    def test_config_with_custom_extra_config(self):
        """Test config with custom extra_config."""
        config = IntegrationConfig(
            name="test",
            extra_config={"webhook_url": "https://hook.example.com"},
        )
        assert config.extra_config["webhook_url"] == "https://hook.example.com"


# =============================================================================
# NotificationPayload Dataclass Tests
# =============================================================================

class TestNotificationPayload:
    """Tests for NotificationPayload dataclass."""

    def test_payload_creation_minimal(self, minimal_payload):
        """Test creating payload with minimal fields."""
        assert minimal_payload.title == "Minimal Alert"
        assert minimal_payload.message == "Minimal message"

    def test_payload_creation_full(self, notification_payload):
        """Test creating payload with all fields."""
        assert notification_payload.title == "Test Alert"
        assert notification_payload.priority == NotificationPriority.HIGH
        assert notification_payload.cvss_score == 7.5

    def test_payload_default_priority(self, minimal_payload):
        """Test default priority is MEDIUM."""
        assert minimal_payload.priority == NotificationPriority.MEDIUM

    def test_payload_default_source(self, minimal_payload):
        """Test default source is 'purplesploit'."""
        assert minimal_payload.source == "purplesploit"

    def test_payload_default_timestamp(self, minimal_payload):
        """Test default timestamp is datetime."""
        assert isinstance(minimal_payload.timestamp, datetime)

    def test_payload_default_finding_id(self, minimal_payload):
        """Test default finding_id is None."""
        assert minimal_payload.finding_id is None

    def test_payload_default_target(self, minimal_payload):
        """Test default target is None."""
        assert minimal_payload.target is None

    def test_payload_default_severity(self, minimal_payload):
        """Test default severity is None."""
        assert minimal_payload.severity is None

    def test_payload_default_cvss_score(self, minimal_payload):
        """Test default cvss_score is None."""
        assert minimal_payload.cvss_score is None

    def test_payload_default_tags(self, minimal_payload):
        """Test default tags is empty list."""
        assert minimal_payload.tags == []

    def test_payload_default_extra_data(self, minimal_payload):
        """Test default extra_data is empty dict."""
        assert minimal_payload.extra_data == {}

    def test_payload_tags_mutable_default(self):
        """Test tags list isolation between instances."""
        p1 = NotificationPayload(title="Test1", message="msg")
        p2 = NotificationPayload(title="Test2", message="msg")
        p1.tags.append("tag1")
        assert "tag1" not in p2.tags

    def test_payload_extra_data_mutable_default(self):
        """Test extra_data dict isolation between instances."""
        p1 = NotificationPayload(title="Test1", message="msg")
        p2 = NotificationPayload(title="Test2", message="msg")
        p1.extra_data["key"] = "value"
        assert "key" not in p2.extra_data


class TestNotificationPayloadToDict:
    """Tests for NotificationPayload.to_dict() method."""

    def test_to_dict_all_fields(self, notification_payload):
        """Test to_dict includes all fields."""
        data = notification_payload.to_dict()
        expected_keys = [
            "title", "message", "priority", "source", "timestamp",
            "finding_id", "target", "severity", "cvss_score", "tags",
            "extra_data",
        ]
        for key in expected_keys:
            assert key in data

    def test_to_dict_priority_serialized(self, notification_payload):
        """Test priority is serialized as string value."""
        data = notification_payload.to_dict()
        assert data["priority"] == "high"
        assert isinstance(data["priority"], str)

    def test_to_dict_timestamp_iso(self, notification_payload):
        """Test timestamp is serialized as ISO string."""
        data = notification_payload.to_dict()
        assert isinstance(data["timestamp"], str)
        # Should be parseable
        datetime.fromisoformat(data["timestamp"])

    def test_to_dict_none_values(self, minimal_payload):
        """Test None values are preserved."""
        data = minimal_payload.to_dict()
        assert data["finding_id"] is None
        assert data["target"] is None
        assert data["severity"] is None
        assert data["cvss_score"] is None

    def test_to_dict_tags_list(self, notification_payload):
        """Test tags list is preserved."""
        data = notification_payload.to_dict()
        assert isinstance(data["tags"], list)
        assert "test" in data["tags"]

    def test_to_dict_with_all_priorities(self):
        """Test serialization of all priority values."""
        for priority in NotificationPriority:
            payload = NotificationPayload(
                title="Test", message="msg", priority=priority
            )
            data = payload.to_dict()
            assert data["priority"] == priority.value


# =============================================================================
# BaseIntegration ABC Tests
# =============================================================================

class TestBaseIntegrationInit:
    """Tests for BaseIntegration initialization."""

    def test_init_sets_config(self, concrete_integration, integration_config):
        """Test __init__ sets config attribute."""
        assert concrete_integration.config == integration_config

    def test_init_initial_status(self, concrete_integration):
        """Test initial status is DISCONNECTED."""
        # Reset to initial state
        integration = ConcreteTestIntegration(
            IntegrationConfig(name="test")
        )
        assert integration.status == IntegrationStatus.DISCONNECTED

    def test_init_initial_request_count(self, concrete_integration):
        """Test initial request count is 0."""
        integration = ConcreteTestIntegration(
            IntegrationConfig(name="test")
        )
        assert integration._request_count == 0

    def test_init_initial_last_request_time(self, concrete_integration):
        """Test initial last request time is None."""
        integration = ConcreteTestIntegration(
            IntegrationConfig(name="test")
        )
        assert integration._last_request_time is None

    def test_init_initial_error_message(self, concrete_integration):
        """Test initial error message is None."""
        integration = ConcreteTestIntegration(
            IntegrationConfig(name="test")
        )
        assert integration._error_message is None

    def test_cannot_instantiate_abstract_class(self, integration_config):
        """Test BaseIntegration cannot be instantiated directly."""
        with pytest.raises(TypeError):
            BaseIntegration(integration_config)


class TestBaseIntegrationProperties:
    """Tests for BaseIntegration properties."""

    def test_name_property(self, concrete_integration, integration_config):
        """Test name property returns config name."""
        assert concrete_integration.name == integration_config.name

    def test_is_enabled_property_true(self, concrete_integration):
        """Test is_enabled returns True when enabled."""
        assert concrete_integration.is_enabled is True

    def test_is_enabled_property_false(self, disabled_config):
        """Test is_enabled returns False when disabled."""
        integration = ConcreteTestIntegration(disabled_config)
        assert integration.is_enabled is False

    def test_is_connected_property_connected(self, concrete_integration):
        """Test is_connected when CONNECTED."""
        concrete_integration.status = IntegrationStatus.CONNECTED
        assert concrete_integration.is_connected is True

    def test_is_connected_property_disconnected(self, concrete_integration):
        """Test is_connected when DISCONNECTED."""
        concrete_integration.status = IntegrationStatus.DISCONNECTED
        assert concrete_integration.is_connected is False

    def test_is_connected_property_error(self, concrete_integration):
        """Test is_connected when ERROR."""
        concrete_integration.status = IntegrationStatus.ERROR
        assert concrete_integration.is_connected is False


class TestBaseIntegrationRateLimiting:
    """Tests for BaseIntegration rate limiting methods."""

    def test_check_rate_limit_no_previous_request(self, concrete_integration):
        """Test first request passes rate limit check."""
        result = concrete_integration._check_rate_limit()
        assert result is True

    def test_check_rate_limit_within_limit(self, concrete_integration):
        """Test under rate limit passes."""
        concrete_integration._last_request_time = datetime.utcnow()
        concrete_integration._request_count = 5
        result = concrete_integration._check_rate_limit()
        assert result is True

    def test_check_rate_limit_at_limit(self, concrete_integration):
        """Test exactly at rate limit fails."""
        concrete_integration._last_request_time = datetime.utcnow()
        concrete_integration._request_count = concrete_integration.config.rate_limit
        result = concrete_integration._check_rate_limit()
        assert result is False
        assert concrete_integration.status == IntegrationStatus.RATE_LIMITED

    def test_check_rate_limit_over_limit(self, concrete_integration):
        """Test over rate limit fails."""
        concrete_integration._last_request_time = datetime.utcnow()
        concrete_integration._request_count = (
            concrete_integration.config.rate_limit + 10
        )
        result = concrete_integration._check_rate_limit()
        assert result is False

    def test_check_rate_limit_window_boundary_59_seconds(
        self, concrete_integration
    ):
        """Test rate limit at 59 second boundary."""
        concrete_integration._last_request_time = (
            datetime.utcnow() - timedelta(seconds=59)
        )
        concrete_integration._request_count = (
            concrete_integration.config.rate_limit
        )
        result = concrete_integration._check_rate_limit()
        # Still within 60 second window
        assert result is False

    def test_check_rate_limit_window_reset_at_60_seconds(
        self, concrete_integration
    ):
        """Test rate limit resets after 60 seconds."""
        concrete_integration._last_request_time = (
            datetime.utcnow() - timedelta(seconds=61)
        )
        concrete_integration._request_count = 100
        result = concrete_integration._check_rate_limit()
        # Window expired, should reset
        assert result is True
        assert concrete_integration._request_count == 0

    def test_check_rate_limit_custom_rate(self):
        """Test rate limit respects custom rate_limit config."""
        config = IntegrationConfig(name="test", rate_limit=10)
        integration = ConcreteTestIntegration(config)
        integration._last_request_time = datetime.utcnow()
        integration._request_count = 10
        result = integration._check_rate_limit()
        assert result is False

    def test_record_request_increments_count(self, concrete_integration):
        """Test _record_request increments count."""
        initial_count = concrete_integration._request_count
        concrete_integration._record_request()
        assert concrete_integration._request_count == initial_count + 1

    def test_record_request_updates_timestamp(self, concrete_integration):
        """Test _record_request updates timestamp."""
        concrete_integration._record_request()
        assert concrete_integration._last_request_time is not None
        assert isinstance(concrete_integration._last_request_time, datetime)

    def test_record_request_multiple_calls(self, concrete_integration):
        """Test multiple _record_request calls."""
        for i in range(5):
            concrete_integration._record_request()
        assert concrete_integration._request_count == 5


class TestBaseIntegrationErrorHandling:
    """Tests for BaseIntegration error handling."""

    def test_handle_error_sets_message(self, concrete_integration):
        """Test _handle_error sets error message."""
        error = Exception("Test error")
        concrete_integration._handle_error(error)
        assert concrete_integration._error_message == "Test error"

    def test_handle_error_sets_status(self, concrete_integration):
        """Test _handle_error sets status to ERROR."""
        error = Exception("Test error")
        concrete_integration._handle_error(error)
        assert concrete_integration.status == IntegrationStatus.ERROR

    def test_handle_error_returns_dict(self, concrete_integration):
        """Test _handle_error returns error dict."""
        error = Exception("Test error")
        result = concrete_integration._handle_error(error)
        assert isinstance(result, dict)
        assert "success" in result
        assert "error" in result
        assert "integration" in result

    def test_handle_error_success_false(self, concrete_integration):
        """Test _handle_error result has success=False."""
        error = Exception("Test error")
        result = concrete_integration._handle_error(error)
        assert result["success"] is False

    def test_handle_error_includes_integration_name(self, concrete_integration):
        """Test _handle_error includes integration name."""
        error = Exception("Test error")
        result = concrete_integration._handle_error(error)
        assert result["integration"] == concrete_integration.name


class TestBaseIntegrationStatus:
    """Tests for BaseIntegration status reporting."""

    def test_get_status_returns_dict(self, concrete_integration):
        """Test get_status returns dict."""
        status = concrete_integration.get_status()
        assert isinstance(status, dict)

    def test_get_status_includes_name(self, concrete_integration):
        """Test get_status includes name."""
        status = concrete_integration.get_status()
        assert status["name"] == concrete_integration.name

    def test_get_status_includes_enabled(self, concrete_integration):
        """Test get_status includes enabled."""
        status = concrete_integration.get_status()
        assert status["enabled"] == concrete_integration.is_enabled

    def test_get_status_includes_status_value(self, concrete_integration):
        """Test get_status includes status as string."""
        concrete_integration.status = IntegrationStatus.CONNECTED
        status = concrete_integration.get_status()
        assert status["status"] == "connected"

    def test_get_status_includes_error(self, concrete_integration):
        """Test get_status includes error message."""
        concrete_integration._error_message = "Some error"
        status = concrete_integration.get_status()
        assert status["error"] == "Some error"

    def test_get_status_includes_request_count(self, concrete_integration):
        """Test get_status includes request count."""
        concrete_integration._request_count = 42
        status = concrete_integration.get_status()
        assert status["request_count"] == 42

    def test_get_status_after_error(self, concrete_integration):
        """Test get_status after error."""
        error = Exception("Connection failed")
        concrete_integration._handle_error(error)
        status = concrete_integration.get_status()
        assert status["status"] == "error"
        assert status["error"] == "Connection failed"

    def test_get_status_after_connection(self, concrete_integration):
        """Test get_status after connect."""
        concrete_integration.connect()
        status = concrete_integration.get_status()
        assert status["status"] == "connected"


# =============================================================================
# WebhookMixin Tests
# =============================================================================

class TestWebhookMixinBuildPayload:
    """Tests for WebhookMixin._build_webhook_payload()."""

    def test_build_webhook_payload_json_format(
        self, webhook_integration, notification_payload
    ):
        """Test JSON format returns to_dict()."""
        result = webhook_integration._build_webhook_payload(
            notification_payload, format_type="json"
        )
        expected = notification_payload.to_dict()
        assert result == expected

    def test_build_webhook_payload_form_format(
        self, webhook_integration, notification_payload
    ):
        """Test form format converts all values to strings."""
        result = webhook_integration._build_webhook_payload(
            notification_payload, format_type="form"
        )
        for key, value in result.items():
            assert isinstance(value, str)

    def test_build_webhook_payload_unknown_format(
        self, webhook_integration, notification_payload
    ):
        """Test unknown format falls back to JSON."""
        result = webhook_integration._build_webhook_payload(
            notification_payload, format_type="unknown"
        )
        expected = notification_payload.to_dict()
        assert result == expected

    def test_build_webhook_payload_default_format(
        self, webhook_integration, notification_payload
    ):
        """Test default format is JSON."""
        result = webhook_integration._build_webhook_payload(notification_payload)
        expected = notification_payload.to_dict()
        assert result == expected

    def test_build_webhook_payload_form_converts_none(
        self, webhook_integration, minimal_payload
    ):
        """Test form format converts None to string."""
        result = webhook_integration._build_webhook_payload(
            minimal_payload, format_type="form"
        )
        assert result["finding_id"] == "None"

    def test_build_webhook_payload_form_converts_list(
        self, webhook_integration, notification_payload
    ):
        """Test form format converts list to string."""
        result = webhook_integration._build_webhook_payload(
            notification_payload, format_type="form"
        )
        assert isinstance(result["tags"], str)


class TestWebhookMixinSeverityColor:
    """Tests for WebhookMixin._get_severity_color()."""

    def test_severity_color_critical(self, webhook_integration):
        """Test critical severity returns red."""
        color = webhook_integration._get_severity_color("critical")
        assert color == "#FF0000"

    def test_severity_color_high(self, webhook_integration):
        """Test high severity returns orange."""
        color = webhook_integration._get_severity_color("high")
        assert color == "#FF6600"

    def test_severity_color_medium(self, webhook_integration):
        """Test medium severity returns yellow."""
        color = webhook_integration._get_severity_color("medium")
        assert color == "#FFCC00"

    def test_severity_color_low(self, webhook_integration):
        """Test low severity returns green."""
        color = webhook_integration._get_severity_color("low")
        assert color == "#00CC00"

    def test_severity_color_info(self, webhook_integration):
        """Test info severity returns blue."""
        color = webhook_integration._get_severity_color("info")
        assert color == "#0066FF"

    def test_severity_color_none(self, webhook_integration):
        """Test None severity defaults to info (blue)."""
        color = webhook_integration._get_severity_color(None)
        assert color == "#0066FF"  # Defaults to info color

    def test_severity_color_unknown(self, webhook_integration):
        """Test unknown severity returns gray."""
        color = webhook_integration._get_severity_color("unknown")
        assert color == "#808080"

    def test_severity_color_case_insensitive_upper(self, webhook_integration):
        """Test severity is case insensitive (uppercase)."""
        color = webhook_integration._get_severity_color("CRITICAL")
        assert color == "#FF0000"

    def test_severity_color_case_insensitive_mixed(self, webhook_integration):
        """Test severity is case insensitive (mixed case)."""
        color = webhook_integration._get_severity_color("High")
        assert color == "#FF6600"

    @pytest.mark.parametrize("severity,expected_color", [
        ("critical", "#FF0000"),
        ("high", "#FF6600"),
        ("medium", "#FFCC00"),
        ("low", "#00CC00"),
        ("info", "#0066FF"),
        ("CRITICAL", "#FF0000"),
        ("unknown", "#808080"),
    ])
    def test_severity_colors_parameterized(
        self, webhook_integration, severity, expected_color
    ):
        """Test all severity color mappings."""
        color = webhook_integration._get_severity_color(severity)
        assert color == expected_color


# =============================================================================
# Integration Tests (combining components)
# =============================================================================

class TestIntegrationWorkflow:
    """Integration tests for complete workflows."""

    def test_send_notification_with_rate_limiting(
        self, concrete_integration, notification_payload
    ):
        """Test send_notification respects rate limiting."""
        # Send up to rate limit
        for i in range(concrete_integration.config.rate_limit):
            result = concrete_integration.send_notification(notification_payload)
            assert result["success"] is True

        # Next one should be rate limited
        result = concrete_integration.send_notification(notification_payload)
        assert result["success"] is False
        assert "Rate limited" in result["error"]

    def test_connect_disconnect_cycle(self, concrete_integration):
        """Test connect/disconnect cycle."""
        # Connect
        result = concrete_integration.connect()
        assert result is True
        assert concrete_integration.is_connected is True

        # Disconnect
        result = concrete_integration.disconnect()
        assert result is True
        assert concrete_integration.is_connected is False

    def test_error_recovery(self, concrete_integration):
        """Test error recovery by reconnecting."""
        # Trigger error
        concrete_integration._handle_error(Exception("Test error"))
        assert concrete_integration.status == IntegrationStatus.ERROR

        # Reconnect should work
        result = concrete_integration.connect()
        assert result is True
        assert concrete_integration.status == IntegrationStatus.CONNECTED
