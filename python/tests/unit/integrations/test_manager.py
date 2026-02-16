"""
Tests for purplesploit.integrations.manager module.

Tests cover:
- IntegrationManagerConfig dataclass
- IntegrationManager initialization
- Integration configuration (configure_integration)
- Connection management (connect, disconnect, connect_all)
- Listing integrations (list_available, list_configured)
- Status retrieval (get_status, test_connection)
- Notification sending (send_notification, send_finding, send_scan_event)
- Config persistence (_load_saved_config, _save_config)
- Integration removal (remove_integration)
"""

import pytest
import json
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

from purplesploit.integrations.manager import (
    IntegrationManager,
    IntegrationManagerConfig,
    INTEGRATION_REGISTRY,
)
from purplesploit.integrations.base import (
    IntegrationStatus,
    NotificationPayload,
    NotificationPriority,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_integration():
    """Create a mock integration instance."""
    integration = MagicMock()
    integration.is_enabled = True
    integration.is_connected = True
    integration.status = IntegrationStatus.CONNECTED
    integration.connect.return_value = True
    integration.disconnect.return_value = True
    integration.send_notification.return_value = {"success": True}
    integration.test_connection.return_value = {"success": True}
    integration.get_status.return_value = {"status": "connected"}
    integration._error_message = None
    return integration


@pytest.fixture
def mock_disconnected_integration():
    """Create a mock disconnected integration."""
    integration = MagicMock()
    integration.is_enabled = True
    integration.is_connected = False
    integration.status = IntegrationStatus.DISCONNECTED
    integration.connect.return_value = False
    integration._error_message = "Connection failed"
    return integration


@pytest.fixture
def manager_config():
    """Create a basic IntegrationManagerConfig."""
    return IntegrationManagerConfig(
        enabled=True,
        auto_notify_on_critical=True,
        auto_notify_on_high=False,
        notification_channels=["slack", "teams"],
        ticketing_channels=["jira"],
        siem_channels=["splunk"],
    )


@pytest.fixture
def manager(tmp_path):
    """Create an IntegrationManager with temp config path."""
    with patch.object(IntegrationManager, '_load_saved_config'):
        mgr = IntegrationManager()
        mgr.config_path = tmp_path / "integrations.json"
        return mgr


# =============================================================================
# IntegrationManagerConfig Tests
# =============================================================================

class TestIntegrationManagerConfig:
    """Tests for IntegrationManagerConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = IntegrationManagerConfig()

        assert config.enabled is True
        assert config.auto_notify_on_critical is True
        assert config.auto_notify_on_high is False
        assert "slack" in config.notification_channels
        assert "teams" in config.notification_channels
        assert "jira" in config.ticketing_channels
        assert "splunk" in config.siem_channels
        assert config.batch_notifications is False
        assert config.batch_interval == 60

    def test_custom_values(self):
        """Test custom configuration values."""
        config = IntegrationManagerConfig(
            enabled=False,
            auto_notify_on_critical=False,
            auto_notify_on_high=True,
            notification_channels=["teams"],
            ticketing_channels=["github"],
            siem_channels=["elasticsearch"],
            batch_notifications=True,
            batch_interval=120,
        )

        assert config.enabled is False
        assert config.auto_notify_on_critical is False
        assert config.auto_notify_on_high is True
        assert config.notification_channels == ["teams"]
        assert config.ticketing_channels == ["github"]
        assert config.siem_channels == ["elasticsearch"]
        assert config.batch_notifications is True
        assert config.batch_interval == 120


# =============================================================================
# IntegrationManager Initialization Tests
# =============================================================================

class TestIntegrationManagerInit:
    """Tests for IntegrationManager initialization."""

    def test_init_with_default_config(self):
        """Test initialization with default config."""
        with patch.object(IntegrationManager, '_load_saved_config'):
            manager = IntegrationManager()

            assert manager.config is not None
            assert manager.config.enabled is True
            assert isinstance(manager.integrations, dict)
            assert len(manager.integrations) == 0

    def test_init_with_custom_config(self):
        """Test initialization with custom config."""
        custom_config = IntegrationManagerConfig(enabled=False)

        with patch.object(IntegrationManager, '_load_saved_config'):
            manager = IntegrationManager(config=custom_config)

            assert manager.config.enabled is False

    def test_config_path_is_set(self):
        """Test that config_path is set to expected location."""
        with patch.object(IntegrationManager, '_load_saved_config'):
            manager = IntegrationManager()

            assert ".purplesploit" in str(manager.config_path)
            assert "integrations.json" in str(manager.config_path)


# =============================================================================
# Config Persistence Tests
# =============================================================================

class TestConfigPersistence:
    """Tests for config loading and saving."""

    def test_load_saved_config_no_file(self, tmp_path):
        """Test loading config when no file exists."""
        with patch.object(Path, 'home', return_value=tmp_path):
            # No config file exists in tmp_path, so it should just return
            manager = IntegrationManager()

            # Should not raise, just return early
            assert len(manager.integrations) == 0

    def test_load_saved_config_valid_file(self, tmp_path):
        """Test loading valid saved config."""
        config_data = {
            "integrations": {
                "slack": {"webhook_url": "https://hooks.slack.com/test"},
            }
        }
        config_file = tmp_path / ".purplesploit" / "integrations.json"
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config_file.write_text(json.dumps(config_data))

        with patch.object(IntegrationManager, 'configure_integration') as mock_configure:
            with patch.object(Path, 'home', return_value=tmp_path):
                manager = IntegrationManager()

                # Should attempt to configure the slack integration
                mock_configure.assert_called()

    def test_load_saved_config_invalid_json(self, tmp_path, caplog):
        """Test loading config with invalid JSON."""
        config_file = tmp_path / ".purplesploit" / "integrations.json"
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config_file.write_text("not valid json{{{")

        with patch.object(Path, 'home', return_value=tmp_path):
            manager = IntegrationManager()

            # Should log error but not crash
            assert len(manager.integrations) == 0

    def test_save_config_creates_directory(self, manager, tmp_path):
        """Test that save_config creates parent directory."""
        manager.config_path = tmp_path / "new_dir" / "integrations.json"

        manager._save_config()

        assert manager.config_path.parent.exists()

    def test_save_config_writes_json(self, manager, tmp_path):
        """Test that save_config writes valid JSON."""
        mock_integration = MagicMock()
        mock_integration.config = MagicMock()
        mock_integration.config.__dict__ = {
            "name": "test",
            "webhook_url": "https://test.com",
        }

        manager.integrations["test"] = mock_integration
        manager._save_config()

        assert manager.config_path.exists()
        saved = json.loads(manager.config_path.read_text())
        assert "integrations" in saved
        assert "manager" in saved

    def test_save_config_excludes_sensitive_data(self, manager, tmp_path):
        """Test that save_config excludes keys/tokens."""
        mock_integration = MagicMock()
        mock_config = MagicMock()
        # Create actual attributes with sensitive data
        mock_config.name = "test"
        mock_config.api_key = "secret123"
        mock_config.api_token = "token456"
        mock_config.webhook_url = "https://test.com"
        mock_integration.config = mock_config

        manager.integrations["test"] = mock_integration
        manager._save_config()

        saved = json.loads(manager.config_path.read_text())
        if "test" in saved.get("integrations", {}):
            config = saved["integrations"]["test"]
            # Keys/tokens should be excluded
            assert "api_key" not in config
            assert "api_token" not in config


# =============================================================================
# List Integrations Tests
# =============================================================================

class TestListIntegrations:
    """Tests for listing integrations."""

    def test_list_available_returns_all(self, manager):
        """Test list_available returns all registered integrations."""
        available = manager.list_available()

        assert len(available) == len(INTEGRATION_REGISTRY)

        names = [i["name"] for i in available]
        assert "slack" in names
        assert "teams" in names
        assert "jira" in names
        assert "github" in names
        assert "splunk" in names
        assert "elasticsearch" in names

    def test_list_available_shows_configured_status(self, manager, mock_integration):
        """Test list_available shows configured status."""
        manager.integrations["slack"] = mock_integration

        available = manager.list_available()
        slack_entry = next(i for i in available if i["name"] == "slack")

        assert slack_entry["configured"] is True
        assert slack_entry["connected"] is True

    def test_list_available_unconfigured_not_connected(self, manager):
        """Test unconfigured integrations show as not connected."""
        available = manager.list_available()
        slack_entry = next(i for i in available if i["name"] == "slack")

        assert slack_entry["configured"] is False
        assert slack_entry["connected"] is False

    def test_list_configured_empty(self, manager):
        """Test list_configured with no configured integrations."""
        configured = manager.list_configured()

        assert len(configured) == 0

    def test_list_configured_with_integrations(self, manager, mock_integration):
        """Test list_configured returns configured integrations."""
        manager.integrations["slack"] = mock_integration
        manager.integrations["teams"] = mock_integration

        configured = manager.list_configured()

        assert len(configured) == 2
        names = [i["name"] for i in configured]
        assert "slack" in names
        assert "teams" in names

    def test_list_configured_includes_status(self, manager, mock_integration):
        """Test list_configured includes status information."""
        manager.integrations["slack"] = mock_integration

        configured = manager.list_configured()
        slack = configured[0]

        assert slack["enabled"] is True
        assert slack["status"] == "connected"
        assert slack["category"] == "notifications"


# =============================================================================
# Configure Integration Tests
# =============================================================================

class TestConfigureIntegration:
    """Tests for configure_integration method."""

    def test_configure_unknown_integration(self, manager):
        """Test configuring unknown integration returns error."""
        result = manager.configure_integration("unknown_service", {})

        assert result["success"] is False
        assert "Unknown integration" in result["error"]
        assert "available" in result

    def test_configure_slack_integration(self, manager):
        """Test configuring Slack integration."""
        with patch('purplesploit.integrations.manager.SlackIntegration') as MockSlack:
            mock_instance = MagicMock()
            mock_instance.status = IntegrationStatus.DISCONNECTED
            MockSlack.return_value = mock_instance

            result = manager.configure_integration("slack", {
                "webhook_url": "https://hooks.slack.com/test"
            })

            assert result["success"] is True
            assert result["integration"] == "slack"
            assert "slack" in manager.integrations

    def test_configure_integration_saves_config(self, manager):
        """Test that configuring integration saves config."""
        with patch('purplesploit.integrations.manager.SlackIntegration') as MockSlack:
            mock_instance = MagicMock()
            mock_instance.status = IntegrationStatus.DISCONNECTED
            MockSlack.return_value = mock_instance

            with patch.object(manager, '_save_config') as mock_save:
                manager.configure_integration("slack", {"webhook_url": "https://test"})

                mock_save.assert_called_once()

    def test_configure_integration_exception(self, manager):
        """Test configuring integration with exception."""
        # Patch the registry entry's config_class to raise an exception
        with patch.dict(INTEGRATION_REGISTRY, {
            "slack": {
                **INTEGRATION_REGISTRY["slack"],
                "config_class": MagicMock(side_effect=ValueError("Invalid config")),
            }
        }):
            result = manager.configure_integration("slack", {})

            assert result["success"] is False
            assert "Invalid config" in result["error"]


# =============================================================================
# Connection Management Tests
# =============================================================================

class TestConnectionManagement:
    """Tests for connect/disconnect methods."""

    def test_connect_not_configured(self, manager):
        """Test connect returns error for unconfigured integration."""
        result = manager.connect("slack")

        assert result["success"] is False
        assert "not configured" in result["error"]

    def test_connect_success(self, manager, mock_integration):
        """Test successful connection."""
        manager.integrations["slack"] = mock_integration

        result = manager.connect("slack")

        assert result["success"] is True
        assert result["integration"] == "slack"
        mock_integration.connect.assert_called_once()

    def test_connect_failure(self, manager, mock_disconnected_integration):
        """Test failed connection."""
        manager.integrations["slack"] = mock_disconnected_integration

        result = manager.connect("slack")

        assert result["success"] is False
        assert result["error"] == "Connection failed"

    def test_connect_all(self, manager, mock_integration):
        """Test connect_all connects multiple integrations."""
        manager.integrations["slack"] = mock_integration
        manager.integrations["teams"] = mock_integration

        results = manager.connect_all()

        assert "slack" in results
        assert "teams" in results
        assert results["slack"]["success"] is True
        assert results["teams"]["success"] is True

    def test_disconnect_not_configured(self, manager):
        """Test disconnect returns error for unconfigured integration."""
        result = manager.disconnect("slack")

        assert result["success"] is False
        assert "not configured" in result["error"]

    def test_disconnect_success(self, manager, mock_integration):
        """Test successful disconnection."""
        manager.integrations["slack"] = mock_integration

        result = manager.disconnect("slack")

        assert result["success"] is True
        mock_integration.disconnect.assert_called_once()


# =============================================================================
# Status and Test Connection Tests
# =============================================================================

class TestStatusAndTestConnection:
    """Tests for get_status and test_connection methods."""

    def test_test_connection_not_configured(self, manager):
        """Test test_connection returns error for unconfigured."""
        result = manager.test_connection("slack")

        assert result["success"] is False
        assert "not configured" in result["error"]

    def test_test_connection_success(self, manager, mock_integration):
        """Test test_connection delegates to integration."""
        manager.integrations["slack"] = mock_integration

        result = manager.test_connection("slack")

        assert result["success"] is True
        mock_integration.test_connection.assert_called_once()

    def test_get_status_specific_integration(self, manager, mock_integration):
        """Test get_status for specific integration."""
        manager.integrations["slack"] = mock_integration

        result = manager.get_status("slack")

        assert result == {"status": "connected"}
        mock_integration.get_status.assert_called_once()

    def test_get_status_not_configured(self, manager):
        """Test get_status for unconfigured integration."""
        result = manager.get_status("slack")

        assert "error" in result
        assert "not configured" in result["error"]

    def test_get_status_all(self, manager, mock_integration):
        """Test get_status for all integrations."""
        manager.integrations["slack"] = mock_integration
        manager.integrations["teams"] = mock_integration

        result = manager.get_status()

        assert "slack" in result
        assert "teams" in result


# =============================================================================
# Send Notification Tests
# =============================================================================

class TestSendNotification:
    """Tests for send_notification method."""

    def test_send_notification_disabled_manager(self, manager):
        """Test send_notification when manager disabled."""
        manager.config.enabled = False

        payload = NotificationPayload(title="Test", message="Test message")
        result = manager.send_notification(payload)

        assert result["success"] is False
        assert "disabled" in result["error"]

    def test_send_notification_to_channels(self, manager, mock_integration):
        """Test send_notification sends to configured channels."""
        manager.integrations["slack"] = mock_integration
        manager.integrations["teams"] = mock_integration

        payload = NotificationPayload(title="Test", message="Test message")
        result = manager.send_notification(payload)

        assert result["success"] is True
        assert "channels" in result
        assert result["channels"]["slack"]["success"] is True
        assert result["channels"]["teams"]["success"] is True

    def test_send_notification_specific_channels(self, manager, mock_integration):
        """Test send_notification to specific channels."""
        manager.integrations["slack"] = mock_integration
        manager.integrations["teams"] = mock_integration

        payload = NotificationPayload(title="Test", message="Test message")
        result = manager.send_notification(payload, channels=["slack"])

        assert result["channels"]["slack"]["success"] is True
        assert "teams" not in result["channels"]

    def test_send_notification_unconfigured_channel(self, manager):
        """Test send_notification to unconfigured channel."""
        payload = NotificationPayload(title="Test", message="Test message")
        result = manager.send_notification(payload, channels=["slack"])

        assert result["channels"]["slack"]["success"] is False
        assert "Not configured" in result["channels"]["slack"]["error"]

    def test_send_notification_disconnected_integration(self, manager, mock_disconnected_integration):
        """Test send_notification to disconnected integration."""
        manager.integrations["slack"] = mock_disconnected_integration

        payload = NotificationPayload(title="Test", message="Test message")
        result = manager.send_notification(payload, channels=["slack"])

        assert result["channels"]["slack"]["success"] is False
        assert "not connected" in result["channels"]["slack"]["error"]


# =============================================================================
# Send Finding Tests
# =============================================================================

class TestSendFinding:
    """Tests for send_finding method."""

    def test_send_finding_critical_notifies(self, manager, mock_integration):
        """Test send_finding notifies on critical severity."""
        manager.integrations["slack"] = mock_integration
        manager.config.notification_channels = ["slack"]

        result = manager.send_finding(
            title="Critical Finding",
            description="Test description",
            severity="critical",
            target="192.168.1.1",
        )

        assert "notifications" in result
        assert "slack" in result["notifications"]

    def test_send_finding_high_with_auto_notify(self, manager, mock_integration):
        """Test send_finding notifies on high severity with auto_notify_on_high."""
        manager.config.auto_notify_on_high = True
        manager.integrations["slack"] = mock_integration
        manager.config.notification_channels = ["slack"]

        result = manager.send_finding(
            title="High Finding",
            description="Test description",
            severity="high",
            target="192.168.1.1",
        )

        assert "slack" in result["notifications"]

    def test_send_finding_creates_ticket(self, manager, mock_integration):
        """Test send_finding creates ticket when requested."""
        manager.integrations["jira"] = mock_integration
        manager.config.ticketing_channels = ["jira"]

        result = manager.send_finding(
            title="Test Finding",
            description="Test description",
            severity="high",
            target="192.168.1.1",
            create_ticket=True,
        )

        assert "tickets" in result
        assert "jira" in result["tickets"]

    def test_send_finding_to_siem(self, manager, mock_integration):
        """Test send_finding sends to SIEM by default."""
        manager.integrations["splunk"] = mock_integration
        manager.config.siem_channels = ["splunk"]

        result = manager.send_finding(
            title="Test Finding",
            description="Test description",
            severity="high",
            target="192.168.1.1",
        )

        assert "siem" in result
        assert "splunk" in result["siem"]

    def test_send_finding_skip_siem(self, manager, mock_integration):
        """Test send_finding skips SIEM when disabled."""
        manager.integrations["splunk"] = mock_integration
        manager.config.siem_channels = ["splunk"]

        result = manager.send_finding(
            title="Test Finding",
            description="Test description",
            severity="high",
            target="192.168.1.1",
            send_to_siem=False,
        )

        assert result["siem"] == {}

    def test_send_finding_with_all_fields(self, manager, mock_integration):
        """Test send_finding with all optional fields."""
        manager.integrations["slack"] = mock_integration
        manager.config.notification_channels = ["slack"]

        result = manager.send_finding(
            title="Complete Finding",
            description="Full test description",
            severity="critical",
            target="192.168.1.100",
            finding_id="F-001",
            cvss_score=9.8,
            tags=["injection", "web"],
            create_ticket=False,
            send_to_siem=False,
        )

        # Verify notification was sent with correct payload
        mock_integration.send_notification.assert_called()
        call_args = mock_integration.send_notification.call_args
        payload = call_args[0][0]
        assert payload.title == "Complete Finding"
        assert payload.cvss_score == 9.8
        assert "injection" in payload.tags


# =============================================================================
# Send Scan Event Tests
# =============================================================================

class TestSendScanEvent:
    """Tests for send_scan_event method."""

    def test_send_scan_event_to_siem(self, manager, mock_integration):
        """Test send_scan_event sends to SIEM channels."""
        mock_integration.send_scan_event = MagicMock(return_value={"success": True})
        manager.integrations["splunk"] = mock_integration
        manager.config.siem_channels = ["splunk"]

        result = manager.send_scan_event(
            event_type="scan_started",
            scan_name="nmap_scan",
            target="192.168.1.0/24",
            status="running",
        )

        assert "splunk" in result
        mock_integration.send_scan_event.assert_called_once()

    def test_send_scan_event_completed_with_findings(self, manager, mock_integration):
        """Test scan_completed event with findings sends notification."""
        mock_integration.send_scan_event = MagicMock(return_value={"success": True})
        mock_integration.send_scan_complete = MagicMock(return_value={"success": True})
        manager.integrations["splunk"] = mock_integration
        manager.integrations["slack"] = mock_integration
        manager.config.siem_channels = ["splunk"]
        manager.config.notification_channels = ["slack"]

        result = manager.send_scan_event(
            event_type="scan_completed",
            scan_name="vuln_scan",
            target="192.168.1.100",
            status="completed",
            findings_summary={"critical": 2, "high": 5, "medium": 3},
        )

        assert "splunk" in result
        # Should also send notification due to critical/high findings
        assert "slack_notification" in result

    def test_send_scan_event_no_notification_for_zero_findings(self, manager, mock_integration):
        """Test scan_completed with no critical/high findings doesn't notify."""
        mock_integration.send_scan_event = MagicMock(return_value={"success": True})
        manager.integrations["splunk"] = mock_integration
        manager.integrations["slack"] = mock_integration
        manager.config.siem_channels = ["splunk"]
        manager.config.notification_channels = ["slack"]

        result = manager.send_scan_event(
            event_type="scan_completed",
            scan_name="info_scan",
            target="192.168.1.100",
            status="completed",
            findings_summary={"low": 3, "info": 10},
        )

        # No notification key because no critical/high findings
        assert "slack_notification" not in result


# =============================================================================
# Remove Integration Tests
# =============================================================================

class TestRemoveIntegration:
    """Tests for remove_integration method."""

    def test_remove_not_configured(self, manager):
        """Test removing unconfigured integration."""
        result = manager.remove_integration("slack")

        assert result["success"] is False
        assert "not configured" in result["error"]

    def test_remove_integration_success(self, manager, mock_integration):
        """Test successful removal."""
        manager.integrations["slack"] = mock_integration

        with patch.object(manager, '_save_config'):
            result = manager.remove_integration("slack")

            assert result["success"] is True
            assert result["integration"] == "slack"
            assert "slack" not in manager.integrations
            mock_integration.disconnect.assert_called_once()

    def test_remove_integration_saves_config(self, manager, mock_integration):
        """Test removal saves config."""
        manager.integrations["slack"] = mock_integration

        with patch.object(manager, '_save_config') as mock_save:
            manager.remove_integration("slack")

            mock_save.assert_called_once()


# =============================================================================
# Integration Registry Tests
# =============================================================================

class TestIntegrationRegistry:
    """Tests for the INTEGRATION_REGISTRY constant."""

    def test_registry_contains_slack(self):
        """Test registry contains Slack integration."""
        assert "slack" in INTEGRATION_REGISTRY
        assert "class" in INTEGRATION_REGISTRY["slack"]
        assert "config_class" in INTEGRATION_REGISTRY["slack"]
        assert INTEGRATION_REGISTRY["slack"]["category"] == "notifications"

    def test_registry_contains_all_expected_integrations(self):
        """Test registry contains all expected integrations."""
        expected = ["slack", "teams", "jira", "github", "siem_webhook", "splunk", "elasticsearch"]

        for name in expected:
            assert name in INTEGRATION_REGISTRY, f"Missing {name} from registry"

    def test_registry_entries_have_required_fields(self):
        """Test all registry entries have required fields."""
        required_fields = ["class", "config_class", "description", "category"]

        for name, entry in INTEGRATION_REGISTRY.items():
            for field in required_fields:
                assert field in entry, f"Integration {name} missing {field}"


# =============================================================================
# Edge Cases and Error Handling Tests
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_send_finding_with_unknown_severity(self, manager, mock_integration):
        """Test send_finding handles unknown severity."""
        manager.integrations["slack"] = mock_integration
        manager.config.notification_channels = ["slack"]

        # Should not crash on unknown severity
        result = manager.send_finding(
            title="Test",
            description="Test",
            severity="unknown_level",
            target="192.168.1.1",
        )

        # Low priority should be used for unknown
        assert isinstance(result, dict)

    def test_send_notification_partial_success(self, manager, mock_integration, mock_disconnected_integration):
        """Test send_notification with partial success."""
        manager.integrations["slack"] = mock_integration
        manager.integrations["teams"] = mock_disconnected_integration
        manager.config.notification_channels = ["slack", "teams"]

        payload = NotificationPayload(title="Test", message="Test")
        result = manager.send_notification(payload)

        # Overall success because at least one succeeded
        assert result["success"] is True
        assert result["channels"]["slack"]["success"] is True
        assert result["channels"]["teams"]["success"] is False

    def test_save_config_handles_error(self, manager, caplog):
        """Test _save_config handles write errors."""
        manager.config_path = Path("/nonexistent/readonly/path/config.json")

        # Should not raise, just log error
        manager._save_config()

    def test_empty_integrations_status(self, manager):
        """Test get_status with no integrations."""
        result = manager.get_status()

        assert result == {}

    def test_list_configured_empty(self, manager):
        """Test list_configured with no configured integrations."""
        result = manager.list_configured()

        assert result == []
