"""
Integration Manager for PurpleSploit

Centralized management of all external integrations.
"""

from typing import Dict, Any, List, Optional, Type
from dataclasses import dataclass, field
from pathlib import Path
import json
import logging

from .base import (
    BaseIntegration,
    IntegrationConfig,
    IntegrationStatus,
    NotificationPayload,
    NotificationPriority,
)
from .slack import SlackIntegration, SlackConfig
from .teams import TeamsIntegration, TeamsConfig
from .jira_integration import JiraIntegration, JiraConfig
from .github_issues import GitHubIssuesIntegration, GitHubConfig
from .siem import (
    SIEMWebhook,
    SIEMConfig,
    SplunkIntegration,
    SplunkConfig,
    ElasticIntegration,
    ElasticConfig,
)

logger = logging.getLogger(__name__)


# Registry of available integrations
INTEGRATION_REGISTRY: Dict[str, Dict[str, Any]] = {
    "slack": {
        "class": SlackIntegration,
        "config_class": SlackConfig,
        "description": "Slack notifications via webhook or bot",
        "category": "notifications",
    },
    "teams": {
        "class": TeamsIntegration,
        "config_class": TeamsConfig,
        "description": "Microsoft Teams notifications via webhook",
        "category": "notifications",
    },
    "jira": {
        "class": JiraIntegration,
        "config_class": JiraConfig,
        "description": "Jira issue tracking integration",
        "category": "ticketing",
    },
    "github": {
        "class": GitHubIssuesIntegration,
        "config_class": GitHubConfig,
        "description": "GitHub Issues integration",
        "category": "ticketing",
    },
    "siem_webhook": {
        "class": SIEMWebhook,
        "config_class": SIEMConfig,
        "description": "Generic SIEM webhook integration",
        "category": "siem",
    },
    "splunk": {
        "class": SplunkIntegration,
        "config_class": SplunkConfig,
        "description": "Splunk HEC integration",
        "category": "siem",
    },
    "elasticsearch": {
        "class": ElasticIntegration,
        "config_class": ElasticConfig,
        "description": "Elasticsearch integration",
        "category": "siem",
    },
}


@dataclass
class IntegrationManagerConfig:
    """Configuration for the integration manager."""
    enabled: bool = True
    auto_notify_on_critical: bool = True
    auto_notify_on_high: bool = False
    notification_channels: List[str] = field(default_factory=lambda: ["slack", "teams"])
    ticketing_channels: List[str] = field(default_factory=lambda: ["jira"])
    siem_channels: List[str] = field(default_factory=lambda: ["splunk"])
    batch_notifications: bool = False
    batch_interval: int = 60  # seconds


class IntegrationManager:
    """
    Manages all external integrations.

    Provides:
    - Centralized configuration
    - Multi-channel notifications
    - Integration health monitoring
    - Automatic finding distribution
    """

    def __init__(self, config: Optional[IntegrationManagerConfig] = None):
        self.config = config or IntegrationManagerConfig()
        self.integrations: Dict[str, BaseIntegration] = {}
        self.config_path = Path.home() / ".purplesploit" / "integrations.json"
        self._load_saved_config()

    def _load_saved_config(self) -> None:
        """Load saved integration configurations."""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    saved_config = json.load(f)

                for name, config_data in saved_config.get("integrations", {}).items():
                    if name in INTEGRATION_REGISTRY:
                        self.configure_integration(name, config_data)

            except Exception as e:
                logger.error(f"Failed to load integration config: {e}")

    def _save_config(self) -> None:
        """Save integration configurations."""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)

            config_data = {
                "integrations": {},
                "manager": {
                    "enabled": self.config.enabled,
                    "auto_notify_on_critical": self.config.auto_notify_on_critical,
                    "auto_notify_on_high": self.config.auto_notify_on_high,
                    "notification_channels": self.config.notification_channels,
                    "ticketing_channels": self.config.ticketing_channels,
                    "siem_channels": self.config.siem_channels,
                },
            }

            for name, integration in self.integrations.items():
                # Extract config (excluding sensitive data for display)
                config_dict = {}
                if hasattr(integration, 'config'):
                    for key, value in vars(integration.config).items():
                        if not key.startswith('_') and 'key' not in key.lower() and 'token' not in key.lower():
                            config_dict[key] = value
                config_data["integrations"][name] = config_dict

            with open(self.config_path, 'w') as f:
                json.dump(config_data, f, indent=2)

        except Exception as e:
            logger.error(f"Failed to save integration config: {e}")

    def list_available(self) -> List[Dict[str, Any]]:
        """List all available integrations."""
        available = []
        for name, info in INTEGRATION_REGISTRY.items():
            available.append({
                "name": name,
                "description": info["description"],
                "category": info["category"],
                "configured": name in self.integrations,
                "connected": self.integrations.get(name, None) is not None
                             and self.integrations[name].is_connected,
            })
        return available

    def list_configured(self) -> List[Dict[str, Any]]:
        """List configured integrations with status."""
        configured = []
        for name, integration in self.integrations.items():
            configured.append({
                "name": name,
                "enabled": integration.is_enabled,
                "status": integration.status.value,
                "category": INTEGRATION_REGISTRY.get(name, {}).get("category", "unknown"),
            })
        return configured

    def configure_integration(
        self,
        name: str,
        config_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Configure an integration.

        Args:
            name: Integration name (e.g., "slack", "jira")
            config_data: Configuration parameters

        Returns:
            Result dict with success status
        """
        if name not in INTEGRATION_REGISTRY:
            return {
                "success": False,
                "error": f"Unknown integration: {name}",
                "available": list(INTEGRATION_REGISTRY.keys()),
            }

        try:
            registry_entry = INTEGRATION_REGISTRY[name]
            config_class = registry_entry["config_class"]
            integration_class = registry_entry["class"]

            # Create config
            config = config_class(name=name, **config_data)

            # Create integration instance
            integration = integration_class(config)

            self.integrations[name] = integration
            self._save_config()

            return {
                "success": True,
                "integration": name,
                "status": integration.status.value,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def connect(self, name: str) -> Dict[str, Any]:
        """
        Connect an integration.

        Args:
            name: Integration name

        Returns:
            Result dict with connection status
        """
        if name not in self.integrations:
            return {"success": False, "error": f"Integration not configured: {name}"}

        integration = self.integrations[name]
        success = integration.connect()

        return {
            "success": success,
            "integration": name,
            "status": integration.status.value,
            "error": integration._error_message if not success else None,
        }

    def connect_all(self) -> Dict[str, Any]:
        """Connect all configured integrations."""
        results = {}
        for name in self.integrations:
            results[name] = self.connect(name)
        return results

    def disconnect(self, name: str) -> Dict[str, Any]:
        """Disconnect an integration."""
        if name not in self.integrations:
            return {"success": False, "error": f"Integration not configured: {name}"}

        integration = self.integrations[name]
        success = integration.disconnect()

        return {
            "success": success,
            "integration": name,
            "status": integration.status.value,
        }

    def test_connection(self, name: str) -> Dict[str, Any]:
        """Test an integration connection."""
        if name not in self.integrations:
            return {"success": False, "error": f"Integration not configured: {name}"}

        return self.integrations[name].test_connection()

    def get_status(self, name: Optional[str] = None) -> Dict[str, Any]:
        """
        Get integration status.

        Args:
            name: Optional specific integration name

        Returns:
            Status dict for one or all integrations
        """
        if name:
            if name not in self.integrations:
                return {"error": f"Integration not configured: {name}"}
            return self.integrations[name].get_status()

        return {
            name: integration.get_status()
            for name, integration in self.integrations.items()
        }

    def send_notification(
        self,
        payload: NotificationPayload,
        channels: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Send notification to multiple channels.

        Args:
            payload: Notification payload
            channels: Specific channels, or use configured defaults

        Returns:
            Results dict with per-channel status
        """
        if not self.config.enabled:
            return {"success": False, "error": "Integration manager disabled"}

        target_channels = channels or self.config.notification_channels
        results = {}

        for channel in target_channels:
            if channel in self.integrations:
                integration = self.integrations[channel]
                if integration.is_enabled and integration.is_connected:
                    results[channel] = integration.send_notification(payload)
                else:
                    results[channel] = {
                        "success": False,
                        "error": f"Integration not connected: {integration.status.value}",
                    }
            else:
                results[channel] = {"success": False, "error": "Not configured"}

        return {
            "success": any(r.get("success") for r in results.values()),
            "channels": results,
        }

    def send_finding(
        self,
        title: str,
        description: str,
        severity: str,
        target: str,
        finding_id: Optional[str] = None,
        cvss_score: Optional[float] = None,
        tags: Optional[List[str]] = None,
        create_ticket: bool = False,
        send_to_siem: bool = True,
    ) -> Dict[str, Any]:
        """
        Distribute a finding to appropriate channels.

        Args:
            title: Finding title
            description: Finding description
            severity: Severity level
            target: Affected target
            finding_id: Optional finding ID
            cvss_score: Optional CVSS score
            tags: Optional tags
            create_ticket: Whether to create a ticket
            send_to_siem: Whether to send to SIEM

        Returns:
            Results dict with per-channel status
        """
        priority_map = {
            "critical": NotificationPriority.CRITICAL,
            "high": NotificationPriority.HIGH,
            "medium": NotificationPriority.MEDIUM,
            "low": NotificationPriority.LOW,
            "info": NotificationPriority.LOW,
        }

        payload = NotificationPayload(
            title=title,
            message=description,
            priority=priority_map.get(severity.lower(), NotificationPriority.MEDIUM),
            severity=severity,
            target=target,
            finding_id=finding_id,
            cvss_score=cvss_score,
            tags=tags or [],
        )

        results = {"notifications": {}, "tickets": {}, "siem": {}}

        # Check if we should auto-notify
        should_notify = (
            (severity.lower() == "critical" and self.config.auto_notify_on_critical) or
            (severity.lower() == "high" and self.config.auto_notify_on_high) or
            severity.lower() in ["critical", "high"]  # Always notify for critical/high
        )

        # Send notifications
        if should_notify:
            for channel in self.config.notification_channels:
                if channel in self.integrations:
                    integration = self.integrations[channel]
                    if integration.is_enabled and integration.is_connected:
                        results["notifications"][channel] = integration.send_notification(payload)

        # Create tickets
        if create_ticket:
            for channel in self.config.ticketing_channels:
                if channel in self.integrations:
                    integration = self.integrations[channel]
                    if integration.is_enabled and integration.is_connected:
                        results["tickets"][channel] = integration.send_notification(payload)

        # Send to SIEM
        if send_to_siem:
            for channel in self.config.siem_channels:
                if channel in self.integrations:
                    integration = self.integrations[channel]
                    if integration.is_enabled and integration.is_connected:
                        results["siem"][channel] = integration.send_notification(payload)

        return results

    def send_scan_event(
        self,
        event_type: str,
        scan_name: str,
        target: str,
        status: str,
        findings_summary: Optional[Dict[str, int]] = None,
    ) -> Dict[str, Any]:
        """
        Send scan lifecycle event.

        Args:
            event_type: Event type (started, completed, failed)
            scan_name: Scan/module name
            target: Target being scanned
            status: Scan status
            findings_summary: Optional summary of findings

        Returns:
            Results dict
        """
        results = {}

        # Send to SIEM channels
        for channel in self.config.siem_channels:
            if channel in self.integrations:
                integration = self.integrations[channel]
                if integration.is_enabled and integration.is_connected:
                    if hasattr(integration, 'send_scan_event'):
                        results[channel] = integration.send_scan_event(
                            event_type=event_type,
                            scan_name=scan_name,
                            target=target,
                            status=status,
                            details=findings_summary,
                        )

        # Send completion notification if findings exist
        if event_type == "scan_completed" and findings_summary:
            critical = findings_summary.get("critical", 0)
            high = findings_summary.get("high", 0)

            if critical > 0 or high > 0:
                for channel in self.config.notification_channels:
                    if channel in self.integrations:
                        integration = self.integrations[channel]
                        if integration.is_enabled and integration.is_connected:
                            if hasattr(integration, 'send_scan_complete'):
                                results[f"{channel}_notification"] = integration.send_scan_complete(
                                    scan_name=scan_name,
                                    target=target,
                                    findings_count=sum(findings_summary.values()),
                                    critical_count=critical,
                                    high_count=high,
                                )

        return results

    def remove_integration(self, name: str) -> Dict[str, Any]:
        """Remove an integration configuration."""
        if name not in self.integrations:
            return {"success": False, "error": f"Integration not configured: {name}"}

        # Disconnect first
        self.integrations[name].disconnect()
        del self.integrations[name]
        self._save_config()

        return {"success": True, "integration": name, "action": "removed"}
