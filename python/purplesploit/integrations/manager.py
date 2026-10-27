"""
Integration Manager for PurpleSploit

Centralized management of all external integrations.
"""

from typing import Dict, Any, List, Optional
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path
import json
import logging
import os
import tempfile
from threading import RLock
import time
from purplesploit.core.findings import Finding
from purplesploit.core.secrets import SecretRedactor, externalize_secrets, resolve_secrets

from .base import (
    BaseIntegration,
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
    max_retry_attempts: int = 3
    retry_base_delay: float = 0.25


class IntegrationManager:
    """
    Manages all external integrations.

    Provides:
    - Centralized configuration
    - Multi-channel notifications
    - Integration health monitoring
    - Automatic finding distribution
    """

    def __init__(self, config: Optional[IntegrationManagerConfig] = None, config_path=None,
                 secret_provider=None, sleeper=time.sleep):
        self.config = config or IntegrationManagerConfig()
        self.integrations: Dict[str, BaseIntegration] = {}
        self.config_path = Path(config_path) if config_path is not None else Path.home() / ".purplesploit" / "integrations.json"
        self.integration_types: Dict[str, str] = {}
        self.remote_ids: Dict[str, Dict[str, Any]] = {}
        self.delivery_log: List[Dict[str, Any]] = []
        self.secret_provider = secret_provider
        self.redactor = SecretRedactor(secret_provider)
        self._loading = False
        self._lock = RLock()
        self._sleep = sleeper
        self._load_saved_config()

    def _load_saved_config(self) -> None:
        """Load saved integration configurations."""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    saved_config = json.load(f)

                self._loading = True
                allowed = {item.name for item in fields(IntegrationManagerConfig)}
                for key, value in saved_config.get("manager", {}).items():
                    if key in allowed:
                        setattr(self.config, key, value)
                self.remote_ids = saved_config.get("remote_ids", {})
                self.delivery_log = saved_config.get("delivery_log", [])
                for name, entry in saved_config.get("integrations", {}).items():
                    config_data = entry.get("config", entry)
                    if self.secret_provider is not None:
                        config_data = resolve_secrets(config_data, self.secret_provider)
                    integration_type = entry.get("type", name)
                    result = self.configure_integration(name, config_data, integration_type)
                    if not result["success"]:
                        logger.error("Unable to load integration %s: %s", name, result["error"])

            except Exception as e:
                logger.error(f"Failed to load integration config: {e}")
            finally:
                self._loading = False

    def _save_config(self) -> bool:
        """Save integration configurations."""
        try:
            if self._loading:
                return True
            self.config_path.parent.mkdir(parents=True, exist_ok=True)

            config_data = {
                "integrations": {},
                "manager": asdict(self.config),
                "remote_ids": self.remote_ids,
                "delivery_log": self.redactor.redact(self.delivery_log),
            }

            for name, integration in self.integrations.items():
                # Normal configuration stores contain references, never secret values.
                config_dict = {}
                if hasattr(integration, 'config'):
                    for key, value in vars(integration.config).items():
                        if not key.startswith('_'):
                            config_dict[key] = value
                if self.secret_provider is not None:
                    config_dict = externalize_secrets(
                        config_dict, self.secret_provider, namespace=f"integration/{name}"
                    )
                config_data["integrations"][name] = {
                    "type": self.integration_types.get(name, name), "config": config_dict,
                }

            temporary = None
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=self.config_path.parent,
                prefix=f".{self.config_path.name}.", suffix=".tmp", delete=False,
            ) as f:
                temporary = Path(f.name)
                os.chmod(temporary, 0o600)
                json.dump(config_data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temporary, self.config_path)
            self.config_path.chmod(0o600)
            return True

        except Exception as e:
            logger.error(f"Failed to save integration config: {e}")
            return False

    def list_available(self) -> List[Dict[str, Any]]:
        """List all available integrations."""
        available = []
        for name, info in INTEGRATION_REGISTRY.items():
            instances = [integration for instance_name, integration in self.integrations.items()
                         if self.integration_types.get(instance_name, instance_name) == name]
            available.append({
                "name": name,
                "description": info["description"],
                "category": info["category"],
                "configured": bool(instances),
                "connected": any(integration.is_connected for integration in instances),
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
                "type": self.integration_types.get(name, name),
                "category": INTEGRATION_REGISTRY.get(self.integration_types.get(name, name), {}).get("category", "unknown"),
            })
        return configured

    def configure_integration(
        self,
        name: str,
        config_data: Dict[str, Any],
        integration_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Configure an integration.

        Args:
            name: Integration name (e.g., "slack", "jira")
            config_data: Configuration parameters

        Returns:
            Result dict with success status
        """
        integration_type = integration_type or name
        if integration_type not in INTEGRATION_REGISTRY:
            return {
                "success": False,
                "error": f"Unknown integration: {name}",
                "available": list(INTEGRATION_REGISTRY.keys()),
            }

        try:
            registry_entry = INTEGRATION_REGISTRY[integration_type]
            config_class = registry_entry["config_class"]
            integration_class = registry_entry["class"]

            # Create config
            config = config_class(**{**config_data, "name": name})

            # Create integration instance
            integration = integration_class(config)

            previous = self.integrations.get(name)
            if previous is not None and vars(previous.config) != vars(config):
                self.remote_ids.pop(name, None)
            self.integrations[name] = integration
            self.integration_types[name] = integration_type
            for attr in ("_issue_cache", "_thread_map"):
                cache = getattr(integration, attr, None)
                if isinstance(cache, dict):
                    cache.update(self.remote_ids.get(name, {}))
            if self._save_config() is False:
                return {"success": False, "error": "Unable to persist integration configuration", "integration": name}

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
        try:
            success = integration.connect()
        except Exception as exc:
            integration._handle_error(exc)
            success = False
        if success:
            integration.status = IntegrationStatus.CONNECTED
            integration._error_message = None
        elif integration.status == IntegrationStatus.DISCONNECTED:
            integration.status = IntegrationStatus.ERROR
            integration._error_message = integration._error_message or "Connection failed"

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
        title: str | Finding = "",
        description: str = "",
        severity: str = "medium",
        target: str = "",
        finding_id: Optional[str] = None,
        cvss_score: Optional[float] = None,
        tags: Optional[List[str]] = None,
        create_ticket: bool = False,
        send_to_siem: bool = True,
        finding: Optional[Finding] = None,
        idempotency_key: Optional[str] = None,
        expected_remote_ids: Optional[Dict[str, Any]] = None,
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
        finding = finding or (title if isinstance(title, Finding) else None)
        if finding is not None:
            if not isinstance(finding, Finding):
                raise TypeError("finding must be core.findings.Finding")
            title, description = finding.title, finding.description
            severity, target = finding.severity.value, finding.target
            finding_id, cvss_score, tags = finding.id, finding.cvss_score, finding.tags
        if not self.config.enabled:
            return {"success": False, "error": "Integration manager disabled",
                    "notifications": {}, "tickets": {}, "siem": {}}
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
            extra_data={"finding": finding.to_dict()} if finding is not None else {},
        )

        results = {"notifications": {}, "tickets": {}, "siem": {}}

        # Check if we should auto-notify
        should_notify = (
            (severity.lower() == "critical" and self.config.auto_notify_on_critical) or
            (severity.lower() == "high" and self.config.auto_notify_on_high)
        )

        # Send notifications
        if should_notify:
            for channel in self.config.notification_channels:
                results["notifications"][channel] = self._deliver(
                    channel, payload, "notification", idempotency_key,
                    (expected_remote_ids or {}).get(channel),
                )

        # Create tickets
        if create_ticket:
            for channel in self.config.ticketing_channels:
                results["tickets"][channel] = self._deliver(
                    channel, payload, "ticket", idempotency_key,
                    (expected_remote_ids or {}).get(channel),
                )

        # Send to SIEM
        if send_to_siem:
            for channel in self.config.siem_channels:
                results["siem"][channel] = self._deliver(
                    channel, payload, "siem", idempotency_key,
                    (expected_remote_ids or {}).get(channel),
                )

        results["success"] = any(item.get("success") for group in ("notifications", "tickets", "siem")
                                 for item in results[group].values())
        results["finding_id"] = finding_id
        return results

    def _deliver(self, channel: str, payload: NotificationPayload, kind: str,
                 idempotency_key=None, expected_remote_id=None) -> Dict[str, Any]:
        """Attempt one delivery and retain its observable outcome across restarts."""
        with self._lock:
            if idempotency_key:
                prior = next((item for item in reversed(self.delivery_log)
                              if item.get("idempotency_key") == idempotency_key
                              and item.get("channel") == channel and item.get("kind") == kind), None)
                if prior is not None:
                    return {**dict(prior["result"]), "duplicate": True, "idempotency_key": idempotency_key}
        integration = self.integrations.get(channel)
        current_remote = self.remote_ids.get(channel, {}).get(payload.finding_id)
        if expected_remote_id is not None and current_remote != expected_remote_id:
            result = {
                "success": False, "conflict": True,
                "error": "Remote mapping changed since it was read",
                "expected_remote_id": expected_remote_id,
                "current_remote_id": current_remote,
            }
        if integration is None:
            result = {"success": False, "error": "Not configured"}
        elif not integration.is_enabled or not integration.is_connected:
            result = {"success": False, "error": f"Integration not connected: {integration.status.value}"}
        elif expected_remote_id is None or current_remote == expected_remote_id:
            attempts = min(max(int(self.config.max_retry_attempts), 1), 5)
            for attempt in range(1, attempts + 1):
                try:
                    result = integration.send_notification(payload)
                except Exception as exc:
                    result = integration._handle_error(exc)
                error = str(result.get("error", ""))
                status = result.get("status_code")
                retryable = status == 429 or (isinstance(status, int) and status >= 500)
                retryable = retryable or any(f"HTTP {code}" in error for code in (429, 500, 502, 503, 504))
                if result.get("success") or not retryable or attempt == attempts:
                    break
                self._sleep(self.config.retry_base_delay * (2 ** (attempt - 1)))
            result = {**result, "attempts": attempt}
        remote_id = next((result[key] for key in ("issue_key", "issue_number", "ts", "id")
                          if result.get(key) is not None), None)
        if result.get("success") and remote_id is not None and payload.finding_id:
            thread_map = getattr(integration, "_thread_map", None)
            if isinstance(thread_map, dict):
                remote_id = thread_map.get(payload.finding_id, remote_id)
            self.remote_ids.setdefault(channel, {})[payload.finding_id] = remote_id
        self.delivery_log.append(self.redactor.redact({
            "timestamp": datetime.now(timezone.utc).isoformat(), "channel": channel,
            "kind": kind, "finding_id": payload.finding_id,
            "idempotency_key": idempotency_key, "result": dict(result),
        }))
        persisted = self._save_config()
        if persisted is False:
            result = {**result, "persisted": False, "persistence_error": "Unable to persist delivery state"}
        return result

    def list_deliveries(self, finding_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return [dict(item) for item in self.delivery_log
                if finding_id is None or item["finding_id"] == finding_id]

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
        self.integration_types.pop(name, None)
        self.remote_ids.pop(name, None)
        self._save_config()

        return {"success": True, "integration": name, "action": "removed"}
