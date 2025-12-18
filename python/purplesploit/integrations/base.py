"""
Base Integration Module

Provides common functionality for all external integrations.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from datetime import datetime
from enum import Enum
import json
import logging

logger = logging.getLogger(__name__)


class IntegrationStatus(Enum):
    """Integration connection status."""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    RATE_LIMITED = "rate_limited"


class NotificationPriority(Enum):
    """Notification priority levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class IntegrationConfig:
    """Base configuration for integrations."""
    name: str
    enabled: bool = True
    api_key: Optional[str] = None
    api_url: Optional[str] = None
    timeout: int = 30
    retry_count: int = 3
    rate_limit: int = 60  # requests per minute
    extra_config: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NotificationPayload:
    """Standard notification payload."""
    title: str
    message: str
    priority: NotificationPriority = NotificationPriority.MEDIUM
    source: str = "purplesploit"
    timestamp: datetime = field(default_factory=datetime.utcnow)
    finding_id: Optional[str] = None
    target: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    tags: List[str] = field(default_factory=list)
    extra_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "message": self.message,
            "priority": self.priority.value,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "finding_id": self.finding_id,
            "target": self.target,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "tags": self.tags,
            "extra_data": self.extra_data,
        }


class BaseIntegration(ABC):
    """
    Abstract base class for all integrations.

    Provides common functionality:
    - Connection management
    - Rate limiting
    - Error handling
    - Retry logic
    """

    def __init__(self, config: IntegrationConfig):
        self.config = config
        self.status = IntegrationStatus.DISCONNECTED
        self._request_count = 0
        self._last_request_time: Optional[datetime] = None
        self._error_message: Optional[str] = None

    @property
    def name(self) -> str:
        return self.config.name

    @property
    def is_enabled(self) -> bool:
        return self.config.enabled

    @property
    def is_connected(self) -> bool:
        return self.status == IntegrationStatus.CONNECTED

    @abstractmethod
    def connect(self) -> bool:
        """Establish connection to the external service."""
        pass

    @abstractmethod
    def disconnect(self) -> bool:
        """Close connection to the external service."""
        pass

    @abstractmethod
    def test_connection(self) -> Dict[str, Any]:
        """Test the connection and return status."""
        pass

    @abstractmethod
    def send_notification(self, payload: NotificationPayload) -> Dict[str, Any]:
        """Send a notification to the external service."""
        pass

    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limits."""
        if not self._last_request_time:
            return True

        elapsed = (datetime.utcnow() - self._last_request_time).total_seconds()
        if elapsed < 60:
            if self._request_count >= self.config.rate_limit:
                self.status = IntegrationStatus.RATE_LIMITED
                return False
        else:
            self._request_count = 0

        return True

    def _record_request(self) -> None:
        """Record a request for rate limiting."""
        self._request_count += 1
        self._last_request_time = datetime.utcnow()

    def _handle_error(self, error: Exception) -> Dict[str, Any]:
        """Handle and log errors."""
        self._error_message = str(error)
        self.status = IntegrationStatus.ERROR
        logger.error(f"Integration {self.name} error: {error}")
        return {
            "success": False,
            "error": str(error),
            "integration": self.name,
        }

    def get_status(self) -> Dict[str, Any]:
        """Get current integration status."""
        return {
            "name": self.name,
            "enabled": self.is_enabled,
            "status": self.status.value,
            "error": self._error_message,
            "request_count": self._request_count,
        }


class WebhookMixin:
    """Mixin for webhook-based integrations."""

    def _build_webhook_payload(
        self,
        payload: NotificationPayload,
        format_type: str = "json",
    ) -> Dict[str, Any]:
        """Build webhook payload in the specified format."""
        if format_type == "json":
            return payload.to_dict()
        elif format_type == "form":
            return {k: str(v) for k, v in payload.to_dict().items()}
        else:
            return payload.to_dict()

    def _get_severity_color(self, severity: Optional[str]) -> str:
        """Get color code for severity level."""
        colors = {
            "critical": "#FF0000",  # Red
            "high": "#FF6600",      # Orange
            "medium": "#FFCC00",    # Yellow
            "low": "#00CC00",       # Green
            "info": "#0066FF",      # Blue
        }
        return colors.get(severity.lower() if severity else "info", "#808080")
