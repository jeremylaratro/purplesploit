"""
External Integrations for PurpleSploit

Provides connectivity to external platforms for notifications,
issue tracking, and security monitoring.
"""

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
from .manager import IntegrationManager, IntegrationManagerConfig

__all__ = [
    # Base classes
    "BaseIntegration",
    "IntegrationConfig",
    "IntegrationStatus",
    "NotificationPayload",
    "NotificationPriority",
    # Notification integrations
    "SlackIntegration",
    "SlackConfig",
    "TeamsIntegration",
    "TeamsConfig",
    # Ticketing integrations
    "JiraIntegration",
    "JiraConfig",
    "GitHubIssuesIntegration",
    "GitHubConfig",
    # SIEM integrations
    "SIEMWebhook",
    "SIEMConfig",
    "SplunkIntegration",
    "SplunkConfig",
    "ElasticIntegration",
    "ElasticConfig",
    # Manager
    "IntegrationManager",
    "IntegrationManagerConfig",
]
