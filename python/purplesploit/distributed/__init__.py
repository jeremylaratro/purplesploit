"""
Distributed Architecture for PurpleSploit

Provides agent deployment, task distribution, and
centralized findings aggregation across multiple nodes.
"""

from .agent import Agent, AgentConfig, AgentStatus
from .coordinator import Coordinator, CoordinatorConfig
from .task import Task, TaskStatus, TaskResult
from .transport import Transport, HTTPTransport, WebSocketTransport

__all__ = [
    "Agent",
    "AgentConfig",
    "AgentStatus",
    "Coordinator",
    "CoordinatorConfig",
    "Task",
    "TaskStatus",
    "TaskResult",
    "Transport",
    "HTTPTransport",
    "WebSocketTransport",
]
