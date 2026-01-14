"""
Distributed Architecture for PurpleSploit

Provides agent deployment, task distribution, and
centralized findings aggregation across multiple nodes.
"""

# Core modules that always exist
from .task import Task, TaskStatus, TaskResult, TaskPriority, TaskQueue
from .transport import (
    Transport,
    TransportConfig,
    HTTPTransport,
    WebSocketTransport,
    ProxyTransport,
    create_transport,
)

__all__ = [
    "Task",
    "TaskStatus",
    "TaskResult",
    "TaskPriority",
    "TaskQueue",
    "Transport",
    "TransportConfig",
    "HTTPTransport",
    "WebSocketTransport",
    "ProxyTransport",
    "create_transport",
]

# Optional modules - import only if available
try:
    from .agent import Agent, AgentConfig, AgentStatus
    __all__.extend(["Agent", "AgentConfig", "AgentStatus"])
except ImportError:
    pass

try:
    from .coordinator import Coordinator, CoordinatorConfig
    __all__.extend(["Coordinator", "CoordinatorConfig"])
except ImportError:
    pass
