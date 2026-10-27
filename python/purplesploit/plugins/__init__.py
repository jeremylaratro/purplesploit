"""
PurpleSploit local plugin lifecycle and repository interfaces.

Provides module installation, versioning, and community repository access.
"""

from .manager import PluginManager
from .models import Plugin, PluginManifest, PluginVersion, PluginStatus
from .repository import PluginRepository, LocalPluginRepository

__all__ = [
    "PluginManager",
    "Plugin",
    "PluginManifest",
    "PluginVersion",
    "PluginStatus",
    "PluginRepository",
    "LocalPluginRepository",
]
