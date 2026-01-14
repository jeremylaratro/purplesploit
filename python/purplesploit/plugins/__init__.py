"""
PurpleSploit Plugin Marketplace.

Provides module installation, versioning, and community repository access.
"""

from .manager import PluginManager
from .models import Plugin, PluginManifest, PluginVersion
from .repository import PluginRepository

__all__ = [
    "PluginManager",
    "Plugin",
    "PluginManifest",
    "PluginVersion",
    "PluginRepository",
]
