"""
Plugin Manager for PurpleSploit.

Handles installation, updates, and management of plugins.
"""

from pathlib import Path
from typing import List, Optional, Dict, Any, Set
from datetime import datetime
import json
import tarfile
import shutil
import logging
import subprocess
import sys

from .models import Plugin, PluginManifest, PluginStatus, PluginCategory
from .repository import PluginRepository, LocalPluginRepository


logger = logging.getLogger(__name__)


class PluginManager:
    """
    Manages plugin lifecycle: install, update, enable/disable, uninstall.
    """

    def __init__(
        self,
        plugins_dir: Optional[Path] = None,
        config_dir: Optional[Path] = None,
        framework=None,
    ):
        """
        Initialize plugin manager.

        Args:
            plugins_dir: Directory where plugins are installed
            config_dir: Configuration directory
            framework: Reference to PurpleSploit framework
        """
        self.framework = framework
        self.plugins_dir = plugins_dir or Path.home() / ".purplesploit" / "plugins"
        self.config_dir = config_dir or Path.home() / ".purplesploit" / "config"

        self.plugins_dir.mkdir(parents=True, exist_ok=True)
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # State file tracking installed plugins
        self.state_file = self.config_dir / "plugins.json"

        # Repositories
        self._repositories: Dict[str, PluginRepository] = {}
        self._installed: Dict[str, Plugin] = {}

        # Load state
        self._load_state()

        # Add default repository
        self.add_repository(PluginRepository())

    def _load_state(self) -> None:
        """Load installed plugins state."""
        if self.state_file.exists():
            try:
                with open(self.state_file) as f:
                    data = json.load(f)

                for plugin_data in data.get("installed", []):
                    try:
                        plugin = Plugin.from_dict(plugin_data)
                        self._installed[plugin.name] = plugin
                    except Exception as e:
                        logger.warning(f"Failed to load plugin state: {e}")

            except Exception as e:
                logger.error(f"Failed to load plugins state: {e}")

    def _save_state(self) -> None:
        """Save installed plugins state."""
        data = {
            "installed": [p.to_dict() for p in self._installed.values()],
            "last_updated": datetime.now().isoformat(),
        }

        try:
            with open(self.state_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save plugins state: {e}")

    def add_repository(self, repo: PluginRepository) -> None:
        """Add a plugin repository."""
        self._repositories[repo.name] = repo
        logger.info(f"Added repository: {repo.name}")

    def remove_repository(self, name: str) -> bool:
        """Remove a plugin repository."""
        if name in self._repositories:
            del self._repositories[name]
            return True
        return False

    def list_repositories(self) -> List[PluginRepository]:
        """Get list of configured repositories."""
        return list(self._repositories.values())

    def search(
        self,
        query: str = "",
        category: Optional[PluginCategory] = None,
        tags: Optional[List[str]] = None,
        installed_only: bool = False,
    ) -> List[Plugin]:
        """
        Search for plugins across all repositories.

        Args:
            query: Search query
            category: Filter by category
            tags: Filter by tags
            installed_only: Only show installed plugins

        Returns:
            List of matching plugins
        """
        if installed_only:
            plugins = list(self._installed.values())
            if query:
                query_lower = query.lower()
                plugins = [
                    p for p in plugins
                    if query_lower in p.name.lower() or query_lower in p.manifest.description.lower()
                ]
            if category:
                plugins = [p for p in plugins if p.manifest.category == category]
            if tags:
                plugins = [p for p in plugins if any(t in p.manifest.tags for t in tags)]
            return plugins

        # Search all repositories
        seen: Set[str] = set()
        results: List[Plugin] = []

        for repo in self._repositories.values():
            for plugin in repo.list_plugins(category=category, tags=tags, search=query or None):
                if plugin.name in seen:
                    continue
                seen.add(plugin.name)

                # Update with installed status
                if plugin.name in self._installed:
                    installed = self._installed[plugin.name]
                    plugin.status = installed.status
                    plugin.installed_version = installed.installed_version
                    plugin.install_path = installed.install_path
                    plugin.installed_at = installed.installed_at
                    plugin.enabled = installed.enabled

                    # Check for updates
                    if plugin.has_update:
                        plugin.status = PluginStatus.UPDATE_AVAILABLE

                results.append(plugin)

        return results

    def get_plugin(self, name: str) -> Optional[Plugin]:
        """Get plugin by name."""
        # Check installed first
        if name in self._installed:
            installed = self._installed[name]
            # Also check repos for updates
            for repo in self._repositories.values():
                remote = repo.get_plugin(name)
                if remote:
                    installed.available_versions = remote.available_versions
                    if installed.has_update:
                        installed.status = PluginStatus.UPDATE_AVAILABLE
                    break
            return installed

        # Search repositories
        for repo in self._repositories.values():
            plugin = repo.get_plugin(name)
            if plugin:
                return plugin

        return None

    def install(
        self,
        name: str,
        version: Optional[str] = None,
        force: bool = False,
    ) -> Plugin:
        """
        Install a plugin.

        Args:
            name: Plugin name
            version: Specific version (default: latest)
            force: Force reinstall

        Returns:
            Installed plugin

        Raises:
            ValueError: If plugin not found
            RuntimeError: If installation fails
        """
        # Get plugin info
        plugin = None
        source_repo = None

        for repo in self._repositories.values():
            plugin = repo.get_plugin(name)
            if plugin:
                source_repo = repo
                break

        if not plugin:
            raise ValueError(f"Plugin not found: {name}")

        # Check if already installed
        if name in self._installed and not force:
            installed = self._installed[name]
            if version and installed.installed_version == version:
                logger.info(f"{name} v{version} already installed")
                return installed
            elif not version:
                logger.info(f"{name} already installed (use force=True to reinstall)")
                return installed

        # Check dependencies
        self._check_dependencies(plugin)

        # Download
        logger.info(f"Downloading {name}...")
        package_path = source_repo.download_plugin(plugin, version)

        # Install
        logger.info(f"Installing {name}...")
        install_path = self.plugins_dir / name

        if install_path.exists():
            shutil.rmtree(install_path)

        install_path.mkdir(parents=True)

        # Extract package with path traversal protection
        with tarfile.open(package_path, "r:gz") as tar:
            # Validate all paths before extraction to prevent directory traversal attacks
            extract_base = install_path.parent.resolve()
            for member in tar.getmembers():
                member_path = (extract_base / member.name).resolve()
                # Check if resolved path escapes the extraction directory
                if not str(member_path).startswith(str(extract_base)):
                    raise RuntimeError(
                        f"Security: Malicious path detected in plugin archive: {member.name}"
                    )
                # Also check for symlinks pointing outside
                if member.issym() or member.islnk():
                    link_target = (extract_base / member.linkname).resolve()
                    if not str(link_target).startswith(str(extract_base)):
                        raise RuntimeError(
                            f"Security: Malicious symlink detected in plugin archive: {member.name} -> {member.linkname}"
                        )
            # Safe to extract after validation
            tar.extractall(extract_base)

        # Install Python dependencies
        if plugin.manifest.python_dependencies:
            self._install_python_dependencies(plugin.manifest.python_dependencies)

        # Update plugin state
        plugin.status = PluginStatus.INSTALLED
        plugin.installed_version = version or plugin.latest_version or plugin.version
        plugin.install_path = str(install_path)
        plugin.installed_at = datetime.now()
        plugin.enabled = True

        self._installed[name] = plugin
        self._save_state()

        logger.info(f"Installed {name} v{plugin.installed_version}")
        return plugin

    def uninstall(self, name: str, keep_config: bool = False) -> bool:
        """
        Uninstall a plugin.

        Args:
            name: Plugin name
            keep_config: Keep configuration files

        Returns:
            True if uninstalled
        """
        if name not in self._installed:
            logger.warning(f"Plugin not installed: {name}")
            return False

        plugin = self._installed[name]

        # Remove plugin directory
        if plugin.install_path:
            install_path = Path(plugin.install_path)
            if install_path.exists():
                shutil.rmtree(install_path)

        # Remove from state
        del self._installed[name]
        self._save_state()

        logger.info(f"Uninstalled {name}")
        return True

    def update(self, name: str, version: Optional[str] = None) -> Plugin:
        """
        Update a plugin to newer version.

        Args:
            name: Plugin name
            version: Target version (default: latest)

        Returns:
            Updated plugin
        """
        if name not in self._installed:
            raise ValueError(f"Plugin not installed: {name}")

        plugin = self.get_plugin(name)
        if not plugin:
            raise ValueError(f"Plugin not found in repositories: {name}")

        if version:
            target_version = version
        elif plugin.latest_version:
            target_version = plugin.latest_version
        else:
            logger.info(f"{name} is already at latest version")
            return self._installed[name]

        # Check if update needed
        from packaging.version import Version
        current = Version(plugin.installed_version or "0.0.0")
        target = Version(target_version)

        if current >= target:
            logger.info(f"{name} is already at version {plugin.installed_version}")
            return self._installed[name]

        # Install new version
        return self.install(name, target_version, force=True)

    def enable(self, name: str) -> bool:
        """Enable a disabled plugin."""
        if name not in self._installed:
            return False

        self._installed[name].enabled = True
        self._installed[name].status = PluginStatus.INSTALLED
        self._save_state()
        return True

    def disable(self, name: str) -> bool:
        """Disable a plugin without uninstalling."""
        if name not in self._installed:
            return False

        self._installed[name].enabled = False
        self._installed[name].status = PluginStatus.DISABLED
        self._save_state()
        return True

    def list_installed(self) -> List[Plugin]:
        """Get list of installed plugins."""
        return list(self._installed.values())

    def check_updates(self) -> List[Plugin]:
        """Check for available updates."""
        updates = []

        for name, installed in self._installed.items():
            for repo in self._repositories.values():
                remote = repo.get_plugin(name)
                if remote and remote.available_versions:
                    installed.available_versions = remote.available_versions
                    if installed.has_update:
                        updates.append(installed)
                    break

        return updates

    def _check_dependencies(self, plugin: Plugin) -> None:
        """Check and resolve plugin dependencies."""
        for dep in plugin.manifest.dependencies:
            if dep.name not in self._installed:
                if not dep.optional:
                    raise RuntimeError(
                        f"Missing dependency: {dep.name} ({dep.version_constraint})"
                    )
            else:
                installed = self._installed[dep.name]
                if not dep.is_satisfied(installed.installed_version):
                    raise RuntimeError(
                        f"Dependency version mismatch: {dep.name} requires {dep.version_constraint}, "
                        f"installed {installed.installed_version}"
                    )

    def _install_python_dependencies(self, packages: List[str]) -> None:
        """Install Python dependencies via pip."""
        if not packages:
            return

        logger.info(f"Installing Python dependencies: {', '.join(packages)}")

        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install",
                "--quiet", "--disable-pip-version-check",
                *packages
            ])
        except subprocess.CalledProcessError as e:
            logger.warning(f"Failed to install Python dependencies: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get plugin statistics."""
        installed = self.list_installed()
        updates = self.check_updates()

        by_category = {}
        for plugin in installed:
            cat = plugin.manifest.category.value
            by_category[cat] = by_category.get(cat, 0) + 1

        return {
            "total_installed": len(installed),
            "enabled": sum(1 for p in installed if p.enabled),
            "disabled": sum(1 for p in installed if not p.enabled),
            "updates_available": len(updates),
            "by_category": by_category,
        }

    def load_plugin_modules(self) -> List[str]:
        """
        Load plugin modules into the framework.

        Returns:
            List of loaded module paths
        """
        loaded = []

        for plugin in self._installed.values():
            if not plugin.enabled:
                continue

            if not plugin.install_path:
                continue

            install_path = Path(plugin.install_path)
            if not install_path.exists():
                logger.warning(f"Plugin path not found: {plugin.name}")
                plugin.status = PluginStatus.BROKEN
                continue

            # Add to Python path if needed
            plugin_src = install_path / "src"
            if plugin_src.exists():
                if str(plugin_src) not in sys.path:
                    sys.path.insert(0, str(plugin_src))

            # Register module with framework
            if self.framework and plugin.manifest.module_path:
                try:
                    # Import and register module
                    module_file = install_path / f"{plugin.manifest.module_path.replace('/', '/')}.py"
                    if module_file.exists():
                        loaded.append(plugin.manifest.module_path)
                        logger.info(f"Loaded plugin module: {plugin.manifest.module_path}")
                except Exception as e:
                    logger.error(f"Failed to load plugin {plugin.name}: {e}")
                    plugin.status = PluginStatus.BROKEN

        self._save_state()
        return loaded
