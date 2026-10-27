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
import re
import importlib
import tempfile
import types
import uuid

from .models import Plugin, PluginManifest, PluginStatus, PluginCategory
from .repository import PluginRepository
from .security import PluginPermissionPolicy, PluginTrustStore, isolated_plugin_class


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
        trust_store: PluginTrustStore | None = None,
        strict_security: bool = False,
        permission_policy: PluginPermissionPolicy | None = None,
    ):
        """
        Initialize plugin manager.

        Args:
            plugins_dir: Directory where plugins are installed
            config_dir: Configuration directory
            framework: Reference to PurpleSploit framework
        """
        self.framework = framework
        self.trust_store = trust_store or PluginTrustStore()
        self.strict_security = strict_security
        self.permission_policy = permission_policy or PluginPermissionPolicy()
        self.plugins_dir = (
            Path(plugins_dir)
            if plugins_dir is not None
            else Path.home() / ".purplesploit" / "plugins"
        )
        self.config_dir = (
            Path(config_dir) if config_dir is not None else Path.home() / ".purplesploit" / "config"
        )

        self.plugins_dir.mkdir(parents=True, exist_ok=True)
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # State file tracking installed plugins
        self.state_file = self.config_dir / "plugins.json"

        # Repositories
        self._repositories: Dict[str, PluginRepository] = {}
        self._installed: Dict[str, Plugin] = {}
        self._loaded: Dict[str, tuple] = {}
        self.last_uninstall_path: Optional[Path] = None

        # Load state
        self._load_state()

        # Add default repository
        self.add_repository(PluginRepository())
        self.discover_plugins()
        if self.framework is not None:
            self.load_plugin_modules()

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

        temporary = self.state_file.with_suffix(".json.tmp")
        try:
            temporary.write_text(json.dumps(data, indent=2))
            temporary.chmod(0o600)
            temporary.replace(self.state_file)
            self.state_file.chmod(0o600)
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _read_manifest(directory: Path) -> PluginManifest:
        for filename in ("plugin.yaml", "plugin.json"):
            path = directory / filename
            if path.is_file():
                if path.suffix == ".json":
                    data = json.loads(path.read_text())
                else:
                    import yaml

                    data = yaml.safe_load(path.read_text())
                return PluginManifest.from_dict(data)
        raise ValueError(f"No plugin.yaml or plugin.json in {directory}")

    def discover_plugins(self) -> List[Plugin]:
        """Discover immediate plugin directories; preserve persisted enable flags."""
        discovered = []
        for directory in sorted(self.plugins_dir.iterdir()):
            if not directory.is_dir() or directory.name.startswith("."):
                continue
            try:
                manifest = self._read_manifest(directory)
                if manifest.name != directory.name:
                    raise ValueError("Manifest name must match the plugin directory")
                self._verify_security(directory, manifest)
                existing = self._installed.get(manifest.name)
                if existing is None:
                    existing = Plugin(manifest=manifest, installed_at=datetime.now())
                    self._installed[manifest.name] = existing
                existing.manifest = manifest
                existing.install_path = str(directory.resolve())
                existing.installed_version = manifest.version
                existing.status = (
                    PluginStatus.INSTALLED if existing.enabled else PluginStatus.DISABLED
                )
                discovered.append(existing)
            except Exception as exc:
                logger.warning("Cannot discover plugin %s: %s", directory, exc)
        if discovered:
            self._save_state()
        return discovered

    def install_local(self, source: Path, force: bool = False) -> Plugin:
        """Copy a local directory and register its manifest entry point immediately."""
        source = Path(source).resolve()
        manifest = self._read_manifest(source)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", manifest.name):
            raise ValueError("Invalid plugin name")
        if manifest.name in self._installed and not force:
            return self._installed[manifest.name]
        self._verify_security(source, manifest)
        plugin = Plugin(manifest=manifest)
        self._check_dependencies(plugin)
        with tempfile.TemporaryDirectory(prefix=".install-", dir=self.plugins_dir) as temporary:
            staging = Path(temporary) / manifest.name
            shutil.copytree(source, staging)
            return self._activate_install(plugin, staging)

    def _activate_install(self, plugin: Plugin, staging: Path) -> Plugin:
        """Publish a staged directory, restoring the old plugin on any failure."""
        name = plugin.name
        destination = self.plugins_dir / name
        previous = self._installed.get(name)
        previous_loaded = name in self._loaded
        backup = staging.parent / f"{name}.previous"
        self._unload_plugin(name)
        published = False
        try:
            if destination.exists():
                destination.rename(backup)
            staging.rename(destination)
            published = True
            plugin.install_path = str(destination.resolve())
            plugin.installed_version = plugin.version
            plugin.installed_at = datetime.now()
            plugin.enabled = True
            plugin.status = PluginStatus.INSTALLED
            self._installed[name] = plugin
            if self.framework is not None:
                self._load_plugin(plugin)
            self._save_state()
        except Exception:
            self._unload_plugin(name)
            if published and destination.exists():
                shutil.rmtree(destination)
            if backup.exists():
                backup.rename(destination)
            if previous is None:
                self._installed.pop(name, None)
            else:
                self._installed[name] = previous
                if previous_loaded:
                    self._load_plugin(previous)
            raise
        return plugin

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
                    p
                    for p in plugins
                    if query_lower in p.name.lower()
                    or query_lower in p.manifest.description.lower()
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
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name):
            raise ValueError("Invalid plugin name")

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
        with tempfile.TemporaryDirectory(prefix=".install-", dir=self.plugins_dir) as temporary:
            install_path = Path(temporary) / name
            install_path.mkdir()
            self._extract_package(package_path, install_path, name)
            if plugin.manifest.python_dependencies:
                self._install_python_dependencies(plugin.manifest.python_dependencies)
            # Packaged manifests describe the actual version being installed.
            if any(
                (install_path / filename).exists() for filename in ("plugin.yaml", "plugin.json")
            ):
                plugin.manifest = self._read_manifest(install_path)
                if plugin.name != name:
                    raise ValueError("Packaged manifest name differs from requested plugin")
            elif version:
                plugin.manifest.version = version
            self._verify_security(install_path, plugin.manifest)
            return self._activate_install(plugin, install_path)

    def _verify_security(self, directory: Path, manifest: PluginManifest) -> None:
        """Apply permission admission, plus fail-closed trust checks in strict mode."""
        try:
            self.permission_policy.validate(directory, manifest.permissions)
        except SyntaxError as exc:
            if self.strict_security:
                raise PermissionError(f"Plugin source cannot be parsed safely: {exc}") from exc
            logger.warning("Skipping permission scan for legacy non-Python payload: %s", exc)
        if not self.strict_security:
            return
        if manifest.python_dependencies:
            raise PermissionError(
                "Strict plugins must vendor reviewed dependencies; host pip installation is disabled"
            )
        if not manifest.signed or not manifest.signature or not manifest.signing_key_id:
            raise PermissionError("Strict plugin mode requires a trusted signature")
        self.trust_store.verify(
            directory,
            key_id=manifest.signing_key_id,
            signature=manifest.signature,
        )

    @staticmethod
    def _extract_package(package_path: Path, install_path: Path, name: str) -> None:
        """Extract a package into a staging directory before replacing any installation."""

        # Extract regular files only, with traversal and decompression limits.
        with tarfile.open(package_path, "r:gz") as tar:
            members = tar.getmembers()
            if len(members) > 10_000:
                raise RuntimeError("Plugin archive contains too many entries")
            if sum(member.size for member in members) > 512 * 1024 * 1024:
                raise RuntimeError("Plugin archive expands beyond the 512 MiB limit")

            # Support archives either wrapped in a plugin-name directory or
            # containing the plugin files at their root.
            top_level = {
                Path(member.name).parts[0] for member in members if Path(member.name).parts
            }
            extract_base = install_path.parent if top_level == {name} else install_path
            resolved_base = install_path.resolve()

            for member in members:
                destination = (extract_base / member.name).resolve()
                try:
                    destination.relative_to(resolved_base)
                except ValueError:
                    raise RuntimeError(
                        f"Security: Malicious path detected in plugin archive: {member.name}"
                    )
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
                    continue
                if not member.isfile():
                    raise RuntimeError(f"Security: Unsupported archive entry: {member.name}")
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                source = tar.extractfile(member)
                if source is None:
                    raise RuntimeError(f"Unable to read plugin archive entry: {member.name}")
                with source, open(destination, "wb") as output:
                    shutil.copyfileobj(source, output)
                destination.chmod((member.mode & 0o155) | 0o600)

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

        # Move exactly this installation out of discovery, retaining its contents.
        archived = None
        if plugin.install_path:
            install_path = Path(plugin.install_path).resolve()
            if install_path != self.plugins_dir.resolve() / name:
                raise ValueError("Plugin installation path does not match its directory")
            if install_path.exists():
                archive_dir = self.plugins_dir / ".uninstalled"
                archive_dir.mkdir(exist_ok=True)
                archived = archive_dir / f"{name}-{uuid.uuid4().hex}"
                install_path.rename(archived)
        was_loaded = name in self._loaded
        self._unload_plugin(name)
        try:
            del self._installed[name]
            self._save_state()
        except Exception:
            self._installed[name] = plugin
            if archived is not None:
                archived.rename(install_path)
            if was_loaded:
                self._load_plugin(plugin)
            raise
        self.last_uninstall_path = archived

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

        plugin = self._installed[name]
        previous = (plugin.enabled, plugin.status, plugin.last_error)
        was_loaded = name in self._loaded
        if self.framework is not None:
            try:
                self._load_plugin(plugin)
            except Exception as exc:
                plugin.status = PluginStatus.BROKEN
                plugin.last_error = str(exc)
                self._save_state()
                return False
        plugin.enabled = True
        plugin.status = PluginStatus.INSTALLED
        plugin.last_error = ""
        try:
            self._save_state()
        except Exception:
            if not was_loaded:
                self._unload_plugin(name)
            plugin.enabled, plugin.status, plugin.last_error = previous
            raise
        return True

    def disable(self, name: str) -> bool:
        """Disable a plugin without uninstalling."""
        if name not in self._installed:
            return False

        plugin = self._installed[name]
        previous = (plugin.enabled, plugin.status, plugin.last_error)
        was_loaded = name in self._loaded
        self._unload_plugin(name)
        plugin.enabled = False
        plugin.status = PluginStatus.DISABLED
        try:
            self._save_state()
        except Exception:
            if was_loaded:
                self._load_plugin(plugin)
            plugin.enabled, plugin.status, plugin.last_error = previous
            raise
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
                    raise RuntimeError(f"Missing dependency: {dep.name} ({dep.version_constraint})")
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
        if self.strict_security:
            raise PermissionError("Host-environment dependency installation is disabled")

        logger.info(f"Installing Python dependencies: {', '.join(packages)}")

        try:
            subprocess.check_call(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    "--quiet",
                    "--disable-pip-version-check",
                    *packages,
                ]
            )
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
        if self.framework is None:
            return []
        loaded = []
        for plugin in self._installed.values():
            if plugin.enabled:
                try:
                    loaded.append(self._load_plugin(plugin))
                except Exception as exc:
                    plugin.status = PluginStatus.BROKEN
                    plugin.last_error = str(exc)
                    logger.error("Failed to load plugin %s: %s", plugin.name, exc)
        self._save_state()
        return loaded

    def _load_plugin(self, plugin: Plugin) -> str:
        """Import one manifest entry point under an isolated Python package name."""
        from purplesploit.core.module import BaseModule

        if plugin.name in self._loaded:
            return self._loaded[plugin.name][0]
        if not plugin.install_path:
            raise ValueError("Plugin has no installation path")
        directory = Path(plugin.install_path)
        if not directory.is_dir():
            raise FileNotFoundError(f"Plugin path not found: {directory}")
        module_path = plugin.manifest.module_path.removesuffix(".py").replace("/", ".")
        if not module_path or not all(part.isidentifier() for part in module_path.split(".")):
            raise ValueError("module_path must identify a Python module")
        if not plugin.manifest.main_class:
            raise ValueError("main_class is required")
        namespace = f"_purplesploit_plugin_{uuid.uuid4().hex}"
        source = directory / "src" if (directory / "src").is_dir() else directory
        package = types.ModuleType(namespace)
        package.__path__ = [str(source)]
        package.__package__ = namespace
        sys.modules[namespace] = package
        registry_path = f"plugin/{plugin.name}/{module_path.replace('.', '/')}"
        if self.strict_security:
            cls = isolated_plugin_class(directory, plugin.manifest)
            self.framework.register_module(registry_path, cls)
            self._loaded[plugin.name] = (registry_path, cls, namespace)
            plugin.status = PluginStatus.INSTALLED
            plugin.last_error = ""
            return registry_path
        try:
            importlib.invalidate_caches()
            module = importlib.import_module(f"{namespace}.{module_path}")
            cls = getattr(module, plugin.manifest.main_class)
            if not isinstance(cls, type) or not issubclass(cls, BaseModule) or cls is BaseModule:
                raise TypeError("main_class must be a BaseModule subclass")
            self.framework.register_module(registry_path, cls)
            self._loaded[plugin.name] = (registry_path, cls, namespace)
            plugin.status = PluginStatus.INSTALLED
            plugin.last_error = ""
            return registry_path
        except Exception:
            self._clear_imports(namespace)
            raise

    @staticmethod
    def _clear_imports(namespace: str) -> None:
        for key in list(sys.modules):
            if key == namespace or key.startswith(namespace + "."):
                del sys.modules[key]

    def _unload_plugin(self, name: str) -> None:
        loaded = self._loaded.pop(name, None)
        if loaded is None:
            return
        path, cls, namespace = loaded
        metadata = self.framework.get_module(path)
        if metadata is not None and metadata.instance is cls:
            self.framework.unregister_module(path)
        self._clear_imports(namespace)
