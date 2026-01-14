"""
Plugin Repository for PurpleSploit Marketplace.

Handles communication with remote plugin repositories.
"""

from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime
import json
import hashlib
import tempfile
import shutil
import logging

from .models import Plugin, PluginManifest, PluginVersion, PluginCategory, PluginStatus


logger = logging.getLogger(__name__)


class PluginRepository:
    """
    Interface to a plugin repository (local or remote).

    Supports browsing, searching, and downloading plugins.
    """

    # Default community repository
    DEFAULT_REPO_URL = "https://raw.githubusercontent.com/purplesploit/plugins/main"

    def __init__(
        self,
        name: str = "community",
        url: str = None,
        cache_dir: Optional[Path] = None,
        cache_ttl: int = 3600,  # 1 hour
    ):
        """
        Initialize repository connection.

        Args:
            name: Repository name
            url: Repository URL (defaults to community repo)
            cache_dir: Local cache directory
            cache_ttl: Cache time-to-live in seconds
        """
        self.name = name
        self.url = url or self.DEFAULT_REPO_URL
        self.cache_dir = cache_dir or Path.home() / ".purplesploit" / "plugin_cache"
        self.cache_ttl = cache_ttl
        self._index_cache: Optional[Dict[str, Any]] = None
        self._cache_timestamp: Optional[datetime] = None

        # Create cache directory
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_cached_index(self) -> Optional[Dict[str, Any]]:
        """Get cached index if valid."""
        if self._index_cache and self._cache_timestamp:
            age = (datetime.now() - self._cache_timestamp).total_seconds()
            if age < self.cache_ttl:
                return self._index_cache

        # Try file cache
        cache_file = self.cache_dir / f"{self.name}_index.json"
        if cache_file.exists():
            try:
                stat = cache_file.stat()
                age = (datetime.now().timestamp() - stat.st_mtime)
                if age < self.cache_ttl:
                    with open(cache_file) as f:
                        self._index_cache = json.load(f)
                        self._cache_timestamp = datetime.fromtimestamp(stat.st_mtime)
                        return self._index_cache
            except Exception as e:
                logger.warning(f"Failed to read cache: {e}")

        return None

    def _fetch_index(self) -> Dict[str, Any]:
        """Fetch index from remote repository."""
        import urllib.request
        import urllib.error

        index_url = f"{self.url}/index.json"

        try:
            with urllib.request.urlopen(index_url, timeout=10) as response:
                data = json.loads(response.read().decode())
        except urllib.error.URLError as e:
            logger.error(f"Failed to fetch repository index: {e}")
            # Return cached data if available, even if expired
            if self._index_cache:
                return self._index_cache
            # Return empty index as fallback
            return {"plugins": [], "updated": datetime.now().isoformat()}

        # Update cache
        self._index_cache = data
        self._cache_timestamp = datetime.now()

        # Save to file cache
        cache_file = self.cache_dir / f"{self.name}_index.json"
        try:
            with open(cache_file, "w") as f:
                json.dump(data, f)
        except Exception as e:
            logger.warning(f"Failed to save cache: {e}")

        return data

    def get_index(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Get repository index.

        Args:
            force_refresh: Bypass cache and fetch fresh data

        Returns:
            Repository index dictionary
        """
        if not force_refresh:
            cached = self._get_cached_index()
            if cached:
                return cached

        return self._fetch_index()

    def list_plugins(
        self,
        category: Optional[PluginCategory] = None,
        tags: Optional[List[str]] = None,
        search: Optional[str] = None,
    ) -> List[Plugin]:
        """
        List available plugins with optional filtering.

        Args:
            category: Filter by category
            tags: Filter by tags (any match)
            search: Search in name and description

        Returns:
            List of matching plugins
        """
        index = self.get_index()
        plugins = []

        for plugin_data in index.get("plugins", []):
            try:
                manifest = PluginManifest.from_dict(plugin_data["manifest"])
                plugin = Plugin(
                    manifest=manifest,
                    status=PluginStatus.NOT_INSTALLED,
                    rating=plugin_data.get("rating", 0.0),
                    downloads=plugin_data.get("downloads", 0),
                )

                # Parse versions
                for version_data in plugin_data.get("versions", []):
                    plugin.available_versions.append(PluginVersion(
                        version=version_data["version"],
                        release_date=datetime.fromisoformat(version_data.get("release_date", "2024-01-01")),
                        changelog=version_data.get("changelog", ""),
                        checksum=version_data.get("checksum", ""),
                        download_url=version_data.get("download_url", ""),
                        size_bytes=version_data.get("size_bytes", 0),
                    ))

                # Apply filters
                if category and manifest.category != category:
                    continue

                if tags:
                    if not any(t in manifest.tags for t in tags):
                        continue

                if search:
                    search_lower = search.lower()
                    if (search_lower not in manifest.name.lower() and
                        search_lower not in manifest.description.lower()):
                        continue

                plugins.append(plugin)

            except Exception as e:
                logger.warning(f"Failed to parse plugin: {e}")
                continue

        return plugins

    def get_plugin(self, name: str, version: Optional[str] = None) -> Optional[Plugin]:
        """
        Get a specific plugin by name.

        Args:
            name: Plugin name
            version: Specific version (default: latest)

        Returns:
            Plugin or None if not found
        """
        plugins = self.list_plugins()
        for plugin in plugins:
            if plugin.name.lower() == name.lower():
                return plugin
        return None

    def search(self, query: str) -> List[Plugin]:
        """
        Search for plugins.

        Args:
            query: Search query

        Returns:
            Matching plugins
        """
        return self.list_plugins(search=query)

    def download_plugin(
        self,
        plugin: Plugin,
        version: Optional[str] = None,
        dest_dir: Optional[Path] = None,
    ) -> Path:
        """
        Download a plugin package.

        Args:
            plugin: Plugin to download
            version: Version to download (default: latest)
            dest_dir: Destination directory

        Returns:
            Path to downloaded file

        Raises:
            ValueError: If version not found
            RuntimeError: If download fails
        """
        import urllib.request
        import urllib.error

        # Find version
        if version:
            version_info = next(
                (v for v in plugin.available_versions if v.version == version),
                None
            )
            if not version_info:
                raise ValueError(f"Version {version} not found for {plugin.name}")
        elif plugin.available_versions:
            from packaging.version import Version
            version_info = max(
                plugin.available_versions,
                key=lambda v: Version(v.version)
            )
        else:
            raise ValueError(f"No versions available for {plugin.name}")

        # Determine download URL
        if version_info.download_url:
            download_url = version_info.download_url
        else:
            # Construct from repository URL
            download_url = f"{self.url}/plugins/{plugin.name}/{version_info.version}/{plugin.name}.tar.gz"

        # Download to cache
        dest_dir = dest_dir or self.cache_dir / "downloads"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_file = dest_dir / f"{plugin.name}-{version_info.version}.tar.gz"

        try:
            with urllib.request.urlopen(download_url, timeout=60) as response:
                content = response.read()

            # Verify checksum if available
            if version_info.checksum:
                if not version_info.verify_checksum(content):
                    raise RuntimeError(f"Checksum verification failed for {plugin.name}")

            with open(dest_file, "wb") as f:
                f.write(content)

            logger.info(f"Downloaded {plugin.name} v{version_info.version}")
            return dest_file

        except urllib.error.URLError as e:
            raise RuntimeError(f"Failed to download {plugin.name}: {e}")

    def get_categories(self) -> List[PluginCategory]:
        """Get list of available categories with counts."""
        plugins = self.list_plugins()
        categories = {}

        for plugin in plugins:
            cat = plugin.manifest.category
            categories[cat] = categories.get(cat, 0) + 1

        return sorted(categories.keys(), key=lambda c: c.value)

    def get_popular_tags(self, limit: int = 20) -> List[tuple]:
        """Get most popular tags."""
        plugins = self.list_plugins()
        tags = {}

        for plugin in plugins:
            for tag in plugin.manifest.tags:
                tags[tag] = tags.get(tag, 0) + 1

        return sorted(tags.items(), key=lambda x: x[1], reverse=True)[:limit]

    def refresh(self) -> None:
        """Force refresh the repository index."""
        self._index_cache = None
        self._cache_timestamp = None
        self.get_index(force_refresh=True)


class LocalPluginRepository(PluginRepository):
    """
    Local plugin repository for offline or private use.
    """

    def __init__(self, path: Path):
        """
        Initialize local repository.

        Args:
            path: Path to local repository directory
        """
        self.path = Path(path)
        super().__init__(
            name="local",
            url=None,
            cache_dir=path / ".cache",
        )

    def _fetch_index(self) -> Dict[str, Any]:
        """Build index from local filesystem."""
        plugins = []
        plugins_dir = self.path / "plugins"

        if not plugins_dir.exists():
            return {"plugins": [], "updated": datetime.now().isoformat()}

        for plugin_dir in plugins_dir.iterdir():
            if not plugin_dir.is_dir():
                continue

            manifest_file = plugin_dir / "plugin.yaml"
            if not manifest_file.exists():
                manifest_file = plugin_dir / "plugin.json"

            if manifest_file.exists():
                try:
                    import yaml
                    with open(manifest_file) as f:
                        if manifest_file.suffix == ".yaml":
                            manifest_data = yaml.safe_load(f)
                        else:
                            manifest_data = json.load(f)

                    plugins.append({
                        "manifest": manifest_data,
                        "versions": [{
                            "version": manifest_data.get("version", "0.0.1"),
                            "release_date": datetime.now().isoformat(),
                        }],
                    })
                except Exception as e:
                    logger.warning(f"Failed to read {manifest_file}: {e}")

        return {
            "plugins": plugins,
            "updated": datetime.now().isoformat(),
        }

    def download_plugin(
        self,
        plugin: Plugin,
        version: Optional[str] = None,
        dest_dir: Optional[Path] = None,
    ) -> Path:
        """Copy plugin from local repository."""
        source = self.path / "plugins" / plugin.name
        if not source.exists():
            raise ValueError(f"Plugin not found: {plugin.name}")

        dest_dir = dest_dir or self.cache_dir / "downloads"
        dest_dir.mkdir(parents=True, exist_ok=True)

        # Create tarball of plugin directory
        dest_file = dest_dir / f"{plugin.name}-{plugin.version}.tar.gz"
        shutil.make_archive(
            str(dest_file.with_suffix("")),
            "gztar",
            source.parent,
            source.name,
        )

        return dest_file
