"""
Tests for purplesploit.plugins.manager module.
"""

import pytest
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
import json
import tempfile

from purplesploit.plugins.manager import PluginManager
from purplesploit.plugins.models import (
    Plugin,
    PluginManifest,
    PluginVersion,
    PluginStatus,
    PluginCategory,
)


class TestPluginManagerInit:
    """Tests for PluginManager initialization."""

    def test_init_creates_directories(self, tmp_path):
        """Test that init creates necessary directories."""
        plugins_dir = tmp_path / "plugins"
        config_dir = tmp_path / "config"

        manager = PluginManager(plugins_dir=plugins_dir, config_dir=config_dir)

        assert plugins_dir.exists()
        assert config_dir.exists()

    def test_init_loads_state(self, tmp_path):
        """Test that init loads existing state."""
        plugins_dir = tmp_path / "plugins"
        config_dir = tmp_path / "config"
        config_dir.mkdir(parents=True)

        # Create state file
        state_file = config_dir / "plugins.json"
        state_data = {
            "installed": [
                {
                    "manifest": {
                        "name": "existing-plugin",
                        "version": "1.0.0",
                        "description": "Test",
                        "author": "Author",
                    },
                    "status": "installed",
                    "installed_version": "1.0.0",
                }
            ]
        }
        with open(state_file, "w") as f:
            json.dump(state_data, f)

        manager = PluginManager(plugins_dir=plugins_dir, config_dir=config_dir)

        assert "existing-plugin" in manager._installed


class TestPluginManagerRepositories:
    """Tests for repository management."""

    def test_add_repository(self, tmp_path):
        """Test adding a repository."""
        manager = PluginManager(plugins_dir=tmp_path / "plugins", config_dir=tmp_path / "config")

        from purplesploit.plugins.repository import PluginRepository
        repo = PluginRepository(name="test-repo", url="https://example.com")
        manager.add_repository(repo)

        repos = manager.list_repositories()
        assert any(r.name == "test-repo" for r in repos)

    def test_remove_repository(self, tmp_path):
        """Test removing a repository."""
        manager = PluginManager(plugins_dir=tmp_path / "plugins", config_dir=tmp_path / "config")

        # Manager adds default repo, so we test removing that
        assert manager.remove_repository("community") is True
        assert manager.remove_repository("nonexistent") is False


class TestPluginManagerSearch:
    """Tests for plugin search functionality."""

    @pytest.fixture
    def manager_with_plugins(self, tmp_path):
        """Create manager with mocked repository."""
        manager = PluginManager(plugins_dir=tmp_path / "plugins", config_dir=tmp_path / "config")

        # Mock repository to return test plugins
        mock_repo = Mock()
        mock_repo.name = "test"
        mock_repo.list_plugins.return_value = [
            Plugin(
                manifest=PluginManifest(
                    name="web-scanner",
                    version="1.0.0",
                    description="Web scanner plugin",
                    author="Author",
                    category=PluginCategory.WEB,
                    tags=["web", "scanner"],
                )
            ),
            Plugin(
                manifest=PluginManifest(
                    name="network-tool",
                    version="2.0.0",
                    description="Network tool",
                    author="Author",
                    category=PluginCategory.NETWORK,
                    tags=["network"],
                )
            ),
        ]
        mock_repo.get_plugin.return_value = None
        manager._repositories = {"test": mock_repo}

        return manager

    def test_search_all(self, manager_with_plugins):
        """Test searching for all plugins."""
        plugins = manager_with_plugins.search()
        assert len(plugins) == 2

    def test_search_by_query(self, manager_with_plugins):
        """Test searching by query string."""
        plugins = manager_with_plugins.search(query="web")
        # Should find web-scanner since "web" is in both name and description
        web_plugins = [p for p in plugins if "web" in p.name.lower() or "web" in p.manifest.description.lower()]
        assert len(web_plugins) >= 1
        assert any(p.name == "web-scanner" for p in web_plugins)

    def test_search_by_category(self, manager_with_plugins):
        """Test searching by category."""
        # The mock returns all plugins regardless of category filter
        # since list_plugins is mocked to always return the same list
        # Update the mock to properly filter
        manager_with_plugins._repositories["test"].list_plugins.side_effect = lambda category=None, tags=None, search=None: [
            p for p in [
                Plugin(
                    manifest=PluginManifest(
                        name="web-scanner",
                        version="1.0.0",
                        description="Web scanner plugin",
                        author="Author",
                        category=PluginCategory.WEB,
                        tags=["web", "scanner"],
                    )
                ),
                Plugin(
                    manifest=PluginManifest(
                        name="network-tool",
                        version="2.0.0",
                        description="Network tool",
                        author="Author",
                        category=PluginCategory.NETWORK,
                        tags=["network"],
                    )
                ),
            ] if category is None or p.manifest.category == category
        ]
        plugins = manager_with_plugins.search(category=PluginCategory.NETWORK)
        assert len(plugins) == 1
        assert plugins[0].name == "network-tool"

    def test_search_installed_only(self, tmp_path):
        """Test searching installed plugins only."""
        manager = PluginManager(plugins_dir=tmp_path / "plugins", config_dir=tmp_path / "config")

        # Add an installed plugin
        manager._installed["test-plugin"] = Plugin(
            manifest=PluginManifest(
                name="test-plugin",
                version="1.0.0",
                description="Test",
                author="Author",
            ),
            status=PluginStatus.INSTALLED,
            installed_version="1.0.0",
        )

        plugins = manager.search(installed_only=True)
        assert len(plugins) == 1
        assert plugins[0].name == "test-plugin"


class TestPluginManagerInstall:
    """Tests for plugin installation."""

    def test_install_plugin_not_found(self, tmp_path):
        """Test installing non-existent plugin."""
        manager = PluginManager(plugins_dir=tmp_path / "plugins", config_dir=tmp_path / "config")

        # Mock empty repository
        mock_repo = Mock()
        mock_repo.get_plugin.return_value = None
        manager._repositories = {"test": mock_repo}

        with pytest.raises(ValueError, match="not found"):
            manager.install("nonexistent-plugin")

    def test_install_already_installed(self, tmp_path):
        """Test installing already installed plugin returns existing without reinstall."""
        manager = PluginManager(plugins_dir=tmp_path / "plugins", config_dir=tmp_path / "config")

        # Add installed plugin
        manager._installed["test-plugin"] = Plugin(
            manifest=PluginManifest(
                name="test-plugin",
                version="1.0.0",
                description="Test",
                author="Author",
            ),
            status=PluginStatus.INSTALLED,
            installed_version="1.0.0",
        )

        # Also need to mock repository to return the plugin
        mock_repo = Mock()
        mock_repo.get_plugin.return_value = Plugin(
            manifest=PluginManifest(
                name="test-plugin",
                version="1.0.0",
                description="Test",
                author="Author",
            )
        )
        manager._repositories = {"test": mock_repo}

        # Should return existing plugin without attempting download
        plugin = manager.install("test-plugin")
        assert plugin.installed_version == "1.0.0"
        # Should not have called download since already installed
        mock_repo.download_plugin.assert_not_called()


class TestPluginManagerUninstall:
    """Tests for plugin uninstallation."""

    def test_uninstall_not_installed(self, tmp_path):
        """Test uninstalling non-installed plugin."""
        manager = PluginManager(plugins_dir=tmp_path / "plugins", config_dir=tmp_path / "config")

        assert manager.uninstall("nonexistent") is False

    def test_uninstall_success(self, tmp_path):
        """Test successful uninstallation."""
        manager = PluginManager(plugins_dir=tmp_path / "plugins", config_dir=tmp_path / "config")

        # Create plugin directory
        plugin_dir = tmp_path / "plugins" / "test-plugin"
        plugin_dir.mkdir(parents=True)
        (plugin_dir / "plugin.py").write_text("# plugin")

        # Add installed plugin
        manager._installed["test-plugin"] = Plugin(
            manifest=PluginManifest(
                name="test-plugin",
                version="1.0.0",
                description="Test",
                author="Author",
            ),
            status=PluginStatus.INSTALLED,
            installed_version="1.0.0",
            install_path=str(plugin_dir),
        )

        assert manager.uninstall("test-plugin") is True
        assert "test-plugin" not in manager._installed
        assert not plugin_dir.exists()


class TestPluginManagerEnableDisable:
    """Tests for enable/disable functionality."""

    def test_enable_plugin(self, tmp_path):
        """Test enabling a disabled plugin."""
        manager = PluginManager(plugins_dir=tmp_path / "plugins", config_dir=tmp_path / "config")

        manager._installed["test-plugin"] = Plugin(
            manifest=PluginManifest(
                name="test-plugin",
                version="1.0.0",
                description="Test",
                author="Author",
            ),
            status=PluginStatus.DISABLED,
            installed_version="1.0.0",
            enabled=False,
        )

        assert manager.enable("test-plugin") is True
        assert manager._installed["test-plugin"].enabled is True
        assert manager._installed["test-plugin"].status == PluginStatus.INSTALLED

    def test_enable_nonexistent(self, tmp_path):
        """Test enabling non-existent plugin."""
        manager = PluginManager(plugins_dir=tmp_path / "plugins", config_dir=tmp_path / "config")

        assert manager.enable("nonexistent") is False

    def test_disable_plugin(self, tmp_path):
        """Test disabling a plugin."""
        manager = PluginManager(plugins_dir=tmp_path / "plugins", config_dir=tmp_path / "config")

        manager._installed["test-plugin"] = Plugin(
            manifest=PluginManifest(
                name="test-plugin",
                version="1.0.0",
                description="Test",
                author="Author",
            ),
            status=PluginStatus.INSTALLED,
            installed_version="1.0.0",
            enabled=True,
        )

        assert manager.disable("test-plugin") is True
        assert manager._installed["test-plugin"].enabled is False
        assert manager._installed["test-plugin"].status == PluginStatus.DISABLED


class TestPluginManagerStatistics:
    """Tests for plugin statistics."""

    def test_get_statistics(self, tmp_path):
        """Test getting plugin statistics."""
        manager = PluginManager(plugins_dir=tmp_path / "plugins", config_dir=tmp_path / "config")

        # Add some plugins
        manager._installed["plugin1"] = Plugin(
            manifest=PluginManifest(
                name="plugin1",
                version="1.0.0",
                description="Test",
                author="Author",
                category=PluginCategory.WEB,
            ),
            status=PluginStatus.INSTALLED,
            enabled=True,
        )
        manager._installed["plugin2"] = Plugin(
            manifest=PluginManifest(
                name="plugin2",
                version="1.0.0",
                description="Test",
                author="Author",
                category=PluginCategory.WEB,
            ),
            status=PluginStatus.DISABLED,
            enabled=False,
        )
        manager._installed["plugin3"] = Plugin(
            manifest=PluginManifest(
                name="plugin3",
                version="1.0.0",
                description="Test",
                author="Author",
                category=PluginCategory.NETWORK,
            ),
            status=PluginStatus.INSTALLED,
            enabled=True,
        )

        stats = manager.get_statistics()

        assert stats["total_installed"] == 3
        assert stats["enabled"] == 2
        assert stats["disabled"] == 1
        assert stats["by_category"]["web"] == 2
        assert stats["by_category"]["network"] == 1
