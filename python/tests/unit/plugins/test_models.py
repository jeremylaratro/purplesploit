"""
Tests for purplesploit.plugins.models module.
"""

import pytest
from datetime import datetime
from unittest.mock import patch

from purplesploit.plugins.models import (
    Plugin,
    PluginManifest,
    PluginVersion,
    PluginStatus,
    PluginCategory,
    PluginDependency,
)


class TestPluginDependency:
    """Tests for PluginDependency class."""

    def test_is_satisfied_when_not_installed(self):
        """Test dependency check when plugin not installed."""
        dep = PluginDependency(name="test-dep", version_constraint=">=1.0.0")
        assert dep.is_satisfied(None) is False

    def test_is_satisfied_optional_when_not_installed(self):
        """Test optional dependency when not installed."""
        dep = PluginDependency(name="test-dep", version_constraint=">=1.0.0", optional=True)
        assert dep.is_satisfied(None) is True

    def test_is_satisfied_version_matches(self):
        """Test dependency satisfied when version matches."""
        dep = PluginDependency(name="test-dep", version_constraint=">=1.0.0")
        assert dep.is_satisfied("1.0.0") is True
        assert dep.is_satisfied("1.5.0") is True
        assert dep.is_satisfied("2.0.0") is True

    def test_is_satisfied_version_too_low(self):
        """Test dependency not satisfied when version too low."""
        dep = PluginDependency(name="test-dep", version_constraint=">=1.0.0")
        assert dep.is_satisfied("0.9.0") is False

    def test_is_satisfied_exact_version(self):
        """Test exact version constraint."""
        dep = PluginDependency(name="test-dep", version_constraint="==1.2.3")
        assert dep.is_satisfied("1.2.3") is True
        assert dep.is_satisfied("1.2.4") is False


class TestPluginVersion:
    """Tests for PluginVersion class."""

    def test_init(self):
        """Test PluginVersion initialization."""
        version = PluginVersion(
            version="1.0.0",
            release_date=datetime.now(),
            changelog="Initial release",
        )
        assert version.version == "1.0.0"
        assert "Initial" in version.changelog

    def test_verify_checksum_empty(self):
        """Test checksum verification with no checksum."""
        version = PluginVersion(
            version="1.0.0",
            release_date=datetime.now(),
            checksum="",
        )
        assert version.verify_checksum(b"anything") is True

    def test_verify_checksum_valid(self):
        """Test checksum verification with valid checksum."""
        import hashlib
        content = b"test content"
        checksum = hashlib.sha256(content).hexdigest()

        version = PluginVersion(
            version="1.0.0",
            release_date=datetime.now(),
            checksum=checksum,
        )
        assert version.verify_checksum(content) is True

    def test_verify_checksum_invalid(self):
        """Test checksum verification with invalid checksum."""
        version = PluginVersion(
            version="1.0.0",
            release_date=datetime.now(),
            checksum="invalid_checksum",
        )
        assert version.verify_checksum(b"test content") is False


class TestPluginManifest:
    """Tests for PluginManifest class."""

    def test_from_dict_basic(self):
        """Test creating manifest from basic dict."""
        data = {
            "name": "test-plugin",
            "version": "1.0.0",
            "description": "A test plugin",
            "author": "Test Author",
        }
        manifest = PluginManifest.from_dict(data)

        assert manifest.name == "test-plugin"
        assert manifest.version == "1.0.0"
        assert manifest.description == "A test plugin"
        assert manifest.author == "Test Author"
        assert manifest.category == PluginCategory.UTILITY

    def test_from_dict_with_category(self):
        """Test creating manifest with category."""
        data = {
            "name": "network-scanner",
            "version": "1.0.0",
            "description": "Network scanning",
            "author": "Author",
            "category": "network",
        }
        manifest = PluginManifest.from_dict(data)

        assert manifest.category == PluginCategory.NETWORK

    def test_from_dict_with_dependencies(self):
        """Test creating manifest with dependencies."""
        data = {
            "name": "test-plugin",
            "version": "1.0.0",
            "description": "Test",
            "author": "Author",
            "dependencies": [
                "other-plugin>=1.0.0",
                {"name": "explicit-dep", "version_constraint": ">=2.0.0", "optional": True},
            ],
        }
        manifest = PluginManifest.from_dict(data)

        assert len(manifest.dependencies) == 2
        assert manifest.dependencies[0].name == "other-plugin"
        assert manifest.dependencies[1].name == "explicit-dep"
        assert manifest.dependencies[1].optional is True

    def test_to_dict(self):
        """Test converting manifest to dict."""
        manifest = PluginManifest(
            name="test-plugin",
            version="1.0.0",
            description="Test description",
            author="Test Author",
            category=PluginCategory.WEB,
            tags=["web", "scanner"],
        )

        data = manifest.to_dict()

        assert data["name"] == "test-plugin"
        assert data["category"] == "web"
        assert data["tags"] == ["web", "scanner"]

    def test_from_dict_invalid_category(self):
        """Test creating manifest with invalid category falls back to utility."""
        data = {
            "name": "test",
            "version": "1.0.0",
            "description": "Test",
            "author": "Author",
            "category": "invalid_category",
        }
        manifest = PluginManifest.from_dict(data)

        assert manifest.category == PluginCategory.UTILITY


class TestPlugin:
    """Tests for Plugin class."""

    @pytest.fixture
    def sample_manifest(self):
        """Create sample manifest."""
        return PluginManifest(
            name="test-plugin",
            version="1.0.0",
            description="Test plugin",
            author="Test Author",
        )

    @pytest.fixture
    def sample_plugin(self, sample_manifest):
        """Create sample plugin."""
        return Plugin(
            manifest=sample_manifest,
            status=PluginStatus.INSTALLED,
            installed_version="1.0.0",
        )

    def test_plugin_name_property(self, sample_plugin):
        """Test name property."""
        assert sample_plugin.name == "test-plugin"

    def test_plugin_version_property(self, sample_plugin):
        """Test version property."""
        assert sample_plugin.version == "1.0.0"

    def test_has_update_no_versions(self, sample_plugin):
        """Test has_update when no versions available."""
        sample_plugin.available_versions = []
        assert sample_plugin.has_update is False

    def test_has_update_same_version(self, sample_plugin):
        """Test has_update when at latest version."""
        sample_plugin.available_versions = [
            PluginVersion(version="1.0.0", release_date=datetime.now())
        ]
        assert sample_plugin.has_update is False

    def test_has_update_newer_available(self, sample_plugin):
        """Test has_update when newer version available."""
        sample_plugin.installed_version = "1.0.0"
        sample_plugin.available_versions = [
            PluginVersion(version="1.0.0", release_date=datetime.now()),
            PluginVersion(version="2.0.0", release_date=datetime.now()),
        ]
        assert sample_plugin.has_update is True

    def test_latest_version(self, sample_plugin):
        """Test getting latest version."""
        sample_plugin.available_versions = [
            PluginVersion(version="1.0.0", release_date=datetime.now()),
            PluginVersion(version="1.5.0", release_date=datetime.now()),
            PluginVersion(version="2.0.0", release_date=datetime.now()),
        ]
        assert sample_plugin.latest_version == "2.0.0"

    def test_latest_version_no_versions(self, sample_plugin):
        """Test latest_version when no versions available."""
        sample_plugin.available_versions = []
        assert sample_plugin.latest_version is None

    def test_is_compatible_min_version(self, sample_manifest):
        """Test compatibility check with min version."""
        sample_manifest.min_framework_version = "1.0.0"
        plugin = Plugin(manifest=sample_manifest)

        assert plugin.is_compatible("1.0.0") is True
        assert plugin.is_compatible("2.0.0") is True
        assert plugin.is_compatible("0.9.0") is False

    def test_is_compatible_max_version(self, sample_manifest):
        """Test compatibility check with max version."""
        sample_manifest.min_framework_version = "1.0.0"
        sample_manifest.max_framework_version = "2.0.0"
        plugin = Plugin(manifest=sample_manifest)

        assert plugin.is_compatible("1.5.0") is True
        assert plugin.is_compatible("2.0.0") is True
        assert plugin.is_compatible("2.1.0") is False

    def test_to_dict(self, sample_plugin):
        """Test converting plugin to dict."""
        data = sample_plugin.to_dict()

        assert data["manifest"]["name"] == "test-plugin"
        assert data["status"] == "installed"
        assert data["installed_version"] == "1.0.0"

    def test_from_dict(self, sample_plugin):
        """Test creating plugin from dict."""
        data = sample_plugin.to_dict()
        restored = Plugin.from_dict(data)

        assert restored.name == sample_plugin.name
        assert restored.status == sample_plugin.status
        assert restored.installed_version == sample_plugin.installed_version


class TestPluginCategory:
    """Tests for PluginCategory enum."""

    def test_all_categories_exist(self):
        """Test that all expected categories exist."""
        expected = ["recon", "network", "web", "exploit", "post", "ad", "osint", "cloud", "mobile", "reporting", "integration", "utility"]
        for cat in expected:
            assert PluginCategory(cat) is not None


class TestPluginStatus:
    """Tests for PluginStatus enum."""

    def test_all_statuses_exist(self):
        """Test that all expected statuses exist."""
        expected = ["not_installed", "installed", "update_available", "disabled", "broken"]
        for status in expected:
            assert PluginStatus(status) is not None
