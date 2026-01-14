"""
Plugin data models for PurpleSploit Marketplace.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum
import hashlib


class PluginStatus(Enum):
    """Plugin installation status."""
    NOT_INSTALLED = "not_installed"
    INSTALLED = "installed"
    UPDATE_AVAILABLE = "update_available"
    DISABLED = "disabled"
    BROKEN = "broken"


class PluginCategory(Enum):
    """Plugin categories."""
    RECON = "recon"
    NETWORK = "network"
    WEB = "web"
    EXPLOIT = "exploit"
    POST = "post"
    AD = "ad"
    OSINT = "osint"
    CLOUD = "cloud"
    MOBILE = "mobile"
    REPORTING = "reporting"
    INTEGRATION = "integration"
    UTILITY = "utility"


@dataclass
class PluginDependency:
    """Plugin dependency specification."""
    name: str
    version_constraint: str  # e.g., ">=1.0.0", "~=2.0", "==1.2.3"
    optional: bool = False

    def is_satisfied(self, installed_version: Optional[str]) -> bool:
        """Check if a version satisfies this dependency."""
        if not installed_version:
            return self.optional

        from packaging.version import Version
        from packaging.specifiers import SpecifierSet

        try:
            spec = SpecifierSet(self.version_constraint)
            return Version(installed_version) in spec
        except Exception:
            return False


@dataclass
class PluginVersion:
    """Plugin version information."""
    version: str
    release_date: datetime
    changelog: str = ""
    min_framework_version: str = "1.0.0"
    checksum: str = ""  # SHA256 of the plugin package
    download_url: str = ""
    size_bytes: int = 0

    def verify_checksum(self, content: bytes) -> bool:
        """Verify content matches expected checksum."""
        if not self.checksum:
            return True
        computed = hashlib.sha256(content).hexdigest()
        return computed.lower() == self.checksum.lower()


@dataclass
class PluginManifest:
    """
    Plugin manifest describing a module package.

    This is typically stored as plugin.yaml in the plugin directory.
    """
    name: str
    version: str
    description: str
    author: str

    # Categorization
    category: PluginCategory = PluginCategory.UTILITY
    tags: List[str] = field(default_factory=list)

    # Dependencies
    dependencies: List[PluginDependency] = field(default_factory=list)
    python_dependencies: List[str] = field(default_factory=list)  # pip packages
    system_dependencies: List[str] = field(default_factory=list)  # system packages

    # Metadata
    homepage: str = ""
    license: str = "MIT"
    repository: str = ""
    documentation: str = ""

    # Module info
    module_path: str = ""  # e.g., "network/custom_scanner"
    main_class: str = ""   # e.g., "CustomScannerModule"

    # Compatibility
    min_framework_version: str = "1.0.0"
    max_framework_version: Optional[str] = None
    platforms: List[str] = field(default_factory=lambda: ["linux", "darwin", "win32"])

    # Security
    signed: bool = False
    signature: str = ""
    trusted_author: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PluginManifest":
        """Create manifest from dictionary."""
        deps = []
        for dep in data.get("dependencies", []):
            if isinstance(dep, str):
                # Simple format: "plugin_name>=1.0.0"
                parts = dep.replace(">=", " >=").replace("<=", " <=").replace("==", " ==").split()
                name = parts[0]
                constraint = parts[1] if len(parts) > 1 else ">=0.0.0"
                deps.append(PluginDependency(name=name, version_constraint=constraint))
            else:
                deps.append(PluginDependency(**dep))

        category = data.get("category", "utility")
        if isinstance(category, str):
            try:
                category = PluginCategory(category)
            except ValueError:
                category = PluginCategory.UTILITY

        return cls(
            name=data["name"],
            version=data["version"],
            description=data.get("description", ""),
            author=data.get("author", "Unknown"),
            category=category,
            tags=data.get("tags", []),
            dependencies=deps,
            python_dependencies=data.get("python_dependencies", []),
            system_dependencies=data.get("system_dependencies", []),
            homepage=data.get("homepage", ""),
            license=data.get("license", "MIT"),
            repository=data.get("repository", ""),
            documentation=data.get("documentation", ""),
            module_path=data.get("module_path", ""),
            main_class=data.get("main_class", ""),
            min_framework_version=data.get("min_framework_version", "1.0.0"),
            max_framework_version=data.get("max_framework_version"),
            platforms=data.get("platforms", ["linux", "darwin", "win32"]),
            signed=data.get("signed", False),
            signature=data.get("signature", ""),
            trusted_author=data.get("trusted_author", False),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "category": self.category.value,
            "tags": self.tags,
            "dependencies": [
                {"name": d.name, "version_constraint": d.version_constraint, "optional": d.optional}
                for d in self.dependencies
            ],
            "python_dependencies": self.python_dependencies,
            "system_dependencies": self.system_dependencies,
            "homepage": self.homepage,
            "license": self.license,
            "repository": self.repository,
            "documentation": self.documentation,
            "module_path": self.module_path,
            "main_class": self.main_class,
            "min_framework_version": self.min_framework_version,
            "max_framework_version": self.max_framework_version,
            "platforms": self.platforms,
            "signed": self.signed,
            "trusted_author": self.trusted_author,
        }


@dataclass
class Plugin:
    """
    Complete plugin information including installation status.
    """
    manifest: PluginManifest
    status: PluginStatus = PluginStatus.NOT_INSTALLED
    installed_version: Optional[str] = None
    install_path: Optional[str] = None
    installed_at: Optional[datetime] = None
    enabled: bool = True
    available_versions: List[PluginVersion] = field(default_factory=list)
    rating: float = 0.0
    downloads: int = 0

    @property
    def name(self) -> str:
        return self.manifest.name

    @property
    def version(self) -> str:
        return self.manifest.version

    @property
    def has_update(self) -> bool:
        """Check if an update is available."""
        if not self.installed_version or not self.available_versions:
            return False

        from packaging.version import Version
        current = Version(self.installed_version)
        latest = max(Version(v.version) for v in self.available_versions)
        return latest > current

    @property
    def latest_version(self) -> Optional[str]:
        """Get latest available version."""
        if not self.available_versions:
            return None

        from packaging.version import Version
        return str(max(Version(v.version) for v in self.available_versions))

    def is_compatible(self, framework_version: str) -> bool:
        """Check if plugin is compatible with framework version."""
        from packaging.version import Version
        from packaging.specifiers import SpecifierSet

        fw = Version(framework_version)

        # Check minimum version
        if self.manifest.min_framework_version:
            if fw < Version(self.manifest.min_framework_version):
                return False

        # Check maximum version
        if self.manifest.max_framework_version:
            if fw > Version(self.manifest.max_framework_version):
                return False

        return True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "manifest": self.manifest.to_dict(),
            "status": self.status.value,
            "installed_version": self.installed_version,
            "install_path": self.install_path,
            "installed_at": self.installed_at.isoformat() if self.installed_at else None,
            "enabled": self.enabled,
            "rating": self.rating,
            "downloads": self.downloads,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Plugin":
        """Create from dictionary."""
        return cls(
            manifest=PluginManifest.from_dict(data["manifest"]),
            status=PluginStatus(data.get("status", "not_installed")),
            installed_version=data.get("installed_version"),
            install_path=data.get("install_path"),
            installed_at=datetime.fromisoformat(data["installed_at"]) if data.get("installed_at") else None,
            enabled=data.get("enabled", True),
            rating=data.get("rating", 0.0),
            downloads=data.get("downloads", 0),
        )
