"""
Tests for the Feroxbuster module.

Tests the Feroxbuster directory discovery module properties and operations.
"""

import pytest
from unittest.mock import MagicMock


class TestFeroxbusterModuleProperties:
    """Tests for Feroxbuster module properties."""

    @pytest.fixture
    def feroxbuster_module(self, mock_framework_minimal):
        """Create Feroxbuster module instance for testing."""
        from purplesploit.modules.web.feroxbuster import FeroxbusterModule
        return FeroxbusterModule(mock_framework_minimal)

    def test_name(self, feroxbuster_module):
        """Test module name."""
        assert feroxbuster_module.name == "Feroxbuster"

    def test_description(self, feroxbuster_module):
        """Test module description."""
        assert "discovery" in feroxbuster_module.description.lower()

    def test_category(self, feroxbuster_module):
        """Test module category is web."""
        assert feroxbuster_module.category == "web"

    def test_tool_name(self, feroxbuster_module):
        """Test tool name is feroxbuster."""
        assert feroxbuster_module.tool_name == "feroxbuster"

    def test_author(self, feroxbuster_module):
        """Test module author."""
        assert feroxbuster_module.author == "PurpleSploit Team"

    def test_uses_parameter_profiles(self, feroxbuster_module):
        """Test that module uses web scanning parameter profiles."""
        assert "web_scan_advanced" in feroxbuster_module.parameter_profiles


class TestFeroxbusterOperations:
    """Tests for Feroxbuster operations."""

    @pytest.fixture
    def feroxbuster_module(self, mock_framework_minimal):
        """Create Feroxbuster module instance for testing."""
        from purplesploit.modules.web.feroxbuster import FeroxbusterModule
        return FeroxbusterModule(mock_framework_minimal)

    def test_get_operations_returns_list(self, feroxbuster_module):
        """Test that get_operations returns a list."""
        ops = feroxbuster_module.get_operations()
        assert isinstance(ops, list)

    def test_get_operations_not_empty(self, feroxbuster_module):
        """Test that operations list is not empty."""
        ops = feroxbuster_module.get_operations()
        assert len(ops) > 0

    def test_has_basic_scan_operation(self, feroxbuster_module):
        """Test that basic scan operation exists."""
        ops = feroxbuster_module.get_operations()
        op_names = [op["name"] for op in ops]
        assert "Basic Directory Scan" in op_names

    def test_has_deep_scan_operation(self, feroxbuster_module):
        """Test that deep scan operation exists."""
        ops = feroxbuster_module.get_operations()
        op_names = [op["name"] for op in ops]
        assert "Deep Scan with Extensions" in op_names

    def test_has_background_scan_operation(self, feroxbuster_module):
        """Test that background scan operation exists."""
        ops = feroxbuster_module.get_operations()
        op_names = [op["name"] for op in ops]
        assert "Background Basic Scan" in op_names

    def test_has_custom_wordlist_operation(self, feroxbuster_module):
        """Test that custom wordlist operation exists."""
        ops = feroxbuster_module.get_operations()
        op_names = [op["name"] for op in ops]
        assert "Custom Wordlist Scan" in op_names

    def test_has_burp_integration_operation(self, feroxbuster_module):
        """Test that Burp integration operation exists."""
        ops = feroxbuster_module.get_operations()
        op_names = [op["name"] for op in ops]
        assert "Burp Integration Scan" in op_names

    def test_has_api_discovery_operation(self, feroxbuster_module):
        """Test that API discovery operation exists."""
        ops = feroxbuster_module.get_operations()
        op_names = [op["name"] for op in ops]
        assert "API Discovery" in op_names

    def test_has_backup_discovery_operation(self, feroxbuster_module):
        """Test that backup file discovery operation exists."""
        ops = feroxbuster_module.get_operations()
        op_names = [op["name"] for op in ops]
        assert "Backup File Discovery" in op_names

    def test_has_custom_scan_operation(self, feroxbuster_module):
        """Test that custom scan operation exists."""
        ops = feroxbuster_module.get_operations()
        op_names = [op["name"] for op in ops]
        assert "Custom Scan" in op_names

    def test_operations_have_handlers(self, feroxbuster_module):
        """Test that all operations have handlers."""
        ops = feroxbuster_module.get_operations()
        for op in ops:
            assert "handler" in op
            assert op["handler"] is not None

    def test_operations_have_descriptions(self, feroxbuster_module):
        """Test that all operations have descriptions."""
        ops = feroxbuster_module.get_operations()
        for op in ops:
            assert "description" in op
            assert len(op["description"]) > 0


class TestFeroxbusterModuleInheritance:
    """Tests for Feroxbuster module inheritance from ExternalToolModule."""

    @pytest.fixture
    def feroxbuster_module(self, mock_framework_minimal):
        """Create Feroxbuster module instance for testing."""
        from purplesploit.modules.web.feroxbuster import FeroxbusterModule
        return FeroxbusterModule(mock_framework_minimal)

    def test_inherits_from_external_tool_module(self, feroxbuster_module):
        """Test that Feroxbuster inherits from ExternalToolModule."""
        from purplesploit.core.module import ExternalToolModule
        assert isinstance(feroxbuster_module, ExternalToolModule)

    def test_has_switches_option(self, feroxbuster_module):
        """Test that SWITCHES option is inherited."""
        assert "SWITCHES" in feroxbuster_module.options

    def test_has_options_dict(self, feroxbuster_module):
        """Test that module has options dictionary."""
        assert hasattr(feroxbuster_module, 'options')
        assert isinstance(feroxbuster_module.options, dict)


class TestFeroxbusterOperationCount:
    """Tests for Feroxbuster operation count."""

    @pytest.fixture
    def feroxbuster_module(self, mock_framework_minimal):
        """Create Feroxbuster module instance for testing."""
        from purplesploit.modules.web.feroxbuster import FeroxbusterModule
        return FeroxbusterModule(mock_framework_minimal)

    def test_has_8_operations(self, feroxbuster_module):
        """Test that module has exactly 8 operations."""
        ops = feroxbuster_module.get_operations()
        assert len(ops) == 8

    def test_has_operations_property(self, feroxbuster_module):
        """Test that module reports having operations."""
        assert feroxbuster_module.has_operations()
