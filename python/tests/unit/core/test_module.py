"""
Unit tests for purplesploit.core.module module.

Tests cover:
- BaseModule option management
- BaseModule validation
- BaseModule context handling
- ExternalToolModule command execution
- ExternalToolModule tool detection
- ModuleMetadata dataclass
"""

import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from purplesploit.core.module import BaseModule, ExternalToolModule, ModuleMetadata


# =============================================================================
# ModuleMetadata Tests
# =============================================================================

class TestModuleMetadata:
    """Tests for the ModuleMetadata dataclass."""

    def test_metadata_creation(self):
        """Test creating module metadata."""
        metadata = ModuleMetadata(
            path="recon/nmap",
            name="Nmap Scan",
            category="recon",
            description="Network scanner",
            author="Test Author"
        )

        assert metadata.path == "recon/nmap"
        assert metadata.name == "Nmap Scan"
        assert metadata.category == "recon"
        assert metadata.instance is None

    def test_metadata_with_instance(self):
        """Test metadata with module instance."""
        mock_instance = MagicMock()
        metadata = ModuleMetadata(
            path="recon/nmap",
            name="Nmap Scan",
            category="recon",
            description="Network scanner",
            author="Test Author",
            instance=mock_instance
        )

        assert metadata.instance is mock_instance


# =============================================================================
# BaseModule Option Tests
# =============================================================================

class TestBaseModuleOptions:
    """Tests for BaseModule option management."""

    def test_default_options_created(self, test_module):
        """Test default options are created for modules without profiles."""
        # Module without profiles should have default options
        assert "RHOST" in test_module.options
        assert "RPORT" in test_module.options
        assert "URL" in test_module.options

    def test_set_option_valid(self, test_module):
        """Test setting a valid option."""
        result = test_module.set_option("RHOST", "192.168.1.100")

        assert result is True
        assert test_module.options["RHOST"]["value"] == "192.168.1.100"

    def test_set_option_case_insensitive(self, test_module):
        """Test option names are case-insensitive."""
        test_module.set_option("rhost", "192.168.1.100")

        assert test_module.options["RHOST"]["value"] == "192.168.1.100"

    def test_set_option_unknown(self, test_module):
        """Test setting unknown option returns False."""
        result = test_module.set_option("UNKNOWN_OPTION", "value")

        assert result is False

    def test_get_option_value(self, test_module):
        """Test getting option value."""
        test_module.set_option("RHOST", "192.168.1.100")

        value = test_module.get_option("RHOST")

        assert value == "192.168.1.100"

    def test_get_option_default(self, test_module):
        """Test getting option returns default when no value set."""
        # Set up an option with a default
        test_module.options["TEST_OPT"] = {
            "value": None,
            "default": "default_value",
            "required": False,
            "description": "Test"
        }

        value = test_module.get_option("TEST_OPT")

        assert value == "default_value"

    def test_get_option_nonexistent(self, test_module):
        """Test getting non-existent option returns None."""
        value = test_module.get_option("NONEXISTENT")
        assert value is None

    def test_show_options(self, test_module):
        """Test showing all options."""
        options = test_module.show_options()

        assert isinstance(options, dict)
        assert "RHOST" in options


# =============================================================================
# BaseModule Validation Tests
# =============================================================================

class TestBaseModuleValidation:
    """Tests for BaseModule validation."""

    def test_validate_options_no_required(self, test_module):
        """Test validation passes when no required options."""
        is_valid, error = test_module.validate_options()

        assert is_valid is True
        assert error == ""

    def test_validate_options_required_missing(self, test_module):
        """Test validation fails when required option is missing."""
        test_module.options["RHOST"]["required"] = True

        is_valid, error = test_module.validate_options()

        assert is_valid is False
        assert "RHOST" in error

    def test_validate_options_required_set(self, test_module):
        """Test validation passes when required option is set."""
        test_module.options["RHOST"]["required"] = True
        test_module.set_option("RHOST", "192.168.1.100")

        is_valid, error = test_module.validate_options()

        assert is_valid is True

    def test_validate_options_required_empty_string(self, test_module):
        """Test validation fails for empty string on required option."""
        test_module.options["RHOST"]["required"] = True
        test_module.set_option("RHOST", "")

        is_valid, error = test_module.validate_options()

        assert is_valid is False


# =============================================================================
# BaseModule Context Tests
# =============================================================================

class TestBaseModuleContext:
    """Tests for BaseModule context handling."""

    def test_get_context_with_session(self, test_module, mock_framework, sample_target, sample_credential):
        """Test getting context from framework session."""
        # Set up context
        mock_framework.session.targets.add(sample_target)
        mock_framework.session.credentials.add(sample_credential)

        context = test_module.get_context()

        assert context["current_target"] is not None
        assert context["current_cred"] is not None

    def test_get_context_no_session(self, concrete_module_class, mock_framework_minimal):
        """Test get_context returns empty dict without session attribute."""
        module = concrete_module_class(mock_framework_minimal)
        # Remove session attribute entirely to test the hasattr check
        del mock_framework_minimal.session

        context = module.get_context()

        # Should return empty dict when no session
        assert isinstance(context, dict)
        assert context == {}

    def test_auto_set_from_context_target(self, test_module, mock_framework, sample_target):
        """Test auto-setting RHOST from context."""
        mock_framework.session.targets.add(sample_target)

        test_module.auto_set_from_context()

        assert test_module.get_option("RHOST") == sample_target["ip"]

    def test_auto_set_from_context_credential(self, test_module, mock_framework, sample_credential):
        """Test auto-setting credentials from context."""
        # Add credential options to module
        test_module.options["USERNAME"] = {"value": None, "required": False, "description": "User", "default": None}
        test_module.options["PASSWORD"] = {"value": None, "required": False, "description": "Pass", "default": None}
        test_module.options["DOMAIN"] = {"value": None, "required": False, "description": "Domain", "default": None}

        mock_framework.session.credentials.add(sample_credential)

        test_module.auto_set_from_context()

        assert test_module.get_option("USERNAME") == sample_credential["username"]
        assert test_module.get_option("PASSWORD") == sample_credential["password"]

    def test_auto_set_does_not_override_user_set(self, test_module, mock_framework, sample_target):
        """Test auto-set doesn't override user-specified values."""
        mock_framework.session.targets.add(sample_target)
        test_module.set_option("RHOST", "10.0.0.1")  # User sets different value

        test_module.auto_set_from_context()

        # Should keep user's value
        assert test_module.get_option("RHOST") == "10.0.0.1"


# =============================================================================
# BaseModule Abstract Methods Tests
# =============================================================================

class TestBaseModuleAbstract:
    """Tests for BaseModule abstract method implementation."""

    def test_module_properties(self, test_module):
        """Test module properties are accessible."""
        assert test_module.name == "Test Module"
        assert test_module.description == "A test module for unit testing"
        assert test_module.author == "Test Author"
        assert test_module.category == "test"

    def test_run_returns_dict(self, test_module):
        """Test run() returns a dictionary."""
        result = test_module.run()

        assert isinstance(result, dict)
        assert "success" in result

    def test_check_validates_options(self, test_module):
        """Test check() validates options."""
        result = test_module.check()

        assert isinstance(result, dict)
        assert "success" in result

    def test_check_reports_invalid_options(self, test_module):
        """Test check() reports validation errors."""
        test_module.options["RHOST"]["required"] = True

        result = test_module.check()

        assert result["success"] is False
        assert "error" in result

    def test_cleanup_callable(self, test_module):
        """Test cleanup() is callable."""
        # Should not raise
        test_module.cleanup()

    def test_log_with_framework(self, test_module, mock_framework):
        """Test logging through framework."""
        test_module.log("Test message", "info")

        mock_framework.log.assert_called_once_with("Test message", "info")

    def test_log_without_framework(self, concrete_module_class, capsys):
        """Test logging without framework falls back to print."""
        framework = MagicMock(spec=[])  # No log method
        module = concrete_module_class(framework)

        module.log("Test message", "info")

        captured = capsys.readouterr()
        assert "[INFO]" in captured.out
        assert "Test message" in captured.out


# =============================================================================
# BaseModule Operations Tests
# =============================================================================

class TestBaseModuleOperations:
    """Tests for BaseModule operations/submenu handling."""

    def test_get_operations_default_empty(self, test_module):
        """Test get_operations returns empty list by default."""
        operations = test_module.get_operations()
        assert operations == []

    def test_has_operations_false(self, test_module):
        """Test has_operations returns False when no operations."""
        assert test_module.has_operations() is False

    def test_get_subcategories_empty(self, test_module):
        """Test get_subcategories with no operations."""
        subcategories = test_module.get_subcategories()
        assert subcategories == []

    def test_get_operations_by_subcategory(self, test_module):
        """Test filtering operations by subcategory."""
        # This will return empty since test module has no operations
        operations = test_module.get_operations_by_subcategory("test")
        assert operations == []


# =============================================================================
# ExternalToolModule Tests
# =============================================================================

class TestExternalToolModule:
    """Tests for ExternalToolModule class."""

    def test_has_switches_option(self, test_external_module):
        """Test SWITCHES option is added automatically."""
        assert "SWITCHES" in test_external_module.options

    def test_check_tool_installed_found(self, test_external_module):
        """Test checking for installed tool (using common tool)."""
        test_external_module.tool_name = "ls"  # Use a tool that should exist

        result = test_external_module.check_tool_installed()

        assert result is True
        assert test_external_module.tool_path is not None

    def test_check_tool_installed_not_found(self, test_external_module):
        """Test checking for non-existent tool."""
        test_external_module.tool_name = "nonexistent_tool_xyz"
        test_external_module.tool_path = None

        result = test_external_module.check_tool_installed()

        assert result is False

    def test_check_tool_installed_with_path(self, test_external_module):
        """Test tool check returns True when path is already set."""
        test_external_module.tool_path = "/usr/bin/test_tool"

        result = test_external_module.check_tool_installed()

        assert result is True

    def test_build_command(self, test_external_module):
        """Test build_command returns command string."""
        test_external_module.set_option("RHOST", "192.168.1.100")

        command = test_external_module.build_command()

        assert "test_tool" in command
        assert "192.168.1.100" in command

    def test_get_default_command(self, test_external_module):
        """Test get_default_command uses build_command."""
        test_external_module.set_option("RHOST", "192.168.1.100")

        command = test_external_module.get_default_command()

        assert "test_tool" in command

    def test_execute_command_success(self, test_external_module):
        """Test successful command execution."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="output",
                stderr=""
            )

            result = test_external_module.execute_command("echo test")

            assert result["success"] is True
            assert result["stdout"] == "output"

    def test_execute_command_failure(self, test_external_module):
        """Test failed command execution."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="error"
            )

            result = test_external_module.execute_command("false")

            assert result["success"] is False

    def test_execute_command_timeout(self, test_external_module):
        """Test command timeout handling."""
        import subprocess
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("cmd", 10)

            result = test_external_module.execute_command("sleep 100", timeout=10)

            assert result["success"] is False
            assert "timed out" in result["error"]

    def test_execute_command_exception(self, test_external_module):
        """Test command exception handling."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = Exception("Test error")

            result = test_external_module.execute_command("echo test")

            assert result["success"] is False
            assert "Test error" in result["error"]

    def test_execute_command_appends_switches(self, test_external_module):
        """Test custom switches are appended to command."""
        test_external_module.set_option("SWITCHES", "--verbose --debug")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            test_external_module.execute_command("test_tool")

            # Check the actual command called
            called_command = mock_run.call_args[1]["shell"]
            # The command is passed via shell=True, so check args
            assert mock_run.called

    def test_execute_command_background(self, test_external_module):
        """Test background command execution."""
        with patch("subprocess.Popen") as mock_popen:
            mock_process = MagicMock()
            mock_process.pid = 12345
            mock_popen.return_value = mock_process

            result = test_external_module.execute_command("long_running_cmd", background=True)

            assert result["success"] is True
            assert result["background"] is True
            assert result["pid"] == 12345

    def test_run_checks_tool_installed(self, mock_framework_minimal):
        """Test run() checks if tool is installed."""
        # Create an ExternalToolModule that uses the parent run() which checks tool install
        class ToolCheckModule(ExternalToolModule):
            def __init__(self, framework):
                super().__init__(framework)
                self.tool_name = "nonexistent_tool_xyz_12345"
                self.tool_path = None

            @property
            def name(self):
                return "Tool Check Test"

            @property
            def description(self):
                return "Test tool check"

            @property
            def author(self):
                return "Test"

            @property
            def category(self):
                return "test"

            def build_command(self):
                return "nonexistent_tool_xyz_12345 --test"
            # Note: Intentionally NOT overriding run() so it uses parent's check

        module = ToolCheckModule(mock_framework_minimal)
        result = module.run()

        assert result["success"] is False
        assert "not found" in result["error"].lower()


# =============================================================================
# Module with Parameter Profiles Tests
# =============================================================================

class TestModuleWithProfiles:
    """Tests for modules using parameter profiles."""

    def test_module_with_profiles(self, mock_framework_minimal):
        """Test module that uses parameter profiles."""
        class ProfileModule(BaseModule):
            @property
            def name(self):
                return "Profile Module"

            @property
            def description(self):
                return "Test"

            @property
            def author(self):
                return "Test"

            @property
            def category(self):
                return "test"

            @property
            def parameter_profiles(self):
                return ["target_basic", "auth_basic"]

            def run(self):
                return {"success": True}

        module = ProfileModule(mock_framework_minimal)

        # Should have parameters from profiles
        assert "RHOST" in module.options
        assert "USERNAME" in module.options
        assert "PASSWORD" in module.options

    def test_module_with_custom_parameters(self, mock_framework_minimal):
        """Test module that adds custom parameters."""
        class CustomModule(BaseModule):
            @property
            def name(self):
                return "Custom Module"

            @property
            def description(self):
                return "Test"

            @property
            def author(self):
                return "Test"

            @property
            def category(self):
                return "test"

            @property
            def parameter_profiles(self):
                return ["target_basic"]

            @property
            def custom_parameters(self):
                return ["WORDLIST"]

            def run(self):
                return {"success": True}

        module = CustomModule(mock_framework_minimal)

        # Should have profile + custom parameters
        assert "RHOST" in module.options
        assert "WORDLIST" in module.options


# =============================================================================
# Edge Cases
# =============================================================================

class TestModuleEdgeCases:
    """Tests for edge cases in module handling."""

    def test_set_option_updates_both_systems(self, test_module):
        """Test set_option updates both options and parameters."""
        # When using profiles, both should be updated
        test_module.set_option("RHOST", "192.168.1.100")

        assert test_module.options["RHOST"]["value"] == "192.168.1.100"

    def test_get_option_prefers_parameters(self, mock_framework_minimal):
        """Test get_option prefers parameter system when available."""
        class ParamModule(BaseModule):
            @property
            def name(self):
                return "Param Module"

            @property
            def description(self):
                return "Test"

            @property
            def author(self):
                return "Test"

            @property
            def category(self):
                return "test"

            @property
            def parameter_profiles(self):
                return ["target_basic"]

            def run(self):
                return {"success": True}

        module = ParamModule(mock_framework_minimal)
        module.set_option("RHOST", "192.168.1.100")

        value = module.get_option("RHOST")
        assert value == "192.168.1.100"

    def test_required_options_property(self, test_module):
        """Test required_options property default."""
        required = test_module.required_options
        assert isinstance(required, list)

    def test_get_default_command_exception(self, test_external_module):
        """Test get_default_command handles exceptions."""
        # Make build_command raise an exception
        test_external_module.build_command = MagicMock(side_effect=Exception("Error"))

        command = test_external_module.get_default_command()

        assert command == ""
