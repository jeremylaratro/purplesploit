"""
Unit tests for purplesploit.core.parameters module.

Tests cover:
- Parameter validation (types, required, choices, min/max)
- ParameterRegistry operations
- ParameterProfile operations
- ProfileRegistry operations
"""

import pytest
from purplesploit.core.parameters import (
    Parameter,
    ParameterType,
    ParameterRegistry,
    ParameterProfile,
    ProfileRegistry,
    get_parameter_registry,
    get_profile_registry,
)


# =============================================================================
# Parameter Class Tests
# =============================================================================

class TestParameter:
    """Tests for the Parameter dataclass."""

    def test_parameter_creation_defaults(self):
        """Test parameter creation with default values."""
        param = Parameter(name="TEST", description="Test param")

        assert param.name == "TEST"
        assert param.description == "Test param"
        assert param.param_type == ParameterType.STRING
        assert param.required is False
        assert param.default is None
        assert param.value is None

    def test_parameter_creation_full(self):
        """Test parameter creation with all values specified."""
        param = Parameter(
            name="PORT",
            description="Target port",
            param_type=ParameterType.PORT,
            required=True,
            default=80,
            value=443,
            choices=[80, 443, 8080],
            min_value=1,
            max_value=65535
        )

        assert param.name == "PORT"
        assert param.param_type == ParameterType.PORT
        assert param.required is True
        assert param.default == 80
        assert param.value == 443
        assert param.choices == [80, 443, 8080]

    def test_get_value_returns_value_when_set(self):
        """Test get_value returns value when explicitly set."""
        param = Parameter(name="TEST", description="Test", default="default", value="custom")
        assert param.get_value() == "custom"

    def test_get_value_returns_default_when_value_none(self):
        """Test get_value returns default when value is None."""
        param = Parameter(name="TEST", description="Test", default="default")
        assert param.get_value() == "default"

    def test_get_value_returns_none_when_both_none(self):
        """Test get_value returns None when both value and default are None."""
        param = Parameter(name="TEST", description="Test")
        assert param.get_value() is None

    def test_to_dict(self):
        """Test parameter to dictionary conversion."""
        param = Parameter(
            name="TEST",
            description="Test param",
            param_type=ParameterType.INTEGER,
            required=True,
            default=10,
            value=20
        )

        result = param.to_dict()

        assert result["value"] == 20
        assert result["required"] is True
        assert result["description"] == "Test param"
        assert result["default"] == 10
        assert result["type"] == "integer"


# =============================================================================
# Parameter Validation Tests
# =============================================================================

class TestParameterValidation:
    """Tests for Parameter.validate() method."""

    def test_validate_required_missing(self):
        """Test validation fails for missing required parameter."""
        param = Parameter(name="REQUIRED", description="Required param", required=True)

        is_valid, error = param.validate()

        assert is_valid is False
        assert "REQUIRED is required" in error

    def test_validate_required_empty_string(self):
        """Test validation fails for empty string on required parameter."""
        param = Parameter(name="REQUIRED", description="Required param", required=True, value="")

        is_valid, error = param.validate()

        assert is_valid is False
        assert "REQUIRED is required" in error

    def test_validate_required_with_value(self):
        """Test validation passes for required parameter with value."""
        param = Parameter(name="REQUIRED", description="Required param", required=True, value="test")

        is_valid, error = param.validate()

        assert is_valid is True
        assert error == ""

    def test_validate_optional_none(self):
        """Test validation passes for optional parameter without value."""
        param = Parameter(name="OPTIONAL", description="Optional param", required=False)

        is_valid, error = param.validate()

        assert is_valid is True
        assert error == ""

    def test_validate_choices_valid(self):
        """Test validation passes for valid choice."""
        param = Parameter(
            name="CHOICE",
            description="Choice param",
            choices=["a", "b", "c"],
            value="b"
        )

        is_valid, error = param.validate()

        assert is_valid is True

    def test_validate_choices_invalid(self):
        """Test validation fails for invalid choice."""
        param = Parameter(
            name="CHOICE",
            description="Choice param",
            choices=["a", "b", "c"],
            value="d"
        )

        is_valid, error = param.validate()

        assert is_valid is False
        assert "must be one of" in error

    def test_validate_integer_valid(self):
        """Test validation passes for valid integer."""
        param = Parameter(
            name="COUNT",
            description="Count",
            param_type=ParameterType.INTEGER,
            value=10,
            min_value=1,
            max_value=100
        )

        is_valid, error = param.validate()

        assert is_valid is True

    def test_validate_integer_below_min(self):
        """Test validation fails for integer below minimum."""
        param = Parameter(
            name="COUNT",
            description="Count",
            param_type=ParameterType.INTEGER,
            value=0,
            min_value=1
        )

        is_valid, error = param.validate()

        assert is_valid is False
        assert "must be >=" in error

    def test_validate_integer_above_max(self):
        """Test validation fails for integer above maximum."""
        param = Parameter(
            name="COUNT",
            description="Count",
            param_type=ParameterType.INTEGER,
            value=200,
            max_value=100
        )

        is_valid, error = param.validate()

        assert is_valid is False
        assert "must be <=" in error

    def test_validate_integer_invalid_type(self):
        """Test validation fails for non-integer value on integer type."""
        param = Parameter(
            name="COUNT",
            description="Count",
            param_type=ParameterType.INTEGER,
            value="not_a_number"
        )

        is_valid, error = param.validate()

        assert is_valid is False
        assert "must be an integer" in error

    def test_validate_port_valid(self):
        """Test validation passes for valid port."""
        param = Parameter(
            name="PORT",
            description="Port",
            param_type=ParameterType.PORT,
            value=443
        )

        is_valid, error = param.validate()

        assert is_valid is True

    def test_validate_port_below_range(self):
        """Test validation fails for port below 1."""
        param = Parameter(
            name="PORT",
            description="Port",
            param_type=ParameterType.PORT,
            value=0
        )

        is_valid, error = param.validate()

        assert is_valid is False
        assert "must be between 1 and 65535" in error

    def test_validate_port_above_range(self):
        """Test validation fails for port above 65535."""
        param = Parameter(
            name="PORT",
            description="Port",
            param_type=ParameterType.PORT,
            value=70000
        )

        is_valid, error = param.validate()

        assert is_valid is False
        assert "must be between 1 and 65535" in error

    def test_validate_port_invalid_type(self):
        """Test validation fails for non-numeric port."""
        param = Parameter(
            name="PORT",
            description="Port",
            param_type=ParameterType.PORT,
            value="http"
        )

        is_valid, error = param.validate()

        assert is_valid is False
        assert "must be a valid port number" in error

    def test_validate_custom_validation_pass(self):
        """Test validation with custom validator that passes."""
        def custom_validator(value):
            if value.startswith("http"):
                return True, ""
            return False, "Must start with http"

        param = Parameter(
            name="URL",
            description="URL",
            validation=custom_validator,
            value="http://example.com"
        )

        is_valid, error = param.validate()

        assert is_valid is True

    def test_validate_custom_validation_fail(self):
        """Test validation with custom validator that fails."""
        def custom_validator(value):
            if value.startswith("http"):
                return True, ""
            return False, "Must start with http"

        param = Parameter(
            name="URL",
            description="URL",
            validation=custom_validator,
            value="ftp://example.com"
        )

        is_valid, error = param.validate()

        assert is_valid is False
        assert "Must start with http" in error


# =============================================================================
# ParameterRegistry Tests
# =============================================================================

class TestParameterRegistry:
    """Tests for the ParameterRegistry class."""

    def test_registry_has_default_parameters(self, parameter_registry):
        """Test registry is populated with default parameters."""
        # Check some expected parameters exist
        assert parameter_registry.get("RHOST") is not None
        assert parameter_registry.get("RPORT") is not None
        assert parameter_registry.get("USERNAME") is not None
        assert parameter_registry.get("PASSWORD") is not None
        assert parameter_registry.get("URL") is not None

    def test_registry_get_existing(self, parameter_registry):
        """Test getting an existing parameter."""
        param = parameter_registry.get("RHOST")

        assert param is not None
        assert param.name == "RHOST"
        assert param.param_type == ParameterType.IP

    def test_registry_get_nonexistent(self, parameter_registry):
        """Test getting a non-existent parameter returns None."""
        param = parameter_registry.get("NONEXISTENT")
        assert param is None

    def test_registry_get_copy_is_independent(self, parameter_registry):
        """Test get_copy returns an independent copy."""
        copy1 = parameter_registry.get_copy("RHOST")
        copy2 = parameter_registry.get_copy("RHOST")

        # Modify copy1
        copy1.value = "192.168.1.1"

        # copy2 should be unaffected
        assert copy2.value is None
        # Original should be unaffected
        assert parameter_registry.get("RHOST").value is None

    def test_registry_get_multiple(self, parameter_registry):
        """Test getting multiple parameters at once."""
        params = parameter_registry.get_multiple(["RHOST", "RPORT", "NONEXISTENT"])

        assert "RHOST" in params
        assert "RPORT" in params
        assert "NONEXISTENT" not in params  # Should skip missing
        assert len(params) == 2

    def test_registry_register_custom(self, parameter_registry):
        """Test registering a custom parameter."""
        custom = Parameter(
            name="CUSTOM_PARAM",
            description="A custom parameter",
            param_type=ParameterType.STRING
        )

        parameter_registry.register(custom)

        assert parameter_registry.get("CUSTOM_PARAM") is not None
        assert parameter_registry.get("CUSTOM_PARAM").description == "A custom parameter"

    def test_registry_parameter_types(self, parameter_registry):
        """Test various parameter types are correctly configured."""
        # IP type
        rhost = parameter_registry.get("RHOST")
        assert rhost.param_type == ParameterType.IP

        # PORT type
        smb_port = parameter_registry.get("SMB_PORT")
        assert smb_port.param_type == ParameterType.PORT

        # INTEGER type
        threads = parameter_registry.get("THREADS")
        assert threads.param_type == ParameterType.INTEGER

        # BOOLEAN type
        verbose = parameter_registry.get("VERBOSE")
        assert verbose.param_type == ParameterType.BOOLEAN


# =============================================================================
# ParameterProfile Tests
# =============================================================================

class TestParameterProfile:
    """Tests for the ParameterProfile class."""

    def test_profile_creation(self):
        """Test profile creation."""
        profile = ParameterProfile(
            name="test_profile",
            description="Test profile",
            parameters=["RHOST", "RPORT", "USERNAME"]
        )

        assert profile.name == "test_profile"
        assert profile.description == "Test profile"
        assert "RHOST" in profile.parameter_names
        assert "RPORT" in profile.parameter_names
        assert "USERNAME" in profile.parameter_names

    def test_profile_get_parameters(self, parameter_registry):
        """Test getting parameters from a profile."""
        profile = ParameterProfile(
            name="test_profile",
            description="Test profile",
            parameters=["RHOST", "RPORT"]
        )

        params = profile.get_parameters(parameter_registry)

        assert "RHOST" in params
        assert "RPORT" in params
        assert len(params) == 2

    def test_profile_add_parameter(self):
        """Test adding a parameter to a profile."""
        profile = ParameterProfile(
            name="test_profile",
            description="Test profile",
            parameters=["RHOST"]
        )

        profile.add_parameter("USERNAME")

        assert "USERNAME" in profile.parameter_names
        assert len(profile.parameter_names) == 2

    def test_profile_remove_parameter(self):
        """Test removing a parameter from a profile."""
        profile = ParameterProfile(
            name="test_profile",
            description="Test profile",
            parameters=["RHOST", "RPORT", "USERNAME"]
        )

        profile.remove_parameter("USERNAME")

        assert "USERNAME" not in profile.parameter_names
        assert len(profile.parameter_names) == 2


# =============================================================================
# ProfileRegistry Tests
# =============================================================================

class TestProfileRegistry:
    """Tests for the ProfileRegistry class."""

    def test_registry_has_default_profiles(self, profile_registry):
        """Test registry is populated with default profiles."""
        profiles = profile_registry.list_profiles()

        assert "target_basic" in profiles
        assert "auth_basic" in profiles
        assert "auth_domain" in profiles
        assert "web_scan_basic" in profiles
        assert "smb_auth" in profiles

    def test_registry_get_existing(self, profile_registry):
        """Test getting an existing profile."""
        profile = profile_registry.get("smb_auth")

        assert profile is not None
        assert profile.name == "smb_auth"
        assert "RHOST" in profile.parameter_names
        assert "USERNAME" in profile.parameter_names

    def test_registry_get_nonexistent(self, profile_registry):
        """Test getting a non-existent profile returns None."""
        profile = profile_registry.get("nonexistent_profile")
        assert profile is None

    def test_registry_register_custom(self, profile_registry):
        """Test registering a custom profile."""
        custom = ParameterProfile(
            name="custom_profile",
            description="Custom profile",
            parameters=["RHOST", "CUSTOM_PARAM"]
        )

        profile_registry.register(custom)

        assert profile_registry.get("custom_profile") is not None

    def test_registry_list_profiles(self, profile_registry):
        """Test listing all profile names."""
        profiles = profile_registry.list_profiles()

        assert isinstance(profiles, list)
        assert len(profiles) > 0
        assert all(isinstance(p, str) for p in profiles)


# =============================================================================
# Global Registry Tests
# =============================================================================

class TestGlobalRegistries:
    """Tests for the global registry accessor functions."""

    def test_get_parameter_registry_returns_same_instance(self):
        """Test global parameter registry returns same instance."""
        registry1 = get_parameter_registry()
        registry2 = get_parameter_registry()

        assert registry1 is registry2

    def test_get_profile_registry_returns_same_instance(self):
        """Test global profile registry returns same instance."""
        registry1 = get_profile_registry()
        registry2 = get_profile_registry()

        assert registry1 is registry2


# =============================================================================
# Edge Cases and Integration
# =============================================================================

class TestParameterEdgeCases:
    """Tests for edge cases and unusual inputs."""

    def test_parameter_integer_as_string(self):
        """Test integer validation handles string representation."""
        param = Parameter(
            name="COUNT",
            description="Count",
            param_type=ParameterType.INTEGER,
            value="42",
            min_value=1,
            max_value=100
        )

        is_valid, error = param.validate()
        assert is_valid is True

    def test_parameter_port_as_string(self):
        """Test port validation handles string representation."""
        param = Parameter(
            name="PORT",
            description="Port",
            param_type=ParameterType.PORT,
            value="443"
        )

        is_valid, error = param.validate()
        assert is_valid is True

    def test_parameter_with_none_choices(self):
        """Test parameter validation with None choices."""
        param = Parameter(
            name="TEST",
            description="Test",
            choices=None,
            value="anything"
        )

        is_valid, error = param.validate()
        assert is_valid is True

    def test_parameter_empty_choices_list(self):
        """Test parameter validation with empty choices list."""
        param = Parameter(
            name="TEST",
            description="Test",
            choices=[],
            value="anything"
        )

        # Empty list is falsy, so should not trigger choice validation
        is_valid, error = param.validate()
        assert is_valid is True

    def test_profile_with_missing_parameters(self, parameter_registry):
        """Test profile handles missing parameters gracefully."""
        profile = ParameterProfile(
            name="test_profile",
            description="Test profile",
            parameters=["RHOST", "NONEXISTENT_PARAM"]
        )

        params = profile.get_parameters(parameter_registry)

        assert "RHOST" in params
        assert "NONEXISTENT_PARAM" not in params
        assert len(params) == 1
