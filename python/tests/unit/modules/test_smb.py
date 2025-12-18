"""
Tests for the SMB modules.

Tests the SMB enumeration, authentication, and other SMB module properties and operations.
"""

import pytest
from unittest.mock import MagicMock, patch


# =============================================================================
# SMB Enumeration Module Tests
# =============================================================================

class TestSMBEnumerationModuleProperties:
    """Tests for SMB Enumeration module properties."""

    @pytest.fixture
    def smb_enum_module(self, mock_framework_minimal):
        """Create SMB Enumeration module instance for testing."""
        from purplesploit.modules.smb.enumeration import SMBEnumerationModule
        return SMBEnumerationModule(mock_framework_minimal)

    def test_name(self, smb_enum_module):
        """Test module name."""
        assert smb_enum_module.name == "SMB Enumeration"

    def test_description(self, smb_enum_module):
        """Test module description."""
        assert "enumeration" in smb_enum_module.description.lower()

    def test_category(self, smb_enum_module):
        """Test module category is smb."""
        assert smb_enum_module.category == "smb"

    def test_tool_name(self, smb_enum_module):
        """Test tool name is nxc."""
        assert smb_enum_module.tool_name == "nxc"

    def test_author(self, smb_enum_module):
        """Test module author."""
        assert smb_enum_module.author == "PurpleSploit Team"

    def test_has_rhost_option(self, smb_enum_module):
        """Test that RHOST option exists and is required."""
        assert "RHOST" in smb_enum_module.options
        assert smb_enum_module.options["RHOST"]["required"] is True

    def test_has_username_option(self, smb_enum_module):
        """Test that USERNAME option exists."""
        assert "USERNAME" in smb_enum_module.options

    def test_has_password_option(self, smb_enum_module):
        """Test that PASSWORD option exists."""
        assert "PASSWORD" in smb_enum_module.options

    def test_has_domain_option(self, smb_enum_module):
        """Test that DOMAIN option exists."""
        assert "DOMAIN" in smb_enum_module.options


class TestSMBEnumerationOperations:
    """Tests for SMB Enumeration operations."""

    @pytest.fixture
    def smb_enum_module(self, mock_framework_minimal):
        """Create SMB Enumeration module instance for testing."""
        from purplesploit.modules.smb.enumeration import SMBEnumerationModule
        return SMBEnumerationModule(mock_framework_minimal)

    def test_get_operations_returns_list(self, smb_enum_module):
        """Test that get_operations returns a list."""
        ops = smb_enum_module.get_operations()
        assert isinstance(ops, list)

    def test_has_list_shares_operation(self, smb_enum_module):
        """Test that list shares operation exists."""
        ops = smb_enum_module.get_operations()
        op_names = [op["name"] for op in ops]
        assert "List Shares" in op_names

    def test_has_enumerate_users_operation(self, smb_enum_module):
        """Test that enumerate users operation exists."""
        ops = smb_enum_module.get_operations()
        op_names = [op["name"] for op in ops]
        assert "Enumerate Users" in op_names

    def test_has_enumerate_groups_operation(self, smb_enum_module):
        """Test that enumerate groups operation exists."""
        ops = smb_enum_module.get_operations()
        op_names = [op["name"] for op in ops]
        assert "Enumerate Groups" in op_names

    def test_has_password_policy_operation(self, smb_enum_module):
        """Test that password policy operation exists."""
        ops = smb_enum_module.get_operations()
        op_names = [op["name"] for op in ops]
        assert "Password Policy" in op_names

    def test_has_active_sessions_operation(self, smb_enum_module):
        """Test that active sessions operation exists."""
        ops = smb_enum_module.get_operations()
        op_names = [op["name"] for op in ops]
        assert "Active Sessions" in op_names

    def test_has_rid_brute_operation(self, smb_enum_module):
        """Test that RID bruteforce operation exists."""
        ops = smb_enum_module.get_operations()
        op_names = [op["name"] for op in ops]
        assert "RID Bruteforce" in op_names

    def test_has_full_enumeration_operation(self, smb_enum_module):
        """Test that full enumeration operation exists."""
        ops = smb_enum_module.get_operations()
        op_names = [op["name"] for op in ops]
        assert "Full Enumeration" in op_names

    def test_operations_have_handlers(self, smb_enum_module):
        """Test that all operations have handlers."""
        ops = smb_enum_module.get_operations()
        for op in ops:
            assert "handler" in op
            assert op["handler"].startswith("op_")


class TestSMBEnumerationAuthBuild:
    """Tests for SMB Enumeration auth string building."""

    @pytest.fixture
    def smb_enum_module(self, mock_framework_minimal):
        """Create SMB Enumeration module instance for testing."""
        from purplesploit.modules.smb.enumeration import SMBEnumerationModule
        return SMBEnumerationModule(mock_framework_minimal)

    def test_build_auth_no_username(self, smb_enum_module):
        """Test that empty auth is returned when no username."""
        auth = smb_enum_module._build_auth()
        assert auth == ""

    def test_build_auth_with_username_only(self, smb_enum_module):
        """Test auth string with username only."""
        smb_enum_module.set_option("USERNAME", "admin")
        auth = smb_enum_module._build_auth()
        assert "-u 'admin'" in auth
        assert "-p ''" in auth

    def test_build_auth_with_username_and_password(self, smb_enum_module):
        """Test auth string with username and password."""
        smb_enum_module.set_option("USERNAME", "admin")
        smb_enum_module.set_option("PASSWORD", "secret123")
        auth = smb_enum_module._build_auth()
        assert "-u 'admin'" in auth
        assert "-p 'secret123'" in auth


# =============================================================================
# SMB Authentication Module Tests
# =============================================================================

class TestSMBAuthenticationModuleProperties:
    """Tests for SMB Authentication module properties."""

    @pytest.fixture
    def smb_auth_module(self, mock_framework_minimal):
        """Create SMB Authentication module instance for testing."""
        from purplesploit.modules.smb.authentication import SMBAuthenticationModule
        return SMBAuthenticationModule(mock_framework_minimal)

    def test_name(self, smb_auth_module):
        """Test module name."""
        assert smb_auth_module.name == "SMB Authentication"

    def test_description(self, smb_auth_module):
        """Test module description."""
        assert "authentication" in smb_auth_module.description.lower()

    def test_category(self, smb_auth_module):
        """Test module category is smb."""
        assert smb_auth_module.category == "smb"

    def test_tool_name(self, smb_auth_module):
        """Test tool name is nxc."""
        assert smb_auth_module.tool_name == "nxc"

    def test_has_hash_option(self, smb_auth_module):
        """Test that HASH option exists for pass-the-hash."""
        assert "HASH" in smb_auth_module.options


class TestSMBAuthenticationOperations:
    """Tests for SMB Authentication operations."""

    @pytest.fixture
    def smb_auth_module(self, mock_framework_minimal):
        """Create SMB Authentication module instance for testing."""
        from purplesploit.modules.smb.authentication import SMBAuthenticationModule
        return SMBAuthenticationModule(mock_framework_minimal)

    def test_get_operations_returns_list(self, smb_auth_module):
        """Test that get_operations returns a list."""
        ops = smb_auth_module.get_operations()
        assert isinstance(ops, list)

    def test_has_test_auth_operation(self, smb_auth_module):
        """Test that test authentication operation exists."""
        ops = smb_auth_module.get_operations()
        op_names = [op["name"] for op in ops]
        assert "Test Authentication" in op_names

    def test_has_pass_the_hash_operation(self, smb_auth_module):
        """Test that pass-the-hash operation exists."""
        ops = smb_auth_module.get_operations()
        op_names = [op["name"] for op in ops]
        assert "Pass-the-Hash" in op_names

    def test_has_local_auth_operation(self, smb_auth_module):
        """Test that local auth operation exists."""
        ops = smb_auth_module.get_operations()
        op_names = [op["name"] for op in ops]
        assert "Local Authentication" in op_names


class TestSMBAuthenticationAuthBuild:
    """Tests for SMB Authentication auth string building."""

    @pytest.fixture
    def smb_auth_module(self, mock_framework_minimal):
        """Create SMB Authentication module instance for testing."""
        from purplesploit.modules.smb.authentication import SMBAuthenticationModule
        return SMBAuthenticationModule(mock_framework_minimal)

    def test_build_auth_with_hash(self, smb_auth_module):
        """Test auth string with NTLM hash."""
        smb_auth_module.set_option("USERNAME", "admin")
        smb_auth_module.set_option("HASH", "aad3b435b51404ee:8846f7eaee8fb117")
        auth = smb_auth_module._build_auth()
        assert "-u 'admin'" in auth
        assert "-H 'aad3b435b51404ee:8846f7eaee8fb117'" in auth
        assert "-p" not in auth

    def test_build_auth_prefers_hash_over_password(self, smb_auth_module):
        """Test that hash is preferred over password when both set."""
        smb_auth_module.set_option("USERNAME", "admin")
        smb_auth_module.set_option("PASSWORD", "password")
        smb_auth_module.set_option("HASH", "aad3b435b51404ee:8846f7eaee8fb117")
        auth = smb_auth_module._build_auth()
        assert "-H 'aad3b435b51404ee:8846f7eaee8fb117'" in auth
        assert "-p 'password'" not in auth


# =============================================================================
# SMB Shares Module Tests
# =============================================================================

class TestSMBSharesModule:
    """Tests for SMB Shares module."""

    @pytest.fixture
    def smb_shares_module(self, mock_framework_minimal):
        """Create SMB Shares module instance for testing."""
        from purplesploit.modules.smb.shares import SMBSharesModule
        return SMBSharesModule(mock_framework_minimal)

    def test_name(self, smb_shares_module):
        """Test module name."""
        assert "Share" in smb_shares_module.name

    def test_category(self, smb_shares_module):
        """Test module category is smb."""
        assert smb_shares_module.category == "smb"

    def test_tool_name(self, smb_shares_module):
        """Test tool name is nxc."""
        assert smb_shares_module.tool_name == "nxc"

    def test_has_operations(self, smb_shares_module):
        """Test that module has operations."""
        ops = smb_shares_module.get_operations()
        assert len(ops) > 0


# =============================================================================
# SMB Execution Module Tests
# =============================================================================

class TestSMBExecutionModule:
    """Tests for SMB Execution module."""

    @pytest.fixture
    def smb_exec_module(self, mock_framework_minimal):
        """Create SMB Execution module instance for testing."""
        from purplesploit.modules.smb.execution import SMBExecutionModule
        return SMBExecutionModule(mock_framework_minimal)

    def test_name(self, smb_exec_module):
        """Test module name."""
        assert "Execution" in smb_exec_module.name

    def test_category(self, smb_exec_module):
        """Test module category is smb."""
        assert smb_exec_module.category == "smb"

    def test_tool_name(self, smb_exec_module):
        """Test tool name is nxc."""
        assert smb_exec_module.tool_name == "nxc"

    def test_has_operations(self, smb_exec_module):
        """Test that module has operations."""
        ops = smb_exec_module.get_operations()
        assert len(ops) > 0


# =============================================================================
# SMB Vulnerability Module Tests
# =============================================================================

class TestSMBVulnerabilityModule:
    """Tests for SMB Vulnerability module."""

    @pytest.fixture
    def smb_vuln_module(self, mock_framework_minimal):
        """Create SMB Vulnerability module instance for testing."""
        from purplesploit.modules.smb.vulnerability import SMBVulnerabilityModule
        return SMBVulnerabilityModule(mock_framework_minimal)

    def test_name(self, smb_vuln_module):
        """Test module name."""
        assert "Vulnerability" in smb_vuln_module.name

    def test_category(self, smb_vuln_module):
        """Test module category is smb."""
        assert smb_vuln_module.category == "smb"

    def test_tool_name(self, smb_vuln_module):
        """Test tool name is nxc."""
        assert smb_vuln_module.tool_name == "nxc"

    def test_has_operations(self, smb_vuln_module):
        """Test that module has operations."""
        ops = smb_vuln_module.get_operations()
        assert len(ops) > 0


# =============================================================================
# SMB Credentials Module Tests
# =============================================================================

class TestSMBCredentialsModule:
    """Tests for SMB Credentials module."""

    @pytest.fixture
    def smb_creds_module(self, mock_framework_minimal):
        """Create SMB Credentials module instance for testing."""
        from purplesploit.modules.smb.credentials import SMBCredentialsModule
        return SMBCredentialsModule(mock_framework_minimal)

    def test_name(self, smb_creds_module):
        """Test module name."""
        assert "Credential" in smb_creds_module.name

    def test_category(self, smb_creds_module):
        """Test module category is smb."""
        assert smb_creds_module.category == "smb"

    def test_tool_name(self, smb_creds_module):
        """Test tool name is nxc."""
        assert smb_creds_module.tool_name == "nxc"

    def test_has_operations(self, smb_creds_module):
        """Test that module has operations."""
        ops = smb_creds_module.get_operations()
        assert len(ops) > 0


# =============================================================================
# Module Inheritance Tests
# =============================================================================

class TestSMBModulesInheritance:
    """Tests for SMB module inheritance from ExternalToolModule."""

    def test_enumeration_inherits_correctly(self, mock_framework_minimal):
        """Test SMB Enumeration inherits from ExternalToolModule."""
        from purplesploit.modules.smb.enumeration import SMBEnumerationModule
        from purplesploit.core.module import ExternalToolModule
        module = SMBEnumerationModule(mock_framework_minimal)
        assert isinstance(module, ExternalToolModule)

    def test_authentication_inherits_correctly(self, mock_framework_minimal):
        """Test SMB Authentication inherits from ExternalToolModule."""
        from purplesploit.modules.smb.authentication import SMBAuthenticationModule
        from purplesploit.core.module import ExternalToolModule
        module = SMBAuthenticationModule(mock_framework_minimal)
        assert isinstance(module, ExternalToolModule)

    def test_shares_inherits_correctly(self, mock_framework_minimal):
        """Test SMB Shares inherits from ExternalToolModule."""
        from purplesploit.modules.smb.shares import SMBSharesModule
        from purplesploit.core.module import ExternalToolModule
        module = SMBSharesModule(mock_framework_minimal)
        assert isinstance(module, ExternalToolModule)
