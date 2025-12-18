"""
Tests for the Network modules (NXC-based).

Tests the NetExec SSH, LDAP, MSSQL, RDP, WinRM modules.
"""

import pytest
from unittest.mock import MagicMock


# =============================================================================
# NXC SSH Module Tests
# =============================================================================

class TestNXCSSHModuleProperties:
    """Tests for NXC SSH module properties."""

    @pytest.fixture
    def nxc_ssh_module(self, mock_framework_minimal):
        """Create NXC SSH module instance for testing."""
        from purplesploit.modules.network.nxc_ssh import NXCSSHModule
        return NXCSSHModule(mock_framework_minimal)

    def test_name(self, nxc_ssh_module):
        """Test module name."""
        assert "SSH" in nxc_ssh_module.name

    def test_description(self, nxc_ssh_module):
        """Test module description."""
        assert "SSH" in nxc_ssh_module.description

    def test_category(self, nxc_ssh_module):
        """Test module category is network."""
        assert nxc_ssh_module.category == "network"

    def test_tool_name(self, nxc_ssh_module):
        """Test tool name is nxc."""
        assert nxc_ssh_module.tool_name == "nxc"

    def test_author(self, nxc_ssh_module):
        """Test module author."""
        assert nxc_ssh_module.author == "PurpleSploit Team"

    def test_has_rhost_option(self, nxc_ssh_module):
        """Test that RHOST option exists and is required."""
        assert "RHOST" in nxc_ssh_module.options
        assert nxc_ssh_module.options["RHOST"]["required"] is True


class TestNXCSSHOperations:
    """Tests for NXC SSH operations."""

    @pytest.fixture
    def nxc_ssh_module(self, mock_framework_minimal):
        """Create NXC SSH module instance for testing."""
        from purplesploit.modules.network.nxc_ssh import NXCSSHModule
        return NXCSSHModule(mock_framework_minimal)

    def test_get_operations_returns_list(self, nxc_ssh_module):
        """Test that get_operations returns a list."""
        ops = nxc_ssh_module.get_operations()
        assert isinstance(ops, list)

    def test_has_test_auth_operation(self, nxc_ssh_module):
        """Test that test authentication operation exists."""
        ops = nxc_ssh_module.get_operations()
        op_names = [op["name"] for op in ops]
        assert "Test Authentication" in op_names

    def test_has_exec_cmd_operation(self, nxc_ssh_module):
        """Test that execute command operation exists."""
        ops = nxc_ssh_module.get_operations()
        op_names = [op["name"] for op in ops]
        assert "Execute Command" in op_names

    def test_has_sysinfo_operation(self, nxc_ssh_module):
        """Test that system info operation exists."""
        ops = nxc_ssh_module.get_operations()
        op_names = [op["name"] for op in ops]
        assert "Get System Info" in op_names

    def test_has_sudo_operation(self, nxc_ssh_module):
        """Test that sudo check operation exists."""
        ops = nxc_ssh_module.get_operations()
        op_names = [op["name"] for op in ops]
        assert "Check Sudo" in op_names


class TestNXCSSHAuthBuild:
    """Tests for NXC SSH auth string building."""

    @pytest.fixture
    def nxc_ssh_module(self, mock_framework_minimal):
        """Create NXC SSH module instance for testing."""
        from purplesploit.modules.network.nxc_ssh import NXCSSHModule
        return NXCSSHModule(mock_framework_minimal)

    def test_build_auth_no_username(self, nxc_ssh_module):
        """Test that empty auth is returned when no username."""
        auth = nxc_ssh_module._build_auth()
        assert auth == ""

    def test_build_auth_with_credentials(self, nxc_ssh_module):
        """Test auth string with username and password."""
        nxc_ssh_module.set_option("USERNAME", "root")
        nxc_ssh_module.set_option("PASSWORD", "toor")
        auth = nxc_ssh_module._build_auth()
        assert "-u 'root'" in auth
        assert "-p 'toor'" in auth


# =============================================================================
# NXC LDAP Module Tests
# =============================================================================

class TestNXCLDAPModuleProperties:
    """Tests for NXC LDAP module properties."""

    @pytest.fixture
    def nxc_ldap_module(self, mock_framework_minimal):
        """Create NXC LDAP module instance for testing."""
        from purplesploit.modules.network.nxc_ldap import NXCLDAPModule
        return NXCLDAPModule(mock_framework_minimal)

    def test_name(self, nxc_ldap_module):
        """Test module name."""
        assert "LDAP" in nxc_ldap_module.name

    def test_category(self, nxc_ldap_module):
        """Test module category is network."""
        assert nxc_ldap_module.category == "network"

    def test_tool_name(self, nxc_ldap_module):
        """Test tool name is nxc."""
        assert nxc_ldap_module.tool_name == "nxc"

    def test_has_rhost_option(self, nxc_ldap_module):
        """Test that RHOST option exists."""
        assert "RHOST" in nxc_ldap_module.options


class TestNXCLDAPOperations:
    """Tests for NXC LDAP operations."""

    @pytest.fixture
    def nxc_ldap_module(self, mock_framework_minimal):
        """Create NXC LDAP module instance for testing."""
        from purplesploit.modules.network.nxc_ldap import NXCLDAPModule
        return NXCLDAPModule(mock_framework_minimal)

    def test_get_operations_returns_list(self, nxc_ldap_module):
        """Test that get_operations returns a list."""
        ops = nxc_ldap_module.get_operations()
        assert isinstance(ops, list)

    def test_has_multiple_operations(self, nxc_ldap_module):
        """Test that module has multiple operations."""
        ops = nxc_ldap_module.get_operations()
        assert len(ops) > 0


# =============================================================================
# NXC MSSQL Module Tests
# =============================================================================

class TestNXCMSSQLModuleProperties:
    """Tests for NXC MSSQL module properties."""

    @pytest.fixture
    def nxc_mssql_module(self, mock_framework_minimal):
        """Create NXC MSSQL module instance for testing."""
        from purplesploit.modules.network.nxc_mssql import NXCMSSQLModule
        return NXCMSSQLModule(mock_framework_minimal)

    def test_name(self, nxc_mssql_module):
        """Test module name."""
        assert "MSSQL" in nxc_mssql_module.name

    def test_category(self, nxc_mssql_module):
        """Test module category is network."""
        assert nxc_mssql_module.category == "network"

    def test_tool_name(self, nxc_mssql_module):
        """Test tool name is nxc."""
        assert nxc_mssql_module.tool_name == "nxc"


class TestNXCMSSQLOperations:
    """Tests for NXC MSSQL operations."""

    @pytest.fixture
    def nxc_mssql_module(self, mock_framework_minimal):
        """Create NXC MSSQL module instance for testing."""
        from purplesploit.modules.network.nxc_mssql import NXCMSSQLModule
        return NXCMSSQLModule(mock_framework_minimal)

    def test_get_operations_returns_list(self, nxc_mssql_module):
        """Test that get_operations returns a list."""
        ops = nxc_mssql_module.get_operations()
        assert isinstance(ops, list)


# =============================================================================
# NXC RDP Module Tests
# =============================================================================

class TestNXCRDPModuleProperties:
    """Tests for NXC RDP module properties."""

    @pytest.fixture
    def nxc_rdp_module(self, mock_framework_minimal):
        """Create NXC RDP module instance for testing."""
        from purplesploit.modules.network.nxc_rdp import NXCRDPModule
        return NXCRDPModule(mock_framework_minimal)

    def test_name(self, nxc_rdp_module):
        """Test module name."""
        assert "RDP" in nxc_rdp_module.name

    def test_category(self, nxc_rdp_module):
        """Test module category is network."""
        assert nxc_rdp_module.category == "network"

    def test_tool_name(self, nxc_rdp_module):
        """Test tool name is nxc."""
        assert nxc_rdp_module.tool_name == "nxc"


class TestNXCRDPOperations:
    """Tests for NXC RDP operations."""

    @pytest.fixture
    def nxc_rdp_module(self, mock_framework_minimal):
        """Create NXC RDP module instance for testing."""
        from purplesploit.modules.network.nxc_rdp import NXCRDPModule
        return NXCRDPModule(mock_framework_minimal)

    def test_get_operations_returns_list(self, nxc_rdp_module):
        """Test that get_operations returns a list."""
        ops = nxc_rdp_module.get_operations()
        assert isinstance(ops, list)


# =============================================================================
# NXC WinRM Module Tests
# =============================================================================

class TestNXCWinRMModuleProperties:
    """Tests for NXC WinRM module properties."""

    @pytest.fixture
    def nxc_winrm_module(self, mock_framework_minimal):
        """Create NXC WinRM module instance for testing."""
        from purplesploit.modules.network.nxc_winrm import NXCWinRMModule
        return NXCWinRMModule(mock_framework_minimal)

    def test_name(self, nxc_winrm_module):
        """Test module name."""
        assert "WinRM" in nxc_winrm_module.name

    def test_category(self, nxc_winrm_module):
        """Test module category is network."""
        assert nxc_winrm_module.category == "network"

    def test_tool_name(self, nxc_winrm_module):
        """Test tool name is nxc."""
        assert nxc_winrm_module.tool_name == "nxc"


class TestNXCWinRMOperations:
    """Tests for NXC WinRM operations."""

    @pytest.fixture
    def nxc_winrm_module(self, mock_framework_minimal):
        """Create NXC WinRM module instance for testing."""
        from purplesploit.modules.network.nxc_winrm import NXCWinRMModule
        return NXCWinRMModule(mock_framework_minimal)

    def test_get_operations_returns_list(self, nxc_winrm_module):
        """Test that get_operations returns a list."""
        ops = nxc_winrm_module.get_operations()
        assert isinstance(ops, list)


# =============================================================================
# NXC SMB Module Tests
# =============================================================================

class TestNXCSMBModuleProperties:
    """Tests for NXC SMB module properties."""

    @pytest.fixture
    def nxc_smb_module(self, mock_framework_minimal):
        """Create NXC SMB module instance for testing."""
        from purplesploit.modules.network.nxc_smb import NXCSMBModule
        return NXCSMBModule(mock_framework_minimal)

    def test_name(self, nxc_smb_module):
        """Test module name."""
        assert "SMB" in nxc_smb_module.name

    def test_category(self, nxc_smb_module):
        """Test module category is network."""
        assert nxc_smb_module.category == "network"

    def test_tool_name(self, nxc_smb_module):
        """Test tool name is nxc."""
        assert nxc_smb_module.tool_name == "nxc"


class TestNXCSMBOperations:
    """Tests for NXC SMB operations."""

    @pytest.fixture
    def nxc_smb_module(self, mock_framework_minimal):
        """Create NXC SMB module instance for testing."""
        from purplesploit.modules.network.nxc_smb import NXCSMBModule
        return NXCSMBModule(mock_framework_minimal)

    def test_get_operations_returns_list(self, nxc_smb_module):
        """Test that get_operations returns a list."""
        ops = nxc_smb_module.get_operations()
        assert isinstance(ops, list)

    def test_has_multiple_operations(self, nxc_smb_module):
        """Test that module has multiple operations."""
        ops = nxc_smb_module.get_operations()
        assert len(ops) > 5  # Should have many SMB operations


# =============================================================================
# Module Inheritance Tests
# =============================================================================

class TestNetworkModulesInheritance:
    """Tests for network module inheritance from ExternalToolModule."""

    def test_ssh_inherits_correctly(self, mock_framework_minimal):
        """Test NXC SSH inherits from ExternalToolModule."""
        from purplesploit.modules.network.nxc_ssh import NXCSSHModule
        from purplesploit.core.module import ExternalToolModule
        module = NXCSSHModule(mock_framework_minimal)
        assert isinstance(module, ExternalToolModule)

    def test_ldap_inherits_correctly(self, mock_framework_minimal):
        """Test NXC LDAP inherits from ExternalToolModule."""
        from purplesploit.modules.network.nxc_ldap import NXCLDAPModule
        from purplesploit.core.module import ExternalToolModule
        module = NXCLDAPModule(mock_framework_minimal)
        assert isinstance(module, ExternalToolModule)

    def test_mssql_inherits_correctly(self, mock_framework_minimal):
        """Test NXC MSSQL inherits from ExternalToolModule."""
        from purplesploit.modules.network.nxc_mssql import NXCMSSQLModule
        from purplesploit.core.module import ExternalToolModule
        module = NXCMSSQLModule(mock_framework_minimal)
        assert isinstance(module, ExternalToolModule)

    def test_rdp_inherits_correctly(self, mock_framework_minimal):
        """Test NXC RDP inherits from ExternalToolModule."""
        from purplesploit.modules.network.nxc_rdp import NXCRDPModule
        from purplesploit.core.module import ExternalToolModule
        module = NXCRDPModule(mock_framework_minimal)
        assert isinstance(module, ExternalToolModule)

    def test_winrm_inherits_correctly(self, mock_framework_minimal):
        """Test NXC WinRM inherits from ExternalToolModule."""
        from purplesploit.modules.network.nxc_winrm import NXCWinRMModule
        from purplesploit.core.module import ExternalToolModule
        module = NXCWinRMModule(mock_framework_minimal)
        assert isinstance(module, ExternalToolModule)

    def test_smb_inherits_correctly(self, mock_framework_minimal):
        """Test NXC SMB inherits from ExternalToolModule."""
        from purplesploit.modules.network.nxc_smb import NXCSMBModule
        from purplesploit.core.module import ExternalToolModule
        module = NXCSMBModule(mock_framework_minimal)
        assert isinstance(module, ExternalToolModule)
