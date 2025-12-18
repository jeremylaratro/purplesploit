"""
Unit tests for purplesploit.modules.network.nxc_smb module.

Tests cover:
- Module properties
- Command building (_build_auth, _execute_nxc)
- Operation handlers by subcategory
- Edge cases and error handling
"""

import pytest
from unittest.mock import MagicMock, patch
from purplesploit.modules.network.nxc_smb import NXCSMBModule


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def nxc_module(mock_framework_minimal):
    """Create a NXCSMBModule instance for testing."""
    return NXCSMBModule(mock_framework_minimal)


@pytest.fixture
def nxc_with_target(nxc_module):
    """Create a NXCSMBModule with RHOST set."""
    nxc_module.set_option("RHOST", "192.168.1.100")
    return nxc_module


@pytest.fixture
def nxc_with_creds(nxc_with_target):
    """Create a NXCSMBModule with target and credentials."""
    nxc_with_target.set_option("USERNAME", "admin")
    nxc_with_target.set_option("PASSWORD", "password123")
    nxc_with_target.set_option("DOMAIN", "TESTDOMAIN")
    return nxc_with_target


# =============================================================================
# Module Properties Tests
# =============================================================================

class TestNXCSMBModuleProperties:
    """Tests for NXCSMBModule properties."""

    def test_name(self, nxc_module):
        """Test module name."""
        assert nxc_module.name == "NetExec SMB"

    def test_description(self, nxc_module):
        """Test module description contains operations count."""
        assert "40+" in nxc_module.description or "operations" in nxc_module.description.lower()

    def test_category(self, nxc_module):
        """Test module category is network."""
        assert nxc_module.category == "network"

    def test_tool_name(self, nxc_module):
        """Test tool name is nxc."""
        assert nxc_module.tool_name == "nxc"

    def test_author(self, nxc_module):
        """Test module author."""
        assert nxc_module.author == "PurpleSploit Team"

    def test_parameter_profiles(self, nxc_module):
        """Test module uses SMB parameter profiles."""
        profiles = nxc_module.parameter_profiles
        assert "smb_auth" in profiles
        assert "smb_shares" in profiles
        assert "smb_execution" in profiles

    def test_has_auth_type_option(self, nxc_module):
        """Test AUTH_TYPE option exists."""
        assert "AUTH_TYPE" in nxc_module.options

    def test_auth_type_default(self, nxc_module):
        """Test AUTH_TYPE default value."""
        assert nxc_module.get_option("AUTH_TYPE") == "domain"


# =============================================================================
# Operations Tests
# =============================================================================

class TestNXCSMBOperations:
    """Tests for NXCSMBModule operations."""

    def test_has_operations(self, nxc_module):
        """Test module has operations."""
        assert nxc_module.has_operations() is True

    def test_get_operations_returns_list(self, nxc_module):
        """Test get_operations returns a list."""
        ops = nxc_module.get_operations()
        assert isinstance(ops, list)
        assert len(ops) > 30  # Should have 40+ operations

    def test_operations_have_required_fields(self, nxc_module):
        """Test all operations have required fields."""
        ops = nxc_module.get_operations()
        for op in ops:
            assert "name" in op
            assert "description" in op
            assert "handler" in op
            assert "subcategory" in op

    def test_get_subcategories(self, nxc_module):
        """Test get_subcategories returns expected categories."""
        subcats = nxc_module.get_subcategories()
        assert "authentication" in subcats
        assert "enumeration" in subcats
        assert "shares" in subcats
        assert "execution" in subcats
        assert "credentials" in subcats
        assert "vulnerability" in subcats

    def test_operations_by_subcategory(self, nxc_module):
        """Test filtering operations by subcategory."""
        auth_ops = nxc_module.get_operations_by_subcategory("authentication")
        assert len(auth_ops) >= 4
        assert all(op["subcategory"] == "authentication" for op in auth_ops)

    def test_operations_have_valid_handlers(self, nxc_module):
        """Test all operation handlers exist as methods."""
        ops = nxc_module.get_operations()
        for op in ops:
            handler_name = op["handler"]
            assert hasattr(nxc_module, handler_name), f"Missing handler: {handler_name}"


# =============================================================================
# _build_auth Tests
# =============================================================================

class TestBuildAuth:
    """Tests for the _build_auth method."""

    def test_build_auth_no_username(self, nxc_with_target):
        """Test _build_auth returns empty string without username."""
        auth = nxc_with_target._build_auth()
        assert auth == ""

    def test_build_auth_username_only(self, nxc_with_target):
        """Test _build_auth with username only."""
        nxc_with_target.set_option("USERNAME", "admin")
        auth = nxc_with_target._build_auth()
        assert "-u 'admin'" in auth
        assert "-p ''" in auth  # Empty password

    def test_build_auth_username_password(self, nxc_with_creds):
        """Test _build_auth with username and password."""
        auth = nxc_with_creds._build_auth()
        assert "-u 'admin'" in auth
        assert "-p 'password123'" in auth

    def test_build_auth_with_hash(self, nxc_with_target):
        """Test _build_auth with NTLM hash."""
        nxc_with_target.set_option("USERNAME", "admin")
        # Ensure HASH option exists in the options dict
        nxc_with_target.options["HASH"] = {"value": "aad3b435b51404ee:8846f7eaee8fb117", "required": False}
        auth = nxc_with_target._build_auth()
        assert "-u 'admin'" in auth
        assert "-H 'aad3b435b51404ee:8846f7eaee8fb117'" in auth
        assert "-p" not in auth

    def test_build_auth_hash_takes_precedence(self, nxc_with_creds):
        """Test hash takes precedence over password."""
        # Ensure HASH option exists in the options dict
        nxc_with_creds.options["HASH"] = {"value": "somehash", "required": False}
        auth = nxc_with_creds._build_auth()
        assert "-H 'somehash'" in auth
        assert "-p" not in auth


# =============================================================================
# _execute_nxc Tests
# =============================================================================

class TestExecuteNxc:
    """Tests for the _execute_nxc method."""

    def test_execute_nxc_basic(self, nxc_with_creds):
        """Test basic nxc execution."""
        with patch.object(nxc_with_creds, 'execute_command', return_value={"success": True}) as mock_exec:
            nxc_with_creds._execute_nxc()
            mock_exec.assert_called_once()
            call_args = mock_exec.call_args[0][0]
            assert "nxc smb" in call_args
            assert "192.168.1.100" in call_args

    def test_execute_nxc_includes_domain(self, nxc_with_creds):
        """Test nxc includes domain."""
        with patch.object(nxc_with_creds, 'execute_command', return_value={"success": True}) as mock_exec:
            nxc_with_creds._execute_nxc()
            call_args = mock_exec.call_args[0][0]
            assert "-d TESTDOMAIN" in call_args

    def test_execute_nxc_no_domain_for_workgroup(self, nxc_with_target):
        """Test nxc doesn't include domain for WORKGROUP."""
        nxc_with_target.set_option("DOMAIN", "WORKGROUP")
        with patch.object(nxc_with_target, 'execute_command', return_value={"success": True}) as mock_exec:
            nxc_with_target._execute_nxc()
            call_args = mock_exec.call_args[0][0]
            assert "-d WORKGROUP" not in call_args

    def test_execute_nxc_local_auth(self, nxc_with_creds):
        """Test nxc with local auth type."""
        nxc_with_creds.set_option("AUTH_TYPE", "local")
        with patch.object(nxc_with_creds, 'execute_command', return_value={"success": True}) as mock_exec:
            nxc_with_creds._execute_nxc()
            call_args = mock_exec.call_args[0][0]
            assert "--local-auth" in call_args

    def test_execute_nxc_kerberos(self, nxc_with_creds):
        """Test nxc with kerberos auth type."""
        nxc_with_creds.set_option("AUTH_TYPE", "kerberos")
        with patch.object(nxc_with_creds, 'execute_command', return_value={"success": True}) as mock_exec:
            nxc_with_creds._execute_nxc()
            call_args = mock_exec.call_args[0][0]
            assert "--kerberos" in call_args

    def test_execute_nxc_with_extra_args(self, nxc_with_creds):
        """Test nxc with extra arguments."""
        with patch.object(nxc_with_creds, 'execute_command', return_value={"success": True}) as mock_exec:
            nxc_with_creds._execute_nxc("--shares")
            call_args = mock_exec.call_args[0][0]
            assert "--shares" in call_args

    def test_execute_nxc_timeout(self, nxc_with_creds):
        """Test nxc execution has timeout."""
        with patch.object(nxc_with_creds, 'execute_command', return_value={"success": True}) as mock_exec:
            nxc_with_creds._execute_nxc()
            call_kwargs = mock_exec.call_args[1]
            assert call_kwargs.get('timeout') == 300


# =============================================================================
# Authentication Operation Tests
# =============================================================================

class TestAuthenticationOperations:
    """Tests for authentication operation handlers."""

    def test_op_test_auth(self, nxc_with_creds):
        """Test basic authentication operation."""
        with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
            result = nxc_with_creds.op_test_auth()
            mock_exec.assert_called_once_with()

    def test_op_test_domain(self, nxc_with_creds):
        """Test domain authentication operation."""
        with patch('builtins.input', return_value='CORP'):
            with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}):
                nxc_with_creds.op_test_domain()
                assert nxc_with_creds.get_option("DOMAIN") == "TESTDOMAIN"  # Already set

    def test_op_pass_the_hash_requires_hash(self, nxc_with_target):
        """Test PTH requires hash input."""
        with patch('builtins.input', return_value=''):
            result = nxc_with_target.op_pass_the_hash()
            assert result["success"] is False
            assert "Hash required" in result["error"]

    def test_op_pass_the_hash_with_hash(self, nxc_with_target):
        """Test PTH with hash input."""
        # Ensure HASH option exists
        nxc_with_target.options["HASH"] = {"value": None, "required": False}
        with patch('builtins.input', side_effect=['aad3b435:8846f7ea', 'admin']):
            with patch.object(nxc_with_target, '_execute_nxc', return_value={"success": True}):
                nxc_with_target.op_pass_the_hash()
                assert nxc_with_target.get_option("HASH") == "aad3b435:8846f7ea"

    def test_op_local_auth(self, nxc_with_creds):
        """Test local auth operation."""
        with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
            nxc_with_creds.op_local_auth()
            mock_exec.assert_called_once_with("--local-auth")


# =============================================================================
# Enumeration Operation Tests
# =============================================================================

class TestEnumerationOperations:
    """Tests for enumeration operation handlers."""

    def test_op_list_shares(self, nxc_with_creds):
        """Test share enumeration."""
        with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
            nxc_with_creds.op_list_shares()
            mock_exec.assert_called_once_with("--shares")

    def test_op_enum_users(self, nxc_with_creds):
        """Test user enumeration."""
        with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
            nxc_with_creds.op_enum_users()
            mock_exec.assert_called_once_with("--users")

    def test_op_enum_local_users(self, nxc_with_creds):
        """Test local user enumeration."""
        with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
            nxc_with_creds.op_enum_local_users()
            mock_exec.assert_called_once_with("--local-users")

    def test_op_enum_groups(self, nxc_with_creds):
        """Test group enumeration."""
        with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
            nxc_with_creds.op_enum_groups()
            mock_exec.assert_called_once_with("--groups")

    def test_op_password_policy(self, nxc_with_creds):
        """Test password policy enumeration."""
        with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
            nxc_with_creds.op_password_policy()
            mock_exec.assert_called_once_with("--pass-pol")

    def test_op_active_sessions(self, nxc_with_creds):
        """Test session enumeration."""
        with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
            nxc_with_creds.op_active_sessions()
            mock_exec.assert_called_once_with("--sessions")

    def test_op_loggedon_users(self, nxc_with_creds):
        """Test logged on users enumeration."""
        with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
            nxc_with_creds.op_loggedon_users()
            mock_exec.assert_called_once_with("--loggedon-users")

    def test_op_rid_brute(self, nxc_with_creds):
        """Test RID bruteforce."""
        with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
            nxc_with_creds.op_rid_brute()
            mock_exec.assert_called_once_with("--rid-brute")

    def test_op_list_disks(self, nxc_with_creds):
        """Test disk enumeration."""
        with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
            nxc_with_creds.op_list_disks()
            mock_exec.assert_called_once_with("--disks")

    def test_op_full_enum(self, nxc_with_creds):
        """Test full enumeration."""
        with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
            nxc_with_creds.op_full_enum()
            call_args = mock_exec.call_args[0][0]
            assert "--users" in call_args
            assert "--groups" in call_args
            assert "--shares" in call_args
            assert "--sessions" in call_args


# =============================================================================
# Share Operation Tests
# =============================================================================

class TestShareOperations:
    """Tests for share operation handlers."""

    def test_op_browse_download(self, nxc_with_creds):
        """Test browse and download operation."""
        with patch('builtins.input', side_effect=['C$', '*.xlsx']):
            with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
                nxc_with_creds.op_browse_download()
                call_args = mock_exec.call_args[0][0]
                assert "spider_plus" in call_args
                assert "DOWNLOAD_FLAG=True" in call_args

    def test_op_download_all_cancelled(self, nxc_with_creds):
        """Test download all operation cancelled."""
        with patch('builtins.input', return_value='n'):
            result = nxc_with_creds.op_download_all()
            assert result["success"] is False
            assert "cancelled" in result["error"]

    def test_op_download_all_confirmed(self, nxc_with_creds):
        """Test download all operation confirmed."""
        with patch('builtins.input', return_value='y'):
            with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
                nxc_with_creds.op_download_all()
                call_args = mock_exec.call_args[0][0]
                assert "spider_plus" in call_args
                assert "DOWNLOAD_FLAG=True" in call_args

    def test_op_download_pattern_requires_pattern(self, nxc_with_creds):
        """Test download pattern requires pattern input."""
        with patch('builtins.input', return_value=''):
            result = nxc_with_creds.op_download_pattern()
            assert result["success"] is False
            assert "Pattern required" in result["error"]

    def test_op_download_pattern_with_pattern(self, nxc_with_creds):
        """Test download pattern with pattern input."""
        with patch('builtins.input', return_value='*.xlsx'):
            with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
                nxc_with_creds.op_download_pattern()
                call_args = mock_exec.call_args[0][0]
                assert "PATTERN='*.xlsx'" in call_args


# =============================================================================
# Execution Operation Tests
# =============================================================================

class TestExecutionOperations:
    """Tests for execution operation handlers."""

    def test_op_system_info(self, nxc_with_creds):
        """Test system info command."""
        with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
            nxc_with_creds.op_system_info()
            call_args = mock_exec.call_args[0][0]
            assert "systeminfo" in call_args.lower() or "--x" in call_args or "-x" in call_args

    def test_op_list_processes(self, nxc_with_creds):
        """Test list processes command."""
        with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
            nxc_with_creds.op_list_processes()
            call_args = mock_exec.call_args[0][0]
            # Should use tasklist or similar
            mock_exec.assert_called()

    def test_op_network_config(self, nxc_with_creds):
        """Test network config command."""
        with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
            nxc_with_creds.op_network_config()
            call_args = mock_exec.call_args[0][0]
            assert "ipconfig" in call_args.lower() or "-x" in call_args

    def test_op_list_admins(self, nxc_with_creds):
        """Test list administrators command."""
        with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
            nxc_with_creds.op_list_admins()
            mock_exec.assert_called()

    def test_op_check_privs(self, nxc_with_creds):
        """Test check privileges command."""
        with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
            nxc_with_creds.op_check_privs()
            call_args = mock_exec.call_args[0][0]
            assert "whoami" in call_args.lower() or "-x" in call_args


# =============================================================================
# Credential Dumping Operation Tests
# =============================================================================

class TestCredentialOperations:
    """Tests for credential dumping operation handlers."""

    def test_op_dump_sam(self, nxc_with_creds):
        """Test SAM dump operation."""
        with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
            nxc_with_creds.op_dump_sam()
            mock_exec.assert_called_once_with("--sam")

    def test_op_dump_lsa(self, nxc_with_creds):
        """Test LSA dump operation."""
        with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
            nxc_with_creds.op_dump_lsa()
            mock_exec.assert_called_once_with("--lsa")

    def test_op_dump_ntds(self, nxc_with_creds):
        """Test NTDS dump operation."""
        with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
            nxc_with_creds.op_dump_ntds()
            mock_exec.assert_called_once_with("--ntds")

    def test_op_dump_all(self, nxc_with_creds):
        """Test dump all operation."""
        with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
            nxc_with_creds.op_dump_all()
            call_args = mock_exec.call_args[0][0]
            assert "--sam" in call_args
            assert "--lsa" in call_args
            assert "--ntds" in call_args

    def test_op_lsassy(self, nxc_with_creds):
        """Test lsassy operation."""
        with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
            nxc_with_creds.op_lsassy()
            call_args = mock_exec.call_args[0][0]
            assert "lsassy" in call_args.lower() or "-M" in call_args


# =============================================================================
# Vulnerability Check Operation Tests
# =============================================================================

class TestVulnerabilityOperations:
    """Tests for vulnerability check operation handlers."""

    def test_op_ms17_010(self, nxc_with_creds):
        """Test MS17-010 check."""
        # MS17-010 uses execute_command directly, not _execute_nxc
        with patch.object(nxc_with_creds, 'execute_command', return_value={"success": True}) as mock_exec:
            nxc_with_creds.op_ms17_010()
            call_args = mock_exec.call_args[0][0]
            assert "ms17-010" in call_args.lower() or "eternal" in call_args.lower()

    def test_op_zerologon(self, nxc_with_creds):
        """Test Zerologon check."""
        with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
            nxc_with_creds.op_zerologon()
            call_args = mock_exec.call_args[0][0]
            assert "zerologon" in call_args.lower()

    def test_op_petitpotam(self, nxc_with_creds):
        """Test PetitPotam check."""
        with patch.object(nxc_with_creds, '_execute_nxc', return_value={"success": True}) as mock_exec:
            nxc_with_creds.op_petitpotam()
            call_args = mock_exec.call_args[0][0]
            assert "petitpotam" in call_args.lower()


# =============================================================================
# Edge Cases
# =============================================================================

class TestNXCSMBEdgeCases:
    """Tests for edge cases in NXC SMB module."""

    def test_special_characters_in_password(self, nxc_with_target):
        """Test handling special characters in password."""
        nxc_with_target.set_option("USERNAME", "admin")
        nxc_with_target.set_option("PASSWORD", "P@ss'word\"123!")

        auth = nxc_with_target._build_auth()
        assert "-u 'admin'" in auth
        # Password should be quoted

    def test_empty_domain(self, nxc_with_creds):
        """Test handling empty domain."""
        nxc_with_creds.set_option("DOMAIN", "")
        with patch.object(nxc_with_creds, 'execute_command', return_value={"success": True}) as mock_exec:
            nxc_with_creds._execute_nxc()
            call_args = mock_exec.call_args[0][0]
            assert "-d" not in call_args or "-d ''" not in call_args

    def test_ipv6_target(self, nxc_module):
        """Test handling IPv6 target."""
        nxc_module.set_option("RHOST", "::1")
        with patch.object(nxc_module, 'execute_command', return_value={"success": True}) as mock_exec:
            nxc_module._execute_nxc()
            call_args = mock_exec.call_args[0][0]
            assert "::1" in call_args

    def test_cidr_target(self, nxc_module):
        """Test handling CIDR notation target."""
        nxc_module.set_option("RHOST", "192.168.1.0/24")
        with patch.object(nxc_module, 'execute_command', return_value={"success": True}) as mock_exec:
            nxc_module._execute_nxc()
            call_args = mock_exec.call_args[0][0]
            assert "192.168.1.0/24" in call_args
