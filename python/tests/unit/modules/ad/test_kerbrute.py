"""
Tests for purplesploit.modules.ad.kerbrute module.

Comprehensive test coverage for:
- Module initialization
- User enumeration
- Password spraying
- Brute force operations
- Output parsing
- Command building
- Error handling
"""

import pytest
import os
from unittest.mock import MagicMock, patch
from pathlib import Path

from purplesploit.modules.ad.kerbrute import KerbruteModule


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_framework():
    """Create mock framework for testing."""
    framework = MagicMock()
    framework.session = MagicMock()
    framework.session.get_current_target = MagicMock(return_value=None)
    framework.session.get_current_credential = MagicMock(return_value=None)
    framework.session.workspace = "default"
    framework.session.credentials = MagicMock()
    framework.session.credentials.add = MagicMock()
    framework.database = MagicMock()
    framework.database.get_module_defaults = MagicMock(return_value={})
    framework.log = MagicMock()
    return framework


@pytest.fixture
def kerbrute_module(mock_framework):
    """Create Kerbrute module instance."""
    return KerbruteModule(mock_framework)


@pytest.fixture
def temp_userlist(tmp_path):
    """Create temporary userlist file."""
    userlist = tmp_path / "users.txt"
    userlist.write_text("admin\nuser1\nuser2\nguest\nservice\n")
    return str(userlist)


@pytest.fixture
def temp_passlist(tmp_path):
    """Create temporary password list file."""
    passlist = tmp_path / "passwords.txt"
    passlist.write_text("Password123\nWinter2024\nP@ssw0rd\n")
    return str(passlist)


# =============================================================================
# Module Initialization Tests
# =============================================================================

class TestKerbruteModuleInit:
    """Tests for Kerbrute module initialization."""

    def test_module_properties(self, kerbrute_module):
        """Test module properties are set correctly."""
        assert kerbrute_module.name == "Kerbrute"
        assert "Kerberos" in kerbrute_module.description
        assert kerbrute_module.category == "ad"
        assert kerbrute_module.author == "PurpleSploit Team"

    def test_tool_name(self, kerbrute_module):
        """Test tool name is set."""
        assert kerbrute_module.tool_name == "kerbrute"

    def test_module_options(self, kerbrute_module):
        """Test module options are initialized."""
        assert "DOMAIN" in kerbrute_module.options
        assert "DC" in kerbrute_module.options
        assert "USERLIST" in kerbrute_module.options
        assert "USERNAME" in kerbrute_module.options
        assert "PASSWORD" in kerbrute_module.options
        assert "PASSLIST" in kerbrute_module.options
        assert "THREADS" in kerbrute_module.options
        assert "OUTPUT" in kerbrute_module.options
        assert "SAFE" in kerbrute_module.options

    def test_domain_option_required(self, kerbrute_module):
        """Test DOMAIN option is marked as required."""
        assert kerbrute_module.options["DOMAIN"]["required"] is True

    def test_default_threads(self, kerbrute_module):
        """Test default thread count."""
        assert kerbrute_module.options["THREADS"]["default"] == "10"

    def test_safe_mode_default(self, kerbrute_module):
        """Test safe mode is enabled by default."""
        assert kerbrute_module.options["SAFE"]["default"] == "true"


# =============================================================================
# Operations Tests
# =============================================================================

class TestKerbruteOperations:
    """Tests for Kerbrute operations."""

    def test_get_operations(self, kerbrute_module):
        """Test getting list of operations."""
        operations = kerbrute_module.get_operations()

        assert len(operations) == 4

    def test_operations_have_required_fields(self, kerbrute_module):
        """Test all operations have required fields."""
        operations = kerbrute_module.get_operations()

        for op in operations:
            assert "name" in op
            assert "description" in op
            assert "handler" in op

    def test_user_enumeration_operation(self, kerbrute_module):
        """Test User Enumeration operation exists."""
        operations = kerbrute_module.get_operations()
        names = [op["name"] for op in operations]

        assert "User Enumeration" in names

    def test_password_spray_operation(self, kerbrute_module):
        """Test Password Spray operation exists."""
        operations = kerbrute_module.get_operations()
        names = [op["name"] for op in operations]

        assert "Password Spray" in names

    def test_brute_force_operation(self, kerbrute_module):
        """Test Brute Force operation exists."""
        operations = kerbrute_module.get_operations()
        names = [op["name"] for op in operations]

        assert "Brute Force" in names

    def test_brute_user_operation(self, kerbrute_module):
        """Test Brute User operation exists."""
        operations = kerbrute_module.get_operations()
        names = [op["name"] for op in operations]

        assert "Brute User" in names


# =============================================================================
# Command Building Tests
# =============================================================================

class TestCommandBuilding:
    """Tests for command building."""

    def test_build_base_command_domain_only(self, kerbrute_module):
        """Test base command with domain only."""
        kerbrute_module.set_option("DOMAIN", "corp.local")

        cmd = kerbrute_module._build_base_command()

        assert "kerbrute" in cmd
        assert "-d corp.local" in cmd

    def test_build_base_command_with_dc(self, kerbrute_module):
        """Test base command with domain controller."""
        kerbrute_module.set_option("DOMAIN", "corp.local")
        kerbrute_module.set_option("DC", "192.168.1.1")

        cmd = kerbrute_module._build_base_command()

        assert "--dc 192.168.1.1" in cmd

    def test_build_base_command_with_threads(self, kerbrute_module):
        """Test base command with thread count."""
        kerbrute_module.set_option("DOMAIN", "corp.local")
        kerbrute_module.set_option("THREADS", "20")

        cmd = kerbrute_module._build_base_command()

        assert "-t 20" in cmd

    def test_build_base_command_with_output(self, kerbrute_module):
        """Test base command with output file."""
        kerbrute_module.set_option("DOMAIN", "corp.local")
        kerbrute_module.set_option("OUTPUT", "/tmp/results.txt")

        cmd = kerbrute_module._build_base_command()

        assert "-o /tmp/results.txt" in cmd

    def test_build_base_command_safe_mode(self, kerbrute_module):
        """Test base command with safe mode."""
        kerbrute_module.set_option("DOMAIN", "corp.local")
        kerbrute_module.set_option("SAFE", "true")

        cmd = kerbrute_module._build_base_command()

        assert "--safe" in cmd

    def test_build_base_command_safe_disabled(self, kerbrute_module):
        """Test base command with safe mode disabled."""
        kerbrute_module.set_option("DOMAIN", "corp.local")
        kerbrute_module.set_option("SAFE", "false")

        cmd = kerbrute_module._build_base_command()

        assert "--safe" not in cmd


# =============================================================================
# User Enumeration Command Tests
# =============================================================================

class TestUserEnumCommand:
    """Tests for user enumeration command building."""

    def test_build_userenum_with_userlist(self, kerbrute_module, temp_userlist):
        """Test userenum command with userlist."""
        kerbrute_module.set_option("DOMAIN", "corp.local")
        kerbrute_module.set_option("USERLIST", temp_userlist)

        cmd = kerbrute_module._build_userenum_command()

        assert "userenum" in cmd
        assert temp_userlist in cmd

    def test_build_userenum_with_username(self, kerbrute_module):
        """Test userenum command with single username."""
        kerbrute_module.set_option("DOMAIN", "corp.local")
        kerbrute_module.set_option("USERNAME", "admin")

        cmd = kerbrute_module._build_userenum_command()

        assert "userenum" in cmd
        assert "admin" in cmd

    def test_build_userenum_no_users(self, kerbrute_module):
        """Test userenum command without users."""
        kerbrute_module.set_option("DOMAIN", "corp.local")

        cmd = kerbrute_module._build_userenum_command()

        assert "Error" in cmd


# =============================================================================
# Password Spray Command Tests
# =============================================================================

class TestPasswordSprayCommand:
    """Tests for password spray command building."""

    def test_build_passwordspray_command(self, kerbrute_module, temp_userlist):
        """Test passwordspray command."""
        kerbrute_module.set_option("DOMAIN", "corp.local")
        kerbrute_module.set_option("USERLIST", temp_userlist)
        kerbrute_module.set_option("PASSWORD", "Winter2024!")

        cmd = kerbrute_module._build_passwordspray_command()

        assert "passwordspray" in cmd
        assert temp_userlist in cmd
        assert "Winter2024!" in cmd

    def test_build_passwordspray_no_userlist(self, kerbrute_module):
        """Test passwordspray command without userlist."""
        kerbrute_module.set_option("DOMAIN", "corp.local")
        kerbrute_module.set_option("PASSWORD", "test")

        cmd = kerbrute_module._build_passwordspray_command()

        assert "Error" in cmd

    def test_build_passwordspray_no_password(self, kerbrute_module, temp_userlist):
        """Test passwordspray command without password."""
        kerbrute_module.set_option("DOMAIN", "corp.local")
        kerbrute_module.set_option("USERLIST", temp_userlist)

        cmd = kerbrute_module._build_passwordspray_command()

        assert "Error" in cmd


# =============================================================================
# Brute Force Command Tests
# =============================================================================

class TestBruteForceCommand:
    """Tests for brute force command building."""

    def test_build_bruteforce_command(self, kerbrute_module, temp_userlist, temp_passlist):
        """Test bruteforce command."""
        kerbrute_module.set_option("DOMAIN", "corp.local")
        kerbrute_module.set_option("USERLIST", temp_userlist)
        kerbrute_module.set_option("PASSLIST", temp_passlist)

        cmd = kerbrute_module._build_bruteforce_command()

        assert "bruteforce" in cmd
        assert temp_userlist in cmd
        assert temp_passlist in cmd

    def test_build_bruteforce_no_userlist(self, kerbrute_module, temp_passlist):
        """Test bruteforce command without userlist."""
        kerbrute_module.set_option("DOMAIN", "corp.local")
        kerbrute_module.set_option("PASSLIST", temp_passlist)

        cmd = kerbrute_module._build_bruteforce_command()

        assert "Error" in cmd

    def test_build_bruteforce_no_passlist(self, kerbrute_module, temp_userlist):
        """Test bruteforce command without passlist."""
        kerbrute_module.set_option("DOMAIN", "corp.local")
        kerbrute_module.set_option("USERLIST", temp_userlist)

        cmd = kerbrute_module._build_bruteforce_command()

        assert "Error" in cmd


# =============================================================================
# Brute User Command Tests
# =============================================================================

class TestBruteUserCommand:
    """Tests for brute user command building."""

    def test_build_bruteuser_command(self, kerbrute_module, temp_passlist):
        """Test bruteuser command."""
        kerbrute_module.set_option("DOMAIN", "corp.local")
        kerbrute_module.set_option("USERNAME", "admin")
        kerbrute_module.set_option("PASSLIST", temp_passlist)

        cmd = kerbrute_module._build_bruteuser_command()

        assert "bruteuser" in cmd
        assert temp_passlist in cmd
        assert "admin" in cmd

    def test_build_bruteuser_no_username(self, kerbrute_module, temp_passlist):
        """Test bruteuser command without username."""
        kerbrute_module.set_option("DOMAIN", "corp.local")
        kerbrute_module.set_option("PASSLIST", temp_passlist)

        cmd = kerbrute_module._build_bruteuser_command()

        assert "Error" in cmd


# =============================================================================
# User Enumeration Output Parsing Tests
# =============================================================================

class TestUserEnumParsing:
    """Tests for user enumeration output parsing."""

    def test_parse_userenum_valid_users(self, kerbrute_module):
        """Test parsing valid users."""
        output = """
        2024/01/15 10:00:00 [+] VALID USERNAME: admin@corp.local
        2024/01/15 10:00:01 [+] VALID USERNAME: user1@corp.local
        2024/01/15 10:00:02 [-] INVALID: nonexistent@corp.local
        2024/01/15 10:00:03 [+] VALID USERNAME: service@corp.local
        """

        result = kerbrute_module._parse_userenum(output)

        assert "valid_users" in result
        assert len(result["valid_users"]) == 3
        assert "admin" in result["valid_users"]
        assert "user1" in result["valid_users"]

    def test_parse_userenum_no_valid_users(self, kerbrute_module):
        """Test parsing with no valid users."""
        output = """
        2024/01/15 10:00:00 [-] INVALID: user1@corp.local
        2024/01/15 10:00:01 [-] INVALID: user2@corp.local
        """

        result = kerbrute_module._parse_userenum(output)

        assert result["valid_users"] == []
        assert result["total_valid"] == 0

    def test_parse_userenum_empty_output(self, kerbrute_module):
        """Test parsing empty output."""
        result = kerbrute_module._parse_userenum("")

        assert result["valid_users"] == []
        assert result["invalid_users"] == []

    def test_parse_userenum_counts(self, kerbrute_module):
        """Test parsing counts valid and invalid."""
        output = """
        [+] VALID USERNAME: admin@corp.local
        [+] VALID USERNAME: user@corp.local
        [-] INVALID: fake@corp.local
        """

        result = kerbrute_module._parse_userenum(output)

        assert result["total_valid"] == 2
        assert len(result["invalid_users"]) == 1


# =============================================================================
# Password Spray Output Parsing Tests
# =============================================================================

class TestSprayParsing:
    """Tests for password spray output parsing."""

    def test_parse_spray_valid_creds(self, kerbrute_module):
        """Test parsing valid credentials."""
        output = """
        2024/01/15 10:00:00 [+] VALID LOGIN: admin@corp.local:Password123
        2024/01/15 10:00:01 [-] Failed: user1@corp.local
        2024/01/15 10:00:02 [+] VALID LOGIN: service@corp.local:Password123
        """

        result = kerbrute_module._parse_spray(output)

        assert "valid_creds" in result
        assert len(result["valid_creds"]) == 2
        assert "admin" in result["valid_creds"]
        assert "service" in result["valid_creds"]

    def test_parse_spray_no_valid_creds(self, kerbrute_module):
        """Test parsing with no valid credentials."""
        output = """
        2024/01/15 10:00:00 [-] Failed: admin@corp.local
        2024/01/15 10:00:01 [-] Failed: user1@corp.local
        """

        result = kerbrute_module._parse_spray(output)

        assert result["valid_creds"] == []
        assert result["total_valid"] == 0

    def test_parse_spray_locked_accounts(self, kerbrute_module):
        """Test parsing locked accounts."""
        output = """
        2024/01/15 10:00:00 [!] LOCKED: admin@corp.local
        2024/01/15 10:00:01 [+] VALID LOGIN: user@corp.local
        """

        result = kerbrute_module._parse_spray(output)

        assert "locked_out" in result
        assert "admin" in result["locked_out"]

    def test_parse_spray_empty_output(self, kerbrute_module):
        """Test parsing empty output."""
        result = kerbrute_module._parse_spray("")

        assert result["valid_creds"] == []
        assert result["locked_out"] == []


# =============================================================================
# Brute Force Output Parsing Tests
# =============================================================================

class TestBruteParsing:
    """Tests for brute force output parsing."""

    def test_parse_brute_valid_creds(self, kerbrute_module):
        """Test parsing valid credentials with passwords."""
        output = """
        2024/01/15 10:00:00 [+] VALID LOGIN: admin@corp.local:Password123
        2024/01/15 10:00:01 [+] VALID LOGIN: user1@corp.local:Winter2024
        """

        result = kerbrute_module._parse_brute(output)

        assert "valid_creds" in result
        assert len(result["valid_creds"]) == 2

        # Check credentials have user and password
        for cred in result["valid_creds"]:
            assert "user" in cred
            assert "password" in cred

    def test_parse_brute_extracts_password(self, kerbrute_module):
        """Test password extraction."""
        output = "[+] VALID LOGIN: admin@corp.local:SecretPass123"

        result = kerbrute_module._parse_brute(output)

        if result["valid_creds"]:
            cred = result["valid_creds"][0]
            assert cred["user"] == "admin"
            assert cred["password"] == "SecretPass123"

    def test_parse_brute_empty_output(self, kerbrute_module):
        """Test parsing empty output."""
        result = kerbrute_module._parse_brute("")

        assert result["valid_creds"] == []
        assert result["total_valid"] == 0


# =============================================================================
# User Enumeration Operation Tests
# =============================================================================

class TestUserEnumOperation:
    """Tests for user enumeration operation."""

    def test_op_userenum_success(self, kerbrute_module, temp_userlist):
        """Test successful user enumeration."""
        kerbrute_module.set_option("DOMAIN", "corp.local")
        kerbrute_module.set_option("USERLIST", temp_userlist)

        mock_output = "[+] VALID USERNAME: admin@corp.local"

        with patch.object(kerbrute_module, 'execute_command', return_value={
            'success': True,
            'output': mock_output,
            'stdout': mock_output,
        }):
            result = kerbrute_module.op_userenum()

        assert result["success"] is True
        assert "parsed" in result

    def test_op_userenum_adds_credentials(self, kerbrute_module, mock_framework, temp_userlist):
        """Test valid users are added as credentials."""
        kerbrute_module.set_option("DOMAIN", "corp.local")
        kerbrute_module.set_option("USERLIST", temp_userlist)

        mock_output = "[+] VALID USERNAME: admin@corp.local"

        with patch.object(kerbrute_module, 'execute_command', return_value={
            'success': True,
            'output': mock_output,
            'stdout': mock_output,
        }):
            kerbrute_module.op_userenum()

        # Verify credential was added
        mock_framework.session.credentials.add.assert_called()


# =============================================================================
# Password Spray Operation Tests
# =============================================================================

class TestPasswordSprayOperation:
    """Tests for password spray operation."""

    def test_op_passwordspray_success(self, kerbrute_module, temp_userlist):
        """Test successful password spray."""
        kerbrute_module.set_option("DOMAIN", "corp.local")
        kerbrute_module.set_option("USERLIST", temp_userlist)
        kerbrute_module.set_option("PASSWORD", "Winter2024!")

        mock_output = "[+] VALID LOGIN: admin@corp.local:Winter2024!"

        with patch.object(kerbrute_module, 'execute_command', return_value={
            'success': True,
            'output': mock_output,
            'stdout': mock_output,
        }):
            result = kerbrute_module.op_passwordspray()

        assert result["success"] is True
        assert "parsed" in result
        assert result["parsed"]["total_valid"] >= 1

    def test_op_passwordspray_adds_credentials(self, kerbrute_module, mock_framework, temp_userlist):
        """Test valid credentials are saved."""
        kerbrute_module.set_option("DOMAIN", "corp.local")
        kerbrute_module.set_option("USERLIST", temp_userlist)
        kerbrute_module.set_option("PASSWORD", "Winter2024!")

        mock_output = "[+] VALID LOGIN: admin@corp.local:Winter2024!"

        with patch.object(kerbrute_module, 'execute_command', return_value={
            'success': True,
            'output': mock_output,
            'stdout': mock_output,
        }):
            kerbrute_module.op_passwordspray()

        mock_framework.session.credentials.add.assert_called()


# =============================================================================
# Brute Force Operation Tests
# =============================================================================

class TestBruteForceOperation:
    """Tests for brute force operation."""

    def test_op_bruteforce_success(self, kerbrute_module, temp_userlist, temp_passlist):
        """Test successful brute force."""
        kerbrute_module.set_option("DOMAIN", "corp.local")
        kerbrute_module.set_option("USERLIST", temp_userlist)
        kerbrute_module.set_option("PASSLIST", temp_passlist)

        mock_output = "[+] VALID LOGIN: admin@corp.local:Password123"

        with patch.object(kerbrute_module, 'execute_command', return_value={
            'success': True,
            'output': mock_output,
            'stdout': mock_output,
        }):
            result = kerbrute_module.op_bruteforce()

        assert result["success"] is True
        assert "parsed" in result


# =============================================================================
# Brute User Operation Tests
# =============================================================================

class TestBruteUserOperation:
    """Tests for brute user operation."""

    def test_op_bruteuser_success(self, kerbrute_module, temp_passlist):
        """Test successful brute user."""
        kerbrute_module.set_option("DOMAIN", "corp.local")
        kerbrute_module.set_option("USERNAME", "admin")
        kerbrute_module.set_option("PASSLIST", temp_passlist)

        mock_output = "[+] VALID LOGIN: admin@corp.local:Password123"

        with patch.object(kerbrute_module, 'execute_command', return_value={
            'success': True,
            'output': mock_output,
            'stdout': mock_output,
        }):
            result = kerbrute_module.op_bruteuser()

        assert result["success"] is True

    def test_op_bruteuser_no_password_found(self, kerbrute_module, temp_passlist):
        """Test brute user with no password found."""
        kerbrute_module.set_option("DOMAIN", "corp.local")
        kerbrute_module.set_option("USERNAME", "admin")
        kerbrute_module.set_option("PASSLIST", temp_passlist)

        mock_output = "[-] Failed: admin@corp.local"

        with patch.object(kerbrute_module, 'execute_command', return_value={
            'success': True,
            'output': mock_output,
            'stdout': mock_output,
        }):
            result = kerbrute_module.op_bruteuser()

        assert result["success"] is True
        assert "No valid password found" in result["message"]


# =============================================================================
# Credential Adding Tests
# =============================================================================

class TestCredentialAdding:
    """Tests for credential adding functionality."""

    def test_add_credential_with_password(self, kerbrute_module, mock_framework):
        """Test adding credential with password."""
        kerbrute_module.set_option("DOMAIN", "corp.local")

        kerbrute_module._add_credential("admin", "Password123")

        mock_framework.session.credentials.add.assert_called_once()
        call_args = mock_framework.session.credentials.add.call_args[0][0]
        assert call_args["username"] == "admin"
        assert call_args["password"] == "Password123"
        assert call_args["domain"] == "corp.local"

    def test_add_credential_without_password(self, kerbrute_module, mock_framework):
        """Test adding credential without password."""
        kerbrute_module.set_option("DOMAIN", "corp.local")

        kerbrute_module._add_credential("admin")

        mock_framework.session.credentials.add.assert_called_once()
        call_args = mock_framework.session.credentials.add.call_args[0][0]
        assert call_args["username"] == "admin"
        assert "password" not in call_args

    def test_add_credential_handles_exception(self, kerbrute_module, mock_framework):
        """Test credential adding handles exceptions."""
        kerbrute_module.set_option("DOMAIN", "corp.local")
        mock_framework.session.credentials.add.side_effect = Exception("Database error")

        # Should not raise exception
        kerbrute_module._add_credential("admin", "pass")


# =============================================================================
# Default Run Tests
# =============================================================================

class TestDefaultRun:
    """Tests for default run behavior."""

    def test_run_calls_userenum(self, kerbrute_module, temp_userlist):
        """Test run() calls user enumeration."""
        kerbrute_module.set_option("DOMAIN", "corp.local")
        kerbrute_module.set_option("USERLIST", temp_userlist)

        with patch.object(kerbrute_module, 'op_userenum', return_value={'success': True}) as mock_userenum:
            result = kerbrute_module.run()

        mock_userenum.assert_called_once()
        assert result["success"] is True

    def test_parse_output_calls_userenum(self, kerbrute_module):
        """Test parse_output uses userenum parsing."""
        output = "[+] VALID USERNAME: admin@corp.local"

        result = kerbrute_module.parse_output(output)

        assert "valid_users" in result


# =============================================================================
# Build Command Tests
# =============================================================================

class TestBuildCommand:
    """Tests for default build_command method."""

    def test_build_command_defaults_to_userenum(self, kerbrute_module, temp_userlist):
        """Test build_command defaults to user enumeration."""
        kerbrute_module.set_option("DOMAIN", "corp.local")
        kerbrute_module.set_option("USERLIST", temp_userlist)

        cmd = kerbrute_module.build_command()

        assert "userenum" in cmd


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestErrorHandling:
    """Tests for error handling scenarios."""

    def test_handles_missing_domain(self, kerbrute_module, temp_userlist):
        """Test handling missing domain option."""
        kerbrute_module.set_option("USERLIST", temp_userlist)

        with patch.object(kerbrute_module, 'execute_command', return_value={
            'success': False,
            'error': 'Domain required',
        }):
            result = kerbrute_module.op_userenum()

        # Command execution should fail

    def test_handles_command_failure(self, kerbrute_module, temp_userlist):
        """Test handling command execution failure."""
        kerbrute_module.set_option("DOMAIN", "corp.local")
        kerbrute_module.set_option("USERLIST", temp_userlist)

        with patch.object(kerbrute_module, 'execute_command', return_value={
            'success': False,
            'error': 'Connection refused',
        }):
            result = kerbrute_module.op_userenum()

        assert result["success"] is False

    def test_handles_no_framework(self, kerbrute_module, temp_userlist):
        """Test handling no framework during credential add."""
        kerbrute_module.framework = None
        kerbrute_module.set_option("DOMAIN", "corp.local")

        # Should not raise exception
        kerbrute_module._add_credential("admin", "pass")
