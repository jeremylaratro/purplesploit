"""
Tests for the Script Deployment Module.

Tests script deployment operations including WinPEAS, LinPEAS, and custom scripts
via various methods (NXC, SSH, SMB, PSExec).
"""

import pytest
from unittest.mock import MagicMock, patch, call
import subprocess
from typing import Dict, Any


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def script_module(mock_framework_minimal):
    """Create a ScriptDeployModule instance for testing."""
    from purplesploit.modules.deploy.script import ScriptDeployModule
    module = ScriptDeployModule(mock_framework_minimal)
    return module


@pytest.fixture
def configured_script_module(script_module):
    """Create a fully configured script module."""
    script_module.set_option("RHOST", "192.168.1.100")
    script_module.set_option("USERNAME", "admin")
    script_module.set_option("PASSWORD", "password123")
    script_module.set_option("LOCAL_FILE", "/path/to/script.exe")
    return script_module


# =============================================================================
# Module Property Tests
# =============================================================================

class TestModuleProperties:
    """Tests for basic module properties."""

    def test_name(self, script_module):
        """Test module name property."""
        assert script_module.name == "Script Deploy"

    def test_description(self, script_module):
        """Test module description property."""
        assert "enumeration scripts" in script_module.description.lower()

    def test_author(self, script_module):
        """Test module author property."""
        assert script_module.author == "PurpleSploit Team"

    def test_category(self, script_module):
        """Test module category property."""
        assert script_module.category == "deploy"


# =============================================================================
# Options Tests
# =============================================================================

class TestModuleOptions:
    """Tests for module options."""

    def test_default_options_exist(self, script_module):
        """Test that required options are initialized."""
        options = script_module.options
        assert "RHOST" in options
        assert "USERNAME" in options
        assert "PASSWORD" in options
        assert "LOCAL_FILE" in options
        assert "EXECUTE" in options
        assert "TARGET_OS" in options

    def test_rhost_required(self, script_module):
        """Test that RHOST is required."""
        assert script_module.options["RHOST"]["required"] is True

    def test_local_file_required(self, script_module):
        """Test that LOCAL_FILE is required."""
        assert script_module.options["LOCAL_FILE"]["required"] is True

    def test_default_target_os(self, script_module):
        """Test default TARGET_OS value."""
        assert script_module.get_option("TARGET_OS") == "windows"

    def test_default_execute_option(self, script_module):
        """Test default EXECUTE value."""
        assert script_module.get_option("EXECUTE") is True

    def test_set_option(self, script_module):
        """Test setting an option."""
        script_module.set_option("RHOST", "10.10.10.10")
        assert script_module.get_option("RHOST") == "10.10.10.10"


# =============================================================================
# Operations Tests
# =============================================================================

class TestOperations:
    """Tests for module operations."""

    def test_get_operations_returns_list(self, script_module):
        """Test that get_operations returns a list."""
        ops = script_module.get_operations()
        assert isinstance(ops, list)
        assert len(ops) > 0

    def test_operations_have_required_keys(self, script_module):
        """Test that operations have required keys."""
        ops = script_module.get_operations()
        for op in ops:
            assert "name" in op
            assert "description" in op
            assert "handler" in op

    def test_operations_include_winpeas(self, script_module):
        """Test that WinPEAS operations are included."""
        ops = script_module.get_operations()
        names = [op["name"] for op in ops]
        assert any("WinPEAS" in name for name in names)

    def test_operations_include_linpeas(self, script_module):
        """Test that LinPEAS operations are included."""
        ops = script_module.get_operations()
        names = [op["name"] for op in ops]
        assert any("LinPEAS" in name for name in names)


# =============================================================================
# WinPEAS NXC Deployment Tests
# =============================================================================

class TestDeployWinpeasNxc:
    """Tests for WinPEAS NXC deployment."""

    def test_missing_local_file(self, script_module):
        """Test deployment without LOCAL_FILE."""
        script_module.set_option("RHOST", "192.168.1.100")
        script_module.set_option("USERNAME", "admin")
        script_module.set_option("PASSWORD", "password123")
        # No LOCAL_FILE set

        result = script_module.deploy_winpeas_nxc()
        assert result["success"] is False
        assert "LOCAL_FILE" in result["error"]

    def test_missing_credentials(self, script_module):
        """Test deployment without credentials."""
        script_module.set_option("RHOST", "192.168.1.100")
        script_module.set_option("LOCAL_FILE", "/path/to/winpeas.exe")
        # No username or password

        result = script_module.deploy_winpeas_nxc()
        assert result["success"] is False
        assert "Missing required" in result["error"]

    def test_successful_deployment_with_password(self, configured_script_module):
        """Test successful deployment with password."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="Upload successful\nExecution successful",
                stderr=""
            )

            result = configured_script_module.deploy_winpeas_nxc()
            assert result["success"] is True
            assert result["method"] == "nxc"
            assert "remote_path" in result

    def test_deployment_with_hash(self, script_module):
        """Test deployment with NTLM hash."""
        script_module.set_option("RHOST", "192.168.1.100")
        script_module.set_option("USERNAME", "admin")
        script_module.set_option("HASH", "aad3b435b51404ee:8846f7eaee8fb117")
        script_module.set_option("LOCAL_FILE", "/path/to/winpeas.exe")

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="OK", stderr="")
            result = script_module.deploy_winpeas_nxc()
            assert result["success"] is True
            # Verify hash was used in command
            calls = mock_run.call_args_list
            assert any("-H" in str(call) for call in calls)

    def test_deployment_with_domain(self, configured_script_module):
        """Test deployment with domain."""
        configured_script_module.set_option("DOMAIN", "TESTDOMAIN")

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="OK", stderr="")
            result = configured_script_module.deploy_winpeas_nxc()
            assert result["success"] is True
            # Verify domain was used
            calls = mock_run.call_args_list
            assert any("-d" in str(call) for call in calls)

    def test_upload_failure(self, configured_script_module):
        """Test handling of upload failure."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="Connection refused"
            )

            result = configured_script_module.deploy_winpeas_nxc()
            assert result["success"] is False
            assert "Upload failed" in result["error"]

    def test_save_output_enabled(self, configured_script_module, tmp_path):
        """Test saving output to file."""
        output_file = tmp_path / "output.txt"
        configured_script_module.set_option("SAVE_OUTPUT", True)
        configured_script_module.set_option("OUTPUT_FILE", str(output_file))

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="WinPEAS output here",
                stderr=""
            )

            result = configured_script_module.deploy_winpeas_nxc()
            assert result["success"] is True
            assert output_file.exists()


# =============================================================================
# WinPEAS SMB Deployment Tests
# =============================================================================

class TestDeployWinpeasSmb:
    """Tests for WinPEAS SMB deployment."""

    def test_missing_password(self, script_module):
        """Test deployment without password for SMB."""
        script_module.set_option("RHOST", "192.168.1.100")
        script_module.set_option("USERNAME", "admin")
        script_module.set_option("LOCAL_FILE", "/path/to/winpeas.exe")
        # No password

        result = script_module.deploy_winpeas_smb()
        assert result["success"] is False

    def test_successful_smb_deployment(self, configured_script_module):
        """Test successful SMB deployment."""
        with patch.object(configured_script_module, '_upload_via_smb') as mock_upload:
            with patch.object(configured_script_module, '_execute_via_wmi') as mock_exec:
                mock_upload.return_value = {
                    "success": True,
                    "remote_path": "C:\\Windows\\Temp\\winpeas.exe"
                }
                mock_exec.return_value = {
                    "success": True,
                    "output": "WinPEAS output"
                }

                result = configured_script_module.deploy_winpeas_smb()
                assert result["success"] is True


# =============================================================================
# WinPEAS PSExec Deployment Tests
# =============================================================================

class TestDeployWinpeasPsexec:
    """Tests for WinPEAS PSExec deployment."""

    def test_missing_auth(self, script_module):
        """Test deployment without authentication."""
        script_module.set_option("RHOST", "192.168.1.100")
        script_module.set_option("USERNAME", "admin")
        script_module.set_option("LOCAL_FILE", "/path/to/winpeas.exe")
        # No password or hash

        result = script_module.deploy_winpeas_psexec()
        assert result["success"] is False
        assert "PASSWORD or HASH" in result["error"]

    def test_successful_psexec_deployment(self, configured_script_module):
        """Test successful PSExec deployment."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="Impacket v0.10\nWinPEAS output",
                stderr=""
            )

            result = configured_script_module.deploy_winpeas_psexec()
            assert result["success"] is True
            assert result["method"] == "psexec"

    def test_psexec_with_domain(self, configured_script_module):
        """Test PSExec with domain authentication."""
        configured_script_module.set_option("DOMAIN", "TESTDOMAIN")

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="Impacket v0.10\nSuccess",
                stderr=""
            )

            result = configured_script_module.deploy_winpeas_psexec()
            assert result["success"] is True


# =============================================================================
# LinPEAS SSH Deployment Tests
# =============================================================================

class TestDeployLinpeasSsh:
    """Tests for LinPEAS SSH deployment."""

    def test_missing_local_file(self, script_module):
        """Test deployment without LOCAL_FILE."""
        script_module.set_option("RHOST", "192.168.1.100")
        script_module.set_option("USERNAME", "root")

        result = script_module.deploy_linpeas_ssh()
        assert result["success"] is False
        assert "LOCAL_FILE" in result["error"]

    def test_successful_ssh_deployment_with_password(self, script_module):
        """Test successful SSH deployment with password."""
        script_module.set_option("RHOST", "192.168.1.100")
        script_module.set_option("USERNAME", "root")
        script_module.set_option("PASSWORD", "toor")
        script_module.set_option("LOCAL_FILE", "/path/to/linpeas.sh")

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="LinPEAS output",
                stderr=""
            )

            result = script_module.deploy_linpeas_ssh()
            assert result["success"] is True
            assert result["method"] == "ssh"
            assert "/tmp/linpeas.sh" in result["remote_path"]

    def test_ssh_deployment_with_key(self, script_module):
        """Test SSH deployment with SSH key."""
        script_module.set_option("RHOST", "192.168.1.100")
        script_module.set_option("USERNAME", "root")
        script_module.set_option("SSH_KEY", "/path/to/id_rsa")
        script_module.set_option("LOCAL_FILE", "/path/to/linpeas.sh")

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="LinPEAS output",
                stderr=""
            )

            result = script_module.deploy_linpeas_ssh()
            assert result["success"] is True
            # Verify -i flag was used
            calls = mock_run.call_args_list
            assert any("-i" in str(call) for call in calls)

    def test_ssh_upload_failure(self, script_module):
        """Test handling of SSH upload failure."""
        script_module.set_option("RHOST", "192.168.1.100")
        script_module.set_option("USERNAME", "root")
        script_module.set_option("PASSWORD", "toor")
        script_module.set_option("LOCAL_FILE", "/path/to/linpeas.sh")

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="Connection refused"
            )

            result = script_module.deploy_linpeas_ssh()
            assert result["success"] is False
            assert "Upload failed" in result["error"]


# =============================================================================
# LinPEAS NXC Deployment Tests
# =============================================================================

class TestDeployLinpeasNxc:
    """Tests for LinPEAS NXC deployment."""

    def test_missing_auth(self, script_module):
        """Test deployment without authentication."""
        script_module.set_option("RHOST", "192.168.1.100")
        script_module.set_option("USERNAME", "root")
        script_module.set_option("LOCAL_FILE", "/path/to/linpeas.sh")
        # No password or key

        result = script_module.deploy_linpeas_nxc()
        assert result["success"] is False

    def test_successful_nxc_ssh_deployment(self, script_module):
        """Test successful NXC SSH deployment."""
        script_module.set_option("RHOST", "192.168.1.100")
        script_module.set_option("USERNAME", "root")
        script_module.set_option("PASSWORD", "toor")
        script_module.set_option("LOCAL_FILE", "/path/to/linpeas.sh")

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="LinPEAS output",
                stderr=""
            )

            result = script_module.deploy_linpeas_nxc()
            assert result["success"] is True
            assert result["method"] == "nxc_ssh"


# =============================================================================
# Custom Script NXC Deployment Tests
# =============================================================================

class TestDeployScriptNxc:
    """Tests for custom script NXC deployment."""

    def test_windows_target(self, configured_script_module):
        """Test deployment to Windows target."""
        configured_script_module.set_option("TARGET_OS", "windows")

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="Script output",
                stderr=""
            )

            result = configured_script_module.deploy_script_nxc()
            assert result["success"] is True
            assert "nxc_smb" in result["method"]

    def test_linux_target(self, script_module):
        """Test deployment to Linux target."""
        script_module.set_option("RHOST", "192.168.1.100")
        script_module.set_option("USERNAME", "root")
        script_module.set_option("PASSWORD", "toor")
        script_module.set_option("LOCAL_FILE", "/path/to/script.sh")
        script_module.set_option("TARGET_OS", "linux")

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="Script output",
                stderr=""
            )

            result = script_module.deploy_script_nxc()
            assert result["success"] is True
            assert "nxc_ssh" in result["method"]

    def test_no_execute(self, configured_script_module):
        """Test deployment without execution."""
        configured_script_module.set_option("EXECUTE", False)

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="Upload complete",
                stderr=""
            )

            result = configured_script_module.deploy_script_nxc()
            assert result["success"] is True
            # Should only call upload, not execute
            assert mock_run.call_count == 1

    def test_with_exec_args(self, configured_script_module):
        """Test deployment with execution arguments."""
        configured_script_module.set_option("EXEC_ARGS", "--verbose --scan-all")

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="Script output",
                stderr=""
            )

            result = configured_script_module.deploy_script_nxc()
            assert result["success"] is True


# =============================================================================
# Custom Script SSH Deployment Tests
# =============================================================================

class TestDeployScriptSsh:
    """Tests for custom script SSH deployment."""

    def test_successful_ssh_deployment(self, script_module):
        """Test successful SSH script deployment."""
        script_module.set_option("RHOST", "192.168.1.100")
        script_module.set_option("USERNAME", "user")
        script_module.set_option("PASSWORD", "pass")
        script_module.set_option("LOCAL_FILE", "/path/to/script.sh")

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="Script output",
                stderr=""
            )

            result = script_module.deploy_script_ssh()
            assert result["success"] is True
            assert result["method"] == "ssh"

    def test_custom_remote_path(self, script_module):
        """Test deployment with custom remote path."""
        script_module.set_option("RHOST", "192.168.1.100")
        script_module.set_option("USERNAME", "user")
        script_module.set_option("PASSWORD", "pass")
        script_module.set_option("LOCAL_FILE", "/path/to/script.sh")
        script_module.set_option("REMOTE_PATH", "/opt/scripts/custom.sh")

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="",
                stderr=""
            )

            result = script_module.deploy_script_ssh()
            assert result["success"] is True
            assert result["remote_path"] == "/opt/scripts/custom.sh"


# =============================================================================
# Custom Script SMB Deployment Tests
# =============================================================================

class TestDeployScriptSmb:
    """Tests for custom script SMB deployment."""

    def test_successful_smb_deployment(self, configured_script_module):
        """Test successful SMB script deployment."""
        with patch.object(configured_script_module, '_upload_via_smb') as mock_upload:
            with patch.object(configured_script_module, '_execute_via_wmi') as mock_exec:
                mock_upload.return_value = {
                    "success": True,
                    "remote_path": "C:\\Windows\\Temp\\script.exe"
                }
                mock_exec.return_value = {
                    "success": True,
                    "output": "Script output"
                }

                result = configured_script_module.deploy_script_smb()
                assert result["success"] is True

    def test_upload_only(self, configured_script_module):
        """Test upload without execution."""
        configured_script_module.set_option("EXECUTE", False)

        with patch.object(configured_script_module, '_upload_via_smb') as mock_upload:
            mock_upload.return_value = {
                "success": True,
                "remote_path": "C:\\Windows\\Temp\\script.exe"
            }

            result = configured_script_module.deploy_script_smb()
            assert result["success"] is True
            assert "not executed" in result["output"]


# =============================================================================
# Helper Method Tests
# =============================================================================

class TestHelperMethods:
    """Tests for helper methods."""

    def test_upload_via_smb_success(self, configured_script_module):
        """Test successful SMB upload."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="",
                stderr=""
            )

            result = configured_script_module._upload_via_smb(
                "192.168.1.100", "admin", "password", "",
                "/path/to/file.exe", "file.exe"
            )
            assert result["success"] is True
            assert "remote_path" in result

    def test_upload_via_smb_failure(self, configured_script_module):
        """Test failed SMB upload."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="Access denied"
            )

            result = configured_script_module._upload_via_smb(
                "192.168.1.100", "admin", "password", "",
                "/path/to/file.exe", "file.exe"
            )
            assert result["success"] is False
            assert "Access denied" in result["error"]

    def test_execute_via_wmi_success(self, configured_script_module):
        """Test successful WMI execution."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="Impacket v0.10\nExecution output",
                stderr=""
            )

            result = configured_script_module._execute_via_wmi(
                "192.168.1.100", "admin", "password", "",
                None, "C:\\Windows\\Temp\\script.exe", ""
            )
            assert result["success"] is True
            assert result["method"] == "wmiexec"

    def test_execute_via_wmi_with_hash(self, configured_script_module):
        """Test WMI execution with hash."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="Impacket v0.10",
                stderr=""
            )

            result = configured_script_module._execute_via_wmi(
                "192.168.1.100", "admin", None, "",
                "aad3b435b51404ee:8846f7eaee8fb117",
                "C:\\Windows\\Temp\\script.exe", ""
            )
            assert result["success"] is True

    def test_execute_via_wmi_no_auth(self, configured_script_module):
        """Test WMI execution without auth."""
        result = configured_script_module._execute_via_wmi(
            "192.168.1.100", "admin", None, "",
            None, "C:\\Windows\\Temp\\script.exe", ""
        )
        assert result["success"] is False
        assert "PASSWORD or HASH" in result["error"]


# =============================================================================
# Run Method Tests
# =============================================================================

class TestRunMethod:
    """Tests for the run method."""

    def test_run_returns_success(self, script_module):
        """Test that run returns success with message."""
        result = script_module.run()
        assert result["success"] is True
        assert "message" in result


# =============================================================================
# Exception Handling Tests
# =============================================================================

class TestExceptionHandling:
    """Tests for exception handling."""

    def test_nxc_exception_handling(self, configured_script_module):
        """Test exception handling in NXC deployment."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("cmd", 60)

            result = configured_script_module.deploy_winpeas_nxc()
            assert result["success"] is False
            assert "failed" in result["error"].lower()

    def test_ssh_exception_handling(self, script_module):
        """Test exception handling in SSH deployment."""
        script_module.set_option("RHOST", "192.168.1.100")
        script_module.set_option("USERNAME", "root")
        script_module.set_option("PASSWORD", "toor")
        script_module.set_option("LOCAL_FILE", "/path/to/linpeas.sh")

        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = Exception("Network error")

            result = script_module.deploy_linpeas_ssh()
            assert result["success"] is False
            assert "failed" in result["error"].lower()
