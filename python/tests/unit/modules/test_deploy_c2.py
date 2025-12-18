"""
Tests for the C2 Beacon Deployment Module.

Tests C2 beacon deployment operations via various methods (NXC, SSH, SMB, PSExec, WMIExec, WinRM).
"""

import pytest
from unittest.mock import MagicMock, patch
import subprocess
from typing import Dict, Any


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def c2_module(mock_framework_minimal):
    """Create a C2DeployModule instance for testing."""
    from purplesploit.modules.deploy.c2 import C2DeployModule
    module = C2DeployModule(mock_framework_minimal)
    return module


@pytest.fixture
def configured_c2_module(c2_module):
    """Create a fully configured C2 module."""
    c2_module.set_option("RHOST", "192.168.1.100")
    c2_module.set_option("USERNAME", "admin")
    c2_module.set_option("PASSWORD", "password123")
    c2_module.set_option("LOCAL_FILE", "/path/to/beacon.exe")
    return c2_module


# =============================================================================
# Module Property Tests
# =============================================================================

class TestModuleProperties:
    """Tests for basic module properties."""

    def test_name(self, c2_module):
        """Test module name property."""
        assert c2_module.name == "C2 Beacon Deploy"

    def test_description(self, c2_module):
        """Test module description property."""
        assert "C2 beacons" in c2_module.description or "beacon" in c2_module.description.lower()

    def test_author(self, c2_module):
        """Test module author property."""
        assert c2_module.author == "PurpleSploit Team"

    def test_category(self, c2_module):
        """Test module category property."""
        assert c2_module.category == "deploy"


# =============================================================================
# Options Tests
# =============================================================================

class TestModuleOptions:
    """Tests for module options."""

    def test_default_options_exist(self, c2_module):
        """Test that required options are initialized."""
        options = c2_module.options
        assert "RHOST" in options
        assert "USERNAME" in options
        assert "PASSWORD" in options
        assert "LOCAL_FILE" in options
        assert "EXECUTE" in options
        assert "TARGET_OS" in options
        assert "BEACON_TYPE" in options

    def test_rhost_required(self, c2_module):
        """Test that RHOST is required."""
        assert c2_module.options["RHOST"]["required"] is True

    def test_local_file_required(self, c2_module):
        """Test that LOCAL_FILE is required."""
        assert c2_module.options["LOCAL_FILE"]["required"] is True

    def test_default_target_os(self, c2_module):
        """Test default TARGET_OS value."""
        assert c2_module.get_option("TARGET_OS") == "windows"

    def test_default_beacon_type(self, c2_module):
        """Test default BEACON_TYPE value."""
        assert c2_module.get_option("BEACON_TYPE") == "generic"


# =============================================================================
# Operations Tests
# =============================================================================

class TestOperations:
    """Tests for module operations."""

    def test_get_operations_returns_list(self, c2_module):
        """Test that get_operations returns a list."""
        ops = c2_module.get_operations()
        assert isinstance(ops, list)
        assert len(ops) >= 6  # NXC, SSH, SMB, PSExec, WMIExec, WinRM

    def test_operations_have_required_keys(self, c2_module):
        """Test that operations have required keys."""
        ops = c2_module.get_operations()
        for op in ops:
            assert "name" in op
            assert "description" in op
            assert "handler" in op

    def test_operations_include_all_methods(self, c2_module):
        """Test that all deployment methods are included."""
        ops = c2_module.get_operations()
        names = [op["name"] for op in ops]
        assert any("NXC" in name for name in names)
        assert any("SSH" in name for name in names)
        assert any("SMB" in name for name in names)
        assert any("PSExec" in name for name in names)
        assert any("WMI" in name for name in names)
        assert any("WinRM" in name for name in names)


# =============================================================================
# NXC Deployment Tests
# =============================================================================

class TestDeployViaNxc:
    """Tests for NXC deployment."""

    def test_missing_required_options(self, c2_module):
        """Test deployment without required options."""
        result = c2_module.deploy_via_nxc()
        assert result["success"] is False
        assert "Missing required" in result["error"]

    def test_missing_auth(self, c2_module):
        """Test deployment without authentication."""
        c2_module.set_option("RHOST", "192.168.1.100")
        c2_module.set_option("USERNAME", "admin")
        c2_module.set_option("LOCAL_FILE", "/path/to/beacon.exe")
        # No password or hash

        result = c2_module.deploy_via_nxc()
        assert result["success"] is False
        assert "PASSWORD or HASH" in result["error"]

    def test_successful_nxc_deployment(self, configured_c2_module):
        """Test successful NXC deployment."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="Upload successful\nBeacon executed",
                stderr=""
            )

            result = configured_c2_module.deploy_via_nxc()
            assert result["success"] is True
            assert result["method"] == "nxc"
            assert "remote_path" in result

    def test_nxc_deployment_with_hash(self, c2_module):
        """Test NXC deployment with NTLM hash."""
        c2_module.set_option("RHOST", "192.168.1.100")
        c2_module.set_option("USERNAME", "admin")
        c2_module.set_option("HASH", "aad3b435b51404ee:8846f7eaee8fb117")
        c2_module.set_option("LOCAL_FILE", "/path/to/beacon.exe")

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="OK", stderr="")
            result = c2_module.deploy_via_nxc()
            assert result["success"] is True

    def test_nxc_deployment_with_domain(self, configured_c2_module):
        """Test NXC deployment with domain."""
        configured_c2_module.set_option("DOMAIN", "TESTDOMAIN")

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="OK", stderr="")
            result = configured_c2_module.deploy_via_nxc()
            assert result["success"] is True

    def test_nxc_upload_failure(self, configured_c2_module):
        """Test handling of upload failure."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="Access denied"
            )

            result = configured_c2_module.deploy_via_nxc()
            assert result["success"] is False
            assert "Upload failed" in result["error"]

    def test_nxc_no_execute(self, configured_c2_module):
        """Test upload without execution."""
        configured_c2_module.set_option("EXECUTE", False)

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="OK", stderr="")
            result = configured_c2_module.deploy_via_nxc()
            assert result["success"] is True
            # Only upload called, not execute
            assert mock_run.call_count == 1


# =============================================================================
# SSH Deployment Tests
# =============================================================================

class TestDeployViaSsh:
    """Tests for SSH deployment."""

    def test_missing_required_options(self, c2_module):
        """Test SSH deployment without required options."""
        result = c2_module.deploy_via_ssh()
        assert result["success"] is False

    def test_successful_ssh_deployment_with_password(self, c2_module):
        """Test successful SSH deployment with password."""
        c2_module.set_option("RHOST", "192.168.1.100")
        c2_module.set_option("USERNAME", "root")
        c2_module.set_option("PASSWORD", "toor")
        c2_module.set_option("LOCAL_FILE", "/path/to/beacon")

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="OK", stderr="")
            result = c2_module.deploy_via_ssh()
            assert result["success"] is True
            assert result["method"] == "ssh"

    def test_ssh_deployment_with_key(self, c2_module):
        """Test SSH deployment with SSH key."""
        c2_module.set_option("RHOST", "192.168.1.100")
        c2_module.set_option("USERNAME", "root")
        c2_module.set_option("SSH_KEY", "/path/to/id_rsa")
        c2_module.set_option("LOCAL_FILE", "/path/to/beacon")

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="OK", stderr="")
            result = c2_module.deploy_via_ssh()
            assert result["success"] is True

    def test_ssh_upload_failure(self, c2_module):
        """Test handling of SSH upload failure."""
        c2_module.set_option("RHOST", "192.168.1.100")
        c2_module.set_option("USERNAME", "root")
        c2_module.set_option("PASSWORD", "toor")
        c2_module.set_option("LOCAL_FILE", "/path/to/beacon")

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="Connection refused"
            )

            result = c2_module.deploy_via_ssh()
            assert result["success"] is False

    def test_ssh_no_execute(self, c2_module):
        """Test SSH upload without execution."""
        c2_module.set_option("RHOST", "192.168.1.100")
        c2_module.set_option("USERNAME", "root")
        c2_module.set_option("PASSWORD", "toor")
        c2_module.set_option("LOCAL_FILE", "/path/to/beacon")
        c2_module.set_option("EXECUTE", False)

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = c2_module.deploy_via_ssh()
            assert result["success"] is True


# =============================================================================
# SMB Deployment Tests
# =============================================================================

class TestDeployViaSmb:
    """Tests for SMB deployment."""

    def test_missing_required_options(self, c2_module):
        """Test SMB deployment without required options."""
        result = c2_module.deploy_via_smb()
        assert result["success"] is False

    def test_successful_smb_deployment(self, configured_c2_module):
        """Test successful SMB deployment."""
        with patch.object(configured_c2_module, '_upload_via_smb') as mock_upload:
            with patch.object(configured_c2_module, '_execute_via_wmi') as mock_exec:
                mock_upload.return_value = {
                    "success": True,
                    "remote_path": "C:\\Windows\\Temp\\beacon.exe"
                }
                mock_exec.return_value = {
                    "success": True,
                    "output": "Beacon executed"
                }

                result = configured_c2_module.deploy_via_smb()
                assert result["success"] is True

    def test_smb_upload_failure(self, configured_c2_module):
        """Test SMB upload failure handling."""
        with patch.object(configured_c2_module, '_upload_via_smb') as mock_upload:
            mock_upload.return_value = {
                "success": False,
                "error": "Access denied"
            }

            result = configured_c2_module.deploy_via_smb()
            assert result["success"] is False

    def test_smb_no_execute(self, configured_c2_module):
        """Test SMB upload without execution."""
        configured_c2_module.set_option("EXECUTE", False)

        with patch.object(configured_c2_module, '_upload_via_smb') as mock_upload:
            mock_upload.return_value = {
                "success": True,
                "remote_path": "C:\\Windows\\Temp\\beacon.exe"
            }

            result = configured_c2_module.deploy_via_smb()
            assert result["success"] is True
            assert "not executed" in result["output"]


# =============================================================================
# PSExec Deployment Tests
# =============================================================================

class TestDeployViaPsexec:
    """Tests for PSExec deployment."""

    def test_missing_required_options(self, c2_module):
        """Test PSExec deployment without required options."""
        result = c2_module.deploy_via_psexec()
        assert result["success"] is False

    def test_missing_auth(self, c2_module):
        """Test PSExec without authentication."""
        c2_module.set_option("RHOST", "192.168.1.100")
        c2_module.set_option("USERNAME", "admin")
        c2_module.set_option("LOCAL_FILE", "/path/to/beacon.exe")

        result = c2_module.deploy_via_psexec()
        assert result["success"] is False
        assert "PASSWORD or HASH" in result["error"]

    def test_successful_psexec_deployment(self, configured_c2_module):
        """Test successful PSExec deployment."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="Impacket v0.10\nBeacon deployed",
                stderr=""
            )

            result = configured_c2_module.deploy_via_psexec()
            assert result["success"] is True
            assert result["method"] == "psexec"

    def test_psexec_with_hash(self, c2_module):
        """Test PSExec with NTLM hash."""
        c2_module.set_option("RHOST", "192.168.1.100")
        c2_module.set_option("USERNAME", "admin")
        c2_module.set_option("HASH", "aad3b435b51404ee:8846f7eaee8fb117")
        c2_module.set_option("LOCAL_FILE", "/path/to/beacon.exe")

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="Impacket",
                stderr=""
            )

            result = c2_module.deploy_via_psexec()
            assert result["success"] is True

    def test_psexec_failure(self, configured_c2_module):
        """Test PSExec failure handling."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="Access denied"
            )

            result = configured_c2_module.deploy_via_psexec()
            assert result["success"] is False


# =============================================================================
# WMIExec Deployment Tests
# =============================================================================

class TestDeployViaWmiexec:
    """Tests for WMIExec deployment."""

    def test_missing_required_options(self, c2_module):
        """Test WMIExec deployment without required options."""
        result = c2_module.deploy_via_wmiexec()
        assert result["success"] is False

    def test_successful_wmiexec_deployment(self, configured_c2_module):
        """Test successful WMIExec deployment."""
        with patch.object(configured_c2_module, '_upload_via_smb') as mock_upload:
            with patch.object(configured_c2_module, '_execute_via_wmi') as mock_exec:
                mock_upload.return_value = {
                    "success": True,
                    "remote_path": "C:\\Windows\\Temp\\beacon.exe"
                }
                mock_exec.return_value = {
                    "success": True,
                    "output": "Beacon executed"
                }

                result = configured_c2_module.deploy_via_wmiexec()
                assert result["success"] is True

    def test_wmiexec_upload_failure(self, configured_c2_module):
        """Test WMIExec upload failure."""
        with patch.object(configured_c2_module, '_upload_via_smb') as mock_upload:
            mock_upload.return_value = {
                "success": False,
                "error": "SMB error"
            }

            result = configured_c2_module.deploy_via_wmiexec()
            assert result["success"] is False


# =============================================================================
# WinRM Deployment Tests
# =============================================================================

class TestDeployViaWinrm:
    """Tests for WinRM deployment."""

    def test_missing_required_options(self, c2_module):
        """Test WinRM deployment without required options."""
        result = c2_module.deploy_via_winrm()
        assert result["success"] is False

    def test_winrm_not_implemented(self, configured_c2_module):
        """Test WinRM returns not implemented message."""
        result = configured_c2_module.deploy_via_winrm()
        assert result["success"] is False
        assert "requires manual" in result["error"].lower() or "hosting" in result["error"].lower()


# =============================================================================
# Helper Method Tests
# =============================================================================

class TestHelperMethods:
    """Tests for helper methods."""

    def test_upload_via_smb_success(self, configured_c2_module):
        """Test successful SMB upload."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            result = configured_c2_module._upload_via_smb(
                "192.168.1.100", "admin", "password", "",
                "/path/to/file.exe", "file.exe"
            )
            assert result["success"] is True
            assert "remote_path" in result
            assert result["method"] == "smb"

    def test_upload_via_smb_failure(self, configured_c2_module):
        """Test failed SMB upload."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="NT_STATUS_ACCESS_DENIED"
            )

            result = configured_c2_module._upload_via_smb(
                "192.168.1.100", "admin", "password", "",
                "/path/to/file.exe", "file.exe"
            )
            assert result["success"] is False

    def test_upload_via_smb_with_domain(self, configured_c2_module):
        """Test SMB upload with domain."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            result = configured_c2_module._upload_via_smb(
                "192.168.1.100", "admin", "password", "TESTDOMAIN",
                "/path/to/file.exe", "file.exe"
            )
            assert result["success"] is True

    def test_execute_via_wmi_success(self, configured_c2_module):
        """Test successful WMI execution."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="Impacket v0.10",
                stderr=""
            )

            result = configured_c2_module._execute_via_wmi(
                "192.168.1.100", "admin", "password", "",
                None, "C:\\Windows\\Temp\\beacon.exe", ""
            )
            assert result["success"] is True
            assert result["method"] == "wmiexec"

    def test_execute_via_wmi_with_hash(self, configured_c2_module):
        """Test WMI execution with hash."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="Impacket",
                stderr=""
            )

            result = configured_c2_module._execute_via_wmi(
                "192.168.1.100", "admin", None, "",
                "aad3b435b51404ee:8846f7eaee8fb117",
                "C:\\Windows\\Temp\\beacon.exe", ""
            )
            assert result["success"] is True

    def test_execute_via_wmi_no_auth(self, configured_c2_module):
        """Test WMI execution without auth."""
        result = configured_c2_module._execute_via_wmi(
            "192.168.1.100", "admin", None, "",
            None, "C:\\Windows\\Temp\\beacon.exe", ""
        )
        assert result["success"] is False

    def test_execute_via_wmi_failure(self, configured_c2_module):
        """Test failed WMI execution."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="RPC connection failed"
            )

            result = configured_c2_module._execute_via_wmi(
                "192.168.1.100", "admin", "password", "",
                None, "C:\\Windows\\Temp\\beacon.exe", ""
            )
            assert result["success"] is False


# =============================================================================
# Run Method Tests
# =============================================================================

class TestRunMethod:
    """Tests for the run method."""

    def test_run_returns_success(self, c2_module):
        """Test that run returns success with message."""
        result = c2_module.run()
        assert result["success"] is True
        assert "message" in result


# =============================================================================
# Exception Handling Tests
# =============================================================================

class TestExceptionHandling:
    """Tests for exception handling."""

    def test_nxc_exception_handling(self, configured_c2_module):
        """Test exception handling in NXC deployment."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = Exception("Network error")

            result = configured_c2_module.deploy_via_nxc()
            assert result["success"] is False
            assert "failed" in result["error"].lower()

    def test_ssh_exception_handling(self, c2_module):
        """Test exception handling in SSH deployment."""
        c2_module.set_option("RHOST", "192.168.1.100")
        c2_module.set_option("USERNAME", "root")
        c2_module.set_option("PASSWORD", "toor")
        c2_module.set_option("LOCAL_FILE", "/path/to/beacon")

        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("cmd", 60)

            result = c2_module.deploy_via_ssh()
            assert result["success"] is False

    def test_smb_exception_handling(self, configured_c2_module):
        """Test exception handling in SMB deployment."""
        with patch.object(configured_c2_module, '_upload_via_smb') as mock_upload:
            mock_upload.side_effect = Exception("SMB error")

            result = configured_c2_module.deploy_via_smb()
            assert result["success"] is False

    def test_psexec_exception_handling(self, configured_c2_module):
        """Test exception handling in PSExec deployment."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = Exception("Impacket error")

            result = configured_c2_module.deploy_via_psexec()
            assert result["success"] is False

    def test_wmiexec_exception_handling(self, configured_c2_module):
        """Test exception handling in WMIExec deployment."""
        with patch.object(configured_c2_module, '_upload_via_smb') as mock_upload:
            mock_upload.side_effect = Exception("WMI error")

            result = configured_c2_module.deploy_via_wmiexec()
            assert result["success"] is False
