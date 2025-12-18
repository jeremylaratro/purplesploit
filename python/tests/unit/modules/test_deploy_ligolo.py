"""
Tests for the Ligolo Pivot Deployment Module.

Tests Ligolo-ng agent deployment via various methods (NXC, SSH, SMB, PSExec, WMIExec).
"""

import pytest
from unittest.mock import MagicMock, patch
import subprocess
from typing import Dict, Any


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def ligolo_module(mock_framework_minimal):
    """Create a LigoloDeployModule instance for testing."""
    from purplesploit.modules.deploy.ligolo import LigoloDeployModule
    module = LigoloDeployModule(mock_framework_minimal)
    return module


@pytest.fixture
def configured_ligolo_module(ligolo_module):
    """Create a fully configured Ligolo module."""
    ligolo_module.set_option("RHOST", "192.168.1.100")
    ligolo_module.set_option("USERNAME", "admin")
    ligolo_module.set_option("PASSWORD", "password123")
    ligolo_module.set_option("LOCAL_FILE", "/path/to/ligolo-agent.exe")
    return ligolo_module


# =============================================================================
# Module Property Tests
# =============================================================================

class TestModuleProperties:
    """Tests for basic module properties."""

    def test_name(self, ligolo_module):
        """Test module name property."""
        assert ligolo_module.name == "Ligolo Pivot Deploy"

    def test_description(self, ligolo_module):
        """Test module description property."""
        assert "ligolo" in ligolo_module.description.lower()
        assert "pivot" in ligolo_module.description.lower()

    def test_author(self, ligolo_module):
        """Test module author property."""
        assert ligolo_module.author == "PurpleSploit Team"

    def test_category(self, ligolo_module):
        """Test module category property."""
        assert ligolo_module.category == "deploy"


# =============================================================================
# Options Tests
# =============================================================================

class TestModuleOptions:
    """Tests for module options."""

    def test_default_options_exist(self, ligolo_module):
        """Test that required options are initialized."""
        options = ligolo_module.options
        assert "RHOST" in options
        assert "USERNAME" in options
        assert "PASSWORD" in options
        assert "LOCAL_FILE" in options
        assert "LIGOLO_SERVER" in options
        assert "TARGET_OS" in options

    def test_rhost_required(self, ligolo_module):
        """Test that RHOST is required."""
        assert ligolo_module.options["RHOST"]["required"] is True

    def test_local_file_required(self, ligolo_module):
        """Test that LOCAL_FILE is required."""
        assert ligolo_module.options["LOCAL_FILE"]["required"] is True

    def test_default_ligolo_server(self, ligolo_module):
        """Test default LIGOLO_SERVER value."""
        assert ligolo_module.get_option("LIGOLO_SERVER") == "127.0.0.1:11601"

    def test_default_target_os(self, ligolo_module):
        """Test default TARGET_OS value."""
        assert ligolo_module.get_option("TARGET_OS") == "windows"


# =============================================================================
# Operations Tests
# =============================================================================

class TestOperations:
    """Tests for module operations."""

    def test_get_operations_returns_list(self, ligolo_module):
        """Test that get_operations returns a list."""
        ops = ligolo_module.get_operations()
        assert isinstance(ops, list)
        assert len(ops) >= 5  # NXC, SSH, SMB, PSExec, WMIExec

    def test_operations_have_required_keys(self, ligolo_module):
        """Test that operations have required keys."""
        ops = ligolo_module.get_operations()
        for op in ops:
            assert "name" in op
            assert "description" in op
            assert "handler" in op

    def test_operations_include_all_methods(self, ligolo_module):
        """Test that all deployment methods are included."""
        ops = ligolo_module.get_operations()
        names = [op["name"] for op in ops]
        assert any("NXC" in name for name in names)
        assert any("SSH" in name for name in names)
        assert any("SMB" in name for name in names)
        assert any("PSExec" in name for name in names)
        assert any("WMI" in name for name in names)


# =============================================================================
# NXC Deployment Tests
# =============================================================================

class TestDeployViaNxc:
    """Tests for NXC deployment."""

    def test_missing_required_options(self, ligolo_module):
        """Test deployment without required options."""
        result = ligolo_module.deploy_via_nxc()
        assert result["success"] is False
        assert "Missing required" in result["error"]

    def test_missing_auth(self, ligolo_module):
        """Test deployment without authentication."""
        ligolo_module.set_option("RHOST", "192.168.1.100")
        ligolo_module.set_option("USERNAME", "admin")
        ligolo_module.set_option("LOCAL_FILE", "/path/to/agent.exe")

        result = ligolo_module.deploy_via_nxc()
        assert result["success"] is False
        assert "PASSWORD or HASH" in result["error"]

    def test_successful_nxc_deployment(self, configured_ligolo_module):
        """Test successful NXC deployment."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="Upload successful\nAgent started",
                stderr=""
            )

            result = configured_ligolo_module.deploy_via_nxc()
            assert result["success"] is True
            assert result["method"] == "nxc"
            assert "remote_path" in result

    def test_nxc_deployment_with_hash(self, ligolo_module):
        """Test NXC deployment with NTLM hash."""
        ligolo_module.set_option("RHOST", "192.168.1.100")
        ligolo_module.set_option("USERNAME", "admin")
        ligolo_module.set_option("HASH", "aad3b435b51404ee:8846f7eaee8fb117")
        ligolo_module.set_option("LOCAL_FILE", "/path/to/agent.exe")

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="OK", stderr="")
            result = ligolo_module.deploy_via_nxc()
            assert result["success"] is True

    def test_nxc_deployment_with_domain(self, configured_ligolo_module):
        """Test NXC deployment with domain."""
        configured_ligolo_module.set_option("DOMAIN", "TESTDOMAIN")

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="OK", stderr="")
            result = configured_ligolo_module.deploy_via_nxc()
            assert result["success"] is True

    def test_nxc_upload_failure(self, configured_ligolo_module):
        """Test handling of upload failure."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="Connection refused"
            )

            result = configured_ligolo_module.deploy_via_nxc()
            assert result["success"] is False
            assert "Upload failed" in result["error"]

    def test_nxc_custom_ligolo_server(self, configured_ligolo_module):
        """Test deployment with custom Ligolo server."""
        configured_ligolo_module.set_option("LIGOLO_SERVER", "10.0.0.1:8443")

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="OK", stderr="")
            result = configured_ligolo_module.deploy_via_nxc()
            assert result["success"] is True
            # Verify custom server was used in command
            calls = mock_run.call_args_list
            assert any("10.0.0.1:8443" in str(call) for call in calls)


# =============================================================================
# SSH Deployment Tests
# =============================================================================

class TestDeployViaSsh:
    """Tests for SSH deployment."""

    def test_missing_required_options(self, ligolo_module):
        """Test SSH deployment without required options."""
        result = ligolo_module.deploy_via_ssh()
        assert result["success"] is False

    def test_successful_ssh_deployment_with_password(self, ligolo_module):
        """Test successful SSH deployment with password."""
        ligolo_module.set_option("RHOST", "192.168.1.100")
        ligolo_module.set_option("USERNAME", "root")
        ligolo_module.set_option("PASSWORD", "toor")
        ligolo_module.set_option("LOCAL_FILE", "/path/to/agent")

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="OK", stderr="")
            result = ligolo_module.deploy_via_ssh()
            assert result["success"] is True
            assert result["method"] == "ssh"
            assert "/tmp/ligolo-agent" in result["remote_path"]

    def test_ssh_deployment_with_key(self, ligolo_module):
        """Test SSH deployment with SSH key."""
        ligolo_module.set_option("RHOST", "192.168.1.100")
        ligolo_module.set_option("USERNAME", "root")
        ligolo_module.set_option("SSH_KEY", "/path/to/id_rsa")
        ligolo_module.set_option("LOCAL_FILE", "/path/to/agent")

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="OK", stderr="")
            result = ligolo_module.deploy_via_ssh()
            assert result["success"] is True

    def test_ssh_upload_failure(self, ligolo_module):
        """Test handling of SSH upload failure."""
        ligolo_module.set_option("RHOST", "192.168.1.100")
        ligolo_module.set_option("USERNAME", "root")
        ligolo_module.set_option("PASSWORD", "toor")
        ligolo_module.set_option("LOCAL_FILE", "/path/to/agent")

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="Connection refused"
            )

            result = ligolo_module.deploy_via_ssh()
            assert result["success"] is False
            assert "Upload failed" in result["error"]


# =============================================================================
# SMB Deployment Tests
# =============================================================================

class TestDeployViaSmb:
    """Tests for SMB deployment."""

    def test_missing_required_options(self, ligolo_module):
        """Test SMB deployment without required options."""
        result = ligolo_module.deploy_via_smb()
        assert result["success"] is False

    def test_successful_smb_deployment(self, configured_ligolo_module):
        """Test successful SMB deployment."""
        with patch.object(configured_ligolo_module, '_upload_via_smb') as mock_upload:
            with patch.object(configured_ligolo_module, '_execute_via_wmi') as mock_exec:
                mock_upload.return_value = {
                    "success": True,
                    "remote_path": "C:\\Windows\\Temp\\ligolo-agent.exe"
                }
                mock_exec.return_value = {
                    "success": True,
                    "output": "Agent started"
                }

                result = configured_ligolo_module.deploy_via_smb()
                assert result["success"] is True

    def test_smb_upload_failure(self, configured_ligolo_module):
        """Test SMB upload failure handling."""
        with patch.object(configured_ligolo_module, '_upload_via_smb') as mock_upload:
            mock_upload.return_value = {
                "success": False,
                "error": "Access denied"
            }

            result = configured_ligolo_module.deploy_via_smb()
            assert result["success"] is False


# =============================================================================
# PSExec Deployment Tests
# =============================================================================

class TestDeployViaPsexec:
    """Tests for PSExec deployment."""

    def test_missing_required_options(self, ligolo_module):
        """Test PSExec deployment without required options."""
        result = ligolo_module.deploy_via_psexec()
        assert result["success"] is False

    def test_missing_auth(self, ligolo_module):
        """Test PSExec without authentication."""
        ligolo_module.set_option("RHOST", "192.168.1.100")
        ligolo_module.set_option("USERNAME", "admin")
        ligolo_module.set_option("LOCAL_FILE", "/path/to/agent.exe")

        result = ligolo_module.deploy_via_psexec()
        assert result["success"] is False
        assert "PASSWORD or HASH" in result["error"]

    def test_successful_psexec_deployment(self, configured_ligolo_module):
        """Test successful PSExec deployment."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="Impacket v0.10\nAgent deployed",
                stderr=""
            )

            result = configured_ligolo_module.deploy_via_psexec()
            assert result["success"] is True
            assert result["method"] == "psexec"

    def test_psexec_with_hash(self, ligolo_module):
        """Test PSExec with NTLM hash."""
        ligolo_module.set_option("RHOST", "192.168.1.100")
        ligolo_module.set_option("USERNAME", "admin")
        ligolo_module.set_option("HASH", "aad3b435b51404ee:8846f7eaee8fb117")
        ligolo_module.set_option("LOCAL_FILE", "/path/to/agent.exe")

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="Impacket",
                stderr=""
            )

            result = ligolo_module.deploy_via_psexec()
            assert result["success"] is True

    def test_psexec_failure(self, configured_ligolo_module):
        """Test PSExec failure handling."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="Access denied"
            )

            result = configured_ligolo_module.deploy_via_psexec()
            assert result["success"] is False


# =============================================================================
# WMIExec Deployment Tests
# =============================================================================

class TestDeployViaWmiexec:
    """Tests for WMIExec deployment."""

    def test_missing_required_options(self, ligolo_module):
        """Test WMIExec deployment without required options."""
        result = ligolo_module.deploy_via_wmiexec()
        assert result["success"] is False

    def test_successful_wmiexec_deployment(self, configured_ligolo_module):
        """Test successful WMIExec deployment."""
        with patch.object(configured_ligolo_module, '_upload_via_smb') as mock_upload:
            with patch.object(configured_ligolo_module, '_execute_via_wmi') as mock_exec:
                mock_upload.return_value = {
                    "success": True,
                    "remote_path": "C:\\Windows\\Temp\\ligolo-agent.exe"
                }
                mock_exec.return_value = {
                    "success": True,
                    "output": "Agent started"
                }

                result = configured_ligolo_module.deploy_via_wmiexec()
                assert result["success"] is True

    def test_wmiexec_upload_failure(self, configured_ligolo_module):
        """Test WMIExec upload failure."""
        with patch.object(configured_ligolo_module, '_upload_via_smb') as mock_upload:
            mock_upload.return_value = {
                "success": False,
                "error": "SMB error"
            }

            result = configured_ligolo_module.deploy_via_wmiexec()
            assert result["success"] is False


# =============================================================================
# Helper Method Tests
# =============================================================================

class TestHelperMethods:
    """Tests for helper methods."""

    def test_upload_via_smb_success(self, configured_ligolo_module):
        """Test successful SMB upload."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            result = configured_ligolo_module._upload_via_smb(
                "192.168.1.100", "admin", "password", "",
                "/path/to/agent.exe", "ligolo-agent.exe"
            )
            assert result["success"] is True
            assert "remote_path" in result
            assert result["method"] == "smb"

    def test_upload_via_smb_failure(self, configured_ligolo_module):
        """Test failed SMB upload."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="NT_STATUS_ACCESS_DENIED"
            )

            result = configured_ligolo_module._upload_via_smb(
                "192.168.1.100", "admin", "password", "",
                "/path/to/agent.exe", "ligolo-agent.exe"
            )
            assert result["success"] is False

    def test_execute_via_wmi_success(self, configured_ligolo_module):
        """Test successful WMI execution."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="Impacket v0.10",
                stderr=""
            )

            result = configured_ligolo_module._execute_via_wmi(
                "192.168.1.100", "admin", "password", "",
                None, "C:\\Windows\\Temp\\agent.exe", "-connect 127.0.0.1:11601"
            )
            assert result["success"] is True
            assert result["method"] == "wmiexec"

    def test_execute_via_wmi_with_hash(self, configured_ligolo_module):
        """Test WMI execution with hash."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="Impacket",
                stderr=""
            )

            result = configured_ligolo_module._execute_via_wmi(
                "192.168.1.100", "admin", None, "",
                "aad3b435b51404ee:8846f7eaee8fb117",
                "C:\\Windows\\Temp\\agent.exe", ""
            )
            assert result["success"] is True

    def test_execute_via_wmi_no_auth(self, configured_ligolo_module):
        """Test WMI execution without auth."""
        result = configured_ligolo_module._execute_via_wmi(
            "192.168.1.100", "admin", None, "",
            None, "C:\\Windows\\Temp\\agent.exe", ""
        )
        assert result["success"] is False


# =============================================================================
# Run Method Tests
# =============================================================================

class TestRunMethod:
    """Tests for the run method."""

    def test_run_returns_success(self, ligolo_module):
        """Test that run returns success with message."""
        result = ligolo_module.run()
        assert result["success"] is True
        assert "message" in result


# =============================================================================
# Exception Handling Tests
# =============================================================================

class TestExceptionHandling:
    """Tests for exception handling."""

    def test_nxc_exception_handling(self, configured_ligolo_module):
        """Test exception handling in NXC deployment."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = Exception("Network error")

            result = configured_ligolo_module.deploy_via_nxc()
            assert result["success"] is False
            assert "failed" in result["error"].lower()

    def test_ssh_exception_handling(self, ligolo_module):
        """Test exception handling in SSH deployment."""
        ligolo_module.set_option("RHOST", "192.168.1.100")
        ligolo_module.set_option("USERNAME", "root")
        ligolo_module.set_option("PASSWORD", "toor")
        ligolo_module.set_option("LOCAL_FILE", "/path/to/agent")

        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("cmd", 60)

            result = ligolo_module.deploy_via_ssh()
            assert result["success"] is False

    def test_smb_exception_handling(self, configured_ligolo_module):
        """Test exception handling in SMB deployment."""
        with patch.object(configured_ligolo_module, '_upload_via_smb') as mock_upload:
            mock_upload.side_effect = Exception("SMB error")

            result = configured_ligolo_module.deploy_via_smb()
            assert result["success"] is False

    def test_psexec_exception_handling(self, configured_ligolo_module):
        """Test exception handling in PSExec deployment."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = Exception("Impacket error")

            result = configured_ligolo_module.deploy_via_psexec()
            assert result["success"] is False

    def test_wmiexec_exception_handling(self, configured_ligolo_module):
        """Test exception handling in WMIExec deployment."""
        with patch.object(configured_ligolo_module, '_upload_via_smb') as mock_upload:
            mock_upload.side_effect = Exception("WMI error")

            result = configured_ligolo_module.deploy_via_wmiexec()
            assert result["success"] is False
