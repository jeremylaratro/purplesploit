"""
Tests for the SMB Shares Module.

Tests SMB share browsing and file operations including spider, download, and upload.
"""

import pytest
from unittest.mock import MagicMock, patch
from typing import Dict, Any


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def smb_shares_module(mock_framework_minimal):
    """Create a SMBSharesModule instance for testing."""
    from purplesploit.modules.smb.shares import SMBSharesModule
    module = SMBSharesModule(mock_framework_minimal)
    return module


@pytest.fixture
def configured_smb_module(smb_shares_module):
    """Create a fully configured SMB shares module."""
    smb_shares_module.set_option("RHOST", "192.168.1.100")
    smb_shares_module.set_option("USERNAME", "admin")
    smb_shares_module.set_option("PASSWORD", "password123")
    return smb_shares_module


# =============================================================================
# Module Property Tests
# =============================================================================

class TestModuleProperties:
    """Tests for basic module properties."""

    def test_name(self, smb_shares_module):
        """Test module name property."""
        assert smb_shares_module.name == "SMB Shares"

    def test_description(self, smb_shares_module):
        """Test module description property."""
        assert "SMB" in smb_shares_module.description
        assert "share" in smb_shares_module.description.lower()

    def test_author(self, smb_shares_module):
        """Test module author property."""
        assert smb_shares_module.author == "PurpleSploit Team"

    def test_category(self, smb_shares_module):
        """Test module category property."""
        assert smb_shares_module.category == "smb"

    def test_tool_name(self, smb_shares_module):
        """Test tool name attribute."""
        assert smb_shares_module.tool_name == "nxc"


# =============================================================================
# Options Tests
# =============================================================================

class TestModuleOptions:
    """Tests for module options."""

    def test_default_options_exist(self, smb_shares_module):
        """Test that required options are initialized."""
        options = smb_shares_module.options
        assert "RHOST" in options
        assert "USERNAME" in options
        assert "PASSWORD" in options
        assert "DOMAIN" in options

    def test_rhost_required(self, smb_shares_module):
        """Test that RHOST is required."""
        assert smb_shares_module.options["RHOST"]["required"] is True

    def test_username_not_required(self, smb_shares_module):
        """Test that USERNAME is not required."""
        assert smb_shares_module.options["USERNAME"]["required"] is False

    def test_default_domain(self, smb_shares_module):
        """Test default DOMAIN value."""
        # Default is WORKGROUP for SMB
        assert smb_shares_module.options["DOMAIN"]["default"] == "WORKGROUP"


# =============================================================================
# Operations Tests
# =============================================================================

class TestOperations:
    """Tests for module operations."""

    def test_get_operations_returns_list(self, smb_shares_module):
        """Test that get_operations returns a list."""
        ops = smb_shares_module.get_operations()
        assert isinstance(ops, list)
        assert len(ops) >= 7  # Multiple share operations

    def test_operations_have_required_keys(self, smb_shares_module):
        """Test that operations have required keys."""
        ops = smb_shares_module.get_operations()
        for op in ops:
            assert "name" in op
            assert "description" in op
            assert "handler" in op

    def test_operations_include_browse(self, smb_shares_module):
        """Test that browse operation is included."""
        ops = smb_shares_module.get_operations()
        names = [op["name"] for op in ops]
        assert any("Browse" in name for name in names)

    def test_operations_include_download(self, smb_shares_module):
        """Test that download operation is included."""
        ops = smb_shares_module.get_operations()
        names = [op["name"] for op in ops]
        assert any("Download" in name for name in names)

    def test_operations_include_upload(self, smb_shares_module):
        """Test that upload operation is included."""
        ops = smb_shares_module.get_operations()
        names = [op["name"] for op in ops]
        assert any("Upload" in name for name in names)

    def test_operations_include_spider(self, smb_shares_module):
        """Test that spider operation is included."""
        ops = smb_shares_module.get_operations()
        names = [op["name"] for op in ops]
        assert any("Spider" in name for name in names)


# =============================================================================
# Authentication Tests
# =============================================================================

class TestBuildAuth:
    """Tests for authentication string building."""

    def test_build_auth_with_username_password(self, smb_shares_module):
        """Test auth string with username and password."""
        smb_shares_module.set_option("USERNAME", "admin")
        smb_shares_module.set_option("PASSWORD", "secret")

        auth = smb_shares_module._build_auth()
        assert "-u 'admin'" in auth
        assert "-p 'secret'" in auth

    def test_build_auth_with_username_only(self, smb_shares_module):
        """Test auth string with username only."""
        smb_shares_module.set_option("USERNAME", "admin")
        smb_shares_module.set_option("PASSWORD", None)

        auth = smb_shares_module._build_auth()
        assert "-u 'admin'" in auth
        assert "-p ''" in auth

    def test_build_auth_no_username(self, smb_shares_module):
        """Test auth string without username."""
        smb_shares_module.set_option("USERNAME", None)

        auth = smb_shares_module._build_auth()
        assert auth == ""


# =============================================================================
# Execute NXC Tests
# =============================================================================

class TestExecuteNxc:
    """Tests for NXC command execution."""

    def test_execute_nxc_basic(self, configured_smb_module):
        """Test basic NXC execution."""
        with patch.object(configured_smb_module, 'execute_command') as mock_exec:
            mock_exec.return_value = {"success": True, "output": "result"}

            result = configured_smb_module._execute_nxc()

            mock_exec.assert_called_once()
            call_args = mock_exec.call_args[0][0]
            assert "nxc smb 192.168.1.100" in call_args
            assert "-u 'admin'" in call_args
            assert "-p 'password123'" in call_args

    def test_execute_nxc_with_domain(self, configured_smb_module):
        """Test NXC execution with domain."""
        configured_smb_module.set_option("DOMAIN", "TESTDOMAIN")

        with patch.object(configured_smb_module, 'execute_command') as mock_exec:
            mock_exec.return_value = {"success": True, "output": "result"}

            configured_smb_module._execute_nxc()

            call_args = mock_exec.call_args[0][0]
            assert "-d TESTDOMAIN" in call_args

    def test_execute_nxc_with_extra_args(self, configured_smb_module):
        """Test NXC execution with extra arguments."""
        with patch.object(configured_smb_module, 'execute_command') as mock_exec:
            mock_exec.return_value = {"success": True, "output": "result"}

            configured_smb_module._execute_nxc("--shares")

            call_args = mock_exec.call_args[0][0]
            assert "--shares" in call_args

    def test_execute_nxc_workgroup_domain_ignored(self, configured_smb_module):
        """Test that WORKGROUP domain is not added to command."""
        configured_smb_module.set_option("DOMAIN", "WORKGROUP")

        with patch.object(configured_smb_module, 'execute_command') as mock_exec:
            mock_exec.return_value = {"success": True, "output": "result"}

            configured_smb_module._execute_nxc()

            call_args = mock_exec.call_args[0][0]
            assert "-d WORKGROUP" not in call_args


# =============================================================================
# Browse Download Operation Tests
# =============================================================================

class TestOpBrowseDownload:
    """Tests for browse and download operation."""

    def test_browse_download_with_share(self, configured_smb_module):
        """Test browse download with specific share."""
        with patch('builtins.input', side_effect=["SYSVOL", ""]):
            with patch.object(configured_smb_module, '_execute_nxc') as mock_exec:
                mock_exec.return_value = {"success": True, "output": "files"}

                result = configured_smb_module.op_browse_download()

                call_args = mock_exec.call_args[0][0]
                assert "spider_plus" in call_args
                assert "SYSVOL" in call_args

    def test_browse_download_with_pattern(self, configured_smb_module):
        """Test browse download with file pattern."""
        with patch('builtins.input', side_effect=["", "*.xlsx"]):
            with patch.object(configured_smb_module, '_execute_nxc') as mock_exec:
                mock_exec.return_value = {"success": True, "output": "files"}

                result = configured_smb_module.op_browse_download()

                call_args = mock_exec.call_args[0][0]
                assert "*.xlsx" in call_args

    def test_browse_download_default(self, configured_smb_module):
        """Test browse download with defaults."""
        with patch('builtins.input', side_effect=["", ""]):
            with patch.object(configured_smb_module, '_execute_nxc') as mock_exec:
                mock_exec.return_value = {"success": True, "output": "files"}

                result = configured_smb_module.op_browse_download()

                call_args = mock_exec.call_args[0][0]
                assert "spider_plus" in call_args
                assert "DOWNLOAD_FLAG=True" in call_args


# =============================================================================
# Download All Operation Tests
# =============================================================================

class TestOpDownloadAll:
    """Tests for download all operation."""

    def test_download_all_confirmed(self, configured_smb_module):
        """Test download all with confirmation."""
        with patch('builtins.input', return_value="y"):
            with patch.object(configured_smb_module, '_execute_nxc') as mock_exec:
                mock_exec.return_value = {"success": True, "output": "files"}

                result = configured_smb_module.op_download_all()

                mock_exec.assert_called_once()
                assert result["success"] is True

    def test_download_all_cancelled(self, configured_smb_module):
        """Test download all cancelled."""
        with patch('builtins.input', return_value="n"):
            result = configured_smb_module.op_download_all()

            assert result["success"] is False
            assert "cancelled" in result["error"].lower()


# =============================================================================
# Download Pattern Operation Tests
# =============================================================================

class TestOpDownloadPattern:
    """Tests for download by pattern operation."""

    def test_download_pattern_success(self, configured_smb_module):
        """Test download with pattern."""
        with patch('builtins.input', return_value="*.xlsx"):
            with patch.object(configured_smb_module, '_execute_nxc') as mock_exec:
                mock_exec.return_value = {"success": True, "output": "files"}

                result = configured_smb_module.op_download_pattern()

                call_args = mock_exec.call_args[0][0]
                assert "PATTERN='*.xlsx'" in call_args

    def test_download_pattern_empty(self, configured_smb_module):
        """Test download with empty pattern."""
        with patch('builtins.input', return_value=""):
            result = configured_smb_module.op_download_pattern()

            assert result["success"] is False
            assert "Pattern required" in result["error"]


# =============================================================================
# Spider Only Operation Tests
# =============================================================================

class TestOpSpiderOnly:
    """Tests for spider only operation."""

    def test_spider_only_basic(self, configured_smb_module):
        """Test spider only without filters."""
        with patch('builtins.input', side_effect=["", ""]):
            with patch.object(configured_smb_module, '_execute_nxc') as mock_exec:
                mock_exec.return_value = {"success": True, "output": "file list"}

                result = configured_smb_module.op_spider_only()

                call_args = mock_exec.call_args[0][0]
                assert "spider_plus" in call_args

    def test_spider_only_with_share(self, configured_smb_module):
        """Test spider only with share filter."""
        with patch('builtins.input', side_effect=["SYSVOL", ""]):
            with patch.object(configured_smb_module, '_execute_nxc') as mock_exec:
                mock_exec.return_value = {"success": True, "output": "file list"}

                result = configured_smb_module.op_spider_only()

                call_args = mock_exec.call_args[0][0]
                assert "SHARE='SYSVOL'" in call_args


# =============================================================================
# Spider Share Operation Tests
# =============================================================================

class TestOpSpiderShare:
    """Tests for spider specific share operation."""

    def test_spider_share_no_download(self, configured_smb_module):
        """Test spider share without download."""
        with patch('builtins.input', side_effect=["NETLOGON", "n"]):
            with patch.object(configured_smb_module, '_execute_nxc') as mock_exec:
                mock_exec.return_value = {"success": True, "output": "files"}

                result = configured_smb_module.op_spider_share()

                call_args = mock_exec.call_args[0][0]
                assert "SHARE='NETLOGON'" in call_args
                assert "DOWNLOAD_FLAG" not in call_args

    def test_spider_share_with_download(self, configured_smb_module):
        """Test spider share with download."""
        with patch('builtins.input', side_effect=["NETLOGON", "y"]):
            with patch.object(configured_smb_module, '_execute_nxc') as mock_exec:
                mock_exec.return_value = {"success": True, "output": "files"}

                result = configured_smb_module.op_spider_share()

                call_args = mock_exec.call_args[0][0]
                assert "DOWNLOAD_FLAG=True" in call_args

    def test_spider_share_empty_name(self, configured_smb_module):
        """Test spider share with empty name."""
        with patch('builtins.input', return_value=""):
            result = configured_smb_module.op_spider_share()

            assert result["success"] is False
            assert "Share name required" in result["error"]


# =============================================================================
# Download File Operation Tests
# =============================================================================

class TestOpDownloadFile:
    """Tests for download specific file operation."""

    def test_download_file_success(self, configured_smb_module):
        """Test download specific file."""
        with patch('builtins.input', side_effect=["\\\\Windows\\\\Temp\\\\test.txt", "/tmp/test.txt"]):
            with patch.object(configured_smb_module, '_execute_nxc') as mock_exec:
                mock_exec.return_value = {"success": True, "output": "downloaded"}

                result = configured_smb_module.op_download_file()

                call_args = mock_exec.call_args[0][0]
                assert "--get-file" in call_args

    def test_download_file_missing_paths(self, configured_smb_module):
        """Test download file with missing paths."""
        with patch('builtins.input', side_effect=["", "/tmp/test.txt"]):
            result = configured_smb_module.op_download_file()

            assert result["success"] is False
            assert "Both paths required" in result["error"]


# =============================================================================
# Upload File Operation Tests
# =============================================================================

class TestOpUploadFile:
    """Tests for upload file operation."""

    def test_upload_file_success(self, configured_smb_module):
        """Test upload file."""
        with patch('builtins.input', side_effect=["/tmp/payload.exe", "\\\\Windows\\\\Temp\\\\payload.exe"]):
            with patch.object(configured_smb_module, '_execute_nxc') as mock_exec:
                mock_exec.return_value = {"success": True, "output": "uploaded"}

                result = configured_smb_module.op_upload_file()

                call_args = mock_exec.call_args[0][0]
                assert "--put-file" in call_args

    def test_upload_file_missing_paths(self, configured_smb_module):
        """Test upload file with missing paths."""
        with patch('builtins.input', side_effect=["/tmp/payload.exe", ""]):
            result = configured_smb_module.op_upload_file()

            assert result["success"] is False
            assert "Both paths required" in result["error"]


# =============================================================================
# Run Method Tests
# =============================================================================

class TestRunMethod:
    """Tests for the run method."""

    def test_run_calls_browse_download(self, configured_smb_module):
        """Test that run calls browse download by default."""
        with patch.object(configured_smb_module, 'op_browse_download') as mock_browse:
            mock_browse.return_value = {"success": True}

            result = configured_smb_module.run()

            mock_browse.assert_called_once()
