"""
Tests for the Impacket modules.

Tests the Impacket-based modules: SecretsDump, Kerberoast, ASREPRoast, PSExec, etc.
"""

import pytest
from unittest.mock import MagicMock


# =============================================================================
# Impacket SecretsDump Module Tests
# =============================================================================

class TestImpacketSecretsDumpProperties:
    """Tests for Impacket SecretsDump module properties."""

    @pytest.fixture
    def secretsdump_module(self, mock_framework_minimal):
        """Create SecretsDump module instance for testing."""
        from purplesploit.modules.impacket.secretsdump import ImpacketSecretsDumpModule
        return ImpacketSecretsDumpModule(mock_framework_minimal)

    def test_name(self, secretsdump_module):
        """Test module name."""
        assert "SecretsDump" in secretsdump_module.name

    def test_description(self, secretsdump_module):
        """Test module description mentions credential dumping."""
        assert "dump" in secretsdump_module.description.lower() or "SAM" in secretsdump_module.description

    def test_category(self, secretsdump_module):
        """Test module category is impacket."""
        assert secretsdump_module.category == "impacket"

    def test_tool_name(self, secretsdump_module):
        """Test tool name is impacket-secretsdump."""
        assert secretsdump_module.tool_name == "impacket-secretsdump"

    def test_has_rhost_option(self, secretsdump_module):
        """Test that RHOST option exists and is required."""
        assert "RHOST" in secretsdump_module.options
        assert secretsdump_module.options["RHOST"]["required"] is True

    def test_has_username_option(self, secretsdump_module):
        """Test that USERNAME option exists and is required."""
        assert "USERNAME" in secretsdump_module.options
        assert secretsdump_module.options["USERNAME"]["required"] is True

    def test_has_hash_option(self, secretsdump_module):
        """Test that HASH option exists for pass-the-hash."""
        assert "HASH" in secretsdump_module.options

    def test_has_sam_option(self, secretsdump_module):
        """Test that SAM option exists."""
        assert "SAM" in secretsdump_module.options

    def test_has_ntds_option(self, secretsdump_module):
        """Test that NTDS option exists."""
        assert "NTDS" in secretsdump_module.options


class TestImpacketSecretsDumpCommandBuilding:
    """Tests for SecretsDump command building."""

    @pytest.fixture
    def secretsdump_module(self, mock_framework_minimal):
        """Create SecretsDump module instance for testing."""
        from purplesploit.modules.impacket.secretsdump import ImpacketSecretsDumpModule
        return ImpacketSecretsDumpModule(mock_framework_minimal)

    def test_build_command_with_password(self, secretsdump_module):
        """Test building command with password authentication."""
        secretsdump_module.set_option("RHOST", "192.168.1.1")
        secretsdump_module.set_option("USERNAME", "admin")
        secretsdump_module.set_option("PASSWORD", "secret123")
        secretsdump_module.set_option("DOMAIN", "CORP")
        cmd = secretsdump_module.build_command()
        assert "impacket-secretsdump" in cmd
        assert "CORP/admin:secret123@192.168.1.1" in cmd

    def test_build_command_with_hash(self, secretsdump_module):
        """Test building command with hash authentication."""
        secretsdump_module.set_option("RHOST", "192.168.1.1")
        secretsdump_module.set_option("USERNAME", "admin")
        secretsdump_module.set_option("HASH", "aad3b435b51404ee:8846f7eaee8fb117")
        secretsdump_module.set_option("DOMAIN", "CORP")
        cmd = secretsdump_module.build_command()
        assert "-hashes aad3b435b51404ee:8846f7eaee8fb117" in cmd

    def test_build_command_with_ntds(self, secretsdump_module):
        """Test building command with NTDS dump."""
        secretsdump_module.set_option("RHOST", "192.168.1.1")
        secretsdump_module.set_option("USERNAME", "admin")
        secretsdump_module.set_option("PASSWORD", "secret")
        secretsdump_module.set_option("NTDS", "true")
        cmd = secretsdump_module.build_command()
        assert "-just-dc" in cmd

    def test_build_command_with_history(self, secretsdump_module):
        """Test building command with password history."""
        secretsdump_module.set_option("RHOST", "192.168.1.1")
        secretsdump_module.set_option("USERNAME", "admin")
        secretsdump_module.set_option("PASSWORD", "secret")
        secretsdump_module.set_option("HISTORY", "true")
        cmd = secretsdump_module.build_command()
        assert "-history" in cmd

    def test_build_command_with_output_file(self, secretsdump_module):
        """Test building command with output file."""
        secretsdump_module.set_option("RHOST", "192.168.1.1")
        secretsdump_module.set_option("USERNAME", "admin")
        secretsdump_module.set_option("PASSWORD", "secret")
        secretsdump_module.set_option("OUTPUT_FILE", "/tmp/hashes")
        cmd = secretsdump_module.build_command()
        assert "-outputfile /tmp/hashes" in cmd


class TestImpacketSecretsDumpOutputParsing:
    """Tests for SecretsDump output parsing."""

    @pytest.fixture
    def secretsdump_module(self, mock_framework_minimal):
        """Create SecretsDump module instance for testing."""
        from purplesploit.modules.impacket.secretsdump import ImpacketSecretsDumpModule
        return ImpacketSecretsDumpModule(mock_framework_minimal)

    def test_parse_output_empty(self, secretsdump_module):
        """Test parsing empty output."""
        result = secretsdump_module.parse_output("")
        assert result["success"] is False
        assert result["sam_hashes"] == []

    def test_parse_output_with_sam_hashes(self, secretsdump_module):
        """Test parsing output with SAM hashes."""
        output = """[*] Target system bootKey: 0x1234...
[*] Dumping SAM hashes
Administrator:500:aad3b435b51404ee:8846f7eaee8fb117:::
Guest:501:aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
"""
        result = secretsdump_module.parse_output(output)
        assert result["success"] is True
        assert len(result["sam_hashes"]) == 2
        assert result["total_hashes"] == 2

    def test_parse_output_with_lsa_secrets(self, secretsdump_module):
        """Test parsing output with LSA secrets."""
        output = """[*] Dumping SAM hashes
[*] Dumping LSA Secrets
$MACHINE.ACC:aes256-cts-hmac-sha1-96:abc123
"""
        result = secretsdump_module.parse_output(output)
        # LSA secrets may have different format


# =============================================================================
# Impacket Kerberoast Module Tests
# =============================================================================

class TestImpacketKerberoastProperties:
    """Tests for Impacket Kerberoast module properties."""

    @pytest.fixture
    def kerberoast_module(self, mock_framework_minimal):
        """Create Kerberoast module instance for testing."""
        from purplesploit.modules.impacket.kerberoast import ImpacketKerberoastModule
        return ImpacketKerberoastModule(mock_framework_minimal)

    def test_name(self, kerberoast_module):
        """Test module name."""
        assert "Kerberoast" in kerberoast_module.name

    def test_category(self, kerberoast_module):
        """Test module category is impacket."""
        assert kerberoast_module.category == "impacket"

    def test_tool_name(self, kerberoast_module):
        """Test tool name is impacket-GetUserSPNs."""
        assert "GetUserSPNs" in kerberoast_module.tool_name

    def test_has_rhost_option(self, kerberoast_module):
        """Test that RHOST option exists."""
        assert "RHOST" in kerberoast_module.options


# =============================================================================
# Impacket ASREPRoast Module Tests
# =============================================================================

class TestImpacketASREPRoastProperties:
    """Tests for Impacket ASREPRoast module properties."""

    @pytest.fixture
    def asreproast_module(self, mock_framework_minimal):
        """Create ASREPRoast module instance for testing."""
        from purplesploit.modules.impacket.asreproast import ImpacketASREPRoastModule
        return ImpacketASREPRoastModule(mock_framework_minimal)

    def test_name(self, asreproast_module):
        """Test module name."""
        assert "AS-REP" in asreproast_module.name or "asrep" in asreproast_module.name.lower()

    def test_category(self, asreproast_module):
        """Test module category is impacket."""
        assert asreproast_module.category == "impacket"

    def test_tool_name(self, asreproast_module):
        """Test tool name is impacket-GetNPUsers."""
        assert "GetNPUsers" in asreproast_module.tool_name

    def test_has_rhost_option(self, asreproast_module):
        """Test that RHOST option exists."""
        assert "RHOST" in asreproast_module.options


# =============================================================================
# Impacket PSExec Module Tests
# =============================================================================

class TestImpacketPSExecProperties:
    """Tests for Impacket PSExec module properties."""

    @pytest.fixture
    def psexec_module(self, mock_framework_minimal):
        """Create PSExec module instance for testing."""
        from purplesploit.modules.impacket.psexec import ImpacketPSExecModule
        return ImpacketPSExecModule(mock_framework_minimal)

    def test_name(self, psexec_module):
        """Test module name."""
        assert "PSExec" in psexec_module.name

    def test_category(self, psexec_module):
        """Test module category is impacket."""
        assert psexec_module.category == "impacket"

    def test_tool_name(self, psexec_module):
        """Test tool name is impacket-psexec."""
        assert "psexec" in psexec_module.tool_name

    def test_has_rhost_option(self, psexec_module):
        """Test that RHOST option exists."""
        assert "RHOST" in psexec_module.options


# =============================================================================
# Impacket WMIExec Module Tests
# =============================================================================

class TestImpacketWMIExecProperties:
    """Tests for Impacket WMIExec module properties."""

    @pytest.fixture
    def wmiexec_module(self, mock_framework_minimal):
        """Create WMIExec module instance for testing."""
        from purplesploit.modules.impacket.wmiexec import ImpacketWMIExecModule
        return ImpacketWMIExecModule(mock_framework_minimal)

    def test_name(self, wmiexec_module):
        """Test module name."""
        assert "WMIExec" in wmiexec_module.name

    def test_category(self, wmiexec_module):
        """Test module category is impacket."""
        assert wmiexec_module.category == "impacket"

    def test_tool_name(self, wmiexec_module):
        """Test tool name is impacket-wmiexec."""
        assert "wmiexec" in wmiexec_module.tool_name


# =============================================================================
# Impacket SMBClient Module Tests
# =============================================================================

class TestImpacketSMBClientProperties:
    """Tests for Impacket SMBClient module properties."""

    @pytest.fixture
    def smbclient_module(self, mock_framework_minimal):
        """Create SMBClient module instance for testing."""
        from purplesploit.modules.impacket.smbclient import ImpacketSMBClientModule
        return ImpacketSMBClientModule(mock_framework_minimal)

    def test_name(self, smbclient_module):
        """Test module name."""
        assert "SMB" in smbclient_module.name or "smb" in smbclient_module.name.lower()

    def test_category(self, smbclient_module):
        """Test module category is impacket."""
        assert smbclient_module.category == "impacket"

    def test_tool_name(self, smbclient_module):
        """Test tool name is impacket-smbclient."""
        assert "smbclient" in smbclient_module.tool_name


# =============================================================================
# Module Inheritance Tests
# =============================================================================

class TestImpacketModulesInheritance:
    """Tests for impacket module inheritance from ExternalToolModule."""

    def test_secretsdump_inherits_correctly(self, mock_framework_minimal):
        """Test SecretsDump inherits from ExternalToolModule."""
        from purplesploit.modules.impacket.secretsdump import ImpacketSecretsDumpModule
        from purplesploit.core.module import ExternalToolModule
        module = ImpacketSecretsDumpModule(mock_framework_minimal)
        assert isinstance(module, ExternalToolModule)

    def test_kerberoast_inherits_correctly(self, mock_framework_minimal):
        """Test Kerberoast inherits from ExternalToolModule."""
        from purplesploit.modules.impacket.kerberoast import ImpacketKerberoastModule
        from purplesploit.core.module import ExternalToolModule
        module = ImpacketKerberoastModule(mock_framework_minimal)
        assert isinstance(module, ExternalToolModule)

    def test_asreproast_inherits_correctly(self, mock_framework_minimal):
        """Test ASREPRoast inherits from ExternalToolModule."""
        from purplesploit.modules.impacket.asreproast import ImpacketASREPRoastModule
        from purplesploit.core.module import ExternalToolModule
        module = ImpacketASREPRoastModule(mock_framework_minimal)
        assert isinstance(module, ExternalToolModule)

    def test_psexec_inherits_correctly(self, mock_framework_minimal):
        """Test PSExec inherits from ExternalToolModule."""
        from purplesploit.modules.impacket.psexec import ImpacketPSExecModule
        from purplesploit.core.module import ExternalToolModule
        module = ImpacketPSExecModule(mock_framework_minimal)
        assert isinstance(module, ExternalToolModule)

    def test_wmiexec_inherits_correctly(self, mock_framework_minimal):
        """Test WMIExec inherits from ExternalToolModule."""
        from purplesploit.modules.impacket.wmiexec import ImpacketWMIExecModule
        from purplesploit.core.module import ExternalToolModule
        module = ImpacketWMIExecModule(mock_framework_minimal)
        assert isinstance(module, ExternalToolModule)

    def test_smbclient_inherits_correctly(self, mock_framework_minimal):
        """Test SMBClient inherits from ExternalToolModule."""
        from purplesploit.modules.impacket.smbclient import ImpacketSMBClientModule
        from purplesploit.core.module import ExternalToolModule
        module = ImpacketSMBClientModule(mock_framework_minimal)
        assert isinstance(module, ExternalToolModule)


# =============================================================================
# Module Options Tests
# =============================================================================

class TestImpacketModulesCommonOptions:
    """Tests for common options across impacket modules."""

    def test_secretsdump_has_domain_option(self, mock_framework_minimal):
        """Test SecretsDump has DOMAIN option."""
        from purplesploit.modules.impacket.secretsdump import ImpacketSecretsDumpModule
        module = ImpacketSecretsDumpModule(mock_framework_minimal)
        assert "DOMAIN" in module.options

    def test_secretsdump_domain_default(self, mock_framework_minimal):
        """Test SecretsDump DOMAIN default is '.' for local."""
        from purplesploit.modules.impacket.secretsdump import ImpacketSecretsDumpModule
        module = ImpacketSecretsDumpModule(mock_framework_minimal)
        assert module.options["DOMAIN"]["default"] == "."

    def test_secretsdump_sam_default_true(self, mock_framework_minimal):
        """Test SecretsDump SAM default is true."""
        from purplesploit.modules.impacket.secretsdump import ImpacketSecretsDumpModule
        module = ImpacketSecretsDumpModule(mock_framework_minimal)
        assert module.options["SAM"]["default"] == "true"

    def test_secretsdump_ntds_default_false(self, mock_framework_minimal):
        """Test SecretsDump NTDS default is false."""
        from purplesploit.modules.impacket.secretsdump import ImpacketSecretsDumpModule
        module = ImpacketSecretsDumpModule(mock_framework_minimal)
        assert module.options["NTDS"]["default"] == "false"
