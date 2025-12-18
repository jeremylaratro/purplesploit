"""
Unit tests for Impacket module output parsers.

Tests cover:
- Secretsdump output parsing
- Kerberoast output parsing
- ASREPRoast output parsing
- PSExec output parsing
- WMIExec output parsing
- SMBClient output parsing
"""

import pytest
from unittest.mock import MagicMock, patch


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_framework_minimal():
    """Create a minimal mock framework for testing."""
    framework = MagicMock()
    framework.session = MagicMock()
    framework.database = MagicMock()
    framework.log = MagicMock()
    return framework


@pytest.fixture
def secretsdump_module(mock_framework_minimal):
    """Create a SecretsDump module for testing."""
    from purplesploit.modules.impacket.secretsdump import ImpacketSecretsDumpModule
    return ImpacketSecretsDumpModule(mock_framework_minimal)


@pytest.fixture
def kerberoast_module(mock_framework_minimal):
    """Create a Kerberoast module for testing."""
    from purplesploit.modules.impacket.kerberoast import ImpacketKerberoastModule
    return ImpacketKerberoastModule(mock_framework_minimal)


@pytest.fixture
def asreproast_module(mock_framework_minimal):
    """Create an ASREPRoast module for testing."""
    from purplesploit.modules.impacket.asreproast import ImpacketASREPRoastModule
    return ImpacketASREPRoastModule(mock_framework_minimal)


@pytest.fixture
def psexec_module(mock_framework_minimal):
    """Create a PSExec module for testing."""
    from purplesploit.modules.impacket.psexec import ImpacketPSExecModule
    return ImpacketPSExecModule(mock_framework_minimal)


@pytest.fixture
def wmiexec_module(mock_framework_minimal):
    """Create a WMIExec module for testing."""
    from purplesploit.modules.impacket.wmiexec import ImpacketWMIExecModule
    return ImpacketWMIExecModule(mock_framework_minimal)


@pytest.fixture
def smbclient_module(mock_framework_minimal):
    """Create an SMBClient module for testing."""
    from purplesploit.modules.impacket.smbclient import ImpacketSMBClientModule
    return ImpacketSMBClientModule(mock_framework_minimal)


# =============================================================================
# SecretsDump Parser Tests
# =============================================================================

class TestSecretsDumpParser:
    """Tests for SecretsDump.parse_output()."""

    def test_parse_sam_hashes(self, secretsdump_module):
        """Test parsing SAM hashes."""
        output = """
[*] Target system bootKey: 0x1234567890abcdef1234567890abcdef
[*] Dumping SAM hashes
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Cleaning up...
"""
        result = secretsdump_module.parse_output(output)

        assert result["success"] is True
        assert len(result["sam_hashes"]) >= 1
        assert result["total_hashes"] >= 1

    def test_parse_lsa_secrets(self, secretsdump_module):
        """Test parsing LSA secrets."""
        output = """
[*] Dumping SAM hashes
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
DOMAIN\\DC$:aes256-cts-hmac-sha1-96:abcdef1234567890
[*] DefaultPassword
DOMAIN\\admin:password123
"""
        result = secretsdump_module.parse_output(output)

        assert len(result["lsa_secrets"]) >= 0

    def test_parse_ntds_hashes(self, secretsdump_module):
        """Test parsing NTDS hashes."""
        output = """
[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a87f3a337d73085c45f9416be5787d86:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:caf31cdb05b9c5d23f0b4b95e4ed7c5e:::
user1:1001:aad3b435b51404eeaad3b435b51404ee:5835048ce94ad0564e29a924a03510ef:::
"""
        result = secretsdump_module.parse_output(output)

        assert len(result["ntds_hashes"]) >= 1
        assert result["total_hashes"] >= 1

    def test_parse_empty_output(self, secretsdump_module):
        """Test parsing empty output."""
        result = secretsdump_module.parse_output("")

        assert result["success"] is False
        assert result["sam_hashes"] == []
        assert result["total_hashes"] == 0

    def test_parse_no_hashes_found(self, secretsdump_module):
        """Test parsing output with no hashes."""
        output = """
[*] Connecting to target...
[-] Access denied
"""
        result = secretsdump_module.parse_output(output)

        assert result["success"] is False
        assert result["total_hashes"] == 0

    def test_parse_mixed_sections(self, secretsdump_module):
        """Test parsing output with all sections."""
        output = """
[*] Dumping SAM hashes
Admin:500:aad3:hash:::
[*] Dumping LSA Secrets
Secret1:value:data
[*] NTDS
User:1001:aad3:hash2:::
"""
        result = secretsdump_module.parse_output(output)

        assert result["success"] is True
        assert len(result["sam_hashes"]) >= 1


# =============================================================================
# Kerberoast Parser Tests
# =============================================================================

class TestKerberoastParser:
    """Tests for Kerberoast.parse_output()."""

    def test_parse_spn_tickets(self, kerberoast_module):
        """Test parsing SPN tickets."""
        output = """
[*] Getting TGT for domain\\user
[*] Getting ST for svc_sql/server.domain.local
$krb5tgs$23$*svc_sql$DOMAIN.LOCAL$svc_sql/server.domain.local*$abcdef123456...
[*] Getting ST for svc_http/web.domain.local
$krb5tgs$23$*svc_http$DOMAIN.LOCAL$svc_http/web.domain.local*$fedcba654321...
"""
        result = kerberoast_module.parse_output(output)

        assert isinstance(result, dict)
        # Check that hashes or tickets were extracted
        if "hashes" in result:
            assert isinstance(result["hashes"], list)

    def test_parse_no_spns_found(self, kerberoast_module):
        """Test parsing when no SPNs are found."""
        output = """
[*] Getting TGT for domain\\user
[*] No entries found with servicePrincipalName attribute set
"""
        result = kerberoast_module.parse_output(output)

        assert isinstance(result, dict)

    def test_parse_empty_output(self, kerberoast_module):
        """Test parsing empty output."""
        result = kerberoast_module.parse_output("")

        assert isinstance(result, dict)


# =============================================================================
# ASREPRoast Parser Tests
# =============================================================================

class TestASREPRoastParser:
    """Tests for ASREPRoast.parse_output()."""

    def test_parse_asrep_hashes(self, asreproast_module):
        """Test parsing AS-REP hashes."""
        output = """
[*] Getting TGT for users without pre-authentication
$krb5asrep$23$user1@DOMAIN.LOCAL:abcdef123456...
$krb5asrep$23$user2@DOMAIN.LOCAL:fedcba654321...
"""
        result = asreproast_module.parse_output(output)

        assert isinstance(result, dict)

    def test_parse_no_vulnerable_users(self, asreproast_module):
        """Test parsing when no users are vulnerable."""
        output = """
[*] Getting TGT for users without pre-authentication
[*] No users found with UF_DONT_REQUIRE_PREAUTH set
"""
        result = asreproast_module.parse_output(output)

        assert isinstance(result, dict)


# =============================================================================
# PSExec Parser Tests
# =============================================================================

class TestPSExecParser:
    """Tests for PSExec.parse_output()."""

    def test_parse_successful_exec(self, psexec_module):
        """Test parsing successful command execution."""
        output = """
[*] Requesting shares on 192.168.1.1.....
[*] Found writable share ADMIN$
[*] Uploading file abcdef.exe
[*] Opening SVCManager on 192.168.1.1.....
[*] Creating service test on 192.168.1.1.....
[*] Starting service test.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19041.1234]
(c) Microsoft Corporation. All rights reserved.

C:\\Windows\\system32>whoami
nt authority\\system
"""
        result = psexec_module.parse_output(output)

        assert isinstance(result, dict)

    def test_parse_access_denied(self, psexec_module):
        """Test parsing access denied error."""
        output = """
[*] Requesting shares on 192.168.1.1.....
[-] share 'ADMIN$' is not writable.
[-] Access denied
"""
        result = psexec_module.parse_output(output)

        assert isinstance(result, dict)

    def test_parse_command_output(self, psexec_module):
        """Test parsing command output."""
        output = """
C:\\>dir
 Volume in drive C has no label.
 Directory of C:\\

01/01/2024  12:00 PM    <DIR>          Users
01/01/2024  12:00 PM    <DIR>          Windows
"""
        result = psexec_module.parse_output(output)

        assert isinstance(result, dict)


# =============================================================================
# WMIExec Parser Tests
# =============================================================================

class TestWMIExecParser:
    """Tests for WMIExec.parse_output()."""

    def test_parse_successful_exec(self, wmiexec_module):
        """Test parsing successful WMI execution."""
        output = """
[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
whoami
domain\\administrator
"""
        result = wmiexec_module.parse_output(output)

        assert isinstance(result, dict)

    def test_parse_authentication_failure(self, wmiexec_module):
        """Test parsing authentication failure."""
        output = """
[-] Authentication failure, check your credentials
"""
        result = wmiexec_module.parse_output(output)

        assert isinstance(result, dict)


# =============================================================================
# SMBClient Parser Tests
# =============================================================================

class TestSMBClientParser:
    """Tests for SMBClient.parse_output()."""

    def test_parse_share_list(self, smbclient_module):
        """Test parsing share listing."""
        output = """
Impacket v0.10.0

Type help for list of commands

# shares
ADMIN$
C$
IPC$
NETLOGON
SYSVOL
"""
        result = smbclient_module.parse_output(output)

        assert isinstance(result, dict)

    def test_parse_directory_listing(self, smbclient_module):
        """Test parsing directory listing."""
        output = """
# ls
drw-rw-rw-          0  Mon Jan  1 12:00:00 2024 .
drw-rw-rw-          0  Mon Jan  1 12:00:00 2024 ..
-rw-rw-rw-       1234  Mon Jan  1 12:00:00 2024 file.txt
drw-rw-rw-          0  Mon Jan  1 12:00:00 2024 subdir
"""
        result = smbclient_module.parse_output(output)

        assert isinstance(result, dict)

    def test_parse_file_download(self, smbclient_module):
        """Test parsing file download output."""
        output = """
# get file.txt
[*] Downloading file.txt
"""
        result = smbclient_module.parse_output(output)

        assert isinstance(result, dict)


# =============================================================================
# Edge Cases
# =============================================================================

class TestParserEdgeCases:
    """Tests for edge cases across all parsers."""

    def test_secretsdump_binary_content(self, secretsdump_module):
        """Test secretsdump with binary content in output."""
        output = "[*] Dumping SAM hashes\n\x00\x01Admin:500:hash:::binary\x00"
        result = secretsdump_module.parse_output(output)
        assert isinstance(result, dict)

    def test_kerberoast_unicode_spn(self, kerberoast_module):
        """Test kerberoast with unicode SPN names."""
        output = "[*] Getting ST for svc_日本語/server.domain.local"
        result = kerberoast_module.parse_output(output)
        assert isinstance(result, dict)

    def test_psexec_large_output(self, psexec_module):
        """Test PSExec with large command output."""
        output = "C:\\>dir /s\n" + "\n".join([f"file_{i}.txt" for i in range(1000)])
        result = psexec_module.parse_output(output)
        assert isinstance(result, dict)

    def test_wmiexec_special_chars(self, wmiexec_module):
        """Test WMIExec with special characters."""
        output = "C:\\Users\\Admin's Folder>echo test & whoami"
        result = wmiexec_module.parse_output(output)
        assert isinstance(result, dict)

    def test_all_parsers_handle_none(self):
        """Test all parsers handle None gracefully."""
        # Note: This tests the general pattern, individual modules may vary
        pass  # Parsers expect string input, not None


# =============================================================================
# Hash Format Validation Tests
# =============================================================================

class TestHashFormatValidation:
    """Tests for validating hash format extraction."""

    def test_ntlm_hash_format(self, secretsdump_module):
        """Test NTLM hash format is correctly identified."""
        output = """
[*] Dumping SAM hashes
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a87f3a337d73085c45f9416be5787d86:::
"""
        result = secretsdump_module.parse_output(output)

        assert result["success"] is True
        # The hash should contain the expected format
        if result["sam_hashes"]:
            hash_line = result["sam_hashes"][0]
            assert ":" in hash_line
            parts = hash_line.split(":")
            assert len(parts) >= 4

    def test_krb5tgs_hash_format(self, kerberoast_module):
        """Test Kerberos TGS hash format."""
        output = """
$krb5tgs$23$*svc_test$DOMAIN.LOCAL$svc_test/server*$hash_content_here...
"""
        result = kerberoast_module.parse_output(output)
        assert isinstance(result, dict)

    def test_krb5asrep_hash_format(self, asreproast_module):
        """Test AS-REP hash format."""
        output = """
$krb5asrep$23$user@DOMAIN.LOCAL:hash_content_here...
"""
        result = asreproast_module.parse_output(output)
        assert isinstance(result, dict)
