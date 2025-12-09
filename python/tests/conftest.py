"""
Shared pytest fixtures for PurpleSploit tests.

This module provides common fixtures used across unit and integration tests,
including mock framework objects, test databases, and clean session instances.
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
from typing import Dict, Any


# =============================================================================
# Database Fixtures
# =============================================================================

@pytest.fixture
def temp_db_path(tmp_path):
    """Provide a temporary database path for testing."""
    return str(tmp_path / "test_purplesploit.db")


@pytest.fixture
def test_database(temp_db_path):
    """
    Create a test database instance with a temporary file.

    Yields:
        Database instance connected to temporary file
    """
    from purplesploit.core.database import Database
    db = Database(temp_db_path)
    yield db
    db.close()


@pytest.fixture
def memory_database():
    """
    Create an in-memory database for fast testing.

    Yields:
        Database instance using in-memory SQLite
    """
    from purplesploit.core.database import Database
    db = Database(":memory:")
    yield db
    db.close()


# =============================================================================
# Session Fixtures
# =============================================================================

@pytest.fixture
def clean_session():
    """
    Create a fresh Session instance for testing.

    Returns:
        New Session instance with empty state
    """
    from purplesploit.core.session import Session
    return Session()


@pytest.fixture
def target_manager():
    """Create a fresh TargetManager for testing."""
    from purplesploit.core.session import TargetManager
    return TargetManager()


@pytest.fixture
def credential_manager():
    """Create a fresh CredentialManager for testing."""
    from purplesploit.core.session import CredentialManager
    return CredentialManager()


@pytest.fixture
def service_manager():
    """Create a fresh ServiceManager for testing."""
    from purplesploit.core.session import ServiceManager
    return ServiceManager()


@pytest.fixture
def wordlist_manager():
    """Create a fresh WordlistManager for testing."""
    from purplesploit.core.session import WordlistManager
    return WordlistManager()


# =============================================================================
# Parameter Fixtures
# =============================================================================

@pytest.fixture
def parameter_registry():
    """
    Create a fresh ParameterRegistry for testing.

    Note: Creates a new instance to avoid polluting the global registry.
    """
    from purplesploit.core.parameters import ParameterRegistry
    return ParameterRegistry()


@pytest.fixture
def profile_registry():
    """Create a fresh ProfileRegistry for testing."""
    from purplesploit.core.parameters import ProfileRegistry
    return ProfileRegistry()


@pytest.fixture
def sample_parameter():
    """Create a sample Parameter for testing."""
    from purplesploit.core.parameters import Parameter, ParameterType
    return Parameter(
        name="TEST_PARAM",
        description="Test parameter",
        param_type=ParameterType.STRING,
        required=False,
        default="default_value"
    )


# =============================================================================
# Framework Fixtures
# =============================================================================

@pytest.fixture
def mock_framework(clean_session, test_database):
    """
    Create a mock framework object for testing modules.

    Provides a framework with:
    - Mock logging
    - Real session instance
    - Real database instance

    Returns:
        MagicMock framework with real session and database
    """
    framework = MagicMock()
    framework.session = clean_session
    framework.database = test_database
    framework.log = MagicMock()

    # Mock add_target to work with session
    def add_target(target_type, identifier, name=None):
        if target_type == "network":
            return clean_session.targets.add({
                "ip": identifier,
                "name": name or identifier,
                "type": target_type
            })
        else:
            return clean_session.targets.add({
                "url": identifier,
                "name": name or identifier,
                "type": target_type
            })

    framework.add_target = add_target
    return framework


@pytest.fixture
def mock_framework_minimal():
    """
    Create a minimal mock framework without database.

    Useful for testing modules that don't need database access.
    """
    framework = MagicMock()
    framework.log = MagicMock()
    framework.session = MagicMock()
    framework.session.get_current_target.return_value = None
    framework.session.get_current_credential.return_value = None
    return framework


# =============================================================================
# Module Fixtures
# =============================================================================

@pytest.fixture
def concrete_module_class():
    """
    Create a concrete implementation of BaseModule for testing.

    BaseModule is abstract, so we need a concrete subclass for testing.
    """
    from purplesploit.core.module import BaseModule
    from typing import Dict, Any

    class TestModule(BaseModule):
        @property
        def name(self) -> str:
            return "Test Module"

        @property
        def description(self) -> str:
            return "A test module for unit testing"

        @property
        def author(self) -> str:
            return "Test Author"

        @property
        def category(self) -> str:
            return "test"

        def run(self) -> Dict[str, Any]:
            return {"success": True, "output": "Test completed"}

    return TestModule


@pytest.fixture
def test_module(concrete_module_class, mock_framework):
    """Create an instance of the concrete test module."""
    return concrete_module_class(mock_framework)


@pytest.fixture
def external_tool_module_class():
    """
    Create a concrete implementation of ExternalToolModule for testing.
    """
    from purplesploit.core.module import ExternalToolModule
    from typing import Dict, Any

    class TestExternalToolModule(ExternalToolModule):
        def __init__(self, framework):
            super().__init__(framework)
            self.tool_name = "test_tool"

        @property
        def name(self) -> str:
            return "Test External Tool"

        @property
        def description(self) -> str:
            return "A test external tool module"

        @property
        def author(self) -> str:
            return "Test Author"

        @property
        def category(self) -> str:
            return "test"

        def build_command(self) -> str:
            rhost = self.get_option("RHOST") or "localhost"
            return f"test_tool --target {rhost}"

        def run(self) -> Dict[str, Any]:
            return {"success": True, "output": "Test tool executed"}

    return TestExternalToolModule


@pytest.fixture
def test_external_module(external_tool_module_class, mock_framework_minimal):
    """Create an instance of the external tool test module."""
    return external_tool_module_class(mock_framework_minimal)


# =============================================================================
# File and Path Fixtures
# =============================================================================

@pytest.fixture
def temp_wordlist(tmp_path):
    """Create a temporary wordlist file for testing."""
    wordlist = tmp_path / "test_wordlist.txt"
    wordlist.write_text("admin\nuser\ntest\nroot\nguest\n")
    return str(wordlist)


@pytest.fixture
def temp_xml_file(tmp_path):
    """Create a temporary XML file for nmap parsing tests."""
    xml_content = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV 192.168.1.1" start="1234567890">
  <host starttime="1234567890" endtime="1234567899">
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="test.local" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.0"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.18"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.18"/>
      </port>
    </ports>
  </host>
</nmaprun>'''
    xml_file = tmp_path / "test_nmap.xml"
    xml_file.write_text(xml_content)
    return str(xml_file)


# =============================================================================
# Sample Data Fixtures
# =============================================================================

@pytest.fixture
def sample_target():
    """Provide sample target data for testing."""
    return {
        "ip": "192.168.1.100",
        "name": "test-server",
        "type": "network"
    }


@pytest.fixture
def sample_web_target():
    """Provide sample web target data for testing."""
    return {
        "url": "http://example.com",
        "name": "example-site",
        "type": "web"
    }


@pytest.fixture
def sample_credential():
    """Provide sample credential data for testing."""
    return {
        "username": "admin",
        "password": "password123",
        "domain": "TESTDOMAIN"
    }


@pytest.fixture
def sample_credential_with_hash():
    """Provide sample credential with hash for testing."""
    return {
        "username": "admin",
        "hash": "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
        "hash_type": "NTLM",
        "domain": "TESTDOMAIN"
    }


# =============================================================================
# Wfuzz Output Fixtures
# =============================================================================

@pytest.fixture
def sample_wfuzz_output():
    """Provide sample wfuzz output for parsing tests."""
    return '''********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://example.com/FUZZ
Total requests: 4

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000001:   200        7 L      11 W       162 Ch      "index"
000000002:   301        9 L      28 W       325 Ch      "admin"
000000003:   404        7 L      11 W       162 Ch      "notfound"
000000004:   200        15 L     42 W       512 Ch      "login"

Total time: 0.5
Processed Requests: 4
Filtered Requests: 0
Requests/sec.: 8
'''


@pytest.fixture
def sample_wfuzz_output_uniform():
    """Provide wfuzz output with uniform responses for smart filter testing."""
    return '''********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://example.com/FUZZ
Total requests: 10

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000001:   200        7 L      11 W       162 Ch      "test1"
000000002:   200        7 L      11 W       162 Ch      "test2"
000000003:   200        7 L      11 W       162 Ch      "test3"
000000004:   200        7 L      11 W       162 Ch      "test4"
000000005:   200        7 L      11 W       162 Ch      "test5"
000000006:   200        7 L      11 W       162 Ch      "test6"
000000007:   200        7 L      11 W       162 Ch      "test7"
000000008:   200        15 L     42 W       512 Ch      "admin"
000000009:   200        7 L      11 W       162 Ch      "test9"
000000010:   200        7 L      11 W       162 Ch      "test10"

Total time: 1.0
Processed Requests: 10
'''


# =============================================================================
# Nmap Output Fixtures
# =============================================================================

@pytest.fixture
def sample_nmap_output():
    """Provide sample nmap stdout for parsing tests."""
    return '''Starting Nmap 7.94 ( https://nmap.org ) at 2024-01-15 10:00 UTC
Nmap scan report for 192.168.1.100
Host is up (0.0010s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.0 (protocol 2.0)
80/tcp   open  http        nginx 1.18.0
443/tcp  open  ssl/https   nginx 1.18.0
445/tcp  open  microsoft-ds Windows Server 2019 SMB

Service detection performed. Please report any incorrect results.
Nmap done: 1 IP address (1 host up) scanned in 15.32 seconds
'''


# =============================================================================
# Utility Functions
# =============================================================================

@pytest.fixture
def assert_valid_command():
    """Provide a helper function to validate command strings."""
    def _assert_valid(command: str, required_parts: list):
        """Assert that command contains all required parts."""
        for part in required_parts:
            assert part in command, f"Command missing required part: {part}"
    return _assert_valid
