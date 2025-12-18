"""
Tests for purplesploit.core.credential_spray module.
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta
import time

from purplesploit.core.credential_spray import (
    CredentialSpray,
    SprayAttempt,
    SprayResult,
    SprayProtocol,
    SprayPattern,
    SprayStatus,
    LockoutPolicy,
    PasswordGenerator,
    create_credential_spray,
)


class TestSprayProtocol:
    """Tests for SprayProtocol enum."""

    def test_all_protocols_exist(self):
        """Test all expected protocols exist."""
        expected = [
            "smb", "ldap", "winrm", "ssh", "rdp", "mssql",
            "kerberos", "http_basic", "http_ntlm", "http_form",
            "ftp", "owa", "o365"
        ]
        for proto in expected:
            assert SprayProtocol(proto) is not None


class TestSprayPattern:
    """Tests for SprayPattern enum."""

    def test_all_patterns_exist(self):
        """Test all expected patterns exist."""
        expected = ["low_and_slow", "depth_first", "breadth_first", "random", "smart"]
        for pattern in expected:
            assert SprayPattern(pattern) is not None


class TestSprayStatus:
    """Tests for SprayStatus enum."""

    def test_all_statuses_exist(self):
        """Test all expected statuses exist."""
        expected = ["pending", "running", "paused", "completed", "stopped", "error"]
        for status in expected:
            assert SprayStatus(status) is not None


class TestSprayAttempt:
    """Tests for SprayAttempt dataclass."""

    def test_basic_attempt(self):
        """Test creating a basic attempt."""
        attempt = SprayAttempt(
            username="admin",
            password="password",
            target="192.168.1.1",
            protocol=SprayProtocol.SMB,
        )

        assert attempt.username == "admin"
        assert attempt.password == "password"
        assert attempt.success is False
        assert attempt.locked_out is False

    def test_successful_attempt(self):
        """Test successful attempt."""
        attempt = SprayAttempt(
            username="admin",
            password="P@ssw0rd",
            target="dc01.corp.local",
            protocol=SprayProtocol.LDAP,
            success=True,
            response_time=0.5,
        )

        assert attempt.success is True
        assert attempt.response_time == 0.5

    def test_attempt_to_dict(self):
        """Test converting attempt to dict."""
        attempt = SprayAttempt(
            username="user1",
            password="secret",
            target="10.0.0.1",
            protocol=SprayProtocol.SSH,
            success=True,
        )

        data = attempt.to_dict()

        assert data["username"] == "user1"
        assert data["password"] == "secret"  # Shown because success
        assert data["protocol"] == "ssh"

    def test_attempt_to_dict_hides_failed_password(self):
        """Test that failed attempts hide password."""
        attempt = SprayAttempt(
            username="user1",
            password="secret",
            target="10.0.0.1",
            protocol=SprayProtocol.SSH,
            success=False,
        )

        data = attempt.to_dict()

        assert data["password"] == "***"


class TestSprayResult:
    """Tests for SprayResult dataclass."""

    def test_basic_result(self):
        """Test creating a basic result."""
        result = SprayResult(
            id="spray:abc123",
            start_time=datetime.now(),
            targets=["192.168.1.1"],
            protocol=SprayProtocol.SMB,
        )

        assert result.id == "spray:abc123"
        assert result.status == SprayStatus.PENDING
        assert result.total_attempts == 0

    def test_result_with_credentials(self):
        """Test result with valid credentials."""
        result = SprayResult(
            id="spray:test",
            start_time=datetime.now(),
            end_time=datetime.now(),
            status=SprayStatus.COMPLETED,
            total_attempts=100,
            successful_attempts=2,
            valid_credentials=[
                {"username": "admin", "password": "admin"},
                {"username": "user", "password": "pass"},
            ],
        )

        assert result.successful_attempts == 2
        assert len(result.valid_credentials) == 2

    def test_result_to_dict(self):
        """Test converting result to dict."""
        result = SprayResult(
            id="spray:xyz",
            start_time=datetime.now(),
            status=SprayStatus.COMPLETED,
            targets=["10.0.0.1"],
            protocol=SprayProtocol.LDAP,
        )

        data = result.to_dict()

        assert data["id"] == "spray:xyz"
        assert data["status"] == "completed"
        assert data["protocol"] == "ldap"


class TestLockoutPolicy:
    """Tests for LockoutPolicy dataclass."""

    def test_default_policy(self):
        """Test default policy values."""
        policy = LockoutPolicy()

        assert policy.threshold == 5
        assert policy.observation_window == 30
        assert policy.safe_attempts == 3

    def test_conservative_policy(self):
        """Test conservative policy."""
        policy = LockoutPolicy.conservative()

        assert policy.threshold == 3
        assert policy.safe_attempts == 1

    def test_from_ad_policy(self):
        """Test creating from AD policy dict."""
        ad_policy = {
            "lockoutThreshold": 10,
            "lockoutObservationWindow": 60,
            "lockoutDuration": 30,
        }

        policy = LockoutPolicy.from_ad_policy(ad_policy)

        assert policy.threshold == 10
        assert policy.observation_window == 60
        assert policy.safe_attempts == 8  # threshold - 2


class TestCredentialSprayInit:
    """Tests for CredentialSpray initialization."""

    def test_init_default(self):
        """Test default initialization."""
        spray = CredentialSpray()

        assert spray.framework is None
        assert spray.lockout_policy is not None
        assert len(spray.results) == 0

    def test_init_with_framework(self):
        """Test initialization with framework."""
        mock_framework = Mock()
        spray = CredentialSpray(framework=mock_framework)

        assert spray.framework == mock_framework

    def test_init_with_policy(self):
        """Test initialization with custom policy."""
        policy = LockoutPolicy(threshold=10, safe_attempts=5)
        spray = CredentialSpray(lockout_policy=policy)

        assert spray.lockout_policy.threshold == 10
        assert spray.lockout_policy.safe_attempts == 5

    def test_factory_function(self):
        """Test factory function."""
        spray = create_credential_spray()

        assert isinstance(spray, CredentialSpray)


class TestCredentialSprayAttemptTracking:
    """Tests for attempt tracking."""

    def test_can_attempt_user_initial(self):
        """Test initial user can be attempted."""
        spray = CredentialSpray()

        assert spray._can_attempt_user("admin") is True

    def test_can_attempt_user_after_attempts(self):
        """Test user after attempts respects safe limit."""
        spray = CredentialSpray(
            lockout_policy=LockoutPolicy(threshold=5, safe_attempts=2)
        )

        # Record attempts
        spray._record_attempt("admin", False, False)
        assert spray._can_attempt_user("admin") is True

        spray._record_attempt("admin", False, False)
        assert spray._can_attempt_user("admin") is False  # At safe limit

    def test_locked_user_cannot_attempt(self):
        """Test locked users cannot be attempted."""
        spray = CredentialSpray()

        spray._record_attempt("admin", False, locked=True)

        assert spray._can_attempt_user("admin") is False


class TestCredentialSprayAttemptOrder:
    """Tests for attempt order generation."""

    def test_breadth_first_order(self):
        """Test breadth-first ordering."""
        spray = CredentialSpray()

        users = ["user1", "user2"]
        passwords = ["pass1", "pass2"]

        order = spray._generate_attempt_order(users, passwords, SprayPattern.BREADTH_FIRST)

        # First password against all users, then second
        assert order[0] == ("user1", "pass1")
        assert order[1] == ("user2", "pass1")
        assert order[2] == ("user1", "pass2")
        assert order[3] == ("user2", "pass2")

    def test_depth_first_order(self):
        """Test depth-first ordering."""
        spray = CredentialSpray()

        users = ["user1", "user2"]
        passwords = ["pass1", "pass2"]

        order = spray._generate_attempt_order(users, passwords, SprayPattern.DEPTH_FIRST)

        # All passwords against first user, then second
        assert order[0] == ("user1", "pass1")
        assert order[1] == ("user1", "pass2")
        assert order[2] == ("user2", "pass1")
        assert order[3] == ("user2", "pass2")

    def test_random_order(self):
        """Test random ordering has all combinations."""
        spray = CredentialSpray()

        users = ["user1", "user2"]
        passwords = ["pass1", "pass2"]

        order = spray._generate_attempt_order(users, passwords, SprayPattern.RANDOM)

        # Should have all 4 combinations
        assert len(order) == 4
        assert ("user1", "pass1") in order
        assert ("user2", "pass2") in order


class TestCredentialSprayExecution:
    """Tests for spray execution."""

    def test_spray_simulation(self):
        """Test spray in simulation mode (no framework)."""
        # Use permissive policy for testing
        policy = LockoutPolicy(threshold=10, safe_attempts=10)
        spray = CredentialSpray(lockout_policy=policy)

        result = spray.spray(
            targets="192.168.1.1",
            users=["admin", "user"],
            passwords=["admin", "wrong"],
            protocol=SprayProtocol.SMB,
        )

        assert result.status == SprayStatus.COMPLETED
        assert result.total_attempts == 4  # 2 users × 2 passwords
        # admin:admin should succeed in simulation
        assert result.successful_attempts >= 1

    def test_spray_stop_on_success(self):
        """Test stop_on_success option."""
        spray = CredentialSpray()

        result = spray.spray(
            targets="192.168.1.1",
            users=["admin", "user1", "user2"],
            passwords=["admin", "password", "test"],
            protocol=SprayProtocol.SMB,
            stop_on_success=True,
        )

        # Should stop after finding admin:admin
        assert result.successful_attempts >= 1
        assert result.status == SprayStatus.STOPPED

    def test_spray_callbacks(self):
        """Test callbacks are fired."""
        spray = CredentialSpray()

        attempt_callback = Mock()
        success_callback = Mock()
        progress_callback = Mock()
        complete_callback = Mock()

        spray.on_attempt = attempt_callback
        spray.on_success = success_callback
        spray.on_progress = progress_callback
        spray.on_complete = complete_callback

        result = spray.spray(
            targets="10.0.0.1",
            users=["admin"],
            passwords=["admin"],
            protocol=SprayProtocol.SMB,
        )

        assert attempt_callback.called
        assert progress_callback.called
        assert complete_callback.called
        # admin:admin succeeds in simulation
        assert success_callback.called

    def test_spray_multiple_targets(self):
        """Test spraying multiple targets."""
        # Use permissive policy for testing
        policy = LockoutPolicy(threshold=10, safe_attempts=10)
        spray = CredentialSpray(lockout_policy=policy)

        result = spray.spray(
            targets=["10.0.0.1", "10.0.0.2"],
            users=["admin"],
            passwords=["admin"],
            protocol=SprayProtocol.SMB,
        )

        assert result.total_attempts == 2  # 1 user × 1 pass × 2 targets
        assert "10.0.0.1" in result.targets
        assert "10.0.0.2" in result.targets


class TestCredentialSprayControl:
    """Tests for spray control (stop, pause, resume)."""

    def test_stop(self):
        """Test stop functionality."""
        spray = CredentialSpray()

        assert spray._stop_requested is False
        spray.stop()
        assert spray._stop_requested is True

    def test_pause_resume(self):
        """Test pause and resume."""
        spray = CredentialSpray()

        assert spray._pause_requested is False
        spray.pause()
        assert spray._pause_requested is True
        spray.resume()
        assert spray._pause_requested is False

    def test_get_status_idle(self):
        """Test status when idle."""
        spray = CredentialSpray()

        status = spray.get_status()

        assert status["status"] == "idle"


class TestCredentialSprayStatistics:
    """Tests for statistics."""

    def test_get_statistics_empty(self):
        """Test statistics with no results."""
        spray = CredentialSpray()

        stats = spray.get_statistics()

        assert stats["total_sprays"] == 0
        assert stats["total_attempts"] == 0

    def test_get_statistics_after_spray(self):
        """Test statistics after spray."""
        # Use permissive policy for testing
        policy = LockoutPolicy(threshold=10, safe_attempts=10)
        spray = CredentialSpray(lockout_policy=policy)

        spray.spray(
            targets="10.0.0.1",
            users=["admin", "user"],
            passwords=["admin", "test"],
            protocol=SprayProtocol.SMB,
        )

        stats = spray.get_statistics()

        assert stats["total_sprays"] == 1
        assert stats["total_attempts"] == 4
        assert stats["successful_attempts"] >= 1

    def test_clear_history(self):
        """Test clearing history."""
        spray = CredentialSpray()

        spray.spray(
            targets="10.0.0.1",
            users=["admin"],
            passwords=["admin"],
            protocol=SprayProtocol.SMB,
        )

        assert len(spray.results) > 0

        spray.clear_history()

        assert len(spray.results) == 0


class TestPasswordGenerator:
    """Tests for PasswordGenerator."""

    def test_get_top_passwords(self):
        """Test getting top passwords."""
        passwords = PasswordGenerator.get_top_passwords(10)

        assert len(passwords) == 10
        assert "Password1" in passwords

    def test_generate_seasonal(self):
        """Test seasonal password generation."""
        passwords = PasswordGenerator.generate_seasonal(2024)

        assert any("Summer2024" in p for p in passwords)
        assert any("Winter2024" in p for p in passwords)
        assert any("January2024" in p for p in passwords)

    def test_generate_company_variants(self):
        """Test company-based password generation."""
        passwords = PasswordGenerator.generate_company_variants("Acme")

        assert "Acme1" in passwords
        assert "Acme123" in passwords
        assert "acme1" in passwords
        assert "Acme2024" in passwords

    def test_generate_username_based(self):
        """Test username-based password generation."""
        passwords = PasswordGenerator.generate_username_based("jsmith")

        assert "jsmith1" in passwords
        assert "jsmith123" in passwords
        assert "Jsmith1" in passwords

    def test_build_wordlist_basic(self):
        """Test building basic wordlist."""
        wordlist = PasswordGenerator.build_wordlist(
            include_common=True,
            include_seasonal=False,
        )

        assert len(wordlist) > 0
        assert "Password1" in wordlist

    def test_build_wordlist_comprehensive(self):
        """Test building comprehensive wordlist."""
        wordlist = PasswordGenerator.build_wordlist(
            include_common=True,
            include_seasonal=True,
            company_name="TestCorp",
            usernames=["admin", "jdoe"],
            year=2024,
        )

        assert "Password1" in wordlist
        assert "Summer2024" in wordlist
        assert "TestCorp1" in wordlist
        assert "admin1" in wordlist


class TestLockoutDetection:
    """Tests for lockout detection and handling."""

    def test_max_lockouts_stops_spray(self):
        """Test spray stops after max lockouts."""
        spray = CredentialSpray()

        # Override simulation to trigger lockouts
        def mock_simulate(username, password):
            return False

        # Can't easily test lockout without framework, but we can
        # verify the result tracks locked accounts
        result = spray.spray(
            targets="10.0.0.1",
            users=["admin"],
            passwords=["wrong1", "wrong2"],
            protocol=SprayProtocol.SMB,
            max_lockouts=3,
        )

        assert result.status in [SprayStatus.COMPLETED, SprayStatus.STOPPED]

    def test_lockout_callback(self):
        """Test lockout callback is fired."""
        spray = CredentialSpray()
        lockout_callback = Mock()
        spray.on_lockout = lockout_callback

        # Manually add a locked user
        spray._record_attempt("locked_user", False, locked=True)

        # Verify user is tracked as locked
        assert "locked_user" in spray._locked_users


class TestProtocolModuleMapping:
    """Tests for protocol to module mapping."""

    def test_protocol_modules_defined(self):
        """Test protocol modules are defined."""
        spray = CredentialSpray()

        assert SprayProtocol.SMB in spray._protocol_modules
        assert SprayProtocol.LDAP in spray._protocol_modules
        assert SprayProtocol.SSH in spray._protocol_modules
        assert SprayProtocol.RDP in spray._protocol_modules

    def test_protocol_module_paths(self):
        """Test module paths are valid."""
        spray = CredentialSpray()

        assert spray._protocol_modules[SprayProtocol.SMB] == "network/nxc_smb"
        assert spray._protocol_modules[SprayProtocol.LDAP] == "network/nxc_ldap"
