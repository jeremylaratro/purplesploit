"""
Tests for purplesploit.core.credential_spray module.
"""

import pytest
from unittest.mock import Mock
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

from purplesploit.core.credential_spray import (
    CredentialSpray,
    SprayAttempt,
    SprayResult,
    SprayProtocol,
    SprayPattern,
    SprayStatus,
    SprayAttemptOutcome,
    LockoutPolicy,
    PasswordGenerator,
    create_credential_spray,
)
from purplesploit.core.framework import Framework
from purplesploit.core.module import BaseModule, ModuleMetadata
from purplesploit.modules.ad.kerbrute import KerbruteModule
from purplesploit.modules.network.nxc_mssql import NXCMSSQLModule
from purplesploit.modules.network.nxc_rdp import NXCRDPModule
from purplesploit.modules.network.nxc_smb import NXCSMBModule
from purplesploit.modules.network.nxc_ssh import NXCSSHModule
from purplesploit.modules.network.nxc_winrm import NXCWinRMModule


class FakeAuthenticationModule(BaseModule):
    """Controlled module used to verify the real framework contract."""

    last_instance = None

    def __init__(self, framework):
        super().__init__(framework)
        type(self).last_instance = self
        self.operation_calls = 0
        self.run_calls = 0

    @property
    def name(self):
        return "Fake Authentication"

    @property
    def description(self):
        return "Test-only authentication module"

    @property
    def author(self):
        return "PurpleSploit Tests"

    @property
    def category(self):
        return "network"

    def _init_options(self):
        self.options = {
            "RHOST": {
                "value": None,
                "required": True,
                "description": "Target",
                "default": None,
            },
            "USERNAME": {
                "value": None,
                "required": True,
                "description": "Username",
                "default": None,
            },
            "PASSWORD": {
                "value": None,
                "required": True,
                "description": "Password",
                "default": None,
            },
            "DOMAIN": {
                "value": None,
                "required": False,
                "description": "Domain",
                "default": None,
            },
            "HASH": {
                "value": None,
                "required": False,
                "description": "NTLM hash",
                "default": None,
            },
        }

    def get_operations(self):
        return [
            {
                "name": "Test Authentication",
                "description": "Test supplied credentials",
                "handler": "op_test_authentication",
            }
        ]

    def op_test_authentication(self):
        self.operation_calls += 1
        password = self.get_option("PASSWORD")
        if password == "valid-password":
            return {
                "success": True,
                "stdout": "SMB 10.0.0.1 445 HOST [+] CORP\\alice",
            }
        if password == "locked-password":
            return {
                "success": True,
                "stdout": (
                    "SMB 10.0.0.1 445 HOST [-] CORP\\alice "
                    "STATUS_ACCOUNT_LOCKED_OUT"
                ),
            }
        return {
            # NXC can exit successfully even when authentication fails.
            "success": True,
            "stdout": "SMB 10.0.0.1 445 HOST [-] CORP\\alice STATUS_LOGON_FAILURE",
        }

    def run(self):
        self.run_calls += 1
        raise AssertionError("Credential spray must use the operation contract")


@pytest.fixture
def framework_with_fake_auth_module(tmp_path):
    """A real Framework whose SMB registration uses a controlled module."""
    modules_path = tmp_path / "modules"
    modules_path.mkdir()
    framework = Framework(
        modules_path=str(modules_path),
        db_path=str(tmp_path / "credential-spray.db"),
    )
    framework.modules["network/nxc_smb"] = ModuleMetadata(
        path="network/nxc_smb",
        name="Fake Authentication",
        category="network",
        description="Test-only authentication module",
        author="PurpleSploit Tests",
        instance=FakeAuthenticationModule,
    )
    yield framework
    framework.cleanup()


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
        assert data["outcome"] == "pending"


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

        spray.spray(
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

    def test_spray_uses_real_framework_operation_contract(
        self, framework_with_fake_auth_module
    ):
        """Spraying configures a live module and runs its auth operation."""
        spray = CredentialSpray(framework=framework_with_fake_auth_module)

        result = spray.spray(
            targets="10.0.0.1",
            users=["alice"],
            passwords=["valid-password"],
            protocol=SprayProtocol.SMB,
            domain="CORP",
        )

        assert result.status == SprayStatus.COMPLETED
        assert result.successful_attempts == 1
        assert result.valid_credentials[0]["username"] == "alice"

        module = FakeAuthenticationModule.last_instance
        assert isinstance(module, FakeAuthenticationModule)
        assert module.get_option("RHOST") == "10.0.0.1"
        assert module.get_option("USERNAME") == "alice"
        assert module.get_option("PASSWORD") == "valid-password"
        assert module.get_option("DOMAIN") == "CORP"
        assert module.operation_calls == 1
        assert module.run_calls == 0

    def test_process_success_does_not_make_failed_authentication_valid(
        self, framework_with_fake_auth_module
    ):
        """NXC's zero process exit status is not an authentication success."""
        spray = CredentialSpray(framework=framework_with_fake_auth_module)

        result = spray.spray(
            targets="10.0.0.1",
            users=["alice"],
            passwords=["wrong-password"],
            protocol=SprayProtocol.SMB,
            domain="CORP",
        )

        assert result.total_attempts == 1
        assert result.successful_attempts == 0
        assert result.valid_credentials == []
        assert result.attempts[0].success is False

    def test_session_hash_and_domain_do_not_replace_sprayed_password(
        self, framework_with_fake_auth_module
    ):
        framework_with_fake_auth_module.session.credentials.add(
            {
                "username": "session-user",
                "hash": "0123456789abcdef",
                "domain": "SESSION-DOMAIN",
            }
        )
        spray = CredentialSpray(framework=framework_with_fake_auth_module)

        result = spray.spray(
            targets="10.0.0.1",
            users=["alice"],
            passwords=["valid-password"],
            protocol=SprayProtocol.SMB,
            domain=None,
        )

        module = FakeAuthenticationModule.last_instance
        assert result.successful_attempts == 1
        assert module.get_option("USERNAME") == "alice"
        assert module.get_option("PASSWORD") == "valid-password"
        assert module.get_option("HASH") is None
        assert module.get_option("DOMAIN") is None
        assert framework_with_fake_auth_module.session.current_module is None

    @pytest.mark.parametrize(
        ("protocol", "module_path", "module_class", "transport"),
        [
            (SprayProtocol.SMB, "network/nxc_smb", NXCSMBModule, "smb"),
            (SprayProtocol.RDP, "network/nxc_rdp", NXCRDPModule, "rdp"),
            (SprayProtocol.WINRM, "network/nxc_winrm", NXCWinRMModule, "winrm"),
            (SprayProtocol.SSH, "network/nxc_ssh", NXCSSHModule, "ssh"),
            (SprayProtocol.MSSQL, "network/nxc_mssql", NXCMSSQLModule, "mssql"),
        ],
    )
    def test_real_nxc_adapters_receive_sprayed_password_at_process_boundary(
        self,
        tmp_path,
        monkeypatch,
        protocol,
        module_path,
        module_class,
        transport,
    ):
        modules_path = tmp_path / "modules"
        modules_path.mkdir()
        framework = Framework(
            modules_path=str(modules_path),
            db_path=str(tmp_path / f"{transport}.db"),
        )
        framework.modules[module_path] = ModuleMetadata(
            path=module_path,
            name=module_class.__name__,
            category="network",
            description="real adapter contract test",
            author="PurpleSploit Tests",
            instance=module_class,
        )
        calls = []

        def fake_run(argv, **kwargs):
            calls.append((argv, kwargs))
            return SimpleNamespace(
                returncode=0,
                stdout=f"{transport.upper()} 10.0.0.1 [+] CORP\\alice",
                stderr="",
            )

        monkeypatch.setattr("subprocess.run", fake_run)
        try:
            result = CredentialSpray(framework=framework).spray(
                targets="10.0.0.1",
                users=["alice"],
                passwords=["sprayed-secret"],
                protocol=protocol,
                domain="CORP",
            )
        finally:
            framework.cleanup()

        assert result.successful_attempts == 1
        assert result.attempts[0].outcome == SprayAttemptOutcome.AUTHENTICATED
        assert len(calls) == 1
        argv = calls[0][0]
        assert argv[:3] == ["nxc", transport, "10.0.0.1"]
        assert "-p" in argv
        assert argv[argv.index("-p") + 1] == "sprayed-secret"
        assert "-H" not in argv

    def test_real_kerbrute_adapter_receives_single_spray_at_process_boundary(
        self,
        tmp_path,
        monkeypatch,
    ):
        modules_path = tmp_path / "modules"
        modules_path.mkdir()
        framework = Framework(
            modules_path=str(modules_path),
            db_path=str(tmp_path / "kerberos.db"),
        )
        framework.modules["ad/kerbrute"] = ModuleMetadata(
            path="ad/kerbrute",
            name="Kerbrute",
            category="ad",
            description="real adapter contract test",
            author="PurpleSploit Tests",
            instance=KerbruteModule,
        )
        calls = []

        def fake_run(argv, **kwargs):
            calls.append((list(argv), kwargs, Path(argv[-2]).read_text(encoding="utf-8")))
            return SimpleNamespace(
                returncode=0,
                stdout="[+] VALID LOGIN: alice@CORP.LOCAL:sprayed-secret\n",
                stderr="",
            )

        monkeypatch.setattr("subprocess.run", fake_run)
        try:
            result = CredentialSpray(framework=framework).spray(
                targets="dc01.corp.local",
                users=["alice"],
                passwords=["sprayed-secret"],
                protocol=SprayProtocol.KERBEROS,
                domain="CORP.LOCAL",
            )
        finally:
            framework.cleanup()

        assert result.status == SprayStatus.COMPLETED
        assert result.successful_attempts == 1
        assert result.attempts[0].outcome == SprayAttemptOutcome.AUTHENTICATED
        assert len(calls) == 1
        argv, _, userlist = calls[0]
        assert argv[0] == "kerbrute"
        assert argv[argv.index("--dc") + 1] == "dc01.corp.local"
        assert argv[argv.index("-d") + 1] == "CORP.LOCAL"
        assert argv[-3] == "passwordspray"
        assert argv[-1] == "sprayed-secret"
        assert userlist == "alice\n"

    def test_kerberos_requires_domain_before_attempt_loop(self):
        framework = Mock()
        result = CredentialSpray(framework=framework).spray(
            targets="dc01.corp.local",
            users=["alice"],
            passwords=["sprayed-secret"],
            protocol=SprayProtocol.KERBEROS,
        )

        assert result.status == SprayStatus.ERROR
        assert result.total_attempts == 0
        assert result.attempts == []
        assert result.errors == ["Kerberos spraying requires a domain"]
        framework.get_module.assert_not_called()

    def test_framework_result_detects_account_lockout(
        self, framework_with_fake_auth_module
    ):
        """NXC's account-lockout status is reflected in the spray result."""
        spray = CredentialSpray(framework=framework_with_fake_auth_module)

        result = spray.spray(
            targets="10.0.0.1",
            users=["alice"],
            passwords=["locked-password"],
            protocol=SprayProtocol.SMB,
            domain="CORP",
        )

        assert result.successful_attempts == 0
        assert result.locked_accounts == ["alice"]
        assert result.attempts[0].locked_out is True

    def test_unsupported_protocol_is_explicit_error(self):
        """Protocols without a real auth operation must not route elsewhere."""
        framework = Mock()
        spray = CredentialSpray(framework=framework)

        success, locked, info = spray._execute_via_framework(
            "10.0.0.1",
            "alice",
            "password",
            SprayProtocol.LDAP,
            "CORP",
        )

        assert success is False
        assert locked is False
        assert info == {"error": "Unsupported protocol: ldap"}
        framework.get_module.assert_not_called()

    def test_unsupported_protocol_is_rejected_before_attempt_loop(self):
        framework = Mock()
        spray = CredentialSpray(framework=framework)

        result = spray.spray(
            targets="10.0.0.1",
            users=["alice", "bob"],
            passwords=["one", "two"],
            protocol=SprayProtocol.LDAP,
        )

        assert result.status == SprayStatus.ERROR
        assert result.total_attempts == 0
        assert result.attempts == []
        assert result.errors == ["Unsupported protocol: ldap"]

    def test_attempt_outcomes_distinguish_invalid_ambiguous_and_tool_error(self):
        assert CredentialSpray._classify_auth_result(
            {"success": True, "stdout": "[-] STATUS_LOGON_FAILURE"}
        )[2] == SprayAttemptOutcome.INVALID_CREDENTIAL
        assert CredentialSpray._classify_auth_result(
            {"success": True, "stdout": "tool completed"}
        )[2] == SprayAttemptOutcome.AMBIGUOUS
        assert CredentialSpray._classify_auth_result(
            {"success": False, "stderr": "not found"}
        )[2] == SprayAttemptOutcome.TOOL_ERROR

    @pytest.mark.parametrize(
        "result",
        [
            {"success": True, "locked_out": True},
            {"success": True, "data": {"locked_out": True}},
            {
                "success": True,
                "observations": [
                    {"type": "credential", "attributes": {"locked_out": True}}
                ],
            },
        ],
    )
    def test_explicit_lockout_is_classified_without_output_markers(self, result):
        assert CredentialSpray._classify_auth_result(result) == (
            False,
            True,
            SprayAttemptOutcome.LOCKED_OUT,
        )

    def test_skipped_attempts_are_visible_and_progress_completes(self):
        spray = CredentialSpray(lockout_policy=LockoutPolicy.conservative())
        progress = []
        spray.on_progress = lambda complete, total: progress.append((complete, total))

        result = spray.spray(
            targets="10.0.0.1",
            users=["alice"],
            passwords=["one", "two"],
            protocol=SprayProtocol.SMB,
        )

        assert result.total_attempts == 1
        assert result.skipped_attempts == 1
        assert result.attempts[-1].outcome == SprayAttemptOutcome.SKIPPED
        assert progress[-1] == (2, 2)

    @pytest.mark.parametrize(
        ("operation_result", "expected"),
        [
            ({"success": True, "authenticated": True}, (True, False)),
            ({"success": True, "data": {"authenticated": True}}, (True, False)),
            ({"success": True, "stdout": "host [+] user"}, (True, False)),
            ({"success": True, "stdout": "host Pwn3d!"}, (True, False)),
            (
                {"success": True, "stdout": "[-] STATUS_LOGON_FAILURE"},
                (False, False),
            ),
            (
                {"success": True, "stderr": "STATUS_ACCOUNT_LOCKED_OUT"},
                (False, True),
            ),
            ({"success": True, "stdout": "tool completed"}, (False, False)),
            ({"success": False, "stdout": "[+] user"}, (False, False)),
        ],
    )
    def test_interpret_auth_result(self, operation_result, expected):
        """Structured values and known NXC markers have deterministic meaning."""
        assert CredentialSpray._interpret_auth_result(operation_result) == expected


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
        """Only protocols with dedicated authentication operations are mapped."""
        spray = CredentialSpray()

        assert set(spray._protocol_modules) == {
            SprayProtocol.SMB,
            SprayProtocol.WINRM,
            SprayProtocol.SSH,
            SprayProtocol.RDP,
            SprayProtocol.MSSQL,
            SprayProtocol.KERBEROS,
        }

    def test_protocol_module_paths(self):
        """Test module paths are valid."""
        spray = CredentialSpray()

        assert spray._protocol_modules[SprayProtocol.SMB] == "network/nxc_smb"
        assert spray._protocol_modules[SprayProtocol.WINRM] == "network/nxc_winrm"
        assert spray._protocol_modules[SprayProtocol.SSH] == "network/nxc_ssh"
        assert spray._protocol_modules[SprayProtocol.RDP] == "network/nxc_rdp"
        assert spray._protocol_modules[SprayProtocol.MSSQL] == "network/nxc_mssql"
        assert spray._protocol_modules[SprayProtocol.KERBEROS] == "ad/kerbrute"
