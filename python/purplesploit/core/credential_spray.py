"""
Credential Spray Intelligence Module.

Provides smart credential spraying with lockout avoidance, spray patterns,
timing controls, and comprehensive result tracking.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable
from datetime import datetime, timedelta
import time
import threading
import queue
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

        # Callbacks
        self.on_attempt: Callable[[SprayAttempt], None] | None = None
        self.on_success: Callable[[SprayAttempt], None] | None = None
        self.on_lockout: Callable[[str], None] | None = None
        self.on_progress: Callable[[int, int], None] | None = None
        self.on_complete: Callable[[SprayResult], None] | None = None

        # Module mapping for protocols
        self._protocol_modules = {
            SprayProtocol.SMB: "network/nxc_smb",
            SprayProtocol.LDAP: "network/nxc_ldap",
            SprayProtocol.WINRM: "network/nxc_winrm",
            SprayProtocol.SSH: "network/nxc_ssh",
            SprayProtocol.RDP: "network/nxc_rdp",
            SprayProtocol.MSSQL: "network/nxc_mssql",
            SprayProtocol.KERBEROS: "network/nxc_ldap",  # Uses LDAP with Kerberos
        }

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
        result_id = f"spray:{hashlib.md5(f'{targets}{users}{datetime.now()}'.encode()).hexdigest()[:12]}"

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
            else:
                # Simulation mode for testing
                attempt.success = self._simulate_attempt(username, password)
                attempt.locked_out = False

        except Exception as e:
            attempt.error = str(e)
            attempt.success = False

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
            return False, False, {"error": f"Unsupported protocol: {protocol}"}

        try:
            # Get module
            module = self.framework.get_module(module_path)
            if not module:
                return False, False, {"error": f"Module not found: {module_path}"}

            # Set parameters
            module.set_option("target", target)
            module.set_option("username", username)
            module.set_option("password", password)
            if domain:
                module.set_option("domain", domain)

            # Select authentication operation
            auth_ops = [op for op in module.operations if "auth" in op.lower() or "login" in op.lower()]
            if auth_ops:
                module.select_operation(auth_ops[0])

            # Execute
            result = module.run()

            # Parse result
            success = result.get("success", False)
            locked = "locked" in str(result.get("output", "")).lower()

            return success, locked, result

        except Exception as e:
            return False, False, {"error": str(e)}

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
