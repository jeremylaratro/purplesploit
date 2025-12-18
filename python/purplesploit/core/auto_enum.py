"""
Smart Auto-Enumeration Pipeline for PurpleSploit.

Provides intelligent, service-driven enumeration that automatically chains
modules based on discovered services, credentials, and findings.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable, Set
from enum import Enum
from datetime import datetime
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class EnumPhase(Enum):
    """Enumeration pipeline phases."""
    DISCOVERY = "discovery"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"


class EnumScope(Enum):
    """Enumeration scope levels."""
    PASSIVE = "passive"      # No direct interaction
    LIGHT = "light"          # Quick scans, low noise
    NORMAL = "normal"        # Standard enumeration
    AGGRESSIVE = "aggressive"  # Full enumeration, high noise
    STEALTH = "stealth"      # Slow, evasive


@dataclass
class ServiceRule:
    """
    Rule for service-based module selection.

    When a service is discovered, these rules determine which
    modules to run next.
    """
    service: str                    # Service name (smb, http, ldap, etc.)
    ports: List[int] = field(default_factory=list)  # Optional specific ports
    modules: List[str] = field(default_factory=list)  # Modules to run
    operations: Dict[str, str] = field(default_factory=dict)  # module: operation
    requires_auth: bool = False     # Requires credentials
    phase: EnumPhase = EnumPhase.ENUMERATION
    priority: int = 5              # 1-10, higher = run first
    conditions: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class EnumResult:
    """Result from an enumeration step."""
    module: str
    operation: Optional[str]
    target: str
    success: bool
    output: str = ""
    error: str = ""
    duration: float = 0.0
    discovered_services: List[Dict] = field(default_factory=list)
    discovered_credentials: List[Dict] = field(default_factory=list)
    discovered_users: List[str] = field(default_factory=list)
    findings: List[Dict] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EnumProgress:
    """Progress tracking for enumeration pipeline."""
    phase: EnumPhase
    current_step: str
    total_steps: int
    completed_steps: int
    current_target: str
    start_time: datetime
    services_found: int = 0
    credentials_found: int = 0
    findings_found: int = 0


class AutoEnumPipeline:
    """
    Smart Auto-Enumeration Pipeline.

    Intelligently chains modules based on discovered services and results.
    Adapts execution path based on what's found during enumeration.
    """

    # Default service rules - what to run when a service is found
    DEFAULT_SERVICE_RULES = [
        # SMB Enumeration
        ServiceRule(
            service="smb",
            ports=[445, 139],
            modules=["network/nxc_smb"],
            operations={"network/nxc_smb": "Enumerate Shares"},
            phase=EnumPhase.ENUMERATION,
            priority=8,
        ),
        ServiceRule(
            service="smb",
            ports=[445, 139],
            modules=["network/nxc_smb"],
            operations={"network/nxc_smb": "Enumerate Users"},
            phase=EnumPhase.ENUMERATION,
            priority=7,
        ),
        ServiceRule(
            service="smb",
            ports=[445, 139],
            modules=["network/nxc_smb"],
            operations={"network/nxc_smb": "Test Authentication"},
            requires_auth=True,
            phase=EnumPhase.ENUMERATION,
            priority=6,
        ),

        # LDAP Enumeration (Active Directory)
        ServiceRule(
            service="ldap",
            ports=[389, 636, 3268, 3269],
            modules=["network/nxc_ldap"],
            operations={"network/nxc_ldap": "Domain Info"},
            phase=EnumPhase.ENUMERATION,
            priority=9,
        ),
        ServiceRule(
            service="ldap",
            ports=[389, 636],
            modules=["network/nxc_ldap"],
            operations={"network/nxc_ldap": "Enumerate Users"},
            requires_auth=True,
            phase=EnumPhase.ENUMERATION,
            priority=7,
        ),

        # Kerberos (AD attacks)
        ServiceRule(
            service="kerberos",
            ports=[88],
            modules=["ad/kerbrute"],
            operations={"ad/kerbrute": "User Enumeration"},
            phase=EnumPhase.ENUMERATION,
            priority=8,
        ),

        # HTTP/HTTPS Web Services
        ServiceRule(
            service="http",
            ports=[80, 8080, 8000, 8888],
            modules=["web/httpx"],
            phase=EnumPhase.ENUMERATION,
            priority=9,
        ),
        ServiceRule(
            service="https",
            ports=[443, 8443],
            modules=["web/httpx"],
            phase=EnumPhase.ENUMERATION,
            priority=9,
        ),
        ServiceRule(
            service="http",
            ports=[80, 8080],
            modules=["web/feroxbuster"],
            phase=EnumPhase.ENUMERATION,
            priority=6,
        ),
        ServiceRule(
            service="http",
            ports=[80, 443],
            modules=["recon/nuclei"],
            operations={"recon/nuclei": "Critical/High Only"},
            phase=EnumPhase.ENUMERATION,
            priority=7,
        ),

        # SSH
        ServiceRule(
            service="ssh",
            ports=[22],
            modules=["network/nxc_ssh"],
            operations={"network/nxc_ssh": "Test Authentication"},
            requires_auth=True,
            phase=EnumPhase.ENUMERATION,
            priority=5,
        ),

        # RDP
        ServiceRule(
            service="rdp",
            ports=[3389],
            modules=["network/nxc_rdp"],
            operations={"network/nxc_rdp": "RDP Screenshot"},
            phase=EnumPhase.ENUMERATION,
            priority=5,
        ),

        # WinRM
        ServiceRule(
            service="winrm",
            ports=[5985, 5986],
            modules=["network/nxc_winrm"],
            operations={"network/nxc_winrm": "Test Authentication"},
            requires_auth=True,
            phase=EnumPhase.ENUMERATION,
            priority=6,
        ),

        # MSSQL
        ServiceRule(
            service="mssql",
            ports=[1433],
            modules=["network/nxc_mssql"],
            operations={"network/nxc_mssql": "Test Authentication"},
            requires_auth=True,
            phase=EnumPhase.ENUMERATION,
            priority=6,
        ),

        # DNS
        ServiceRule(
            service="dns",
            ports=[53],
            modules=["recon/dns"],
            operations={"recon/dns": "Zone Transfer"},
            phase=EnumPhase.ENUMERATION,
            priority=8,
        ),

        # FTP
        ServiceRule(
            service="ftp",
            ports=[21],
            modules=[],  # Check for anonymous access
            phase=EnumPhase.ENUMERATION,
            priority=5,
        ),
    ]

    def __init__(self, framework, scope: EnumScope = EnumScope.NORMAL):
        """
        Initialize auto-enumeration pipeline.

        Args:
            framework: Reference to PurpleSploit framework
            scope: Enumeration aggressiveness level
        """
        self.framework = framework
        self.scope = scope
        self.service_rules = list(self.DEFAULT_SERVICE_RULES)
        self._lock = threading.RLock()

        # State tracking
        self.results: List[EnumResult] = []
        self.discovered_services: Dict[str, Set[str]] = {}  # target: {services}
        self.discovered_credentials: List[Dict] = []
        self.discovered_users: Dict[str, List[str]] = {}  # target: [users]
        self.executed_modules: Set[str] = set()  # "module:operation:target"

        # Callbacks
        self.on_progress: Optional[Callable[[EnumProgress], None]] = None
        self.on_service_found: Optional[Callable[[str, str, int], None]] = None
        self.on_credential_found: Optional[Callable[[Dict], None]] = None
        self.on_finding: Optional[Callable[[Dict], None]] = None
        self.on_step_complete: Optional[Callable[[EnumResult], None]] = None

        # Control
        self._stop_requested = False
        self._pause_requested = False

    def add_service_rule(self, rule: ServiceRule) -> None:
        """Add a custom service rule."""
        self.service_rules.append(rule)
        # Re-sort by priority
        self.service_rules.sort(key=lambda r: r.priority, reverse=True)

    def run(
        self,
        targets: List[str],
        phases: Optional[List[EnumPhase]] = None,
        parallel: bool = False,
        max_workers: int = 4,
    ) -> Dict[str, Any]:
        """
        Run smart auto-enumeration on targets.

        Args:
            targets: List of target IPs or CIDRs
            phases: Phases to run (default: all)
            parallel: Run target enumeration in parallel
            max_workers: Max parallel workers

        Returns:
            Summary of enumeration results
        """
        if phases is None:
            phases = [EnumPhase.DISCOVERY, EnumPhase.ENUMERATION]

        self._stop_requested = False
        self._pause_requested = False
        start_time = datetime.now()

        logger.info(f"Starting auto-enumeration on {len(targets)} target(s)")
        logger.info(f"Scope: {self.scope.value}, Phases: {[p.value for p in phases]}")

        # Phase 1: Discovery
        if EnumPhase.DISCOVERY in phases:
            self._run_discovery_phase(targets)

        if self._stop_requested:
            return self._build_summary(start_time)

        # Phase 2: Service-based enumeration
        if EnumPhase.ENUMERATION in phases:
            if parallel and len(targets) > 1:
                self._run_enumeration_parallel(targets, max_workers)
            else:
                for target in targets:
                    if self._stop_requested:
                        break
                    self._run_enumeration_phase(target)

        if self._stop_requested:
            return self._build_summary(start_time)

        # Phase 3: Exploitation (if credentials found)
        if EnumPhase.EXPLOITATION in phases and self.discovered_credentials:
            self._run_exploitation_phase(targets)

        return self._build_summary(start_time)

    def stop(self) -> None:
        """Stop enumeration gracefully."""
        self._stop_requested = True
        logger.info("Stop requested, finishing current step...")

    def pause(self) -> None:
        """Pause enumeration."""
        self._pause_requested = True

    def resume(self) -> None:
        """Resume paused enumeration."""
        self._pause_requested = False

    def _run_discovery_phase(self, targets: List[str]) -> None:
        """Run discovery phase - port scanning."""
        logger.info("=== DISCOVERY PHASE ===")

        for target in targets:
            if self._stop_requested:
                return

            self._update_progress(EnumPhase.DISCOVERY, "Port Scan", target)

            # Run nmap for service discovery
            result = self._run_module(
                target=target,
                module_path="recon/nmap",
                operation=self._get_nmap_operation(),
            )

            if result and result.success:
                # Extract discovered services
                self._process_discovery_results(target, result)

    def _get_nmap_operation(self) -> str:
        """Get appropriate nmap operation based on scope."""
        scope_operations = {
            EnumScope.PASSIVE: None,  # No nmap in passive
            EnumScope.STEALTH: "Stealth Scan",
            EnumScope.LIGHT: "Quick Scan",
            EnumScope.NORMAL: "Service Version",
            EnumScope.AGGRESSIVE: "Full Scan",
        }
        return scope_operations.get(self.scope, "Service Version")

    def _process_discovery_results(self, target: str, result: EnumResult) -> None:
        """Process nmap results and extract services."""
        # Initialize target services
        if target not in self.discovered_services:
            self.discovered_services[target] = set()

        # Extract from result
        for service_info in result.discovered_services:
            service = service_info.get("service", "unknown")
            port = service_info.get("port")

            self.discovered_services[target].add(service)

            # Add to framework session
            if self.framework:
                self.framework.session.services.add_service(target, service, port)

            # Callback
            if self.on_service_found:
                self.on_service_found(target, service, port)

            logger.info(f"  Found: {service} on port {port}")

    def _run_enumeration_phase(self, target: str) -> None:
        """Run enumeration phase for a single target."""
        logger.info(f"=== ENUMERATION PHASE: {target} ===")

        services = self.discovered_services.get(target, set())
        if not services:
            logger.warning(f"No services discovered for {target}, skipping enumeration")
            return

        # Get applicable rules sorted by priority
        rules = self._get_applicable_rules(target, services, EnumPhase.ENUMERATION)

        for rule in rules:
            if self._stop_requested:
                return

            while self._pause_requested:
                import time
                time.sleep(0.5)

            # Skip if requires auth and we don't have creds
            if rule.requires_auth and not self._has_credentials():
                logger.debug(f"Skipping {rule.modules} - requires authentication")
                continue

            for module_path in rule.modules:
                operation = rule.operations.get(module_path)

                # Check if already executed
                exec_key = f"{module_path}:{operation}:{target}"
                if exec_key in self.executed_modules:
                    continue

                self._update_progress(
                    EnumPhase.ENUMERATION,
                    f"{module_path} ({operation or 'default'})",
                    target
                )

                result = self._run_module(
                    target=target,
                    module_path=module_path,
                    operation=operation,
                )

                if result:
                    self.executed_modules.add(exec_key)
                    self._process_enum_results(target, result)

    def _run_enumeration_parallel(self, targets: List[str], max_workers: int) -> None:
        """Run enumeration on multiple targets in parallel."""
        logger.info(f"Running parallel enumeration with {max_workers} workers")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self._run_enumeration_phase, target): target
                for target in targets
            }

            for future in as_completed(futures):
                target = futures[future]
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error enumerating {target}: {e}")

    def _run_exploitation_phase(self, targets: List[str]) -> None:
        """Run exploitation phase using discovered credentials."""
        logger.info("=== EXPLOITATION PHASE ===")

        for target in targets:
            if self._stop_requested:
                return

            services = self.discovered_services.get(target, set())
            rules = self._get_applicable_rules(target, services, EnumPhase.EXPLOITATION)

            for rule in rules:
                if rule.requires_auth and self._has_credentials():
                    for module_path in rule.modules:
                        operation = rule.operations.get(module_path)

                        # Try with each discovered credential
                        for cred in self.discovered_credentials:
                            self._update_progress(
                                EnumPhase.EXPLOITATION,
                                f"{module_path} with {cred.get('username', 'unknown')}",
                                target
                            )

                            result = self._run_module(
                                target=target,
                                module_path=module_path,
                                operation=operation,
                                credential=cred,
                            )

                            if result and result.success:
                                self._process_enum_results(target, result)
                                # Stop trying more creds if successful
                                break

    def _get_applicable_rules(
        self,
        target: str,
        services: Set[str],
        phase: EnumPhase,
    ) -> List[ServiceRule]:
        """Get rules applicable to discovered services."""
        applicable = []

        for rule in self.service_rules:
            if rule.phase != phase:
                continue

            # Check if service matches
            if rule.service in services:
                # Check conditions
                if self._check_rule_conditions(rule, target):
                    applicable.append(rule)

        # Sort by priority
        return sorted(applicable, key=lambda r: r.priority, reverse=True)

    def _check_rule_conditions(self, rule: ServiceRule, target: str) -> bool:
        """Check if rule conditions are met."""
        for condition in rule.conditions:
            cond_type = condition.get("type")

            if cond_type == "has_users":
                if target not in self.discovered_users or not self.discovered_users[target]:
                    return False

            elif cond_type == "has_credentials":
                if not self.discovered_credentials:
                    return False

            elif cond_type == "finding_exists":
                # Check if a specific finding type exists
                finding_type = condition.get("finding_type")
                if not any(f.get("type") == finding_type for f in self._get_findings()):
                    return False

        return True

    def _run_module(
        self,
        target: str,
        module_path: str,
        operation: Optional[str] = None,
        credential: Optional[Dict] = None,
    ) -> Optional[EnumResult]:
        """Run a single module and return results."""
        start_time = datetime.now()

        try:
            # Load module
            module = self.framework.use_module(module_path)
            if not module:
                logger.error(f"Module not found: {module_path}")
                return None

            # Set target
            if hasattr(module, 'set_option'):
                # Determine target type
                if self._is_url(target):
                    module.set_option('URL', target)
                else:
                    module.set_option('RHOST', target)

            # Set credentials if provided
            if credential:
                if 'USERNAME' in module.options:
                    module.set_option('USERNAME', credential.get('username', ''))
                if 'PASSWORD' in module.options:
                    module.set_option('PASSWORD', credential.get('password', ''))
                if 'DOMAIN' in module.options:
                    module.set_option('DOMAIN', credential.get('domain', ''))
                if 'HASH' in module.options and credential.get('hash'):
                    module.set_option('HASH', credential.get('hash'))

            # Auto-populate from context
            module.auto_set_from_context()

            # Select operation if specified
            if operation and hasattr(module, 'set_operation'):
                module.set_operation(operation)
            elif operation and hasattr(module, 'get_operations'):
                ops = module.get_operations()
                for op in ops:
                    if op.get('name') == operation:
                        module.current_operation = op
                        break

            # Run module
            result = self.framework.run_module(module)

            duration = (datetime.now() - start_time).total_seconds()

            # Build EnumResult
            enum_result = EnumResult(
                module=module_path,
                operation=operation,
                target=target,
                success=result.get('success', False),
                output=result.get('output', result.get('stdout', '')),
                error=result.get('error', result.get('stderr', '')),
                duration=duration,
                raw_data=result,
            )

            # Extract discovered data
            enum_result.discovered_services = result.get('services', [])
            enum_result.discovered_credentials = result.get('credentials', [])
            enum_result.discovered_users = result.get('users', [])
            enum_result.findings = result.get('findings', [])

            # Store result
            self.results.append(enum_result)

            # Callback
            if self.on_step_complete:
                self.on_step_complete(enum_result)

            return enum_result

        except Exception as e:
            logger.error(f"Error running {module_path}: {e}")
            return EnumResult(
                module=module_path,
                operation=operation,
                target=target,
                success=False,
                error=str(e),
                duration=(datetime.now() - start_time).total_seconds(),
            )

    def _process_enum_results(self, target: str, result: EnumResult) -> None:
        """Process enumeration results and update state."""
        # Process new services
        for service_info in result.discovered_services:
            service = service_info.get("service")
            port = service_info.get("port")

            if target not in self.discovered_services:
                self.discovered_services[target] = set()
            self.discovered_services[target].add(service)

            if self.on_service_found:
                self.on_service_found(target, service, port)

        # Process credentials
        for cred in result.discovered_credentials:
            self.discovered_credentials.append(cred)

            # Add to framework
            if self.framework:
                self.framework.add_credential(
                    username=cred.get('username'),
                    password=cred.get('password'),
                    domain=cred.get('domain'),
                    hash_value=cred.get('hash'),
                )

            if self.on_credential_found:
                self.on_credential_found(cred)

            logger.info(f"  Credential found: {cred.get('username', 'unknown')}")

        # Process users
        if result.discovered_users:
            if target not in self.discovered_users:
                self.discovered_users[target] = []
            self.discovered_users[target].extend(result.discovered_users)
            logger.info(f"  Users found: {len(result.discovered_users)}")

        # Process findings
        for finding in result.findings:
            if self.on_finding:
                self.on_finding(finding)

    def _has_credentials(self) -> bool:
        """Check if any credentials have been discovered."""
        return len(self.discovered_credentials) > 0

    def _get_findings(self) -> List[Dict]:
        """Get all findings from results."""
        findings = []
        for result in self.results:
            findings.extend(result.findings)
        return findings

    def _is_url(self, target: str) -> bool:
        """Check if target is a URL."""
        return target.startswith('http://') or target.startswith('https://')

    def _update_progress(self, phase: EnumPhase, step: str, target: str) -> None:
        """Update progress and invoke callback."""
        if self.on_progress:
            progress = EnumProgress(
                phase=phase,
                current_step=step,
                total_steps=len(self.service_rules),
                completed_steps=len(self.results),
                current_target=target,
                start_time=datetime.now(),
                services_found=sum(len(s) for s in self.discovered_services.values()),
                credentials_found=len(self.discovered_credentials),
                findings_found=len(self._get_findings()),
            )
            self.on_progress(progress)

    def _build_summary(self, start_time: datetime) -> Dict[str, Any]:
        """Build summary of enumeration results."""
        duration = (datetime.now() - start_time).total_seconds()

        successful = [r for r in self.results if r.success]
        failed = [r for r in self.results if not r.success]

        return {
            "success": len(failed) == 0 or len(successful) > 0,
            "duration_seconds": duration,
            "targets_scanned": len(self.discovered_services),
            "modules_executed": len(self.results),
            "successful_executions": len(successful),
            "failed_executions": len(failed),
            "services_discovered": {
                target: list(services)
                for target, services in self.discovered_services.items()
            },
            "credentials_discovered": len(self.discovered_credentials),
            "users_discovered": sum(len(u) for u in self.discovered_users.values()),
            "findings": len(self._get_findings()),
            "results": [
                {
                    "module": r.module,
                    "operation": r.operation,
                    "target": r.target,
                    "success": r.success,
                    "duration": r.duration,
                }
                for r in self.results
            ],
        }


def create_auto_enum(
    framework,
    scope: str = "normal",
) -> AutoEnumPipeline:
    """
    Factory function to create auto-enumeration pipeline.

    Args:
        framework: PurpleSploit framework instance
        scope: Enumeration scope (passive, light, normal, aggressive, stealth)

    Returns:
        Configured AutoEnumPipeline
    """
    try:
        enum_scope = EnumScope(scope.lower())
    except ValueError:
        enum_scope = EnumScope.NORMAL

    return AutoEnumPipeline(framework, scope=enum_scope)
