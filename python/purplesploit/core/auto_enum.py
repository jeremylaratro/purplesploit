"""
Smart Auto-Enumeration Pipeline for PurpleSploit.

Provides intelligent, service-driven enumeration that automatically chains
modules based on discovered services, credentials, and findings.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable, Set
from enum import Enum
from datetime import datetime
from pathlib import Path
import logging
import threading
import ipaddress
from urllib.parse import urlsplit
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class MissingEnumContext(ValueError):
    """A rule cannot run with the available endpoint context."""


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

    SERVICE_ALIASES = {
        "domain": "dns",
        "kerberos-sec": "kerberos",
        "ldapssl": "ldap",
        "ldaps": "ldap",
        "microsoft-ds": "smb",
        "ms-sql-s": "mssql",
        "ms-wbt-server": "rdp",
        "netbios-ssn": "smb",
        "ssl/http": "https",
        "ssl/https": "https",
        "http-proxy": "http",
        "wsman": "winrm",
    }

    # Default service rules - what to run when a service is found
    DEFAULT_SERVICE_RULES = [
        # SMB Enumeration
        ServiceRule(
            service="smb",
            ports=[445, 139],
            modules=["network/nxc_smb"],
            operations={"network/nxc_smb": "List Shares"},
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
            operations={"network/nxc_ldap": "Check LDAP Signing"},
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
            service="https",
            ports=[443, 8443],
            modules=["web/feroxbuster"],
            phase=EnumPhase.ENUMERATION,
            priority=6,
        ),
        ServiceRule(
            service="http",
            ports=[80, 8080],
            modules=["recon/nuclei"],
            operations={"recon/nuclei": "Critical/High Only"},
            phase=EnumPhase.ENUMERATION,
            priority=7,
        ),
        ServiceRule(
            service="https",
            ports=[443, 8443],
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
            operations={"network/nxc_rdp": "Check NLA Status"},
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
            operations={"recon/dns": "Zone Transfer (AXFR)"},
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

    def __init__(
        self,
        framework,
        scope: EnumScope = EnumScope.NORMAL,
        *,
        run_dir: Optional[Path] = None,
        timeout_s: float = 600,
    ):
        """
        Initialize auto-enumeration pipeline.

        Args:
            framework: Reference to PurpleSploit framework
            scope: Enumeration aggressiveness level
        """
        self.framework = framework
        self.scope = scope
        self.run_dir = Path(run_dir) if run_dir is not None else None
        self.timeout_s = timeout_s
        self.service_rules = list(self.DEFAULT_SERVICE_RULES)
        self._lock = threading.RLock()

        # State tracking
        self.results: List[EnumResult] = []
        self.discovered_services: Dict[str, Set[str]] = {}  # target: {services}
        # Full endpoint records retain the identity discarded by the legacy name index.
        self.discovered_endpoints: Dict[str, List[Dict[str, Any]]] = {}
        self.discovered_credentials: List[Dict] = []
        self.discovered_users: Dict[str, List[str]] = {}  # target: [users]
        self.executed_modules: Set[str] = set()  # "module:operation:target"
        self.skipped_rules: List[Dict[str, Any]] = []

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
        seeds: Optional[List[Dict[str, Any]]] = None,
        skip_discovery: bool = False,
    ) -> Dict[str, Any]:
        """
        Run smart auto-enumeration on targets.

        Args:
            targets: List of target IPs or CIDRs
            phases: Phases to run (default: all)
            parallel: Run target enumeration in parallel
            max_workers: Max parallel workers
            seeds: Endpoint observation dictionaries to import before discovery
            skip_discovery: Enumerate available inventory without running Nmap

        Returns:
            Summary of enumeration results
        """
        if phases is None:
            phases = [EnumPhase.DISCOVERY, EnumPhase.ENUMERATION]

        self._stop_requested = False
        self._pause_requested = False
        start_time = datetime.now()
        self.ingest_seeds(seeds or [], source="external", targets=targets)
        self._ingest_context_seeds(targets)

        logger.info(f"Starting auto-enumeration on {len(targets)} target(s)")
        logger.info(f"Scope: {self.scope.value}, Phases: {[p.value for p in phases]}")

        # Phase 1: Discovery
        if EnumPhase.DISCOVERY in phases:
            discovery_targets = [
                target for target in targets
                if not any(self._target_matches(host, target) for host in self.discovered_endpoints)
            ]
            if not skip_discovery:
                self._run_discovery_phase(discovery_targets)

        if self._stop_requested:
            return self._build_summary(start_time)

        # Phase 2: Service-based enumeration
        if EnumPhase.ENUMERATION in phases:
            enumeration_targets = targets
            if self.discovered_services:
                # CIDR discovery produces concrete hosts. Enumerate those hosts rather
                # than passing the original network expression to service modules.
                enumeration_targets = [
                    host for host in self.discovered_services
                    if any(self._target_matches(host, target) for target in targets)
                ]

            if parallel and len(enumeration_targets) > 1:
                self._run_enumeration_parallel(enumeration_targets, max_workers)
            else:
                for target in enumeration_targets:
                    if self._stop_requested:
                        break
                    self._run_enumeration_phase(target)

        if self._stop_requested:
            return self._build_summary(start_time)

        # Phase 3: Exploitation (if credentials found)
        if EnumPhase.EXPLOITATION in phases and self._has_credentials():
            self._run_exploitation_phase([
                host for host in self.discovered_services
                if any(self._target_matches(host, target) for target in targets)
            ])

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

    @staticmethod
    def _is_concrete_target(target: str) -> bool:
        """Reject Nmap network expressions while allowing hosts and URLs."""
        host = urlsplit(target).hostname if "://" in target else target
        if not host or any(char in host for char in ("/", ",", "*", " ")):
            return False
        # Nmap supports ranges in any IPv4 octet, as well as full IP ranges.
        return not ("-" in host and all(char in "0123456789.-" for char in host))

    @classmethod
    def _target_matches(cls, host: str, expression: str) -> bool:
        if host == expression:
            return True
        host = urlsplit(host).hostname if "://" in host else host
        expression = urlsplit(expression).hostname if "://" in expression else expression
        if host == expression:
            return True
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(expression, strict=False)
        except ValueError:
            pass
        if host and expression:
            if "-" in expression:
                try:
                    lower, upper = expression.split("-", 1)
                    return ipaddress.ip_address(lower) <= ipaddress.ip_address(host) <= ipaddress.ip_address(upper)
                except (ValueError, TypeError):
                    pass
            parts, ranges = host.split("."), expression.split(".")
            if len(parts) == len(ranges) == 4:
                try:
                    return all(
                        int(spec.split("-")[0]) <= int(part) <= int(spec.split("-")[-1])
                        for part, spec in zip(parts, ranges)
                    )
                except ValueError:
                    pass
        return False

    def ingest_seeds(
        self, seeds: Any, source: str = "external", targets: Optional[List[str]] = None,
    ) -> int:
        """Import endpoint observations without discarding metadata or provenance.

        Accept endpoint dictionaries or containers with endpoints/observations/hosts/
        services. Session and database imports use the same normalization path.
        """
        if isinstance(seeds, dict):
            for key in ("endpoints", "observations", "hosts"):
                if isinstance(seeds.get(key), list):
                    inherited = {name: value for name, value in seeds.items() if name != key}
                    return self.ingest_seeds(
                        [{**inherited, **entry} for entry in seeds[key] if isinstance(entry, dict)],
                        source, targets,
                    )
            seeds = [seeds]
        if not isinstance(seeds, (list, tuple)):
            return 0
        count = 0
        for observation in seeds:
            if not isinstance(observation, dict):
                continue
            host = str(observation.get("target") or observation.get("ip") or observation.get("host") or observation.get("url") or "")
            if isinstance(observation.get("services"), (list, dict)):
                entries = self._service_collection_to_endpoints(observation["services"], host)
                entries = [{**{k: v for k, v in observation.items() if k != "services"}, **entry} for entry in entries]
            else:
                entries = [observation]
            for entry in entries:
                endpoint = self._normalize_endpoint(entry, host)
                if not endpoint or endpoint["port"] is None or endpoint["service"] == "unknown":
                    continue
                if targets and not any(self._target_matches(endpoint["target"], target) for target in targets):
                    continue
                endpoint.setdefault("source", source)
                self._remember_endpoint(endpoint, endpoint["target"])
                count += 1
        return count

    def _ingest_context_seeds(self, targets: List[str]) -> None:
        for host, services in self._snapshot_session_services().items():
            for service, ports in services.items():
                self.ingest_seeds([
                    {"target": host, "service": service, "port": port}
                    for port in ports
                ], source="session", targets=targets)
        database = getattr(self.framework, "database", None)
        getter = getattr(database, "get_services", None)
        if callable(getter):
            try:
                self.ingest_seeds(getter(), source="database", targets=targets)
            except Exception as exc:
                logger.warning("Could not read service seeds: %s", exc)

    def _skip_rule(self, target: str, module: str, operation: Optional[str], reason: str) -> None:
        with self._lock:
            self.skipped_rules.append({
                "target": target, "module": module, "operation": operation,
                "status": "skipped", "reason": reason,
            })

    def _run_discovery_phase(self, targets: List[str]) -> None:
        """Run discovery phase - port scanning."""
        logger.info("=== DISCOVERY PHASE ===")

        if self.scope is EnumScope.PASSIVE:
            logger.info("Passive scope selected; skipping active Nmap discovery")
            return

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

    def _get_nmap_operation(self) -> Optional[str]:
        """Get appropriate nmap operation based on scope."""
        scope_operations = {
            EnumScope.PASSIVE: None,  # No nmap in passive
            EnumScope.STEALTH: "Stealth Scan",
            EnumScope.LIGHT: "Fast Scan",
            EnumScope.NORMAL: "Default Scan",
            EnumScope.AGGRESSIVE: "Aggressive Scan",
        }
        return scope_operations.get(self.scope, "Default Scan")

    def _process_discovery_results(self, target: str, result: EnumResult) -> None:
        """Process nmap results and extract services."""
        for service_info in result.discovered_services:
            endpoint = self._normalize_endpoint(service_info, target)
            if endpoint is None:
                continue
            service_target = endpoint["target"]
            service = endpoint["service"]
            port = endpoint["port"]
            protocol = endpoint["protocol"]

            self._remember_endpoint(endpoint, service_target)

            # Add to framework session
            if self.framework:
                self.framework.session.services.add_service(service_target, service, port)

            # Callback
            if self.on_service_found:
                self.on_service_found(service_target, service, port)

            endpoint = f"{port}/{protocol}" if protocol else str(port)
            logger.info(f"  Found: {service} on {service_target}:{endpoint}")

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
            credentials = self._available_credentials(target) if rule.requires_auth else []
            if rule.requires_auth and not credentials:
                logger.debug(f"Skipping {rule.modules} - requires authentication")
                for module_path in rule.modules:
                    self._skip_rule(target, module_path, rule.operations.get(module_path), "No usable credentials available")
                continue

            matching_endpoints = self._get_rule_endpoints(target, rule)
            for endpoint in matching_endpoints:
                port = endpoint.get("port") if endpoint else None
                protocol = endpoint.get("protocol") if endpoint else None

                for module_path in rule.modules:
                    operation = rule.operations.get(module_path)

                    # Include endpoint identity so a service on distinct ports is
                    # not accidentally collapsed into one execution.
                    exec_key = f"{module_path}:{operation}:{target}:{port}:{protocol}"
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
                        port=port,
                        service=rule.service,
                        credential=credentials[0] if credentials else None,
                        endpoint=endpoint,
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
            if not self._is_concrete_target(target):
                continue
            if self._stop_requested:
                return

            services = self.discovered_services.get(target, set())
            rules = self._get_applicable_rules(target, services, EnumPhase.EXPLOITATION)

            for rule in rules:
                if rule.requires_auth and self._has_credentials():
                    for module_path in rule.modules:
                        operation = rule.operations.get(module_path)

                        # Try with each discovered credential
                        for cred in self._available_credentials(target):
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
                endpoints = self.discovered_endpoints.get(target, [])
                if rule.ports and endpoints and not self._get_rule_endpoints(target, rule):
                    continue
                # Check conditions
                if self._check_rule_conditions(rule, target):
                    applicable.append(rule)

        # Sort by priority
        return sorted(applicable, key=lambda r: r.priority, reverse=True)

    def _get_rule_endpoints(
        self,
        target: str,
        rule: ServiceRule,
    ) -> List[Optional[Dict[str, Any]]]:
        """Return concrete endpoints matching a service rule.

        Older callers may seed only ``discovered_services``. In that case a
        single ``None`` endpoint preserves the previous one-execution behavior.
        """
        known = self.discovered_endpoints.get(target, [])
        if not known:
            return [None]

        matches = []
        for endpoint in known:
            if endpoint.get("service") != rule.service:
                continue
            if rule.ports and endpoint.get("port") not in rule.ports:
                continue
            matches.append(endpoint)
        return matches

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

    def _resolve_operation(self, module: Any, operation_name: str) -> Optional[Dict[str, Any]]:
        """Resolve an operation name to the module's registered operation object."""
        finder = getattr(self.framework, "find_operation", None)
        if callable(finder):
            resolved = finder(module, operation_name)
            # Lightweight framework doubles may expose an unconfigured
            # MagicMock attribute. Only the canonical dict/None contract is
            # authoritative; otherwise retain the compatibility resolver.
            if isinstance(resolved, dict) or resolved is None:
                return resolved
        operations = module.get_operations()
        for operation in operations:
            if operation.get("name") == operation_name:
                return operation

        requested = operation_name.casefold()
        for operation in operations:
            if str(operation.get("name", "")).casefold() == requested:
                return operation
        return None

    def _set_module_target(
        self,
        module: Any,
        target: str,
        port: Optional[int] = None,
        service: Optional[str] = None,
        endpoint: Optional[Dict[str, Any]] = None,
        credential: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Populate the concrete target option used by a live module instance."""
        options = module.options if isinstance(module.options, dict) else {}

        def is_required(name: str) -> bool:
            value = options.get(name, {})
            return isinstance(value, dict) and bool(value.get("required"))

        endpoint = endpoint or {}
        host = urlsplit(target).hostname if self._is_url(target) else target
        attributes = endpoint.get("attributes") if isinstance(endpoint.get("attributes"), dict) else {}
        metadata = endpoint.get("metadata") if isinstance(endpoint.get("metadata"), dict) else {}
        context_domain = endpoint.get("domain") or attributes.get("domain") or metadata.get("domain") or (credential or {}).get("domain")
        if not context_domain and "DOMAIN" in options:
            configured_domain = module.get_option("DOMAIN")
            if isinstance(configured_domain, str):
                context_domain = configured_domain
        if not context_domain:
            context_domain = next((cred.get("domain") for cred in self._available_credentials(target) if cred.get("domain")), None)
        if context_domain and self._is_ip(str(context_domain)):
            context_domain = None
        if "DOMAIN" in options:
            if context_domain:
                module.set_option("DOMAIN", context_domain)
            elif is_required("DOMAIN"):
                raise MissingEnumContext("Domain required; no domain name is available for this endpoint")
        for name in ("DC", "DCIP", "NAMESERVER"):
            if name in options:
                module.set_option(name, endpoint.get(name.lower()) or host)

        if self._is_url(target) and "URL" in options and not is_required("TARGET"):
            target_option = "URL"
            target_value = target
        elif is_required("URL"):
            target_option = "URL"
            target_value = self._build_service_url(target, port, service)
        elif is_required("TARGET"):
            target_option = "TARGET"
            target_value = self._build_service_url(target, port, service) if service in {"http", "https"} else target
        elif is_required("RHOST"):
            target_option = "RHOST"
            target_value = host
        else:
            target_option = next(
                (name for name in ("RHOST", "TARGET", "URL") if name in options),
                None,
            )
            target_value = (
                self._build_service_url(target, port, service)
                if target_option == "URL" or (target_option == "TARGET" and service in {"http", "https"})
                else host
            )

        if target_option:
            module.set_option(target_option, target_value)

        if port is not None:
            if "RPORT" in options:
                module.set_option("RPORT", port)
            if target_option == "TARGET" and "PORTS" in options:
                module.set_option("PORTS", str(port))

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def _build_service_url(
        target: str,
        port: Optional[int],
        service: Optional[str],
    ) -> str:
        """Build a URL for URL-only modules from a discovered endpoint."""
        if target.startswith(("http://", "https://")):
            return target

        scheme = "https" if service == "https" or port in {443, 8443} else "http"
        authority = f"[{target}]" if ":" in target and not target.startswith("[") else target
        default_port = 443 if scheme == "https" else 80
        suffix = f":{port}" if port is not None and port != default_port else ""
        return f"{scheme}://{authority}{suffix}"

    def _extract_discovered_services(
        self,
        result: Dict[str, Any],
        default_target: str,
    ) -> List[Dict[str, Any]]:
        """Extract endpoint identities from native and Nmap result structures."""
        endpoints: List[Dict[str, Any]] = []

        parsed = result.get("parsed")
        host_endpoints = self._host_results_to_endpoints(result.get("hosts"))
        if isinstance(parsed, dict):
            host_endpoints.extend(self._host_results_to_endpoints(parsed.get("hosts")))
        if host_endpoints or result.get("xml_parsed"):
            return self._deduplicate_endpoints(host_endpoints)

        endpoints.extend(
            self._service_collection_to_endpoints(
                result.get("services"), default_target
            )
        )

        parsed = result.get("parsed")
        if isinstance(parsed, dict):
            endpoints.extend(
                self._service_collection_to_endpoints(
                    parsed.get("services"), default_target
                )
            )
            endpoints.extend(self._host_results_to_endpoints(parsed.get("hosts")))

        endpoints.extend(self._host_results_to_endpoints(result.get("hosts")))
        return self._deduplicate_endpoints(endpoints)

    def _host_results_to_endpoints(self, hosts: Any) -> List[Dict[str, Any]]:
        """Convert Nmap XML-style host results to endpoint records."""
        if not isinstance(hosts, list):
            return []

        endpoints = []
        for host in hosts:
            if not isinstance(host, dict):
                continue
            host_target = host.get("ip") or host.get("target") or host.get("host")
            if not host_target:
                continue
            endpoints.extend(
                self._service_collection_to_endpoints(
                    host.get("services"), str(host_target)
                )
            )
        return endpoints

    def _service_collection_to_endpoints(
        self,
        services: Any,
        default_target: str,
    ) -> List[Dict[str, Any]]:
        """Convert list- or keyed-dictionary service collections to endpoints."""
        if isinstance(services, list):
            entries = [(None, entry) for entry in services]
        elif isinstance(services, dict):
            entries = list(services.items())
        else:
            return []

        endpoints = []
        for key, value in entries:
            if not isinstance(value, dict):
                continue
            endpoint = self._normalize_endpoint(value, default_target, key)
            if endpoint:
                endpoints.append(endpoint)
        return endpoints

    def _normalize_endpoint(
        self,
        service_info: Dict[str, Any],
        default_target: str,
        key: Optional[Any] = None,
    ) -> Optional[Dict[str, Any]]:
        """Normalize one discovered service without losing its endpoint identity."""
        raw_service = str(
            service_info.get("service")
            or service_info.get("name")
            or "unknown"
        ).strip().lower()
        service = self.SERVICE_ALIASES.get(raw_service, raw_service)
        target = str(
            service_info.get("target")
            or service_info.get("ip")
            or service_info.get("host")
            or service_info.get("url")
            or default_target
        )
        if not self._is_concrete_target(target):
            return None
        if service_info.get("tunnel") == "ssl" and service == "http":
            service = "https"

        port = service_info.get("port")
        protocol = service_info.get("protocol")
        key_text = str(key) if key is not None else ""
        if "/" in key_text:
            key_port, key_protocol = key_text.split("/", 1)
            if port is None:
                port = key_port
            if not protocol:
                protocol = key_protocol
        elif port is None and key_text:
            port = key_text

        if isinstance(port, str) and "/" in port:
            port_text, port_protocol = port.split("/", 1)
            port = port_text
            if not protocol:
                protocol = port_protocol
        try:
            port = int(port) if port is not None else None
        except (TypeError, ValueError):
            return None

        if port is None and self._is_url(target):
            port = urlsplit(target).port or (443 if target.startswith("https://") else 80)
        if port is not None and not 1 <= port <= 65535:
            return None
        endpoint = {
            **service_info,
            "target": target,
            "service": service,
            "port": port,
            "protocol": str(protocol).lower() if protocol else None,
            "version": service_info.get("version", ""),
        }
        if raw_service != service:
            endpoint["raw_service"] = raw_service
        return endpoint

    @staticmethod
    def _deduplicate_endpoints(
        endpoints: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Deduplicate endpoints by host/service/port/protocol while retaining metadata."""
        unique: List[Dict[str, Any]] = []
        for endpoint in endpoints:
            existing = next(
                (
                    candidate
                    for candidate in unique
                    if candidate.get("target") == endpoint.get("target")
                    and candidate.get("service") == endpoint.get("service")
                    and candidate.get("port") == endpoint.get("port")
                    and (
                        candidate.get("protocol") == endpoint.get("protocol")
                        or not candidate.get("protocol")
                        or not endpoint.get("protocol")
                    )
                ),
                None,
            )
            if existing is None:
                unique.append(endpoint)
            else:
                for field, value in endpoint.items():
                    if value not in (None, "") and existing.get(field) in (None, ""):
                        existing[field] = value
        return unique

    def _extract_nmap_xml_services(
        self,
        module: Any,
        target: str,
    ) -> List[Dict[str, Any]]:
        """Read the completed Nmap XML output when the module emitted one."""
        if not hasattr(module, "parse_xml_output"):
            return []

        output_file = module.get_option("OUTPUT_FILE")
        if not output_file:
            target_name = target.replace("/", "_").replace(":", "_")
            output_file = f"nmap_{target_name}"

        output_path = Path(str(output_file))
        candidates = [
            output_path if output_path.suffix == ".xml" else Path(f"{output_path}.xml")
        ]
        if module.get_option("OUTPUT_FORMAT") == "xml":
            candidates = [output_path]
        for xml_path in candidates:
            if not xml_path.is_file():
                continue
            parsed = module.parse_xml_output(str(xml_path))
            if isinstance(parsed, dict):
                return self._host_results_to_endpoints(parsed.get("hosts"))
        return []

    def _snapshot_session_services(self) -> Dict[str, Dict[str, Set[int]]]:
        """Copy the lightweight service index without depending on mock attributes."""
        try:
            raw = self.framework.session.services.services
        except AttributeError:
            return {}
        if not isinstance(raw, dict):
            return {}

        snapshot: Dict[str, Dict[str, Set[int]]] = {}
        for target, services in raw.items():
            if not isinstance(services, dict):
                continue
            snapshot[str(target)] = {
                str(service): set(ports) if isinstance(ports, (list, set, tuple)) else set()
                for service, ports in services.items()
            }
        return snapshot

    def _session_service_delta(
        self,
        before: Dict[str, Dict[str, Set[int]]],
        after: Dict[str, Dict[str, Set[int]]],
    ) -> List[Dict[str, Any]]:
        """Recover host identities imported by Nmap when XML was not returned."""
        endpoints = []
        for target, services in after.items():
            for service, ports in services.items():
                previous_ports = before.get(target, {}).get(service, set())
                for port in ports - previous_ports:
                    endpoint = self._normalize_endpoint(
                        {"service": service, "port": port}, target
                    )
                    if endpoint:
                        endpoints.append(endpoint)
        return endpoints

    def _run_module(
        self,
        target: str,
        module_path: str,
        operation: Optional[str] = None,
        credential: Optional[Dict] = None,
        port: Optional[int] = None,
        service: Optional[str] = None,
        endpoint: Optional[Dict[str, Any]] = None,
    ) -> Optional[EnumResult]:
        """Run a single module and return results."""
        start_time = datetime.now()

        try:
            # Keep the interactive session's current module and option context intact.
            instantiate = getattr(self.framework, "instantiate_module", None)
            if callable(instantiate):
                module = instantiate(module_path)
            else:
                metadata = self.framework.get_module(module_path)
                module = metadata.instance(self.framework) if metadata else None
            if not module:
                raise ValueError(f"Module not found: {module_path}")

            # Framework validation re-populates context. Freeze this instance's
            # credential context so an explicitly selected empty password cannot
            # be replaced with a different interactive credential on that pass.
            context = module.get_context()
            if isinstance(context, dict):
                context = dict(context)
                selected_credential = credential or context.get("current_cred")
                if isinstance(selected_credential, dict):
                    selected_credential = dict(selected_credential)
                    if self._is_ip(str(selected_credential.get("domain", ""))):
                        selected_credential.pop("domain", None)
                    context["current_cred"] = selected_credential
                module.get_context = lambda: context
            module.auto_set_from_context()
            self._set_module_target(module, target, port=port, service=service,
                                    endpoint=endpoint, credential=credential)

            # Discovery must return completed output that can be parsed. Nmap's
            # interactive default is background execution, so override it here.
            if module_path == "recon/nmap" and "BACKGROUND" in module.options:
                module.set_option("BACKGROUND", "false")

            # Set credentials if provided
            if credential:
                if 'USERNAME' in module.options:
                    module.set_option('USERNAME', credential.get('username', ''))
                if 'PASSWORD' in module.options:
                    module.set_option('PASSWORD', credential.get('password', ''))
                if 'DOMAIN' in module.options and credential.get('domain') and not self._is_ip(str(credential['domain'])):
                    module.set_option('DOMAIN', credential['domain'])
                if 'HASH' in module.options and credential.get('hash'):
                    module.set_option('HASH', credential.get('hash'))

            # The execution request supplies a bounded process deadline and an
            # isolated artifact directory to every external-tool adapter, even
            # though AutoEnum invokes the live module instance directly.
            from purplesploit.core.execution import ExecutionRequest
            request = ExecutionRequest(
                module_path=module_path,
                operation_name=operation,
                timeout_s=self.timeout_s,
                background=False,
                stdin="none",
            )
            if self.run_dir is not None:
                request.run_dir = str(self.run_dir / request.request_id)
            module.execution_request = request

            if operation:
                selected_operation = self._resolve_operation(module, operation)
                if selected_operation is None:
                    available = ", ".join(
                        op.get("name", "") for op in module.get_operations()
                    )
                    raise ValueError(
                        f"Operation not found for {module_path}: {operation}. "
                        f"Available operations: {available or 'none'}"
                    )
                result = self.framework.run_operation(module, selected_operation)
            else:
                result = self.framework.run_module(module)

            if not isinstance(result, dict):
                result = {"success": False, "error": "Module returned a non-dictionary result"}
            if module_path == "recon/nmap" and result.get("background"):
                result = {
                    **result,
                    "success": False,
                    "error": "Nmap discovery returned before scan completion",
                }

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
            enum_result.discovered_services = self._extract_discovered_services(
                result, target
            )
            if module_path == "recon/nmap" and result.get("success"):
                enum_result.discovered_services.extend(
                    self._extract_nmap_xml_services(module, target)
                )
                enum_result.discovered_services = self._deduplicate_endpoints(
                    enum_result.discovered_services
                )
            enum_result.discovered_credentials = result.get('credentials', [])
            enum_result.discovered_users = result.get('users', [])
            enum_result.findings = result.get('findings', [])

            # Store result
            with self._lock:
                self.results.append(enum_result)

            # Callback
            if self.on_step_complete:
                self.on_step_complete(enum_result)

            return enum_result

        except MissingEnumContext as exc:
            self._skip_rule(target, module_path, operation, str(exc))
            return None
        except Exception as e:
            logger.error(f"Error running {module_path}: {e}")
            failed = EnumResult(
                module=module_path,
                operation=operation,
                target=target,
                success=False,
                error=str(e),
                duration=(datetime.now() - start_time).total_seconds(),
            )
            with self._lock:
                self.results.append(failed)
            if self.on_step_complete:
                self.on_step_complete(failed)
            return failed

    def _process_enum_results(self, target: str, result: EnumResult) -> None:
        """Process enumeration results and update state."""
        # Process new services
        for service_info in result.discovered_services:
            endpoint = self._normalize_endpoint(service_info, target)
            if endpoint is None:
                continue
            service_target = endpoint["target"]
            service = endpoint["service"]
            port = endpoint["port"]
            self._remember_endpoint(endpoint, service_target)

            if self.on_service_found:
                self.on_service_found(service_target, service, port)

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

    def _remember_endpoint(
        self,
        endpoint: Dict[str, Any],
        default_target: str,
    ) -> None:
        """Store both the legacy service-name index and the full endpoint record."""
        target = str(endpoint.get("target") or default_target)
        service = str(endpoint.get("service") or "unknown")
        endpoint = {**endpoint, "target": target, "service": service}

        self.discovered_services.setdefault(target, set()).add(service)
        known = self.discovered_endpoints.setdefault(target, [])
        existing = next(
            (
                item
                for item in known
                if item.get("target") == target
                and item.get("service") == service
                and item.get("port") == endpoint.get("port")
                and (
                    item.get("protocol") == endpoint.get("protocol")
                    or not item.get("protocol")
                    or not endpoint.get("protocol")
                )
            ),
            None,
        )
        if existing is None:
            known.append(endpoint)
        else:
            for field, value in endpoint.items():
                if value not in (None, "") and existing.get(field) in (None, ""):
                    existing[field] = value

    def _has_credentials(self) -> bool:
        """Check if any credentials have been discovered."""
        return bool(self._available_credentials())

    def _available_credentials(self, target: Optional[str] = None) -> List[Dict[str, Any]]:
        """Read actual usable credentials without changing session selection."""
        candidates = list(self.discovered_credentials)
        session = getattr(self.framework, "session", None)
        manager = getattr(session, "credentials", None)
        session_credentials = getattr(manager, "credentials", None)
        if isinstance(session_credentials, list):
            candidates.extend(session_credentials)
        current_getter = getattr(session, "get_current_credential", None)
        if callable(current_getter):
            current = current_getter()
            if isinstance(current, dict):
                candidates.insert(0, current)
        usable = []
        for cred in candidates:
            if not isinstance(cred, dict) or not cred.get("username"):
                continue
            if cred.get("authenticated") is False:
                continue
            if cred.get("credential_type") in {
                "offline_hash", "krb5asrep", "krb5tgs",
            }:
                continue
            if not (cred.get("hash") or ("password" in cred and cred["password"] is not None)):
                continue
            if target and cred.get("target") and not self._target_matches(target, str(cred["target"])):
                continue
            if cred not in usable:
                usable.append(cred)
        return usable

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
            "success": not failed and not self.skipped_rules and not self._stop_requested,
            "status": ("stopped" if self._stop_requested else "partial" if successful and (failed or self.skipped_rules) else "failed" if failed else "skipped" if self.skipped_rules and not successful else "completed"),
            "partial": bool(successful and (failed or self.skipped_rules)),
            "skipped_rules": list(self.skipped_rules),
            "duration_seconds": duration,
            "targets_scanned": len(self.discovered_services),
            "modules_executed": len(self.results),
            "successful_executions": len(successful),
            "failed_executions": len(failed),
            "services_discovered": {
                target: list(services)
                for target, services in self.discovered_services.items()
            },
            "service_endpoints": [
                endpoint
                for target_endpoints in self.discovered_endpoints.values()
                for endpoint in target_endpoints
            ],
            "credentials_discovered": len(self.discovered_credentials),
            "users_discovered": sum(len(u) for u in self.discovered_users.values()),
            "findings": len(self._get_findings()),
            "results": [
                {
                    "module": r.module,
                    "operation": r.operation,
                    "target": r.target,
                    "success": r.success,
                    "error": r.error,
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
