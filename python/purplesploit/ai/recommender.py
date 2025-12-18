"""
Module Recommender for PurpleSploit

Provides intelligent module recommendations based on discovered services,
current context, and penetration testing best practices.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Set
from enum import Enum
from datetime import datetime


class Priority(Enum):
    """Recommendation priority levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Recommendation:
    """A module recommendation with context."""
    module_path: str
    operation: Optional[str] = None
    priority: Priority = Priority.MEDIUM
    reason: str = ""
    prerequisites: List[str] = field(default_factory=list)
    expected_outcome: str = ""
    risk_level: str = "low"  # low, medium, high
    tags: List[str] = field(default_factory=list)
    confidence: float = 0.8  # 0-1 confidence score

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module_path,
            "operation": self.operation,
            "priority": self.priority.value,
            "reason": self.reason,
            "prerequisites": self.prerequisites,
            "expected_outcome": self.expected_outcome,
            "risk_level": self.risk_level,
            "tags": self.tags,
            "confidence": self.confidence,
        }


# Service to module mapping with priorities and context
SERVICE_MODULE_MAP = {
    "smb": {
        "modules": [
            {
                "path": "smb/enumeration",
                "priority": Priority.HIGH,
                "reason": "SMB enumeration can reveal shares, users, and system info",
                "prereqs": [],
                "tags": ["enumeration", "anonymous"],
            },
            {
                "path": "smb/shares",
                "priority": Priority.HIGH,
                "reason": "Check for readable shares with sensitive data",
                "prereqs": [],
                "tags": ["enumeration", "data-exposure"],
            },
            {
                "path": "network/nxc_smb",
                "priority": Priority.HIGH,
                "reason": "Comprehensive SMB testing with NetExec",
                "prereqs": [],
                "tags": ["enumeration", "auth-testing"],
            },
            {
                "path": "impacket/secretsdump",
                "priority": Priority.CRITICAL,
                "reason": "Dump secrets if admin credentials available",
                "prereqs": ["admin_creds"],
                "tags": ["post-exploit", "credential-dump"],
            },
        ],
        "quick_wins": ["anonymous_shares", "null_session", "guest_access"],
    },
    "ldap": {
        "modules": [
            {
                "path": "network/nxc_ldap",
                "priority": Priority.HIGH,
                "reason": "LDAP enumeration reveals AD structure and users",
                "prereqs": [],
                "tags": ["enumeration", "active-directory"],
            },
            {
                "path": "impacket/asreproast",
                "priority": Priority.HIGH,
                "reason": "Find accounts without Kerberos pre-auth",
                "prereqs": ["user_list"],
                "tags": ["attack", "kerberos"],
            },
        ],
        "quick_wins": ["anonymous_bind", "null_base_dn"],
    },
    "http": {
        "modules": [
            {
                "path": "web/httpx",
                "priority": Priority.HIGH,
                "reason": "HTTP probe for technology fingerprinting",
                "prereqs": [],
                "tags": ["enumeration", "fingerprint"],
            },
            {
                "path": "web/feroxbuster",
                "priority": Priority.HIGH,
                "reason": "Directory and file discovery",
                "prereqs": [],
                "tags": ["enumeration", "content-discovery"],
            },
            {
                "path": "recon/nuclei",
                "priority": Priority.CRITICAL,
                "reason": "Vulnerability scanning with community templates",
                "prereqs": [],
                "tags": ["vuln-scan", "automated"],
            },
            {
                "path": "web/sqlmap",
                "priority": Priority.MEDIUM,
                "reason": "SQL injection testing on discovered forms",
                "prereqs": ["forms_found"],
                "tags": ["attack", "injection"],
            },
        ],
        "quick_wins": ["default_creds", "exposed_panels", "backup_files"],
    },
    "https": {
        "modules": [
            {
                "path": "web/httpx",
                "priority": Priority.HIGH,
                "reason": "HTTPS probe and certificate analysis",
                "prereqs": [],
                "tags": ["enumeration", "fingerprint"],
            },
            {
                "path": "web/feroxbuster",
                "priority": Priority.HIGH,
                "reason": "Directory discovery on HTTPS endpoint",
                "prereqs": [],
                "tags": ["enumeration", "content-discovery"],
            },
            {
                "path": "recon/nuclei",
                "priority": Priority.CRITICAL,
                "reason": "Comprehensive vulnerability scanning",
                "prereqs": [],
                "tags": ["vuln-scan", "automated"],
            },
        ],
        "quick_wins": ["ssl_issues", "certificate_info"],
    },
    "kerberos": {
        "modules": [
            {
                "path": "ad/kerbrute",
                "priority": Priority.HIGH,
                "reason": "Kerberos user enumeration and password spraying",
                "prereqs": [],
                "tags": ["enumeration", "brute-force"],
            },
            {
                "path": "impacket/asreproast",
                "priority": Priority.HIGH,
                "reason": "AS-REP roasting for accounts without pre-auth",
                "prereqs": ["user_list"],
                "tags": ["attack", "credential-harvest"],
            },
            {
                "path": "impacket/kerberoast",
                "priority": Priority.HIGH,
                "reason": "Kerberoasting for service account hashes",
                "prereqs": ["valid_creds"],
                "tags": ["attack", "credential-harvest"],
            },
        ],
        "quick_wins": ["asrep_roastable", "spn_accounts"],
    },
    "dns": {
        "modules": [
            {
                "path": "recon/dns",
                "priority": Priority.MEDIUM,
                "reason": "DNS enumeration and zone transfer attempt",
                "prereqs": [],
                "tags": ["enumeration", "recon"],
            },
            {
                "path": "osint/dnsdumpster",
                "priority": Priority.MEDIUM,
                "reason": "Passive DNS reconnaissance",
                "prereqs": [],
                "tags": ["osint", "passive"],
            },
        ],
        "quick_wins": ["zone_transfer", "subdomain_enum"],
    },
    "ssh": {
        "modules": [
            {
                "path": "network/nxc_ssh",
                "priority": Priority.MEDIUM,
                "reason": "SSH authentication testing",
                "prereqs": ["valid_creds"],
                "tags": ["auth-testing", "access"],
            },
        ],
        "quick_wins": ["weak_creds", "key_auth"],
    },
    "rdp": {
        "modules": [
            {
                "path": "network/nxc_rdp",
                "priority": Priority.MEDIUM,
                "reason": "RDP authentication and NLA check",
                "prereqs": ["valid_creds"],
                "tags": ["auth-testing", "access"],
            },
        ],
        "quick_wins": ["nla_disabled", "bluekeep"],
    },
    "winrm": {
        "modules": [
            {
                "path": "network/nxc_winrm",
                "priority": Priority.HIGH,
                "reason": "WinRM execution with credentials",
                "prereqs": ["valid_creds"],
                "tags": ["access", "execution"],
            },
            {
                "path": "impacket/wmiexec",
                "priority": Priority.HIGH,
                "reason": "Remote execution via WMI",
                "prereqs": ["admin_creds"],
                "tags": ["access", "execution"],
            },
        ],
        "quick_wins": ["local_admin"],
    },
    "mssql": {
        "modules": [
            {
                "path": "network/nxc_mssql",
                "priority": Priority.HIGH,
                "reason": "MSSQL enumeration and access testing",
                "prereqs": [],
                "tags": ["enumeration", "database"],
            },
        ],
        "quick_wins": ["sa_account", "xp_cmdshell"],
    },
    "ftp": {
        "modules": [
            {
                "path": "recon/nmap",
                "operation": "ftp_anon",
                "priority": Priority.MEDIUM,
                "reason": "Check for anonymous FTP access",
                "prereqs": [],
                "tags": ["enumeration", "anonymous"],
            },
        ],
        "quick_wins": ["anonymous_access", "writable"],
    },
}

# Port to service mapping
PORT_SERVICE = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    88: "kerberos",
    110: "pop3",
    111: "rpc",
    135: "msrpc",
    139: "smb",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "smb",
    464: "kerberos",
    587: "smtp",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5985: "winrm",
    5986: "winrm",
    6379: "redis",
    8080: "http",
    8443: "https",
    9200: "elasticsearch",
    27017: "mongodb",
}


class ModuleRecommender:
    """
    Intelligent module recommender based on context and services.

    Analyzes the current penetration test state and recommends
    the most effective modules to run next.
    """

    def __init__(self, framework=None):
        self.framework = framework
        self._completed_modules: Set[str] = set()
        self._findings: List[Dict] = []

    def get_recommendations(
        self,
        services: Optional[List[Dict]] = None,
        credentials: Optional[List[Dict]] = None,
        findings: Optional[List[Dict]] = None,
        completed: Optional[List[str]] = None,
        max_results: int = 10,
    ) -> List[Recommendation]:
        """
        Get module recommendations based on current context.

        Args:
            services: List of discovered services [{port, service, target}]
            credentials: List of available credentials
            findings: List of current findings
            completed: List of already-run module paths
            max_results: Maximum recommendations to return

        Returns:
            List of prioritized recommendations
        """
        recommendations = []

        # Load context from framework if available
        if self.framework and not services:
            services = self._get_services_from_framework()
        if self.framework and not credentials:
            credentials = self._get_credentials_from_framework()

        services = services or []
        credentials = credentials or []
        findings = findings or []
        completed = set(completed or [])

        # Track what we have
        has_creds = len(credentials) > 0
        has_admin = any(c.get("is_admin") for c in credentials)
        has_user_list = any(f.get("type") == "user_list" for f in findings)

        # Analyze each service
        for svc in services:
            service_name = self._normalize_service(svc)
            if not service_name:
                continue

            service_config = SERVICE_MODULE_MAP.get(service_name, {})
            modules = service_config.get("modules", [])

            for mod_config in modules:
                module_path = mod_config["path"]

                # Skip if already completed
                if module_path in completed:
                    continue

                # Check prerequisites
                prereqs = mod_config.get("prereqs", [])
                prereqs_met = self._check_prerequisites(
                    prereqs, has_creds, has_admin, has_user_list
                )

                if not prereqs_met:
                    continue

                # Create recommendation
                rec = Recommendation(
                    module_path=module_path,
                    operation=mod_config.get("operation"),
                    priority=mod_config.get("priority", Priority.MEDIUM),
                    reason=mod_config.get("reason", ""),
                    prerequisites=prereqs,
                    expected_outcome=self._get_expected_outcome(module_path),
                    risk_level=self._assess_risk(module_path),
                    tags=mod_config.get("tags", []),
                    confidence=self._calculate_confidence(svc, mod_config),
                )
                recommendations.append(rec)

        # Sort by priority and confidence
        recommendations.sort(
            key=lambda r: (
                list(Priority).index(r.priority),
                -r.confidence
            )
        )

        # Deduplicate by module path
        seen = set()
        unique_recs = []
        for rec in recommendations:
            if rec.module_path not in seen:
                seen.add(rec.module_path)
                unique_recs.append(rec)

        return unique_recs[:max_results]

    def get_quick_wins(
        self,
        services: Optional[List[Dict]] = None,
    ) -> List[Recommendation]:
        """
        Get quick win recommendations - low-hanging fruit.

        Args:
            services: Discovered services

        Returns:
            List of quick win recommendations
        """
        quick_wins = []

        if self.framework and not services:
            services = self._get_services_from_framework()

        services = services or []

        for svc in services:
            service_name = self._normalize_service(svc)
            if not service_name:
                continue

            service_config = SERVICE_MODULE_MAP.get(service_name, {})
            wins = service_config.get("quick_wins", [])

            for win in wins:
                rec = Recommendation(
                    module_path=f"quick_win/{win}",
                    priority=Priority.HIGH,
                    reason=f"Quick win check: {win.replace('_', ' ')}",
                    tags=["quick-win", service_name],
                    confidence=0.9,
                )
                quick_wins.append(rec)

        return quick_wins

    def get_recommendations_for_service(
        self,
        service: str,
        has_creds: bool = False,
        has_admin: bool = False,
    ) -> List[Recommendation]:
        """
        Get recommendations for a specific service type.

        Args:
            service: Service name (smb, http, etc.)
            has_creds: Whether credentials are available
            has_admin: Whether admin credentials are available

        Returns:
            List of recommendations for the service
        """
        service = service.lower()
        service_config = SERVICE_MODULE_MAP.get(service, {})
        modules = service_config.get("modules", [])

        recommendations = []
        for mod_config in modules:
            prereqs = mod_config.get("prereqs", [])
            prereqs_met = self._check_prerequisites(
                prereqs, has_creds, has_admin, False
            )

            if not prereqs_met:
                continue

            rec = Recommendation(
                module_path=mod_config["path"],
                operation=mod_config.get("operation"),
                priority=mod_config.get("priority", Priority.MEDIUM),
                reason=mod_config.get("reason", ""),
                prerequisites=prereqs,
                tags=mod_config.get("tags", []),
            )
            recommendations.append(rec)

        return recommendations

    def suggest_next_module(
        self,
        current_phase: str = "enumeration",
    ) -> Optional[Recommendation]:
        """
        Suggest the single best next module to run.

        Args:
            current_phase: Current pentest phase

        Returns:
            Best recommendation or None
        """
        recommendations = self.get_recommendations()
        if recommendations:
            return recommendations[0]
        return None

    def _normalize_service(self, svc: Dict) -> Optional[str]:
        """Normalize service info to service name."""
        if isinstance(svc, str):
            return svc.lower()

        # Try service name first
        service = svc.get("service", "").lower()
        if service in SERVICE_MODULE_MAP:
            return service

        # Try port mapping
        port = svc.get("port")
        if port and port in PORT_SERVICE:
            return PORT_SERVICE[port]

        # Try to extract from service name
        for known_service in SERVICE_MODULE_MAP.keys():
            if known_service in service:
                return known_service

        return None

    def _check_prerequisites(
        self,
        prereqs: List[str],
        has_creds: bool,
        has_admin: bool,
        has_user_list: bool,
    ) -> bool:
        """Check if prerequisites are met."""
        for prereq in prereqs:
            if prereq == "valid_creds" and not has_creds:
                return False
            if prereq == "admin_creds" and not has_admin:
                return False
            if prereq == "user_list" and not has_user_list:
                return False
        return True

    def _get_expected_outcome(self, module_path: str) -> str:
        """Get expected outcome description for a module."""
        outcomes = {
            "smb/enumeration": "Discover shares, users, and system information",
            "smb/shares": "Find accessible shares and sensitive files",
            "network/nxc_smb": "Test authentication and enumerate SMB",
            "network/nxc_ldap": "Enumerate AD users, groups, and policies",
            "web/feroxbuster": "Discover hidden directories and files",
            "web/httpx": "Fingerprint web technologies",
            "recon/nuclei": "Identify known vulnerabilities",
            "impacket/secretsdump": "Extract credentials from target",
            "impacket/asreproast": "Obtain crackable Kerberos hashes",
            "impacket/kerberoast": "Obtain service account hashes",
        }
        return outcomes.get(module_path, "Execute module functionality")

    def _assess_risk(self, module_path: str) -> str:
        """Assess risk level of running a module."""
        high_risk = ["impacket/psexec", "impacket/wmiexec", "deploy/"]
        medium_risk = ["web/sqlmap", "impacket/secretsdump", "brute"]

        for pattern in high_risk:
            if pattern in module_path:
                return "high"
        for pattern in medium_risk:
            if pattern in module_path:
                return "medium"
        return "low"

    def _calculate_confidence(
        self,
        service: Dict,
        mod_config: Dict,
    ) -> float:
        """Calculate confidence score for recommendation."""
        base_confidence = 0.7

        # Boost for high priority
        if mod_config.get("priority") == Priority.CRITICAL:
            base_confidence += 0.2
        elif mod_config.get("priority") == Priority.HIGH:
            base_confidence += 0.1

        # Boost if service version matches known vulns
        version = service.get("version", "")
        if version and "enumeration" in mod_config.get("tags", []):
            base_confidence += 0.1

        return min(base_confidence, 1.0)

    def _get_services_from_framework(self) -> List[Dict]:
        """Get services from framework database."""
        if not self.framework:
            return []

        try:
            services = self.framework.database.get_all_services()
            return [s.to_dict() for s in services]
        except Exception:
            return []

    def _get_credentials_from_framework(self) -> List[Dict]:
        """Get credentials from framework database."""
        if not self.framework:
            return []

        try:
            creds = self.framework.database.get_all_credentials()
            return [c.to_dict() for c in creds]
        except Exception:
            return []
