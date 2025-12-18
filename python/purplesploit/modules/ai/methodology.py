"""
Pentesting Methodology Module for MCP Automation

Derived from HackTheBox writeup analysis, this module provides structured
attack pathways for automated penetration testing workflows.
"""

from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum


class Phase(Enum):
    """Penetration test phases."""
    INIT = "init"
    RECON_NETWORK = "recon_network"
    RECON_SERVICES = "recon_services"
    ENUM_SMB = "enum_smb"
    ENUM_WEB = "enum_web"
    ENUM_AD = "enum_ad"
    ENUM_DNS = "enum_dns"
    ATTACK_KERBEROS = "attack_kerberos"
    ATTACK_WEB = "attack_web"
    INITIAL_ACCESS = "initial_access"
    POST_EXPLOIT = "post_exploit"
    PRIV_ESC = "priv_esc"
    LATERAL = "lateral"
    COMPLETE = "complete"


class ServiceType(Enum):
    """Detected service types."""
    SMB = "smb"
    LDAP = "ldap"
    DNS = "dns"
    HTTP = "http"
    HTTPS = "https"
    FTP = "ftp"
    SSH = "ssh"
    RDP = "rdp"
    WINRM = "winrm"
    MSSQL = "mssql"
    KERBEROS = "kerberos"
    UNKNOWN = "unknown"


@dataclass
class ServiceInfo:
    """Information about a detected service."""
    port: int
    service_type: ServiceType
    version: str = ""
    product: str = ""
    extra_info: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Credential:
    """Credential storage."""
    username: str
    password: Optional[str] = None
    hash: Optional[str] = None
    domain: Optional[str] = None
    source: str = ""
    valid_for: List[str] = field(default_factory=list)


@dataclass
class Finding:
    """Security finding."""
    category: str
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    evidence: str = ""
    remediation: str = ""


@dataclass
class AssessmentState:
    """Current state of the assessment."""
    target: str
    phase: Phase = Phase.INIT
    services: List[ServiceInfo] = field(default_factory=list)
    credentials: List[Credential] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    completed_checks: Set[str] = field(default_factory=set)
    access_level: str = "none"  # none, user, admin, system
    notes: List[str] = field(default_factory=list)


# Service priority for enumeration (lower = higher priority)
SERVICE_PRIORITY = {
    ServiceType.SMB: 1,      # Often allows anonymous access
    ServiceType.LDAP: 1,     # AD enumeration without creds
    ServiceType.DNS: 2,      # Zone transfers
    ServiceType.HTTP: 2,     # Web app vulnerabilities
    ServiceType.HTTPS: 2,
    ServiceType.FTP: 3,      # Anonymous access
    ServiceType.SSH: 4,      # Credential testing
    ServiceType.RDP: 4,      # Credential testing
    ServiceType.WINRM: 4,    # Credential testing
    ServiceType.MSSQL: 3,    # Database access
    ServiceType.KERBEROS: 2, # Kerberos attacks
}

# Port to service type mapping
PORT_SERVICE_MAP = {
    21: ServiceType.FTP,
    22: ServiceType.SSH,
    53: ServiceType.DNS,
    80: ServiceType.HTTP,
    88: ServiceType.KERBEROS,
    135: ServiceType.SMB,
    139: ServiceType.SMB,
    389: ServiceType.LDAP,
    443: ServiceType.HTTPS,
    445: ServiceType.SMB,
    636: ServiceType.LDAP,
    1433: ServiceType.MSSQL,
    3306: ServiceType.MSSQL,
    3389: ServiceType.RDP,
    5985: ServiceType.WINRM,
    5986: ServiceType.WINRM,
    8080: ServiceType.HTTP,
    8443: ServiceType.HTTPS,
}

# Sensitive files to look for in SMB shares
SENSITIVE_SMB_FILES = [
    "Groups.xml",           # GPP passwords
    "*.xml",               # Config files
    "*.config",            # Web configs
    "*.vhd",               # VHD backups
    "*.pfx",               # Certificates
    "*.zip",               # Archives
    "*.kdbx",              # KeePass databases
    "web.config",          # ASP.NET config
    "unattend.xml",        # Windows setup
    "*.ps1",               # PowerShell scripts
    "*.bat",               # Batch scripts
    "SAM",                 # Registry hives
    "SYSTEM",
    "SECURITY",
]

# Technology fingerprints and associated exploits
TECH_EXPLOITS = {
    "drupal": {
        "versions": ["7.x"],
        "cves": ["CVE-2018-7600", "CVE-2019-6340"],
        "modules": ["web/drupalgeddon"],
    },
    "wordpress": {
        "versions": ["*"],
        "cves": [],
        "modules": ["web/wpscan"],
        "checks": ["plugin_enum", "user_enum"],
    },
    "strapi": {
        "versions": ["3.0.0-beta"],
        "cves": ["CVE-2019-18818", "CVE-2019-19609"],
        "modules": [],
    },
    "laravel": {
        "versions": ["< 8.4.2"],
        "cves": ["CVE-2021-3129"],
        "modules": [],
    },
    "php_dev": {
        "versions": ["8.1.0-dev"],
        "cves": ["backdoor"],
        "modules": [],
    },
    "tomcat": {
        "versions": ["*"],
        "cves": [],
        "checks": ["manager_brute", "host_manager"],
    },
}

# Linux privilege escalation checks
LINUX_PRIVESC_CHECKS = [
    {"name": "suid_binaries", "command": "find / -perm -4000 -type f 2>/dev/null"},
    {"name": "capabilities", "command": "getcap -r / 2>/dev/null"},
    {"name": "sudo_permissions", "command": "sudo -l"},
    {"name": "cron_jobs", "command": "cat /etc/crontab; ls -la /etc/cron.*"},
    {"name": "writable_paths", "command": "find / -writable -type d 2>/dev/null"},
    {"name": "ssh_keys", "command": "find / -name 'id_rsa*' 2>/dev/null"},
    {"name": "password_files", "command": "cat /etc/passwd; cat /etc/shadow 2>/dev/null"},
    {"name": "kernel_version", "command": "uname -a"},
]

# Windows privilege escalation checks
WINDOWS_PRIVESC_CHECKS = [
    {"name": "token_privs", "command": "whoami /priv"},
    {"name": "service_permissions", "command": "sc query state= all"},
    {"name": "scheduled_tasks", "command": "schtasks /query /fo LIST /v"},
    {"name": "unquoted_paths", "command": "wmic service get name,displayname,pathname,startmode"},
    {"name": "always_install_elevated", "command": "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer"},
    {"name": "credential_files", "command": "dir /s /b *.xml *.ini *.txt *.config 2>nul"},
]

# Phase to module mapping
PHASE_MODULES = {
    Phase.RECON_NETWORK: [
        "recon/nmap_fast",
        "recon/nmap_comprehensive",
        "recon/nmap_udp",
    ],
    Phase.ENUM_SMB: [
        "smb/enumeration",
        "smb/shares",
        "network/nxc_smb",
    ],
    Phase.ENUM_WEB: [
        "web/httpx",
        "web/feroxbuster",
        "web/wfuzz",
        "web/wpscan",
    ],
    Phase.ENUM_AD: [
        "network/nxc_ldap",
        "ad/kerbrute",
        "impacket/asreproast",
    ],
    Phase.ENUM_DNS: [
        "recon/dns",
    ],
    Phase.ATTACK_KERBEROS: [
        "ad/kerbrute",
        "impacket/asreproast",
        "impacket/kerberoast",
    ],
    Phase.ATTACK_WEB: [
        "web/sqlmap",
        "web/wpscan",
    ],
    Phase.INITIAL_ACCESS: [
        "network/nxc_smb",
        "network/nxc_winrm",
        "network/nxc_ssh",
        "impacket/psexec",
        "impacket/wmiexec",
    ],
    Phase.POST_EXPLOIT: [
        "deploy/script",
    ],
    Phase.PRIV_ESC: [
        "impacket/secretsdump",
    ],
    Phase.LATERAL: [
        "deploy/ligolo",
        "impacket/psexec",
        "network/nxc_smb",
    ],
}


class PentestMethodology:
    """
    Automated pentesting methodology based on HTB writeup analysis.

    Provides decision trees and automation logic for MCP server integration.
    """

    def __init__(self, framework=None):
        self.framework = framework
        self.state: Optional[AssessmentState] = None

    def start_assessment(self, target: str) -> AssessmentState:
        """Initialize a new assessment."""
        self.state = AssessmentState(target=target, phase=Phase.INIT)
        return self.state

    def get_next_phase(self) -> Phase:
        """Determine the next phase based on current state."""
        if not self.state:
            return Phase.INIT

        current = self.state.phase

        if current == Phase.INIT:
            return Phase.RECON_NETWORK

        if current == Phase.RECON_NETWORK:
            return Phase.RECON_SERVICES

        if current == Phase.RECON_SERVICES:
            # Determine enumeration priority based on services
            return self._determine_enum_phase()

        if current in [Phase.ENUM_SMB, Phase.ENUM_WEB, Phase.ENUM_AD, Phase.ENUM_DNS]:
            # Check if we have credentials to try
            if self.state.credentials:
                return Phase.INITIAL_ACCESS
            # Check for more enumeration
            return self._determine_next_enum_phase()

        if current == Phase.ATTACK_KERBEROS:
            if self.state.credentials:
                return Phase.INITIAL_ACCESS
            return self._determine_next_enum_phase()

        if current == Phase.INITIAL_ACCESS:
            if self.state.access_level != "none":
                return Phase.POST_EXPLOIT
            return self._determine_next_attack_phase()

        if current == Phase.POST_EXPLOIT:
            return Phase.PRIV_ESC

        if current == Phase.PRIV_ESC:
            if self.state.access_level in ["admin", "system"]:
                return Phase.LATERAL
            return Phase.POST_EXPLOIT  # Continue looking

        return Phase.COMPLETE

    def _determine_enum_phase(self) -> Phase:
        """Determine which enumeration phase to start with."""
        services = self.state.services if self.state else []

        # Sort services by priority
        sorted_services = sorted(
            services,
            key=lambda s: SERVICE_PRIORITY.get(s.service_type, 99)
        )

        if not sorted_services:
            return Phase.COMPLETE

        top_service = sorted_services[0].service_type

        if top_service == ServiceType.SMB:
            return Phase.ENUM_SMB
        elif top_service == ServiceType.LDAP:
            return Phase.ENUM_AD
        elif top_service in [ServiceType.HTTP, ServiceType.HTTPS]:
            return Phase.ENUM_WEB
        elif top_service == ServiceType.DNS:
            return Phase.ENUM_DNS
        elif top_service == ServiceType.KERBEROS:
            return Phase.ATTACK_KERBEROS

        return Phase.ENUM_WEB  # Default to web enum

    def _determine_next_enum_phase(self) -> Phase:
        """Determine the next enumeration phase."""
        completed = self.state.completed_checks if self.state else set()
        services = self.state.services if self.state else []

        service_types = {s.service_type for s in services}

        # Check what we haven't done yet
        if ServiceType.SMB in service_types and "enum_smb" not in completed:
            return Phase.ENUM_SMB
        if ServiceType.LDAP in service_types and "enum_ad" not in completed:
            return Phase.ENUM_AD
        if ServiceType.KERBEROS in service_types and "attack_kerberos" not in completed:
            return Phase.ATTACK_KERBEROS
        if (ServiceType.HTTP in service_types or ServiceType.HTTPS in service_types) \
           and "enum_web" not in completed:
            return Phase.ENUM_WEB
        if ServiceType.DNS in service_types and "enum_dns" not in completed:
            return Phase.ENUM_DNS

        # All enumeration complete, try attacks
        return self._determine_next_attack_phase()

    def _determine_next_attack_phase(self) -> Phase:
        """Determine the next attack phase."""
        completed = self.state.completed_checks if self.state else set()
        services = self.state.services if self.state else []

        service_types = {s.service_type for s in services}

        # Kerberos attacks if we have user list
        if ServiceType.KERBEROS in service_types and "attack_kerberos" not in completed:
            return Phase.ATTACK_KERBEROS

        # Web attacks
        if (ServiceType.HTTP in service_types or ServiceType.HTTPS in service_types) \
           and "attack_web" not in completed:
            return Phase.ATTACK_WEB

        return Phase.COMPLETE

    def get_modules_for_phase(self, phase: Phase) -> List[str]:
        """Get the modules to run for a given phase."""
        return PHASE_MODULES.get(phase, [])

    def analyze_nmap_results(self, nmap_output: Dict[str, Any]) -> List[ServiceInfo]:
        """Parse nmap results and identify services."""
        services = []

        hosts = nmap_output.get("hosts", [])
        for host in hosts:
            for port_info in host.get("ports", []):
                port = port_info.get("port", 0)
                service_type = PORT_SERVICE_MAP.get(port, ServiceType.UNKNOWN)

                # Try to detect from service name
                service_name = port_info.get("service", "").lower()
                if "http" in service_name:
                    service_type = ServiceType.HTTP
                elif "smb" in service_name or "microsoft-ds" in service_name:
                    service_type = ServiceType.SMB
                elif "ldap" in service_name:
                    service_type = ServiceType.LDAP
                elif "ssh" in service_name:
                    service_type = ServiceType.SSH

                services.append(ServiceInfo(
                    port=port,
                    service_type=service_type,
                    version=port_info.get("version", ""),
                    product=port_info.get("product", ""),
                    extra_info=port_info
                ))

        return services

    def analyze_smb_shares(self, shares: List[Dict]) -> List[Dict[str, Any]]:
        """Analyze SMB shares for interesting content."""
        interesting_findings = []

        for share in shares:
            share_name = share.get("name", "")
            access = share.get("access", "")

            # Check for readable shares
            if "READ" in access.upper() or "OK" in access.upper():
                interesting_findings.append({
                    "share": share_name,
                    "action": "spider",
                    "priority": "high" if share_name.upper() in ["SYSVOL", "NETLOGON", "REPLICATION"] else "medium",
                    "files_to_find": SENSITIVE_SMB_FILES,
                })

        return interesting_findings

    def detect_web_technology(self, headers: Dict[str, str], body: str) -> List[Dict[str, Any]]:
        """Detect web technologies and suggest exploits."""
        detections = []

        # Check headers
        server = headers.get("Server", "").lower()
        x_powered = headers.get("X-Powered-By", "").lower()

        # Check for Drupal
        if "drupal" in body.lower() or "x-drupal" in str(headers).lower():
            detections.append({
                "technology": "drupal",
                "exploits": TECH_EXPLOITS["drupal"],
                "action": "check_drupalgeddon"
            })

        # Check for WordPress
        if "wp-content" in body or "wordpress" in body.lower():
            detections.append({
                "technology": "wordpress",
                "exploits": TECH_EXPLOITS["wordpress"],
                "action": "run_wpscan"
            })

        # Check for Strapi
        if "strapi" in body.lower():
            detections.append({
                "technology": "strapi",
                "exploits": TECH_EXPLOITS["strapi"],
                "action": "check_strapi_rce"
            })

        # Check for Laravel
        if "laravel" in body.lower():
            detections.append({
                "technology": "laravel",
                "exploits": TECH_EXPLOITS["laravel"],
                "action": "check_ignition_rce"
            })

        # Check PHP version backdoor
        if "php/8.1.0-dev" in x_powered:
            detections.append({
                "technology": "php_dev",
                "exploits": TECH_EXPLOITS["php_dev"],
                "action": "exploit_php_backdoor"
            })

        return detections

    def suggest_privesc_checks(self, os_type: str) -> List[Dict[str, Any]]:
        """Suggest privilege escalation checks based on OS."""
        if os_type.lower() == "linux":
            return LINUX_PRIVESC_CHECKS
        elif os_type.lower() == "windows":
            return WINDOWS_PRIVESC_CHECKS
        return []

    def generate_ai_prompt(self, prompt_type: str, context: Dict[str, Any]) -> str:
        """Generate AI prompts for decision making."""
        prompts = {
            "analyze_ports": f"""
Analyze the following open ports and services for a penetration test:

Services detected:
{context.get('services', [])}

Target: {context.get('target', 'unknown')}

Questions to answer:
1. What is the priority order for enumeration?
2. Are there any quick wins (anonymous access, default creds)?
3. What attack vectors are most promising?
4. What additional enumeration is needed?

Provide actionable recommendations.
""",

            "analyze_shares": f"""
SMB shares found on target:

Shares:
{context.get('shares', [])}

Files discovered:
{context.get('files', [])}

Questions to answer:
1. What sensitive files should we prioritize?
2. Are there any GPP passwords or config files?
3. What credentials might be extractable?
4. What lateral movement opportunities exist?
""",

            "suggest_exploitation": f"""
Target information for exploitation planning:

Services: {context.get('services', [])}
Vulnerabilities found: {context.get('vulns', [])}
Credentials available: {context.get('creds', [])}
Technology stack: {context.get('tech', [])}

Questions to answer:
1. What is the most reliable exploitation path?
2. What order should we attempt exploits?
3. Are there any credential-based attacks to try?
4. What backup methods exist if primary fails?
""",

            "analyze_privesc": f"""
Post-exploitation privilege escalation analysis:

Operating System: {context.get('os', 'unknown')}
Current User: {context.get('user', 'unknown')}
User Privileges: {context.get('privileges', [])}

Interesting findings:
{context.get('findings', [])}

Questions to answer:
1. What privilege escalation vectors are available?
2. What is the most reliable method?
3. Are there any quick wins (sudo, SUID, capabilities)?
4. What credentials might help escalate?
""",
        }

        return prompts.get(prompt_type, "No prompt template found.")

    def get_assessment_summary(self) -> Dict[str, Any]:
        """Get a summary of the current assessment state."""
        if not self.state:
            return {"error": "No assessment in progress"}

        return {
            "target": self.state.target,
            "current_phase": self.state.phase.value,
            "access_level": self.state.access_level,
            "services_found": len(self.state.services),
            "credentials_found": len(self.state.credentials),
            "findings_count": len(self.state.findings),
            "completed_checks": list(self.state.completed_checks),
            "next_phase": self.get_next_phase().value,
            "recommended_modules": self.get_modules_for_phase(self.get_next_phase()),
        }
