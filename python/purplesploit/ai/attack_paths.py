"""
Attack Path Analyzer for PurpleSploit

Analyzes discovered services and findings to suggest attack chains
and prioritize exploitation paths.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Set
from enum import Enum
import json


class AttackCategory(Enum):
    """Categories of attacks."""
    INITIAL_ACCESS = "initial_access"
    CREDENTIAL_ACCESS = "credential_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    DATA_EXFILTRATION = "data_exfiltration"


@dataclass
class AttackStep:
    """A single step in an attack path."""
    name: str
    module: str
    operation: Optional[str] = None
    description: str = ""
    requirements: List[str] = field(default_factory=list)
    provides: List[str] = field(default_factory=list)
    mitre_technique: Optional[str] = None
    risk_level: str = "medium"
    success_probability: float = 0.5

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "module": self.module,
            "operation": self.operation,
            "description": self.description,
            "requirements": self.requirements,
            "provides": self.provides,
            "mitre_technique": self.mitre_technique,
            "risk_level": self.risk_level,
            "success_probability": self.success_probability,
        }


@dataclass
class AttackPath:
    """A complete attack path from initial access to objective."""
    name: str
    description: str
    category: AttackCategory
    steps: List[AttackStep] = field(default_factory=list)
    total_probability: float = 0.0
    complexity: str = "medium"  # low, medium, high
    stealth_level: str = "medium"  # low, medium, high
    prerequisites: List[str] = field(default_factory=list)
    objective: str = ""

    def calculate_probability(self):
        """Calculate total success probability of the path."""
        if not self.steps:
            self.total_probability = 0.0
            return

        prob = 1.0
        for step in self.steps:
            prob *= step.success_probability
        self.total_probability = prob

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "steps": [s.to_dict() for s in self.steps],
            "total_probability": self.total_probability,
            "complexity": self.complexity,
            "stealth_level": self.stealth_level,
            "prerequisites": self.prerequisites,
            "objective": self.objective,
        }


# Pre-defined attack path templates
ATTACK_PATH_TEMPLATES = {
    "smb_anonymous_to_creds": {
        "name": "SMB Anonymous → Credential Harvest",
        "description": "Exploit anonymous SMB access to find credentials",
        "category": AttackCategory.CREDENTIAL_ACCESS,
        "complexity": "low",
        "stealth_level": "high",
        "steps": [
            AttackStep(
                name="Enumerate SMB Shares",
                module="smb/enumeration",
                description="List accessible SMB shares",
                requirements=["smb_service"],
                provides=["share_list"],
                mitre_technique="T1135",
                success_probability=0.9,
            ),
            AttackStep(
                name="Spider Shares",
                module="network/nxc_smb",
                operation="spider",
                description="Search shares for sensitive files",
                requirements=["share_list"],
                provides=["sensitive_files"],
                mitre_technique="T1039",
                success_probability=0.6,
            ),
            AttackStep(
                name="Extract Credentials",
                module="smb/shares",
                description="Extract credentials from found files",
                requirements=["sensitive_files"],
                provides=["credentials"],
                mitre_technique="T1552",
                success_probability=0.4,
            ),
        ],
    },
    "ldap_to_asreproast": {
        "name": "LDAP Enum → AS-REP Roasting",
        "description": "Enumerate AD users and roast those without pre-auth",
        "category": AttackCategory.CREDENTIAL_ACCESS,
        "complexity": "low",
        "stealth_level": "high",
        "steps": [
            AttackStep(
                name="LDAP User Enumeration",
                module="network/nxc_ldap",
                description="Enumerate AD users via LDAP",
                requirements=["ldap_service"],
                provides=["user_list"],
                mitre_technique="T1087.002",
                success_probability=0.85,
            ),
            AttackStep(
                name="AS-REP Roasting",
                module="impacket/asreproast",
                description="Request TGTs for users without pre-auth",
                requirements=["user_list", "kerberos_service"],
                provides=["asrep_hashes"],
                mitre_technique="T1558.004",
                success_probability=0.3,
            ),
            AttackStep(
                name="Crack Hashes",
                module="utility/hashcat",
                description="Crack obtained AS-REP hashes",
                requirements=["asrep_hashes"],
                provides=["credentials"],
                mitre_technique="T1110.002",
                success_probability=0.5,
            ),
        ],
    },
    "kerberoast_path": {
        "name": "Kerberoasting Attack Chain",
        "description": "Use valid credentials to kerberoast service accounts",
        "category": AttackCategory.CREDENTIAL_ACCESS,
        "complexity": "medium",
        "stealth_level": "medium",
        "steps": [
            AttackStep(
                name="Kerberoasting",
                module="impacket/kerberoast",
                description="Request TGS tickets for service accounts",
                requirements=["valid_credentials", "kerberos_service"],
                provides=["tgs_hashes"],
                mitre_technique="T1558.003",
                success_probability=0.8,
            ),
            AttackStep(
                name="Crack Service Hashes",
                module="utility/hashcat",
                description="Crack TGS hashes offline",
                requirements=["tgs_hashes"],
                provides=["service_credentials"],
                mitre_technique="T1110.002",
                success_probability=0.4,
            ),
        ],
    },
    "web_to_rce": {
        "name": "Web Vulnerability → RCE",
        "description": "Exploit web vulnerabilities for initial access",
        "category": AttackCategory.INITIAL_ACCESS,
        "complexity": "medium",
        "stealth_level": "low",
        "steps": [
            AttackStep(
                name="Web Reconnaissance",
                module="web/httpx",
                description="Fingerprint web technologies",
                requirements=["http_service"],
                provides=["tech_stack"],
                mitre_technique="T1592",
                success_probability=0.95,
            ),
            AttackStep(
                name="Vulnerability Scan",
                module="recon/nuclei",
                description="Scan for known vulnerabilities",
                requirements=["http_service"],
                provides=["vulnerabilities"],
                mitre_technique="T1595.002",
                success_probability=0.7,
            ),
            AttackStep(
                name="Exploit Vulnerability",
                module="web/exploit",
                description="Exploit discovered vulnerability",
                requirements=["vulnerabilities"],
                provides=["shell_access"],
                mitre_technique="T1190",
                success_probability=0.3,
            ),
        ],
    },
    "creds_to_domain_admin": {
        "name": "User Creds → Domain Admin",
        "description": "Escalate from user credentials to domain admin",
        "category": AttackCategory.PRIVILEGE_ESCALATION,
        "complexity": "high",
        "stealth_level": "low",
        "steps": [
            AttackStep(
                name="Validate Credentials",
                module="network/nxc_smb",
                description="Verify credentials work",
                requirements=["credentials", "smb_service"],
                provides=["valid_user"],
                mitre_technique="T1078",
                success_probability=0.9,
            ),
            AttackStep(
                name="BloodHound Collection",
                module="ad/bloodhound",
                description="Collect AD data for path analysis",
                requirements=["valid_user"],
                provides=["ad_graph"],
                mitre_technique="T1087.002",
                success_probability=0.85,
            ),
            AttackStep(
                name="Find Attack Path",
                module="ad/bloodhound",
                operation="analyze",
                description="Identify path to Domain Admin",
                requirements=["ad_graph"],
                provides=["attack_path"],
                mitre_technique="T1087.002",
                success_probability=0.6,
            ),
            AttackStep(
                name="Execute Path",
                module="ad/path_execute",
                description="Execute identified attack path",
                requirements=["attack_path"],
                provides=["domain_admin"],
                mitre_technique="T1484",
                success_probability=0.4,
            ),
        ],
    },
    "secretsdump_lateral": {
        "name": "Credential Dump → Lateral Movement",
        "description": "Dump credentials and move laterally",
        "category": AttackCategory.LATERAL_MOVEMENT,
        "complexity": "medium",
        "stealth_level": "low",
        "steps": [
            AttackStep(
                name="Dump Secrets",
                module="impacket/secretsdump",
                description="Extract credentials from compromised host",
                requirements=["admin_access"],
                provides=["dumped_hashes"],
                mitre_technique="T1003.002",
                success_probability=0.9,
            ),
            AttackStep(
                name="Pass the Hash",
                module="network/nxc_smb",
                operation="pth",
                description="Use obtained hashes for lateral movement",
                requirements=["dumped_hashes"],
                provides=["lateral_access"],
                mitre_technique="T1550.002",
                success_probability=0.7,
            ),
        ],
    },
}


class AttackPathAnalyzer:
    """
    Analyzes context and generates attack path recommendations.

    Uses discovered services, credentials, and findings to suggest
    the most promising attack chains.
    """

    def __init__(self, framework=None):
        self.framework = framework
        self._available_resources: Set[str] = set()

    def analyze(
        self,
        services: Optional[List[Dict]] = None,
        credentials: Optional[List[Dict]] = None,
        findings: Optional[List[Dict]] = None,
    ) -> List[AttackPath]:
        """
        Analyze context and return viable attack paths.

        Args:
            services: Discovered services
            credentials: Available credentials
            findings: Current findings

        Returns:
            List of viable attack paths sorted by probability
        """
        # Determine available resources
        self._available_resources = self._determine_resources(
            services or [],
            credentials or [],
            findings or [],
        )

        viable_paths = []

        # Check each template
        for template_name, template in ATTACK_PATH_TEMPLATES.items():
            path = self._evaluate_template(template)
            if path:
                viable_paths.append(path)

        # Sort by probability (descending)
        viable_paths.sort(key=lambda p: p.total_probability, reverse=True)

        return viable_paths

    def get_attack_path(self, path_name: str) -> Optional[AttackPath]:
        """Get a specific attack path by name."""
        template = ATTACK_PATH_TEMPLATES.get(path_name)
        if not template:
            return None

        path = AttackPath(
            name=template["name"],
            description=template["description"],
            category=template["category"],
            complexity=template["complexity"],
            stealth_level=template["stealth_level"],
            steps=[
                AttackStep(**step) if isinstance(step, dict) else step
                for step in template["steps"]
            ],
        )
        path.calculate_probability()
        return path

    def suggest_next_step(
        self,
        current_resources: Set[str],
    ) -> Optional[AttackStep]:
        """
        Suggest the best next step given current resources.

        Args:
            current_resources: Set of currently available resources

        Returns:
            Best next step or None
        """
        best_step = None
        best_score = 0

        for template in ATTACK_PATH_TEMPLATES.values():
            for step_config in template["steps"]:
                step = AttackStep(**step_config) if isinstance(step_config, dict) else step_config

                # Check if requirements are met
                requirements = set(step.requirements)
                if not requirements.issubset(current_resources):
                    continue

                # Check if this step provides new resources
                provides = set(step.provides)
                if provides.issubset(current_resources):
                    continue  # Already have what this provides

                # Score based on probability and value of what it provides
                score = step.success_probability * len(provides)

                if score > best_score:
                    best_score = score
                    best_step = step

        return best_step

    def get_mitre_mapping(
        self,
        attack_path: AttackPath,
    ) -> Dict[str, List[str]]:
        """
        Get MITRE ATT&CK mapping for an attack path.

        Args:
            attack_path: Attack path to map

        Returns:
            Dict mapping tactics to techniques
        """
        mapping = {}

        tactic_map = {
            "T1135": ("Discovery", "Network Share Discovery"),
            "T1039": ("Collection", "Data from Network Shared Drive"),
            "T1552": ("Credential Access", "Unsecured Credentials"),
            "T1087": ("Discovery", "Account Discovery"),
            "T1558": ("Credential Access", "Steal or Forge Kerberos Tickets"),
            "T1110": ("Credential Access", "Brute Force"),
            "T1592": ("Reconnaissance", "Gather Victim Host Information"),
            "T1595": ("Reconnaissance", "Active Scanning"),
            "T1190": ("Initial Access", "Exploit Public-Facing Application"),
            "T1078": ("Persistence", "Valid Accounts"),
            "T1484": ("Defense Evasion", "Domain Policy Modification"),
            "T1003": ("Credential Access", "OS Credential Dumping"),
            "T1550": ("Lateral Movement", "Use Alternate Authentication Material"),
        }

        for step in attack_path.steps:
            if step.mitre_technique:
                base_technique = step.mitre_technique.split(".")[0]
                if base_technique in tactic_map:
                    tactic, technique_name = tactic_map[base_technique]
                    if tactic not in mapping:
                        mapping[tactic] = []
                    mapping[tactic].append(f"{step.mitre_technique}: {technique_name}")

        return mapping

    def generate_report(
        self,
        attack_paths: List[AttackPath],
    ) -> str:
        """
        Generate a text report of attack paths.

        Args:
            attack_paths: List of attack paths

        Returns:
            Formatted report string
        """
        lines = []
        lines.append("=" * 60)
        lines.append("ATTACK PATH ANALYSIS REPORT")
        lines.append("=" * 60)
        lines.append("")

        for i, path in enumerate(attack_paths, 1):
            lines.append(f"[{i}] {path.name}")
            lines.append(f"    Category: {path.category.value}")
            lines.append(f"    Success Probability: {path.total_probability:.1%}")
            lines.append(f"    Complexity: {path.complexity}")
            lines.append(f"    Stealth: {path.stealth_level}")
            lines.append("")
            lines.append(f"    Steps:")
            for j, step in enumerate(path.steps, 1):
                lines.append(f"      {j}. {step.name}")
                lines.append(f"         Module: {step.module}")
                lines.append(f"         Probability: {step.success_probability:.0%}")
                if step.mitre_technique:
                    lines.append(f"         MITRE: {step.mitre_technique}")
            lines.append("")
            lines.append("-" * 60)
            lines.append("")

        return "\n".join(lines)

    def _determine_resources(
        self,
        services: List[Dict],
        credentials: List[Dict],
        findings: List[Dict],
    ) -> Set[str]:
        """Determine available resources from context."""
        resources = set()

        # Add service-based resources
        for svc in services:
            service = svc.get("service", "").lower()
            port = svc.get("port", 0)

            if "smb" in service or port in [139, 445]:
                resources.add("smb_service")
            if "ldap" in service or port in [389, 636]:
                resources.add("ldap_service")
            if "http" in service or port in [80, 8080, 8000]:
                resources.add("http_service")
            if "https" in service or port in [443, 8443]:
                resources.add("https_service")
                resources.add("http_service")
            if "kerberos" in service or port == 88:
                resources.add("kerberos_service")
            if "ssh" in service or port == 22:
                resources.add("ssh_service")
            if "winrm" in service or port in [5985, 5986]:
                resources.add("winrm_service")

        # Add credential-based resources
        if credentials:
            resources.add("credentials")
            resources.add("valid_credentials")

            for cred in credentials:
                if cred.get("is_admin"):
                    resources.add("admin_credentials")
                    resources.add("admin_access")

        # Add finding-based resources
        for finding in findings:
            finding_type = finding.get("type", "")
            if "user" in finding_type.lower():
                resources.add("user_list")
            if "hash" in finding_type.lower():
                resources.add("hashes")
            if "vuln" in finding_type.lower():
                resources.add("vulnerabilities")

        return resources

    def _evaluate_template(
        self,
        template: Dict,
    ) -> Optional[AttackPath]:
        """Evaluate if an attack path template is viable."""
        # Check first step requirements
        first_step = template["steps"][0]
        if isinstance(first_step, dict):
            first_reqs = set(first_step.get("requirements", []))
        else:
            first_reqs = set(first_step.requirements)

        # If we can't start, path isn't viable
        if not first_reqs.issubset(self._available_resources):
            return None

        # Build the path
        path = AttackPath(
            name=template["name"],
            description=template["description"],
            category=template["category"],
            complexity=template["complexity"],
            stealth_level=template["stealth_level"],
            steps=[
                AttackStep(**step) if isinstance(step, dict) else step
                for step in template["steps"]
            ],
        )
        path.calculate_probability()

        return path
