"""
Service Detection

Detects services on targets and provides visual indicators
"""

from typing import Dict, List, Optional, Set
from pathlib import Path
import re
from .bash_executor import BashExecutor
from .themes import SERVICE_ICONS


class ServiceDetector:
    """Detects and tracks services on targets"""

    def __init__(self, bash_executor: BashExecutor):
        """
        Initialize service detector

        Args:
            bash_executor: BashExecutor instance
        """
        self.bash_executor = bash_executor
        self.detected_services: Dict[str, Set[str]] = {}  # target -> set of services

    def detect_services(self, target: str, force_rescan: bool = False) -> Set[str]:
        """
        Detect services on a target

        Args:
            target: Target IP or hostname
            force_rescan: Force a new scan even if cached

        Returns:
            Set of detected service names
        """
        # Check cache
        if not force_rescan and target in self.detected_services:
            return self.detected_services[target]

        services = set()

        # Try to read from service database
        returncode, stdout, _ = self.bash_executor.source_and_call(
            "framework/core/service_analyzer.sh",
            "service_list",
            [target]
        )

        if returncode == 0 and stdout.strip():
            # Parse service output
            for line in stdout.strip().split("\n"):
                # Expected format: port/protocol service_name
                match = re.match(r"(\d+)/(tcp|udp)\s+(\S+)", line)
                if match:
                    port, protocol, service = match.groups()
                    services.add(service.lower())

                    # Map common ports to service names
                    port_num = int(port)
                    if port_num == 445 or port_num == 139:
                        services.add("smb")
                    elif port_num == 389 or port_num == 636:
                        services.add("ldap")
                    elif port_num == 5985 or port_num == 5986:
                        services.add("winrm")
                    elif port_num == 1433:
                        services.add("mssql")
                    elif port_num == 3389:
                        services.add("rdp")
                    elif port_num == 22:
                        services.add("ssh")
                    elif port_num == 80:
                        services.add("http")
                    elif port_num == 443:
                        services.add("https")
                    elif port_num == 21:
                        services.add("ftp")
                    elif port_num == 25 or port_num == 587:
                        services.add("smtp")

        # Cache results
        self.detected_services[target] = services
        return services

    def is_service_detected(self, target: str, service: str) -> bool:
        """
        Check if a service is detected on a target

        Args:
            target: Target IP or hostname
            service: Service name to check

        Returns:
            True if service is detected
        """
        services = self.detect_services(target)
        return service.lower() in services

    def get_service_icon(self, service: str, target: Optional[str] = None) -> str:
        """
        Get icon for a service, optionally colored based on detection

        Args:
            service: Service name
            target: Target to check (if None, returns neutral icon)

        Returns:
            Icon string with Rich markup
        """
        icon = SERVICE_ICONS.get(service.lower(), "●")

        if target is None:
            return icon

        if self.is_service_detected(target, service):
            return f"[service_detected]{icon}[/service_detected]"
        else:
            return f"[service_missing]{icon}[/service_missing]"

    def get_relevant_tools(self, target: str) -> List[str]:
        """
        Get list of tool categories relevant for detected services

        Args:
            target: Target IP or hostname

        Returns:
            List of relevant tool category names
        """
        services = self.detect_services(target)
        relevant = []

        # Map services to tool categories
        if "smb" in services:
            relevant.extend(["SMB Operations", "SMB Authentication", "SMB Enumeration"])
        if "ldap" in services:
            relevant.extend(["LDAP Operations", "Active Directory"])
        if "winrm" in services:
            relevant.append("WinRM Operations")
        if "mssql" in services:
            relevant.append("MSSQL Operations")
        if "rdp" in services:
            relevant.append("RDP Operations")
        if "ssh" in services:
            relevant.append("SSH Operations")
        if "http" in services or "https" in services:
            relevant.extend(["Web Testing", "Web Fuzzing", "Web Scanning"])
        if "ftp" in services:
            relevant.append("FTP Operations")

        return relevant

    def run_nmap_scan(self, target: str, scan_type: str = "quick") -> bool:
        """
        Run an nmap scan on a target

        Args:
            target: Target IP or hostname
            scan_type: Type of scan (quick, full, vuln)

        Returns:
            True if scan was successful
        """
        # Map scan type to nmap module
        scan_map = {
            "quick": "recon/nmap/quick_scan.psm",
            "full": "recon/nmap/full_scan.psm",
            "vuln": "recon/nmap/vuln_scan.psm",
        }

        module = scan_map.get(scan_type, "recon/nmap/quick_scan.psm")

        # Execute scan using framework
        returncode, stdout, stderr = self.bash_executor.execute_command(
            f"export RHOST={target} && source framework/core/engine.sh && "
            f"framework_init_silent && module_load {module} && module_run",
            show_spinner=True
        )

        if returncode == 0:
            # Force re-detection
            self.detect_services(target, force_rescan=True)
            return True

        return False
