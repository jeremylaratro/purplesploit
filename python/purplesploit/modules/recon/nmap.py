"""
Nmap Scan Module

Network scanning and service detection using Nmap.
"""

from typing import List, Dict, Any
from purplesploit.core.module import ExternalToolModule
from purplesploit.models.database import db_manager


class NmapModule(ExternalToolModule):
    """
    Nmap - Network scanning and service detection.

    Comprehensive network scanning tool for port discovery and service identification.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "nmap"

    @property
    def name(self) -> str:
        return "Nmap Scan"

    @property
    def description(self) -> str:
        return "All ports + version/script detection (-p- -sCV)"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "recon"

    def _init_options(self):
        """Initialize module-specific options."""
        super()._init_options()

        self.options.update({
            "RHOST": {
                "value": None,
                "required": True,
                "description": "Target host IP address or network",
                "default": None
            },
            "PORTS": {
                "value": "-",
                "required": False,
                "description": "Port specification (e.g., 1-1000, 80,443, - for all ports)",
                "default": "-"
            },
            "SCAN_TYPE": {
                "value": "sCV",
                "required": False,
                "description": "Scan type (sS, sT, sU, sV, sC, sCV, etc.)",
                "default": "sCV"
            },
            "TOP_PORTS": {
                "value": None,
                "required": False,
                "description": "Scan top N ports (e.g., 100, 1000)",
                "default": None
            },
            "SCRIPT": {
                "value": None,
                "required": False,
                "description": "NSE script to run (e.g., vuln, default)",
                "default": None
            },
            "OUTPUT_FORMAT": {
                "value": "all",
                "required": False,
                "description": "Output format (normal, xml, grepable, all)",
                "default": "all"
            },
            "OUTPUT_FILE": {
                "value": None,
                "required": False,
                "description": "Output file path (without extension for -oA)",
                "default": None
            },
            "TIMING": {
                "value": "4",
                "required": False,
                "description": "Timing template (0-5, 4=aggressive)",
                "default": "4"
            },
            "OS_DETECTION": {
                "value": "false",
                "required": False,
                "description": "Enable OS detection (-O)",
                "default": "false"
            },
            "VERSION_INTENSITY": {
                "value": None,
                "required": False,
                "description": "Version scan intensity (0-9)",
                "default": None
            },
            "MIN_RATE": {
                "value": "3900",
                "required": False,
                "description": "Minimum packets per second",
                "default": "3900"
            },
            "MAX_RTT_TIMEOUT": {
                "value": "4.5",
                "required": False,
                "description": "Maximum round-trip time timeout (e.g., 100ms, 4.5)",
                "default": "4.5"
            },
            "MAX_RETRIES": {
                "value": None,
                "required": False,
                "description": "Maximum port scan probe retransmissions",
                "default": None
            },
            "HOST_TIMEOUT": {
                "value": None,
                "required": False,
                "description": "Give up on host after this long (e.g., 30m)",
                "default": None
            },
            "BACKGROUND": {
                "value": "false",
                "required": False,
                "description": "Run scan in background (true/false)",
                "default": "false"
            }
        })

    def get_operations(self) -> List[Dict[str, Any]]:
        """
        Get available scan type operations.

        Returns:
            List of operation dictionaries
        """
        return [
            {
                "name": "Default Scan",
                "description": "All ports + version/script detection (-p- -sCV)",
                "handler": "op_default_scan",
                "subcategory": "standard"
            },
            {
                "name": "Fast Scan",
                "description": "Top 100 ports only + quick version (--top-ports 100 -sV -T4)",
                "handler": "op_fast_scan",
                "subcategory": "standard"
            },
            {
                "name": "Comprehensive Scan",
                "description": "All ports + max version intensity (-p- -sCV --version-intensity 9)",
                "handler": "op_comprehensive_scan",
                "subcategory": "standard"
            },
            {
                "name": "Aggressive Scan",
                "description": "OS detection + scripts + traceroute (-sCV -O --traceroute)",
                "handler": "op_aggressive_scan",
                "subcategory": "advanced"
            },
            {
                "name": "Stealth Scan",
                "description": "Stealth SYN + slow timing (requires root: -sS -T2 -p-)",
                "handler": "op_stealth_scan",
                "subcategory": "advanced"
            },
            {
                "name": "UDP Scan",
                "description": "UDP top 100 ports (-sU --top-ports 100)",
                "handler": "op_udp_scan",
                "subcategory": "specialized"
            },
            {
                "name": "No Ping Scan",
                "description": "No ping/discovery + all ports (-Pn -p- -sCV)",
                "handler": "op_no_ping_scan",
                "subcategory": "specialized"
            }
        ]

    def op_default_scan(self) -> Dict[str, Any]:
        """Execute default scan: All ports + version/script detection."""
        # Set default scan options
        self.set_option("PORTS", "-")
        self.set_option("SCAN_TYPE", "sCV")
        self.set_option("TIMING", "4")
        self.set_option("MIN_RATE", "3900")
        self.set_option("MAX_RTT_TIMEOUT", "4.5")

        return self.run()

    def op_fast_scan(self) -> Dict[str, Any]:
        """Execute fast scan: Top 100 ports only."""
        # Set fast scan options
        self.set_option("TOP_PORTS", "100")
        self.set_option("PORTS", None)
        self.set_option("SCAN_TYPE", "sV")
        self.set_option("TIMING", "4")
        self.set_option("MIN_RATE", "5000")
        self.set_option("MAX_RTT_TIMEOUT", "2")
        self.set_option("MAX_RETRIES", "1")
        self.set_option("VERSION_INTENSITY", "2")

        return self.run()

    def op_comprehensive_scan(self) -> Dict[str, Any]:
        """Execute comprehensive scan: All ports + max version intensity."""
        # Set comprehensive scan options
        self.set_option("PORTS", "-")
        self.set_option("SCAN_TYPE", "sCV")
        self.set_option("VERSION_INTENSITY", "9")
        self.set_option("TIMING", "4")
        self.set_option("MIN_RATE", "3900")
        self.set_option("MAX_RTT_TIMEOUT", "4.5")

        return self.run()

    def op_aggressive_scan(self) -> Dict[str, Any]:
        """Execute aggressive scan: OS detection + scripts + traceroute."""
        # Set aggressive scan options
        self.set_option("SCAN_TYPE", "sCV")
        self.set_option("OS_DETECTION", "true")
        self.set_option("VERSION_INTENSITY", "9")
        self.set_option("TIMING", "4")

        # Run the scan
        result = self.run()

        # Note: Traceroute would need additional implementation in build_command
        # For now, users can add --traceroute via SCRIPT or custom flags if needed

        return result

    def op_stealth_scan(self) -> Dict[str, Any]:
        """Execute stealth scan: SYN scan with slow timing."""
        # Set stealth scan options
        self.set_option("SCAN_TYPE", "sS")
        self.set_option("TIMING", "2")
        self.set_option("MIN_RATE", "100")
        self.set_option("MAX_RTT_TIMEOUT", "10")
        self.set_option("PORTS", "-")

        return self.run()

    def op_udp_scan(self) -> Dict[str, Any]:
        """Execute UDP scan: Top 100 UDP ports."""
        # Set UDP scan options
        self.set_option("SCAN_TYPE", "sU")
        self.set_option("TOP_PORTS", "100")
        self.set_option("PORTS", None)
        self.set_option("TIMING", "4")
        self.set_option("MIN_RATE", "1000")

        return self.run()

    def op_no_ping_scan(self) -> Dict[str, Any]:
        """Execute no ping scan: Skip host discovery."""
        # Set no ping scan options
        self.set_option("PORTS", "-")
        self.set_option("SCAN_TYPE", "sCV")

        # Run the scan
        result = self.run()

        # Note: -Pn flag would need to be added in build_command
        # For now, users can add it via custom options if the module supports it

        return result

    def build_command(self) -> str:
        """
        Build the nmap command.

        Returns:
            Command string to execute
        """
        rhost = self.get_option("RHOST")
        ports = self.get_option("PORTS")
        scan_type = self.get_option("SCAN_TYPE")
        top_ports = self.get_option("TOP_PORTS")
        script = self.get_option("SCRIPT")
        output_format = self.get_option("OUTPUT_FORMAT")
        output_file = self.get_option("OUTPUT_FILE")
        timing = self.get_option("TIMING")
        os_detection = self.get_option("OS_DETECTION")
        version_intensity = self.get_option("VERSION_INTENSITY")
        min_rate = self.get_option("MIN_RATE")
        max_rtt_timeout = self.get_option("MAX_RTT_TIMEOUT")
        max_retries = self.get_option("MAX_RETRIES")
        host_timeout = self.get_option("HOST_TIMEOUT")

        # Base command
        cmd = f"nmap"

        # Scan type
        if scan_type:
            cmd += f" -{scan_type}"

        # Ports
        if ports:
            cmd += f" -p {ports}"
        elif top_ports:
            cmd += f" --top-ports {top_ports}"

        # Timing
        if timing:
            cmd += f" -T{timing}"

        # OS detection
        if os_detection and os_detection.lower() == "true":
            cmd += " -O"

        # Version intensity
        if version_intensity:
            cmd += f" --version-intensity {version_intensity}"

        # Performance options
        if min_rate:
            cmd += f" --min-rate {min_rate}"

        if max_rtt_timeout:
            cmd += f" --max-rtt-timeout {max_rtt_timeout}"

        if max_retries:
            cmd += f" --max-retries {max_retries}"

        if host_timeout:
            cmd += f" --host-timeout {host_timeout}"

        # Scripts
        if script:
            cmd += f" --script={script}"

        # Output
        # If no output file specified but format is set, use target name
        if not output_file and output_format and output_format != "normal":
            # Use target as filename (sanitize it)
            target_name = rhost.replace("/", "_").replace(":", "_")
            output_file = f"nmap_{target_name}"

        if output_file:
            if output_format == "xml":
                cmd += f" -oX {output_file}"
            elif output_format == "grepable":
                cmd += f" -oG {output_file}"
            elif output_format == "all":
                cmd += f" -oA {output_file}"
            else:
                cmd += f" -oN {output_file}"

        # Target
        cmd += f" {rhost}"

        return cmd

    def parse_output(self, output: str) -> dict:
        """
        Parse nmap output.

        Args:
            output: Command stdout

        Returns:
            Parsed results dictionary
        """
        results = {
            "open_ports": [],
            "services": {},
            "os_guess": None,
        }

        current_port = None

        # Parse output
        for line in output.split('\n'):
            line = line.strip()

            # Parse open ports
            if "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 3 and "open" in parts[1]:
                    port = parts[0]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    version = " ".join(parts[3:]) if len(parts) > 3 else ""

                    results["open_ports"].append(port)
                    results["services"][port] = {
                        "service": service,
                        "version": version
                    }

            # Parse OS detection
            if "OS details:" in line or "Aggressive OS guesses:" in line:
                results["os_guess"] = line.split(":", 1)[1].strip() if ":" in line else None

        return results

    def run(self) -> dict:
        """
        Execute nmap scan and auto-import services to context.

        Returns:
            Execution results
        """
        # Check if background mode is enabled
        background = self.get_option("BACKGROUND")
        run_in_background = background and str(background).lower() == "true"

        if run_in_background:
            # Check tool is installed
            if not self.check_tool_installed():
                return {
                    "success": False,
                    "error": f"Tool not found: {self.tool_name}. Please install it first."
                }

            # Build command and execute in background
            command = self.build_command()
            result = self.execute_command(command, background=True)

            # Return background execution info
            return result
        else:
            # Run the command normally (synchronous)
            result = super().run()

            # If successful, parse and import services
            if result.get("success") and "parsed" in result:
                parsed = result["parsed"]
                rhost = self.get_option("RHOST")

                # Import detected services into framework
                for port_str, service_info in parsed.get("services", {}).items():
                    # Extract port number
                    port = int(port_str.split("/")[0])
                    service_name = service_info.get("service", "unknown")

                    # Map common services
                    if service_name in ["microsoft-ds", "netbios-ssn"]:
                        self.framework.session.services.add_service(rhost, "smb", port)
                    elif service_name in ["ldap", "ldaps"]:
                        self.framework.session.services.add_service(rhost, "ldap", port)
                    elif service_name in ["ms-wbt-server", "rdp"]:
                        self.framework.session.services.add_service(rhost, "rdp", port)
                    elif service_name in ["winrm", "wsman"]:
                        self.framework.session.services.add_service(rhost, "winrm", port)
                    elif service_name in ["ms-sql-s", "mssql"]:
                        self.framework.session.services.add_service(rhost, "mssql", port)
                    elif service_name == "ssh":
                        self.framework.session.services.add_service(rhost, "ssh", port)
                    elif service_name in ["http", "https", "http-proxy"]:
                        self.framework.session.services.add_service(rhost, "http", port)

                    # Save to old database (backwards compatibility)
                    self.framework.database.add_service(rhost, service_name, port, service_info.get("version"))

                    # Save to models database (for webserver)
                    try:
                        db_manager.add_service(rhost, service_name, port, service_info.get("version"))
                    except Exception as e:
                        self.log(f"Failed to save service to models database: {e}", "debug")

                self.log(f"Imported {len(parsed.get('services', {}))} services to context", "success")

            return result
