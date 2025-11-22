"""
Nmap Scan Module

Network scanning and service detection using Nmap.
"""

from purplesploit.core.module import ExternalToolModule


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
        return "Standard nmap scan: all ports, version/script detection (-p- -sCV)"

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
            }
        })

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
        # Run the command
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

                # Also save to database
                self.framework.database.add_service(rhost, service_name, port, service_info.get("version"))

            self.log(f"Imported {len(parsed.get('services', {}))} services to context", "success")

        return result
