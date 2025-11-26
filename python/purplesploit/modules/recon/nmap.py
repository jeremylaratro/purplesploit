"""
Nmap Scan Module

Network scanning and service detection using Nmap.
"""

import xml.etree.ElementTree as ET
import os
from pathlib import Path
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
                "value": "true",
                "required": False,
                "description": "Run scan in background (true/false)",
                "default": "true"
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

    def parse_xml_output(self, xml_path: str) -> dict:
        """
        Parse nmap XML output file.

        Args:
            xml_path: Path to nmap XML output file

        Returns:
            Dictionary with hosts and their services
        """
        results = {
            "hosts": [],
            "total_hosts": 0,
            "hosts_with_ports": 0
        }

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            for host in root.findall('host'):
                # Get host status
                status = host.find('status')
                if status is None or status.get('state') != 'up':
                    continue

                # Get IP address
                address = host.find('address[@addrtype="ipv4"]')
                if address is None:
                    address = host.find('address[@addrtype="ipv6"]')
                if address is None:
                    continue

                ip = address.get('addr')
                results["total_hosts"] += 1

                # Get hostname if available
                hostname = None
                hostnames = host.find('hostnames')
                if hostnames is not None:
                    hostname_elem = hostnames.find('hostname')
                    if hostname_elem is not None:
                        hostname = hostname_elem.get('name')

                # Get ports
                ports_elem = host.find('ports')
                if ports_elem is None:
                    continue

                open_ports = []
                services = {}

                for port in ports_elem.findall('port'):
                    state = port.find('state')
                    if state is None or state.get('state') != 'open':
                        continue

                    protocol = port.get('protocol', 'tcp')
                    portid = port.get('portid')
                    port_key = f"{portid}/{protocol}"

                    service = port.find('service')
                    service_name = service.get('name', 'unknown') if service is not None else 'unknown'
                    service_product = service.get('product', '') if service is not None else ''
                    service_version = service.get('version', '') if service is not None else ''

                    version_str = f"{service_product} {service_version}".strip()

                    open_ports.append(port_key)
                    services[port_key] = {
                        "service": service_name,
                        "version": version_str,
                        "port": int(portid),
                        "protocol": protocol
                    }

                # Only add hosts with open ports
                if open_ports:
                    results["hosts_with_ports"] += 1
                    results["hosts"].append({
                        "ip": ip,
                        "hostname": hostname,
                        "open_ports": open_ports,
                        "services": services
                    })

        except Exception as e:
            self.log(f"Error parsing XML: {e}", "error")

        return results

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

    def process_discovered_hosts(self, parsed_xml: dict):
        """
        Process discovered hosts and add them to targets and services.

        Args:
            parsed_xml: Parsed XML results from parse_xml_output()
        """
        for host_info in parsed_xml.get("hosts", []):
            ip = host_info["ip"]
            hostname = host_info.get("hostname")

            # Add host to targets table with verified status
            try:
                self.framework.database.add_target(
                    target_type="network",
                    identifier=ip,
                    name=hostname or ip,
                    metadata={"hostname": hostname} if hostname else {}
                )
                # Mark as verified
                self.framework.database.mark_target_verified(ip)
                self.log(f"Added target: {ip}", "success")
            except Exception as e:
                self.log(f"Target {ip} may already exist: {e}", "debug")

            # Add services
            for port_str, service_info in host_info["services"].items():
                port = service_info["port"]
                service_name = service_info["service"]
                version = service_info["version"]

                # Map common services to framework context
                if service_name in ["microsoft-ds", "netbios-ssn"]:
                    self.framework.session.services.add_service(ip, "smb", port)
                elif service_name in ["ldap", "ldaps"]:
                    self.framework.session.services.add_service(ip, "ldap", port)
                elif service_name in ["ms-wbt-server", "rdp"]:
                    self.framework.session.services.add_service(ip, "rdp", port)
                elif service_name in ["winrm", "wsman"]:
                    self.framework.session.services.add_service(ip, "winrm", port)
                elif service_name in ["ms-sql-s", "mssql"]:
                    self.framework.session.services.add_service(ip, "mssql", port)
                elif service_name == "ssh":
                    self.framework.session.services.add_service(ip, "ssh", port)
                elif service_name in ["http", "https", "http-proxy"]:
                    self.framework.session.services.add_service(ip, "http", port)

                # Save to database
                try:
                    self.framework.database.add_service(ip, service_name, port, version)
                    db_manager.add_service(ip, service_name, port, version)
                except Exception as e:
                    self.log(f"Service may already exist: {e}", "debug")

        self.log(f"Processed {len(parsed_xml.get('hosts', []))} hosts with open ports", "success")

    def run(self) -> dict:
        """
        Execute nmap scan and auto-import services to context.

        Returns:
            Execution results
        """
        # Check if background mode is enabled
        background = self.get_option("BACKGROUND")
        run_in_background = background and str(background).lower() == "true"

        rhost = self.get_option("RHOST")
        output_file = self.get_option("OUTPUT_FILE")

        # Determine XML output path
        if not output_file:
            target_name = rhost.replace("/", "_").replace(":", "_")
            output_file = f"nmap_{target_name}"

        xml_path = f"{output_file}.xml"

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

            # Add note about XML parsing
            if result.get("success"):
                result["note"] = f"Scan running in background. Run 'parse {xml_path}' to import results when complete."

            # Return background execution info
            return result
        else:
            # Run the command normally (synchronous)
            result = super().run()

            # Try to parse XML output if it exists
            if result.get("success") and os.path.exists(xml_path):
                try:
                    parsed_xml = self.parse_xml_output(xml_path)

                    # Process discovered hosts (add to targets and services)
                    if parsed_xml.get("hosts"):
                        self.process_discovered_hosts(parsed_xml)

                        result["xml_parsed"] = True
                        result["hosts_discovered"] = len(parsed_xml.get("hosts", []))
                        result["total_scanned"] = parsed_xml.get("total_hosts", 0)

                        self.log(f"Discovered {result['hosts_discovered']} hosts with open ports out of {result['total_scanned']} total hosts", "success")
                    else:
                        self.log("No hosts with open ports discovered", "info")

                except Exception as e:
                    self.log(f"Error parsing XML output: {e}", "error")

            # Also parse stdout for backward compatibility (only if XML parsing failed or didn't happen)
            if result.get("success") and "parsed" in result and not result.get("xml_parsed"):
                parsed = result["parsed"]

                # Only import services from stdout if scanning a single host (not a network range)
                # For network ranges, we need XML output to distinguish individual IPs
                is_network_range = "/" in rhost or "-" in rhost.split(".")[-1] if "." in rhost else False

                if not is_network_range:
                    # Import detected services into framework (for single host scans without XML)
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
                else:
                    self.log("Network range detected - services require XML parsing. Use 'parse <xml_file>' to import.", "warning")

            return result
