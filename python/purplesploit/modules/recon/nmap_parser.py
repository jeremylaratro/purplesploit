"""
Nmap XML Parser Module

Parses nmap XML output and populates the service database with detected services.
Also runs searchsploit on discovered service versions to find potential exploits.
"""

import xml.etree.ElementTree as ET
import subprocess
import re
from typing import Dict, Any, List, Tuple
from ..core.module import BaseModule


class NmapParser(BaseModule):
    """Parse nmap XML output and extract service information."""

    @property
    def name(self) -> str:
        return "Nmap XML Parser"

    @property
    def description(self) -> str:
        return "Parse nmap XML output files, populate service database, and run searchsploit on discovered services"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "recon"

    def _init_options(self):
        """Initialize module options."""
        self.options = {
            "XML_FILE": {
                "value": None,
                "required": True,
                "description": "Path to nmap XML output file",
                "default": None
            },
            "AUTO_ADD_TARGETS": {
                "value": "true",
                "required": False,
                "description": "Automatically add discovered hosts as targets",
                "default": "true"
            },
            "RUN_SEARCHSPLOIT": {
                "value": "true",
                "required": False,
                "description": "Run searchsploit on discovered service versions",
                "default": "true"
            }
        }

    def _run_searchsploit(self, service: str, version: str) -> List[Tuple[str, str, str]]:
        """
        Run searchsploit on a service/version and parse results.

        Args:
            service: Service name (e.g., "Apache", "OpenSSH")
            version: Service version (e.g., "2.4.41", "7.2p2")

        Returns:
            List of tuples containing (exploit_title, exploit_path, edb_id)
        """
        if not version:
            return []

        search_query = f"{service} {version}"

        try:
            # Run searchsploit
            result = subprocess.run(
                ["searchsploit", "--colour", search_query],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                return []

            # Parse output
            exploits = []
            lines = result.stdout.split('\n')

            for line in lines:
                # Skip header lines and separators
                if '---' in line or 'Exploit Title' in line or not line.strip():
                    continue

                # Extract exploit info using regex
                # Format: Title | Path
                match = re.search(r'^(.+?)\s+\|\s+(.+)$', line)
                if match:
                    title = match.group(1).strip()
                    path = match.group(2).strip()

                    # Extract EDB-ID if present
                    edb_match = re.search(r'EDB-ID:\s*(\d+)', line)
                    edb_id = edb_match.group(1) if edb_match else None

                    exploits.append((title, path, edb_id))

            return exploits

        except subprocess.TimeoutExpired:
            self.log(f"Searchsploit timed out for {search_query}", "warning")
            return []
        except FileNotFoundError:
            self.log("Searchsploit not found. Install exploitdb to enable exploit search.", "warning")
            return []
        except Exception as e:
            self.log(f"Error running searchsploit: {str(e)}", "error")
            return []

    def run(self) -> Dict[str, Any]:
        """
        Parse the nmap XML file and extract service information.

        Returns:
            Dictionary with parsed results
        """
        xml_file = self.get_option("XML_FILE")
        auto_add = self.get_option("AUTO_ADD_TARGETS").lower() == "true"
        run_searchsploit = self.get_option("RUN_SEARCHSPLOIT").lower() == "true"

        try:
            # Parse XML file
            tree = ET.parse(xml_file)
            root = tree.getroot()

            hosts_processed = 0
            services_found = 0
            targets_added = 0
            exploits_found = 0

            # Process each host
            for host in root.findall('.//host'):
                # Get host status
                status = host.find('status')
                if status is None or status.get('state') != 'up':
                    continue

                # Get IP address
                address = host.find('address')
                if address is None:
                    continue

                ip_addr = address.get('addr')
                if not ip_addr:
                    continue

                hosts_processed += 1

                # Add to targets if enabled
                if auto_add:
                    if self.framework.add_target('network', ip_addr):
                        targets_added += 1

                # Get hostname if available
                hostname = None
                hostnames = host.find('hostnames')
                if hostnames is not None:
                    hostname_elem = hostnames.find('hostname')
                    if hostname_elem is not None:
                        hostname = hostname_elem.get('name')

                # Process ports
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        port_state = port.find('state')
                        if port_state is None or port_state.get('state') != 'open':
                            continue

                        port_id = int(port.get('portid'))
                        protocol = port.get('protocol')

                        # Get service information
                        service_elem = port.find('service')
                        if service_elem is not None:
                            service_name = service_elem.get('name', 'unknown')
                            service_version = service_elem.get('version', '')
                            product = service_elem.get('product', '')

                            # Build version string
                            version_str = f"{product} {service_version}".strip() if product or service_version else None

                            # Map common service names
                            service_mapping = {
                                'microsoft-ds': 'smb',
                                'netbios-ssn': 'smb',
                                'ms-wbt-server': 'rdp',
                                'ldap': 'ldap',
                                'ms-sql-s': 'mssql',
                                'mysql': 'mysql',
                                'postgresql': 'postgresql',
                                'winrm': 'winrm',
                                'http': 'http',
                                'https': 'https',
                                'ssh': 'ssh',
                                'ftp': 'ftp',
                                'telnet': 'telnet',
                                'smtp': 'smtp',
                                'pop3': 'pop3',
                                'imap': 'imap',
                                'domain': 'dns'
                            }

                            mapped_service = service_mapping.get(service_name, service_name)

                            # Add to service database
                            self.framework.session.services.add_service(
                                target=ip_addr,
                                service=mapped_service,
                                port=port_id
                            )

                            # Also add to persistent database
                            self.framework.database.add_service(
                                target=ip_addr,
                                service=mapped_service,
                                port=port_id,
                                version=version_str
                            )

                            services_found += 1

                            # Run searchsploit if enabled and version is available
                            if run_searchsploit and version_str:
                                self.log(f"Running searchsploit for {product} {service_version}...", "info")
                                exploits = self._run_searchsploit(product or service_name, service_version)

                                # Store exploit results
                                for exploit_title, exploit_path, edb_id in exploits:
                                    try:
                                        self.framework.database.add_exploit(
                                            target=ip_addr,
                                            service=mapped_service,
                                            port=port_id,
                                            version=version_str,
                                            exploit_title=exploit_title,
                                            exploit_path=exploit_path,
                                            edb_id=edb_id
                                        )
                                        exploits_found += 1
                                    except Exception as e:
                                        self.log(f"Error storing exploit: {str(e)}", "error")

                                if exploits:
                                    self.log(f"Found {len(exploits)} potential exploits for {product} {service_version}", "success")

            return {
                "success": True,
                "output": f"Parsed nmap results successfully",
                "data": {
                    "hosts_processed": hosts_processed,
                    "services_found": services_found,
                    "targets_added": targets_added,
                    "exploits_found": exploits_found
                },
                "message": f"Processed {hosts_processed} hosts, found {services_found} services, discovered {exploits_found} potential exploits"
            }

        except ET.ParseError as e:
            return {
                "success": False,
                "error": f"Failed to parse XML file: {str(e)}"
            }
        except FileNotFoundError:
            return {
                "success": False,
                "error": f"File not found: {xml_file}"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error parsing nmap XML: {str(e)}"
            }

    def check(self) -> Dict[str, Any]:
        """Check if the XML file exists."""
        xml_file = self.get_option("XML_FILE")

        if not xml_file:
            return {
                "success": False,
                "error": "XML_FILE option is required"
            }

        import os
        if not os.path.exists(xml_file):
            return {
                "success": False,
                "error": f"File not found: {xml_file}"
            }

        return {
            "success": True,
            "message": "XML file exists and ready to parse"
        }
