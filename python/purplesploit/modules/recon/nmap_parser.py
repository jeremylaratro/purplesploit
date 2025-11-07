"""
Nmap XML Parser Module

Parses nmap XML output and populates the service database with detected services.
"""

import xml.etree.ElementTree as ET
from typing import Dict, Any, List
from ..core.module import BaseModule


class NmapParser(BaseModule):
    """Parse nmap XML output and extract service information."""

    @property
    def name(self) -> str:
        return "Nmap XML Parser"

    @property
    def description(self) -> str:
        return "Parse nmap XML output files and populate service database"

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
            }
        }

    def run(self) -> Dict[str, Any]:
        """
        Parse the nmap XML file and extract service information.

        Returns:
            Dictionary with parsed results
        """
        xml_file = self.get_option("XML_FILE")
        auto_add = self.get_option("AUTO_ADD_TARGETS").lower() == "true"

        try:
            # Parse XML file
            tree = ET.parse(xml_file)
            root = tree.getroot()

            hosts_processed = 0
            services_found = 0
            targets_added = 0

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

            return {
                "success": True,
                "output": f"Parsed nmap results successfully",
                "data": {
                    "hosts_processed": hosts_processed,
                    "services_found": services_found,
                    "targets_added": targets_added
                },
                "message": f"Processed {hosts_processed} hosts, found {services_found} services"
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
