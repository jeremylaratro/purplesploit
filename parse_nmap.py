#!/usr/bin/env python3
"""
Parse nmap XML output and display discovered services with auto-detection for web servers.
"""
import xml.etree.ElementTree as ET
import sys
import json
from pathlib import Path
from typing import Dict, List, Tuple
from collections import defaultdict


class NmapParser:
    """Parser for nmap XML output with web server detection."""

    # Services commonly indicating web servers
    WEB_SERVICES = {
        'http', 'https', 'http-proxy', 'http-alt', 'https-alt',
        'ssl/http', 'ssl/https', 'http-mgmt', 'https-mgmt'
    }

    # Ports commonly used for web services
    WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 9090, 3000, 5000,
                 9000, 8001, 8008, 4443, 8081, 8082, 9443}

    def __init__(self, xml_path: str):
        """Initialize parser with XML file path."""
        self.xml_path = xml_path
        self.hosts = []
        self.web_targets = []

    def parse(self) -> bool:
        """Parse the nmap XML file and extract host/port information."""
        try:
            tree = ET.parse(self.xml_path)
            root = tree.getroot()

            for host in root.findall('.//host'):
                host_data = self._parse_host(host)
                if host_data:
                    self.hosts.append(host_data)

            return True

        except ET.ParseError as e:
            print(f"Error parsing XML: {e}", file=sys.stderr)
            return False
        except FileNotFoundError:
            print(f"Error: File not found: {self.xml_path}", file=sys.stderr)
            return False

    def _parse_host(self, host_elem) -> Dict:
        """Parse a single host element."""
        # Get host status
        status = host_elem.find('status')
        if status is None or status.get('state') != 'up':
            return None

        # Get IP address
        address = host_elem.find('address')
        if address is None:
            return None
        ip = address.get('addr')

        # Get hostname if available
        hostname = None
        hostnames = host_elem.find('hostnames')
        if hostnames is not None:
            hostname_elem = hostnames.find('hostname')
            if hostname_elem is not None:
                hostname = hostname_elem.get('name')

        # Parse ports
        ports = []
        ports_elem = host_elem.find('ports')
        if ports_elem is not None:
            for port in ports_elem.findall('port'):
                port_data = self._parse_port(port, ip, hostname)
                if port_data:
                    ports.append(port_data)

        # Get OS detection if available
        os_info = None
        os_elem = host_elem.find('.//osmatch')
        if os_elem is not None:
            os_info = os_elem.get('name')

        return {
            'ip': ip,
            'hostname': hostname,
            'os': os_info,
            'ports': ports
        }

    def _parse_port(self, port_elem, ip: str, hostname: str) -> Dict:
        """Parse a single port element."""
        port_id = port_elem.get('portid')
        protocol = port_elem.get('protocol', 'tcp')

        # Get port state
        state = port_elem.find('state')
        if state is None:
            return None
        state_val = state.get('state')

        # Get service information
        service = port_elem.find('service')
        service_name = service.get('name', 'unknown') if service is not None else 'unknown'
        service_product = service.get('product', '') if service is not None else ''
        service_version = service.get('version', '') if service is not None else ''
        service_tunnel = service.get('tunnel', '') if service is not None else ''

        # Build service string
        service_str = service_name
        if service_product:
            service_str += f" ({service_product}"
            if service_version:
                service_str += f" {service_version}"
            service_str += ")"
        if service_tunnel:
            service_str = f"{service_tunnel}/{service_str}"

        # Check if this is a web service
        is_web = self._is_web_service(service_name, int(port_id), service_tunnel)

        # Add to web targets if it's a web service
        if is_web and state_val == 'open':
            protocol_prefix = 'https' if (service_tunnel == 'ssl' or
                                         'https' in service_name or
                                         int(port_id) == 443) else 'http'

            target_host = hostname if hostname else ip
            url = f"{protocol_prefix}://{target_host}:{port_id}"

            # Use standard ports without port number in URL
            if (protocol_prefix == 'http' and int(port_id) == 80) or \
               (protocol_prefix == 'https' and int(port_id) == 443):
                url = f"{protocol_prefix}://{target_host}"

            self.web_targets.append({
                'ip': ip,
                'hostname': hostname,
                'port': port_id,
                'protocol': protocol_prefix,
                'url': url,
                'service': service_str
            })

        return {
            'port': port_id,
            'protocol': protocol,
            'state': state_val,
            'service': service_str,
            'is_web': is_web
        }

    def _is_web_service(self, service_name: str, port: int, tunnel: str) -> bool:
        """Determine if a service is a web server."""
        # Check service name
        service_lower = service_name.lower()
        if any(web_svc in service_lower for web_svc in self.WEB_SERVICES):
            return True

        # Check if it's SSL/TLS tunnel with common web port
        if tunnel == 'ssl' and port in self.WEB_PORTS:
            return True

        # Check common web ports
        if port in self.WEB_PORTS:
            return True

        return False

    def get_web_targets(self) -> List[Dict]:
        """Return list of detected web targets."""
        return self.web_targets

    def print_summary(self):
        """Print a summary of scan results."""
        if not self.hosts:
            print("No hosts found in scan results.")
            return

        print(f"\n{'='*80}")
        print(f"Nmap Scan Summary")
        print(f"{'='*80}\n")

        total_hosts = len(self.hosts)
        total_ports = sum(len(h['ports']) for h in self.hosts)
        open_ports = sum(len([p for p in h['ports'] if p['state'] == 'open']) for h in self.hosts)

        print(f"Total hosts: {total_hosts}")
        print(f"Total ports scanned: {total_ports}")
        print(f"Open ports: {open_ports}")
        print(f"Web servers detected: {len(self.web_targets)}\n")

    def print_detailed(self, sort_by: str = 'host'):
        """Print detailed scan results."""
        if not self.hosts:
            print("No hosts found in scan results.")
            return

        hosts = self.hosts
        if sort_by == 'ports':
            hosts = sorted(hosts, key=lambda x: len(x['ports']), reverse=True)

        for host in hosts:
            print(f"\n{'='*80}")
            header = f"Host: {host['ip']}"
            if host['hostname']:
                header += f" ({host['hostname']})"
            print(header)
            if host['os']:
                print(f"OS: {host['os']}")
            print(f"{'='*80}")

            if not host['ports']:
                print("  No ports found")
                continue

            # Print ports
            print(f"\n{'Port':<8} {'State':<10} {'Service':<40} {'Web':<5}")
            print(f"{'-'*8} {'-'*10} {'-'*40} {'-'*5}")

            for port in host['ports']:
                web_indicator = '[W]' if port['is_web'] else ''
                print(f"{port['port']:<8} {port['state']:<10} {port['service']:<40} {web_indicator:<5}")

            open_ports = [p for p in host['ports'] if p['state'] == 'open']
            print(f"\nOpen ports: {len(open_ports)}/{len(host['ports'])}")

    def print_web_targets(self):
        """Print detected web targets."""
        if not self.web_targets:
            print("\nNo web servers detected.")
            return

        print(f"\n{'='*80}")
        print("Detected Web Servers")
        print(f"{'='*80}\n")

        print(f"{'IP':<16} {'Port':<6} {'Protocol':<8} {'URL':<40}")
        print(f"{'-'*16} {'-'*6} {'-'*8} {'-'*40}")

        for target in self.web_targets:
            ip = target['ip']
            port = target['port']
            protocol = target['protocol']
            url = target['url']
            print(f"{ip:<16} {port:<6} {protocol:<8} {url:<40}")

        print(f"\nTotal web servers: {len(self.web_targets)}")

    def export_web_targets(self, output_file: str = None):
        """Export web targets in a format suitable for plat02.sh web targets DB."""
        if not self.web_targets:
            return []

        # Format: NAME|URL
        entries = []
        for target in self.web_targets:
            # Create a descriptive name
            name_parts = []
            if target['hostname']:
                name_parts.append(target['hostname'])
            else:
                name_parts.append(target['ip'])
            name_parts.append(f"port{target['port']}")

            name = "_".join(name_parts)
            url = target['url']
            entries.append(f"{name}|{url}")

        if output_file:
            try:
                with open(output_file, 'a') as f:
                    for entry in entries:
                        f.write(entry + '\n')
                print(f"\nWeb targets appended to: {output_file}")
            except IOError as e:
                print(f"Error writing to file: {e}", file=sys.stderr)

        return entries


def main():
    """Main function to parse nmap XML output."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Parse nmap XML output and detect web servers',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Parse nmap results and show summary
  %(prog)s scan_results.xml

  # Show detailed port information
  %(prog)s scan_results.xml --detailed

  # Show only web servers
  %(prog)s scan_results.xml --web-only

  # Export web targets to file
  %(prog)s scan_results.xml --export-web ~/.pentest-web-targets.db

  # Output as JSON
  %(prog)s scan_results.xml --json
        """
    )

    parser.add_argument('xml_file', help='Nmap XML output file to parse')
    parser.add_argument('--detailed', '-d', action='store_true',
                       help='Show detailed port information')
    parser.add_argument('--web-only', '-w', action='store_true',
                       help='Show only detected web servers')
    parser.add_argument('--sort', '-s', choices=['host', 'ports'],
                       default='host', help='Sort by host (default) or number of ports')
    parser.add_argument('--export-web', '-e', metavar='FILE',
                       help='Export web targets to file (appends)')
    parser.add_argument('--json', '-j', action='store_true',
                       help='Output results as JSON')

    args = parser.parse_args()

    # Parse nmap XML
    nmap_parser = NmapParser(args.xml_file)
    if not nmap_parser.parse():
        sys.exit(1)

    if args.json:
        # Output as JSON
        output = {
            'hosts': nmap_parser.hosts,
            'web_targets': nmap_parser.web_targets
        }
        print(json.dumps(output, indent=2))
    elif args.web_only:
        # Show only web targets
        nmap_parser.print_web_targets()
    else:
        # Show summary and optionally detailed info
        nmap_parser.print_summary()
        if args.detailed:
            nmap_parser.print_detailed(args.sort)
        nmap_parser.print_web_targets()

    # Export web targets if requested
    if args.export_web:
        entries = nmap_parser.export_web_targets(args.export_web)
        if entries:
            print(f"\nExported {len(entries)} web target(s)")


if __name__ == '__main__':
    main()
