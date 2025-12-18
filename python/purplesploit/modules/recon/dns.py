"""
DNS Enumeration Module

DNS reconnaissance using dig for zone transfers, record enumeration, and subdomain discovery.
"""

from purplesploit.core.module import ExternalToolModule
from typing import List, Dict, Any
import re


class DNSModule(ExternalToolModule):
    """
    DNS Enumeration - DNS reconnaissance using dig.

    Performs zone transfers, record enumeration, and DNS information gathering.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "dig"

    @property
    def name(self) -> str:
        return "DNS Enumeration"

    @property
    def description(self) -> str:
        return "DNS reconnaissance using dig for zone transfers and record enumeration"

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
            "DOMAIN": {
                "value": None,
                "required": True,
                "description": "Target domain to enumerate",
                "default": None
            },
            "NAMESERVER": {
                "value": None,
                "required": False,
                "description": "DNS server to query (default: domain's NS)",
                "default": None
            },
            "RECORD_TYPE": {
                "value": "ANY",
                "required": False,
                "description": "Record type to query (A, AAAA, MX, NS, TXT, SOA, ANY, AXFR)",
                "default": "ANY"
            },
        })

    def get_operations(self) -> List[Dict[str, Any]]:
        """Get available DNS operations."""
        return [
            {
                "name": "Zone Transfer (AXFR)",
                "description": "Attempt DNS zone transfer to dump all records",
                "handler": self.op_zone_transfer
            },
            {
                "name": "All Records",
                "description": "Query all common record types",
                "handler": self.op_all_records
            },
            {
                "name": "NS Records",
                "description": "Get nameserver records",
                "handler": self.op_ns_records
            },
            {
                "name": "MX Records",
                "description": "Get mail exchanger records",
                "handler": self.op_mx_records
            },
            {
                "name": "TXT Records",
                "description": "Get TXT records (SPF, DKIM, etc.)",
                "handler": self.op_txt_records
            },
            {
                "name": "SOA Record",
                "description": "Get Start of Authority record",
                "handler": self.op_soa_record
            },
            {
                "name": "Reverse Lookup",
                "description": "Perform reverse DNS lookup on IP",
                "handler": self.op_reverse_lookup
            },
        ]

    def build_command(self) -> str:
        """Build the dig command."""
        domain = self.get_option("DOMAIN")
        nameserver = self.get_option("NAMESERVER")
        record_type = self.get_option("RECORD_TYPE")

        cmd = "dig"

        # Add nameserver if specified
        if nameserver:
            cmd += f" @{nameserver}"

        # Add domain
        cmd += f" {domain}"

        # Add record type
        if record_type:
            cmd += f" {record_type}"

        # Add +short for cleaner output in some cases
        cmd += " +noall +answer"

        return cmd

    def op_zone_transfer(self) -> Dict[str, Any]:
        """Attempt DNS zone transfer."""
        domain = self.get_option("DOMAIN")
        nameserver = self.get_option("NAMESERVER")

        # First get NS records if no nameserver specified
        if not nameserver:
            ns_cmd = f"dig {domain} NS +short"
            ns_result = self.execute_command(ns_cmd)
            if ns_result.get("success") and ns_result.get("output"):
                nameservers = ns_result["output"].strip().split('\n')
                nameserver = nameservers[0].rstrip('.') if nameservers else domain
            else:
                nameserver = domain

        # Attempt zone transfer
        cmd = f"dig @{nameserver} {domain} AXFR"
        result = self.execute_command(cmd)

        if result.get("success"):
            output = result.get("output", "")
            parsed = self._parse_zone_transfer(output)
            result["parsed"] = parsed

            if parsed.get("records"):
                result["message"] = f"Zone transfer successful! Found {len(parsed['records'])} records"

                # Add discovered hosts to session
                for record in parsed.get("records", []):
                    if record.get("type") in ["A", "AAAA"]:
                        self._add_target(record.get("value"), record.get("name"))
            else:
                result["message"] = "Zone transfer failed or not allowed"

        return result

    def op_all_records(self) -> Dict[str, Any]:
        """Query all common record types."""
        domain = self.get_option("DOMAIN")
        nameserver = self.get_option("NAMESERVER")

        results = {
            "success": True,
            "records": {},
            "output": ""
        }

        record_types = ["A", "AAAA", "NS", "MX", "TXT", "SOA", "CNAME", "SRV"]

        for rtype in record_types:
            ns_part = f"@{nameserver} " if nameserver else ""
            cmd = f"dig {ns_part}{domain} {rtype} +noall +answer"
            result = self.execute_command(cmd)

            if result.get("success") and result.get("output", "").strip():
                results["records"][rtype] = result["output"].strip()
                results["output"] += f"\n=== {rtype} Records ===\n{result['output']}"

        results["message"] = f"Queried {len(record_types)} record types, found {len(results['records'])} with data"
        return results

    def op_ns_records(self) -> Dict[str, Any]:
        """Get nameserver records."""
        domain = self.get_option("DOMAIN")
        nameserver = self.get_option("NAMESERVER")

        ns_part = f"@{nameserver} " if nameserver else ""
        cmd = f"dig {ns_part}{domain} NS +noall +answer"

        result = self.execute_command(cmd)
        if result.get("success"):
            result["parsed"] = self._parse_records(result.get("output", ""))
        return result

    def op_mx_records(self) -> Dict[str, Any]:
        """Get mail exchanger records."""
        domain = self.get_option("DOMAIN")
        nameserver = self.get_option("NAMESERVER")

        ns_part = f"@{nameserver} " if nameserver else ""
        cmd = f"dig {ns_part}{domain} MX +noall +answer"

        result = self.execute_command(cmd)
        if result.get("success"):
            result["parsed"] = self._parse_records(result.get("output", ""))
        return result

    def op_txt_records(self) -> Dict[str, Any]:
        """Get TXT records."""
        domain = self.get_option("DOMAIN")
        nameserver = self.get_option("NAMESERVER")

        ns_part = f"@{nameserver} " if nameserver else ""
        cmd = f"dig {ns_part}{domain} TXT +noall +answer"

        result = self.execute_command(cmd)
        if result.get("success"):
            result["parsed"] = self._parse_records(result.get("output", ""))
        return result

    def op_soa_record(self) -> Dict[str, Any]:
        """Get SOA record."""
        domain = self.get_option("DOMAIN")
        nameserver = self.get_option("NAMESERVER")

        ns_part = f"@{nameserver} " if nameserver else ""
        cmd = f"dig {ns_part}{domain} SOA +noall +answer"

        result = self.execute_command(cmd)
        if result.get("success"):
            result["parsed"] = self._parse_soa(result.get("output", ""))
        return result

    def op_reverse_lookup(self) -> Dict[str, Any]:
        """Perform reverse DNS lookup."""
        target = self.get_option("DOMAIN")  # In this case, it's an IP
        nameserver = self.get_option("NAMESERVER")

        ns_part = f"@{nameserver} " if nameserver else ""
        cmd = f"dig {ns_part}-x {target} +noall +answer"

        result = self.execute_command(cmd)
        if result.get("success"):
            result["parsed"] = self._parse_records(result.get("output", ""))
        return result

    def _parse_zone_transfer(self, output: str) -> Dict[str, Any]:
        """Parse zone transfer output."""
        records = []
        subdomains = set()

        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith(';'):
                continue

            parts = line.split()
            if len(parts) >= 5:
                record = {
                    "name": parts[0].rstrip('.'),
                    "ttl": parts[1],
                    "class": parts[2],
                    "type": parts[3],
                    "value": ' '.join(parts[4:]).rstrip('.')
                }
                records.append(record)

                # Extract subdomain
                if record["name"] and record["type"] in ["A", "AAAA", "CNAME"]:
                    subdomains.add(record["name"])

        return {
            "records": records,
            "subdomains": list(subdomains),
            "record_count": len(records)
        }

    def _parse_records(self, output: str) -> List[Dict[str, str]]:
        """Parse dig answer section."""
        records = []

        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith(';'):
                continue

            parts = line.split()
            if len(parts) >= 5:
                records.append({
                    "name": parts[0].rstrip('.'),
                    "ttl": parts[1],
                    "class": parts[2],
                    "type": parts[3],
                    "value": ' '.join(parts[4:]).rstrip('.')
                })

        return records

    def _parse_soa(self, output: str) -> Dict[str, Any]:
        """Parse SOA record."""
        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith(';'):
                continue

            parts = line.split()
            if len(parts) >= 7 and parts[3] == "SOA":
                return {
                    "primary_ns": parts[4].rstrip('.'),
                    "admin_email": parts[5].rstrip('.').replace('.', '@', 1),
                    "serial": parts[6] if len(parts) > 6 else "",
                    "refresh": parts[7] if len(parts) > 7 else "",
                    "retry": parts[8] if len(parts) > 8 else "",
                    "expire": parts[9] if len(parts) > 9 else "",
                    "minimum": parts[10] if len(parts) > 10 else "",
                }

        return {}

    def _add_target(self, ip: str, hostname: str):
        """Add discovered target to session."""
        if self.framework and hasattr(self.framework, 'session'):
            try:
                self.framework.session.targets.add({
                    'ip': ip,
                    'hostname': hostname,
                    'source': 'dns_enum'
                })
            except Exception:
                pass

    def parse_output(self, output: str) -> dict:
        """Parse dig output."""
        return {
            "records": self._parse_records(output),
            "raw": output
        }

    def run(self) -> Dict[str, Any]:
        """Default run performs zone transfer."""
        return self.op_zone_transfer()
