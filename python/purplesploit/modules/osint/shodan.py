"""
Shodan Module

OSINT module for Shodan.io API integration.
Search for internet-connected devices, services, and vulnerabilities.
"""

from purplesploit.core.module import BaseModule
from typing import Dict, Any, List, Optional
from pathlib import Path
import json


class ShodanModule(BaseModule):
    """
    Shodan.io API integration module.

    Provides passive reconnaissance through Shodan's database of
    internet-connected devices and services.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self._api = None
        self._api_key = None

    @property
    def name(self) -> str:
        return "Shodan"

    @property
    def description(self) -> str:
        return "Shodan.io API for passive reconnaissance"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "osint"

    def _init_options(self):
        """Initialize Shodan-specific options."""
        self.options = {
            "API_KEY": {
                "value": None,
                "required": True,
                "description": "Shodan API key (get from account.shodan.io)",
                "default": None
            },
            "TARGET": {
                "value": None,
                "required": False,
                "description": "Target IP address or domain",
                "default": None
            },
            "QUERY": {
                "value": None,
                "required": False,
                "description": "Shodan search query",
                "default": None
            },
            "LIMIT": {
                "value": 100,
                "required": False,
                "description": "Maximum results to return",
                "default": 100
            },
        }

    def _get_api(self):
        """Get or initialize Shodan API client."""
        if self._api:
            return self._api

        try:
            import shodan
        except ImportError:
            self.log("Shodan library not installed. Run: pip install shodan", "error")
            return None

        api_key = self._get_api_key()
        if not api_key:
            return None

        try:
            self._api = shodan.Shodan(api_key)
            # Verify API key
            self._api.info()
            return self._api
        except shodan.APIError as e:
            self.log(f"Shodan API error: {e}", "error")
            return None

    def _get_api_key(self) -> Optional[str]:
        """Get API key from options, env, or config file."""
        import os

        # Check options first
        key = self.get_option("API_KEY")
        if key:
            return key

        # Check environment variable
        key = os.environ.get("SHODAN_API_KEY")
        if key:
            self.set_option("API_KEY", key)
            return key

        # Check config file
        config_file = Path.home() / ".purplesploit" / "shodan_key"
        if config_file.exists():
            key = config_file.read_text().strip()
            if key:
                self.set_option("API_KEY", key)
                return key

        return None

    def _get_target(self) -> Optional[str]:
        """Get target from options or context."""
        target = self.get_option("TARGET")
        if target:
            return target

        # Try framework context
        self.auto_set_from_context()
        context = self.get_context()

        if context.get('current_target'):
            t = context['current_target']
            if isinstance(t, dict):
                target = t.get('ip')
            else:
                target = t

            if target:
                self.set_option("TARGET", target)
                return target

        return None

    def get_operations(self) -> List[Dict[str, Any]]:
        """Get list of Shodan operations."""
        return [
            {
                "name": "Host Lookup",
                "description": "Get information about a specific IP",
                "handler": "op_host_lookup",
                "subcategory": "lookup"
            },
            {
                "name": "DNS Lookup",
                "description": "Resolve domain to IP addresses",
                "handler": "op_dns_lookup",
                "subcategory": "lookup"
            },
            {
                "name": "Reverse DNS",
                "description": "Find domains pointing to an IP",
                "handler": "op_reverse_dns",
                "subcategory": "lookup"
            },
            {
                "name": "Search Query",
                "description": "Search Shodan with custom query",
                "handler": "op_search",
                "subcategory": "search"
            },
            {
                "name": "Search Organization",
                "description": "Find hosts by organization name",
                "handler": "op_search_org",
                "subcategory": "search"
            },
            {
                "name": "Search Port",
                "description": "Find hosts with specific port open",
                "handler": "op_search_port",
                "subcategory": "search"
            },
            {
                "name": "Search Product",
                "description": "Find hosts running specific product",
                "handler": "op_search_product",
                "subcategory": "search"
            },
            {
                "name": "Vulnerabilities",
                "description": "Get known vulnerabilities for IP",
                "handler": "op_vulns",
                "subcategory": "analysis"
            },
            {
                "name": "Honeypot Check",
                "description": "Check if IP might be a honeypot",
                "handler": "op_honeypot",
                "subcategory": "analysis"
            },
            {
                "name": "API Info",
                "description": "Show API key info and credits",
                "handler": "op_api_info",
                "subcategory": "utility"
            },
        ]

    def _save_results(self, results: Dict[str, Any], operation: str):
        """Save results to file and database."""
        from datetime import datetime

        # Create output directory
        output_dir = Path.home() / ".purplesploit" / "logs" / "osint"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Save to JSON file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target = self._get_target() or "query"
        safe_target = target.replace(".", "_").replace("/", "_")[:30]
        output_file = output_dir / f"shodan_{safe_target}_{operation}_{timestamp}.json"

        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        self.log(f"Results saved to {output_file}", "info")

        # Store in database
        self.framework.database.save_scan_results(
            scan_name="shodan",
            target=target,
            scan_type="osint",
            results=results,
            file_path=str(output_file)
        )

    def _import_services(self, host_data: Dict[str, Any]):
        """Import discovered services to database."""
        ip = host_data.get('ip_str', '')
        if not ip:
            return

        for service in host_data.get('data', []):
            port = service.get('port')
            product = service.get('product', '')
            version = service.get('version', '')

            service_name = product or service.get('_shodan', {}).get('module', 'unknown')
            version_str = f"{product} {version}".strip() if version else product

            self.framework.database.add_service(
                target=ip,
                service=service_name,
                port=port,
                version=version_str
            )

        self.log(f"Imported {len(host_data.get('data', []))} services to database", "info")

    # ========================================================================
    # Operation Handlers
    # ========================================================================

    def op_host_lookup(self) -> Dict[str, Any]:
        """Get detailed information about a specific IP."""
        api = self._get_api()
        if not api:
            return {"success": False, "error": "API not available"}

        target = self._get_target()
        if not target:
            return {"success": False, "error": "TARGET required"}

        try:
            import shodan
            self.log(f"Looking up host: {target}", "info")
            host = api.host(target)

            # Format results
            result = {
                "ip": host.get('ip_str'),
                "organization": host.get('org'),
                "isp": host.get('isp'),
                "asn": host.get('asn'),
                "country": host.get('country_name'),
                "city": host.get('city'),
                "hostnames": host.get('hostnames', []),
                "domains": host.get('domains', []),
                "ports": host.get('ports', []),
                "vulns": host.get('vulns', []),
                "last_update": host.get('last_update'),
                "services": []
            }

            # Extract service details
            for service in host.get('data', []):
                svc = {
                    "port": service.get('port'),
                    "transport": service.get('transport'),
                    "product": service.get('product'),
                    "version": service.get('version'),
                    "banner": service.get('data', '')[:500],  # Truncate banner
                }
                result["services"].append(svc)

            # Import services to database
            self._import_services(host)

            # Save results
            self._save_results(result, "host")

            # Log summary
            self.log(f"Organization: {result['organization']}", "success")
            self.log(f"Open ports: {result['ports']}", "success")
            if result['vulns']:
                self.log(f"Vulnerabilities: {len(result['vulns'])} found", "warning")

            return {"success": True, "data": result}

        except shodan.APIError as e:
            return {"success": False, "error": str(e)}

    def op_dns_lookup(self) -> Dict[str, Any]:
        """Resolve domain to IP addresses."""
        api = self._get_api()
        if not api:
            return {"success": False, "error": "API not available"}

        target = self._get_target()
        if not target:
            target = input("Domain to resolve: ")
            if not target:
                return {"success": False, "error": "Domain required"}

        try:
            self.log(f"Resolving domain: {target}", "info")
            result = api.dns.domain_info(target)

            self._save_results(result, "dns")
            self.log(f"Found {len(result.get('data', []))} DNS records", "success")

            return {"success": True, "data": result}

        except Exception as e:
            # Fallback to resolve
            try:
                result = api.dns.resolve([target])
                self._save_results(result, "dns")
                return {"success": True, "data": result}
            except Exception as e2:
                return {"success": False, "error": str(e2)}

    def op_reverse_dns(self) -> Dict[str, Any]:
        """Find domains pointing to an IP."""
        api = self._get_api()
        if not api:
            return {"success": False, "error": "API not available"}

        target = self._get_target()
        if not target:
            return {"success": False, "error": "TARGET IP required"}

        try:
            self.log(f"Reverse DNS lookup: {target}", "info")
            result = api.dns.reverse([target])

            self._save_results(result, "reverse-dns")

            domains = result.get(target, [])
            self.log(f"Found {len(domains)} domains", "success")
            for domain in domains[:10]:
                self.log(f"  → {domain}", "info")
            if len(domains) > 10:
                self.log(f"  ... and {len(domains) - 10} more", "info")

            return {"success": True, "data": result}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def op_search(self) -> Dict[str, Any]:
        """Search Shodan with custom query."""
        api = self._get_api()
        if not api:
            return {"success": False, "error": "API not available"}

        query = self.get_option("QUERY")
        if not query:
            query = input("Shodan query: ")
            if not query:
                return {"success": False, "error": "QUERY required"}

        limit = self.get_option("LIMIT") or 100

        try:
            self.log(f"Searching: {query}", "info")
            results = api.search(query, limit=limit)

            summary = {
                "query": query,
                "total": results.get('total', 0),
                "matches": len(results.get('matches', [])),
                "results": []
            }

            for match in results.get('matches', []):
                summary["results"].append({
                    "ip": match.get('ip_str'),
                    "port": match.get('port'),
                    "org": match.get('org'),
                    "product": match.get('product'),
                    "hostnames": match.get('hostnames', []),
                })

            self._save_results(summary, "search")
            self.log(f"Found {summary['total']} total results ({summary['matches']} returned)", "success")

            return {"success": True, "data": summary}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def op_search_org(self) -> Dict[str, Any]:
        """Search for hosts by organization."""
        org = input("Organization name: ")
        if not org:
            return {"success": False, "error": "Organization name required"}

        self.set_option("QUERY", f'org:"{org}"')
        return self.op_search()

    def op_search_port(self) -> Dict[str, Any]:
        """Search for hosts with specific port."""
        port = input("Port number: ")
        if not port:
            return {"success": False, "error": "Port required"}

        self.set_option("QUERY", f"port:{port}")
        return self.op_search()

    def op_search_product(self) -> Dict[str, Any]:
        """Search for hosts running specific product."""
        product = input("Product name (e.g., Apache, nginx, ssh): ")
        if not product:
            return {"success": False, "error": "Product name required"}

        self.set_option("QUERY", f'product:"{product}"')
        return self.op_search()

    def op_vulns(self) -> Dict[str, Any]:
        """Get known vulnerabilities for an IP."""
        api = self._get_api()
        if not api:
            return {"success": False, "error": "API not available"}

        target = self._get_target()
        if not target:
            return {"success": False, "error": "TARGET required"}

        try:
            import shodan
            self.log(f"Checking vulnerabilities for: {target}", "info")
            host = api.host(target)

            vulns = host.get('vulns', [])
            if not vulns:
                self.log("No known vulnerabilities found", "info")
                return {"success": True, "data": {"vulns": [], "message": "No vulnerabilities"}}

            result = {
                "ip": target,
                "vulns": vulns,
                "cve_details": []
            }

            # Get CVE details
            for cve in vulns[:20]:  # Limit to 20
                try:
                    cve_info = api.exploits.search(cve)
                    if cve_info.get('matches'):
                        result["cve_details"].append({
                            "cve": cve,
                            "exploits": len(cve_info.get('matches', []))
                        })
                except Exception:
                    pass

            self._save_results(result, "vulns")
            self.log(f"Found {len(vulns)} vulnerabilities", "warning")
            for v in vulns[:10]:
                self.log(f"  → {v}", "warning")

            return {"success": True, "data": result}

        except shodan.APIError as e:
            return {"success": False, "error": str(e)}

    def op_honeypot(self) -> Dict[str, Any]:
        """Check if IP might be a honeypot."""
        api = self._get_api()
        if not api:
            return {"success": False, "error": "API not available"}

        target = self._get_target()
        if not target:
            return {"success": False, "error": "TARGET required"}

        try:
            self.log(f"Honeypot check: {target}", "info")
            score = api.labs.honeyscore(target)

            result = {
                "ip": target,
                "honeyscore": score,
                "likely_honeypot": score > 0.5
            }

            if score > 0.8:
                self.log(f"High probability honeypot! Score: {score}", "warning")
            elif score > 0.5:
                self.log(f"Possible honeypot. Score: {score}", "warning")
            else:
                self.log(f"Likely not a honeypot. Score: {score}", "success")

            return {"success": True, "data": result}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def op_api_info(self) -> Dict[str, Any]:
        """Show API key information and credits."""
        api = self._get_api()
        if not api:
            return {"success": False, "error": "API not available"}

        try:
            info = api.info()

            self.log(f"Plan: {info.get('plan', 'unknown')}", "info")
            self.log(f"Query credits: {info.get('query_credits', 0)}", "info")
            self.log(f"Scan credits: {info.get('scan_credits', 0)}", "info")

            return {"success": True, "data": info}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def run(self) -> Dict[str, Any]:
        """Default run - host lookup."""
        return self.op_host_lookup()
