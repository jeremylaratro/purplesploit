"""
DNSDumpster Module

DNS reconnaissance using DNSDumpster.com for subdomain enumeration
and DNS record discovery.
"""

from purplesploit.core.module import BaseModule
from typing import Dict, Any, List, Optional
from pathlib import Path
import json
import re


class DNSDumpsterModule(BaseModule):
    """
    DNSDumpster.com DNS reconnaissance module.

    Discovers subdomains, DNS records, and network mappings
    through passive DNS analysis.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.base_url = "https://dnsdumpster.com"

    @property
    def name(self) -> str:
        return "DNSDumpster"

    @property
    def description(self) -> str:
        return "DNS reconnaissance and subdomain discovery"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "osint"

    def _init_options(self):
        """Initialize DNSDumpster options."""
        self.options = {
            "DOMAIN": {
                "value": None,
                "required": True,
                "description": "Target domain (e.g., example.com)",
                "default": None
            },
        }

    def _get_domain(self) -> Optional[str]:
        """Get domain from options or context."""
        domain = self.get_option("DOMAIN")
        if domain:
            return domain

        self.auto_set_from_context()
        context = self.get_context()

        if context.get('current_target'):
            t = context['current_target']
            if isinstance(t, dict):
                domain = t.get('url', '').replace('https://', '').replace('http://', '').split('/')[0]
            else:
                domain = str(t)

            if domain:
                self.set_option("DOMAIN", domain)
                return domain

        return None

    def _get_csrf_token(self, session) -> Optional[str]:
        """Get CSRF token from DNSDumpster."""
        import urllib.request

        try:
            req = urllib.request.Request(
                self.base_url,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
            )

            with urllib.request.urlopen(req, timeout=15) as response:
                html = response.read().decode('utf-8')
                cookies = response.headers.get('Set-Cookie', '')

                # Extract CSRF token
                csrf_match = re.search(r'name=["\']csrfmiddlewaretoken["\'] value=["\']([^"\']+)["\']', html)
                if csrf_match:
                    return csrf_match.group(1), cookies

        except Exception as e:
            self.log(f"Error getting CSRF token: {e}", "error")

        return None, None

    def _query_dnsdumpster(self, domain: str) -> Dict[str, Any]:
        """
        Query DNSDumpster for domain information.

        Args:
            domain: Target domain

        Returns:
            Parsed results dictionary
        """
        import urllib.request
        import urllib.parse

        self.log(f"Querying DNSDumpster for: {domain}", "info")

        # Get CSRF token
        csrf_token, cookies = self._get_csrf_token(None)
        if not csrf_token:
            self.log("Could not get CSRF token, trying alternative method", "warning")
            return self._query_alternative(domain)

        # Prepare POST data
        data = urllib.parse.urlencode({
            'csrfmiddlewaretoken': csrf_token,
            'targetip': domain,
            'user': 'free'
        }).encode('utf-8')

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Referer': self.base_url,
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        if cookies:
            headers['Cookie'] = cookies.split(';')[0]

        try:
            req = urllib.request.Request(self.base_url, data=data, headers=headers)

            with urllib.request.urlopen(req, timeout=30) as response:
                html = response.read().decode('utf-8')
                return self._parse_response(html, domain)

        except Exception as e:
            self.log(f"DNSDumpster query failed: {e}", "error")
            return self._query_alternative(domain)

    def _query_alternative(self, domain: str) -> Dict[str, Any]:
        """Alternative method using DNS lookups."""
        import socket

        results = {
            "domain": domain,
            "dns_records": {
                "a": [],
                "mx": [],
                "ns": [],
                "txt": []
            },
            "subdomains": []
        }

        # Try common subdomains
        common_subdomains = [
            'www', 'mail', 'ftp', 'smtp', 'pop', 'ns1', 'ns2',
            'webmail', 'admin', 'portal', 'vpn', 'api', 'dev',
            'staging', 'test', 'blog', 'shop', 'store', 'app',
            'cdn', 'static', 'img', 'images', 'assets', 'media',
            'secure', 'login', 'remote', 'cloud', 'm', 'mobile'
        ]

        self.log("Using DNS brute-force method", "info")

        for sub in common_subdomains:
            try:
                hostname = f"{sub}.{domain}"
                ip = socket.gethostbyname(hostname)
                results["subdomains"].append({
                    "hostname": hostname,
                    "ip": ip
                })
                self.log(f"  Found: {hostname} → {ip}", "success")
            except socket.gaierror:
                continue
            except Exception:
                continue

        # Get main domain records
        try:
            results["dns_records"]["a"] = [socket.gethostbyname(domain)]
        except Exception:
            pass

        return results

    def _parse_response(self, html: str, domain: str) -> Dict[str, Any]:
        """Parse DNSDumpster HTML response."""
        results = {
            "domain": domain,
            "dns_records": {
                "a": [],
                "mx": [],
                "ns": [],
                "txt": []
            },
            "subdomains": [],
            "host_records": []
        }

        # Extract DNS records from tables
        # A records
        a_pattern = r'<td class="col-md-4">([^<]+)</td>\s*<td class="col-md-3">(\d+\.\d+\.\d+\.\d+)</td>'
        for match in re.finditer(a_pattern, html):
            hostname, ip = match.groups()
            hostname = hostname.strip()
            if hostname and domain in hostname:
                results["subdomains"].append({
                    "hostname": hostname,
                    "ip": ip.strip()
                })
                if hostname == domain:
                    results["dns_records"]["a"].append(ip.strip())

        # MX records
        mx_pattern = r'<td[^>]*>MX</td>\s*<td[^>]*>([^<]+)</td>'
        for match in re.finditer(mx_pattern, html):
            mx = match.group(1).strip()
            if mx:
                results["dns_records"]["mx"].append(mx)

        # NS records
        ns_pattern = r'<td[^>]*>NS</td>\s*<td[^>]*>([^<]+)</td>'
        for match in re.finditer(ns_pattern, html):
            ns = match.group(1).strip()
            if ns:
                results["dns_records"]["ns"].append(ns)

        # TXT records
        txt_pattern = r'<td[^>]*>TXT</td>\s*<td[^>]*>([^<]+)</td>'
        for match in re.finditer(txt_pattern, html):
            txt = match.group(1).strip()
            if txt:
                results["dns_records"]["txt"].append(txt)

        # Extract hostnames from anywhere in the page
        hostname_pattern = rf'([a-zA-Z0-9][-a-zA-Z0-9]*\.)*{re.escape(domain)}'
        for match in re.finditer(hostname_pattern, html):
            hostname = match.group(0).lower()
            if hostname and hostname not in [s.get('hostname') for s in results["subdomains"]]:
                results["subdomains"].append({"hostname": hostname, "ip": ""})

        # Deduplicate
        seen = set()
        unique_subs = []
        for sub in results["subdomains"]:
            if sub["hostname"] not in seen:
                seen.add(sub["hostname"])
                unique_subs.append(sub)
        results["subdomains"] = unique_subs

        return results

    def _save_results(self, results: Dict[str, Any], operation: str):
        """Save results to file."""
        from datetime import datetime

        output_dir = Path.home() / ".purplesploit" / "logs" / "osint"
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = results.get("domain", "unknown")
        safe_domain = domain.replace(".", "_")

        output_file = output_dir / f"dnsdumpster_{safe_domain}_{operation}_{timestamp}.json"

        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)

        self.log(f"Results saved to {output_file}", "info")
        return output_file

    def get_operations(self) -> List[Dict[str, Any]]:
        """Get list of DNSDumpster operations."""
        return [
            {
                "name": "Full DNS Recon",
                "description": "Complete DNS reconnaissance",
                "handler": "op_full_recon",
                "subcategory": "enumeration"
            },
            {
                "name": "Subdomain Discovery",
                "description": "Find subdomains only",
                "handler": "op_subdomains",
                "subcategory": "enumeration"
            },
            {
                "name": "DNS Records",
                "description": "Get DNS records (A, MX, NS, TXT)",
                "handler": "op_dns_records",
                "subcategory": "enumeration"
            },
            {
                "name": "Export Subdomains",
                "description": "Add discovered subdomains as targets",
                "handler": "op_export_targets",
                "subcategory": "utility"
            },
        ]

    # ========================================================================
    # Operation Handlers
    # ========================================================================

    def op_full_recon(self) -> Dict[str, Any]:
        """Perform complete DNS reconnaissance."""
        domain = self._get_domain()
        if not domain:
            return {"success": False, "error": "DOMAIN required"}

        results = self._query_dnsdumpster(domain)

        if not results:
            return {"success": False, "error": "Query failed"}

        # Save results
        self._save_results(results, "full")

        # Log summary
        self.log(f"\nDNS Reconnaissance for {domain}", "success")
        self.log("="*50, "info")

        # A Records
        if results["dns_records"]["a"]:
            self.log(f"\nA Records:", "info")
            for ip in results["dns_records"]["a"]:
                self.log(f"  → {ip}", "info")

        # MX Records
        if results["dns_records"]["mx"]:
            self.log(f"\nMX Records:", "info")
            for mx in results["dns_records"]["mx"]:
                self.log(f"  → {mx}", "info")

        # NS Records
        if results["dns_records"]["ns"]:
            self.log(f"\nNS Records:", "info")
            for ns in results["dns_records"]["ns"]:
                self.log(f"  → {ns}", "info")

        # Subdomains
        if results["subdomains"]:
            self.log(f"\nSubdomains ({len(results['subdomains'])}):", "info")
            for sub in results["subdomains"][:20]:
                ip_str = f" → {sub['ip']}" if sub.get('ip') else ""
                self.log(f"  → {sub['hostname']}{ip_str}", "info")
            if len(results["subdomains"]) > 20:
                self.log(f"  ... and {len(results['subdomains']) - 20} more", "info")

        return {"success": True, "data": results}

    def op_subdomains(self) -> Dict[str, Any]:
        """Find subdomains only."""
        domain = self._get_domain()
        if not domain:
            return {"success": False, "error": "DOMAIN required"}

        results = self._query_dnsdumpster(domain)

        if not results:
            return {"success": False, "error": "Query failed"}

        subdomains = results.get("subdomains", [])

        # Save subdomain list
        output_dir = Path.home() / ".purplesploit" / "logs" / "osint"
        output_dir.mkdir(parents=True, exist_ok=True)

        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_domain = domain.replace(".", "_")

        txt_file = output_dir / f"dnsdumpster_{safe_domain}_subdomains_{timestamp}.txt"
        with open(txt_file, 'w') as f:
            for sub in subdomains:
                f.write(f"{sub['hostname']}\n")

        self.log(f"Found {len(subdomains)} subdomains", "success")
        self.log(f"Saved to {txt_file}", "info")

        for sub in subdomains[:15]:
            self.log(f"  → {sub['hostname']}", "info")
        if len(subdomains) > 15:
            self.log(f"  ... and {len(subdomains) - 15} more", "info")

        return {"success": True, "data": {"subdomains": subdomains, "count": len(subdomains)}}

    def op_dns_records(self) -> Dict[str, Any]:
        """Get DNS records for domain."""
        domain = self._get_domain()
        if not domain:
            return {"success": False, "error": "DOMAIN required"}

        results = self._query_dnsdumpster(domain)

        if not results:
            return {"success": False, "error": "Query failed"}

        records = results.get("dns_records", {})

        # Save records
        self._save_results({"domain": domain, "records": records}, "dns")

        # Display records
        self.log(f"\nDNS Records for {domain}:", "success")

        for record_type, values in records.items():
            if values:
                self.log(f"\n{record_type.upper()} Records:", "info")
                for value in values:
                    self.log(f"  → {value}", "info")

        return {"success": True, "data": records}

    def op_export_targets(self) -> Dict[str, Any]:
        """Export discovered subdomains as targets."""
        # Run subdomain discovery first
        sub_result = self.op_subdomains()
        if not sub_result.get('success'):
            return sub_result

        subdomains = sub_result.get('data', {}).get('subdomains', [])
        if not subdomains:
            return {"success": False, "error": "No subdomains to export"}

        added = 0
        for sub in subdomains:
            hostname = sub.get('hostname', '')
            ip = sub.get('ip', '')

            if hostname:
                try:
                    # Add as target
                    if ip:
                        self.framework.database.add_target(
                            name=hostname,
                            ip=ip,
                            description="Discovered via DNSDumpster"
                        )
                    # Add as web target
                    self.framework.database.add_web_target(
                        name=hostname,
                        url=f"https://{hostname}",
                        description="Discovered via DNSDumpster"
                    )
                    added += 1
                except Exception:
                    continue

        self.log(f"Added {added} targets to database", "success")
        return {"success": True, "data": {"added": added}}

    def run(self) -> Dict[str, Any]:
        """Default run - full recon."""
        return self.op_full_recon()
