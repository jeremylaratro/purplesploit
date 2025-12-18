"""
crt.sh Module

Certificate Transparency log search for subdomain enumeration.
No API key required - uses public crt.sh database.
"""

from purplesploit.core.module import BaseModule
from typing import Dict, Any, List, Optional
from pathlib import Path
import json
import re


class CrtshModule(BaseModule):
    """
    Certificate Transparency (crt.sh) module.

    Enumerates subdomains by searching certificate transparency logs.
    Free service - no API key required.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.base_url = "https://crt.sh"

    @property
    def name(self) -> str:
        return "crt.sh"

    @property
    def description(self) -> str:
        return "Certificate Transparency subdomain enumeration"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "osint"

    def _init_options(self):
        """Initialize crt.sh options."""
        self.options = {
            "DOMAIN": {
                "value": None,
                "required": True,
                "description": "Domain to search for (e.g., example.com)",
                "default": None
            },
            "WILDCARD": {
                "value": True,
                "required": False,
                "description": "Include wildcard search",
                "default": True
            },
            "EXPIRED": {
                "value": False,
                "required": False,
                "description": "Include expired certificates",
                "default": False
            },
            "OUTPUT_FORMAT": {
                "value": "json",
                "required": False,
                "description": "Output format (json, text)",
                "default": "json"
            },
        }

    def _get_domain(self) -> Optional[str]:
        """Get domain from options or context."""
        domain = self.get_option("DOMAIN")
        if domain:
            return domain

        # Try framework context
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

    def _fetch_certs(self, domain: str, wildcard: bool = True) -> List[Dict]:
        """
        Fetch certificates from crt.sh.

        Args:
            domain: Domain to search
            wildcard: Include wildcard search

        Returns:
            List of certificate entries
        """
        import urllib.request
        import urllib.parse

        # Build query
        query = f"%.{domain}" if wildcard else domain
        url = f"{self.base_url}/?q={urllib.parse.quote(query)}&output=json"

        self.log(f"Querying crt.sh for: {query}", "info")

        try:
            req = urllib.request.Request(
                url,
                headers={'User-Agent': 'PurpleSploit/1.0'}
            )

            with urllib.request.urlopen(req, timeout=30) as response:
                data = response.read().decode('utf-8')
                if data:
                    return json.loads(data)
                return []

        except urllib.error.HTTPError as e:
            self.log(f"HTTP Error: {e.code}", "error")
            return []
        except urllib.error.URLError as e:
            self.log(f"URL Error: {e.reason}", "error")
            return []
        except json.JSONDecodeError:
            self.log("Invalid JSON response from crt.sh", "error")
            return []
        except Exception as e:
            self.log(f"Error: {e}", "error")
            return []

    def _extract_subdomains(self, certs: List[Dict]) -> List[str]:
        """Extract unique subdomains from certificate data."""
        subdomains = set()

        for cert in certs:
            name = cert.get('name_value', '')
            # Split by newline (crt.sh returns multiple names per cert)
            for subdomain in name.split('\n'):
                subdomain = subdomain.strip().lower()
                # Skip wildcards and empty
                if subdomain and not subdomain.startswith('*'):
                    subdomains.add(subdomain)

        return sorted(subdomains)

    def _save_results(self, results: Dict[str, Any], operation: str):
        """Save results to file."""
        from datetime import datetime

        output_dir = Path.home() / ".purplesploit" / "logs" / "osint"
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = self._get_domain() or "unknown"
        safe_domain = domain.replace(".", "_")

        output_file = output_dir / f"crtsh_{safe_domain}_{operation}_{timestamp}.json"

        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)

        self.log(f"Results saved to {output_file}", "info")

        # Also save plain subdomain list
        if results.get('subdomains'):
            txt_file = output_dir / f"crtsh_{safe_domain}_subdomains_{timestamp}.txt"
            with open(txt_file, 'w') as f:
                f.write('\n'.join(results['subdomains']))
            self.log(f"Subdomain list saved to {txt_file}", "info")

        return output_file

    def get_operations(self) -> List[Dict[str, Any]]:
        """Get list of crt.sh operations."""
        return [
            {
                "name": "Subdomain Enumeration",
                "description": "Find all subdomains via CT logs",
                "handler": "op_subdomains",
                "subcategory": "enumeration"
            },
            {
                "name": "Certificate Details",
                "description": "Get full certificate information",
                "handler": "op_cert_details",
                "subcategory": "enumeration"
            },
            {
                "name": "Organization Search",
                "description": "Find certs by organization name",
                "handler": "op_org_search",
                "subcategory": "search"
            },
            {
                "name": "Recent Certificates",
                "description": "Get recently issued certificates",
                "handler": "op_recent_certs",
                "subcategory": "monitoring"
            },
            {
                "name": "Export to Targets",
                "description": "Add discovered subdomains as targets",
                "handler": "op_export_targets",
                "subcategory": "utility"
            },
        ]

    # ========================================================================
    # Operation Handlers
    # ========================================================================

    def op_subdomains(self) -> Dict[str, Any]:
        """Find all subdomains via Certificate Transparency logs."""
        domain = self._get_domain()
        if not domain:
            return {"success": False, "error": "DOMAIN required"}

        wildcard = self.get_option("WILDCARD")

        # Fetch certificates
        certs = self._fetch_certs(domain, wildcard)

        if not certs:
            self.log(f"No certificates found for {domain}", "warning")
            return {"success": True, "data": {"subdomains": [], "count": 0}}

        # Extract subdomains
        subdomains = self._extract_subdomains(certs)

        result = {
            "domain": domain,
            "subdomains": subdomains,
            "count": len(subdomains),
            "certificates_analyzed": len(certs)
        }

        # Save results
        self._save_results(result, "subdomains")

        # Log summary
        self.log(f"Found {len(subdomains)} unique subdomains", "success")
        for sub in subdomains[:20]:
            self.log(f"  → {sub}", "info")
        if len(subdomains) > 20:
            self.log(f"  ... and {len(subdomains) - 20} more", "info")

        return {"success": True, "data": result}

    def op_cert_details(self) -> Dict[str, Any]:
        """Get detailed certificate information."""
        domain = self._get_domain()
        if not domain:
            return {"success": False, "error": "DOMAIN required"}

        certs = self._fetch_certs(domain, wildcard=False)

        if not certs:
            return {"success": True, "data": {"certificates": [], "count": 0}}

        # Process certificates
        processed = []
        for cert in certs[:50]:  # Limit to 50
            processed.append({
                "id": cert.get('id'),
                "issuer_name": cert.get('issuer_name'),
                "common_name": cert.get('common_name'),
                "name_value": cert.get('name_value'),
                "not_before": cert.get('not_before'),
                "not_after": cert.get('not_after'),
                "serial_number": cert.get('serial_number'),
            })

        result = {
            "domain": domain,
            "certificates": processed,
            "count": len(certs)
        }

        self._save_results(result, "certs")
        self.log(f"Found {len(certs)} certificates", "success")

        return {"success": True, "data": result}

    def op_org_search(self) -> Dict[str, Any]:
        """Search certificates by organization name."""
        import urllib.request
        import urllib.parse

        org = input("Organization name: ")
        if not org:
            return {"success": False, "error": "Organization name required"}

        url = f"{self.base_url}/?O={urllib.parse.quote(org)}&output=json"

        self.log(f"Searching certs for organization: {org}", "info")

        try:
            req = urllib.request.Request(
                url,
                headers={'User-Agent': 'PurpleSploit/1.0'}
            )

            with urllib.request.urlopen(req, timeout=30) as response:
                data = response.read().decode('utf-8')
                certs = json.loads(data) if data else []

            # Extract unique domains
            domains = set()
            for cert in certs:
                name = cert.get('name_value', '')
                for subdomain in name.split('\n'):
                    subdomain = subdomain.strip().lower()
                    if subdomain and not subdomain.startswith('*'):
                        # Extract base domain
                        parts = subdomain.split('.')
                        if len(parts) >= 2:
                            domains.add('.'.join(parts[-2:]))

            result = {
                "organization": org,
                "certificates": len(certs),
                "domains": sorted(domains)
            }

            self._save_results(result, "org")
            self.log(f"Found {len(certs)} certificates for {len(domains)} domains", "success")

            return {"success": True, "data": result}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def op_recent_certs(self) -> Dict[str, Any]:
        """Get recently issued certificates for monitoring."""
        domain = self._get_domain()
        if not domain:
            return {"success": False, "error": "DOMAIN required"}

        certs = self._fetch_certs(domain, wildcard=True)

        if not certs:
            return {"success": True, "data": {"recent": [], "count": 0}}

        # Sort by not_before (most recent first)
        sorted_certs = sorted(
            certs,
            key=lambda x: x.get('not_before', ''),
            reverse=True
        )

        # Take recent 20
        recent = []
        for cert in sorted_certs[:20]:
            recent.append({
                "name": cert.get('name_value', '').split('\n')[0],
                "issuer": cert.get('issuer_name'),
                "issued": cert.get('not_before'),
                "expires": cert.get('not_after'),
            })

        result = {
            "domain": domain,
            "recent_certificates": recent,
            "total_found": len(certs)
        }

        self._save_results(result, "recent")
        self.log(f"Most recent certificates for {domain}:", "success")
        for cert in recent[:5]:
            self.log(f"  → {cert['name']} (issued: {cert['issued']})", "info")

        return {"success": True, "data": result}

    def op_export_targets(self) -> Dict[str, Any]:
        """Export discovered subdomains as targets in framework."""
        # First run subdomain enumeration
        sub_result = self.op_subdomains()
        if not sub_result.get('success'):
            return sub_result

        subdomains = sub_result.get('data', {}).get('subdomains', [])
        if not subdomains:
            return {"success": False, "error": "No subdomains to export"}

        # Add as web targets
        added = 0
        for subdomain in subdomains:
            try:
                from purplesploit.models.database import WebTarget
                self.framework.database.add_web_target(
                    name=subdomain,
                    url=f"https://{subdomain}",
                    description=f"Discovered via crt.sh"
                )
                added += 1
            except Exception:
                continue

        self.log(f"Added {added} subdomains as web targets", "success")
        return {"success": True, "data": {"added": added, "subdomains": subdomains}}

    def run(self) -> Dict[str, Any]:
        """Default run - subdomain enumeration."""
        return self.op_subdomains()
