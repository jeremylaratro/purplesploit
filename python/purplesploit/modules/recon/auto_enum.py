"""
Auto-Enumeration Module

Comprehensive automated enumeration combining multiple reconnaissance tools.
Inspired by enum.sh but improved with better error handling and integration.
"""

import os
import subprocess
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List
from purplesploit.core.module import ExternalToolModule


class AutoEnumModule(ExternalToolModule):
    """
    Auto-Enumeration - Automated comprehensive reconnaissance.

    Orchestrates multiple tools for network, web, DNS, and service enumeration.
    Organizes output into structured directories and provides detailed results.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "auto-enum"
        self.output_dir = None
        self.results = {
            "network": {},
            "web": {},
            "dns": {},
            "services": {},
            "vulnerabilities": []
        }

    @property
    def name(self) -> str:
        return "Auto-Enumeration"

    @property
    def description(self) -> str:
        return "Automated comprehensive enumeration (network, web, DNS, services)"

    @property
    def author(self) -> str:
        return "Jeremy Laratro (adapted for PurpleSploit)"

    @property
    def category(self) -> str:
        return "recon"

    def _init_options(self):
        """Initialize module-specific options."""
        super()._init_options()

        self.options.update({
            "TARGET": {
                "value": None,
                "required": True,
                "description": "Target IP address or domain",
                "default": None
            },
            "DOMAIN": {
                "value": None,
                "required": False,
                "description": "Domain name (for DNS/subdomain enum)",
                "default": None
            },
            "OUTPUT_DIR": {
                "value": None,
                "required": False,
                "description": "Output directory (auto-generated if not set)",
                "default": None
            },
            "NETWORK_SCAN": {
                "value": "true",
                "required": False,
                "description": "Run network enumeration (nmap/rustscan)",
                "default": "true"
            },
            "WEB_SCAN": {
                "value": "true",
                "required": False,
                "description": "Run web enumeration (httpx/whatweb/gospider)",
                "default": "true"
            },
            "DIR_SCAN": {
                "value": "true",
                "required": False,
                "description": "Run directory enumeration (feroxbuster)",
                "default": "true"
            },
            "DNS_SCAN": {
                "value": "false",
                "required": False,
                "description": "Run DNS/subdomain enumeration (requires DOMAIN)",
                "default": "false"
            },
            "SMB_SCAN": {
                "value": "true",
                "required": False,
                "description": "Run SMB enumeration if port 445 is open",
                "default": "true"
            },
            "EXPLOIT_SEARCH": {
                "value": "true",
                "required": False,
                "description": "Search for exploits using searchsploit",
                "default": "true"
            },
            "WORDLIST": {
                "value": "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt",
                "required": False,
                "description": "Wordlist for directory bruteforcing",
                "default": "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt"
            },
            "THREADS": {
                "value": "50",
                "required": False,
                "description": "Number of threads for various tools",
                "default": "50"
            },
            "ADD_TO_HOSTS": {
                "value": "false",
                "required": False,
                "description": "Add domain to /etc/hosts (requires DOMAIN)",
                "default": "false"
            }
        })

    def _setup_output_dir(self) -> str:
        """
        Setup organized output directory structure.

        Returns:
            Path to output directory
        """
        output_dir = self.get_option("OUTPUT_DIR")
        target = self.get_option("TARGET")

        if not output_dir:
            # Auto-generate output directory
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_target = target.replace(".", "_").replace("/", "_")
            output_dir = f"./enum_output/{safe_target}_{timestamp}"

        # Create directory structure
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        Path(f"{output_dir}/network").mkdir(exist_ok=True)
        Path(f"{output_dir}/web").mkdir(exist_ok=True)
        Path(f"{output_dir}/dns").mkdir(exist_ok=True)
        Path(f"{output_dir}/services").mkdir(exist_ok=True)
        Path(f"{output_dir}/exploits").mkdir(exist_ok=True)

        self.log(f"Output directory: {output_dir}", "info")
        return output_dir

    def _check_tool(self, tool_name: str) -> bool:
        """
        Check if a tool is installed.

        Args:
            tool_name: Name of the tool to check

        Returns:
            True if tool is available
        """
        import shutil
        return shutil.which(tool_name) is not None

    def _run_command(self, cmd: str, output_file: str = None, timeout: int = None) -> Dict[str, Any]:
        """
        Run a command and optionally save output.

        Args:
            cmd: Command to run
            output_file: Optional file to save output
            timeout: Optional timeout in seconds

        Returns:
            Dictionary with success status and output
        """
        try:
            self.log(f"Running: {cmd}", "info")

            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            output = result.stdout

            # Save to file if specified
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(output)
                    if result.stderr:
                        f.write("\n=== STDERR ===\n")
                        f.write(result.stderr)

            return {
                "success": result.returncode == 0,
                "output": output,
                "stderr": result.stderr,
                "returncode": result.returncode
            }

        except subprocess.TimeoutExpired:
            self.log(f"Command timed out after {timeout}s", "warning")
            return {"success": False, "error": "Timeout", "output": ""}
        except Exception as e:
            self.log(f"Error running command: {e}", "error")
            return {"success": False, "error": str(e), "output": ""}

    def _network_enumeration(self) -> Dict[str, Any]:
        """
        Perform network enumeration using nmap/rustscan.

        Returns:
            Dictionary with discovered ports and services
        """
        self.log("=== Starting Network Enumeration ===", "info")
        target = self.get_option("TARGET")
        output_dir = self.output_dir

        results = {
            "ports": [],
            "services": []
        }

        # Try rustscan first (faster), fall back to nmap
        if self._check_tool("rustscan"):
            self.log("Running rustscan for fast port discovery...", "info")
            cmd = f"rustscan -a {target} --ulimit 5000 -- -sV -sC"
            result = self._run_command(cmd, f"{output_dir}/network/rustscan.txt", timeout=600)

            if result["success"]:
                # Parse ports from output
                ports = self._parse_nmap_ports(result["output"])
                results["ports"] = ports
        else:
            self.log("rustscan not found, using nmap", "warning")

        # Always run comprehensive nmap scan
        self.log("Running nmap comprehensive scan...", "info")
        nmap_cmd = f"nmap -p- -sV -sC -T4 --min-rate 1000 {target} -oN {output_dir}/network/nmap_full.txt -oX {output_dir}/network/nmap_full.xml"
        result = self._run_command(nmap_cmd, timeout=1800)

        if result["success"]:
            ports = self._parse_nmap_ports(result["output"])
            services = self._parse_nmap_services(result["output"])
            results["ports"] = ports
            results["services"] = services

            self.log(f"Found {len(ports)} open ports", "success")

        self.results["network"] = results
        return results

    def _parse_nmap_ports(self, output: str) -> List[int]:
        """Parse open ports from nmap output."""
        ports = []
        for line in output.split('\n'):
            if '/tcp' in line and 'open' in line:
                try:
                    port = int(line.split('/')[0].strip())
                    ports.append(port)
                except:
                    pass
        return sorted(ports)

    def _parse_nmap_services(self, output: str) -> List[Dict[str, str]]:
        """Parse service information from nmap output."""
        services = []
        for line in output.split('\n'):
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        port = int(parts[0].split('/')[0])
                        service = parts[2] if len(parts) > 2 else "unknown"
                        version = ' '.join(parts[3:]) if len(parts) > 3 else ""

                        services.append({
                            "port": port,
                            "service": service,
                            "version": version
                        })
                    except:
                        pass
        return services

    def _web_enumeration(self, ports: List[int] = None) -> Dict[str, Any]:
        """
        Perform web enumeration using httpx and whatweb.

        Args:
            ports: List of ports to check (or auto-detect common web ports)

        Returns:
            Dictionary with web service information
        """
        self.log("=== Starting Web Enumeration ===", "info")
        target = self.get_option("TARGET")
        output_dir = self.output_dir

        results = {
            "live_urls": [],
            "technologies": []
        }

        # Determine ports to scan
        if not ports:
            ports = [80, 443, 8000, 8080, 8443]
        else:
            # Filter to likely web ports
            web_ports = [p for p in ports if p in [80, 443, 8000, 8080, 8443, 8888, 3000, 5000, 9090]]
            if web_ports:
                ports = web_ports

        # Use httpx to probe web services
        if self._check_tool("httpx"):
            self.log("Running httpx for web service discovery...", "info")
            ports_str = ",".join(map(str, ports))
            cmd = f"echo {target} | httpx -p {ports_str} -title -tech-detect -status-code -silent"
            result = self._run_command(cmd, f"{output_dir}/web/httpx.txt", timeout=300)

            if result["success"]:
                for line in result["output"].split('\n'):
                    if line.strip() and line.startswith('http'):
                        results["live_urls"].append(line.strip())

                self.log(f"Found {len(results['live_urls'])} live web services", "success")

        # Use whatweb for technology detection
        if self._check_tool("whatweb") and results["live_urls"]:
            self.log("Running whatweb for technology fingerprinting...", "info")
            for url in results["live_urls"][:5]:  # Limit to first 5 URLs
                cmd = f"whatweb -a 3 {url}"
                result = self._run_command(cmd, f"{output_dir}/web/whatweb_{url.replace('://', '_').replace('/', '_')}.txt")

                if result["success"] and result["output"]:
                    results["technologies"].append({
                        "url": url,
                        "info": result["output"]
                    })

        # Run gospider for crawling if available
        if self._check_tool("gospider") and results["live_urls"]:
            self.log("Running gospider for web crawling...", "info")
            for url in results["live_urls"][:3]:  # Limit to first 3 URLs
                cmd = f"gospider -s {url} -d 2 -t 20 -c 10"
                self._run_command(cmd, f"{output_dir}/web/gospider_{url.replace('://', '_').replace('/', '_')}.txt", timeout=300)

        self.results["web"] = results
        return results

    def _directory_enumeration(self, urls: List[str]) -> Dict[str, Any]:
        """
        Perform directory enumeration using feroxbuster.

        Args:
            urls: List of URLs to enumerate

        Returns:
            Dictionary with discovered directories
        """
        self.log("=== Starting Directory Enumeration ===", "info")
        output_dir = self.output_dir
        wordlist = self.get_option("WORDLIST")
        threads = self.get_option("THREADS")

        results = {"discoveries": []}

        if not urls:
            self.log("No URLs to enumerate", "warning")
            return results

        # Use feroxbuster (preferred) or dirsearch
        if self._check_tool("feroxbuster"):
            self.log("Running feroxbuster for directory enumeration...", "info")
            for url in urls[:3]:  # Limit to first 3 URLs
                safe_name = url.replace('://', '_').replace('/', '_')
                cmd = f"feroxbuster -u {url} -w {wordlist} -t {threads} -x php,html,txt,js -o {output_dir}/web/feroxbuster_{safe_name}.txt"
                self._run_command(cmd, timeout=600)

        elif self._check_tool("dirsearch"):
            self.log("Running dirsearch for directory enumeration...", "info")
            for url in urls[:3]:
                safe_name = url.replace('://', '_').replace('/', '_')
                cmd = f"dirsearch -u {url} -w {wordlist} -t {threads} -e php,html,txt,js -o {output_dir}/web/dirsearch_{safe_name}.txt"
                self._run_command(cmd, timeout=600)
        else:
            self.log("No directory enumeration tool found (feroxbuster/dirsearch)", "warning")

        return results

    def _dns_enumeration(self) -> Dict[str, Any]:
        """
        Perform DNS and subdomain enumeration.

        Returns:
            Dictionary with DNS information and subdomains
        """
        self.log("=== Starting DNS Enumeration ===", "info")
        domain = self.get_option("DOMAIN")
        output_dir = self.output_dir

        if not domain:
            self.log("DOMAIN not set, skipping DNS enumeration", "warning")
            return {}

        results = {
            "dns_records": [],
            "subdomains": []
        }

        # Basic DNS queries
        if self._check_tool("dig"):
            self.log("Running dig for DNS records...", "info")
            for record_type in ["A", "AAAA", "MX", "NS", "TXT", "SOA"]:
                cmd = f"dig {domain} {record_type} +short"
                result = self._run_command(cmd)
                if result["success"] and result["output"].strip():
                    results["dns_records"].append({
                        "type": record_type,
                        "records": result["output"].strip().split('\n')
                    })

        # Subdomain enumeration with gobuster
        if self._check_tool("gobuster"):
            self.log("Running gobuster for subdomain enumeration...", "info")
            wordlist = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
            if os.path.exists(wordlist):
                cmd = f"gobuster dns -d {domain} -w {wordlist} -t 50 -o {output_dir}/dns/gobuster_subdomains.txt"
                result = self._run_command(cmd, timeout=600)

                if result["success"]:
                    for line in result["output"].split('\n'):
                        if "Found:" in line:
                            subdomain = line.split("Found:")[1].strip()
                            results["subdomains"].append(subdomain)

        # VHOST fuzzing with ffuf if available
        if self._check_tool("ffuf"):
            target = self.get_option("TARGET")
            wordlist = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
            if os.path.exists(wordlist):
                self.log("Running ffuf for VHOST discovery...", "info")
                cmd = f"ffuf -w {wordlist} -u http://{target} -H 'Host: FUZZ.{domain}' -mc 200,301,302 -o {output_dir}/dns/vhosts.json -of json -t 50"
                self._run_command(cmd, timeout=600)

        self.results["dns"] = results
        return results

    def _smb_enumeration(self, target: str) -> Dict[str, Any]:
        """
        Perform SMB enumeration if port 445 is open.

        Args:
            target: Target IP address

        Returns:
            Dictionary with SMB enumeration results
        """
        self.log("=== Starting SMB Enumeration ===", "info")
        output_dir = self.output_dir

        results = {"enum4linux": "", "nxc": ""}

        # Try enum4linux
        if self._check_tool("enum4linux"):
            self.log("Running enum4linux...", "info")
            cmd = f"enum4linux -a {target}"
            result = self._run_command(cmd, f"{output_dir}/services/enum4linux.txt", timeout=300)
            results["enum4linux"] = result.get("output", "")

        # Try NetExec (nxc)
        if self._check_tool("nxc") or self._check_tool("netexec"):
            tool = "nxc" if self._check_tool("nxc") else "netexec"
            self.log(f"Running {tool} for SMB enumeration...", "info")

            # Basic SMB enumeration
            cmd = f"{tool} smb {target} --shares --users --groups"
            result = self._run_command(cmd, f"{output_dir}/services/nxc_smb.txt", timeout=300)
            results["nxc"] = result.get("output", "")

        self.results["services"]["smb"] = results
        return results

    def _exploit_search(self, services: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """
        Search for exploits using searchsploit.

        Args:
            services: List of service dictionaries with version info

        Returns:
            List of potential exploits
        """
        self.log("=== Searching for Exploits ===", "info")
        output_dir = self.output_dir

        if not self._check_tool("searchsploit"):
            self.log("searchsploit not found", "warning")
            return []

        exploits = []

        for service in services:
            service_name = service.get("service", "")
            version = service.get("version", "")

            if service_name and service_name != "unknown":
                search_term = f"{service_name} {version}".strip()
                self.log(f"Searching exploits for: {search_term}", "info")

                cmd = f"searchsploit {search_term}"
                result = self._run_command(cmd, timeout=30)

                if result["success"] and result["output"].strip():
                    exploits.append({
                        "service": service_name,
                        "version": version,
                        "port": service.get("port"),
                        "exploits": result["output"]
                    })

        # Save all exploits to file
        if exploits:
            exploit_file = f"{output_dir}/exploits/searchsploit_results.txt"
            with open(exploit_file, 'w') as f:
                for item in exploits:
                    f.write(f"\n{'='*60}\n")
                    f.write(f"Service: {item['service']} {item['version']} (Port {item['port']})\n")
                    f.write(f"{'='*60}\n")
                    f.write(item['exploits'])
                    f.write("\n")

            self.log(f"Found exploits for {len(exploits)} services", "success")

        self.results["vulnerabilities"] = exploits
        return exploits

    def _add_to_hosts(self):
        """Add domain to /etc/hosts file."""
        domain = self.get_option("DOMAIN")
        target = self.get_option("TARGET")

        if not domain:
            return

        try:
            # Check if entry already exists
            with open('/etc/hosts', 'r') as f:
                hosts_content = f.read()
                if domain in hosts_content:
                    self.log(f"Domain {domain} already in /etc/hosts", "info")
                    return

            # Add entry (requires sudo)
            entry = f"{target} {domain}\n"
            cmd = f"echo '{entry}' | sudo tee -a /etc/hosts"
            result = self._run_command(cmd)

            if result["success"]:
                self.log(f"Added {domain} to /etc/hosts", "success")
            else:
                self.log("Failed to add to /etc/hosts (may need sudo)", "warning")

        except Exception as e:
            self.log(f"Error modifying /etc/hosts: {e}", "error")

    def _generate_summary(self) -> str:
        """
        Generate a summary report of all findings.

        Returns:
            Summary text
        """
        summary = []
        summary.append("="*60)
        summary.append("AUTO-ENUMERATION SUMMARY")
        summary.append("="*60)
        summary.append(f"Target: {self.get_option('TARGET')}")
        if self.get_option('DOMAIN'):
            summary.append(f"Domain: {self.get_option('DOMAIN')}")
        summary.append(f"Output Directory: {self.output_dir}")
        summary.append("")

        # Network summary
        if self.results.get("network"):
            network = self.results["network"]
            summary.append(f"[+] Network Enumeration:")
            summary.append(f"    - Open Ports: {len(network.get('ports', []))}")
            if network.get('ports'):
                summary.append(f"    - Ports: {', '.join(map(str, network['ports']))}")
            summary.append(f"    - Services Identified: {len(network.get('services', []))}")
            summary.append("")

        # Web summary
        if self.results.get("web"):
            web = self.results["web"]
            summary.append(f"[+] Web Enumeration:")
            summary.append(f"    - Live URLs: {len(web.get('live_urls', []))}")
            for url in web.get('live_urls', [])[:10]:
                summary.append(f"      * {url}")
            summary.append("")

        # DNS summary
        if self.results.get("dns"):
            dns = self.results["dns"]
            summary.append(f"[+] DNS Enumeration:")
            summary.append(f"    - DNS Records: {len(dns.get('dns_records', []))}")
            summary.append(f"    - Subdomains Found: {len(dns.get('subdomains', []))}")
            summary.append("")

        # Exploits summary
        if self.results.get("vulnerabilities"):
            summary.append(f"[+] Potential Exploits:")
            summary.append(f"    - Services with Exploits: {len(self.results['vulnerabilities'])}")
            for vuln in self.results["vulnerabilities"][:5]:
                summary.append(f"      * {vuln['service']} {vuln['version']} (Port {vuln['port']})")
            summary.append("")

        summary.append("="*60)
        summary.append(f"Full results saved to: {self.output_dir}")
        summary.append("="*60)

        return '\n'.join(summary)

    def build_command(self) -> str:
        """Not used - this module orchestrates multiple commands."""
        return "auto-enum (orchestrates multiple tools)"

    def run(self) -> Dict[str, Any]:
        """
        Execute the auto-enumeration module.

        Returns:
            Dictionary containing results
        """
        try:
            # Setup output directory
            self.output_dir = self._setup_output_dir()

            # Add to hosts if requested
            if self.get_option("ADD_TO_HOSTS") and self.get_option("ADD_TO_HOSTS").lower() == "true":
                self._add_to_hosts()

            # Track what we're running
            enabled_scans = []
            if self.get_option("NETWORK_SCAN").lower() == "true":
                enabled_scans.append("network")
            if self.get_option("WEB_SCAN").lower() == "true":
                enabled_scans.append("web")
            if self.get_option("DIR_SCAN").lower() == "true":
                enabled_scans.append("directory")
            if self.get_option("DNS_SCAN").lower() == "true":
                enabled_scans.append("dns")
            if self.get_option("SMB_SCAN").lower() == "true":
                enabled_scans.append("smb")
            if self.get_option("EXPLOIT_SEARCH").lower() == "true":
                enabled_scans.append("exploits")

            self.log(f"Enabled scans: {', '.join(enabled_scans)}", "info")

            # 1. Network Enumeration
            open_ports = []
            if self.get_option("NETWORK_SCAN").lower() == "true":
                network_results = self._network_enumeration()
                open_ports = network_results.get("ports", [])

            # 2. Web Enumeration
            live_urls = []
            if self.get_option("WEB_SCAN").lower() == "true":
                web_results = self._web_enumeration(open_ports)
                live_urls = web_results.get("live_urls", [])

            # 3. Directory Enumeration
            if self.get_option("DIR_SCAN").lower() == "true" and live_urls:
                self._directory_enumeration(live_urls)

            # 4. DNS Enumeration
            if self.get_option("DNS_SCAN").lower() == "true":
                self._dns_enumeration()

            # 5. SMB Enumeration (if port 445 is open)
            if self.get_option("SMB_SCAN").lower() == "true" and 445 in open_ports:
                target = self.get_option("TARGET")
                self._smb_enumeration(target)

            # 6. Exploit Search
            if self.get_option("EXPLOIT_SEARCH").lower() == "true":
                services = self.results.get("network", {}).get("services", [])
                if services:
                    self._exploit_search(services)

            # Generate summary
            summary = self._generate_summary()

            # Save summary to file
            with open(f"{self.output_dir}/SUMMARY.txt", 'w') as f:
                f.write(summary)

            # Save JSON results
            with open(f"{self.output_dir}/results.json", 'w') as f:
                json.dump(self.results, f, indent=2)

            self.log("\n" + summary, "success")

            return {
                "success": True,
                "output": summary,
                "results": self.results,
                "output_dir": self.output_dir
            }

        except Exception as e:
            self.log(f"Error during auto-enumeration: {e}", "error")
            return {
                "success": False,
                "error": str(e)
            }
