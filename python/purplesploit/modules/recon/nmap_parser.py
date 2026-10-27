"""
Nmap XML Parser Module

Parses nmap XML output and populates the service database with detected services.
Also runs searchsploit on discovered service versions to find potential exploits.
"""

import subprocess
import re
from typing import Dict, Any, List, Tuple
from purplesploit.core.module import BaseModule
from purplesploit.models.database import db_manager
from purplesploit.modules.recon.nmap_importer import (
    SERVICE_ALIASES, import_discovered_hosts, parse_nmap_xml,
)


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
        """Import completed XML through the scanner's shared offline importer."""
        checked = self.check()
        if not checked["success"]:
            return checked
        try:
            request = self.execution_request or getattr(self, "_execution_context_request", None)
            parsed = parse_nmap_xml(
                self.get_option("XML_FILE"),
                source_execution_id=request.request_id if request else "",
                module_path=request.module_path if request else "recon/nmap_parser",
            )
            counts = import_discovered_hosts(
                self.framework, parsed, models_db=db_manager, log=self.log,
                auto_add=self.option_enabled("AUTO_ADD_TARGETS"),
            )
            exploits_found = 0
            if self.option_enabled("RUN_SEARCHSPLOIT"):
                for host in parsed["discovered_hosts"]:
                    for service in host["services"].values():
                        version = service.get("service_version", "")
                        if not version:
                            continue
                        product = service.get("product") or service["service"]
                        for title, path, edb_id in self._run_searchsploit(product, version):
                            try:
                                db_manager.add_exploit(
                                    target=host["ip"],
                                    service=SERVICE_ALIASES.get(service["service"], service["service"]),
                                    port=service["port"], version=service["version"],
                                    exploit_title=title, exploit_path=path, edb_id=edb_id,
                                )
                                exploits_found += 1
                            except Exception as exc:
                                self.log(f"Error storing exploit: {exc}", "error")
            counts["exploits_found"] = exploits_found
            return {
                "success": True, "output": "Parsed nmap results successfully", "data": counts,
                "hosts": parsed["hosts"], "observations": parsed["observations"],
                "message": (f"Processed {counts['hosts_processed']} hosts, found "
                            f"{counts['services_found']} services, discovered "
                            f"{exploits_found} potential exploits"),
            }
        except (OSError, ValueError) as exc:
            return {"success": False, "error": f"Error parsing nmap XML: {exc}", "observations": []}
        except Exception as exc:
            return {"success": False, "error": f"Error importing nmap XML: {exc}", "observations": []}

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
