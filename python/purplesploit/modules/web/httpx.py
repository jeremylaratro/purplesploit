"""
HTTPx Module

Fast HTTP probe and analysis tool.
"""

from pathlib import Path
import re
import shlex

from purplesploit.web_observations import WebToolModule, json_records, observation


class HTTPxModule(WebToolModule):
    """
    HTTPx - Fast HTTP probe and analysis tool.

    Probes for working HTTP/HTTPS services and extracts useful information.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "httpx"

    emits = ["http_endpoint", "service", "technology"]
    supported_tool_versions = ["ProjectDiscovery httpx 1.x (-json)"]

    @property
    def name(self) -> str:
        return "HTTPx"

    @property
    def description(self) -> str:
        return "Fast HTTP probe and analysis tool for discovering web services"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "web"

    def _init_options(self):
        """Initialize module-specific options."""
        super()._init_options()

        self.options.update({
            "TARGET": {
                "value": None,
                "required": True,
                "description": "Target URL, IP, or file with list",
                "default": None
            },
            "PORTS": {
                "value": "80,443,8080,8443",
                "required": False,
                "description": "Ports to probe (comma-separated)",
                "default": "80,443,8080,8443"
            },
            "TITLE": {
                "value": "true",
                "required": False,
                "description": "Extract page titles",
                "default": "true"
            },
            "STATUS_CODE": {
                "value": "true",
                "required": False,
                "description": "Show status codes",
                "default": "true"
            },
            "TECH_DETECT": {
                "value": "true",
                "required": False,
                "description": "Detect technologies",
                "default": "true"
            },
            "CONTENT_LENGTH": {
                "value": "true",
                "required": False,
                "description": "Show content length",
                "default": "true"
            },
            "FOLLOW_REDIRECTS": {
                "value": "false",
                "required": False,
                "description": "Follow redirects",
                "default": "false"
            },
            "THREADS": {
                "value": "50",
                "required": False,
                "description": "Number of concurrent threads",
                "default": "50"
            },
            "TIMEOUT": {
                "value": "10",
                "required": False,
                "description": "Timeout in seconds",
                "default": "10"
            }
        })

    def build_command(self) -> str:
        """
        Build the httpx command.

        Returns:
            Command string to execute
        """
        target = self.get_option("TARGET")
        ports = self.get_option("PORTS")
        threads = self.get_option("THREADS")
        timeout = self.get_option("TIMEOUT")

        # Base command
        target_flag = "-l" if target and Path(str(target)).is_file() else "-u"
        cmd = f"httpx {target_flag} {self.quote_arg(target)}"

        # Ports
        if ports:
            cmd += f" -p {self.quote_arg(ports)}"

        # Threads
        if threads:
            cmd += f" -threads {self.quote_arg(threads)}"

        # Timeout
        if timeout:
            cmd += f" -timeout {self.quote_arg(timeout)}"

        # Output options
        if self.option_enabled("TITLE"):
            cmd += " -title"

        if self.option_enabled("STATUS_CODE"):
            cmd += " -status-code"

        if self.option_enabled("TECH_DETECT"):
            cmd += " -tech-detect"

        if self.option_enabled("CONTENT_LENGTH"):
            cmd += " -content-length"

        if self.option_enabled("FOLLOW_REDIRECTS"):
            cmd += " -follow-redirects"

        # Silent mode for cleaner output
        cmd += " -silent -json -web-server"

        return cmd

    def build_argv(self):
        return shlex.split(self.build_command())

    def parse_output(self, output: str) -> dict:
        """
        Parse httpx output.

        Args:
            output: Command stdout

        Returns:
            Parsed results dictionary
        """
        results = {"live_hosts": [], "technologies": [], "endpoints": [], "observations": []}
        records, errors = json_records(output)
        if output.strip().startswith(("{", "[")):
            results["parse_errors"] = errors
        if not records:
            for line in output.splitlines():
                if not line.startswith(("http://", "https://")):
                    continue
                results["live_hosts"].append(line.strip())
                groups = re.findall(r"\[([^]]*)\]", line)
                record = {"url": line.split()[0]}
                if groups and groups[0].isdigit():
                    record["status_code"] = int(groups.pop(0))
                # Text fields are ambiguous; retain them without calling status/title a technology.
                record["text_fields"] = groups
                if len(groups) == 1 and re.fullmatch(r"[\w.+:-]+(?:,[\w.+:-]+)*", groups[0]):
                    record["tech"] = groups[0].split(",")
                records.append(record)
        for record in records:
            url = record.get("url") or record.get("input")
            if not url or not str(url).startswith(("http://", "https://")):
                continue
            if not results["live_hosts"] or str(url) not in [line.split()[0] for line in results["live_hosts"]]:
                results["live_hosts"].append(url)
            tech = record.get("tech") or record.get("technologies") or []
            tech = [tech] if isinstance(tech, str) else tech
            endpoint = {**record, "url": url, "status": record.get("status_code", record.get("status-code")),
                        "title": record.get("title"), "webserver": record.get("webserver", record.get("web-server")),
                        "tech": tech}
            results["endpoints"].append(endpoint)
            results["observations"].append(observation("http_endpoint", url, **{k: v for k, v in endpoint.items() if k != "url"}))
            service = observation("service", url, webserver=endpoint["webserver"], status=endpoint["status"])
            service["target"] = service["attributes"]["host"] or url
            results["observations"].append(service)
            for technology in tech:
                results["technologies"].append(technology)
                results["observations"].append(observation("technology", url, name=technology))
        return results
