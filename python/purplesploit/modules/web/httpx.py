"""
HTTPx Module

Fast HTTP probe and analysis tool.
"""

from purplesploit.core.module import ExternalToolModule


class HTTPxModule(ExternalToolModule):
    """
    HTTPx - Fast HTTP probe and analysis tool.

    Probes for working HTTP/HTTPS services and extracts useful information.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "httpx"

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
        if target.startswith("http"):
            cmd = f"echo '{target}' | httpx"
        else:
            cmd = f"httpx -u '{target}'"

        # Ports
        if ports:
            cmd += f" -p {ports}"

        # Threads
        if threads:
            cmd += f" -threads {threads}"

        # Timeout
        if timeout:
            cmd += f" -timeout {timeout}"

        # Output options
        if self.get_option("TITLE") and self.get_option("TITLE").lower() == "true":
            cmd += " -title"

        if self.get_option("STATUS_CODE") and self.get_option("STATUS_CODE").lower() == "true":
            cmd += " -status-code"

        if self.get_option("TECH_DETECT") and self.get_option("TECH_DETECT").lower() == "true":
            cmd += " -tech-detect"

        if self.get_option("CONTENT_LENGTH") and self.get_option("CONTENT_LENGTH").lower() == "true":
            cmd += " -content-length"

        if self.get_option("FOLLOW_REDIRECTS") and self.get_option("FOLLOW_REDIRECTS").lower() == "true":
            cmd += " -follow-redirects"

        # Silent mode for cleaner output
        cmd += " -silent"

        return cmd

    def parse_output(self, output: str) -> dict:
        """
        Parse httpx output.

        Args:
            output: Command stdout

        Returns:
            Parsed results dictionary
        """
        results = {
            "live_hosts": [],
            "technologies": [],
        }

        # Parse output
        for line in output.split('\n'):
            if line.strip() and line.startswith('http'):
                results["live_hosts"].append(line.strip())

                # Extract technologies if present
                if '[' in line and ']' in line:
                    tech_start = line.index('[')
                    tech_end = line.index(']', tech_start)
                    tech = line[tech_start+1:tech_end]
                    if tech:
                        results["technologies"].append(tech)

        return results
