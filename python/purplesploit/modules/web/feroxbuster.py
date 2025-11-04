"""
Feroxbuster Module

Fast directory and file discovery for web applications.
"""

from purplesploit.core.module import ExternalToolModule


class FeroxbusterModule(ExternalToolModule):
    """
    Feroxbuster directory and file discovery module.

    A fast, simple, recursive content discovery tool written in Rust.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "feroxbuster"

    @property
    def name(self) -> str:
        return "Feroxbuster"

    @property
    def description(self) -> str:
        return "Fast directory and file discovery tool for web applications"

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
            "URL": {
                "value": None,
                "required": True,
                "description": "Target URL (e.g., http://10.10.10.10)",
                "default": None
            },
            "WORDLIST": {
                "value": "/usr/share/wordlists/dirb/common.txt",
                "required": False,
                "description": "Wordlist path",
                "default": "/usr/share/wordlists/dirb/common.txt"
            },
            "EXTENSIONS": {
                "value": "php,html,js,txt",
                "required": False,
                "description": "File extensions (comma-separated)",
                "default": "php,html,js,txt"
            },
            "THREADS": {
                "value": "50",
                "required": False,
                "description": "Number of concurrent threads",
                "default": "50"
            },
            "PROXY": {
                "value": None,
                "required": False,
                "description": "Proxy URL (e.g., http://127.0.0.1:8080)",
                "default": None
            },
            "THOROUGH": {
                "value": "true",
                "required": False,
                "description": "Enable thorough mode",
                "default": "true"
            },
            "METHODS": {
                "value": "GET,POST",
                "required": False,
                "description": "HTTP methods (comma-separated)",
                "default": "GET,POST"
            }
        })

    def build_command(self) -> str:
        """
        Build the feroxbuster command.

        Returns:
            Command string to execute
        """
        url = self.get_option("URL")
        wordlist = self.get_option("WORDLIST")
        extensions = self.get_option("EXTENSIONS")
        threads = self.get_option("THREADS")
        proxy = self.get_option("PROXY")
        thorough = self.get_option("THOROUGH")
        methods = self.get_option("METHODS")

        # Base command
        cmd = f"feroxbuster -u '{url}'"

        # Add wordlist
        if wordlist:
            cmd += f" -w '{wordlist}'"

        # Add extensions
        if extensions:
            cmd += f" -x '{extensions}'"

        # Add threads
        if threads:
            cmd += f" -t {threads}"

        # Add methods
        if methods:
            cmd += f" --methods {methods}"

        # Add thorough mode
        if thorough and thorough.lower() == "true":
            cmd += " --thorough"

        # Add proxy
        if proxy:
            cmd += f" --proxy '{proxy}'"

        return cmd

    def parse_output(self, output: str) -> dict:
        """
        Parse feroxbuster output.

        Args:
            output: Command stdout

        Returns:
            Parsed results dictionary
        """
        results = {
            "found_urls": [],
            "status_codes": {},
        }

        # Parse each line
        for line in output.split('\n'):
            # Look for status codes and URLs
            # Feroxbuster output format: STATUS SIZE URL
            if line.strip() and not line.startswith('['):
                parts = line.split()
                if len(parts) >= 3:
                    status = parts[0]
                    url = parts[-1]
                    results["found_urls"].append(url)

                    if status not in results["status_codes"]:
                        results["status_codes"][status] = 0
                    results["status_codes"][status] += 1

        return results
