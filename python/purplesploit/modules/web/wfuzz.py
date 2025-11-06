"""
Wfuzz Module

Web application fuzzer for discovering hidden resources and parameters.
"""

from purplesploit.core.module import ExternalToolModule


class WfuzzModule(ExternalToolModule):
    """
    Wfuzz - Web application fuzzer.

    Fuzzes web applications to discover hidden resources, parameters, and vulnerabilities.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "wfuzz"

    @property
    def name(self) -> str:
        return "Wfuzz"

    @property
    def description(self) -> str:
        return "Web application fuzzer for discovering hidden resources and testing parameters"

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
                "description": "Target URL with FUZZ keyword (e.g., http://target.com/FUZZ)",
                "default": None
            },
            "WORDLIST": {
                "value": "/usr/share/wordlists/dirb/common.txt",
                "required": False,
                "description": "Wordlist path",
                "default": "/usr/share/wordlists/dirb/common.txt"
            },
            "HIDE_CODE": {
                "value": "404",
                "required": False,
                "description": "Hide responses with this status code",
                "default": "404"
            },
            "HIDE_WORDS": {
                "value": None,
                "required": False,
                "description": "Hide responses with this number of words",
                "default": None
            },
            "HIDE_CHARS": {
                "value": None,
                "required": False,
                "description": "Hide responses with this number of chars",
                "default": None
            },
            "THREADS": {
                "value": "50",
                "required": False,
                "description": "Number of concurrent connections",
                "default": "50"
            },
            "METHOD": {
                "value": "GET",
                "required": False,
                "description": "HTTP method (GET, POST, PUT, etc.)",
                "default": "GET"
            },
            "DATA": {
                "value": None,
                "required": False,
                "description": "POST data (use FUZZ for fuzzing)",
                "default": None
            },
            "HEADERS": {
                "value": None,
                "required": False,
                "description": "Additional headers (e.g., 'Header: value')",
                "default": None
            },
            "FOLLOW": {
                "value": "false",
                "required": False,
                "description": "Follow redirects",
                "default": "false"
            }
        })

    def build_command(self) -> str:
        """
        Build the wfuzz command.

        Returns:
            Command string to execute
        """
        url = self.get_option("URL")
        wordlist = self.get_option("WORDLIST")
        hide_code = self.get_option("HIDE_CODE")
        hide_words = self.get_option("HIDE_WORDS")
        hide_chars = self.get_option("HIDE_CHARS")
        threads = self.get_option("THREADS")
        method = self.get_option("METHOD")
        data = self.get_option("DATA")
        headers = self.get_option("HEADERS")
        follow = self.get_option("FOLLOW")

        # Base command
        cmd = f"wfuzz -w '{wordlist}'"

        # Threads
        if threads:
            cmd += f" -t {threads}"

        # Hide responses
        if hide_code:
            cmd += f" --hc {hide_code}"
        if hide_words:
            cmd += f" --hw {hide_words}"
        if hide_chars:
            cmd += f" --hh {hide_chars}"

        # HTTP method
        if method and method.upper() != "GET":
            cmd += f" -X {method.upper()}"

        # POST data
        if data:
            cmd += f" -d '{data}'"

        # Headers
        if headers:
            cmd += f" -H '{headers}'"

        # Follow redirects
        if follow and follow.lower() == "true":
            cmd += " -L"

        # URL (must be last)
        cmd += f" '{url}'"

        return cmd

    def parse_output(self, output: str) -> dict:
        """
        Parse wfuzz output.

        Args:
            output: Command stdout

        Returns:
            Parsed results dictionary
        """
        results = {
            "found_paths": [],
            "status_codes": {},
        }

        # Parse output
        for line in output.split('\n'):
            # Wfuzz output format: ID Response Lines Word Chars Request
            if line.strip() and not line.startswith('=') and not line.startswith('*'):
                parts = line.split()
                if len(parts) >= 4 and parts[1].isdigit():
                    status_code = parts[1]
                    path = parts[-1] if parts else ""

                    results["found_paths"].append({
                        "status": status_code,
                        "path": path,
                        "line": line.strip()
                    })

                    if status_code not in results["status_codes"]:
                        results["status_codes"][status_code] = 0
                    results["status_codes"][status_code] += 1

        return results
