"""
Nmap Aggressive Scan Module

Comprehensive aggressive scanning with OS detection and script scanning.
"""

from purplesploit.modules.recon.nmap import NmapModule


class NmapAggressiveModule(NmapModule):
    """
    Nmap Aggressive Scan - Comprehensive scanning with all features.

    Enables OS detection, version detection, script scanning, and traceroute.
    Equivalent to using the -A flag. Slower but very thorough.
    """

    @property
    def name(self) -> str:
        return "Nmap Aggressive Scan"

    @property
    def description(self) -> str:
        return "Comprehensive aggressive scanning (-A equivalent)"

    def _init_options(self):
        """Initialize module-specific options with aggressive scan defaults."""
        super()._init_options()

        # Enable script and version scanning
        self.options["SCAN_TYPE"]["value"] = "sCV"
        self.options["SCAN_TYPE"]["default"] = "sCV"

        # Enable OS detection
        self.options["OS_DETECTION"]["value"] = "true"
        self.options["OS_DETECTION"]["default"] = "true"

        # Maximum version intensity
        self.options["VERSION_INTENSITY"]["value"] = "9"
        self.options["VERSION_INTENSITY"]["default"] = "9"

        # Aggressive timing
        self.options["TIMING"]["value"] = "4"
        self.options["TIMING"]["default"] = "4"

        # Add traceroute option
        self.options["TRACEROUTE"] = {
            "value": "true",
            "required": False,
            "description": "Trace hop path to each host",
            "default": "true"
        }

    def build_command(self) -> str:
        """
        Build the nmap command with aggressive flags.

        Returns:
            Command string to execute
        """
        cmd = super().build_command()

        # Add traceroute if enabled
        traceroute = self.get_option("TRACEROUTE")
        if traceroute and traceroute.lower() == "true":
            cmd = cmd.replace("nmap ", "nmap --traceroute ")

        return cmd
