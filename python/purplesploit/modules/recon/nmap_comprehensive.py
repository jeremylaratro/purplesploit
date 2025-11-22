"""
Nmap Comprehensive Scan Module

Thorough scanning of all TCP ports with service and script detection.
"""

from purplesploit.modules.recon.nmap import NmapModule


class NmapComprehensiveModule(NmapModule):
    """
    Nmap Comprehensive Scan - Thorough all-port scanning.

    Scans all 65535 TCP ports with version detection and default scripts.
    This is a thorough but time-consuming scan. Good for finding services
    running on non-standard ports.
    """

    @property
    def name(self) -> str:
        return "Nmap Comprehensive Scan"

    @property
    def description(self) -> str:
        return "Thorough all-port TCP scanning with service detection"

    def _init_options(self):
        """Initialize module-specific options with comprehensive scan defaults."""
        super()._init_options()

        # Scan all ports (this is already the default in updated nmap.py)
        self.options["PORTS"]["value"] = "-"
        self.options["PORTS"]["default"] = "-"

        # Full service and script scanning
        self.options["SCAN_TYPE"]["value"] = "sCV"
        self.options["SCAN_TYPE"]["default"] = "sCV"

        # Maximum version intensity
        self.options["VERSION_INTENSITY"]["value"] = "9"
        self.options["VERSION_INTENSITY"]["default"] = "9"

        # Balanced timing
        self.options["TIMING"]["value"] = "4"
        self.options["TIMING"]["default"] = "4"

        # These match the user's requested defaults
        self.options["MIN_RATE"]["value"] = "3900"
        self.options["MIN_RATE"]["default"] = "3900"
        self.options["MAX_RTT_TIMEOUT"]["value"] = "4.5"
        self.options["MAX_RTT_TIMEOUT"]["default"] = "4.5"
