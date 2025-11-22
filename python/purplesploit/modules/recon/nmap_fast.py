"""
Nmap Fast Scan Module

Quick network scanning of the most common ports.
"""

from purplesploit.modules.recon.nmap import NmapModule


class NmapFastModule(NmapModule):
    """
    Nmap Fast Scan - Quick scan of most common ports.

    Scans only the top 100 most common ports with optimized
    timing settings for fast results.
    """

    @property
    def name(self) -> str:
        return "Nmap Fast Scan"

    @property
    def description(self) -> str:
        return "Fast scan of top 100 ports with quick version detection (--top-ports 100 -sV)"

    def _init_options(self):
        """Initialize module-specific options with fast scan defaults."""
        super()._init_options()

        # Scan only top 100 ports
        self.options["TOP_PORTS"]["value"] = "100"
        self.options["TOP_PORTS"]["default"] = "100"
        self.options["PORTS"]["value"] = None
        self.options["PORTS"]["default"] = None

        # Use faster timing
        self.options["TIMING"]["value"] = "4"
        self.options["TIMING"]["default"] = "4"

        # Fast rate settings
        self.options["MIN_RATE"]["value"] = "5000"
        self.options["MIN_RATE"]["default"] = "5000"
        self.options["MAX_RTT_TIMEOUT"]["value"] = "2"
        self.options["MAX_RTT_TIMEOUT"]["default"] = "2"
        self.options["MAX_RETRIES"]["value"] = "1"
        self.options["MAX_RETRIES"]["default"] = "1"

        # Quick version detection
        self.options["SCAN_TYPE"]["value"] = "sV"
        self.options["SCAN_TYPE"]["default"] = "sV"
        self.options["VERSION_INTENSITY"]["value"] = "2"
        self.options["VERSION_INTENSITY"]["default"] = "2"
