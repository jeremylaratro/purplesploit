"""
Nmap UDP Scan Module

UDP port scanning using Nmap.
"""

from purplesploit.modules.recon.nmap import NmapModule


class NmapUdpModule(NmapModule):
    """
    Nmap UDP Scan - UDP port scanning.

    Scans for open UDP ports. UDP scans are slower than TCP scans
    but can discover services not found via TCP scanning.
    """

    @property
    def name(self) -> str:
        return "Nmap UDP Scan"

    @property
    def description(self) -> str:
        return "UDP port scanning using Nmap"

    def _init_options(self):
        """Initialize module-specific options with UDP scan defaults."""
        super()._init_options()

        # Override defaults for UDP scanning
        self.options["SCAN_TYPE"]["value"] = "sU"
        self.options["SCAN_TYPE"]["default"] = "sU"

        # UDP scans are slower, so scan common ports by default
        self.options["TOP_PORTS"]["value"] = "100"
        self.options["TOP_PORTS"]["default"] = "100"
        self.options["PORTS"]["value"] = None
        self.options["PORTS"]["default"] = None

        # Adjust timing for UDP
        self.options["TIMING"]["value"] = "4"
        self.options["MIN_RATE"]["value"] = "1000"
