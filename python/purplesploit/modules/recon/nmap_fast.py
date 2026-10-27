"""Compatibility alias for the canonical Nmap fast profile."""

from purplesploit.modules.recon.nmap import NmapModule


class NmapFastModule(NmapModule):
    profile_name = "fast"

    @property
    def name(self) -> str:
        return "Nmap Fast Scan"
