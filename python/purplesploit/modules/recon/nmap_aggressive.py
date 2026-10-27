"""Compatibility alias for the canonical Nmap aggressive profile."""

from purplesploit.modules.recon.nmap import NmapModule


class NmapAggressiveModule(NmapModule):
    profile_name = "aggressive"

    @property
    def name(self) -> str:
        return "Nmap Aggressive Scan"
