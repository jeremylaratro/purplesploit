"""Compatibility alias for the canonical Nmap stealth profile."""

from purplesploit.modules.recon.nmap import NmapModule


class NmapStealthModule(NmapModule):
    profile_name = "stealth"

    @property
    def name(self) -> str:
        return "Nmap Stealth Scan"
