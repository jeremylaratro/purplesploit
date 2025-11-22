"""
Nmap No Ping Scan Module

Network scanning with host discovery disabled (-Pn).
"""

from purplesploit.modules.recon.nmap import NmapModule


class NmapNoPingModule(NmapModule):
    """
    Nmap No Ping Scan - Scan without host discovery.

    Skips host discovery phase and treats all targets as online.
    Useful when targets block ping probes or when scanning through
    firewalls that filter ICMP.
    """

    @property
    def name(self) -> str:
        return "Nmap No Ping Scan"

    @property
    def description(self) -> str:
        return "No ping/discovery + all ports (-Pn -p- -sCV)"

    def _init_options(self):
        """Initialize module-specific options with no-ping defaults."""
        super()._init_options()

        # Add NO_PING option
        self.options["NO_PING"] = {
            "value": "true",
            "required": False,
            "description": "Skip host discovery (treat all hosts as online)",
            "default": "true"
        }

    def build_command(self) -> str:
        """
        Build the nmap command with -Pn flag.

        Returns:
            Command string to execute
        """
        cmd = super().build_command()

        # Insert -Pn flag after 'nmap'
        no_ping = self.get_option("NO_PING")
        if no_ping and no_ping.lower() == "true":
            cmd = cmd.replace("nmap ", "nmap -Pn ")

        return cmd
