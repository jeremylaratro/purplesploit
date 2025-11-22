"""
Nmap Stealth Scan Module

Stealthy SYN scanning that avoids completing TCP connections.
"""

from purplesploit.modules.recon.nmap import NmapModule


class NmapStealthModule(NmapModule):
    """
    Nmap Stealth Scan - SYN scan with stealth options.

    Uses SYN scanning (-sS) which doesn't complete TCP connections,
    making it harder to detect. Requires root/sudo privileges.
    """

    @property
    def name(self) -> str:
        return "Nmap Stealth Scan"

    @property
    def description(self) -> str:
        return "Stealthy SYN scanning (requires root)"

    def _init_options(self):
        """Initialize module-specific options with stealth scan defaults."""
        super()._init_options()

        # Use SYN scan (requires root)
        self.options["SCAN_TYPE"]["value"] = "sS"
        self.options["SCAN_TYPE"]["default"] = "sS"

        # Slower, more careful timing
        self.options["TIMING"]["value"] = "2"
        self.options["TIMING"]["default"] = "2"

        # Conservative rate settings
        self.options["MIN_RATE"]["value"] = "100"
        self.options["MIN_RATE"]["default"] = "100"
        self.options["MAX_RTT_TIMEOUT"]["value"] = "10"
        self.options["MAX_RTT_TIMEOUT"]["default"] = "10"

        # Add options for fragment packets and decoy
        self.options["FRAGMENT"] = {
            "value": "false",
            "required": False,
            "description": "Fragment packets (harder to detect)",
            "default": "false"
        }

        self.options["DECOY"] = {
            "value": None,
            "required": False,
            "description": "Use decoy hosts (e.g., RND:10 for 10 random decoys)",
            "default": None
        }

    def build_command(self) -> str:
        """
        Build the nmap command with stealth flags.

        Returns:
            Command string to execute
        """
        cmd = super().build_command()

        # Add fragmentation if enabled
        fragment = self.get_option("FRAGMENT")
        if fragment and fragment.lower() == "true":
            cmd = cmd.replace("nmap ", "nmap -f ")

        # Add decoys if specified
        decoy = self.get_option("DECOY")
        if decoy:
            cmd = cmd.replace("nmap ", f"nmap -D {decoy} ")

        return cmd
