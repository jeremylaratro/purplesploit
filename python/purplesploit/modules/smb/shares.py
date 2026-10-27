"""Compatibility path for NetExec SMB share operations."""

from ._compat import LegacySMBView


class SMBSharesModule(LegacySMBView):
    operation_subcategory = "shares"
    legacy_name = "SMB Shares"
    legacy_description = "SMB share browsing and file operations"

    def run(self):
        """Preserve the legacy default while sharing the canonical handler."""
        return self.op_browse_download()
