"""Compatibility path for NetExec SMB authentication operations."""

from ._compat import LegacySMBView


class SMBAuthenticationModule(LegacySMBView):
    operation_subcategory = "authentication"
    legacy_name = "SMB Authentication"
    legacy_description = "SMB authentication testing with multiple methods"
