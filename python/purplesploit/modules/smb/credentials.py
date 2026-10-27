"""Compatibility path for NetExec SMB credential operations."""

from ._compat import LegacySMBView


class SMBCredentialsModule(LegacySMBView):
    operation_subcategory = "credentials"
    legacy_name = "SMB Credential Dumping"
    legacy_description = "SMB credential dumping and extraction"
