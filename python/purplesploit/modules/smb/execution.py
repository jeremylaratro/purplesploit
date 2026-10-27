"""Compatibility path for NetExec SMB execution operations."""

from ._compat import LegacySMBView


class SMBExecutionModule(LegacySMBView):
    operation_subcategory = "execution"
    legacy_name = "SMB Command Execution"
    legacy_description = "SMB command and script execution"
