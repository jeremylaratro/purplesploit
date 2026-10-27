"""Compatibility path for NetExec SMB enumeration operations."""

from ._compat import LegacySMBView


class SMBEnumerationModule(LegacySMBView):
    operation_subcategory = "enumeration"
    legacy_name = "SMB Enumeration"
    legacy_description = "SMB enumeration and information gathering"
