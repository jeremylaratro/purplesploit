"""Legacy SMB module-path views over the canonical NetExec SMB adapter."""

from purplesploit.modules.network.nxc_smb import NXCSMBModule


class LegacySMBView(NXCSMBModule):
    """Expose one legacy operation group without duplicating its implementation."""

    operation_subcategory = ""
    legacy_name = "SMB"
    legacy_description = "SMB operations"

    @property
    def name(self):
        return self.legacy_name

    @property
    def description(self):
        return self.legacy_description

    @property
    def category(self):
        return "smb"

    def get_operations(self):
        return [
            operation
            for operation in super().get_operations()
            if operation.get("subcategory") == self.operation_subcategory
        ]
