"""
NetExec (NXC) LDAP Module

LDAP protocol operations using NetExec.
"""

from purplesploit.core.module import ExternalToolModule
from typing import Dict, Any, List
from purplesploit.modules.network.nxc_common import NXCModuleMixin


class NXCLDAPModule(NXCModuleMixin, ExternalToolModule):
    """
    NetExec LDAP module for LDAP/Active Directory enumeration.

    Supports user/group enumeration, BloodHound collection, LDAP queries,
    and various AD attack techniques.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "nxc"

    @property
    def name(self) -> str:
        return "NetExec LDAP"

    @property
    def description(self) -> str:
        return "LDAP/AD enumeration with 13 operations"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "network"

    def _init_options(self):
        """Initialize module-specific options."""
        super()._init_options()

        self.options.update({
            "RHOST": {
                "value": None,
                "required": True,
                "description": "Target Domain Controller IP",
                "default": None
            },
            "USERNAME": {
                "value": None,
                "required": False,
                "description": "Username for authentication",
                "default": None
            },
            "PASSWORD": {
                "value": None,
                "required": False,
                "description": "Password for authentication",
                "default": None
            },
            "DOMAIN": {
                "value": None,
                "required": False,
                "description": "Domain name",
                "default": "WORKGROUP"
            },
            "HASH": {
                "value": None,
                "required": False,
                "description": "NTLM hash for pass-the-hash",
                "default": None
            },
        })

    def get_operations(self) -> List[Dict[str, Any]]:
        """Get list of LDAP operations."""
        return self._operation_manifest([
            # Enumeration
            {"name": "Enumerate Users", "description": "List domain users", "handler": "op_enum_users"},
            {"name": "Enumerate Groups", "description": "List domain groups", "handler": "op_enum_groups"},
            {"name": "Get User Descriptions", "description": "Extract user description fields", "handler": "op_user_desc"},
            {"name": "Enumerate Computers", "description": "List domain computers", "handler": "op_enum_computers"},
            {"name": "Enumerate Domain Trusts", "description": "List trusted domains", "handler": "op_enum_trusts"},
            {"name": "ADCS Enumeration", "description": "Enumerate Active Directory Certificate Services", "handler": "op_adcs"},
            {"name": "Check LDAP Signing", "description": "Check LDAP signing requirements", "handler": "op_ldap_signing"},
            {"name": "Get All User Attributes", "description": "Dump all LDAP attributes", "handler": "op_all_attributes"},

            # BloodHound Collection
            {"name": "BloodHound - Collect All", "description": "Collect all BloodHound data", "handler": "op_bloodhound_all"},
            {"name": "BloodHound - Sessions", "description": "Collect session data only", "handler": "op_bloodhound_sessions"},
            {"name": "BloodHound - Trusts", "description": "Collect trust relationships", "handler": "op_bloodhound_trusts"},
            {"name": "BloodHound - ACL", "description": "Collect ACL data", "handler": "op_bloodhound_acl"},
            {"name": "BloodHound - Groups", "description": "Collect group memberships", "handler": "op_bloodhound_groups"},
        ], emits={
            "op_enum_users": ["user"], "op_enum_groups": ["group"],
            "op_user_desc": ["user"], "op_enum_computers": ["computer"],
            "op_enum_trusts": ["domain"], "op_adcs": ["resource"],
            "op_ldap_signing": ["policy"], "op_all_attributes": ["user"],
        })

    def _build_auth(self) -> str:
        """Build authentication string for nxc."""
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        hash_val = self.get_option("HASH")

        if not username:
            return ""

        auth = f"-u {self.quote_arg(username)}"

        if hash_val:
            auth += f" -H {self.quote_arg(hash_val)}"
        elif password:
            auth += f" -p {self.quote_arg(password)}"
        else:
            auth += " -p ''"

        return auth

    def _execute_nxc(self, extra_args="") -> Dict[str, Any]:
        """Execute nxc ldap command with extra arguments."""
        return self._run_nxc("ldap", extra_args, timeout=300)

    # ========================================================================
    # Enumeration Operations
    # ========================================================================

    def op_enum_users(self) -> Dict[str, Any]:
        """Enumerate domain users."""
        return self._execute_nxc("--users")

    def op_enum_groups(self) -> Dict[str, Any]:
        """Enumerate domain groups."""
        return self._execute_nxc("--groups")

    def op_user_desc(self) -> Dict[str, Any]:
        """Get user description fields (often contain passwords)."""
        return self._execute_nxc("-M get-desc-users")

    def op_enum_computers(self) -> Dict[str, Any]:
        """Enumerate domain computers."""
        return self._execute_nxc(["--query", "(objectClass=computer)", "sAMAccountName"])

    def op_enum_trusts(self) -> Dict[str, Any]:
        """Enumerate domain trust relationships."""
        return self._execute_nxc(["--query", "(objectClass=trustedDomain)", "trustPartner trustDirection trustAttributes"])

    def op_adcs(self) -> Dict[str, Any]:
        """Enumerate Active Directory Certificate Services."""
        self.log("Enumerating ADCS for potential certificate-based attacks", "info")
        return self._execute_nxc("-M adcs")

    def op_ldap_signing(self) -> Dict[str, Any]:
        """Check LDAP signing requirements."""
        return self._execute_nxc("-M ldap-checker")

    def op_all_attributes(self) -> Dict[str, Any]:
        """Get all LDAP user attributes."""
        return self._execute_nxc("-M user-desc")

    # ========================================================================
    # BloodHound Collection Operations
    # ========================================================================

    def op_bloodhound_all(self) -> Dict[str, Any]:
        """Collect all BloodHound data."""
        self.log("Collecting all BloodHound data...", "info")
        self.log("This may take several minutes on large domains", "warning")
        return self._execute_nxc("-M bloodhound -o COLLECTION=All")

    def op_bloodhound_sessions(self) -> Dict[str, Any]:
        """Collect BloodHound session data."""
        return self._execute_nxc("-M bloodhound -o COLLECTION=Session")

    def op_bloodhound_trusts(self) -> Dict[str, Any]:
        """Collect BloodHound trust data."""
        return self._execute_nxc("-M bloodhound -o COLLECTION=Trusts")

    def op_bloodhound_acl(self) -> Dict[str, Any]:
        """Collect BloodHound ACL data."""
        return self._execute_nxc("-M bloodhound -o COLLECTION=ACL")

    def op_bloodhound_groups(self) -> Dict[str, Any]:
        """Collect BloodHound group membership data."""
        return self._execute_nxc("-M bloodhound -o COLLECTION=Group")

    def run(self) -> Dict[str, Any]:
        """Fallback run method."""
        return self.op_enum_users()
