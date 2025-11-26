"""
NetExec (NXC) MSSQL Module

MSSQL protocol operations using NetExec.
"""

from purplesploit.core.module import ExternalToolModule
from typing import Dict, Any, List


class NXCMSSQLModule(ExternalToolModule):
    """NetExec MSSQL module for SQL Server operations."""

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "nxc"

    @property
    def name(self) -> str:
        return "NetExec MSSQL"

    @property
    def description(self) -> str:
        return "MSSQL operations with 7 commands"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "network"

    def _init_options(self):
        super()._init_options()
        self.options.update({
            "RHOST": {"value": None, "required": True, "description": "Target SQL server IP", "default": None},
            "USERNAME": {"value": None, "required": False, "description": "SQL username", "default": None},
            "PASSWORD": {"value": None, "required": False, "description": "SQL password", "default": None},
            "DOMAIN": {"value": None, "required": False, "description": "Domain", "default": None},
            "HASH": {"value": None, "required": False, "description": "NTLM hash", "default": None},
            "AUTH_TYPE": {"value": "domain", "required": False, "description": "Authentication type: domain, local, kerberos, windows", "default": "domain"},
        })

    def get_operations(self) -> List[Dict[str, Any]]:
        return [
            {"name": "Test Authentication", "description": "Test MSSQL authentication", "handler": "op_test_auth"},
            {"name": "Get Version", "description": "Get SQL Server version", "handler": "op_version"},
            {"name": "List Databases", "description": "List all databases", "handler": "op_list_dbs"},
            {"name": "List Tables", "description": "List tables in database", "handler": "op_list_tables"},
            {"name": "Check Privileges", "description": "Check user privileges", "handler": "op_privs"},
            {"name": "Execute Command (xp_cmdshell)", "description": "Execute OS command via xp_cmdshell", "handler": "op_exec_cmd"},
            {"name": "Enable xp_cmdshell", "description": "Enable xp_cmdshell", "handler": "op_enable_xpcmdshell"},
        ]

    def _build_auth(self) -> str:
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        hash_val = self.get_option("HASH")
        if not username:
            return ""
        auth = f"-u '{username}'"
        if hash_val:
            auth += f" -H '{hash_val}'"
        elif password:
            auth += f" -p '{password}'"
        else:
            auth += " -p ''"
        return auth

    def _execute_nxc(self, extra_args: str = "") -> Dict[str, Any]:
        rhost = self.get_option("RHOST")
        auth_type = self.get_option("AUTH_TYPE") or "domain"
        auth = self._build_auth()

        cmd = f"nxc mssql {rhost} {auth}"

        # Add authentication type flags
        if auth_type == "local":
            cmd += " --local-auth"
        elif auth_type == "kerberos":
            cmd += " --kerberos"
        elif auth_type == "windows":
            cmd += " --windows-auth"

        if extra_args:
            cmd += f" {extra_args}"
        return self.execute_command(cmd, timeout=180)

    def op_test_auth(self) -> Dict[str, Any]:
        return self._execute_nxc()

    def op_version(self) -> Dict[str, Any]:
        return self._execute_nxc("-q 'SELECT @@version'")

    def op_list_dbs(self) -> Dict[str, Any]:
        return self._execute_nxc("-q 'SELECT name FROM sys.databases'")

    def op_list_tables(self) -> Dict[str, Any]:
        db = input("Database name: ")
        return self._execute_nxc(f"-q 'SELECT * FROM {db}.INFORMATION_SCHEMA.TABLES'")

    def op_privs(self) -> Dict[str, Any]:
        return self._execute_nxc("-M mssql_priv")

    def op_exec_cmd(self) -> Dict[str, Any]:
        cmd = input("Command: ")
        return self._execute_nxc(f"-x '{cmd}'")

    def op_enable_xpcmdshell(self) -> Dict[str, Any]:
        query = "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
        return self._execute_nxc(f'-q "{query}"')

    def run(self) -> Dict[str, Any]:
        return self.op_test_auth()
