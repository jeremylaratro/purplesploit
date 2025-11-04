"""
Context Display

Manages and displays the current context (workspace, targets, credentials, etc.)
"""

import os
from pathlib import Path
from typing import Optional, Dict, List
from rich.panel import Panel
from rich.table import Table
from rich.console import Group
from rich.text import Text
from .bash_executor import BashExecutor


class Context:
    """Manages the current pentesting context"""

    def __init__(self, bash_executor: BashExecutor):
        """
        Initialize context

        Args:
            bash_executor: BashExecutor instance for calling bash functions
        """
        self.bash_executor = bash_executor
        self.workspace_dir = Path.home() / ".purplesploit" / "workspaces"
        self._current_workspace = None
        self._current_target = None
        self._current_credentials = None
        self._variables = {}

    @property
    def current_workspace(self) -> Optional[str]:
        """Get current workspace name"""
        if self._current_workspace is None:
            # Try to read from framework
            returncode, stdout, _ = self.bash_executor.source_and_call(
                "framework/core/workspace_manager.sh",
                "workspace_current"
            )
            if returncode == 0 and stdout.strip():
                self._current_workspace = stdout.strip()
            else:
                self._current_workspace = "default"
        return self._current_workspace

    @current_workspace.setter
    def current_workspace(self, value: str):
        """Set current workspace"""
        self._current_workspace = value
        # Update in framework
        self.bash_executor.source_and_call(
            "framework/core/workspace_manager.sh",
            "workspace_switch",
            [value]
        )

    @property
    def current_target(self) -> Optional[str]:
        """Get current target"""
        if self._current_target is None:
            # Try to read RHOST variable
            value = self.get_variable("RHOST")
            if value:
                self._current_target = value
        return self._current_target

    @current_target.setter
    def current_target(self, value: str):
        """Set current target"""
        self._current_target = value
        self.set_variable("RHOST", value)

    @property
    def current_credentials(self) -> Optional[Dict[str, str]]:
        """Get current credentials"""
        if self._current_credentials is None:
            username = self.get_variable("USERNAME")
            password = self.get_variable("PASSWORD")
            domain = self.get_variable("DOMAIN")
            hash_value = self.get_variable("HASH")

            if username or password:
                self._current_credentials = {
                    "username": username or "",
                    "password": password or "",
                    "domain": domain or "",
                    "hash": hash_value or ""
                }
        return self._current_credentials

    def set_credentials(self, username: str = "", password: str = "",
                       domain: str = "", hash_value: str = ""):
        """Set current credentials"""
        self._current_credentials = {
            "username": username,
            "password": password,
            "domain": domain,
            "hash": hash_value
        }
        if username:
            self.set_variable("USERNAME", username)
        if password:
            self.set_variable("PASSWORD", password)
        if domain:
            self.set_variable("DOMAIN", domain)
        if hash_value:
            self.set_variable("HASH", hash_value)

    def get_variable(self, var_name: str) -> Optional[str]:
        """Get a variable value from the framework"""
        if var_name in self._variables:
            return self._variables[var_name]

        # Read from framework
        returncode, stdout, _ = self.bash_executor.source_and_call(
            "framework/core/variable_manager.sh",
            "var_get",
            [var_name]
        )
        if returncode == 0 and stdout.strip():
            value = stdout.strip()
            self._variables[var_name] = value
            return value
        return None

    def set_variable(self, var_name: str, value: str):
        """Set a variable value in the framework"""
        self._variables[var_name] = value
        self.bash_executor.source_and_call(
            "framework/core/variable_manager.sh",
            "var_set",
            [var_name, value]
        )

    def get_workspaces(self) -> List[str]:
        """Get list of available workspaces"""
        if not self.workspace_dir.exists():
            return ["default"]

        workspaces = [d.name for d in self.workspace_dir.iterdir() if d.is_dir()]
        if not workspaces:
            return ["default"]
        return sorted(workspaces)

    def get_targets(self) -> List[str]:
        """Get list of targets in current workspace"""
        targets_file = self.workspace_dir / self.current_workspace / "targets" / "hosts.txt"
        if not targets_file.exists():
            return []

        with open(targets_file, "r") as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        return targets

    def add_target(self, target: str):
        """Add a target to the current workspace"""
        self.bash_executor.source_and_call(
            "framework/core/workspace_manager.sh",
            "workspace_add_target",
            [target]
        )

    def render_context_panel(self) -> Panel:
        """Render the context information as a Rich panel"""
        # Create context table
        table = Table.grid(padding=(0, 2))
        table.add_column(style="context_label", justify="right")
        table.add_column(style="context_value")

        # Add rows
        workspace = self.current_workspace or "None"
        target = self.current_target or "Not set"

        creds = self.current_credentials
        if creds and (creds.get("username") or creds.get("hash")):
            if creds.get("hash"):
                cred_str = f"{creds.get('domain', '')}/{creds.get('username', '')} (hash)"
            else:
                cred_str = f"{creds.get('domain', '')}/{creds.get('username', '')}".lstrip("/")
        else:
            cred_str = "Not set"

        table.add_row("Workspace:", f"[workspace]{workspace}[/workspace]")
        table.add_row("Target:", f"[target]{target}[/target]")
        table.add_row("Credentials:", f"[credential]{cred_str}[/credential]")

        return Panel(
            table,
            title="[header] Context [/header]",
            border_style="border",
            padding=(0, 1)
        )

    def render_variables_panel(self) -> Panel:
        """Render common variables as a Rich panel"""
        table = Table.grid(padding=(0, 2))
        table.add_column(style="context_label", justify="right", width=15)
        table.add_column(style="context_value")

        common_vars = ["RHOST", "RPORT", "LHOST", "LPORT", "DOMAIN", "USERNAME"]
        for var in common_vars:
            value = self.get_variable(var)
            if value:
                table.add_row(f"{var}:", value)

        return Panel(
            table,
            title="[header] Variables [/header]",
            border_style="border",
            padding=(0, 1)
        )
