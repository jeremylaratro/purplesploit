"""
Module Handler

Handles execution of bash module scripts with proper terminal pass-through
"""

import subprocess
import os
from pathlib import Path
from typing import Optional, Dict
from rich.console import Console
from rich.panel import Panel

from .bash_executor import BashExecutor
from .themes import get_console


class ModuleHandler:
    """Execute bash module handlers"""

    def __init__(self, bash_executor: BashExecutor, console: Optional[Console] = None):
        """
        Initialize module handler

        Args:
            bash_executor: BashExecutor instance
            console: Rich console
        """
        self.bash_executor = bash_executor
        self.console = console or get_console()
        self.project_root = bash_executor.project_root

    def execute_module_interactive(self, module_path: str, handler_function: str) -> int:
        """
        Execute a module handler with full terminal interactivity

        Args:
            module_path: Path to module .sh file (relative to project root)
            handler_function: Name of handler function to call

        Returns:
            Return code
        """
        full_path = self.project_root / module_path

        if not full_path.exists():
            self.console.print(f"[danger]Module not found: {module_path}[/danger]")
            return 1

        self.console.print(f"\n[info]Launching {handler_function}...[/info]\n")

        # Create bash command that sources the module and calls handler
        bash_cmd = f"""
cd {self.bash_executor.project_root}
source {full_path}
{handler_function}
"""

        # Execute with full terminal access (not captured)
        env = self.bash_executor.env.copy()
        result = subprocess.run(
            ["bash", "-c", bash_cmd],
            env=env,
            cwd=self.bash_executor.project_root
        )

        return result.returncode

    def run_web_tool(self, tool_name: str) -> int:
        """Execute a web testing tool"""
        module_map = {
            "feroxbuster": ("modules/web/feroxbuster.sh", "handle_feroxbuster"),
            "sqlmap": ("modules/web/sqlmap.sh", "handle_sqlmap"),
            "wfuzz": ("modules/web/wfuzz.sh", "handle_wfuzz"),
            "httpx": ("modules/web/httpx.sh", "handle_httpx"),
        }

        if tool_name not in module_map:
            self.console.print(f"[danger]Unknown tool: {tool_name}[/danger]")
            return 1

        module_path, handler = module_map[tool_name]
        return self.execute_module_interactive(module_path, handler)

    def run_nxc_tool(self, protocol: str) -> int:
        """Execute an NXC tool"""
        module_map = {
            "nxc_smb": ("modules/nxc/smb.sh", "handle_smb"),
            "nxc_ldap": ("modules/nxc/ldap.sh", "handle_ldap"),
            "nxc_winrm": ("modules/nxc/winrm.sh", "handle_winrm"),
            "nxc_mssql": ("modules/nxc/mssql.sh", "handle_mssql"),
            "nxc_rdp": ("modules/nxc/rdp.sh", "handle_rdp"),
            "nxc_ssh": ("modules/nxc/ssh.sh", "handle_ssh"),
            "nxc_scan": ("modules/nxc/scanning.sh", "handle_scanning"),
        }

        if protocol not in module_map:
            self.console.print(f"[danger]Unknown protocol: {protocol}[/danger]")
            return 1

        module_path, handler = module_map[protocol]
        return self.execute_module_interactive(module_path, handler)

    def run_impacket_tool(self, category: str) -> int:
        """Execute an Impacket tool"""
        module_map = {
            "impacket_exec": ("modules/impacket/execution.sh", "handle_execution"),
            "impacket_creds": ("modules/impacket/credentials.sh", "handle_credentials"),
            "impacket_kerberos": ("modules/impacket/kerberos.sh", "handle_kerberos"),
            "impacket_smb": ("modules/impacket/smbclient.sh", "handle_smbclient"),
            "impacket_enum": ("modules/impacket/enumeration.sh", "handle_enumeration"),
            "impacket_services": ("modules/impacket/services.sh", "handle_services"),
            "impacket_registry": ("modules/impacket/registry.sh", "handle_registry"),
        }

        if category not in module_map:
            self.console.print(f"[danger]Unknown category: {category}[/danger]")
            return 1

        module_path, handler = module_map[category]
        return self.execute_module_interactive(module_path, handler)

    def run_ai_automation(self) -> int:
        """Execute AI automation"""
        return self.execute_module_interactive(
            "modules/ai_automation.sh",
            "handle_ai_automation"
        )

    def run_tool_by_category(self, category: str, tool: str) -> int:
        """
        Run a tool by category and tool name

        Args:
            category: Category (web, nxc, impacket, etc.)
            tool: Tool/protocol name

        Returns:
            Return code
        """
        if category == "web":
            return self.run_web_tool(tool)
        elif category == "nxc":
            return self.run_nxc_tool(tool)
        elif category == "impacket":
            return self.run_impacket_tool(tool)
        elif category == "ai":
            return self.run_ai_automation()
        else:
            self.console.print(f"[danger]Unknown category: {category}[/danger]")
            return 1
