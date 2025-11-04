"""
PurpleSploit Rich TUI - Interactive Application

Main application with mouse and keyboard interactive menus
"""

import sys
import os
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .themes import get_console, BANNER
from .context import Context
from .bash_executor import BashExecutor
from .service_detector import ServiceDetector
from .interactive_menu import (
    create_main_menu,
    create_web_menu,
    create_nxc_menu,
    create_impacket_menu,
    create_settings_menu
)
from .module_handler import ModuleHandler


class PurpleSploitInteractiveTUI:
    """Main interactive TUI application"""

    def __init__(self, project_root: Optional[Path] = None):
        """
        Initialize the PurpleSploit TUI

        Args:
            project_root: Path to project root (auto-detected if None)
        """
        # Find project root
        if project_root is None:
            current = Path(__file__).resolve()
            while current.parent != current:
                if (current / "purplesploit-tui.sh").exists():
                    project_root = current
                    break
                current = current.parent
            else:
                project_root = Path.cwd()

        self.project_root = Path(project_root)
        self.console = get_console()

        # Initialize components
        self.bash_executor = BashExecutor(self.project_root)
        self.context = Context(self.bash_executor)
        self.service_detector = ServiceDetector(self.bash_executor)
        self.module_handler = ModuleHandler(self.bash_executor, self.console)

        # Initialize framework
        self._init_framework()

    def _init_framework(self):
        """Initialize the bash framework"""
        framework_engine = self.project_root / "framework" / "core" / "engine.sh"

        if not framework_engine.exists():
            self.console.print("[warning]Framework not found - running in lite mode[/warning]")
            return

        self.console.print("[info]Initializing PurpleSploit framework...[/info]")

        returncode, stdout, stderr = self.bash_executor.execute_command(
            "source framework/core/engine.sh && framework_init_silent 2>/dev/null || true",
            show_spinner=True
        )

        if returncode != 0:
            self.console.print(f"[warning]Framework initialization had issues (continuing anyway)[/warning]")

    def display_banner(self):
        """Display the PurpleSploit banner"""
        self.console.clear()
        self.console.print(BANNER)

    def display_header(self):
        """Display context header"""
        context_panel = self.context.render_context_panel()
        self.console.print(context_panel)
        self.console.print()

    def run_main_loop(self):
        """Main application loop"""
        while True:
            self.display_banner()
            self.display_header()

            # Show main menu
            menu = create_main_menu()
            choice = menu.show()

            if choice is None or choice == "exit":
                break

            # Handle selection
            if choice == "web":
                self.handle_web_menu()
            elif choice == "nxc":
                self.handle_nxc_menu()
            elif choice == "impacket":
                self.handle_impacket_menu()
            elif choice == "smb":
                self.handle_smb_direct()
            elif choice == "ldap":
                self.handle_ldap_direct()
            elif choice == "winrm":
                self.handle_winrm_direct()
            elif choice == "mssql":
                self.handle_mssql_direct()
            elif choice == "rdp":
                self.handle_rdp_direct()
            elif choice == "ssh":
                self.handle_ssh_direct()
            elif choice == "ai":
                self.handle_ai()
            elif choice == "settings":
                self.handle_settings()

        self.console.print("\n[success]Thank you for using PurpleSploit![/success]\n")

    def handle_web_menu(self):
        """Handle web testing menu"""
        while True:
            self.display_banner()
            self.display_header()

            menu = create_web_menu()
            choice = menu.show()

            if choice is None or choice == "back":
                break

            # Execute the tool
            self.module_handler.run_web_tool(choice)
            self.console.input("\n[dim]Press Enter to continue...[/dim]")

    def handle_nxc_menu(self):
        """Handle NXC menu"""
        while True:
            self.display_banner()
            self.display_header()

            menu = create_nxc_menu()
            choice = menu.show()

            if choice is None or choice == "back":
                break

            # Execute the tool
            self.module_handler.run_nxc_tool(choice)
            self.console.input("\n[dim]Press Enter to continue...[/dim]")

    def handle_impacket_menu(self):
        """Handle Impacket menu"""
        while True:
            self.display_banner()
            self.display_header()

            menu = create_impacket_menu()
            choice = menu.show()

            if choice is None or choice == "back":
                break

            # Execute the tool
            self.module_handler.run_impacket_tool(choice)
            self.console.input("\n[dim]Press Enter to continue...[/dim]")

    def handle_smb_direct(self):
        """Handle SMB operations directly"""
        self.module_handler.run_nxc_tool("nxc_smb")
        self.console.input("\n[dim]Press Enter to continue...[/dim]")

    def handle_ldap_direct(self):
        """Handle LDAP operations directly"""
        self.module_handler.run_nxc_tool("nxc_ldap")
        self.console.input("\n[dim]Press Enter to continue...[/dim]")

    def handle_winrm_direct(self):
        """Handle WinRM operations directly"""
        self.module_handler.run_nxc_tool("nxc_winrm")
        self.console.input("\n[dim]Press Enter to continue...[/dim]")

    def handle_mssql_direct(self):
        """Handle MSSQL operations directly"""
        self.module_handler.run_nxc_tool("nxc_mssql")
        self.console.input("\n[dim]Press Enter to continue...[/dim]")

    def handle_rdp_direct(self):
        """Handle RDP operations directly"""
        self.module_handler.run_nxc_tool("nxc_rdp")
        self.console.input("\n[dim]Press Enter to continue...[/dim]")

    def handle_ssh_direct(self):
        """Handle SSH operations directly"""
        self.module_handler.run_nxc_tool("nxc_ssh")
        self.console.input("\n[dim]Press Enter to continue...[/dim]")

    def handle_ai(self):
        """Handle AI automation"""
        self.module_handler.run_ai_automation()
        self.console.input("\n[dim]Press Enter to continue...[/dim]")

    def handle_settings(self):
        """Handle settings menu"""
        while True:
            self.display_banner()
            self.display_header()

            menu = create_settings_menu()
            choice = menu.show()

            if choice is None or choice == "back":
                break

            if choice == "workspaces":
                self.manage_workspaces()
            elif choice == "targets":
                self.manage_targets()
            elif choice == "credentials":
                self.manage_credentials()
            elif choice == "variables":
                self.set_variables()
            elif choice == "scan":
                self.run_service_scan()
            elif choice == "show_vars":
                self.view_variables()

    def manage_workspaces(self):
        """Manage workspaces"""
        self.console.clear()
        self.console.print("\n[header] Workspace Management [/header]\n")

        current = self.context.current_workspace
        self.console.print(f"Current workspace: [workspace]{current}[/workspace]\n")

        workspaces = self.context.get_workspaces()
        table = Table(title="Available Workspaces", border_style="border")
        table.add_column("#", style="dim", width=4)
        table.add_column("Name", style="workspace")
        table.add_column("Current", style="success")

        for idx, ws in enumerate(workspaces, 1):
            is_current = "✓" if ws == current else ""
            table.add_row(str(idx), ws, is_current)

        self.console.print(table)
        self.console.print()

        choice = self.console.input(
            "[menu_title]Options:[/menu_title] [dim](s)witch, (c)reate, (b)ack[/dim]: "
        )

        if choice.lower() in ['s', 'switch']:
            ws_choice = self.console.input("Enter workspace number or name: ")
            if ws_choice.isdigit():
                idx = int(ws_choice) - 1
                if 0 <= idx < len(workspaces):
                    self.context.current_workspace = workspaces[idx]
                    self.console.print(f"[success]Switched to workspace: {workspaces[idx]}[/success]")
            else:
                if ws_choice in workspaces:
                    self.context.current_workspace = ws_choice
                    self.console.print(f"[success]Switched to workspace: {ws_choice}[/success]")
            self.console.input("\nPress Enter to continue...")
        elif choice.lower() in ['c', 'create']:
            ws_name = self.console.input("Enter new workspace name: ")
            if ws_name:
                self.bash_executor.source_and_call(
                    "framework/core/workspace_manager.sh",
                    "workspace_create",
                    [ws_name]
                )
                self.console.print(f"[success]Created workspace: {ws_name}[/success]")
                self.console.input("\nPress Enter to continue...")

    def manage_targets(self):
        """Manage targets"""
        self.console.clear()
        self.console.print("\n[header] Target Management [/header]\n")

        targets = self.context.get_targets()

        if targets:
            table = Table(title="Targets in Current Workspace", border_style="border")
            table.add_column("#", style="dim", width=4)
            table.add_column("Target", style="target")

            for idx, target in enumerate(targets, 1):
                table.add_row(str(idx), target)

            self.console.print(table)
            self.console.print()

        choice = self.console.input(
            "[menu_title]Options:[/menu_title] [dim](a)dd, (s)et current, (b)ack[/dim]: "
        )

        if choice.lower() in ['a', 'add']:
            target = self.console.input("Enter target IP or hostname: ")
            if target:
                self.context.add_target(target)
                self.console.print(f"[success]Added target: {target}[/success]")
                self.console.input("\nPress Enter to continue...")
        elif choice.lower() in ['s', 'set']:
            if targets:
                target_choice = self.console.input("Enter target number or IP: ")
                if target_choice.isdigit():
                    idx = int(target_choice) - 1
                    if 0 <= idx < len(targets):
                        self.context.current_target = targets[idx]
                        self.console.print(f"[success]Set current target: {targets[idx]}[/success]")
                else:
                    self.context.current_target = target_choice
                    self.console.print(f"[success]Set current target: {target_choice}[/success]")
                self.console.input("\nPress Enter to continue...")

    def manage_credentials(self):
        """Manage credentials"""
        self.console.clear()
        self.console.print("\n[header] Credential Management [/header]\n")

        current_creds = self.context.current_credentials
        if current_creds and (current_creds.get("username") or current_creds.get("hash")):
            self.console.print("Current credentials:")
            self.console.print(f"  Username: [credential]{current_creds.get('username', 'N/A')}[/credential]")
            self.console.print(f"  Domain: [credential]{current_creds.get('domain', 'N/A')}[/credential]")
            if current_creds.get('hash'):
                self.console.print(f"  Hash: [credential]{current_creds.get('hash', 'N/A')}[/credential]")
            else:
                self.console.print(f"  Password: [credential]{'*' * len(current_creds.get('password', ''))}[/credential]")
            self.console.print()

        choice = self.console.input(
            "[menu_title]Set credentials:[/menu_title] [dim](u)sername/password, (h)ash, (c)lear, (b)ack[/dim]: "
        )

        if choice.lower() in ['u', 'username']:
            username = self.console.input("Username: ")
            password = self.console.input("Password: ")
            domain = self.console.input("Domain (optional): ")
            self.context.set_credentials(username=username, password=password, domain=domain)
            self.console.print("[success]Credentials set![/success]")
            self.console.input("\nPress Enter to continue...")
        elif choice.lower() in ['h', 'hash']:
            username = self.console.input("Username: ")
            hash_value = self.console.input("NTLM Hash: ")
            domain = self.console.input("Domain (optional): ")
            self.context.set_credentials(username=username, hash_value=hash_value, domain=domain)
            self.console.print("[success]Credentials set![/success]")
            self.console.input("\nPress Enter to continue...")
        elif choice.lower() in ['c', 'clear']:
            self.context.set_credentials()
            self.console.print("[success]Credentials cleared![/success]")
            self.console.input("\nPress Enter to continue...")

    def set_variables(self):
        """Set framework variables"""
        self.console.clear()
        self.console.print("\n[header] Set Variables [/header]\n")

        var_name = self.console.input("Variable name (e.g., LHOST, THREADS): ").upper()
        if var_name:
            var_value = self.console.input(f"Value for {var_name}: ")
            self.context.set_variable(var_name, var_value)
            self.console.print(f"[success]Set {var_name} = {var_value}[/success]")
        self.console.input("\nPress Enter to continue...")

    def view_variables(self):
        """View all variables"""
        self.console.clear()
        vars_panel = self.context.render_variables_panel()
        self.console.print(vars_panel)
        self.console.input("\nPress Enter to continue...")

    def run_service_scan(self):
        """Run nmap service scan"""
        target = self.context.current_target
        if not target:
            self.console.print("[warning]No target set! Set a target first.[/warning]")
            self.console.input("\nPress Enter to continue...")
            return

        self.console.clear()
        self.console.print(f"\n[info]Scanning target: {target}[/info]\n")

        scan_type = self.console.input("Scan type [dim](quick, full, vuln)[/dim] [quick]: ").strip() or "quick"

        self.console.print(f"\n[info]Running {scan_type} scan...[/info]")
        success = self.service_detector.run_nmap_scan(target, scan_type)

        if success:
            services = self.service_detector.detect_services(target, force_rescan=True)
            self.console.print(f"\n[success]Scan complete! Detected services:[/success]")
            for service in sorted(services):
                icon = self.service_detector.get_service_icon(service, target)
                self.console.print(f"  {icon} {service}")
        else:
            self.console.print("\n[danger]Scan failed![/danger]")

        self.console.input("\nPress Enter to continue...")

    def run(self):
        """Run the TUI application"""
        try:
            self.run_main_loop()
        except KeyboardInterrupt:
            self.console.print("\n\n[warning]Interrupted by user[/warning]")
        except Exception as e:
            self.console.print(f"\n\n[danger]Error: {e}[/danger]")
            raise


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="PurpleSploit Rich TUI (Interactive)")
    parser.add_argument(
        "-r", "--root",
        type=Path,
        help="Project root directory"
    )

    args = parser.parse_args()

    tui = PurpleSploitInteractiveTUI(project_root=args.root)
    tui.run()


if __name__ == "__main__":
    main()
