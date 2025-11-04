"""
PurpleSploit Rich TUI - Main Application

The main terminal user interface application using Rich library
"""

import sys
import os
from pathlib import Path
from typing import Optional, Dict, List
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.live import Live
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory

from .themes import get_console, BANNER, format_status
from .context import Context
from .bash_executor import BashExecutor
from .service_detector import ServiceDetector
from .menu import Menu, MenuItem, create_category_menu, ToolMenu
from .completer import PurpleSploitCompleter


class PurpleSploitTUI:
    """Main TUI application"""

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

        # Set up prompt session for autocomplete
        history_file = Path.home() / ".purplesploit" / "tui_history"
        history_file.parent.mkdir(parents=True, exist_ok=True)

        self.completer = PurpleSploitCompleter(self.context, self.service_detector)
        self.prompt_session = PromptSession(
            history=FileHistory(str(history_file)),
            auto_suggest=AutoSuggestFromHistory(),
            completer=self.completer,
        )

        # Initialize framework
        self._init_framework()

    def _init_framework(self):
        """Initialize the bash framework"""
        self.console.print("[info]Initializing PurpleSploit framework...[/info]")

        # Source framework and initialize
        returncode, stdout, stderr = self.bash_executor.execute_command(
            "source framework/core/engine.sh && framework_init_silent",
            show_spinner=True
        )

        if returncode != 0:
            self.console.print(f"[danger]Failed to initialize framework: {stderr}[/danger]")
            sys.exit(1)

    def display_banner(self):
        """Display the PurpleSploit banner"""
        self.console.clear()
        self.console.print(BANNER)

    def display_header(self):
        """Display context header"""
        context_panel = self.context.render_context_panel()
        self.console.print(context_panel)
        self.console.print()

    def run_main_menu(self):
        """Run the main menu loop"""
        while True:
            self.display_banner()
            self.display_header()

            # Get detected services for current target
            detected_services = []
            if self.context.current_target:
                detected_services = list(
                    self.service_detector.detect_services(self.context.current_target)
                )

            # Create and display main menu
            menu = create_category_menu(self.console)
            menu.display(detected_services)

            # Get selection
            selected = menu.select("Select category")

            if selected is None:
                break

            # Handle selection
            if selected.title == "Exit":
                break
            elif selected.title == "Settings":
                self.run_settings_menu()
            elif selected.title == "Web Testing":
                self.run_web_menu()
            elif selected.title.startswith("SMB"):
                self.run_smb_menu()
            elif selected.title.startswith("LDAP"):
                self.run_ldap_menu()
            elif selected.title.startswith("WinRM"):
                self.run_winrm_menu()
            elif selected.title.startswith("MSSQL"):
                self.run_mssql_menu()
            elif selected.title.startswith("RDP"):
                self.run_rdp_menu()
            elif selected.title.startswith("SSH"):
                self.run_ssh_menu()
            elif selected.title == "Reconnaissance":
                self.run_recon_menu()
            elif selected.title == "Network Testing - NXC":
                self.run_nxc_menu()
            elif selected.title == "Network Testing - Impacket":
                self.run_impacket_menu()
            elif selected.title == "C2 & Command Control":
                self.run_c2_menu()
            elif selected.title == "AI Automation":
                self.run_ai_menu()

        self.console.print("\n[success]Thank you for using PurpleSploit![/success]\n")

    def run_settings_menu(self):
        """Run settings menu"""
        while True:
            self.display_banner()
            self.display_header()

            menu = Menu(self.console)
            menu.set_title("Settings", "Configure framework settings")

            menu.add_item(MenuItem("Manage Workspaces", "Create, switch, or list workspaces", icon="📁"))
            menu.add_item(MenuItem("Manage Targets", "Add, remove, or list targets", icon="🎯"))
            menu.add_item(MenuItem("Manage Credentials", "Add, remove, or list credentials", icon="🔑"))
            menu.add_item(MenuItem("Set Variables", "Configure framework variables", icon="⚙"))
            menu.add_item(MenuItem("Run Service Scan", "Scan current target for services", icon="🔍"))
            menu.add_item(MenuItem("View Variables", "Show all configured variables", icon="📋"))
            menu.add_separator()
            menu.add_item(MenuItem("Back", "Return to main menu", icon="←"))

            menu.display()
            selected = menu.select("Select setting")

            if selected is None or selected.title == "Back":
                break

            if selected.title == "Manage Workspaces":
                self.manage_workspaces()
            elif selected.title == "Manage Targets":
                self.manage_targets()
            elif selected.title == "Manage Credentials":
                self.manage_credentials()
            elif selected.title == "Set Variables":
                self.set_variables()
            elif selected.title == "Run Service Scan":
                self.run_service_scan()
            elif selected.title == "View Variables":
                self.view_variables()

    def manage_workspaces(self):
        """Manage workspaces"""
        while True:
            self.console.clear()
            self.console.print("\n[header] Workspace Management [/header]\n")

            # Show current workspace
            current = self.context.current_workspace
            self.console.print(f"Current workspace: [workspace]{current}[/workspace]\n")

            # List workspaces
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

            # Options
            choice = self.console.input(
                "[menu_title]Options:[/menu_title] [dim](s)witch, (c)reate, (b)ack[/dim]: "
            )

            if choice.lower() in ['b', 'back', 'q']:
                break
            elif choice.lower() in ['s', 'switch']:
                ws_choice = self.console.input("Enter workspace number or name: ")
                if ws_choice.isdigit():
                    idx = int(ws_choice) - 1
                    if 0 <= idx < len(workspaces):
                        self.context.current_workspace = workspaces[idx]
                        self.console.print(
                            f"[success]Switched to workspace: {workspaces[idx]}[/success]"
                        )
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
                        self.console.print(
                            f"[success]Set current target: {targets[idx]}[/success]"
                        )
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

    def run_web_menu(self):
        """Run web testing menu"""
        self.run_tool_category_menu("Web Testing", "modules/web")

    def run_smb_menu(self):
        """Run SMB operations menu"""
        self.run_tool_category_menu("SMB Operations", "modules/nxc", "smb.sh")

    def run_ldap_menu(self):
        """Run LDAP operations menu"""
        self.run_tool_category_menu("LDAP Operations", "modules/nxc", "ldap.sh")

    def run_winrm_menu(self):
        """Run WinRM operations menu"""
        self.run_tool_category_menu("WinRM Operations", "modules/nxc", "winrm.sh")

    def run_mssql_menu(self):
        """Run MSSQL operations menu"""
        self.run_tool_category_menu("MSSQL Operations", "modules/nxc", "mssql.sh")

    def run_rdp_menu(self):
        """Run RDP operations menu"""
        self.run_tool_category_menu("RDP Operations", "modules/nxc", "rdp.sh")

    def run_ssh_menu(self):
        """Run SSH operations menu"""
        self.run_tool_category_menu("SSH Operations", "modules/nxc", "ssh.sh")

    def run_recon_menu(self):
        """Run reconnaissance menu"""
        self.run_tool_category_menu("Reconnaissance", "modules/recon")

    def run_nxc_menu(self):
        """Run NXC menu"""
        self.run_tool_category_menu("Network Testing - NXC", "modules/nxc")

    def run_impacket_menu(self):
        """Run Impacket menu"""
        self.run_tool_category_menu("Network Testing - Impacket", "modules/impacket")

    def run_c2_menu(self):
        """Run C2 menu"""
        self.run_tool_category_menu("C2 & Command Control", "modules/c2")

    def run_ai_menu(self):
        """Run AI automation"""
        self.console.clear()
        self.console.print("\n[info]Launching AI automation module...[/info]\n")

        returncode, stdout, stderr = self.bash_executor.source_and_call(
            "modules/ai_automation.sh",
            "handle_ai_automation"
        )

        if returncode != 0:
            self.console.print(f"[danger]Error: {stderr}[/danger]")

        self.console.input("\nPress Enter to continue...")

    def run_tool_category_menu(self, category_name: str, module_dir: str, specific_module: Optional[str] = None):
        """
        Run a generic tool category menu

        Args:
            category_name: Display name of the category
            module_dir: Directory containing modules
            specific_module: Specific module file to run
        """
        self.console.clear()
        self.console.print(f"\n[header] {category_name} [/header]\n")
        self.console.print("[info]This feature will list and execute tools from the bash backend.[/info]")
        self.console.print(f"[dim]Module directory: {module_dir}[/dim]\n")

        if specific_module:
            # Run specific module handler
            module_path = f"{module_dir}/{specific_module}"
            self.console.print(f"[info]Executing: {module_path}[/info]\n")

            returncode, stdout, stderr = self.bash_executor.execute_script(
                module_path,
                capture_output=False
            )

            if returncode != 0 and stderr:
                self.console.print(f"[danger]Error: {stderr}[/danger]")
        else:
            # List available tools in directory
            module_path = self.project_root / module_dir
            if module_path.exists():
                tools = [f.stem for f in module_path.glob("*.sh")]
                if tools:
                    self.console.print("Available tools:")
                    for tool in sorted(tools):
                        self.console.print(f"  • {tool}")
                else:
                    self.console.print("[warning]No tools found in this category.[/warning]")

        self.console.input("\n\nPress Enter to continue...")

    def run_interactive_mode(self):
        """Run interactive command-line mode"""
        self.display_banner()
        self.console.print("\n[info]Interactive mode - Type 'help' for commands, 'exit' to quit[/info]\n")

        while True:
            try:
                # Show mini context
                ws = self.context.current_workspace or "none"
                target = self.context.current_target or "none"
                prompt_text = f"[workspace]{ws}[/workspace]@[target]{target}[/target] > "

                # Get input with autocomplete
                user_input = self.prompt_session.prompt(prompt_text, )

                if not user_input.strip():
                    continue

                # Parse command
                parts = user_input.strip().split()
                command = parts[0].lower()

                if command in ['exit', 'quit']:
                    break
                elif command == 'help':
                    self.show_help()
                elif command == 'clear':
                    self.console.clear()
                elif command == 'menu':
                    return  # Return to menu mode
                else:
                    self.console.print(f"[warning]Unknown command: {command}[/warning]")
                    self.console.print("[dim]Type 'help' for available commands[/dim]")

            except KeyboardInterrupt:
                self.console.print("\n[dim]Use 'exit' to quit[/dim]")
                continue
            except EOFError:
                break

    def show_help(self):
        """Show help information"""
        help_text = """
[header] Available Commands [/header]

[menu_title]Workspace Management:[/menu_title]
  workspace list              - List all workspaces
  workspace switch <name>     - Switch to a workspace
  workspace create <name>     - Create a new workspace

[menu_title]Target Management:[/menu_title]
  target list                 - List targets
  target set <ip>             - Set current target
  target add <ip>             - Add target to workspace

[menu_title]Variable Management:[/menu_title]
  set <VAR> <value>           - Set a variable
  get <VAR>                   - Get variable value
  show variables              - Show all variables

[menu_title]Scanning:[/menu_title]
  scan quick                  - Quick nmap scan
  scan full                   - Full nmap scan
  scan vuln                   - Vulnerability scan

[menu_title]Other:[/menu_title]
  menu                        - Return to menu interface
  clear                       - Clear screen
  help                        - Show this help
  exit                        - Exit PurpleSploit
"""
        self.console.print(help_text)

    def run(self, interactive: bool = False):
        """
        Run the TUI application

        Args:
            interactive: Start in interactive CLI mode instead of menu mode
        """
        try:
            if interactive:
                self.run_interactive_mode()
            else:
                self.run_main_menu()
        except KeyboardInterrupt:
            self.console.print("\n\n[warning]Interrupted by user[/warning]")
        except Exception as e:
            self.console.print(f"\n\n[danger]Error: {e}[/danger]")
            raise


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="PurpleSploit Rich TUI")
    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Start in interactive CLI mode"
    )
    parser.add_argument(
        "-r", "--root",
        type=Path,
        help="Project root directory"
    )

    args = parser.parse_args()

    tui = PurpleSploitTUI(project_root=args.root)
    tui.run(interactive=args.interactive)


if __name__ == "__main__":
    main()
