"""
Display Module for PurpleSploit

Handles all output formatting using Rich library for beautiful CLI display.
"""

from rich.console import Console as RichConsole
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.syntax import Syntax
from rich import box
from typing import Dict, List, Any, Optional
import pandas as pd


class Display:
    """
    Display manager for PurpleSploit output.

    Uses Rich library for formatted, colored output with tables, panels, and more.
    """

    def __init__(self):
        """Initialize display with Rich console."""
        # Set width to ensure banner doesn't wrap
        self.console = RichConsole(width=120, no_color=False)

    def print_banner(self):
        """Print the PurpleSploit banner."""
        banner = """[bold magenta]
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║  ██████╗ ██╗   ██╗██████╗ ██████╗ ██╗     ███████╗███████╗██████╗ ██╗       ║
║  ██╔══██╗██║   ██║██╔══██╗██╔══██╗██║     ██╔════╝██╔════╝██╔══██╗██║       ║
║  ██████╔╝██║   ██║██████╔╝██████╔╝██║     █████╗  ███████╗██████╔╝██║       ║
║  ██╔═══╝ ██║   ██║██╔══██╗██╔═══╝ ██║     ██╔══╝  ╚════██║██╔═══╝ ██║       ║
║  ██║     ╚██████╔╝██║  ██║██║     ███████╗███████╗███████║██║     ███████╗  ║
║  ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚══════╝╚═╝     ╚══════╝  ║
║                                                                               ║
║                   ██████╗ ██╗      ██████╗ ██╗████████╗                      ║
║                   ██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝                      ║
║                   ██████╔╝██║     ██║   ██║██║   ██║                         ║
║                   ██╔═══╝ ██║     ██║   ██║██║   ██║                         ║
║                   ██║     ███████╗╚██████╔╝██║   ██║                         ║
║                   ╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝                         ║
║                                                                               ║
║                  [bold cyan]Command Workflow Automation Framework[/bold cyan]                        ║
║                              [dim cyan]by d0sf3t[/dim cyan]                                        ║
║                           [dim]Version 3.3 - Console Mode[/dim]                         ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝[/bold magenta]
"""
        # Print banner without wrapping to prevent cut-off
        self.console.print(banner, overflow="ignore", no_wrap=True)
        self.console.print()

    def print_success(self, message: str):
        """Print a success message."""
        self.console.print(f"[bold green][+][/bold green] {message}")

    def print_error(self, message: str):
        """Print an error message."""
        self.console.print(f"[bold red][-][/bold red] {message}")

    def print_warning(self, message: str):
        """Print a warning message."""
        self.console.print(f"[bold yellow][!][/bold yellow] {message}")

    def print_info(self, message: str):
        """Print an info message."""
        self.console.print(f"[bold blue][*][/bold blue] {message}")

    def print_modules_table(self, modules: List, show_category: bool = True):
        """
        Print a table of modules.

        Args:
            modules: List of ModuleMetadata objects
            show_category: Whether to show category column
        """
        if not modules:
            self.print_warning("No modules found")
            return

        table = Table(
            title="Available Modules",
            box=box.ROUNDED,
            header_style="bold cyan",
            border_style="bright_black"
        )

        table.add_column("#", style="dim", width=4, justify="right")
        if show_category:
            table.add_column("Category", style="magenta")
        table.add_column("Module Path", style="cyan")
        table.add_column("Name", style="bright_cyan")
        table.add_column("Description", style="white")

        for idx, module in enumerate(modules, 1):
            row = [str(idx)]
            if show_category:
                row.append(module.category)
            row.extend([
                module.path,
                module.name,
                module.description[:60] + "..." if len(module.description) > 60 else module.description
            ])
            table.add_row(*row)

        self.console.print(table)
        self.console.print(f"\n[dim]Total: {len(modules)} modules[/dim]\n")

    def print_options_table(self, options: Dict[str, Dict]):
        """
        Print a table of module options.

        Args:
            options: Dictionary of options
        """
        table = Table(
            title="Module Options",
            box=box.ROUNDED,
            header_style="bold cyan",
            border_style="bright_black"
        )

        table.add_column("Option", style="cyan", width=20)
        table.add_column("Current Value", style="green", width=30)
        table.add_column("Required", style="yellow", width=10)
        table.add_column("Description", style="white")

        for name, option in options.items():
            value = option.get('value')
            required = "yes" if option.get('required', False) else "no"
            description = option.get('description', '')

            # Format value display
            if value is None:
                value_display = "[dim]<not set>[/dim]"
            elif len(str(value)) > 30:
                value_display = str(value)[:27] + "..."
            else:
                value_display = str(value)

            table.add_row(name, value_display, required, description)

        self.console.print(table)
        self.console.print()

    def print_targets_table(self, targets: List[Dict]):
        """
        Print a table of targets.

        Args:
            targets: List of target dictionaries
        """
        if not targets:
            self.print_warning("No targets configured")
            return

        table = Table(
            title="Targets",
            box=box.ROUNDED,
            header_style="bold cyan",
            border_style="bright_black"
        )

        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("Type", style="magenta", width=10)
        table.add_column("Target", style="cyan", width=40)
        table.add_column("Name", style="white", width=20)
        table.add_column("Added", style="dim", width=20)

        for idx, target in enumerate(targets):
            target_display = target.get('ip') or target.get('url', '<unknown>')
            name = target.get('name', '')
            added = target.get('added_at', '')
            if added and len(added) > 19:
                added = added[:19]  # Trim timestamp

            table.add_row(
                str(idx),
                target.get('type', 'unknown'),
                target_display,
                name,
                added
            )

        self.console.print(table)
        self.console.print(f"\n[dim]Total: {len(targets)} targets[/dim]\n")

    def print_credentials_table(self, credentials: List[Dict]):
        """
        Print a table of credentials.

        Args:
            credentials: List of credential dictionaries
        """
        if not credentials:
            self.print_warning("No credentials configured")
            return

        table = Table(
            title="Credentials",
            box=box.ROUNDED,
            header_style="bold cyan",
            border_style="bright_black"
        )

        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("Name", style="cyan", width=15)
        table.add_column("Username", style="green", width=20)
        table.add_column("Password", style="yellow", width=20)
        table.add_column("Domain", style="magenta", width=15)
        table.add_column("Hash", style="red", width=15)

        for idx, cred in enumerate(credentials):
            username = cred.get('username', '')
            password = cred.get('password', '')
            domain = cred.get('domain', '')
            hash_val = cred.get('hash', '')
            name = cred.get('name', '')

            # Mask sensitive data
            if password:
                password = "*" * min(len(password), 10)
            if hash_val:
                hash_val = hash_val[:12] + "..." if len(hash_val) > 12 else hash_val

            table.add_row(
                str(idx),
                name,
                username,
                password,
                domain,
                hash_val
            )

        self.console.print(table)
        self.console.print(f"\n[dim]Total: {len(credentials)} credentials[/dim]\n")

    def print_services_table(self, services: Dict[str, Dict[str, List[int]]]):
        """
        Print a table of detected services.

        Args:
            services: Dictionary of {target: {service: [ports]}}
        """
        if not services:
            self.print_warning("No services detected")
            return

        table = Table(
            title="Detected Services",
            box=box.ROUNDED,
            header_style="bold cyan",
            border_style="bright_black"
        )

        table.add_column("Target", style="cyan", width=30)
        table.add_column("Service", style="green", width=15)
        table.add_column("Ports", style="yellow", width=40)

        for target, target_services in services.items():
            for service, ports in target_services.items():
                ports_str = ", ".join(map(str, ports))
                table.add_row(target, service, ports_str)

        self.console.print(table)
        self.console.print()

    def print_results(self, results: Dict[str, Any]):
        """
        Print module execution results.

        Args:
            results: Results dictionary
        """
        if not results.get('success', False):
            self.print_error(f"Module failed: {results.get('error', 'Unknown error')}")
            return

        self.print_success("Module executed successfully")

        # Display stdout if present
        if 'stdout' in results and results['stdout']:
            self.console.print("\n[bold]Output:[/bold]")
            self.console.print(Panel(results['stdout'], border_style="green"))

        # Display stderr if present
        if 'stderr' in results and results['stderr']:
            self.console.print("\n[bold yellow]Errors/Warnings:[/bold yellow]")
            self.console.print(Panel(results['stderr'], border_style="yellow"))

        # Display parsed results if present
        if 'parsed' in results:
            self.console.print("\n[bold]Parsed Results:[/bold]")
            self._print_generic(results['parsed'])

        # Display any other data
        for key, value in results.items():
            if key not in ['success', 'stdout', 'stderr', 'parsed', 'command', 'returncode']:
                self.console.print(f"\n[bold]{key.replace('_', ' ').title()}:[/bold]")
                self._print_generic(value)

    def _print_generic(self, data: Any):
        """
        Print data in an appropriate format based on type.

        Args:
            data: Data to print
        """
        if isinstance(data, dict):
            self._print_dict(data)
        elif isinstance(data, list):
            self._print_list(data)
        elif isinstance(data, pd.DataFrame):
            self._print_dataframe(data)
        else:
            self.console.print(str(data))

    def _print_dict(self, data: Dict):
        """Print a dictionary."""
        table = Table(box=box.SIMPLE, show_header=False)
        table.add_column("Key", style="cyan")
        table.add_column("Value", style="white")

        for key, value in data.items():
            if isinstance(value, (dict, list)):
                value_str = str(value)[:100] + "..." if len(str(value)) > 100 else str(value)
            else:
                value_str = str(value)
            table.add_row(str(key), value_str)

        self.console.print(table)

    def _print_list(self, data: List):
        """Print a list."""
        for i, item in enumerate(data, 1):
            if isinstance(item, dict):
                self.console.print(f"\n[bold cyan]Item {i}:[/bold cyan]")
                self._print_dict(item)
            else:
                self.console.print(f"{i}. {item}")

    def _print_dataframe(self, df: pd.DataFrame):
        """Print a pandas DataFrame."""
        table = Table(box=box.ROUNDED, header_style="bold cyan")

        # Add columns
        for col in df.columns:
            table.add_column(str(col))

        # Add rows
        for _, row in df.iterrows():
            table.add_row(*[str(val) for val in row])

        self.console.print(table)

    def print_module_info(self, module):
        """
        Print detailed module information.

        Args:
            module: Module instance
        """
        info_text = f"""
[bold cyan]Name:[/bold cyan] {module.name}
[bold cyan]Description:[/bold cyan] {module.description}
[bold cyan]Author:[/bold cyan] {module.author}
[bold cyan]Category:[/bold cyan] {module.category}
"""
        panel = Panel(
            info_text,
            title="Module Information",
            border_style="cyan"
        )
        self.console.print(panel)
        self.console.print()

    def print_help(self, commands: Dict[str, str]):
        """
        Print help information.

        Args:
            commands: Dictionary of {command: description}
        """
        table = Table(
            title="Available Commands",
            box=box.ROUNDED,
            header_style="bold cyan",
            border_style="bright_black"
        )

        table.add_column("Command", style="cyan", width=20)
        table.add_column("Description", style="white")

        for cmd, desc in sorted(commands.items()):
            table.add_row(cmd, desc)

        self.console.print(table)
        self.console.print()

    def clear(self):
        """Clear the screen."""
        self.console.clear()

    def print_status_bar(self, stats: Dict):
        """
        Print a status bar with current context.

        Args:
            stats: Statistics dictionary
        """
        current_module = stats.get('current_module', 'None')
        targets = stats.get('targets', 0)
        creds = stats.get('credentials', 0)

        status = f"[cyan]Module:[/cyan] {current_module} | [cyan]Targets:[/cyan] {targets} | [cyan]Creds:[/cyan] {creds}"
        self.console.print(Panel(status, border_style="dim"))
