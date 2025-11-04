"""
Menu System

Rich-based menu system with beautiful tables, panels, and navigation
"""

from typing import List, Dict, Optional, Callable, Any
from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich.layout import Layout
from rich.align import Align
from prompt_toolkit import prompt
from prompt_toolkit.shortcuts import radiolist_dialog, button_dialog, message_dialog
from .themes import get_console, PURPLESPLOIT_THEME
from .completer import ToolCompleter


class MenuItem:
    """Represents a single menu item"""

    def __init__(
        self,
        title: str,
        description: str = "",
        action: Optional[Callable] = None,
        icon: str = "●",
        category: str = "",
        requires_service: Optional[str] = None
    ):
        """
        Initialize menu item

        Args:
            title: Item title
            description: Item description
            action: Callable action when item is selected
            icon: Icon to display
            category: Category for grouping
            requires_service: Service that must be detected to highlight this item
        """
        self.title = title
        self.description = description
        self.action = action
        self.icon = icon
        self.category = category
        self.requires_service = requires_service


class Menu:
    """Rich-based menu system"""

    def __init__(self, console: Optional[Console] = None):
        """
        Initialize menu

        Args:
            console: Rich console (creates new one if None)
        """
        self.console = console or get_console()
        self.items: List[MenuItem] = []
        self.title = ""
        self.subtitle = ""

    def add_item(self, item: MenuItem):
        """Add an item to the menu"""
        self.items.append(item)

    def add_separator(self):
        """Add a separator line"""
        self.items.append(None)

    def set_title(self, title: str, subtitle: str = ""):
        """Set menu title and subtitle"""
        self.title = title
        self.subtitle = subtitle

    def render_table(
        self,
        detected_services: Optional[List[str]] = None,
        show_categories: bool = True
    ) -> Table:
        """
        Render menu as a Rich table

        Args:
            detected_services: List of detected services for highlighting
            show_categories: Group items by category

        Returns:
            Rich Table
        """
        detected_services = detected_services or []

        if show_categories and any(item and item.category for item in self.items):
            # Group by category
            categories = {}
            for item in self.items:
                if item is None:
                    continue
                cat = item.category or "General"
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(item)

            # Create table with categories
            table = Table(
                title=self.title,
                title_style="menu_title",
                border_style="border",
                show_header=True,
                header_style="bold cyan",
                padding=(0, 1)
            )

            table.add_column("#", style="dim", width=4, justify="right")
            table.add_column("Category", style="category_web")
            table.add_column("Tool / Action", style="menu_item")
            table.add_column("Description", style="dim")

            idx = 1
            for cat_name in sorted(categories.keys()):
                for item in categories[cat_name]:
                    # Check if service is detected for highlighting
                    highlight = False
                    if item.requires_service:
                        highlight = item.requires_service.lower() in [
                            s.lower() for s in detected_services
                        ]

                    # Style based on detection
                    if highlight:
                        icon = f"[service_detected]{item.icon}[/service_detected]"
                        title_style = "menu_highlight"
                    else:
                        icon = item.icon
                        title_style = "menu_item"

                    table.add_row(
                        str(idx),
                        f"{icon} {cat_name}",
                        f"[{title_style}]{item.title}[/{title_style}]",
                        item.description
                    )
                    idx += 1

        else:
            # Simple list
            table = Table(
                title=self.title,
                title_style="menu_title",
                border_style="border",
                show_header=True,
                header_style="bold cyan",
                padding=(0, 1)
            )

            table.add_column("#", style="dim", width=4, justify="right")
            table.add_column("Option", style="menu_item")
            table.add_column("Description", style="dim")

            for idx, item in enumerate(self.items, 1):
                if item is None:
                    table.add_row("", "─" * 40, "")
                    continue

                # Check if service is detected
                highlight = False
                if item.requires_service:
                    highlight = item.requires_service.lower() in [
                        s.lower() for s in detected_services
                    ]

                if highlight:
                    icon = f"[service_detected]{item.icon}[/service_detected]"
                    title_style = "menu_highlight"
                else:
                    icon = item.icon
                    title_style = "menu_item"

                table.add_row(
                    str(idx),
                    f"{icon} [{title_style}]{item.title}[/{title_style}]",
                    item.description
                )

        return table

    def render_panel(
        self,
        detected_services: Optional[List[str]] = None,
        show_categories: bool = True
    ) -> Panel:
        """
        Render menu as a Rich panel

        Args:
            detected_services: List of detected services
            show_categories: Group items by category

        Returns:
            Rich Panel containing the menu
        """
        table = self.render_table(detected_services, show_categories)
        return Panel(
            table,
            title=f"[header] {self.title} [/header]",
            subtitle=self.subtitle if self.subtitle else None,
            border_style="border_active",
            padding=(1, 2)
        )

    def display(
        self,
        detected_services: Optional[List[str]] = None,
        show_categories: bool = True
    ):
        """
        Display the menu

        Args:
            detected_services: List of detected services
            show_categories: Group items by category
        """
        panel = self.render_panel(detected_services, show_categories)
        self.console.print(panel)

    def select(self, prompt_text: str = "Select option") -> Optional[MenuItem]:
        """
        Prompt user to select a menu item

        Args:
            prompt_text: Prompt text

        Returns:
            Selected MenuItem or None
        """
        while True:
            try:
                # Filter out separators for selection
                selectable_items = [item for item in self.items if item is not None]

                if not selectable_items:
                    return None

                choice = self.console.input(f"\n[menu_title]{prompt_text}[/menu_title] [dim](1-{len(selectable_items)} or 'b' for back)[/dim]: ")

                if choice.lower() in ['b', 'back', 'q', 'quit']:
                    return None

                if choice.isdigit():
                    idx = int(choice) - 1
                    if 0 <= idx < len(selectable_items):
                        return selectable_items[idx]

                self.console.print("[warning]Invalid selection. Please try again.[/warning]")
            except KeyboardInterrupt:
                return None
            except EOFError:
                return None


class ToolMenu:
    """Specialized menu for tool operations"""

    def __init__(
        self,
        tool_name: str,
        operations: Dict[str, Dict[str, Any]],
        console: Optional[Console] = None
    ):
        """
        Initialize tool menu

        Args:
            tool_name: Name of the tool
            operations: Dictionary of operations {name: {description, requires_service, action}}
            console: Rich console
        """
        self.tool_name = tool_name
        self.operations = operations
        self.console = console or get_console()

    def display_and_select(self, detected_services: Optional[List[str]] = None) -> Optional[str]:
        """
        Display tool operations and get selection

        Args:
            detected_services: List of detected services

        Returns:
            Selected operation name or None
        """
        menu = Menu(self.console)
        menu.set_title(f"{self.tool_name} Operations", "Select an operation to perform")

        for op_name, op_info in self.operations.items():
            menu.add_item(MenuItem(
                title=op_name,
                description=op_info.get("description", ""),
                icon="►",
                requires_service=op_info.get("requires_service")
            ))

        menu.display(detected_services)
        selected = menu.select("Select operation")

        if selected:
            # Find the operation name
            for idx, (op_name, _) in enumerate(self.operations.items()):
                if idx == self.items.index(selected):
                    return op_name

        return None


def create_category_menu(console: Optional[Console] = None) -> Menu:
    """Create the main category menu"""
    menu = Menu(console)
    menu.set_title("PurpleSploit - Main Menu", "Select a tool category")

    categories = [
        ("Web Testing", "Web application testing tools", "category_web", "http"),
        ("Network Testing - NXC", "NetExec (formerly CrackMapExec) tools", "category_network", None),
        ("Network Testing - Impacket", "Impacket protocol tools", "category_network", None),
        ("SMB Operations", "SMB enumeration and exploitation", "category_network", "smb"),
        ("LDAP Operations", "LDAP and Active Directory", "category_network", "ldap"),
        ("WinRM Operations", "Windows Remote Management", "category_network", "winrm"),
        ("MSSQL Operations", "Microsoft SQL Server testing", "category_network", "mssql"),
        ("RDP Operations", "Remote Desktop Protocol", "category_network", "rdp"),
        ("SSH Operations", "Secure Shell operations", "category_network", "ssh"),
        ("Reconnaissance", "Information gathering and scanning", "category_recon", None),
        ("C2 & Command Control", "Mythic C2 deployment", "category_c2", None),
        ("AI Automation", "AI-assisted pentesting", "category_post", None),
    ]

    for title, desc, style, service in categories:
        menu.add_item(MenuItem(
            title=title,
            description=desc,
            icon="►",
            requires_service=service
        ))

    menu.add_separator()
    menu.add_item(MenuItem("Settings", "Configure framework settings", icon="⚙"))
    menu.add_item(MenuItem("Exit", "Exit PurpleSploit", icon="✕"))

    return menu
