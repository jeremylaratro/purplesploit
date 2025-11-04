"""
Interactive Menu System

Mouse and keyboard interactive menus using prompt_toolkit
"""

from typing import List, Dict, Optional, Tuple, Any, Callable
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from prompt_toolkit.shortcuts import radiolist_dialog, button_dialog
from prompt_toolkit.styles import Style as PTStyle

from .themes import get_console


class InteractiveMenu:
    """Interactive menu with mouse and keyboard support"""

    def __init__(self, title: str, subtitle: str = "", console: Optional[Console] = None):
        """
        Initialize interactive menu

        Args:
            title: Menu title
            subtitle: Menu subtitle
            console: Rich console
        """
        self.title = title
        self.subtitle = subtitle
        self.console = console or get_console()
        self.items: List[Tuple[Any, str]] = []  # (value, label) pairs

    def add_item(self, value: Any, label: str):
        """Add a menu item"""
        self.items.append((value, label))

    def add_separator(self):
        """Add a visual separator"""
        self.items.append((None, "─" * 50))

    def show(self) -> Optional[Any]:
        """
        Show the menu and get user selection

        Returns:
            Selected value or None if cancelled
        """
        if not self.items:
            return None

        # Create prompt_toolkit style
        style = PTStyle.from_dict({
            'dialog': 'bg:#1a1a2e',
            'dialog.body': 'bg:#16213e',
            'dialog shadow': 'bg:#000000',
            'button': 'bg:#0f3460 #e94560',
            'button.focused': 'bg:#e94560 #ffffff bold',
            'radio-list': 'bg:#16213e #00d9ff',
            'radio-checked': '#e94560 bold',
            'radio-selected': 'bg:#0f3460 #ffffff',
        })

        # Show radiolist dialog
        result = radiolist_dialog(
            title=self.title,
            text=self.subtitle if self.subtitle else None,
            values=self.items,
            style=style,
        ).run()

        return result


def create_main_menu() -> InteractiveMenu:
    """Create the main category menu"""
    menu = InteractiveMenu(
        "PurpleSploit - Main Menu",
        "Use arrow keys or mouse to select, Enter to confirm"
    )

    menu.add_item("web", "🌐 Web Testing - Web application testing tools")
    menu.add_item("nxc", "🔧 Network Testing - NXC - NetExec (CrackMapExec) tools")
    menu.add_item("impacket", "🛠️  Network Testing - Impacket - Impacket protocol tools")
    menu.add_item("smb", "🗄️  SMB Operations - SMB enumeration and exploitation")
    menu.add_item("ldap", "📁 LDAP Operations - LDAP and Active Directory")
    menu.add_item("winrm", "🖥️  WinRM Operations - Windows Remote Management")
    menu.add_item("mssql", "🗃️  MSSQL Operations - Microsoft SQL Server testing")
    menu.add_item("rdp", "🖱️  RDP Operations - Remote Desktop Protocol")
    menu.add_item("ssh", "🔐 SSH Operations - Secure Shell operations")
    menu.add_item("recon", "🔍 Reconnaissance - Information gathering and scanning")
    menu.add_item("c2", "🎮 C2 & Command Control - Mythic C2 deployment")
    menu.add_item("ai", "🤖 AI Automation - AI-assisted pentesting")
    menu.add_separator()
    menu.add_item("settings", "⚙️  Settings - Configure framework settings")
    menu.add_item("exit", "✕ Exit - Exit PurpleSploit")

    return menu


def create_web_menu() -> InteractiveMenu:
    """Create web testing menu"""
    menu = InteractiveMenu("Web Testing", "Select a web testing tool")

    menu.add_item("feroxbuster", "🔍 Feroxbuster - Fast directory/file discovery")
    menu.add_item("sqlmap", "💉 SQLMap - SQL injection testing")
    menu.add_item("wfuzz", "🎯 Wfuzz - Web application fuzzer")
    menu.add_item("httpx", "🌐 HTTPx - HTTP probe and analysis")
    menu.add_separator()
    menu.add_item("back", "← Back to main menu")

    return menu


def create_nxc_menu() -> InteractiveMenu:
    """Create NXC menu"""
    menu = InteractiveMenu("NetExec (NXC) Tools", "Select a protocol")

    menu.add_item("nxc_smb", "🗄️  SMB - SMB protocol operations")
    menu.add_item("nxc_ldap", "📁 LDAP - LDAP protocol operations")
    menu.add_item("nxc_winrm", "🖥️  WinRM - WinRM protocol operations")
    menu.add_item("nxc_mssql", "🗃️  MSSQL - MSSQL protocol operations")
    menu.add_item("nxc_rdp", "🖱️  RDP - RDP protocol operations")
    menu.add_item("nxc_ssh", "🔐 SSH - SSH protocol operations")
    menu.add_item("nxc_scan", "📡 Scanning - Network scanning with NXC")
    menu.add_separator()
    menu.add_item("back", "← Back to main menu")

    return menu


def create_impacket_menu() -> InteractiveMenu:
    """Create Impacket menu"""
    menu = InteractiveMenu("Impacket Tools", "Select an Impacket tool category")

    menu.add_item("impacket_exec", "⚡ Execution - PSExec, WMIExec, SMBExec, etc.")
    menu.add_item("impacket_creds", "🔑 Credentials - SecretsDump, credential extraction")
    menu.add_item("impacket_kerberos", "🎫 Kerberos - Kerberoasting, AS-REP roasting")
    menu.add_item("impacket_smb", "🗄️  SMB Client - SMB operations")
    menu.add_item("impacket_enum", "📋 Enumeration - LDAP and AD enumeration")
    menu.add_item("impacket_services", "🔧 Services - Service management")
    menu.add_item("impacket_registry", "📝 Registry - Registry operations")
    menu.add_separator()
    menu.add_item("back", "← Back to main menu")

    return menu


def create_settings_menu() -> InteractiveMenu:
    """Create settings menu"""
    menu = InteractiveMenu("Settings", "Configure framework settings")

    menu.add_item("workspaces", "📁 Manage Workspaces - Create, switch, or list workspaces")
    menu.add_item("targets", "🎯 Manage Targets - Add, remove, or list targets")
    menu.add_item("credentials", "🔑 Manage Credentials - Add, remove, or list credentials")
    menu.add_item("variables", "⚙️  Set Variables - Configure framework variables")
    menu.add_item("scan", "🔍 Run Service Scan - Scan current target for services")
    menu.add_item("show_vars", "📋 View Variables - Show all configured variables")
    menu.add_separator()
    menu.add_item("back", "← Back to main menu")

    return menu
