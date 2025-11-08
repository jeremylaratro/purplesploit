"""
Themes and styling for PurpleSploit Rich TUI
"""

from rich.console import Console
from rich.theme import Theme
from rich.style import Style

# PurpleSploit color scheme
PURPLESPLOIT_THEME = Theme({
    # Main colors
    "primary": "bold magenta",
    "secondary": "bold cyan",
    "success": "bold green",
    "warning": "bold yellow",
    "danger": "bold red",
    "info": "bold blue",

    # UI elements
    "header": "bold magenta on black",
    "footer": "cyan on black",
    "menu_title": "bold cyan",
    "menu_item": "white",
    "menu_selected": "black on cyan",
    "menu_highlight": "bold yellow",

    # Status indicators
    "status_active": "bold green",
    "status_inactive": "dim white",
    "service_detected": "bold green",
    "service_missing": "dim red",

    # Context display
    "context_label": "bold cyan",
    "context_value": "yellow",
    "workspace": "bold magenta",
    "target": "bold green",
    "credential": "bold yellow",

    # Tool categories
    "category_web": "bold cyan",
    "category_network": "bold magenta",
    "category_recon": "bold blue",
    "category_exploit": "bold red",
    "category_post": "bold yellow",
    "category_c2": "bold orange1",

    # Output
    "output_success": "green",
    "output_error": "red",
    "output_info": "cyan",
    "output_command": "yellow",

    # Borders
    "border": "cyan",
    "border_active": "magenta",
})

# ASCII Art Banner
BANNER = """[bold magenta]
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
║                            [dim]Version 3.3 - TUI Mode[/dim]                           ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝[/bold magenta]
"""

# Service detection icons
SERVICE_ICONS = {
    "smb": "🗄️",
    "ldap": "📁",
    "winrm": "🖥️",
    "mssql": "🗃️",
    "rdp": "🖱️",
    "ssh": "🔐",
    "http": "🌐",
    "https": "🔒",
    "ftp": "📂",
    "smtp": "📧",
}

# Status icons
STATUS_ICONS = {
    "active": "●",
    "inactive": "○",
    "success": "✓",
    "error": "✗",
    "warning": "⚠",
    "info": "ℹ",
    "running": "⚙",
}

def get_console(theme=PURPLESPLOIT_THEME):
    """Get a Rich console with the PurpleSploit theme"""
    return Console(theme=theme)

def format_service_status(service_name, is_detected):
    """Format a service status with icon and color"""
    icon = SERVICE_ICONS.get(service_name.lower(), "●")
    if is_detected:
        return f"[service_detected]{icon}[/service_detected]"
    else:
        return f"[service_missing]{icon}[/service_missing]"

def format_status(status_type, message):
    """Format a status message with appropriate icon and color"""
    icon = STATUS_ICONS.get(status_type, "")
    style_map = {
        "success": "output_success",
        "error": "output_error",
        "warning": "warning",
        "info": "output_info",
        "running": "info",
    }
    style = style_map.get(status_type, "info")
    return f"[{style}]{icon} {message}[/{style}]"
