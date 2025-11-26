"""
PurpleSploit - Offensive Security Framework

A Metasploit-style framework with improved usability and persistent context.

Key Features:
- Persistent targets and credentials across module switches
- Auto-population of module options from context
- Service detection integration
- SQLite-based persistence
- Rich CLI with tables and formatted output
"""

from .core.framework import Framework
from .core.module import BaseModule, ExternalToolModule
from .core.session import Session

__version__ = "6.6.0"
__author__ = "PurpleSploit Team"

__all__ = [
    'Framework',
    'BaseModule',
    'ExternalToolModule',
    'Session',
]
