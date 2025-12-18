"""
OSINT (Open Source Intelligence) modules for passive reconnaissance.

These modules gather intelligence from public sources without directly
interacting with the target infrastructure.
"""

from .shodan import ShodanModule
from .crtsh import CrtshModule
from .dnsdumpster import DNSDumpsterModule

__all__ = [
    'ShodanModule',
    'CrtshModule',
    'DNSDumpsterModule',
]
