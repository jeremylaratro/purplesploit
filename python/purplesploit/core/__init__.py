"""
PurpleSploit Core Module
Core framework components including module management, session handling, and database operations.
"""

from .framework import Framework
from .module import BaseModule, ModuleMetadata
from .session import Session
from .database import Database

__all__ = [
    'Framework',
    'BaseModule',
    'ModuleMetadata',
    'Session',
    'Database',
]
