"""
PurpleSploit Command Mixins

Modular command handling split into focused command groups.
These mixins can be used to compose the main CommandHandler.

Available mixins:
- BaseCommandMixin: Core command infrastructure
- ModuleCommandsMixin: Module-related commands
- ContextCommandsMixin: Target, credential, service management
- UtilityCommandsMixin: Help, history, stats commands
"""

from .base import BaseCommandMixin
from .module_commands import ModuleCommandsMixin
from .context_commands import ContextCommandsMixin
from .utility_commands import UtilityCommandsMixin

__all__ = [
    'BaseCommandMixin',
    'ModuleCommandsMixin',
    'ContextCommandsMixin',
    'UtilityCommandsMixin',
]
