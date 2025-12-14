"""
Base command infrastructure for PurpleSploit.

Provides the foundation for command registration and execution.
"""

from typing import Dict, List, Callable, Any


class BaseCommandMixin:
    """
    Mixin providing base command infrastructure.

    Attributes:
        commands: Dictionary mapping command names to handler functions
        aliases: Dictionary mapping aliases to command names
    """

    def _init_base_commands(self):
        """Initialize command infrastructure."""
        self.commands: Dict[str, Callable] = {}
        self.aliases: Dict[str, str] = {}
        self.last_search_results = []
        self.last_ops_results = []

    def register_command(self, name: str, handler: Callable, aliases: List[str] = None):
        """
        Register a command handler.

        Args:
            name: Primary command name
            handler: Function to handle the command
            aliases: Optional list of command aliases
        """
        self.commands[name] = handler
        if aliases:
            for alias in aliases:
                self.aliases[alias] = name

    def get_handler(self, command: str) -> Callable:
        """
        Get handler for a command, resolving aliases.

        Args:
            command: Command name or alias

        Returns:
            Handler function or None
        """
        command = command.lower()
        # Check for alias first
        if command in self.aliases:
            command = self.aliases[command]
        return self.commands.get(command)

    def parse_command(self, command_line: str) -> tuple:
        """
        Parse a command line into command and arguments.

        Args:
            command_line: Raw command line input

        Returns:
            Tuple of (command, args_list)
        """
        import shlex
        try:
            parts = shlex.split(command_line)
        except ValueError:
            # Handle unclosed quotes
            parts = command_line.split()

        if not parts:
            return "", []

        return parts[0].lower(), parts[1:]

    def get_all_commands(self) -> List[str]:
        """Get list of all registered commands."""
        return sorted(self.commands.keys())

    def get_command_aliases(self, command: str) -> List[str]:
        """Get all aliases for a command."""
        return [alias for alias, cmd in self.aliases.items() if cmd == command]
