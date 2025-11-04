"""
Autocomplete and Tab Completion

Provides intelligent autocomplete for commands, targets, and options
"""

from typing import List, Dict, Optional
from prompt_toolkit.completion import Completer, Completion, PathCompleter
from prompt_toolkit.document import Document


class PurpleSploitCompleter(Completer):
    """Autocompleter for PurpleSploit commands and options"""

    def __init__(self, context, service_detector):
        """
        Initialize completer

        Args:
            context: Context instance with workspace/target info
            service_detector: ServiceDetector instance
        """
        self.context = context
        self.service_detector = service_detector
        self.path_completer = PathCompleter()

        # Command completions
        self.commands = [
            "help",
            "exit",
            "quit",
            "workspace",
            "target",
            "credentials",
            "creds",
            "set",
            "get",
            "unset",
            "show",
            "run",
            "scan",
            "services",
            "clear",
            "back",
        ]

        # Tool categories
        self.categories = [
            "web",
            "network",
            "recon",
            "smb",
            "ldap",
            "winrm",
            "mssql",
            "rdp",
            "ssh",
            "impacket",
            "c2",
            "mythic",
        ]

        # Common variables
        self.variables = [
            "RHOST",
            "RPORT",
            "RHOSTS",
            "LHOST",
            "LPORT",
            "USERNAME",
            "PASSWORD",
            "DOMAIN",
            "HASH",
            "TARGET_URL",
            "WORDLIST",
            "THREADS",
            "TIMEOUT",
        ]

    def get_completions(self, document: Document, complete_event):
        """Get completions for the current input"""
        text = document.text_before_cursor
        words = text.split()

        # Empty input - show commands
        if not words:
            for cmd in self.commands:
                yield Completion(cmd, start_position=0, display_meta="command")
            return

        # First word - command completion
        if len(words) == 1 and not text.endswith(" "):
            word = words[0].lower()
            for cmd in self.commands:
                if cmd.startswith(word):
                    yield Completion(
                        cmd,
                        start_position=-len(word),
                        display_meta="command"
                    )
            return

        # Context-aware completion
        command = words[0].lower()

        # Workspace command
        if command == "workspace":
            if len(words) == 1 or (len(words) == 2 and not text.endswith(" ")):
                subcommands = ["list", "switch", "create", "current"]
                word = words[1] if len(words) == 2 else ""
                for subcmd in subcommands:
                    if subcmd.startswith(word):
                        yield Completion(
                            subcmd,
                            start_position=-len(word),
                            display_meta="workspace command"
                        )
            elif len(words) == 2 and words[1] == "switch":
                # Show available workspaces
                workspaces = self.context.get_workspaces()
                for ws in workspaces:
                    yield Completion(ws, start_position=0, display_meta="workspace")

        # Target command
        elif command == "target":
            if len(words) == 1 or (len(words) == 2 and not text.endswith(" ")):
                subcommands = ["list", "set", "add", "current"]
                word = words[1] if len(words) == 2 else ""
                for subcmd in subcommands:
                    if subcmd.startswith(word):
                        yield Completion(
                            subcmd,
                            start_position=-len(word),
                            display_meta="target command"
                        )
            elif len(words) == 2 and words[1] == "set":
                # Show available targets
                targets = self.context.get_targets()
                for target in targets:
                    yield Completion(target, start_position=0, display_meta="target")

        # Set command (variables)
        elif command == "set":
            if len(words) == 1 or (len(words) == 2 and not text.endswith(" ")):
                word = words[1] if len(words) == 2 else ""
                for var in self.variables:
                    if var.lower().startswith(word.lower()):
                        yield Completion(
                            var,
                            start_position=-len(word),
                            display_meta="variable"
                        )

        # Show command
        elif command == "show":
            if len(words) == 1 or (len(words) == 2 and not text.endswith(" ")):
                options = ["variables", "targets", "workspaces", "services", "context"]
                word = words[1] if len(words) == 2 else ""
                for opt in options:
                    if opt.startswith(word):
                        yield Completion(
                            opt,
                            start_position=-len(word),
                            display_meta="show option"
                        )

        # Run command (tools)
        elif command == "run":
            if len(words) == 1 or (len(words) == 2 and not text.endswith(" ")):
                word = words[1] if len(words) == 2 else ""
                for category in self.categories:
                    if category.startswith(word):
                        yield Completion(
                            category,
                            start_position=-len(word),
                            display_meta="tool category"
                        )

        # Scan command
        elif command == "scan":
            if len(words) == 1 or (len(words) == 2 and not text.endswith(" ")):
                scan_types = ["quick", "full", "vuln"]
                word = words[1] if len(words) == 2 else ""
                for scan_type in scan_types:
                    if scan_type.startswith(word):
                        yield Completion(
                            scan_type,
                            start_position=-len(word),
                            display_meta="scan type"
                        )


class ToolCompleter(Completer):
    """Completer for tool-specific options"""

    def __init__(self, tool_name: str, options: List[str]):
        """
        Initialize tool completer

        Args:
            tool_name: Name of the tool
            options: List of available options
        """
        self.tool_name = tool_name
        self.options = options

    def get_completions(self, document: Document, complete_event):
        """Get completions for tool options"""
        text = document.text_before_cursor
        word = text.split()[-1] if text.split() else ""

        for option in self.options:
            if option.lower().startswith(word.lower()):
                yield Completion(
                    option,
                    start_position=-len(word),
                    display_meta=f"{self.tool_name} option"
                )
