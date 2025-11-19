"""
Console Module for PurpleSploit

Interactive REPL console with prompt_toolkit integration.
"""

from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory, InMemoryHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter, merge_completers, FuzzyCompleter
from prompt_toolkit.styles import Style
from pathlib import Path

from .display import Display
from .commands import CommandHandler


class Console:
    """
    Interactive console for PurpleSploit.

    Provides a Metasploit-style REPL with enhanced command completion, history, and
    context-aware prompting with dropdown menu support.
    """

    def __init__(self, framework):
        """
        Initialize console.

        Args:
            framework: Reference to Framework instance
        """
        self.framework = framework
        self.display = Display()
        self.command_handler = CommandHandler(framework)
        self.running = True

        # Setup history file
        history_path = Path.home() / ".purplesploit" / "history"
        history_path.parent.mkdir(exist_ok=True)

        # Setup prompt session with file history
        self.session = PromptSession(
            history=FileHistory(str(history_path)),
            auto_suggest=AutoSuggestFromHistory(),
            enable_history_search=True,
        )

        # Setup auto-completion with dropdown menu
        self.completer = self._create_completer()

        # Prompt style with enhanced dropdown menu colors
        self.prompt_style = Style.from_dict({
            'prompt': '#ff00ff bold',      # Magenta prompt
            'module': '#00ffff',            # Cyan module name
            'completion-menu': 'bg:#1a1a1a #00ff00',  # Dark bg, green text
            'completion-menu.completion': 'bg:#1a1a1a #00ff00',
            'completion-menu.completion.current': 'bg:#00ff00 #000000 bold',  # Inverted for current
            'scrollbar.background': 'bg:#333333',
            'scrollbar.button': 'bg:#00ff00',
        })

    def _create_completer(self) -> WordCompleter:
        """
        Create dynamic command completer with context-aware suggestions.

        Returns:
            WordCompleter with all available commands and context items
        """
        # Base commands from command handler
        commands = list(self.command_handler.commands.keys())

        # Add common subcommands and options
        suggestions = commands.copy()
        suggestions.extend([
            'select', 'list', 'add', 'remove', 'set',
            'auth', 'enum', 'shares', 'users', 'groups',
            'bloodhound', 'dump', 'spray', 'brute',
        ])

        # Add module paths if available
        try:
            modules = self.framework.list_modules()
            module_paths = [m.path for m in modules]
            suggestions.extend(module_paths)
        except:
            pass

        # Add target IPs if available
        try:
            targets = self.framework.session.targets.list()
            target_ips = [t.get('ip') or t.get('url', '') for t in targets if t.get('ip') or t.get('url')]
            suggestions.extend(target_ips)
        except:
            pass

        # Remove duplicates while preserving order
        seen = set()
        unique_suggestions = []
        for item in suggestions:
            if item and item not in seen:
                seen.add(item)
                unique_suggestions.append(item)

        return WordCompleter(
            unique_suggestions,
            ignore_case=True,
            sentence=True,
            match_middle=True
        )

    def start(self):
        """Start the console REPL loop."""
        # Print banner
        self.display.print_banner()

        # Welcome message with stats
        stats = self.framework.get_stats()
        self.display.console.print(f"[dim cyan]  ◆ {stats['modules']} modules loaded across {stats['categories']} categories[/dim cyan]")
        self.display.console.print(f"[dim cyan]  ◆ Type [bold cyan]help[/bold cyan] for commands | [bold cyan]module select[/bold cyan] to browse interactively[/dim cyan]")
        self.display.console.print(f"[dim cyan]  ◆ Quick start: [bold cyan]target[/bold cyan] <ip> → [bold cyan]cred[/bold cyan] <user:pass> → [bold cyan]module select[/bold cyan][/dim cyan]")
        self.display.console.print()

        # Main loop
        while self.running:
            try:
                # Get prompt text
                prompt_text = self._get_prompt()

                # Update completer with current context
                self.completer = self._create_completer()

                # Get user input with enhanced dropdown menu
                user_input = self.session.prompt(
                    prompt_text,
                    completer=self.completer,
                    style=self.prompt_style,
                    complete_while_typing=True,
                    complete_in_thread=True
                )

                # Execute command
                if user_input.strip():
                    self.running = self.command_handler.execute(user_input)

            except KeyboardInterrupt:
                # Ctrl+C: just continue
                self.display.console.print()
                continue

            except EOFError:
                # Ctrl+D: exit
                break

            except Exception as e:
                self.display.print_error(f"Console error: {e}")
                import traceback
                traceback.print_exc()

        # Cleanup
        self._cleanup()

    def _get_prompt(self) -> list:
        """
        Generate the prompt text.

        Returns:
            List of (style, text) tuples for prompt_toolkit
        """
        prompt_parts = [
            ('class:prompt', 'purplesploit'),
        ]

        # Add current module if loaded
        if self.framework.session.current_module:
            module_name = self.framework.session.current_module.name
            prompt_parts.append(('class:prompt', ' '))
            prompt_parts.append(('class:module', f'({module_name})'))

        prompt_parts.append(('class:prompt', ' > '))

        return prompt_parts

    def _cleanup(self):
        """Cleanup before exit."""
        self.display.print_info("Cleaning up...")
        self.framework.cleanup()
        self.display.print_info("Goodbye!")
