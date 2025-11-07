"""
Console Module for PurpleSploit

Interactive REPL console with prompt_toolkit integration.
"""

from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style
from pathlib import Path

from .display import Display
from .commands import CommandHandler


class Console:
    """
    Interactive console for PurpleSploit.

    Provides a Metasploit-style REPL with command completion, history, and
    context-aware prompting.
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

        # Setup prompt session
        self.session = PromptSession(
            history=FileHistory(str(history_path)),
            auto_suggest=AutoSuggestFromHistory(),
            enable_history_search=True,
        )

        # Command completer
        commands = list(self.command_handler.commands.keys())
        self.completer = WordCompleter(
            commands,
            ignore_case=True,
            sentence=True
        )

        # Prompt style
        self.prompt_style = Style.from_dict({
            'prompt': '#ff00ff bold',  # Magenta
            'module': '#00ffff',        # Cyan
        })

    def start(self):
        """Start the console REPL loop."""
        # Print banner
        self.display.print_banner()

        # Welcome message
        self.display.print_info("Type 'help' for available commands")
        self.display.console.print()

        # Main loop
        while self.running:
            try:
                # Get prompt text
                prompt_text = self._get_prompt()

                # Get user input
                user_input = self.session.prompt(
                    prompt_text,
                    completer=self.completer,
                    style=self.prompt_style,
                    complete_while_typing=True
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
