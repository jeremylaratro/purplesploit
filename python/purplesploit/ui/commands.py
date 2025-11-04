"""
Command Handler for PurpleSploit

Handles all console commands including module management, context commands,
and utility operations.
"""

import shlex
from typing import Dict, List, Callable
from .display import Display


class CommandHandler:
    """
    Command handler for PurpleSploit console.

    Processes user input and executes appropriate commands.
    """

    def __init__(self, framework):
        """
        Initialize command handler.

        Args:
            framework: Reference to Framework instance
        """
        self.framework = framework
        self.display = Display()
        self.commands = self._register_commands()

    def _register_commands(self) -> Dict[str, Callable]:
        """
        Register all available commands.

        Returns:
            Dictionary mapping command names to handler methods
        """
        return {
            # Help
            "help": self.cmd_help,
            "?": self.cmd_help,

            # Module commands
            "search": self.cmd_search,
            "use": self.cmd_use,
            "back": self.cmd_back,
            "info": self.cmd_info,
            "options": self.cmd_options,
            "show": self.cmd_show,
            "set": self.cmd_set,
            "unset": self.cmd_unset,
            "run": self.cmd_run,
            "exploit": self.cmd_run,  # Alias
            "check": self.cmd_check,

            # Context commands
            "targets": self.cmd_targets,
            "creds": self.cmd_creds,
            "services": self.cmd_services,

            # Utility commands
            "clear": self.cmd_clear,
            "history": self.cmd_history,
            "stats": self.cmd_stats,
            "exit": self.cmd_exit,
            "quit": self.cmd_exit,
        }

    def execute(self, command_line: str) -> bool:
        """
        Execute a command.

        Args:
            command_line: Full command line from user

        Returns:
            False if should exit, True otherwise
        """
        if not command_line or not command_line.strip():
            return True

        # Add to history
        self.framework.session.add_command(command_line)

        try:
            # Parse command using shlex for proper quoted argument handling
            parts = shlex.split(command_line)
            command = parts[0].lower()
            args = parts[1:] if len(parts) > 1 else []

            # Execute command
            handler = self.commands.get(command)
            if handler:
                return handler(args)
            else:
                self.display.print_error(f"Unknown command: {command}")
                self.display.print_info("Type 'help' for available commands")
                return True

        except ValueError as e:
            self.display.print_error(f"Invalid command syntax: {e}")
            return True
        except Exception as e:
            self.display.print_error(f"Error executing command: {e}")
            import traceback
            traceback.print_exc()
            return True

    def cmd_help(self, args: List[str]) -> bool:
        """Show help information."""
        help_text = {
            "help, ?": "Show this help message",
            "": "",
            "Module Commands": "",
            "search <query>": "Search for modules by name, description, or category",
            "use <module>": "Load a module by path (e.g., use web/feroxbuster)",
            "back": "Unload current module",
            "info": "Show information about current module",
            "options": "Show current module options",
            "set <option> <value>": "Set a module option",
            "unset <option>": "Clear a module option",
            "run": "Execute the current module",
            "check": "Check if module can run without executing",
            "": "",
            "Context Commands": "",
            "targets [add|list|set|remove]": "Manage targets",
            "creds [add|list|set|remove]": "Manage credentials",
            "services [list|scan]": "View detected services",
            "": "",
            "Show Commands": "",
            "show modules": "List all modules",
            "show options": "Show current module options",
            "show targets": "List all targets",
            "show creds": "List all credentials",
            "show services": "List detected services",
            "": "",
            "Utility Commands": "",
            "clear": "Clear the screen",
            "history": "Show command history",
            "stats": "Show framework statistics",
            "exit, quit": "Exit PurpleSploit",
        }

        self.display.print_help(help_text)
        return True

    def cmd_search(self, args: List[str]) -> bool:
        """Search for modules."""
        if not args:
            self.display.print_error("Usage: search <query>")
            return True

        query = " ".join(args)
        results = self.framework.search_modules(query)

        if results:
            self.display.print_modules_table(results)
        else:
            self.display.print_warning(f"No modules found matching: {query}")

        return True

    def cmd_use(self, args: List[str]) -> bool:
        """Load a module."""
        if not args:
            self.display.print_error("Usage: use <module_path>")
            return True

        module_path = args[0]
        module = self.framework.use_module(module_path)

        if module:
            self.display.print_success(f"Loaded module: {module.name}")
            self.display.print_info("Type 'options' to view module options")
            self.display.print_info("Type 'info' for module information")
        else:
            self.display.print_error(f"Failed to load module: {module_path}")
            self.display.print_info("Use 'search' to find modules")

        return True

    def cmd_back(self, args: List[str]) -> bool:
        """Unload current module."""
        if self.framework.session.current_module:
            module_name = self.framework.session.current_module.name
            self.framework.session.unload_module()
            self.display.print_success(f"Unloaded module: {module_name}")
        else:
            self.display.print_warning("No module loaded")

        return True

    def cmd_info(self, args: List[str]) -> bool:
        """Show module information."""
        module = self.framework.session.current_module
        if not module:
            self.display.print_error("No module loaded. Use 'use <module>' first")
            return True

        self.display.print_module_info(module)
        return True

    def cmd_options(self, args: List[str]) -> bool:
        """Show module options."""
        module = self.framework.session.current_module
        if not module:
            self.display.print_error("No module loaded. Use 'use <module>' first")
            return True

        options = module.show_options()
        self.display.print_options_table(options)
        return True

    def cmd_show(self, args: List[str]) -> bool:
        """Show various information."""
        if not args:
            self.display.print_error("Usage: show <modules|options|targets|creds|services>")
            return True

        what = args[0].lower()

        if what == "modules":
            modules = self.framework.list_modules()
            self.display.print_modules_table(modules)

        elif what == "options":
            return self.cmd_options([])

        elif what == "targets":
            targets = self.framework.session.targets.list()
            self.display.print_targets_table(targets)

        elif what == "creds" or what == "credentials":
            creds = self.framework.session.credentials.list()
            self.display.print_credentials_table(creds)

        elif what == "services":
            services = self.framework.session.services.services
            self.display.print_services_table(services)

        else:
            self.display.print_error(f"Unknown show option: {what}")

        return True

    def cmd_set(self, args: List[str]) -> bool:
        """Set a module option."""
        if len(args) < 2:
            self.display.print_error("Usage: set <option> <value>")
            return True

        module = self.framework.session.current_module
        if not module:
            self.display.print_error("No module loaded. Use 'use <module>' first")
            return True

        option = args[0].upper()
        value = " ".join(args[1:])

        if module.set_option(option, value):
            self.display.print_success(f"{option} => {value}")
        else:
            self.display.print_error(f"Failed to set option: {option}")

        return True

    def cmd_unset(self, args: List[str]) -> bool:
        """Clear a module option."""
        if not args:
            self.display.print_error("Usage: unset <option>")
            return True

        module = self.framework.session.current_module
        if not module:
            self.display.print_error("No module loaded. Use 'use <module>' first")
            return True

        option = args[0].upper()
        if module.set_option(option, None):
            self.display.print_success(f"Cleared option: {option}")
        else:
            self.display.print_error(f"Failed to clear option: {option}")

        return True

    def cmd_run(self, args: List[str]) -> bool:
        """Run the current module."""
        module = self.framework.session.current_module
        if not module:
            self.display.print_error("No module loaded. Use 'use <module>' first")
            return True

        self.display.print_info(f"Running module: {module.name}")
        results = self.framework.run_module(module)
        self.display.print_results(results)

        return True

    def cmd_check(self, args: List[str]) -> bool:
        """Check if module can run."""
        module = self.framework.session.current_module
        if not module:
            self.display.print_error("No module loaded. Use 'use <module>' first")
            return True

        result = module.check()
        if result.get('success'):
            self.display.print_success(result.get('message', 'Module check passed'))
        else:
            self.display.print_error(result.get('error', 'Module check failed'))

        return True

    def cmd_targets(self, args: List[str]) -> bool:
        """Manage targets."""
        if not args or args[0] == "list":
            targets = self.framework.session.targets.list()
            self.display.print_targets_table(targets)
            return True

        subcommand = args[0].lower()

        if subcommand == "add":
            if len(args) < 2:
                self.display.print_error("Usage: targets add <ip|url> [name]")
                return True

            identifier = args[1]
            name = args[2] if len(args) > 2 else None

            # Detect type
            target_type = "web" if identifier.startswith("http") else "network"

            if self.framework.add_target(target_type, identifier, name):
                self.display.print_success(f"Added target: {identifier}")
            else:
                self.display.print_warning("Target already exists")

        elif subcommand == "set":
            if len(args) < 2:
                self.display.print_error("Usage: targets set <index|identifier>")
                return True

            if self.framework.session.targets.set_current(args[1]):
                target = self.framework.session.targets.get_current()
                identifier = target.get('ip') or target.get('url')
                self.display.print_success(f"Current target set to: {identifier}")
            else:
                self.display.print_error("Target not found")

        elif subcommand == "remove":
            if len(args) < 2:
                self.display.print_error("Usage: targets remove <identifier>")
                return True

            if self.framework.session.targets.remove(args[1]):
                self.display.print_success(f"Removed target: {args[1]}")
            else:
                self.display.print_error("Target not found")

        else:
            self.display.print_error(f"Unknown subcommand: {subcommand}")
            self.display.print_info("Usage: targets [list|add|set|remove]")

        return True

    def cmd_creds(self, args: List[str]) -> bool:
        """Manage credentials."""
        if not args or args[0] == "list":
            creds = self.framework.session.credentials.list()
            self.display.print_credentials_table(creds)
            return True

        subcommand = args[0].lower()

        if subcommand == "add":
            if len(args) < 2:
                self.display.print_error("Usage: creds add <username>:<password> [domain]")
                return True

            # Parse username:password
            if ":" in args[1]:
                username, password = args[1].split(":", 1)
            else:
                username = args[1]
                password = None

            domain = args[2] if len(args) > 2 else None

            if self.framework.add_credential(username, password, domain):
                self.display.print_success(f"Added credential: {username}")
            else:
                self.display.print_warning("Credential already exists")

        elif subcommand == "set":
            if len(args) < 2:
                self.display.print_error("Usage: creds set <index|username>")
                return True

            if self.framework.session.credentials.set_current(args[1]):
                cred = self.framework.session.credentials.get_current()
                self.display.print_success(f"Current credential set to: {cred['username']}")
            else:
                self.display.print_error("Credential not found")

        elif subcommand == "remove":
            if len(args) < 2:
                self.display.print_error("Usage: creds remove <identifier>")
                return True

            if self.framework.session.credentials.remove(args[1]):
                self.display.print_success(f"Removed credential: {args[1]}")
            else:
                self.display.print_error("Credential not found")

        else:
            self.display.print_error(f"Unknown subcommand: {subcommand}")
            self.display.print_info("Usage: creds [list|add|set|remove]")

        return True

    def cmd_services(self, args: List[str]) -> bool:
        """View detected services."""
        services = self.framework.session.services.services
        self.display.print_services_table(services)
        return True

    def cmd_clear(self, args: List[str]) -> bool:
        """Clear the screen."""
        self.display.clear()
        return True

    def cmd_history(self, args: List[str]) -> bool:
        """Show command history."""
        history = self.framework.session.command_history

        if not history:
            self.display.print_info("No command history")
            return True

        # Show last 20 commands
        recent = history[-20:]
        for i, entry in enumerate(recent, 1):
            cmd = entry.get('command', '')
            timestamp = entry.get('timestamp', '')
            if timestamp:
                timestamp = timestamp.split('.')[0]  # Remove microseconds
            self.display.console.print(f"[dim]{i}.[/dim] [{timestamp}] {cmd}")

        return True

    def cmd_stats(self, args: List[str]) -> bool:
        """Show framework statistics."""
        stats = self.framework.get_stats()

        self.display.print_info("Framework Statistics:")
        self.display.console.print(f"  Modules: {stats['modules']}")
        self.display.console.print(f"  Categories: {stats['categories']}")
        self.display.console.print(f"  Targets: {stats['targets']}")
        self.display.console.print(f"  Credentials: {stats['credentials']}")
        self.display.console.print(f"  Current Module: {stats['current_module'] or 'None'}")

        return True

    def cmd_exit(self, args: List[str]) -> bool:
        """Exit the framework."""
        self.display.print_info("Exiting PurpleSploit...")
        return False
