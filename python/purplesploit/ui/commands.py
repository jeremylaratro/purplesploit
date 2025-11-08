"""
Command Handler for PurpleSploit

Handles all console commands including module management, context commands,
and utility operations.
"""

import shlex
from typing import Dict, List, Callable, Any
from pathlib import Path
from .display import Display
from .interactive import InteractiveSelector


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
        self.interactive = InteractiveSelector()
        self.commands = self._register_commands()
        self.last_search_results = []  # Store last search results for number selection
        self.current_operation_index = None  # Track selected operation

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
            "module": self.cmd_module,  # Module management with select
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

            # Enhanced search commands
            "ops": self.cmd_ops,  # Search operations globally
            "recent": self.cmd_recent,  # Show recent modules

            # Quick shortcuts
            "target": self.cmd_target_quick,  # Quick: target 192.168.1.1
            "cred": self.cmd_cred_quick,      # Quick: cred admin:password
            "go": self.cmd_go,                # Super quick: go target creds operation
            "quick": self.cmd_quick,          # Quick module load: quick smb auth

            # Utility commands
            "clear": self.cmd_clear,
            "history": self.cmd_history,
            "stats": self.cmd_stats,
            "interactive": self.cmd_interactive,  # Launch interactive TUI
            "i": self.cmd_interactive,            # Alias for interactive
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
            "search select": "Interactive module selection from last search (with fzf)",
            "module select": "Interactive module/operation selection with submenu (with fzf)",
            "use <module>": "Load a module by path (e.g., use web/feroxbuster)",
            "use <number>": "Load a module from search/show results",
            "back": "Unload current module",
            "info": "Show information about current module",
            "options": "Show current module options",
            "set <option> <value>": "Set a module option",
            "unset <option>": "Clear a module option",
            "run": "Execute the current module (interactive selection)",
            "run <number>": "Execute a specific operation by number",
            "check": "Check if module can run without executing",
            "": "",
            "Smart Search Commands": "",
            "ops <query>": "Search for operations across all modules",
            "ops select": "Interactive operation selection from last search (with fzf)",
            "recent": "Show recently used modules",
            "recent select": "Interactive selection from recent modules (with fzf)",
            "": "",
            "Context Commands": "",
            "targets add <ip|url> [name]": "Add a target",
            "targets list": "List all targets",
            "targets select": "Interactive target selection (with fzf)",
            "targets set <index>": "Set current target by index",
            "targets remove <ip|url>": "Remove a target",
            "": "",
            "creds add <user:pass> [domain]": "Add credentials",
            "creds list": "List all credentials",
            "creds select": "Interactive credential selection (with fzf)",
            "creds set <index>": "Set current credential by index",
            "creds remove <user>": "Remove credentials",
            "": "",
            "services": "View detected services on targets",
            "services select": "Interactive service selection (with fzf)",
            "": "",
            "Quick Shortcuts": "",
            "target <ip|url>": "Quick: add and set target",
            "cred <user:pass> [domain]": "Quick: add and set credential",
            "quick <module> [filter]": "Quick: load module with auto-population",
            "go <target> [creds] [op]": "All-in-one: set target, creds, run operation",
            "": "",
            "Show Commands": "",
            "show modules": "List all modules with operations (tree view)",
            "show options": "Show current module options",
            "show targets": "List all targets",
            "show creds": "List all credentials",
            "show services": "List detected services",
            "": "",
            "Utility Commands": "",
            "clear": "Clear the screen",
            "history": "Show command history",
            "stats": "Show framework statistics",
            "interactive, i": "Launch interactive TUI menu",
            "exit, quit": "Exit PurpleSploit",
        }

        self.display.print_help(help_text)
        return True

    def cmd_search(self, args: List[str]) -> bool:
        """Enhanced search for modules with auto-load on single result."""
        if not args:
            self.display.print_error("Usage: search <query>")
            self.display.print_info("       search select  # Interactive module selection from last search")
            self.display.print_info("Tip: Search looks at module name, description, category, and path")
            return True

        # Check for 'select' subcommand
        if args[0].lower() == "select":
            if not self.last_search_results:
                self.display.print_error("No search results available. Run 'search <query>' first")
                return True

            # Interactive selection
            selected = self.interactive.select_module(self.last_search_results, auto_load_single=False)
            if selected:
                return self.cmd_use([selected.path])
            else:
                self.display.print_warning("No module selected")
            return True

        query = " ".join(args)

        # Search modules
        module_results = self.framework.search_modules(query)

        if module_results:
            # Store results for number-based selection
            self.last_search_results = module_results
            self.display.print_modules_table(module_results)

            # Auto-load if single result
            if len(module_results) == 1:
                self.display.print_info(f"\n[Auto-loading single result...]")
                return self.cmd_use([module_results[0].path])
            else:
                self.display.print_info("\nTip: Use 'use <number>' to load a module or 'search select' for interactive selection")
        else:
            self.display.print_warning(f"No modules found matching: {query}")
            self.display.print_info("Tip: Use 'ops <query>' to search operations instead")

        return True

    def cmd_module(self, args: List[str]) -> bool:
        """
        Module management with interactive selection.

        Usage: module select
        """
        if not args or args[0].lower() == "select":
            # Get all modules
            modules = self.framework.list_modules()
            if not modules:
                self.display.print_warning("No modules available")
                return True

            # Interactive module selection
            selected_module = self.interactive.select_module(modules, auto_load_single=False)
            if not selected_module:
                self.display.print_warning("No module selected")
                return True

            # Load the module
            module = self.framework.use_module(selected_module.path)
            if not module:
                self.display.print_error(f"Failed to load module: {selected_module.path}")
                return True

            self.display.print_success(f"Loaded module: {module.name}")

            # Check if module has operations - if so, show submenu
            if module.has_operations():
                operations = module.get_operations()
                self.display.print_info(f"\nThis module has {len(operations)} operations")

                # Interactive operation selection
                selected_operation = self.interactive.select_operation(operations)

                if selected_operation:
                    # Execute the selected operation
                    self.display.print_info(f"Running: {selected_operation['name']}")
                    results = self._execute_operation(module, selected_operation)
                    self.display.print_results(results)
                else:
                    self.display.print_info("No operation selected - module loaded")
                    self.display.print_info("Type 'run' to select an operation or 'options' to view module options")
            else:
                self.display.print_info("Type 'options' to view module options")
                self.display.print_info("Type 'run' to execute the module")

            return True
        else:
            self.display.print_error("Usage: module select")
            return True

    def cmd_use(self, args: List[str]) -> bool:
        """Smart module loading with optional operation filtering."""
        if not args:
            self.display.print_error("Usage: use <module_path | number> [operation_filter]")
            self.display.print_info("Examples:")
            self.display.print_info("  use network/nxc_smb")
            self.display.print_info("  use 1                  # Select from search results")
            self.display.print_info("  use smb auth           # Load SMB module, show auth operations")
            return True

        # Check for multi-word usage like "use smb auth"
        if len(args) >= 2 and not args[0].isdigit():
            # Try to find module matching first part
            potential_module = args[0]
            filter_term = " ".join(args[1:])

            # Search for module
            results = self.framework.search_modules(potential_module)
            if len(results) == 1:
                module_path = results[0].path
                module = self.framework.use_module(module_path)

                if module:
                    self.display.print_success(f"Loaded module: {module.name}")

                    if module.has_operations():
                        operations = module.get_operations()
                        # Filter operations by the filter term
                        filtered_ops = [op for op in operations
                                       if filter_term.lower() in op['name'].lower()
                                       or filter_term.lower() in op['description'].lower()]

                        if filtered_ops:
                            self.display.print_info(f"\nShowing operations matching '{filter_term}':")
                            self._show_operations(filtered_ops)
                            self.display.print_info("\nTip: Use 'run <number>' to execute an operation")
                        else:
                            self.display.print_warning(f"No operations matching '{filter_term}'")
                            self.display.print_info("\nShowing all operations:")
                            self._show_operations(operations)
                    return True
            elif len(results) > 1:
                self.display.print_error(f"Multiple modules match '{potential_module}'. Be more specific:")
                self.last_search_results = results
                self.display.print_modules_table(results)
                return True

        module_identifier = args[0]

        # Check if it's a number (selecting from search results)
        if module_identifier.isdigit():
            index = int(module_identifier) - 1  # Convert to 0-based index

            if not self.last_search_results:
                self.display.print_error("No search results available. Run 'search' first")
                return True

            if index < 0 or index >= len(self.last_search_results):
                self.display.print_error(f"Invalid number. Must be 1-{len(self.last_search_results)}")
                return True

            # Get module path from search results
            module_path = self.last_search_results[index].path
        else:
            module_path = module_identifier

        module = self.framework.use_module(module_path)

        if module:
            self.display.print_success(f"Loaded module: {module.name}")

            # Check if module has operations/submenu
            if module.has_operations():
                operations = module.get_operations()
                self.display.print_info(f"\nThis module has {len(operations)} operations:")
                self._show_operations(operations)
                self.display.print_info("\nTip: Use 'run <number>' or 'run <operation_name>' to execute")
            else:
                self.display.print_info("Type 'options' to view module options")
                self.display.print_info("Type 'run' to execute the module")
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
            self.last_search_results = modules  # Store for number selection

            # Display modules with operations in tree view
            self._show_modules_tree(modules)
            self.display.print_info("\nTip: Use 'use <number>' to load a module or 'module select' for interactive selection")

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
        """Run the current module or a specific operation."""
        module = self.framework.session.current_module
        if not module:
            self.display.print_error("No module loaded. Use 'use <module>' first")
            return True

        # Check if module has operations
        if module.has_operations():
            operations = module.get_operations()

            # If args provided, select operation by number or name
            if args:
                operation_id = args[0]

                # Try as number first
                if operation_id.isdigit():
                    index = int(operation_id) - 1
                    if 0 <= index < len(operations):
                        operation = operations[index]
                    else:
                        self.display.print_error(f"Invalid operation number. Must be 1-{len(operations)}")
                        return True
                else:
                    # Try to find by name
                    operation = None
                    for op in operations:
                        if op['name'].lower() == operation_id.lower():
                            operation = op
                            break

                    if not operation:
                        self.display.print_error(f"Operation not found: {operation_id}")
                        self.display.print_info("Available operations:")
                        self._show_operations(operations)
                        return True
            else:
                # No args - use interactive selector
                self.display.print_info("Select an operation:")
                operation = self.interactive.select_operation(operations)

                if not operation:
                    self.display.print_warning("No operation selected")
                    return True

            # Execute the selected operation
            self.display.print_info(f"Running: {operation['name']}")
            results = self._execute_operation(module, operation)
            self.display.print_results(results)

        else:
            # Traditional single-operation module
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

        elif subcommand == "select":
            # Interactive selection
            targets = self.framework.session.targets.list()
            if not targets:
                self.display.print_warning("No targets available. Add targets first with 'targets add'")
                return True

            selected = self.interactive.select_target(targets)
            if selected:
                # Find index and set as current
                for i, target in enumerate(targets):
                    if target == selected:
                        self.framework.session.targets.current_index = i
                        identifier = selected.get('ip') or selected.get('url')
                        self.display.print_success(f"Selected target: {identifier}")

                        # Auto-set in current module if loaded
                        module = self.framework.session.current_module
                        if module:
                            if 'ip' in selected and "RHOST" in module.options:
                                module.set_option("RHOST", selected['ip'])
                                self.display.print_info(f"  → Set RHOST = {selected['ip']}")
                            elif 'url' in selected and "URL" in module.options:
                                module.set_option("URL", selected['url'])
                                self.display.print_info(f"  → Set URL = {selected['url']}")
                        break
            else:
                self.display.print_warning("No target selected")

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
            self.display.print_info("Usage: targets [list|add|set|select|remove]")

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

        elif subcommand == "select":
            # Interactive selection
            creds = self.framework.session.credentials.list()
            if not creds:
                self.display.print_warning("No credentials available. Add credentials first with 'creds add'")
                return True

            selected = self.interactive.select_credential(creds)
            if selected:
                # Find index and set as current
                for i, cred in enumerate(creds):
                    if cred == selected:
                        self.framework.session.credentials.current_index = i
                        self.display.print_success(f"Selected credential: {selected['username']}")

                        # Auto-set in current module if loaded
                        module = self.framework.session.current_module
                        if module:
                            if "USERNAME" in module.options:
                                module.set_option("USERNAME", selected['username'])
                                self.display.print_info(f"  → Set USERNAME = {selected['username']}")
                            if selected.get('password') and "PASSWORD" in module.options:
                                module.set_option("PASSWORD", selected['password'])
                                self.display.print_info(f"  → Set PASSWORD = ****")
                            if selected.get('domain') and "DOMAIN" in module.options:
                                module.set_option("DOMAIN", selected['domain'])
                                self.display.print_info(f"  → Set DOMAIN = {selected['domain']}")
                            if selected.get('hash') and "HASH" in module.options:
                                module.set_option("HASH", selected['hash'])
                                self.display.print_info(f"  → Set HASH = ****")
                        break
            else:
                self.display.print_warning("No credential selected")

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
            self.display.print_info("Usage: creds [list|add|set|select|remove]")

        return True

    def cmd_services(self, args: List[str]) -> bool:
        """View detected services."""
        # Check for 'select' subcommand
        if args and args[0].lower() == "select":
            services = self.framework.session.services.services
            if not services:
                self.display.print_warning("No services available")
                return True

            selected = self.interactive.select_service(services)
            if selected:
                self.display.print_success(f"Selected service: {selected.get('target')}:{selected.get('port')} - {selected.get('name')}")

                # Optionally set target based on service
                if selected.get('target'):
                    self.framework.session.targets.set_current(selected['target'])
                    self.display.print_info(f"  → Set current target to {selected['target']}")
            else:
                self.display.print_warning("No service selected")
        else:
            services = self.framework.session.services.services
            self.display.print_services_table(services)
            self.display.print_info("\nTip: Use 'services select' for interactive selection")

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

    def cmd_interactive(self, args: List[str]) -> bool:
        """Launch the interactive TUI menu (bash version)."""
        import subprocess
        import os

        try:
            # Find project root by looking for purplesploit-tui.sh
            project_root = None
            current = Path.cwd()
            while current.parent != current:
                tui_script = current / "purplesploit-tui.sh"
                if tui_script.exists():
                    project_root = current
                    break
                current = current.parent

            if not project_root:
                self.display.print_error("Could not find purplesploit-tui.sh")
                self.display.print_info("Make sure you're running from the PurpleSploit directory")
                return True

            tui_script = project_root / "purplesploit-tui.sh"
            self.display.print_info("Launching interactive TUI menu...")

            # Execute the bash TUI script
            # Use os.system to properly handle terminal control
            os.system(f'cd "{project_root}" && bash "{tui_script}"')

            # Clear screen and show console banner again after exiting TUI
            self.display.console.clear()
            self.display.print_banner()
            self.display.print_info("Returned to console mode. Type 'help' for commands.")

        except Exception as e:
            self.display.print_error(f"Error launching interactive mode: {e}")
            import traceback
            traceback.print_exc()

        return True

    def cmd_exit(self, args: List[str]) -> bool:
        """Exit the framework."""
        self.display.print_info("Exiting PurpleSploit...")
        return False


    def cmd_ops(self, args: List[str]) -> bool:
        """Search operations globally across all modules."""
        if not args:
            self.display.print_error("Usage: ops <query>")
            self.display.print_info("       ops select  # Interactive operation selection from last search")
            self.display.print_info("Example: ops authentication")
            return True

        # Check for 'select' subcommand
        if args[0].lower() == "select":
            if not hasattr(self, 'last_ops_results') or not self.last_ops_results:
                self.display.print_error("No operation search results available. Run 'ops <query>' first")
                return True

            # Format operations with module info for selection
            formatted_ops = []
            for result in self.last_ops_results:
                formatted_ops.append({
                    'name': f"{result['module']} - {result['operation']}",
                    'description': result['description'],
                    'module_path': result['module_path'],
                    'handler': None  # Not needed for selection
                })

            selected = self.interactive.select_operation(formatted_ops)
            if selected:
                # Extract module path from the result
                for result in self.last_ops_results:
                    if f"{result['module']} - {result['operation']}" == selected['name']:
                        self.display.print_info(f"Loading module: {result['module_path']}")
                        return self.cmd_use([result['module_path']])
            else:
                self.display.print_warning("No operation selected")
            return True

        query = " ".join(args).lower()
        results = self._search_operations(query)

        if results:
            # Group results by module for better organization
            from collections import defaultdict
            grouped = defaultdict(list)

            for result in results:
                module_key = result['module_path']
                grouped[module_key].append(result)

            # Display grouped results
            self.display.console.print(f"\n[bold cyan]Found {len(results)} operations across {len(grouped)} modules matching '{query}':[/bold cyan]\n")

            for module_path in sorted(grouped.keys()):
                ops_list = grouped[module_path]
                mod_name = ops_list[0]['module']  # All ops in group have same module name

                # Module header
                self.display.console.print(f"[bold green]▸ {mod_name}[/bold green] [dim]({module_path})[/dim]")

                # List operations under this module
                for i, result in enumerate(ops_list, 1):
                    op_name = result['operation']
                    op_desc = result['description']

                    self.display.console.print(f"  [cyan]{i}.[/cyan] {op_name}")
                    self.display.console.print(f"     [dim]{op_desc}[/dim]")

                self.display.console.print()  # Blank line between modules
            # Store results for selection
            self.last_ops_results = results

            self.display.console.print(f"\n[bold cyan]Found {len(results)} operations matching '{query}':[/bold cyan]\n")
            for i, result in enumerate(results, 1):
                mod_name = result['module']
                mod_path = result['module_path']
                op_name = result['operation']
                op_desc = result['description']

                self.display.console.print(f"  [dim]{i}.[/dim] [green]{mod_name}[/green]")
                self.display.console.print(f"     Operation: {op_name}")
                self.display.console.print(f"     {op_desc}")
                self.display.console.print(f"     [dim]Path: {mod_path}[/dim]\n")

            self.display.print_info("Tip: Use 'use <module_path>' to load the module or 'ops select' for interactive selection")
        else:
            self.display.print_warning(f"No operations found matching: {query}")

        return True

    def cmd_recent(self, args: List[str]) -> bool:
        """Show recently used modules."""
        history = self.framework.session.command_history[-50:]  # Last 50 commands

        # Extract 'use' commands
        recent_modules = []
        recent_module_objects = []
        for entry in reversed(history):
            cmd = entry.get('command', '')
            if cmd.startswith('use '):
                parts = cmd.split()
                if len(parts) >= 2 and not parts[1].isdigit():
                    module_path = parts[1]
                    if module_path not in recent_modules:
                        recent_modules.append(module_path)
                        # Get module metadata if available
                        if module_path in self.framework.modules:
                            recent_module_objects.append(self.framework.modules[module_path])
                    if len(recent_modules) >= 10:
                        break

        # Check for 'select' subcommand
        if args and args[0].lower() == "select":
            if not recent_module_objects:
                self.display.print_warning("No recent modules available")
                return True

            selected = self.interactive.select_module(recent_module_objects, auto_load_single=False)
            if selected:
                return self.cmd_use([selected.path])
            else:
                self.display.print_warning("No module selected")
            return True

        if recent_modules:
            self.display.console.print("\n[bold cyan]Recently Used Modules:[/bold cyan]\n")
            for i, mod_path in enumerate(recent_modules, 1):
                # Try to get module info
                if mod_path in self.framework.modules:
                    meta = self.framework.modules[mod_path]
                    self.display.console.print(f"  [dim]{i}.[/dim] [green]{mod_path}[/green] - {meta.description}")
                else:
                    self.display.console.print(f"  [dim]{i}.[/dim] {mod_path}")

            self.display.print_info("\nTip: Use 'use <number>' after running 'search' or 'recent select' for interactive selection")
        else:
            self.display.print_info("No recent modules found")

        return True

    def cmd_target_quick(self, args: List[str]) -> bool:
        """Quick target setting: target 192.168.1.1"""
        if not args:
            # Show current target
            target = self.framework.session.targets.get_current()
            if target:
                identifier = target.get('ip') or target.get('url')
                self.display.print_info(f"Current target: {identifier}")
            else:
                self.display.print_info("No target set")
            return True

        identifier = args[0]

        # Detect type
        target_type = "web" if identifier.startswith("http") else "network"

        # Add target
        self.framework.add_target(target_type, identifier)

        # Set as current
        self.framework.session.targets.set_current(identifier)

        self.display.print_success(f"Target set to: {identifier}")

        # Also set RHOST/URL in current module if loaded
        module = self.framework.session.current_module
        if module:
            if target_type == "network" and "RHOST" in module.options:
                module.set_option("RHOST", identifier)
                self.display.print_info(f"  → Set RHOST = {identifier}")
            elif target_type == "web" and "URL" in module.options:
                module.set_option("URL", identifier)
                self.display.print_info(f"  → Set URL = {identifier}")

        return True

    def cmd_cred_quick(self, args: List[str]) -> bool:
        """Quick credential setting: cred admin:password [domain]"""
        if not args:
            # Show current cred
            cred = self.framework.session.credentials.get_current()
            if cred:
                self.display.print_info(f"Current cred: {cred['username']}")
            else:
                self.display.print_info("No credential set")
            return True

        # Parse username:password
        if ":" in args[0]:
            username, password = args[0].split(":", 1)
        else:
            username = args[0]
            password = None

        domain = args[1] if len(args) > 1 else None

        # Add credential
        self.framework.add_credential(username, password, domain)

        # Set as current
        self.framework.session.credentials.set_current(username)

        self.display.print_success(f"Credential set: {username}")

        # Also set in current module if loaded
        module = self.framework.session.current_module
        if module:
            if "USERNAME" in module.options:
                module.set_option("USERNAME", username)
                self.display.print_info(f"  → Set USERNAME = {username}")
            if password and "PASSWORD" in module.options:
                module.set_option("PASSWORD", password)
                self.display.print_info(f"  → Set PASSWORD = ****")
            if domain and "DOMAIN" in module.options:
                module.set_option("DOMAIN", domain)
                self.display.print_info(f"  → Set DOMAIN = {domain}")

        return True

    def _search_operations(self, query: str) -> List[Dict]:
        """
        Search for operations across all modules.

        Supports multi-word queries where all words must match somewhere in:
        - Module path (e.g., "network/nxc_smb")
        - Module name (e.g., "NetExec SMB")
        - Operation name (e.g., "List Shares")
        - Operation description

        Args:
            query: Search term (can be multiple words)

        Returns:
            List of matching operations with module info
        """
        results = []

        # Split query into individual words for flexible matching
        query_words = query.lower().split()

        for mod_path, metadata in self.framework.modules.items():
            # Load module to get operations
            try:
                module_class = metadata.instance
                if module_class:
                    # Instantiate temporarily to get operations
                    temp_module = module_class(self.framework)
                    if temp_module.has_operations():
                        operations = temp_module.get_operations()
                        for op in operations:
                            # Build searchable text including module context
                            searchable_text = ' '.join([
                                mod_path,                    # e.g., "network/nxc_smb"
                                metadata.name,               # e.g., "NetExec SMB"
                                metadata.category,           # e.g., "network"
                                op['name'],                  # e.g., "List Shares"
                                op['description']            # e.g., "Enumerate SMB shares"
                            ]).lower()

                            # Check if ALL query words appear in searchable text
                            if all(word in searchable_text for word in query_words):
                                results.append({
                                    'module': metadata.name,
                                    'module_path': mod_path,
                                    'operation': op['name'],
                                    'description': op['description']
                                })
            except Exception:
                pass  # Skip modules that fail to instantiate

        return results

    # Helper methods
    def _show_modules_tree(self, modules: List[Any]) -> None:
        """
        Display modules with their operations in a tree view.

        Args:
            modules: List of module metadata objects
        """
        from rich.table import Table
        from rich import box

        table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
        table.add_column("#", style="dim", width=5)
        table.add_column("Category", style="yellow", width=10)
        table.add_column("Module / Operation", style="white")
        table.add_column("Description", style="white")

        item_number = 1
        for mod in modules:
            path = self._get_attr(mod, 'path', '')
            name = self._get_attr(mod, 'name', '')
            desc = self._get_attr(mod, 'description', '')
            category = self._get_attr(mod, 'category', '').upper()

            # Add module row
            table.add_row(
                str(item_number),
                f"[{category}]",
                f"[green]{path}[/green]",
                desc
            )
            item_number += 1

            # Try to get operations for this module
            try:
                module_class = self._get_attr(mod, 'instance', None)
                if module_class:
                    temp_module = module_class(self.framework)
                    if temp_module.has_operations():
                        operations = temp_module.get_operations()
                        for op in operations:
                            op_name = op.get('name', '')
                            op_desc = op.get('description', '')
                            # Add indented operation row
                            table.add_row(
                                "",
                                "",
                                f"  └─ [cyan]{op_name}[/cyan]",
                                f"[dim]{op_desc}[/dim]"
                            )
            except Exception:
                pass  # Skip if can't load operations

        self.display.console.print(table)

    def _get_attr(self, obj: Any, attr: str, default: Any = None) -> Any:
        """
        Get attribute from object or dict.

        Args:
            obj: Dictionary or object
            attr: Attribute name
            default: Default value if not found

        Returns:
            Attribute value or default
        """
        if isinstance(obj, dict):
            return obj.get(attr, default)
        else:
            return getattr(obj, attr, default)

    # Helper methods
    def _show_operations(self, operations: List[Dict]) -> None:
        """
        Display operations menu in a formatted table.

        Args:
            operations: List of operation dictionaries
        """
        from rich.table import Table
        from rich import box

        table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
        table.add_column("#", style="dim", width=4)
        table.add_column("Operation", style="green")
        table.add_column("Description", style="white")

        for i, op in enumerate(operations, 1):
            table.add_row(
                str(i),
                op.get('name', 'Unknown'),
                op.get('description', 'No description')
            )

        self.display.console.print(table)

    def _execute_operation(self, module, operation: Dict) -> Dict:
        """
        Execute a specific module operation.

        Args:
            module: Module instance
            operation: Operation dictionary with 'handler' key

        Returns:
            Results dictionary
        """
        handler = operation.get('handler')

        if handler is None:
            return {
                "success": False,
                "error": "No handler defined for operation"
            }

        try:
            # Handler can be a method name (string) or callable
            if isinstance(handler, str):
                # Get method from module
                method = getattr(module, handler, None)
                if method is None:
                    return {
                        "success": False,
                        "error": f"Handler method not found: {handler}"
                    }
                result = method()
            elif callable(handler):
                # Call directly
                result = handler()
            else:
                return {
                    "success": False,
                    "error": f"Invalid handler type: {type(handler)}"
                }

            return result if isinstance(result, dict) else {"success": True, "output": str(result)}

        except Exception as e:
            return {
                "success": False,
                "error": f"Error executing operation: {str(e)}"
            }

    def cmd_go(self, args: List[str]) -> bool:
        """
        Quick workflow: go <target> [username:password] [operation]
        
        Examples:
          go 192.168.1.100                    # Set target and show operations
          go 192.168.1.100 admin:pass        # Set target + creds, show operations
          go 192.168.1.100 admin:pass 1      # Set target + creds, run operation #1
        """
        if not args:
            self.display.print_error("Usage: go <target> [username:password] [operation]")
            self.display.print_info("Examples:")
            self.display.print_info("  go 192.168.1.100")
            self.display.print_info("  go 192.168.1.100 admin:Password123")
            self.display.print_info("  go 192.168.1.100 admin:pass 1")
            return True

        # Parse target
        target = args[0]
        self.cmd_target_quick([target])

        # Parse credentials if provided
        if len(args) >= 2 and ':' in args[1]:
            self.cmd_cred_quick([args[1]])

        # Parse operation if provided
        if len(args) >= 3:
            # Check if we have a module loaded
            module = self.framework.session.current_module
            if module and module.has_operations():
                return self.cmd_run([args[2]])
            else:
                self.display.print_warning("No module loaded. Load a module first with 'use'")

        # If no operation specified, show operations if module is loaded
        module = self.framework.session.current_module
        if module and module.has_operations():
            self.display.print_info("\nModule loaded and ready. Available operations:")
            operations = module.get_operations()
            self._show_operations(operations)

        return True

    def cmd_quick(self, args: List[str]) -> bool:
        """
        Quick module shortcuts:
        
          quick smb                  # Load SMB, auto-set target/creds from context
          quick smb shares           # Load SMB, run shares operation
          quick ldap bloodhound      # Load LDAP, run bloodhound collection
        """
        if not args:
            self.display.print_error("Usage: quick <module_type> [operation_filter]")
            self.display.print_info("Examples:")
            self.display.print_info("  quick smb")
            self.display.print_info("  quick smb auth")
            self.display.print_info("  quick ldap bloodhound")
            return True

        module_type = args[0].lower()
        operation_filter = " ".join(args[1:]) if len(args) > 1 else None

        # Map quick names to module paths
        quick_map = {
            'smb': 'network/nxc_smb',
            'ldap': 'network/nxc_ldap',
            'winrm': 'network/nxc_winrm',
            'mssql': 'network/nxc_mssql',
            'rdp': 'network/nxc_rdp',
            'ssh': 'network/nxc_ssh',
            'ferox': 'web/feroxbuster',
            'sqlmap': 'web/sqlmap',
        }

        if module_type not in quick_map:
            self.display.print_error(f"Unknown quick module: {module_type}")
            self.display.print_info("Available: " + ", ".join(quick_map.keys()))
            return True

        # Load module
        module_path = quick_map[module_type]
        module = self.framework.use_module(module_path)

        if not module:
            self.display.print_error(f"Failed to load module: {module_path}")
            return True

        self.display.print_success(f"Loaded: {module.name}")

        # Auto-populate from context
        module.auto_set_from_context()

        # Show what was auto-populated
        if module.get_option('RHOST'):
            self.display.print_info(f"  → RHOST = {module.get_option('RHOST')}")
        if module.get_option('USERNAME'):
            self.display.print_info(f"  → USERNAME = {module.get_option('USERNAME')}")

        # Filter operations if specified
        if module.has_operations() and operation_filter:
            operations = module.get_operations()
            filtered = [op for op in operations
                       if operation_filter.lower() in op['name'].lower()
                       or operation_filter.lower() in op['description'].lower()]

            if filtered:
                self.display.print_info(f"\nOperations matching '{operation_filter}':")
                self._show_operations(filtered)
            else:
                self.display.print_warning(f"No operations matching '{operation_filter}'")
                self.display.print_info("\nAll operations:")
                self._show_operations(operations)
        elif module.has_operations():
            self.display.print_info("\nAvailable operations:")
            self._show_operations(module.get_operations())

        return True
