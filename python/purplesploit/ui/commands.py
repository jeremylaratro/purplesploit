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
        self.webserver_process = None  # Track background webserver process

        # Service name shortcuts - maps service names to module paths
        self.service_shortcuts = {
            'smb': 'network/nxc_smb',
            'ldap': 'network/nxc_ldap',
            'winrm': 'network/nxc_winrm',
            'mssql': 'network/nxc_mssql',
            'rdp': 'network/nxc_rdp',
            'ssh': 'network/nxc_ssh',
            'nmap': 'recon/nmap',
            'feroxbuster': 'web/feroxbuster',
            'ferox': 'web/feroxbuster',
            'sqlmap': 'web/sqlmap',
            'wfuzz': 'web/wfuzz',
            'httpx': 'web/httpx',
        }

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
            "wordlists": self.cmd_wordlists,
            "analysis": self.cmd_analysis,     # View analysis results (web scans, etc.)
            "webresults": self.cmd_analysis,   # Alias for analysis

            # Enhanced search commands
            "ops": self.cmd_ops,  # Search operations globally
            "recent": self.cmd_recent,  # Show recent modules
            "l": self.cmd_show_ops,  # Show operations (short alias)
            "operations": self.cmd_show_ops,  # Show operations

            # Quick shortcuts
            "target": self.cmd_target_quick,  # Quick: target 192.168.1.1
            "cred": self.cmd_cred_quick,      # Quick: cred admin:password
            "go": self.cmd_go,                # Super quick: go target creds operation
            "quick": self.cmd_quick,          # Quick module load: quick smb auth

            # Utility commands
            "clear": self.cmd_clear,
            "history": self.cmd_history,
            "stats": self.cmd_stats,
            "hosts": self.cmd_hosts,              # Generate hosts file
            "ligolo": self.cmd_ligolo,            # Launch ligolo-ng
            "shell": self.cmd_shell,              # Drop to localhost shell
            "webserver": self.cmd_webserver,      # Start/stop web server
            "deploy": self.cmd_deploy,            # Deploy payloads/tools to targets
            "defaults": self.cmd_defaults,        # Manage module default options
            "parse": self.cmd_parse,              # Parse nmap XML results
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
        """Show help information with enhanced visual layout."""
        from rich.panel import Panel
        from rich.columns import Columns
        from rich import box

        self.display.console.print()
        self.display.console.print("[bold magenta]═══════════════════════════════════════════════════════════════════[/bold magenta]")
        self.display.console.print("[bold cyan]                        PURPLESPLOIT HELP                          [/bold cyan]")
        self.display.console.print("[bold magenta]═══════════════════════════════════════════════════════════════════[/bold magenta]")
        self.display.console.print()

        # Module Commands Panel
        module_help = """[cyan]search <query>[/cyan]          Search for modules
[cyan]search select[/cyan]          Interactive module selection (fzf)
[cyan]module select[/cyan]          Browse modules + operations (fzf)
[cyan]use <module>[/cyan]            Load module (e.g., network/nxc_smb)
[cyan]use <number>[/cyan]            Load from search results
[cyan]back[/cyan]                   Unload current module
[cyan]info[/cyan]                   Show module information
[cyan]options[/cyan]                Show module options
[cyan]set <opt> <val>[/cyan]        Set module option
[cyan]run[/cyan]                    Execute module (interactive)
[cyan]check[/cyan]                  Check if module can run"""

        # Smart Search Panel
        search_help = """[cyan]ops <query>[/cyan]             Search operations globally
[cyan]ops select[/cyan]             Interactive operation selection
[cyan]recent[/cyan]                 Show recently used modules
[cyan]recent select[/cyan]          Interactive recent selection"""

        # Context Commands Panel - Basic
        context_basic = """[green]targets add/list/select[/green]        Manage targets (add, view, pick)
[green]targets set/remove/clear[/green]        Set current, remove, or clear all
[green]targets modify[/green]                  Interactive modification
[green]targets <idx> modify <k=v>[/green]      Modify by index (e.g., 1 modify ip=10.0.0.1)
[green]targets <idx|range> clear[/green]       Clear by index/range (e.g., 1-5 clear)
[green]creds add/list/select[/green]           Manage credentials (add, view, pick)
[green]creds set/remove/clear[/green]          Set current, remove, or clear all
[green]creds modify[/green]                    Interactive modification
[green]creds <idx> modify <k=v>[/green]        Modify by index (e.g., 1 modify password=new)
[green]creds <idx|range> clear[/green]         Clear by index/range"""

        # Context Commands Panel - Resources
        context_resources = """[green]wordlists add <cat> <path>[/green]     Add wordlist by category
[green]wordlists list/select/set[/green]       View, pick, or set wordlist
[green]wordlists remove <cat> <id>[/green]     Remove wordlist from category
[green]services[/green]                        View detected services from scans
[green]services select/clear[/green]           Pick service or clear all
[green]analysis[/green]                        View web scan results dashboard"""

        # Quick Shortcuts Panel
        shortcuts_help = """[yellow]target <ip>[/yellow]          Quick add and set target
[yellow]cred <user:pass>[/yellow]    Quick add and set credential
[yellow]quick <module>[/yellow]      Quick load with auto-populate
[yellow]go <tgt> <cred>[/yellow]     All-in-one workflow"""

        # Show Commands Panel
        show_help = """[magenta]show modules[/magenta]         List all (tree view)
[magenta]show targets[/magenta]         List all targets
[magenta]show creds[/magenta]           List all credentials
[magenta]show services[/magenta]        List detected services"""

        # Utility Commands Panel
        utility_help = """[blue]clear[/blue]                  Clear the screen
[blue]history[/blue]                Show command history
[blue]stats[/blue]                  Show statistics
[blue]defaults <cmd>[/blue]         Manage module default options
[blue]deploy[/blue]                 Show deployment modules (ligolo, c2, script)
[blue]deploy <type>[/blue]          Load deployment module (ligolo/c2/script)
[blue]webserver start[/blue]        Start web portal in background
[blue]webserver stop[/blue]         Stop web portal
[blue]webserver status[/blue]       Check web portal status
[blue]ligolo[/blue]                 Launch ligolo-ng (CTRL+D to return)
[blue]shell[/blue]                  Drop to localhost shell (CTRL+D to return)
[blue]exit, quit[/blue]             Exit framework"""

        # Display panels in columns
        self.display.console.print(Panel(module_help, title="[bold cyan]📦 Module Commands[/bold cyan]",
                                         border_style="cyan", box=box.ROUNDED, padding=(1, 2)))
        self.display.console.print()

        # Search panel (full width)
        self.display.console.print(Panel(search_help, title="[bold cyan]🔍 Smart Search[/bold cyan]",
                                         border_style="cyan", box=box.ROUNDED, padding=(1, 2)))
        self.display.console.print()

        # Two column layout for context management
        col1 = Panel(context_basic, title="[bold green]🎯 Targets & Credentials[/bold green]",
                    border_style="green", box=box.ROUNDED, padding=(1, 2))
        col2 = Panel(context_resources, title="[bold green]📦 Resources & Services[/bold green]",
                    border_style="green", box=box.ROUNDED, padding=(1, 2))
        self.display.console.print(Columns([col1, col2], equal=True, expand=True))
        self.display.console.print()

        # Two column layout for shortcuts and show
        col3 = Panel(shortcuts_help, title="[bold yellow]⚡ Quick Shortcuts[/bold yellow]",
                    border_style="yellow", box=box.ROUNDED, padding=(1, 2))
        col4 = Panel(show_help, title="[bold magenta]📋 Show Commands[/bold magenta]",
                    border_style="magenta", box=box.ROUNDED, padding=(1, 2))
        self.display.console.print(Columns([col3, col4], equal=True, expand=True))
        self.display.console.print()

        # Full width utility panel
        self.display.console.print(Panel(utility_help, title="[bold blue]🔧 Utility Commands[/bold blue]",
                                         border_style="blue", box=box.ROUNDED, padding=(1, 2)))

        self.display.console.print()
        self.display.console.print("[dim cyan]💡 Tip: Most commands support interactive selection with fzf - look for 'select' options[/dim cyan]")
        self.display.console.print()

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
        """Smart module loading with optional operation/subcategory filtering."""
        if not args:
            self.display.print_error("Usage: use <module_path | number> [operation_filter | subcategory]")
            self.display.print_info("Examples:")
            self.display.print_info("  use network/nxc_smb")
            self.display.print_info("  use 1                  # Select from search or ops results")
            self.display.print_info("  use smb auth           # Load SMB module, show auth subcategory")
            self.display.print_info("  use smb shares         # Load SMB module, show shares subcategory")
            return True

        # Check for multi-word usage like "use smb auth"
        if len(args) >= 2 and not args[0].isdigit():
            # Try to find module matching first part
            potential_module = args[0].lower()
            filter_term = " ".join(args[1:])

            # Check if it's a service shortcut first
            if potential_module in self.service_shortcuts:
                module_path = self.service_shortcuts[potential_module]
                results = [mod for mod in self.framework.list_modules() if mod.path == module_path]
            else:
                # Search for module
                results = self.framework.search_modules(potential_module)
            if len(results) == 1:
                module_path = results[0].path
                module = self.framework.use_module(module_path)

                if module:
                    self.display.print_success(f"Loaded module: {module.name}")

                    if module.has_operations():
                        operations = module.get_operations()

                        # Check if filter_term matches a subcategory
                        subcategories = module.get_subcategories()
                        matching_subcategory = None
                        for subcat in subcategories:
                            if filter_term.lower() == subcat.lower() or filter_term.lower() in subcat.lower():
                                matching_subcategory = subcat
                                break

                        if matching_subcategory:
                            # Filter by subcategory
                            filtered_ops = module.get_operations_by_subcategory(matching_subcategory)
                            self.display.console.print(f"\n[bold cyan]{matching_subcategory.upper()} Operations:[/bold cyan]")
                            self._show_operations(filtered_ops)
                            self.display.print_info(f"\nTip: Use 'run <number>' to execute an operation")
                        else:
                            # Filter operations by name/description
                            filtered_ops = [op for op in operations
                                           if filter_term.lower() in op['name'].lower()
                                           or filter_term.lower() in op['description'].lower()
                                           or filter_term.lower() == op.get('subcategory', '').lower()]

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

        # Check if it's a service shortcut
        if module_identifier.lower() in self.service_shortcuts:
            module_path = self.service_shortcuts[module_identifier.lower()]
        # Check if it's a number (selecting from search results or ops results)
        elif module_identifier.isdigit():
            index = int(module_identifier) - 1  # Convert to 0-based index

            # Check for module search results first
            if self.last_search_results:
                if index < 0 or index >= len(self.last_search_results):
                    self.display.print_error(f"Invalid number. Must be 1-{len(self.last_search_results)}")
                    return True
                # Get module path from search results
                module_path = self.last_search_results[index].path

            # Fall back to ops search results if available
            elif hasattr(self, 'last_ops_results') and self.last_ops_results:
                if index < 0 or index >= len(self.last_ops_results):
                    self.display.print_error(f"Invalid number. Must be 1-{len(self.last_ops_results)}")
                    return True
                # Get module path from ops results
                module_path = self.last_ops_results[index]['module_path']
                self.display.print_info(f"Loading module from operation result: {self.last_ops_results[index]['module']}")

            else:
                self.display.print_error("No search or ops results available. Run 'search' or 'ops' first")
                return True
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

        # Show default command if available
        default_cmd = module.get_default_command()
        if default_cmd:
            self.display.console.print("[bold cyan]Default Command:[/bold cyan]")
            self.display.console.print(f"[dim]$ [/dim]{default_cmd}\n")

        return True

    def cmd_show(self, args: List[str]) -> bool:
        """Show various information."""
        if not args:
            self.display.print_error("Usage: show <modules|options|targets|creds|services|ops>")
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

        elif what == "ops" or what == "operations":
            return self.cmd_show_ops([])

        else:
            self.display.print_error(f"Unknown show option: {what}")

        return True

    def cmd_show_ops(self, args: List[str]) -> bool:
        """
        Show operations for the current module.

        Supports optional subcategory filtering:
        - show ops              # Show all operations
        - show ops auth         # Show only auth operations
        - l                     # Short alias - show all operations
        - l auth                # Short alias - show auth operations
        """
        module = self.framework.session.current_module

        if not module:
            self.display.print_error("No module loaded. Use 'use <module>' first")
            return True

        if not module.has_operations():
            self.display.print_warning("Current module does not have operations")
            self.display.print_info("Try 'show options' to see module options instead")
            return True

        operations = module.get_operations()

        # Check if subcategory filter provided
        if args:
            filter_term = " ".join(args).lower()

            # Check if it matches a subcategory
            subcategories = module.get_subcategories()
            matching_subcategory = None
            for subcat in subcategories:
                if filter_term == subcat.lower() or filter_term in subcat.lower():
                    matching_subcategory = subcat
                    break

            if matching_subcategory:
                # Filter by subcategory
                filtered_ops = module.get_operations_by_subcategory(matching_subcategory)
                self.display.console.print(f"\n[bold cyan]{matching_subcategory.upper()} Operations:[/bold cyan]")
                self._show_operations(filtered_ops)
            else:
                # Filter by name/description
                filtered_ops = [op for op in operations
                               if filter_term in op['name'].lower()
                               or filter_term in op['description'].lower()
                               or filter_term == op.get('subcategory', '').lower()]

                if filtered_ops:
                    self.display.print_info(f"\nOperations matching '{filter_term}':")
                    self._show_operations(filtered_ops)
                else:
                    self.display.print_warning(f"No operations matching '{filter_term}'")
                    self.display.print_info("\nShowing all operations:")
                    self._show_operations(operations)
        else:
            # Show all operations
            self.display.print_info(f"\n{module.name} Operations:")

            # Show available subcategories if they exist
            subcategories = module.get_subcategories()
            if subcategories:
                self.display.console.print(f"[dim]Subcategories: {', '.join(subcategories)}[/dim]\n")

            self._show_operations(operations)

        self.display.print_info("\nTip: Use 'run <number>' to execute an operation")
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

        # If no module loaded, check if we can run from last ops results
        if not module:
            # Check if user provided a number and we have last ops results
            if args and args[0].isdigit() and hasattr(self, 'last_ops_results') and self.last_ops_results:
                op_index = int(args[0]) - 1
                if 0 <= op_index < len(self.last_ops_results):
                    result = self.last_ops_results[op_index]
                    self.display.print_info(f"Loading module: {result['module_path']}")
                    self.display.print_info(f"Running operation: {result['operation']}")

                    # Load the module
                    if not self.cmd_use([result['module_path']]):
                        return True

                    # Get the loaded module
                    module = self.framework.session.current_module
                    if not module:
                        self.display.print_error("Failed to load module")
                        return True

                    # Find the operation by name
                    operations = module.get_operations()
                    operation = None
                    for op in operations:
                        if op['name'] == result['operation']:
                            operation = op
                            break

                    if operation:
                        results = self._execute_operation(module, operation)
                        self.display.print_results(results)
                        return True
                    else:
                        self.display.print_error(f"Operation not found: {result['operation']}")
                        return True
                else:
                    self.display.print_error(f"Invalid operation number. Must be 1-{len(self.last_ops_results)}")
                    self.display.print_info("Run 'ops <query>' first to search for operations")
                    return True
            else:
                self.display.print_error("No module loaded. Use 'use <module>' first")
                if hasattr(self, 'last_ops_results') and self.last_ops_results:
                    self.display.print_info("Or use 'run <number>' to run an operation from your last ops search")
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

        # Handle "targets clear" - clear all
        if subcommand == "clear":
            # Clear from session
            count = self.framework.session.targets.clear()

            # Clear from legacy database
            self.framework.database.clear_all_targets()

            # Clear from models database (for dashboard sync)
            try:
                from purplesploit.models.database import db_manager
                db_manager.clear_all_targets()
            except Exception as e:
                self.display.print_warning(f"Could not clear dashboard targets: {e}")

            self.display.print_success(f"Cleared {count} target(s) from session and databases")
            return True

        # Handle "targets 1-5 clear" or "targets 1 clear" - range/index clear
        if subcommand.isdigit() or '-' in subcommand:
            if len(args) < 2:
                self.display.print_error("Usage: targets <index|range> <clear|modify> [options]")
                return True

            action = args[1].lower()

            if action == "clear":
                # Parse index or range
                if '-' in subcommand:
                    try:
                        start, end = subcommand.split('-')
                        start_idx = int(start)
                        end_idx = int(end)
                        count = self.framework.session.targets.remove_range(start_idx, end_idx)
                        self.display.print_success(f"Cleared {count} target(s)")
                    except ValueError:
                        self.display.print_error("Invalid range format. Use: targets 1-5 clear")
                else:
                    try:
                        index = int(subcommand)
                        if self.framework.session.targets.remove_by_index(index):
                            self.display.print_success(f"Cleared target at index {index}")
                        else:
                            self.display.print_error(f"No target at index {index}")
                    except ValueError:
                        self.display.print_error("Invalid index format")

            elif action == "modify":
                # Parse modify arguments: targets 1 modify name=NewName ip=10.0.0.1
                if len(args) < 3:
                    self.display.print_error("Usage: targets <index> modify <key=value> [key=value...]")
                    return True

                try:
                    index = int(subcommand)
                    modifications = {}
                    for arg in args[2:]:
                        if '=' in arg:
                            key, value = arg.split('=', 1)
                            modifications[key] = value

                    if modifications:
                        if self.framework.session.targets.modify(index, **modifications):
                            self.display.print_success(f"Modified target at index {index}")
                        else:
                            self.display.print_error(f"No target at index {index}")
                    else:
                        self.display.print_error("No modifications specified")
                except ValueError:
                    self.display.print_error("Invalid index format")

            else:
                self.display.print_error(f"Unknown action: {action}")
                self.display.print_info("Available actions: clear, modify")

            return True

        # Original subcommands
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

        elif subcommand == "modify":
            # Interactive target modification
            targets = self.framework.session.targets.list()
            if not targets:
                self.display.print_warning("No targets available. Add targets first with 'targets add' or 'target'")
                return True

            # Select target to modify
            self.display.print_info("Select target to modify:")
            selected = self.interactive.select_target(targets)
            if not selected:
                self.display.print_warning("No target selected")
                return True

            # Find the index by comparing identifier (more reliable than full dict comparison)
            index = None
            selected_id = selected.get('ip') or selected.get('url')
            for i, target in enumerate(targets):
                target_id = target.get('ip') or target.get('url')
                if target_id == selected_id:
                    index = i
                    break

            if index is None:
                self.display.print_error("Could not find target index")
                return True

            # Show current values
            identifier = selected.get('ip') or selected.get('url') or 'Unknown'
            self.display.print_info(f"\nModifying target: {identifier}")
            self.display.print_info("Current values:")
            for key in ['ip', 'url', 'name', 'type']:
                val = selected.get(key)
                self.display.print_info(f"  {key}: {val or 'Not set'}")

            # Prompt for modifications
            self.display.print_info("\nEnter new values (press Enter to skip):")
            modifications = {}

            for field in ['ip', 'url', 'name', 'type']:
                new_val = input(f"{field.capitalize()}: ").strip()
                if new_val:
                    modifications[field] = new_val

            if modifications:
                if self.framework.session.targets.modify(index, **modifications):
                    self.display.print_success(f"Modified target")
                    for key, val in modifications.items():
                        self.display.print_info(f"  → Set {key} = {val}")
                else:
                    self.display.print_error("Failed to modify target")
            else:
                self.display.print_info("No modifications made")

        else:
            self.display.print_error(f"Unknown subcommand: {subcommand}")
            self.display.print_info("Usage: targets [list|add|set|select|modify|remove|clear|<index> clear|<range> clear|<index> modify]")

        return True

    def cmd_creds(self, args: List[str]) -> bool:
        """Manage credentials."""
        if not args or args[0] == "list":
            creds = self.framework.session.credentials.list()
            self.display.print_credentials_table(creds)
            return True

        subcommand = args[0].lower()

        # Handle "creds clear" - clear all
        if subcommand == "clear":
            count = self.framework.session.credentials.clear()
            self.display.print_success(f"Cleared {count} credential(s)")
            return True

        # Handle "creds 1-5 clear" or "creds 1 clear" - range/index clear
        if subcommand.isdigit() or '-' in subcommand:
            if len(args) < 2:
                self.display.print_error("Usage: creds <index|range> <clear|modify> [options]")
                return True

            action = args[1].lower()

            if action == "clear":
                # Parse index or range
                if '-' in subcommand:
                    try:
                        start, end = subcommand.split('-')
                        start_idx = int(start)
                        end_idx = int(end)
                        count = self.framework.session.credentials.remove_range(start_idx, end_idx)
                        self.display.print_success(f"Cleared {count} credential(s)")
                    except ValueError:
                        self.display.print_error("Invalid range format. Use: creds 1-5 clear")
                else:
                    try:
                        index = int(subcommand)
                        if self.framework.session.credentials.remove_by_index(index):
                            self.display.print_success(f"Cleared credential at index {index}")
                        else:
                            self.display.print_error(f"No credential at index {index}")
                    except ValueError:
                        self.display.print_error("Invalid index format")

            elif action == "modify":
                # Parse modify arguments: creds 1 modify username=admin password=newpass
                if len(args) < 3:
                    self.display.print_error("Usage: creds <index> modify <key=value> [key=value...]")
                    return True

                try:
                    index = int(subcommand)
                    modifications = {}
                    for arg in args[2:]:
                        if '=' in arg:
                            key, value = arg.split('=', 1)
                            modifications[key] = value

                    if modifications:
                        if self.framework.session.credentials.modify(index, **modifications):
                            self.display.print_success(f"Modified credential at index {index}")
                        else:
                            self.display.print_error(f"No credential at index {index}")
                    else:
                        self.display.print_error("No modifications specified")
                except ValueError:
                    self.display.print_error("Invalid index format")

            else:
                self.display.print_error(f"Unknown action: {action}")
                self.display.print_info("Available actions: clear, modify")

            return True

        # Original subcommands
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

            selected = self.interactive.select_credential(creds)

            # Handle "Add New Credential" option
            if selected == "ADD_NEW":
                self.display.print_info("\n[Add New Credential]")
                username = input("Username: ").strip()
                if not username:
                    self.display.print_warning("Username required")
                    return True

                password = input("Password: ").strip()
                domain = input("Domain (optional): ").strip() or None
                dcip = input("Domain Controller IP (optional): ").strip() or None
                dns = input("DNS Server (optional): ").strip() or None

                if self.framework.add_credential(username, password, domain, dcip, dns):
                    self.display.print_success(f"Added credential: {username}")

                    # Refresh creds list and auto-select the new credential
                    creds = self.framework.session.credentials.list()
                    if creds:
                        self.framework.session.credentials.current_index = len(creds) - 1
                        selected = creds[-1]
                    else:
                        return True
                else:
                    self.display.print_warning("Failed to add credential")
                    return True

            if selected and selected != "ADD_NEW":
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
                            if selected.get('dcip') and "DCIP" in module.options:
                                module.set_option("DCIP", selected['dcip'])
                                self.display.print_info(f"  → Set DCIP = {selected['dcip']}")
                            if selected.get('dns') and "DNS" in module.options:
                                module.set_option("DNS", selected['dns'])
                                self.display.print_info(f"  → Set DNS = {selected['dns']}")
                            if selected.get('hash') and "HASH" in module.options:
                                module.set_option("HASH", selected['hash'])
                                self.display.print_info(f"  → Set HASH = ****")
                        break
            elif not selected:
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

        elif subcommand == "modify":
            # Interactive credential modification
            creds = self.framework.session.credentials.list()
            if not creds:
                self.display.print_warning("No credentials available. Add credentials first with 'creds add'")
                return True

            # Select credential to modify
            self.display.print_info("Select credential to modify:")
            selected = self.interactive.select_credential(creds, allow_add_new=False)
            if not selected or selected == "ADD_NEW":
                self.display.print_warning("No credential selected")
                return True

            # Find the index by comparing username (more reliable than full dict comparison)
            index = None
            for i, cred in enumerate(creds):
                if (cred.get('username') == selected.get('username') and
                    cred.get('domain') == selected.get('domain')):
                    index = i
                    break

            if index is None:
                self.display.print_error("Could not find credential index")
                return True

            # Show current values
            self.display.print_info(f"\nModifying credential: {selected.get('username', 'N/A')}")
            self.display.print_info("Current values:")
            for key in ['username', 'password', 'domain', 'dcip', 'dns', 'hash']:
                val = selected.get(key)
                if key in ['password', 'hash'] and val:
                    self.display.print_info(f"  {key}: ****")
                else:
                    self.display.print_info(f"  {key}: {val or 'Not set'}")

            # Prompt for modifications
            self.display.print_info("\nEnter new values (press Enter to skip):")
            modifications = {}

            for field in ['username', 'password', 'domain', 'dcip', 'dns', 'hash']:
                new_val = input(f"{field.capitalize()}: ").strip()
                if new_val:
                    modifications[field] = new_val

            if modifications:
                if self.framework.session.credentials.modify(index, **modifications):
                    self.display.print_success(f"Modified credential")
                    for key, val in modifications.items():
                        if key in ['password', 'hash']:
                            self.display.print_info(f"  → Set {key} = ****")
                        else:
                            self.display.print_info(f"  → Set {key} = {val}")
                else:
                    self.display.print_error("Failed to modify credential")
            else:
                self.display.print_info("No modifications made")

        else:
            self.display.print_error(f"Unknown subcommand: {subcommand}")
            self.display.print_info("Usage: creds [list|add|set|select|modify|remove|clear|<index> clear|<range> clear|<index> modify]")

        return True

    def cmd_services(self, args: List[str]) -> bool:
        """View detected services."""
        # Check for 'clear' subcommand
        if args and args[0].lower() == "clear":
            # Clear from session
            count = self.framework.session.services.clear()

            # Clear from legacy database
            self.framework.database.clear_all_services()

            # Clear from models database (for dashboard sync)
            try:
                from purplesploit.models.database import db_manager
                db_manager.clear_all_services()
            except Exception as e:
                self.display.print_warning(f"Could not clear dashboard services: {e}")

            self.display.print_success(f"Cleared {count} service target(s) from session and databases")
            return True

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
            self.display.print_info("\nTip: Use 'services select' for interactive selection or 'services clear' to remove all")

        return True

    def cmd_wordlists(self, args: List[str]) -> bool:
        """Manage wordlists by category."""
        if not args or args[0] == "list":
            # Show all wordlists organized by category
            all_wordlists = self.framework.session.wordlists.list()
            self._display_wordlists(all_wordlists)
            self.display.print_info("\nCategories: web_dir, dns_vhost, username, password, subdomain, parameter, api, general")
            self.display.print_info("Usage: wordlists [list|add|remove|set|select] <category> [args]")
            return True

        subcommand = args[0].lower()

        if subcommand == "add":
            if len(args) < 3:
                self.display.print_error("Usage: wordlists add <category> <path> [name]")
                self.display.print_info("Categories: web_dir, dns_vhost, username, password, subdomain, parameter, api, general")
                return True

            category = args[1]
            path = args[2]
            name = args[3] if len(args) > 3 else None

            if self.framework.session.wordlists.add(category, path, name):
                self.display.print_success(f"Added wordlist to {category}: {path}")
            else:
                self.display.print_error(f"Failed to add wordlist (check path and category)")

        elif subcommand == "remove":
            if len(args) < 3:
                self.display.print_error("Usage: wordlists remove <category> <path|name>")
                return True

            category = args[1]
            identifier = args[2]

            if self.framework.session.wordlists.remove(category, identifier):
                self.display.print_success(f"Removed wordlist from {category}")
            else:
                self.display.print_error("Wordlist not found")

        elif subcommand == "set":
            if len(args) < 3:
                self.display.print_error("Usage: wordlists set <category> <path|name|index>")
                return True

            category = args[1]
            identifier = args[2]

            if self.framework.session.wordlists.set_current(category, identifier):
                wordlist = self.framework.session.wordlists.get_current(category)
                self.display.print_success(f"Current {category} wordlist set to: {wordlist['name']}")
            else:
                self.display.print_error("Wordlist not found")

        elif subcommand == "select":
            if len(args) < 2:
                self.display.print_error("Usage: wordlists select <category>")
                return True

            category = args[1]
            wordlists_dict = self.framework.session.wordlists.list(category)

            if not wordlists_dict or not wordlists_dict.get(category):
                self.display.print_warning(f"No wordlists available in {category}. Add wordlists first.")
                return True

            wordlists = wordlists_dict[category]
            selected = self.interactive.select_wordlist(category, wordlists)

            if selected:
                # Find index and set as current
                for i, wl in enumerate(wordlists):
                    if wl == selected:
                        self.framework.session.wordlists.current_selections[category] = i
                        self.display.print_success(f"Selected {category} wordlist: {selected['name']}")
                        break
            else:
                self.display.print_warning("No wordlist selected")

        else:
            self.display.print_error(f"Unknown subcommand: {subcommand}")
            self.display.print_info("Usage: wordlists [list|add|remove|set|select] <category> [args]")

        return True

    def _display_wordlists(self, wordlists_dict: Dict) -> None:
        """Display wordlists organized by category."""
        from rich.table import Table
        from rich import box

        for category, wordlists in wordlists_dict.items():
            if not wordlists:
                continue

            current_selection = self.framework.session.wordlists.current_selections.get(category)

            table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
            table.add_column("#", style="dim", width=4)
            table.add_column("Name", style="green")
            table.add_column("Path", style="white")
            table.add_column("Status", style="yellow", width=10)

            for i, wordlist in enumerate(wordlists):
                status = "[✓]" if i == current_selection else ""
                table.add_row(
                    str(i),
                    wordlist.get('name', 'Unknown'),
                    wordlist.get('path', ''),
                    status
                )

            self.display.console.print(f"\n[bold cyan]{category.upper()}[/bold cyan]")
            self.display.console.print(table)

    def cmd_analysis(self, args: List[str]) -> bool:
        """View analysis results (web scans, etc.) organized by target."""
        from rich.table import Table
        from rich.panel import Panel
        from rich import box

        # Get all scan results
        web_results = self.framework.database.get_scan_results(scan_type="web")

        if not web_results:
            self.display.print_warning("No web scan results available")
            self.display.print_info("Run web scans using modules like feroxbuster, wfuzz, or httpx first")
            return True

        # Group results by target
        results_by_target = {}
        for result in web_results:
            target = result['target']
            if target not in results_by_target:
                results_by_target[target] = []
            results_by_target[target].append(result)

        # Display results organized by target
        self.display.console.print("\n[bold cyan]═══ Web Scan Analysis Results ═══[/bold cyan]\n")

        for target, scans in results_by_target.items():
            # Create panel for each target
            target_info = f"[bold yellow]Target:[/bold yellow] {target}\n"
            target_info += f"[bold yellow]Total Scans:[/bold yellow] {len(scans)}\n\n"

            # Create table for this target's scans
            table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
            table.add_column("Scan Type", style="green", width=15)
            table.add_column("Timestamp", style="dim", width=20)
            table.add_column("Status", style="yellow", width=12)
            table.add_column("Findings", style="white")
            table.add_column("Log File", style="blue")

            for scan in scans:
                scan_name = scan['scan_name']
                timestamp = scan['created_at']
                results_data = scan['results']
                log_file = scan.get('file_path', 'N/A')

                # Determine status and findings
                if results_data.get('status') == 'running':
                    status = "[yellow]Running[/yellow]"
                    findings = f"PID: {results_data.get('pid', 'N/A')}"
                else:
                    status = "[green]Complete[/green]"
                    found_paths = results_data.get('found_paths', [])
                    interesting = results_data.get('interesting_finds', [])
                    findings = f"{len(found_paths)} paths ({len(interesting)} interesting)"

                # Truncate log file path for display
                if log_file != 'N/A':
                    import os
                    log_file = os.path.basename(log_file)

                table.add_row(
                    scan_name,
                    timestamp.split('.')[0] if '.' in timestamp else timestamp,
                    status,
                    findings,
                    log_file
                )

            # Show target panel
            panel = Panel(
                target_info + str(table),
                title=f"[bold white]{target}[/bold white]",
                border_style="cyan"
            )
            self.display.console.print(panel)
            self.display.console.print()

        # Show summary
        self.display.console.print(f"\n[bold green]Total Targets with Results:[/bold green] {len(results_by_target)}")
        self.display.console.print(f"[bold green]Total Scans:[/bold green] {len(web_results)}")
        self.display.print_info("\nTip: Check log files in ~/.purplesploit/logs/web/ for detailed results")

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

    def cmd_ligolo(self, args: List[str]) -> bool:
        """
        Launch or attach to ligolo-ng proxy interface (shell command passthrough).

        Usage:
            ligolo                    # Launch ligolo-ng with default settings (-selfcert)
            ligolo --help             # Show ligolo-ng help
            ligolo -selfcert -laddr 0.0.0.0:11601  # Custom proxy settings
            ligolo kill               # Kill existing ligolo-ng session

        The ligolo command runs ligolo-ng directly in a tmux session.
        All arguments are passed through to the ligolo-ng binary.

        Note: This is different from the 'c2/ligolo_pivot' module which is for
              automated agent deployment. Use this command for interactive proxy control.

        Press CTRL+B then D to detach from session (keeps it running).
        """
        import subprocess
        import os
        import shutil

        # Special commands
        if args and args[0] == "kill":
            # Kill existing ligolo session
            result = subprocess.run(
                ["tmux", "kill-session", "-t", "ligolo"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                self.display.print_success("Killed ligolo-ng session")
            else:
                self.display.print_warning("No ligolo-ng session to kill")
            return True

        # Check if tmux is installed
        if not shutil.which("tmux"):
            self.display.print_error("tmux not found in PATH")
            self.display.print_info("Install tmux: apt install tmux / brew install tmux")
            return True

        # Check if ligolo-ng is installed
        ligolo_cmd = None
        for cmd in ["ligolo-ng", "ligolo", "ligolo-proxy"]:
            if shutil.which(cmd):
                ligolo_cmd = cmd
                break

        if not ligolo_cmd:
            self.display.print_error("ligolo-ng not found in PATH")
            self.display.print_info("Install ligolo-ng:")
            self.display.print_info("  Download: https://github.com/nicocha30/ligolo-ng/releases")
            self.display.print_info("  Or build: go install github.com/nicocha30/ligolo-ng/cmd/proxy@latest")
            return True

        try:
            # Check if ligolo tmux session already exists
            check_session = subprocess.run(
                ["tmux", "has-session", "-t", "ligolo"],
                capture_output=True,
                text=True
            )

            if check_session.returncode == 0:
                # Session exists, attach to it
                self.display.print_info("Attaching to existing ligolo-ng session...")
                self.display.print_info("Press CTRL+B then D to detach (keeps session running)")
                self.display.console.print()
                os.system("tmux attach-session -t ligolo")
            else:
                # Create new session
                self.display.print_info("Creating new ligolo-ng session...")
                self.display.print_info("Press CTRL+B then D to detach (keeps session running)")
                self.display.console.print()

                # Build command with args if provided
                # Default to -selfcert if no args provided
                if args:
                    cmd_args = [ligolo_cmd] + args
                else:
                    cmd_args = [ligolo_cmd, "-selfcert"]

                # Create tmux session and run ligolo
                cmd_str = " ".join(cmd_args)
                os.system(f"tmux new-session -s ligolo '{cmd_str}'")

            # User returned (via detach or exit)
            self.display.console.print()
            self.display.print_success("Returned to PurpleSploit")

        except KeyboardInterrupt:
            self.display.console.print()
            self.display.print_info("Returned to PurpleSploit")
        except Exception as e:
            self.display.print_error(f"Error with ligolo-ng: {e}")
            import traceback
            traceback.print_exc()

        return True

    def cmd_shell(self, args: List[str]) -> bool:
        """
        Drop to localhost shell.

        Usage:
            shell                     # Launch bash shell
            shell [command]           # Execute command in shell

        Press CTRL+D to return to PurpleSploit.
        """
        import subprocess
        import os

        try:
            if args:
                # Execute single command
                cmd = " ".join(args)
                self.display.print_info(f"Executing: {cmd}")
                result = subprocess.run(cmd, shell=True)
                return True
            else:
                # Launch interactive shell
                self.display.print_info("Dropping to localhost shell...")
                self.display.print_info("Press CTRL+D (EOF) to return to PurpleSploit")
                self.display.console.print()

                # Get user's shell or default to bash
                user_shell = os.environ.get('SHELL', '/bin/bash')

                # Launch shell with full terminal control
                os.system(user_shell)

                # User returned (via CTRL+D or exit)
                self.display.console.print()
                self.display.print_success("Returned to PurpleSploit")

        except KeyboardInterrupt:
            self.display.console.print()
            self.display.print_info("Shell interrupted, returning to PurpleSploit")
        except Exception as e:
            self.display.print_error(f"Error launching shell: {e}")
            import traceback
            traceback.print_exc()

        return True

    def cmd_deploy(self, args: List[str]) -> bool:
        """
        Deploy payloads, pivots, and tools to target systems.

        Usage:
            deploy                      # Show available deployment modules
            deploy ligolo               # Load Ligolo pivot deployment module
            deploy c2                   # Load C2 beacon deployment module
            deploy script               # Load script deployment module

        Examples:
            deploy                      # Show all deployment modules
            deploy ligolo               # Load deploy/ligolo module
            deploy c2                   # Load deploy/c2 module
        """
        # Module path mapping
        module_map = {
            "ligolo": "deploy/ligolo",
            "c2": "deploy/c2",
            "beacon": "deploy/c2",  # Alias
            "script": "deploy/script",
            "scripts": "deploy/script"  # Alias
        }

        # If no args, show available modules
        if not args:
            self._display_deploy_modules()
            return True

        subcommand = args[0].lower()

        # Check if it's a known module
        if subcommand in module_map:
            module_path = module_map[subcommand]

            # Check if module exists
            if module_path not in self.framework.modules:
                self.display.print_error(f"Deploy module not found: {module_path}")
                self.display.print_info("Run 'deploy' to see available modules")
                return True

            # Load the module
            self.display.print_info(f"Loading {module_path}...")
            return self.cmd_use([module_path])

        else:
            self.display.print_error(f"Unknown deploy subcommand: {subcommand}")
            self.display.print_info("Usage: deploy [ligolo|c2|script]")
            return True

    def _display_deploy_modules(self):
        """Display available deployment modules."""
        self.display.console.print()
        self.display.console.print("[bold cyan]═══ Deploy Modules ═══[/bold cyan]")
        self.display.console.print()

        # Define modules
        modules = [
            {
                "name": "deploy/ligolo",
                "command": "deploy ligolo",
                "description": "Deploy ligolo-ng agents for network pivoting",
                "methods": "NXC, SSH, SMB, PSExec, WMIExec"
            },
            {
                "name": "deploy/c2",
                "command": "deploy c2",
                "description": "Deploy C2 beacons and payloads to targets",
                "methods": "NXC, SSH, SMB, PSExec, WMIExec, WinRM"
            },
            {
                "name": "deploy/script",
                "command": "deploy script",
                "description": "Deploy enumeration scripts (WinPEAS, LinPEAS, custom)",
                "methods": "NXC, SSH, SMB, PSExec"
            }
        ]

        # Display each module
        for idx, module in enumerate(modules, 1):
            self.display.console.print(f"[bold green]{idx}. {module['name']}[/bold green]")
            self.display.console.print(f"   [cyan]Command:[/cyan] {module['command']}")
            self.display.console.print(f"   [dim]{module['description']}[/dim]")
            self.display.console.print(f"   [yellow]Methods:[/yellow] {module['methods']}")
            self.display.console.print()

        # Display helpful tips
        self.display.print_info("Tip: Use 'deploy <type>' to load a deployment module")
        self.display.print_info("     Then use 'options' to set targets and credentials")
        self.display.print_info("     Use 'run' or 'operations' to see available operations")

    def cmd_webserver(self, args: List[str]) -> bool:
        """
        Manage the PurpleSploit web portal and API server.

        Usage:
            webserver start              # Start the web server in background (default)
            webserver start --port 8080  # Start on custom port
            webserver stop               # Stop the running web server
            webserver status             # Check web server status

        The server runs in the background so you can continue using PurpleSploit.
        """
        import multiprocessing
        import time
        from pathlib import Path

        # Default action is start
        action = args[0].lower() if args else "start"

        if action == "start":
            # Check if already running
            if self.webserver_process and self.webserver_process.is_alive():
                self.display.print_warning("Web server is already running")
                self.display.print_info("Use 'webserver stop' to stop it first")
                return True

            # Parse additional arguments
            port = 5000
            host = "0.0.0.0"

            # Parse flags
            i = 1
            while i < len(args):
                if args[i] == "--port" and i + 1 < len(args):
                    try:
                        port = int(args[i + 1])
                        i += 1
                    except ValueError:
                        self.display.print_error(f"Invalid port number: {args[i + 1]}")
                        return True
                elif args[i] == "--host" and i + 1 < len(args):
                    host = args[i + 1]
                    i += 1
                i += 1

            try:
                # Check if dependencies are available
                try:
                    import uvicorn
                    import fastapi
                except ImportError as e:
                    self.display.print_error(f"Missing dependencies: {e}")
                    self.display.print_info("Install with: pip install fastapi uvicorn")
                    return True

                # Create and start background process
                self.display.console.print()
                self.display.console.print("[bold magenta]" + "=" * 70 + "[/bold magenta]")
                self.display.console.print("[bold cyan]       🔮 Starting PurpleSploit Web Portal & API Server[/bold cyan]")
                self.display.console.print("[bold magenta]" + "=" * 70 + "[/bold magenta]")
                self.display.console.print()

                # Start server in background process
                def run_server():
                    """Background server process"""
                    import sys
                    import os
                    import uvicorn

                    # Redirect stdout/stderr to suppress request logging
                    # This prevents HTTP requests from cluttering the CLI
                    sys.stdout = open(os.devnull, 'w')
                    sys.stderr = open(os.devnull, 'w')

                    # Run with error-only logging to suppress HTTP request logs
                    uvicorn.run(
                        "purplesploit.api.server:app",
                        host=host,
                        port=port,
                        reload=False,
                        log_level="error",  # Only show errors, not every HTTP request
                        access_log=False    # Disable access logging
                    )

                # Create and start the process
                self.webserver_process = multiprocessing.Process(
                    target=run_server,
                    daemon=True,
                    name="purplesploit-webserver"
                )
                self.webserver_process.start()

                # Give it a moment to start
                time.sleep(1.5)

                # Check if it started successfully
                if self.webserver_process.is_alive():
                    self.display.console.print(f"[green]✓ Server started successfully on {host}:{port}[/green]")
                    self.display.console.print()
                    self.display.console.print(f"[cyan]Web Portal:[/cyan] http://localhost:{port}")
                    self.display.console.print(f"[cyan]API Docs:  [/cyan] http://localhost:{port}/api/docs")
                    self.display.console.print()
                    self.display.console.print("[dim]Server is running in the background[/dim]")
                    self.display.console.print("[dim]Use 'webserver stop' to stop the server[/dim]")
                    self.display.console.print("[dim]Use 'webserver status' to check server status[/dim]")
                else:
                    self.display.print_error("Failed to start web server")
                    self.webserver_process = None

                self.display.console.print("[bold magenta]" + "=" * 70 + "[/bold magenta]")
                self.display.console.print()

            except Exception as e:
                self.display.print_error(f"Error starting web server: {e}")
                import traceback
                traceback.print_exc()
                self.webserver_process = None
                return True

        elif action == "stop":
            if not self.webserver_process or not self.webserver_process.is_alive():
                self.display.print_warning("Web server is not running")
                return True

            self.display.print_info("Stopping web server...")
            self.webserver_process.terminate()
            self.webserver_process.join(timeout=5)

            if self.webserver_process.is_alive():
                self.display.print_warning("Server didn't stop gracefully, forcing shutdown...")
                self.webserver_process.kill()
                self.webserver_process.join()

            self.webserver_process = None
            self.display.print_success("Web server stopped")

        elif action == "status":
            if self.webserver_process and self.webserver_process.is_alive():
                self.display.print_success(f"Web server is running (PID: {self.webserver_process.pid})")
                self.display.print_info("Access at: http://localhost:5000")
                self.display.print_info("API docs: http://localhost:5000/api/docs")
            else:
                self.display.print_info("Web server is not running")
                self.display.print_info("Use 'webserver start' to start it")

        else:
            self.display.print_error(f"Unknown webserver command: {action}")
            self.display.print_info("Usage: webserver [start|stop|status] [--port PORT] [--host HOST]")

        return True

    def cmd_hosts(self, args: List[str]) -> bool:
        """
        Generate /etc/hosts file entries from session targets.

        Usage:
            hosts                    # Show hosts entries
            hosts export <file>      # Export to file
            hosts append <file>      # Append to file
            hosts sudo               # Append to /etc/hosts (requires sudo)
        """
        if not args:
            # Just display the hosts entries
            targets = self.framework.session.targets.list()

            if not targets:
                self.display.print_warning("No targets configured")
                self.display.print_info("Add targets with 'targets add <ip> [hostname]'")
                return True

            # Generate hosts entries
            entries = []
            for target in targets:
                ip = target.get('ip')
                name = target.get('name')

                if ip:
                    if name:
                        entries.append(f"{ip}\t{name}")
                    else:
                        # Generate a default name from IP
                        hostname = f"target-{ip.replace('.', '-')}"
                        entries.append(f"{ip}\t{hostname}")

            if entries:
                self.display.console.print("\n[bold cyan]Generated /etc/hosts entries:[/bold cyan]\n")
                for entry in entries:
                    self.display.console.print(f"  {entry}")
                self.display.console.print()

                self.display.print_info("Commands:")
                self.display.print_info("  hosts export <file>      # Export to file")
                self.display.print_info("  hosts append <file>      # Append to existing file")
                self.display.print_info("  hosts sudo               # Append to /etc/hosts (requires sudo)")
            else:
                self.display.print_warning("No valid targets with IP addresses found")

            return True

        subcommand = args[0].lower()

        if subcommand == "export":
            if len(args) < 2:
                self.display.print_error("Usage: hosts export <file>")
                return True

            output_file = args[1]
            targets = self.framework.session.targets.list()

            if not targets:
                self.display.print_warning("No targets configured")
                return True

            # Generate entries
            entries = []
            for target in targets:
                ip = target.get('ip')
                name = target.get('name')

                if ip:
                    if name:
                        entries.append(f"{ip}\t{name}")
                    else:
                        hostname = f"target-{ip.replace('.', '-')}"
                        entries.append(f"{ip}\t{hostname}")

            if entries:
                try:
                    with open(output_file, 'w') as f:
                        f.write("# PurpleSploit generated hosts file\n")
                        f.write("# Generated from session targets\n\n")
                        for entry in entries:
                            f.write(entry + "\n")

                    self.display.print_success(f"Hosts file exported to: {output_file}")
                    self.display.print_info(f"Entries: {len(entries)}")
                except Exception as e:
                    self.display.print_error(f"Failed to export hosts file: {e}")
            else:
                self.display.print_warning("No valid targets with IP addresses found")

        elif subcommand == "append":
            if len(args) < 2:
                self.display.print_error("Usage: hosts append <file>")
                return True

            output_file = args[1]
            targets = self.framework.session.targets.list()

            if not targets:
                self.display.print_warning("No targets configured")
                return True

            # Generate entries
            entries = []
            for target in targets:
                ip = target.get('ip')
                name = target.get('name')

                if ip:
                    if name:
                        entries.append(f"{ip}\t{name}")
                    else:
                        hostname = f"target-{ip.replace('.', '-')}"
                        entries.append(f"{ip}\t{hostname}")

            if entries:
                try:
                    with open(output_file, 'a') as f:
                        f.write("\n# PurpleSploit generated entries\n")
                        for entry in entries:
                            f.write(entry + "\n")

                    self.display.print_success(f"Hosts entries appended to: {output_file}")
                    self.display.print_info(f"Entries: {len(entries)}")
                except Exception as e:
                    self.display.print_error(f"Failed to append hosts file: {e}")
            else:
                self.display.print_warning("No valid targets with IP addresses found")

        elif subcommand == "sudo":
            # Append to /etc/hosts with sudo
            targets = self.framework.session.targets.list()

            if not targets:
                self.display.print_warning("No targets configured")
                return True

            # Generate entries
            entries = []
            for target in targets:
                ip = target.get('ip')
                name = target.get('name')

                if ip:
                    if name:
                        entries.append(f"{ip}\t{name}")
                    else:
                        hostname = f"target-{ip.replace('.', '-')}"
                        entries.append(f"{ip}\t{hostname}")

            if entries:
                self.display.print_warning("This will modify /etc/hosts and requires sudo privileges")
                confirm = input("Continue? (y/n): ")

                if confirm.lower() != 'y':
                    self.display.print_info("Operation cancelled")
                    return True

                try:
                    import tempfile
                    import subprocess

                    # Create temporary file with entries
                    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.hosts') as tmp:
                        tmp.write("\n# PurpleSploit generated entries\n")
                        for entry in entries:
                            tmp.write(entry + "\n")
                        tmp_path = tmp.name

                    # Append to /etc/hosts using sudo and tee
                    cmd = f"sudo bash -c 'cat {tmp_path} >> /etc/hosts'"
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

                    # Clean up temp file
                    import os
                    os.unlink(tmp_path)

                    if result.returncode == 0:
                        self.display.print_success("Hosts entries appended to /etc/hosts")
                        self.display.print_info(f"Entries: {len(entries)}")
                    else:
                        self.display.print_error(f"Failed to append to /etc/hosts: {result.stderr}")
                except Exception as e:
                    self.display.print_error(f"Failed to append to /etc/hosts: {e}")
            else:
                self.display.print_warning("No valid targets with IP addresses found")

        else:
            self.display.print_error(f"Unknown subcommand: {subcommand}")
            self.display.print_info("Usage: hosts [export|append|sudo] [file]")

        return True

    def cmd_defaults(self, args: List[str]) -> bool:
        """Manage module default option values."""
        from rich.table import Table

        if not args:
            self.display.print_error("Usage: defaults <command> [args]")
            self.display.print_info("Commands:")
            self.display.print_info("  defaults show <module>           - Show default values for a module")
            self.display.print_info("  defaults set <module> <opt> <val> - Set a default value")
            self.display.print_info("  defaults delete <module> <opt>   - Delete a default value")
            self.display.print_info("  defaults reset <module>          - Reset all defaults for a module")
            self.display.print_info("")
            self.display.print_info("Examples:")
            self.display.print_info("  defaults show nmap")
            self.display.print_info("  defaults set nmap PORTS -")
            self.display.print_info("  defaults set nmap MIN_RATE 3900")
            self.display.print_info("  defaults delete nmap PORTS")
            self.display.print_info("  defaults reset nmap")
            return True

        subcommand = args[0].lower()

        # Show defaults for a module
        if subcommand == "show":
            if len(args) < 2:
                self.display.print_error("Usage: defaults show <module>")
                self.display.print_info("Example: defaults show nmap")
                return True

            module_name = args[1].lower()
            defaults = self.framework.database.get_module_defaults(module_name)

            if not defaults:
                self.display.print_warning(f"No custom defaults found for module '{module_name}'")
                self.display.print_info("Defaults are set using: defaults set <module> <option> <value>")
                return True

            # Display defaults in a table
            table = Table(title=f"Default Values for '{module_name}'")
            table.add_column("Option", style="cyan")
            table.add_column("Default Value", style="green")

            for option, value in sorted(defaults.items()):
                table.add_row(option, str(value))

            self.display.console.print(table)
            self.display.print_info(f"Total: {len(defaults)} custom defaults")

        # Set a default value
        elif subcommand == "set":
            if len(args) < 4:
                self.display.print_error("Usage: defaults set <module> <option> <value>")
                self.display.print_info("Example: defaults set nmap PORTS -")
                return True

            module_name = args[1].lower()
            option_name = args[2].upper()
            option_value = " ".join(args[3:])  # Allow values with spaces

            success = self.framework.database.set_module_default(
                module_name, option_name, option_value
            )

            if success:
                self.display.print_success(
                    f"Set default for {module_name}.{option_name} = {option_value}"
                )
                self.display.print_info("This default will be applied when the module is loaded")
            else:
                self.display.print_error("Failed to set default value")

        # Delete a default value
        elif subcommand == "delete":
            if len(args) < 3:
                self.display.print_error("Usage: defaults delete <module> <option>")
                self.display.print_info("Example: defaults delete nmap PORTS")
                return True

            module_name = args[1].lower()
            option_name = args[2].upper()

            success = self.framework.database.delete_module_default(module_name, option_name)

            if success:
                self.display.print_success(
                    f"Deleted default for {module_name}.{option_name}"
                )
            else:
                self.display.print_warning(
                    f"No default found for {module_name}.{option_name}"
                )

        # Reset all defaults for a module
        elif subcommand == "reset":
            if len(args) < 2:
                self.display.print_error("Usage: defaults reset <module>")
                self.display.print_info("Example: defaults reset nmap")
                return True

            module_name = args[1].lower()

            # Confirm reset
            self.display.print_warning(
                f"This will delete all custom defaults for '{module_name}'"
            )
            confirm = input("Continue? [y/N]: ")

            if confirm.lower() == 'y':
                success = self.framework.database.delete_all_module_defaults(module_name)

                if success:
                    self.display.print_success(f"Reset all defaults for '{module_name}'")
                else:
                    self.display.print_warning(f"No defaults found for '{module_name}'")
            else:
                self.display.print_info("Operation cancelled")

        else:
            self.display.print_error(f"Unknown subcommand: {subcommand}")
            self.display.print_info("Use: defaults <show|set|delete|reset>")

        return True

    def cmd_parse(self, args: List[str]) -> bool:
        """Parse nmap XML results and import to targets/services."""
        if not args:
            self.display.print_error("Usage: parse <nmap_xml_file>")
            self.display.print_info("Example: parse nmap_192.168.1.0_24.xml")
            return True

        xml_file = args[0]

        if not Path(xml_file).exists():
            self.display.print_error(f"File not found: {xml_file}")
            return True

        try:
            # Import the nmap module to use its parsing functionality
            from purplesploit.modules.recon.nmap import NmapModule

            # Create temporary nmap module instance
            nmap_module = NmapModule(self.framework)

            # Parse XML
            self.display.print_info(f"Parsing {xml_file}...")
            parsed_xml = nmap_module.parse_xml_output(xml_file)

            if not parsed_xml.get("hosts"):
                self.display.print_warning("No hosts with open ports found in scan results")
                return True

            # Process discovered hosts
            nmap_module.process_discovered_hosts(parsed_xml)

            # Display summary
            hosts_discovered = len(parsed_xml.get("hosts", []))
            total_scanned = parsed_xml.get("total_hosts", 0)

            self.display.print_success(f"Successfully imported {hosts_discovered} hosts with open ports (out of {total_scanned} total)")
            self.display.print_info("Run 'targets' to see all discovered targets")
            self.display.print_info("Run 'services' to see all discovered services")

        except Exception as e:
            self.display.print_error(f"Error parsing XML file: {e}")
            import traceback
            traceback.print_exc()

        return True

    def cmd_exit(self, args: List[str]) -> bool:
        """Exit the framework."""
        self.display.print_info("Exiting PurpleSploit...")
        # Clean up webserver if running
        self.cleanup()
        return False

    def cleanup(self):
        """Cleanup resources before exit."""
        # Stop webserver if running
        if self.webserver_process and self.webserver_process.is_alive():
            self.display.print_info("Stopping web server...")
            self.webserver_process.terminate()
            self.webserver_process.join(timeout=3)
            if self.webserver_process.is_alive():
                self.webserver_process.kill()


    def cmd_ops(self, args: List[str]) -> bool:
        """
        Context-aware operations command.
        - When in a module with no args: Show operations (or options if no operations)
        - When given args: Search operations globally across all modules
        """
        if not args:
            # If in a module, show operations or options
            module = self.framework.session.current_module
            if module:
                # Check if module has operations
                if module.has_operations():
                    return self.cmd_show_ops([])
                else:
                    # Module has no operations, show options instead
                    self.display.print_info(f"\n{module.name} Options:")
                    return self.cmd_options([])
            else:
                self.display.print_error("Usage: ops <query>")
                self.display.print_info("       ops select  # Interactive operation selection from last search")
                self.display.print_info("Example: ops authentication")
                self.display.print_info("\nTip: Load a module first to use 'ops' to see its operations")
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
            # Store results for selection and run command
            self.last_ops_results = results

            # Group results by module for better organization
            from collections import defaultdict
            grouped = defaultdict(list)

            # Track global index for numbering
            result_index_map = {}
            for idx, result in enumerate(results):
                module_key = result['module_path']
                grouped[module_key].append(result)
                result_index_map[id(result)] = idx

            # Display grouped results
            self.display.console.print(f"\n[bold cyan]Found {len(results)} operations across {len(grouped)} modules matching '{query}':[/bold cyan]\n")

            for module_path in sorted(grouped.keys()):
                ops_list = grouped[module_path]
                mod_name = ops_list[0]['module']  # All ops in group have same module name

                # Module header
                self.display.console.print(f"[bold green]▸ {mod_name}[/bold green] [dim]({module_path})[/dim]")

                # List operations under this module with global numbering
                for result in ops_list:
                    global_idx = results.index(result) + 1
                    op_name = result['operation']
                    op_desc = result['description']

                    self.display.console.print(f"  [cyan]{global_idx}.[/cyan] {op_name}")
                    self.display.console.print(f"     [dim]{op_desc}[/dim]")

                self.display.console.print()  # Blank line between modules

            self.display.print_info("Tip: Use 'run <number>' to execute directly, 'use <number>' to load the parent module, or 'ops select' for interactive selection")
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
                            # Tokenize underscores and slashes for better keyword matching
                            mod_path_tokenized = mod_path.replace('/', ' ').replace('_', ' ')
                            name_tokenized = metadata.name.replace('/', ' ').replace('_', ' ')

                            searchable_text = ' '.join([
                                mod_path,                    # e.g., "network/nxc_smb"
                                mod_path_tokenized,          # e.g., "network nxc smb"
                                metadata.name,               # e.g., "NetExec SMB"
                                name_tokenized,              # e.g., "NetExec SMB"
                                metadata.category,           # e.g., "network"
                                op.get('subcategory', ''),   # e.g., "authentication"
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
        Display operations menu in a formatted table, grouped by subcategory if available.

        Args:
            operations: List of operation dictionaries
        """
        from rich.table import Table
        from rich import box
        from collections import defaultdict

        # Check if operations have subcategories
        has_subcategories = any(op.get('subcategory') for op in operations)

        if has_subcategories:
            # Group operations by subcategory
            grouped = defaultdict(list)
            for i, op in enumerate(operations, 1):
                subcategory = op.get('subcategory', 'Other')
                grouped[subcategory].append((i, op))

            # Display grouped operations
            for subcategory in sorted(grouped.keys()):
                self.display.console.print(f"\n[bold yellow]═══ {subcategory.upper()} ═══[/bold yellow]")

                table = Table(box=box.SIMPLE, show_header=False, show_edge=False, pad_edge=False)
                table.add_column("#", style="dim", width=4)
                table.add_column("Operation", style="green")
                table.add_column("Description", style="white")

                for idx, op in grouped[subcategory]:
                    table.add_row(
                        str(idx),
                        op.get('name', 'Unknown'),
                        op.get('description', 'No description')
                    )

                self.display.console.print(table)
        else:
            # Original flat display
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
