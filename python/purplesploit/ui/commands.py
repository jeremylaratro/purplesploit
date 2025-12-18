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

            # Phase 2: Findings & Workflow commands
            "findings": self.cmd_findings,        # Manage security findings
            "finding": self.cmd_findings,         # Alias
            "workflow": self.cmd_workflow,        # Workflow automation
            "report": self.cmd_report,            # Generate reports

            # Phase 3: Plugin marketplace
            "plugin": self.cmd_plugin,            # Plugin management
            "plugins": self.cmd_plugin,           # Alias

            # Advanced: Smart Auto-Enumeration
            "auto": self.cmd_auto,                # Smart auto-enumeration
            "autoenum": self.cmd_auto,            # Alias

            # Advanced: Attack Graph Visualization
            "graph": self.cmd_graph,              # Attack graph management
            "attackgraph": self.cmd_graph,        # Alias

            # Advanced: Credential Spray Intelligence
            "spray": self.cmd_spray,              # Smart credential spraying
            "credspray": self.cmd_spray,          # Alias

            # Advanced: Session/Shell Management
            "sessions": self.cmd_sessions,        # Session management
            "session": self.cmd_sessions,         # Alias
            "interact": self.cmd_interact,        # Interact with session

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

            # Check if this will be the first target
            was_empty = len(self.framework.session.targets.list()) == 0

            if self.framework.add_target(target_type, identifier, name):
                self.display.print_success(f"Added target: {identifier}")

                # If this was the first target, auto-select it and apply to current module
                if was_empty:
                    target = self.framework.session.targets.get_current()
                    if target:
                        self.display.print_info(f"Auto-selected first target: {identifier}")

                        # Auto-set in current module if loaded
                        module = self.framework.session.current_module
                        if module:
                            target_value = target.get('ip') or target.get('url')

                            # Set RHOST for network targets
                            if 'ip' in target and "RHOST" in module.options:
                                module.set_option("RHOST", target['ip'])
                                self.display.print_info(f"  → Set RHOST = {target['ip']}")

                            # Set TARGET option (used by modules like auto_enum)
                            if target_value and "TARGET" in module.options:
                                module.set_option("TARGET", target_value)
                                self.display.print_info(f"  → Set TARGET = {target_value}")

                            # Set URL for web targets
                            if 'url' in target and "URL" in module.options:
                                module.set_option("URL", target['url'])
                                self.display.print_info(f"  → Set URL = {target['url']}")
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
                            target_value = selected.get('ip') or selected.get('url')

                            # Set RHOST for network targets
                            if 'ip' in selected and "RHOST" in module.options:
                                module.set_option("RHOST", selected['ip'])
                                self.display.print_info(f"  → Set RHOST = {selected['ip']}")

                            # Set TARGET option (used by modules like auto_enum)
                            if target_value and "TARGET" in module.options:
                                module.set_option("TARGET", target_value)
                                self.display.print_info(f"  → Set TARGET = {target_value}")

                            # Set URL for web targets
                            if 'url' in selected and "URL" in module.options:
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

                # Auto-set in current module if loaded
                module = self.framework.session.current_module
                if module:
                    target_value = target.get('ip') or target.get('url')

                    # Set RHOST for network targets
                    if 'ip' in target and "RHOST" in module.options:
                        module.set_option("RHOST", target['ip'])
                        self.display.print_info(f"  → Set RHOST = {target['ip']}")

                    # Set TARGET option (used by modules like auto_enum)
                    if target_value and "TARGET" in module.options:
                        module.set_option("TARGET", target_value)
                        self.display.print_info(f"  → Set TARGET = {target_value}")

                    # Set URL for web targets
                    if 'url' in target and "URL" in module.options:
                        module.set_option("URL", target['url'])
                        self.display.print_info(f"  → Set URL = {target['url']}")
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
            # Clear search results so 'use <number>' uses ops results
            self.last_search_results = None

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

        # Also set RHOST/URL/TARGET in current module if loaded
        module = self.framework.session.current_module
        if module:
            # Set RHOST for network targets
            if target_type == "network" and "RHOST" in module.options:
                module.set_option("RHOST", identifier)
                self.display.print_info(f"  → Set RHOST = {identifier}")

            # Set TARGET option (used by modules like auto_enum)
            if "TARGET" in module.options:
                module.set_option("TARGET", identifier)
                self.display.print_info(f"  → Set TARGET = {identifier}")

            # Set URL for web targets
            if target_type == "web" and "URL" in module.options:
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

    # =========================================================================
    # Phase 2: Findings Management Commands
    # =========================================================================

    def cmd_findings(self, args: List[str]) -> bool:
        """
        Manage security findings.

        Usage:
            findings                    - List all findings
            findings list               - List all findings
            findings list --severity X  - Filter by severity
            findings add <title>        - Add new finding (interactive)
            findings show <id>          - Show finding details
            findings update <id> <status> - Update finding status
            findings evidence <id> <file> - Add evidence to finding
            findings export <format> [path] - Export findings
            findings stats              - Show findings statistics
            findings clear              - Clear all findings
        """
        from purplesploit.core.findings import FindingsManager, FindingStatus, Severity

        # Get or create findings manager
        if not hasattr(self, '_findings_manager'):
            self._findings_manager = FindingsManager(framework=self.framework)

        if not args:
            args = ["list"]

        subcommand = args[0].lower()

        if subcommand == "list":
            return self._findings_list(args[1:])
        elif subcommand == "add":
            return self._findings_add(args[1:])
        elif subcommand == "show":
            return self._findings_show(args[1:])
        elif subcommand == "update":
            return self._findings_update(args[1:])
        elif subcommand == "evidence":
            return self._findings_evidence(args[1:])
        elif subcommand == "export":
            return self._findings_export(args[1:])
        elif subcommand == "stats":
            return self._findings_stats()
        elif subcommand == "clear":
            return self._findings_clear()
        else:
            self.display.print_error(f"Unknown subcommand: {subcommand}")
            self.display.print_info("Usage: findings [list|add|show|update|evidence|export|stats|clear]")
            return True

    def _findings_list(self, args: List[str]) -> bool:
        """List findings with optional filters."""
        from purplesploit.core.findings import FindingStatus, Severity
        from rich.table import Table

        findings = self._findings_manager.list_findings()

        if not findings:
            self.display.print_warning("No findings recorded yet")
            self.display.print_info("Use 'findings add <title>' to create a finding")
            return True

        table = Table(title="Security Findings")
        table.add_column("ID", style="cyan")
        table.add_column("Title", style="white")
        table.add_column("Severity", style="bold")
        table.add_column("Target", style="green")
        table.add_column("Status", style="yellow")
        table.add_column("CVSS", style="magenta")

        severity_colors = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "green",
            Severity.INFO: "blue",
        }

        for finding in findings:
            sev_color = severity_colors.get(finding.severity, "white")
            cvss = f"{finding.cvss_score:.1f}" if finding.cvss_score else "-"

            table.add_row(
                finding.id,
                finding.title[:40] + "..." if len(finding.title) > 40 else finding.title,
                f"[{sev_color}]{finding.severity.value.upper()}[/{sev_color}]",
                finding.target,
                finding.status.value,
                cvss,
            )

        self.display.console.print(table)
        return True

    def _findings_add(self, args: List[str]) -> bool:
        """Add a new finding (interactive)."""
        from purplesploit.core.findings import Severity

        if not args:
            self.display.print_error("Usage: findings add <title>")
            return True

        title = " ".join(args)

        # Interactive prompts
        self.display.print_info(f"Creating finding: {title}")

        # Get severity
        severity_options = ["critical", "high", "medium", "low", "info"]
        self.display.console.print("\nSeverity levels: critical, high, medium, low, info")
        try:
            severity_input = input("Severity [medium]: ").strip().lower() or "medium"
            if severity_input not in severity_options:
                self.display.print_warning(f"Invalid severity, using 'medium'")
                severity_input = "medium"
        except (EOFError, KeyboardInterrupt):
            self.display.print_warning("\nCancelled")
            return True

        # Get target
        current_target = self.framework.session.targets.current
        default_target = current_target.identifier if current_target else ""
        try:
            target = input(f"Target [{default_target}]: ").strip() or default_target
        except (EOFError, KeyboardInterrupt):
            self.display.print_warning("\nCancelled")
            return True

        # Get description
        try:
            description = input("Description: ").strip()
        except (EOFError, KeyboardInterrupt):
            self.display.print_warning("\nCancelled")
            return True

        # Create finding
        finding = self._findings_manager.create(
            title=title,
            severity=severity_input,
            description=description,
            target=target,
        )

        self.display.print_success(f"Created finding: {finding.id}")
        return True

    def _findings_show(self, args: List[str]) -> bool:
        """Show finding details."""
        if not args:
            self.display.print_error("Usage: findings show <id>")
            return True

        finding_id = args[0]
        finding = self._findings_manager.get(finding_id)

        if not finding:
            self.display.print_error(f"Finding not found: {finding_id}")
            return True

        self.display.console.print(f"\n[bold cyan]Finding: {finding.title}[/bold cyan]")
        self.display.console.print(f"ID: {finding.id}")
        self.display.console.print(f"Severity: {finding.severity.value.upper()}")
        self.display.console.print(f"Status: {finding.status.value}")
        self.display.console.print(f"Target: {finding.target}")

        if finding.cvss_score:
            self.display.console.print(f"CVSS: {finding.cvss_score}")
        if finding.cvss_vector:
            self.display.console.print(f"Vector: {finding.cvss_vector}")
        if finding.cve_ids:
            self.display.console.print(f"CVEs: {', '.join(finding.cve_ids)}")

        self.display.console.print(f"\n[bold]Description:[/bold]\n{finding.description}")

        if finding.impact:
            self.display.console.print(f"\n[bold]Impact:[/bold]\n{finding.impact}")
        if finding.remediation:
            self.display.console.print(f"\n[bold]Remediation:[/bold]\n{finding.remediation}")

        if finding.evidence:
            self.display.console.print(f"\n[bold]Evidence ({len(finding.evidence)}):[/bold]")
            for ev in finding.evidence:
                self.display.console.print(f"  - {ev.title}: {ev.file_path or ev.content[:50]}")

        if finding.notes:
            self.display.console.print(f"\n[bold]Notes:[/bold]")
            for note in finding.notes:
                self.display.console.print(f"  {note}")

        return True

    def _findings_update(self, args: List[str]) -> bool:
        """Update finding status."""
        from purplesploit.core.findings import FindingStatus

        if len(args) < 2:
            self.display.print_error("Usage: findings update <id> <status>")
            self.display.print_info("Statuses: draft, confirmed, reported, remediated, verified, false_positive, accepted_risk")
            return True

        finding_id = args[0]
        new_status = args[1].lower()

        try:
            status = FindingStatus(new_status)
        except ValueError:
            self.display.print_error(f"Invalid status: {new_status}")
            return True

        success = self._findings_manager.transition_status(finding_id, status)
        if success:
            self.display.print_success(f"Updated finding {finding_id} to {new_status}")
        else:
            self.display.print_error(f"Failed to update finding {finding_id}")

        return True

    def _findings_evidence(self, args: List[str]) -> bool:
        """Add evidence to a finding."""
        if len(args) < 2:
            self.display.print_error("Usage: findings evidence <id> <file_path>")
            return True

        finding_id = args[0]
        file_path = " ".join(args[1:])

        if not Path(file_path).exists():
            self.display.print_error(f"File not found: {file_path}")
            return True

        evidence = self._findings_manager.add_evidence(
            finding_id=finding_id,
            title=Path(file_path).name,
            file_path=file_path,
            evidence_type="file",
        )

        if evidence:
            self.display.print_success(f"Added evidence to finding {finding_id}")
        else:
            self.display.print_error(f"Failed to add evidence to {finding_id}")

        return True

    def _findings_export(self, args: List[str]) -> bool:
        """Export findings."""
        if not args:
            self.display.print_error("Usage: findings export <format> [path]")
            self.display.print_info("Formats: json")
            return True

        export_format = args[0].lower()
        output_path = args[1] if len(args) > 1 else f"findings_{self.framework.session.workspace}.json"

        if export_format == "json":
            result = self._findings_manager.export_json(output_path)
            self.display.print_success(f"Exported findings to: {result}")
        else:
            self.display.print_error(f"Unsupported export format: {export_format}")

        return True

    def _findings_stats(self) -> bool:
        """Show findings statistics."""
        stats = self._findings_manager.get_statistics()

        self.display.console.print("\n[bold cyan]Findings Statistics[/bold cyan]")
        self.display.console.print(f"Total: {stats['total']}")

        self.display.console.print("\n[bold]By Severity:[/bold]")
        for sev, count in stats['by_severity'].items():
            if count > 0:
                self.display.console.print(f"  {sev.upper()}: {count}")

        self.display.console.print("\n[bold]By Status:[/bold]")
        for status, count in stats['by_status'].items():
            if count > 0:
                self.display.console.print(f"  {status}: {count}")

        self.display.console.print(f"\nWith Evidence: {stats['with_evidence']}")
        self.display.console.print(f"With CVSS: {stats['with_cvss']}")

        return True

    def _findings_clear(self) -> bool:
        """Clear all findings."""
        try:
            confirm = input("Clear all findings? [y/N]: ").strip().lower()
            if confirm == 'y':
                self._findings_manager.findings.clear()
                self._findings_manager._save_findings()
                self.display.print_success("Cleared all findings")
            else:
                self.display.print_info("Cancelled")
        except (EOFError, KeyboardInterrupt):
            self.display.print_info("\nCancelled")

        return True

    # =========================================================================
    # Workflow Commands
    # =========================================================================

    def cmd_workflow(self, args: List[str]) -> bool:
        """
        Manage and run workflows.

        Usage:
            workflow                    - List workflows
            workflow list               - List available workflows
            workflow templates          - List workflow templates
            workflow create <name>      - Create new workflow from template
            workflow run <id> [target]  - Run a workflow
            workflow status <id>        - Show workflow status
            workflow pause <id>         - Pause a running workflow
            workflow resume <id>        - Resume a paused workflow
        """
        from purplesploit.core.workflow import WorkflowEngine

        # Get or create workflow engine
        if not hasattr(self, '_workflow_engine'):
            self._workflow_engine = WorkflowEngine(framework=self.framework)

        if not args:
            args = ["list"]

        subcommand = args[0].lower()

        if subcommand == "list":
            return self._workflow_list()
        elif subcommand == "templates":
            return self._workflow_templates()
        elif subcommand == "create":
            return self._workflow_create(args[1:])
        elif subcommand == "run":
            return self._workflow_run(args[1:])
        elif subcommand == "status":
            return self._workflow_status(args[1:])
        elif subcommand == "pause":
            return self._workflow_pause(args[1:])
        elif subcommand == "resume":
            return self._workflow_resume(args[1:])
        else:
            self.display.print_error(f"Unknown subcommand: {subcommand}")
            self.display.print_info("Usage: workflow [list|templates|create|run|status|pause|resume]")
            return True

    def _workflow_list(self) -> bool:
        """List existing workflows."""
        from rich.table import Table

        workflows = self._workflow_engine.list_workflows()

        if not workflows:
            self.display.print_warning("No workflows created yet")
            self.display.print_info("Use 'workflow templates' to see available templates")
            self.display.print_info("Use 'workflow create <name> --template <template>' to create")
            return True

        table = Table(title="Workflows")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="white")
        table.add_column("Status", style="yellow")
        table.add_column("Steps", style="green")
        table.add_column("Tags", style="dim")

        for wf in workflows:
            table.add_row(
                wf.id,
                wf.name,
                wf.status.value,
                str(len(wf.steps)),
                ", ".join(wf.tags) if wf.tags else "-",
            )

        self.display.console.print(table)
        return True

    def _workflow_templates(self) -> bool:
        """List workflow templates."""
        from rich.table import Table

        templates = self._workflow_engine.list_templates()

        table = Table(title="Workflow Templates")
        table.add_column("Template ID", style="cyan")
        table.add_column("Name", style="white")
        table.add_column("Description", style="dim")
        table.add_column("Steps", style="green")
        table.add_column("Tags", style="yellow")

        for tmpl in templates:
            table.add_row(
                tmpl["id"],
                tmpl["name"],
                tmpl["description"][:50] + "..." if len(tmpl["description"]) > 50 else tmpl["description"],
                str(tmpl["steps"]),
                ", ".join(tmpl.get("tags", [])),
            )

        self.display.console.print(table)
        self.display.print_info("\nCreate workflow: workflow create <name> --template <template_id>")
        return True

    def _workflow_create(self, args: List[str]) -> bool:
        """Create a new workflow."""
        if not args:
            self.display.print_error("Usage: workflow create <name> [--template <template>]")
            return True

        name = args[0]
        template = None

        # Parse --template option
        if "--template" in args:
            idx = args.index("--template")
            if idx + 1 < len(args):
                template = args[idx + 1]

        workflow = self._workflow_engine.create_workflow(
            name=name,
            from_template=template,
        )

        self.display.print_success(f"Created workflow: {workflow.id}")
        self.display.console.print(f"Name: {workflow.name}")
        self.display.console.print(f"Steps: {len(workflow.steps)}")

        if workflow.steps:
            self.display.console.print("\nWorkflow steps:")
            for i, step in enumerate(workflow.steps, 1):
                self.display.console.print(f"  {i}. {step.name} ({step.module})")

        return True

    def _workflow_run(self, args: List[str]) -> bool:
        """Run a workflow."""
        if not args:
            self.display.print_error("Usage: workflow run <workflow_id> [--target <target>]")
            return True

        workflow_id = args[0]
        variables = {}

        # Parse --target option
        if "--target" in args:
            idx = args.index("--target")
            if idx + 1 < len(args):
                variables["target"] = args[idx + 1]

        # Use current target if not specified
        if "target" not in variables:
            current = self.framework.session.targets.current
            if current:
                variables["target"] = current.identifier

        if not variables.get("target"):
            self.display.print_error("No target specified. Use --target or set a current target")
            return True

        self.display.print_info(f"Running workflow {workflow_id} against {variables['target']}...")

        # Set up progress callbacks
        def on_step_start(workflow, step):
            self.display.print_info(f"  → Starting: {step.name}")

        def on_step_complete(workflow, step, result):
            if result.get("success"):
                self.display.print_success(f"  ✓ {step.name}")
            else:
                self.display.print_error(f"  ✗ {step.name}: {result.get('error', 'Failed')}")

        self._workflow_engine.on_step_start = on_step_start
        self._workflow_engine.on_step_complete = on_step_complete

        result = self._workflow_engine.run_workflow(workflow_id, variables)

        if result.get("success"):
            self.display.print_success(f"\nWorkflow completed!")
            self.display.console.print(f"  Completed: {result['steps_completed']}")
            self.display.console.print(f"  Failed: {result['steps_failed']}")
            self.display.console.print(f"  Skipped: {result['steps_skipped']}")
        else:
            self.display.print_error(f"\nWorkflow failed: {result.get('error')}")

        return True

    def _workflow_status(self, args: List[str]) -> bool:
        """Show workflow status."""
        if not args:
            self.display.print_error("Usage: workflow status <workflow_id>")
            return True

        workflow_id = args[0]
        workflow = self._workflow_engine.get_workflow(workflow_id)

        if not workflow:
            self.display.print_error(f"Workflow not found: {workflow_id}")
            return True

        self.display.console.print(f"\n[bold cyan]Workflow: {workflow.name}[/bold cyan]")
        self.display.console.print(f"ID: {workflow.id}")
        self.display.console.print(f"Status: {workflow.status.value}")

        if workflow.steps:
            self.display.console.print("\n[bold]Steps:[/bold]")
            for step in workflow.steps:
                status_icon = {
                    "pending": "○",
                    "running": "◐",
                    "success": "✓",
                    "failed": "✗",
                    "skipped": "−",
                }.get(step.status.value, "?")
                self.display.console.print(f"  {status_icon} {step.name} [{step.status.value}]")

        return True

    def _workflow_pause(self, args: List[str]) -> bool:
        """Pause a workflow."""
        if not args:
            self.display.print_error("Usage: workflow pause <workflow_id>")
            return True

        success = self._workflow_engine.pause_workflow(args[0])
        if success:
            self.display.print_success(f"Paused workflow: {args[0]}")
        else:
            self.display.print_error(f"Failed to pause workflow: {args[0]}")

        return True

    def _workflow_resume(self, args: List[str]) -> bool:
        """Resume a workflow."""
        if not args:
            self.display.print_error("Usage: workflow resume <workflow_id>")
            return True

        result = self._workflow_engine.resume_workflow(args[0])
        if result.get("success"):
            self.display.print_success(f"Resumed workflow: {args[0]}")
        else:
            self.display.print_error(f"Failed to resume: {result.get('error')}")

        return True

    # =========================================================================
    # Report Generation Commands
    # =========================================================================

    def cmd_report(self, args: List[str]) -> bool:
        """
        Generate reports.

        Usage:
            report generate <format> [path]  - Generate report (pdf, html, xlsx, md, json)
            report config                    - Show/edit report configuration
            report preview                   - Preview findings summary
        """
        if not args:
            self.display.print_error("Usage: report [generate|config|preview]")
            return True

        subcommand = args[0].lower()

        if subcommand == "generate":
            return self._report_generate(args[1:])
        elif subcommand == "config":
            return self._report_config(args[1:])
        elif subcommand == "preview":
            return self._report_preview()
        else:
            self.display.print_error(f"Unknown subcommand: {subcommand}")
            return True

    def _report_generate(self, args: List[str]) -> bool:
        """Generate a report."""
        from purplesploit.reporting import ReportGenerator

        if not args:
            self.display.print_error("Usage: report generate <format> [output_path]")
            self.display.print_info("Formats: pdf, html, xlsx, markdown (md), json")
            return True

        format_type = args[0].lower()
        output_path = args[1] if len(args) > 1 else None

        # Get findings from findings manager
        if not hasattr(self, '_findings_manager'):
            from purplesploit.core.findings import FindingsManager
            self._findings_manager = FindingsManager(framework=self.framework)

        generator = ReportGenerator(framework=self.framework)

        # Import findings
        for finding in self._findings_manager.findings.values():
            from purplesploit.reporting.models import Finding as ReportFinding, Severity
            report_finding = ReportFinding(
                id=finding.id,
                title=finding.title,
                severity=Severity(finding.severity.value),
                description=finding.description,
                target=finding.target,
                cvss_score=finding.cvss_score,
                cvss_vector=finding.cvss_vector,
                cve_ids=finding.cve_ids,
                cwe_ids=finding.cwe_ids,
                impact=finding.impact,
                remediation=finding.remediation,
                port=finding.port,
                service=finding.service,
                module_name=finding.module_name,
            )
            generator.add_finding(report_finding)

        try:
            result = generator.generate(format_type, output_path)
            self.display.print_success(f"Generated report: {result}")
        except ImportError as e:
            self.display.print_error(f"Missing dependency: {e}")
            self.display.print_info("Install optional dependencies: pip install weasyprint openpyxl")
        except Exception as e:
            self.display.print_error(f"Failed to generate report: {e}")

        return True

    def _report_config(self, args: List[str]) -> bool:
        """Show or edit report configuration."""
        self.display.console.print("\n[bold]Report Configuration[/bold]")
        self.display.console.print("(Interactive configuration not yet implemented)")
        self.display.console.print("\nUse 'report generate <format>' to generate reports")
        return True

    def _report_preview(self) -> bool:
        """Preview findings summary."""
        if not hasattr(self, '_findings_manager'):
            from purplesploit.core.findings import FindingsManager
            self._findings_manager = FindingsManager(framework=self.framework)

        stats = self._findings_manager.get_statistics()

        self.display.console.print("\n[bold cyan]Report Preview[/bold cyan]")
        self.display.console.print(f"\nTotal Findings: {stats['total']}")

        if stats['total'] > 0:
            self.display.console.print("\n[bold]Severity Breakdown:[/bold]")
            for sev in ['critical', 'high', 'medium', 'low', 'info']:
                count = stats['by_severity'].get(sev, 0)
                if count > 0:
                    self.display.console.print(f"  {sev.upper()}: {count}")

            self.display.console.print("\n[bold]Targets Affected:[/bold]")
            for target, count in stats['by_target'].items():
                self.display.console.print(f"  {target}: {count} finding(s)")
        else:
            self.display.print_warning("No findings to report")
            self.display.print_info("Use 'findings add <title>' to create findings")

        return True

    # =========================================================================
    # Phase 3: Plugin Marketplace Commands
    # =========================================================================

    def cmd_plugin(self, args: List[str]) -> bool:
        """
        Manage plugins from the marketplace.

        Usage:
            plugin                      - Show installed plugins
            plugin list                 - List installed plugins
            plugin search <query>       - Search available plugins
            plugin browse [category]    - Browse plugins by category
            plugin install <name>       - Install a plugin
            plugin update <name>        - Update a plugin
            plugin uninstall <name>     - Uninstall a plugin
            plugin enable <name>        - Enable a disabled plugin
            plugin disable <name>       - Disable a plugin
            plugin info <name>          - Show plugin details
            plugin updates              - Check for updates
            plugin repos                - List repositories
        """
        from purplesploit.plugins import PluginManager

        # Get or create plugin manager
        if not hasattr(self, '_plugin_manager'):
            self._plugin_manager = PluginManager(framework=self.framework)

        if not args:
            args = ["list"]

        subcommand = args[0].lower()

        if subcommand == "list":
            return self._plugin_list(args[1:])
        elif subcommand == "search":
            return self._plugin_search(args[1:])
        elif subcommand == "browse":
            return self._plugin_browse(args[1:])
        elif subcommand == "install":
            return self._plugin_install(args[1:])
        elif subcommand == "update":
            return self._plugin_update(args[1:])
        elif subcommand == "uninstall":
            return self._plugin_uninstall(args[1:])
        elif subcommand == "enable":
            return self._plugin_enable(args[1:])
        elif subcommand == "disable":
            return self._plugin_disable(args[1:])
        elif subcommand == "info":
            return self._plugin_info(args[1:])
        elif subcommand == "updates":
            return self._plugin_check_updates()
        elif subcommand == "repos":
            return self._plugin_repos()
        else:
            self.display.print_error(f"Unknown subcommand: {subcommand}")
            self.display.print_info("Usage: plugin [list|search|browse|install|update|uninstall|enable|disable|info|updates|repos]")
            return True

    def _plugin_list(self, args: List[str]) -> bool:
        """List installed plugins."""
        from rich.table import Table
        from purplesploit.plugins.models import PluginStatus

        plugins = self._plugin_manager.list_installed()

        if not plugins:
            self.display.print_warning("No plugins installed")
            self.display.print_info("Use 'plugin search <query>' to find plugins")
            self.display.print_info("Use 'plugin install <name>' to install")
            return True

        table = Table(title="Installed Plugins")
        table.add_column("Name", style="cyan")
        table.add_column("Version", style="white")
        table.add_column("Category", style="green")
        table.add_column("Status", style="yellow")
        table.add_column("Description", style="dim")

        status_colors = {
            PluginStatus.INSTALLED: "green",
            PluginStatus.UPDATE_AVAILABLE: "yellow",
            PluginStatus.DISABLED: "dim",
            PluginStatus.BROKEN: "red",
        }

        for plugin in plugins:
            status_color = status_colors.get(plugin.status, "white")
            table.add_row(
                plugin.name,
                plugin.installed_version or plugin.version,
                plugin.manifest.category.value,
                f"[{status_color}]{plugin.status.value}[/{status_color}]",
                plugin.manifest.description[:40] + "..." if len(plugin.manifest.description) > 40 else plugin.manifest.description,
            )

        self.display.console.print(table)
        return True

    def _plugin_search(self, args: List[str]) -> bool:
        """Search for plugins."""
        from rich.table import Table

        if not args:
            self.display.print_error("Usage: plugin search <query>")
            return True

        query = " ".join(args)
        plugins = self._plugin_manager.search(query)

        if not plugins:
            self.display.print_warning(f"No plugins found matching: {query}")
            return True

        table = Table(title=f"Search Results: {query}")
        table.add_column("Name", style="cyan")
        table.add_column("Version", style="white")
        table.add_column("Category", style="green")
        table.add_column("Author", style="yellow")
        table.add_column("Downloads", style="magenta")
        table.add_column("Description", style="dim")

        for plugin in plugins[:20]:  # Limit to 20 results
            installed = "✓ " if plugin.installed_version else ""
            table.add_row(
                installed + plugin.name,
                plugin.version,
                plugin.manifest.category.value,
                plugin.manifest.author,
                str(plugin.downloads),
                plugin.manifest.description[:30] + "..." if len(plugin.manifest.description) > 30 else plugin.manifest.description,
            )

        self.display.console.print(table)
        self.display.print_info(f"\nFound {len(plugins)} plugin(s). Use 'plugin install <name>' to install.")
        return True

    def _plugin_browse(self, args: List[str]) -> bool:
        """Browse plugins by category."""
        from rich.table import Table
        from purplesploit.plugins.models import PluginCategory

        category = None
        if args:
            try:
                category = PluginCategory(args[0].lower())
            except ValueError:
                self.display.print_error(f"Invalid category: {args[0]}")
                self.display.print_info("Categories: " + ", ".join(c.value for c in PluginCategory))
                return True

        if category:
            plugins = self._plugin_manager.search(category=category)
            title = f"Plugins - {category.value.upper()}"
        else:
            # Show category summary
            plugins = self._plugin_manager.search()
            categories = {}
            for p in plugins:
                cat = p.manifest.category.value
                categories[cat] = categories.get(cat, 0) + 1

            table = Table(title="Plugin Categories")
            table.add_column("Category", style="cyan")
            table.add_column("Count", style="green")

            for cat, count in sorted(categories.items()):
                table.add_row(cat, str(count))

            self.display.console.print(table)
            self.display.print_info("\nUse 'plugin browse <category>' to list plugins in a category")
            return True

        # Show plugins in category
        table = Table(title=title)
        table.add_column("Name", style="cyan")
        table.add_column("Version", style="white")
        table.add_column("Author", style="yellow")
        table.add_column("Rating", style="magenta")
        table.add_column("Description", style="dim")

        for plugin in plugins[:20]:
            installed = "✓ " if plugin.installed_version else ""
            rating = f"{plugin.rating:.1f}" if plugin.rating else "-"
            table.add_row(
                installed + plugin.name,
                plugin.version,
                plugin.manifest.author,
                rating,
                plugin.manifest.description[:35] + "..." if len(plugin.manifest.description) > 35 else plugin.manifest.description,
            )

        self.display.console.print(table)
        return True

    def _plugin_install(self, args: List[str]) -> bool:
        """Install a plugin."""
        if not args:
            self.display.print_error("Usage: plugin install <name> [--version <ver>]")
            return True

        name = args[0]
        version = None

        if "--version" in args:
            idx = args.index("--version")
            if idx + 1 < len(args):
                version = args[idx + 1]

        try:
            self.display.print_info(f"Installing {name}...")
            plugin = self._plugin_manager.install(name, version)
            self.display.print_success(f"Installed {plugin.name} v{plugin.installed_version}")

            if plugin.manifest.description:
                self.display.console.print(f"  {plugin.manifest.description}")
            if plugin.manifest.module_path:
                self.display.console.print(f"  Module: {plugin.manifest.module_path}")

        except ValueError as e:
            self.display.print_error(f"Plugin not found: {e}")
        except RuntimeError as e:
            self.display.print_error(f"Installation failed: {e}")
        except Exception as e:
            self.display.print_error(f"Error: {e}")

        return True

    def _plugin_update(self, args: List[str]) -> bool:
        """Update a plugin."""
        if not args:
            self.display.print_error("Usage: plugin update <name>")
            return True

        name = args[0]

        try:
            self.display.print_info(f"Updating {name}...")
            plugin = self._plugin_manager.update(name)
            self.display.print_success(f"Updated {plugin.name} to v{plugin.installed_version}")
        except ValueError as e:
            self.display.print_error(str(e))
        except Exception as e:
            self.display.print_error(f"Update failed: {e}")

        return True

    def _plugin_uninstall(self, args: List[str]) -> bool:
        """Uninstall a plugin."""
        if not args:
            self.display.print_error("Usage: plugin uninstall <name>")
            return True

        name = args[0]

        try:
            confirm = input(f"Uninstall {name}? [y/N]: ").strip().lower()
            if confirm == 'y':
                if self._plugin_manager.uninstall(name):
                    self.display.print_success(f"Uninstalled {name}")
                else:
                    self.display.print_error(f"Failed to uninstall {name}")
            else:
                self.display.print_info("Cancelled")
        except (EOFError, KeyboardInterrupt):
            self.display.print_info("\nCancelled")

        return True

    def _plugin_enable(self, args: List[str]) -> bool:
        """Enable a disabled plugin."""
        if not args:
            self.display.print_error("Usage: plugin enable <name>")
            return True

        if self._plugin_manager.enable(args[0]):
            self.display.print_success(f"Enabled {args[0]}")
        else:
            self.display.print_error(f"Plugin not found: {args[0]}")

        return True

    def _plugin_disable(self, args: List[str]) -> bool:
        """Disable a plugin."""
        if not args:
            self.display.print_error("Usage: plugin disable <name>")
            return True

        if self._plugin_manager.disable(args[0]):
            self.display.print_success(f"Disabled {args[0]}")
        else:
            self.display.print_error(f"Plugin not found: {args[0]}")

        return True

    def _plugin_info(self, args: List[str]) -> bool:
        """Show plugin details."""
        if not args:
            self.display.print_error("Usage: plugin info <name>")
            return True

        plugin = self._plugin_manager.get_plugin(args[0])
        if not plugin:
            self.display.print_error(f"Plugin not found: {args[0]}")
            return True

        self.display.console.print(f"\n[bold cyan]{plugin.name}[/bold cyan] v{plugin.version}")
        self.display.console.print(f"Author: {plugin.manifest.author}")
        self.display.console.print(f"Category: {plugin.manifest.category.value}")
        self.display.console.print(f"License: {plugin.manifest.license}")

        if plugin.manifest.tags:
            self.display.console.print(f"Tags: {', '.join(plugin.manifest.tags)}")

        self.display.console.print(f"\n[bold]Description:[/bold]")
        self.display.console.print(f"  {plugin.manifest.description}")

        if plugin.installed_version:
            self.display.console.print(f"\n[bold]Installation:[/bold]")
            self.display.console.print(f"  Installed: v{plugin.installed_version}")
            self.display.console.print(f"  Path: {plugin.install_path}")
            self.display.console.print(f"  Status: {plugin.status.value}")
            self.display.console.print(f"  Enabled: {plugin.enabled}")

            if plugin.has_update:
                self.display.console.print(f"  [yellow]Update available: v{plugin.latest_version}[/yellow]")

        if plugin.manifest.python_dependencies:
            self.display.console.print(f"\n[bold]Python Dependencies:[/bold]")
            for dep in plugin.manifest.python_dependencies:
                self.display.console.print(f"  - {dep}")

        if plugin.manifest.homepage:
            self.display.console.print(f"\nHomepage: {plugin.manifest.homepage}")
        if plugin.manifest.repository:
            self.display.console.print(f"Repository: {plugin.manifest.repository}")

        return True

    def _plugin_check_updates(self) -> bool:
        """Check for plugin updates."""
        self.display.print_info("Checking for updates...")

        updates = self._plugin_manager.check_updates()

        if not updates:
            self.display.print_success("All plugins are up to date!")
            return True

        from rich.table import Table
        table = Table(title="Available Updates")
        table.add_column("Plugin", style="cyan")
        table.add_column("Current", style="white")
        table.add_column("Available", style="green")

        for plugin in updates:
            table.add_row(
                plugin.name,
                plugin.installed_version or "?",
                plugin.latest_version or "?",
            )

        self.display.console.print(table)
        self.display.print_info(f"\n{len(updates)} update(s) available. Use 'plugin update <name>' to update.")
        return True

    def _plugin_repos(self) -> bool:
        """List configured repositories."""
        from rich.table import Table

        repos = self._plugin_manager.list_repositories()

        table = Table(title="Plugin Repositories")
        table.add_column("Name", style="cyan")
        table.add_column("URL", style="white")

        for repo in repos:
            table.add_row(repo.name, repo.url or "(local)")

        self.display.console.print(table)
        return True

    # =========================================================================
    # Advanced: Smart Auto-Enumeration
    # =========================================================================

    def cmd_auto(self, args: List[str]) -> bool:
        """
        Smart auto-enumeration pipeline.

        Usage:
            auto <target>                  - Run auto-enum on target
            auto <target1> <target2> ...   - Multiple targets
            auto --scope light             - Quick enumeration
            auto --scope aggressive        - Full enumeration
            auto --scope stealth           - Slow, evasive enumeration
            auto --parallel                - Parallel target enumeration
            auto status                    - Show running auto-enum status
            auto stop                      - Stop running enumeration

        Examples:
            auto 192.168.1.0/24
            auto 10.0.0.1 10.0.0.2 --scope aggressive
            auto 192.168.1.50 --parallel
        """
        from purplesploit.core.auto_enum import (
            AutoEnumPipeline, create_auto_enum, EnumScope, EnumPhase
        )

        if not args:
            # Use current target if set
            current = self.framework.session.targets.current
            if current:
                args = [current.identifier]
            else:
                self.display.print_error("Usage: auto <target> [--scope <scope>] [--parallel]")
                self.display.print_info("Scopes: passive, light, normal, aggressive, stealth")
                return True

        # Handle subcommands
        if args[0] == "status":
            return self._auto_status()
        elif args[0] == "stop":
            return self._auto_stop()

        # Parse arguments
        targets = []
        scope = "normal"
        parallel = False
        phases = None

        i = 0
        while i < len(args):
            arg = args[i]
            if arg == "--scope" and i + 1 < len(args):
                scope = args[i + 1]
                i += 2
            elif arg == "--parallel":
                parallel = True
                i += 1
            elif arg == "--phases" and i + 1 < len(args):
                phase_str = args[i + 1]
                phases = [EnumPhase(p.strip()) for p in phase_str.split(",")]
                i += 2
            elif arg.startswith("--"):
                i += 1
            else:
                targets.append(arg)
                i += 1

        if not targets:
            self.display.print_error("No targets specified")
            return True

        # Create pipeline
        self.display.console.print()
        self.display.console.print("[bold cyan]═══════════════════════════════════════════════════════════════════[/bold cyan]")
        self.display.console.print("[bold white]              SMART AUTO-ENUMERATION PIPELINE                       [/bold white]")
        self.display.console.print("[bold cyan]═══════════════════════════════════════════════════════════════════[/bold cyan]")
        self.display.console.print()

        self.display.print_info(f"Targets: {', '.join(targets)}")
        self.display.print_info(f"Scope: {scope}")
        self.display.print_info(f"Parallel: {parallel}")
        self.display.console.print()

        # Create and configure pipeline
        pipeline = create_auto_enum(self.framework, scope=scope)

        # Store for status/stop commands
        self._auto_pipeline = pipeline

        # Set up callbacks
        def on_progress(progress):
            self.display.console.print(
                f"[dim][{progress.phase.value}][/dim] {progress.current_step} → {progress.current_target}"
            )

        def on_service_found(target, service, port):
            self.display.print_success(f"  Found: {service}:{port} on {target}")

        def on_credential_found(cred):
            username = cred.get('username', 'unknown')
            domain = cred.get('domain', '')
            if domain:
                self.display.print_success(f"  [bold green]CREDENTIAL:[/bold green] {domain}\\{username}")
            else:
                self.display.print_success(f"  [bold green]CREDENTIAL:[/bold green] {username}")

        def on_finding(finding):
            severity = finding.get('severity', 'info').upper()
            title = finding.get('title', 'Unknown')
            colors = {
                'CRITICAL': 'red',
                'HIGH': 'red',
                'MEDIUM': 'yellow',
                'LOW': 'green',
                'INFO': 'blue',
            }
            color = colors.get(severity, 'white')
            self.display.console.print(f"  [{color}][{severity}][/{color}] {title}")

        def on_step_complete(result):
            if result.success:
                status = "[green]✓[/green]"
            else:
                status = "[red]✗[/red]"
            self.display.console.print(
                f"  {status} {result.module} ({result.duration:.1f}s)"
            )

        pipeline.on_progress = on_progress
        pipeline.on_service_found = on_service_found
        pipeline.on_credential_found = on_credential_found
        pipeline.on_finding = on_finding
        pipeline.on_step_complete = on_step_complete

        # Run enumeration
        try:
            self.display.console.print("[bold]Starting enumeration...[/bold]")
            self.display.console.print()

            summary = pipeline.run(
                targets=targets,
                phases=phases,
                parallel=parallel,
            )

            # Display summary
            self._display_auto_summary(summary)

        except KeyboardInterrupt:
            self.display.print_warning("\nEnumeration interrupted by user")
            pipeline.stop()
        except Exception as e:
            self.display.print_error(f"Enumeration error: {e}")
            import traceback
            traceback.print_exc()

        return True

    def _auto_status(self) -> bool:
        """Show auto-enumeration status."""
        if not hasattr(self, '_auto_pipeline') or not self._auto_pipeline:
            self.display.print_warning("No auto-enumeration running")
            return True

        pipeline = self._auto_pipeline

        self.display.console.print("\n[bold cyan]Auto-Enumeration Status[/bold cyan]")
        self.display.console.print(f"Modules executed: {len(pipeline.results)}")
        self.display.console.print(f"Services found: {sum(len(s) for s in pipeline.discovered_services.values())}")
        self.display.console.print(f"Credentials found: {len(pipeline.discovered_credentials)}")
        self.display.console.print(f"Users found: {sum(len(u) for u in pipeline.discovered_users.values())}")

        return True

    def _auto_stop(self) -> bool:
        """Stop running auto-enumeration."""
        if not hasattr(self, '_auto_pipeline') or not self._auto_pipeline:
            self.display.print_warning("No auto-enumeration running")
            return True

        self._auto_pipeline.stop()
        self.display.print_success("Stop signal sent")
        return True

    def _display_auto_summary(self, summary: Dict) -> bool:
        """Display auto-enumeration summary."""
        from rich.table import Table
        from rich.panel import Panel

        self.display.console.print()
        self.display.console.print("[bold cyan]═══════════════════════════════════════════════════════════════════[/bold cyan]")
        self.display.console.print("[bold white]                    ENUMERATION SUMMARY                            [/bold white]")
        self.display.console.print("[bold cyan]═══════════════════════════════════════════════════════════════════[/bold cyan]")
        self.display.console.print()

        # Statistics
        self.display.console.print(f"[bold]Duration:[/bold] {summary['duration_seconds']:.1f} seconds")
        self.display.console.print(f"[bold]Targets Scanned:[/bold] {summary['targets_scanned']}")
        self.display.console.print(f"[bold]Modules Executed:[/bold] {summary['modules_executed']}")
        self.display.console.print(f"  ✓ Successful: {summary['successful_executions']}")
        self.display.console.print(f"  ✗ Failed: {summary['failed_executions']}")
        self.display.console.print()

        # Services discovered
        if summary['services_discovered']:
            self.display.console.print("[bold]Services Discovered:[/bold]")
            for target, services in summary['services_discovered'].items():
                self.display.console.print(f"  {target}: {', '.join(services)}")
            self.display.console.print()

        # Credentials
        if summary['credentials_discovered'] > 0:
            self.display.console.print(f"[bold green]Credentials Discovered:[/bold green] {summary['credentials_discovered']}")
            self.display.print_info("Use 'creds list' to view credentials")
            self.display.console.print()

        # Users
        if summary['users_discovered'] > 0:
            self.display.console.print(f"[bold]Users Discovered:[/bold] {summary['users_discovered']}")
            self.display.console.print()

        # Findings
        if summary['findings'] > 0:
            self.display.console.print(f"[bold yellow]Findings:[/bold yellow] {summary['findings']}")
            self.display.print_info("Use 'findings list' to view findings")
            self.display.console.print()

        # Execution details table
        if summary['results']:
            table = Table(title="Module Execution Details")
            table.add_column("Module", style="cyan")
            table.add_column("Operation", style="white")
            table.add_column("Target", style="green")
            table.add_column("Status", style="bold")
            table.add_column("Duration", style="dim")

            for result in summary['results'][:20]:  # Limit to 20
                status = "[green]✓[/green]" if result['success'] else "[red]✗[/red]"
                table.add_row(
                    result['module'],
                    result['operation'] or "-",
                    result['target'],
                    status,
                    f"{result['duration']:.1f}s",
                )

            self.display.console.print(table)

            if len(summary['results']) > 20:
                self.display.console.print(f"  ... and {len(summary['results']) - 20} more")

        # Next steps suggestion
        self.display.console.print()
        self.display.console.print("[bold]Suggested Next Steps:[/bold]")

        if summary['credentials_discovered'] > 0:
            self.display.console.print("  • Try credentials with: [cyan]use network/nxc_smb[/cyan] → [cyan]run[/cyan]")
            self.display.console.print("  • Spray credentials with: [cyan]spray <target>[/cyan]")

        if summary['findings'] > 0:
            self.display.console.print("  • Review findings: [cyan]findings list[/cyan]")
            self.display.console.print("  • Generate report: [cyan]report generate html[/cyan]")

        if summary['services_discovered']:
            services_flat = set()
            for svcs in summary['services_discovered'].values():
                services_flat.update(svcs)

            if 'ldap' in services_flat or 'kerberos' in services_flat:
                self.display.console.print("  • AD enumeration: [cyan]use ad/kerbrute[/cyan]")

            if 'http' in services_flat or 'https' in services_flat:
                self.display.console.print("  • Web scanning: [cyan]use web/feroxbuster[/cyan]")

        return True

    # =========================================================================
    # Attack Graph Visualization Commands
    # =========================================================================

    def cmd_graph(self, args: List[str]) -> bool:
        """
        Attack graph visualization management.

        Usage:
            graph                      - Show graph statistics
            graph show                 - Display graph summary
            graph add host <ip>        - Add a host node
            graph add service <ip> <port> <name>  - Add a service
            graph add cred <user> [pass] [domain] - Add credential
            graph add vuln <service_id> <name> <severity>  - Add vulnerability
            graph link <cred_id> <host_id>  - Link credential to host
            graph compromised <node_id>     - Mark node as compromised
            graph paths <from> <to>    - Find attack paths
            graph lateral <host_id>    - Find lateral movement paths
            graph export json [file]   - Export to JSON
            graph export dot [file]    - Export to GraphViz DOT
            graph export cytoscape     - Export to Cytoscape format
            graph clear                - Clear the graph
            graph import <file>        - Import from JSON

        Examples:
            graph add host 192.168.1.1
            graph add service 192.168.1.1 445 smb
            graph add cred administrator P@ssw0rd CORP
            graph link cred:abc123 host:xyz789
            graph paths host:start host:target
            graph export json attack_graph.json
        """
        from purplesploit.core.attack_graph import (
            AttackGraph, create_attack_graph, NodeType, NodeStatus, EdgeType
        )

        # Initialize graph if not exists
        if not hasattr(self, '_attack_graph') or self._attack_graph is None:
            self._attack_graph = create_attack_graph()

        graph = self._attack_graph

        if not args:
            return self._graph_show_stats(graph)

        subcommand = args[0].lower()

        if subcommand == "show":
            return self._graph_show(graph)
        elif subcommand == "add":
            return self._graph_add(graph, args[1:])
        elif subcommand == "link":
            return self._graph_link(graph, args[1:])
        elif subcommand == "compromised":
            return self._graph_compromised(graph, args[1:])
        elif subcommand == "paths":
            return self._graph_paths(graph, args[1:])
        elif subcommand == "lateral":
            return self._graph_lateral(graph, args[1:])
        elif subcommand == "export":
            return self._graph_export(graph, args[1:])
        elif subcommand == "import":
            return self._graph_import(graph, args[1:])
        elif subcommand == "clear":
            return self._graph_clear(graph)
        else:
            self.display.print_error(f"Unknown graph subcommand: {subcommand}")
            self.display.print_info("Use 'graph' for usage info")

        return True

    def _graph_show_stats(self, graph) -> bool:
        """Show graph statistics."""
        from rich.panel import Panel
        from rich.table import Table

        stats = graph.get_statistics()

        self.display.console.print()
        self.display.console.print("[bold cyan]═══════════════════════════════════════════════════════════════════[/bold cyan]")
        self.display.console.print("[bold white]                    ATTACK GRAPH STATUS                            [/bold white]")
        self.display.console.print("[bold cyan]═══════════════════════════════════════════════════════════════════[/bold cyan]")
        self.display.console.print()

        table = Table(show_header=False, box=None)
        table.add_column("Metric", style="bold")
        table.add_column("Value", style="cyan")

        table.add_row("Total Nodes", str(stats["total_nodes"]))
        table.add_row("Total Edges", str(stats["total_edges"]))
        table.add_row("", "")
        table.add_row("Hosts", str(stats["hosts"]))
        table.add_row("Services", str(stats["services"]))
        table.add_row("Credentials", str(stats["credentials"]))
        table.add_row("Vulnerabilities", str(stats["vulnerabilities"]))
        table.add_row("", "")
        table.add_row("Compromised Hosts", f"[red]{stats['compromised_hosts']}[/red]")
        table.add_row("Attack Paths", str(stats["attack_paths"]))

        self.display.console.print(table)
        self.display.console.print()

        if stats["total_nodes"] == 0:
            self.display.print_info("Graph is empty. Use 'graph add' to add nodes.")
            self.display.print_info("Or run 'auto <target>' to auto-populate from scans.")

        return True

    def _graph_show(self, graph) -> bool:
        """Show detailed graph view."""
        from rich.tree import Tree
        from purplesploit.core.attack_graph import NodeType, NodeStatus

        if len(graph.nodes) == 0:
            self.display.print_warning("Graph is empty")
            return True

        # Build tree by host
        tree = Tree("[bold]Attack Graph[/bold]")

        hosts = graph.get_nodes_by_type(NodeType.HOST)
        for host in hosts:
            status_icon = "🔴" if host.status == NodeStatus.COMPROMISED else "🟢"
            host_branch = tree.add(f"{status_icon} [bold cyan]{host.label}[/bold cyan] ({host.id})")

            # Add services under host
            for edge in graph.get_edges_from(host.id):
                if edge.edge_type.value == "has_service":
                    service = graph.nodes.get(edge.target_id)
                    if service:
                        svc_branch = host_branch.add(f"[green]↳ {service.label}[/green]")

                        # Add vulns under service
                        for svc_edge in graph.get_edges_from(service.id):
                            if svc_edge.edge_type.value == "has_vulnerability":
                                vuln = graph.nodes.get(svc_edge.target_id)
                                if vuln:
                                    severity = vuln.properties.get("severity", "medium")
                                    colors = {"critical": "red", "high": "red", "medium": "yellow", "low": "green"}
                                    color = colors.get(severity.lower(), "white")
                                    svc_branch.add(f"[{color}]⚠ {vuln.label}[/{color}]")

            # Add credentials that authenticate to this host
            for edge in graph.get_edges_to(host.id):
                if edge.edge_type.value == "authenticates_to":
                    cred = graph.nodes.get(edge.source_id)
                    if cred:
                        host_branch.add(f"[yellow]🔑 {cred.label}[/yellow]")

        # Show orphan credentials
        creds = graph.get_nodes_by_type(NodeType.CREDENTIAL)
        orphan_creds = []
        for cred in creds:
            edges = graph.get_edges_from(cred.id)
            if not edges:
                orphan_creds.append(cred)

        if orphan_creds:
            cred_branch = tree.add("[yellow]Unlinked Credentials[/yellow]")
            for cred in orphan_creds:
                cred_branch.add(f"🔑 {cred.label}")

        self.display.console.print(tree)
        return True

    def _graph_add(self, graph, args: List[str]) -> bool:
        """Add node to graph."""
        if not args:
            self.display.print_error("Usage: graph add <host|service|cred|vuln> ...")
            return True

        node_type = args[0].lower()

        if node_type == "host":
            if len(args) < 2:
                self.display.print_error("Usage: graph add host <ip> [hostname] [os]")
                return True
            ip = args[1]
            hostname = args[2] if len(args) > 2 else None
            os_type = args[3] if len(args) > 3 else None

            node = graph.add_host(ip, hostname, os_type)
            self.display.print_success(f"Added host: {node.label} ({node.id})")

        elif node_type == "service":
            if len(args) < 4:
                self.display.print_error("Usage: graph add service <host_ip> <port> <name> [version]")
                return True
            host_ip = args[1]
            port = int(args[2])
            name = args[3]
            version = args[4] if len(args) > 4 else None

            node = graph.add_service(host_ip, port, name, version)
            self.display.print_success(f"Added service: {node.label} ({node.id})")

        elif node_type == "cred":
            if len(args) < 2:
                self.display.print_error("Usage: graph add cred <username> [password] [domain]")
                return True
            username = args[1]
            password = args[2] if len(args) > 2 else None
            domain = args[3] if len(args) > 3 else None

            node = graph.add_credential(username, password, domain=domain)
            self.display.print_success(f"Added credential: {node.label} ({node.id})")

        elif node_type == "vuln":
            if len(args) < 3:
                self.display.print_error("Usage: graph add vuln <service_id> <name> [severity] [cve]")
                return True
            service_id = args[1]
            name = args[2]
            severity = args[3] if len(args) > 3 else "medium"
            cve = args[4] if len(args) > 4 else None

            node = graph.add_vulnerability(service_id, name, severity, cve)
            self.display.print_success(f"Added vulnerability: {node.label} ({node.id})")

        else:
            self.display.print_error(f"Unknown node type: {node_type}")

        return True

    def _graph_link(self, graph, args: List[str]) -> bool:
        """Link credential to host."""
        if len(args) < 2:
            self.display.print_error("Usage: graph link <cred_id> <host_id> [service]")
            return True

        cred_id = args[0]
        host_id = args[1]
        service = args[2] if len(args) > 2 else None

        edge = graph.link_credential_to_host(cred_id, host_id, service)
        if edge:
            self.display.print_success(f"Linked {cred_id} → {host_id}")
        else:
            self.display.print_error("Failed to create link. Check node IDs exist.")

        return True

    def _graph_compromised(self, graph, args: List[str]) -> bool:
        """Mark node as compromised."""
        if not args:
            self.display.print_error("Usage: graph compromised <node_id>")
            return True

        node_id = args[0]
        if graph.mark_compromised(node_id):
            self.display.print_success(f"Marked {node_id} as compromised")
        else:
            self.display.print_error(f"Node not found: {node_id}")

        return True

    def _graph_paths(self, graph, args: List[str]) -> bool:
        """Find attack paths between nodes."""
        if len(args) < 2:
            self.display.print_error("Usage: graph paths <from_node_id> <to_node_id>")
            return True

        from_id = args[0]
        to_id = args[1]

        paths = graph.find_attack_paths(from_id, to_id)

        if not paths:
            self.display.print_warning(f"No paths found from {from_id} to {to_id}")
            return True

        self.display.console.print(f"\n[bold]Found {len(paths)} attack path(s):[/bold]\n")

        for i, path in enumerate(paths[:5], 1):
            self.display.console.print(f"[cyan]Path {i}[/cyan] (Risk Score: {path.risk_score:.1f})")

            path_str = " → ".join([
                graph.nodes[nid].label if nid in graph.nodes else nid
                for nid in path.nodes
            ])
            self.display.console.print(f"  {path_str}")
            self.display.console.print()

        if len(paths) > 5:
            self.display.console.print(f"  ... and {len(paths) - 5} more paths")

        return True

    def _graph_lateral(self, graph, args: List[str]) -> bool:
        """Find lateral movement paths from a host."""
        if not args:
            self.display.print_error("Usage: graph lateral <host_id>")
            return True

        host_id = args[0]
        paths = graph.find_lateral_paths(host_id)

        if not paths:
            self.display.print_warning(f"No lateral paths found from {host_id}")
            return True

        self.display.console.print(f"\n[bold]Found {len(paths)} lateral movement path(s):[/bold]\n")

        for path in paths:
            self.display.console.print(f"  [cyan]{path.description}[/cyan]")
            path_str = " → ".join([
                graph.nodes[nid].label if nid in graph.nodes else nid
                for nid in path.nodes
            ])
            self.display.console.print(f"    {path_str}")

        return True

    def _graph_export(self, graph, args: List[str]) -> bool:
        """Export graph to file."""
        if not args:
            self.display.print_error("Usage: graph export <json|dot|cytoscape> [filename]")
            return True

        format_type = args[0].lower()
        filename = args[1] if len(args) > 1 else None

        if format_type == "json":
            output = graph.to_json(indent=2)
            default_name = "attack_graph.json"
        elif format_type == "dot":
            output = graph.to_graphviz()
            default_name = "attack_graph.dot"
        elif format_type == "cytoscape":
            import json
            output = json.dumps(graph.to_cytoscape(), indent=2)
            default_name = "attack_graph_cytoscape.json"
        else:
            self.display.print_error(f"Unknown format: {format_type}")
            return True

        if filename:
            with open(filename, 'w') as f:
                f.write(output)
            self.display.print_success(f"Exported to {filename}")
        else:
            self.display.console.print(output)
            self.display.print_info(f"Use 'graph export {format_type} <filename>' to save to file")

        return True

    def _graph_import(self, graph, args: List[str]) -> bool:
        """Import graph from file."""
        if not args:
            self.display.print_error("Usage: graph import <filename>")
            return True

        filename = args[0]

        try:
            from purplesploit.core.attack_graph import AttackGraph

            with open(filename, 'r') as f:
                content = f.read()

            self._attack_graph = AttackGraph.from_json(content)
            stats = self._attack_graph.get_statistics()

            self.display.print_success(f"Imported graph from {filename}")
            self.display.print_info(f"  {stats['total_nodes']} nodes, {stats['total_edges']} edges")

        except FileNotFoundError:
            self.display.print_error(f"File not found: {filename}")
        except Exception as e:
            self.display.print_error(f"Import failed: {e}")

        return True

    def _graph_clear(self, graph) -> bool:
        """Clear the attack graph."""
        graph.clear()
        self.display.print_success("Attack graph cleared")
        return True

    # =========================================================================
    # Credential Spray Intelligence Commands
    # =========================================================================

    def cmd_spray(self, args: List[str]) -> bool:
        """
        Credential spray intelligence.

        Usage:
            spray <target>                      - Spray with context creds/users
            spray <target> -u users.txt         - Spray with user file
            spray <target> -p passwords.txt     - Spray with password file
            spray <target> -u user1,user2 -p pass1,pass2
            spray --protocol <proto>            - Use specific protocol
            spray --pattern <pattern>           - Use spray pattern
            spray --domain <domain>             - Set domain
            spray --delay <seconds>             - Set delay between attempts
            spray --jitter <seconds>            - Add random jitter
            spray --stop-on-success             - Stop after first success
            spray status                        - Show spray status
            spray stop                          - Stop current spray
            spray history                       - Show spray history
            spray wordlist                      - Generate smart wordlist

        Protocols: smb, ldap, winrm, ssh, rdp, mssql, kerberos
        Patterns: breadth_first, depth_first, low_and_slow, random, smart

        Examples:
            spray 192.168.1.100
            spray dc01.corp.local --protocol ldap --domain CORP
            spray 10.0.0.1 -u admin,user -p Summer2024,P@ssw0rd
            spray 10.0.0.1 --pattern low_and_slow --delay 30
        """
        from purplesploit.core.credential_spray import (
            CredentialSpray, create_credential_spray,
            SprayProtocol, SprayPattern, LockoutPolicy, PasswordGenerator
        )

        # Initialize spray manager if not exists
        if not hasattr(self, '_credential_spray') or self._credential_spray is None:
            self._credential_spray = create_credential_spray(self.framework)

        spray = self._credential_spray

        if not args:
            self.display.print_error("Usage: spray <target> [options]")
            self.display.print_info("Use 'spray --help' for full usage")
            return True

        # Handle subcommands
        if args[0] == "status":
            return self._spray_status(spray)
        elif args[0] == "stop":
            return self._spray_stop(spray)
        elif args[0] == "history":
            return self._spray_history(spray)
        elif args[0] == "wordlist":
            return self._spray_wordlist(args[1:])
        elif args[0] == "--help":
            self.display.console.print(self.cmd_spray.__doc__)
            return True

        # Parse arguments
        targets = []
        users = []
        passwords = []
        protocol = "smb"
        pattern = "breadth_first"
        domain = None
        delay = 0.0
        jitter = 0.0
        stop_on_success = False

        i = 0
        while i < len(args):
            arg = args[i]
            if arg in ["-u", "--users"]:
                if i + 1 < len(args):
                    user_arg = args[i + 1]
                    if "," in user_arg:
                        users.extend(user_arg.split(","))
                    elif user_arg.endswith(".txt"):
                        users.extend(self._read_file_lines(user_arg))
                    else:
                        users.append(user_arg)
                    i += 2
                else:
                    i += 1
            elif arg in ["-p", "--passwords"]:
                if i + 1 < len(args):
                    pass_arg = args[i + 1]
                    if "," in pass_arg:
                        passwords.extend(pass_arg.split(","))
                    elif pass_arg.endswith(".txt"):
                        passwords.extend(self._read_file_lines(pass_arg))
                    else:
                        passwords.append(pass_arg)
                    i += 2
                else:
                    i += 1
            elif arg == "--protocol":
                if i + 1 < len(args):
                    protocol = args[i + 1]
                    i += 2
                else:
                    i += 1
            elif arg == "--pattern":
                if i + 1 < len(args):
                    pattern = args[i + 1]
                    i += 2
                else:
                    i += 1
            elif arg in ["-d", "--domain"]:
                if i + 1 < len(args):
                    domain = args[i + 1]
                    i += 2
                else:
                    i += 1
            elif arg == "--delay":
                if i + 1 < len(args):
                    delay = float(args[i + 1])
                    i += 2
                else:
                    i += 1
            elif arg == "--jitter":
                if i + 1 < len(args):
                    jitter = float(args[i + 1])
                    i += 2
                else:
                    i += 1
            elif arg == "--stop-on-success":
                stop_on_success = True
                i += 1
            elif arg.startswith("-"):
                i += 1
            else:
                targets.append(arg)
                i += 1

        # Use context if not specified
        if not targets:
            current = self.framework.session.targets.current
            if current:
                targets = [current.identifier]
            else:
                self.display.print_error("No target specified")
                return True

        if not users:
            # Use context users
            ctx_users = list(self.framework.session.context.get("users", []))
            if ctx_users:
                users = ctx_users
            else:
                self.display.print_warning("No users specified. Using common usernames.")
                users = ["administrator", "admin", "guest", "user"]

        if not passwords:
            # Generate smart wordlist
            self.display.print_info("No passwords specified. Generating smart wordlist...")
            passwords = PasswordGenerator.build_wordlist(
                include_common=True,
                include_seasonal=True,
                usernames=users[:5],  # Use first 5 users for variations
            )[:20]  # Limit to 20 for safety

        # Display configuration
        self.display.console.print()
        self.display.console.print("[bold cyan]═══════════════════════════════════════════════════════════════════[/bold cyan]")
        self.display.console.print("[bold white]              CREDENTIAL SPRAY INTELLIGENCE                        [/bold white]")
        self.display.console.print("[bold cyan]═══════════════════════════════════════════════════════════════════[/bold cyan]")
        self.display.console.print()

        self.display.print_info(f"Targets: {', '.join(targets)}")
        self.display.print_info(f"Users: {len(users)}")
        self.display.print_info(f"Passwords: {len(passwords)}")
        self.display.print_info(f"Protocol: {protocol}")
        self.display.print_info(f"Pattern: {pattern}")
        if domain:
            self.display.print_info(f"Domain: {domain}")
        if delay > 0:
            self.display.print_info(f"Delay: {delay}s")

        total_attempts = len(targets) * len(users) * len(passwords)
        self.display.print_info(f"Total potential attempts: {total_attempts}")
        self.display.console.print()

        # Set up callbacks
        def on_attempt(attempt):
            status = "[green]✓[/green]" if attempt.success else "[dim]·[/dim]"
            self.display.console.print(
                f"  {status} {attempt.username}:{attempt.password[:8]}... → {attempt.target}"
            )

        def on_success(attempt):
            self.display.console.print()
            self.display.print_success(
                f"[bold green]VALID CREDENTIAL:[/bold green] {attempt.username}:{attempt.password}"
            )
            self.display.console.print()

        def on_lockout(username):
            self.display.print_warning(f"Lockout detected: {username}")

        def on_progress(completed, total):
            if completed % 10 == 0:
                pct = int(completed / total * 100)
                self.display.console.print(f"  [dim]Progress: {completed}/{total} ({pct}%)[/dim]")

        spray.on_attempt = on_attempt
        spray.on_success = on_success
        spray.on_lockout = on_lockout
        spray.on_progress = on_progress

        # Execute spray
        try:
            self.display.console.print("[bold]Starting credential spray...[/bold]")
            self.display.console.print()

            result = spray.spray(
                targets=targets,
                users=users,
                passwords=passwords,
                protocol=protocol,
                pattern=SprayPattern(pattern),
                domain=domain,
                delay=delay,
                jitter=jitter,
                stop_on_success=stop_on_success,
            )

            # Display results
            self._display_spray_results(result)

            # Add valid credentials to context
            for cred in result.valid_credentials:
                self.framework.session.credentials.add(
                    cred["username"],
                    cred.get("password", ""),
                    domain=cred.get("domain"),
                    source="credential_spray",
                )

        except KeyboardInterrupt:
            self.display.print_warning("\nSpray interrupted by user")
            spray.stop()
        except Exception as e:
            self.display.print_error(f"Spray error: {e}")
            import traceback
            traceback.print_exc()

        return True

    def _read_file_lines(self, filepath: str) -> list[str]:
        """Read lines from a file."""
        try:
            with open(filepath, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.display.print_error(f"File not found: {filepath}")
            return []

    def _spray_status(self, spray) -> bool:
        """Show spray status."""
        status = spray.get_status()

        self.display.console.print("\n[bold cyan]Spray Status[/bold cyan]")
        self.display.console.print(f"Status: {status['status']}")

        if status['status'] != 'idle':
            self.display.console.print(f"Total attempts: {status['total_attempts']}")
            self.display.console.print(f"Successful: {status['successful']}")
            self.display.console.print(f"Locked accounts: {status['locked_accounts']}")
            self.display.console.print(f"Valid credentials: {status['valid_credentials']}")

        return True

    def _spray_stop(self, spray) -> bool:
        """Stop running spray."""
        spray.stop()
        self.display.print_success("Stop signal sent")
        return True

    def _spray_history(self, spray) -> bool:
        """Show spray history."""
        from rich.table import Table

        if not spray.results:
            self.display.print_warning("No spray history")
            return True

        table = Table(title="Spray History")
        table.add_column("ID", style="cyan")
        table.add_column("Targets", style="green")
        table.add_column("Protocol", style="white")
        table.add_column("Attempts", style="yellow")
        table.add_column("Success", style="bold green")
        table.add_column("Locked", style="red")
        table.add_column("Status", style="dim")

        for result in spray.results[-10:]:  # Last 10
            table.add_row(
                result.id[:15],
                ", ".join(result.targets)[:20],
                result.protocol.value if result.protocol else "-",
                str(result.total_attempts),
                str(result.successful_attempts),
                str(len(result.locked_accounts)),
                result.status.value,
            )

        self.display.console.print(table)

        # Show statistics
        stats = spray.get_statistics()
        self.display.console.print()
        self.display.console.print(f"[bold]Total sprays:[/bold] {stats['total_sprays']}")
        self.display.console.print(f"[bold]Total attempts:[/bold] {stats['total_attempts']}")
        self.display.console.print(f"[bold]Success rate:[/bold] {stats['success_rate']:.1f}%")
        self.display.console.print(f"[bold]Unique valid creds:[/bold] {stats['unique_valid_credentials']}")

        return True

    def _spray_wordlist(self, args: list) -> bool:
        """Generate smart wordlist."""
        from purplesploit.core.credential_spray import PasswordGenerator

        company = None
        usernames = []
        count = 50

        i = 0
        while i < len(args):
            if args[i] == "--company" and i + 1 < len(args):
                company = args[i + 1]
                i += 2
            elif args[i] == "--users" and i + 1 < len(args):
                usernames = args[i + 1].split(",")
                i += 2
            elif args[i] == "--count" and i + 1 < len(args):
                count = int(args[i + 1])
                i += 2
            else:
                i += 1

        wordlist = PasswordGenerator.build_wordlist(
            include_common=True,
            include_seasonal=True,
            company_name=company,
            usernames=usernames,
        )[:count]

        self.display.console.print(f"\n[bold]Generated {len(wordlist)} passwords:[/bold]\n")
        for pwd in wordlist:
            self.display.console.print(f"  {pwd}")

        return True

    def _display_spray_results(self, result) -> bool:
        """Display spray results."""
        from rich.table import Table
        from rich.panel import Panel

        self.display.console.print()
        self.display.console.print("[bold cyan]═══════════════════════════════════════════════════════════════════[/bold cyan]")
        self.display.console.print("[bold white]                    SPRAY RESULTS                                  [/bold white]")
        self.display.console.print("[bold cyan]═══════════════════════════════════════════════════════════════════[/bold cyan]")
        self.display.console.print()

        # Duration
        if result.end_time and result.start_time:
            duration = (result.end_time - result.start_time).total_seconds()
            self.display.console.print(f"[bold]Duration:[/bold] {duration:.1f} seconds")

        self.display.console.print(f"[bold]Total Attempts:[/bold] {result.total_attempts}")
        self.display.console.print(f"[bold]Successful:[/bold] [green]{result.successful_attempts}[/green]")
        self.display.console.print(f"[bold]Locked Accounts:[/bold] [red]{len(result.locked_accounts)}[/red]")
        self.display.console.print(f"[bold]Status:[/bold] {result.status.value}")
        self.display.console.print()

        # Valid credentials
        if result.valid_credentials:
            self.display.console.print("[bold green]Valid Credentials Found:[/bold green]")
            table = Table(show_header=True)
            table.add_column("Username", style="cyan")
            table.add_column("Password", style="green")
            table.add_column("Domain", style="white")
            table.add_column("Target", style="dim")

            for cred in result.valid_credentials:
                table.add_row(
                    cred["username"],
                    cred["password"],
                    cred.get("domain", "-"),
                    cred["target"],
                )

            self.display.console.print(table)
            self.display.console.print()

        # Locked accounts
        if result.locked_accounts:
            self.display.console.print(f"[bold red]Locked Accounts:[/bold red] {', '.join(result.locked_accounts)}")
            self.display.console.print()

        # Errors
        if result.errors:
            self.display.console.print("[bold yellow]Errors:[/bold yellow]")
            for error in result.errors:
                self.display.console.print(f"  • {error}")

        # Suggestions
        if result.valid_credentials:
            self.display.console.print()
            self.display.console.print("[bold]Suggested Next Steps:[/bold]")
            self.display.console.print("  • Use valid credentials: [cyan]creds list[/cyan]")
            self.display.console.print("  • Add to attack graph: [cyan]graph add cred <user> <pass>[/cyan]")
            self.display.console.print("  • Try lateral movement: [cyan]use network/nxc_smb[/cyan]")

        return True

    # =========================================================================
    # Session/Shell Management Commands
    # =========================================================================

    def cmd_sessions(self, args: List[str]) -> bool:
        """
        Session and shell management.

        Usage:
            sessions                       - List all sessions
            sessions list                  - List all sessions
            sessions active                - List active sessions only
            sessions elevated              - List elevated sessions only
            sessions add <type> <host>     - Create a session manually
            sessions select <id>           - Select a session as current
            sessions close <id>            - Close a session
            sessions kill <id>             - Alias for close
            sessions tag <id> <tag>        - Add tag to session
            sessions untag <id> <tag>      - Remove tag from session
            sessions info <id>             - Show session details
            sessions routes                - Show all routes
            sessions route add <sess> <subnet>  - Add route through session
            sessions forwards              - Show port forwards
            sessions forward add <local> <remote_host> <remote_port>
            sessions stats                 - Show statistics
            sessions export [file]         - Export sessions to JSON
            sessions clear                 - Clear all sessions

        Session types: shell, ssh, winrm, meterpreter, beacon, smb_exec, etc.

        Examples:
            sessions add shell 192.168.1.100
            sessions add ssh 10.0.0.1 --user admin --priv high
            sessions select sess:abc123
            sessions tag sess:abc123 dc
            sessions route add sess:abc123 10.10.10.0
        """
        from purplesploit.core.session_manager import (
            SessionManager, create_session_manager,
            SessionType, SessionState, SessionPrivilege
        )

        # Initialize session manager if not exists
        if not hasattr(self, '_session_manager') or self._session_manager is None:
            self._session_manager = create_session_manager(self.framework)

        manager = self._session_manager

        if not args or args[0] == "list":
            return self._sessions_list(manager, "all")

        subcommand = args[0].lower()

        if subcommand == "active":
            return self._sessions_list(manager, "active")
        elif subcommand == "elevated":
            return self._sessions_list(manager, "elevated")
        elif subcommand == "add":
            return self._sessions_add(manager, args[1:])
        elif subcommand == "select":
            return self._sessions_select(manager, args[1:])
        elif subcommand in ["close", "kill"]:
            return self._sessions_close(manager, args[1:])
        elif subcommand == "tag":
            return self._sessions_tag(manager, args[1:], add=True)
        elif subcommand == "untag":
            return self._sessions_tag(manager, args[1:], add=False)
        elif subcommand == "info":
            return self._sessions_info(manager, args[1:])
        elif subcommand == "routes":
            return self._sessions_routes(manager)
        elif subcommand == "route":
            return self._sessions_route(manager, args[1:])
        elif subcommand == "forwards":
            return self._sessions_forwards(manager)
        elif subcommand == "forward":
            return self._sessions_forward(manager, args[1:])
        elif subcommand == "stats":
            return self._sessions_stats(manager)
        elif subcommand == "export":
            return self._sessions_export(manager, args[1:])
        elif subcommand == "clear":
            return self._sessions_clear(manager)
        else:
            self.display.print_error(f"Unknown sessions subcommand: {subcommand}")
            self.display.print_info("Use 'sessions' for usage info")

        return True

    def _sessions_list(self, manager, filter_type: str) -> bool:
        """List sessions."""
        from rich.table import Table

        if filter_type == "active":
            sessions = manager.get_active_sessions()
            title = "Active Sessions"
        elif filter_type == "elevated":
            sessions = manager.get_elevated_sessions()
            title = "Elevated Sessions"
        else:
            sessions = list(manager.sessions.values())
            title = "All Sessions"

        if not sessions:
            self.display.print_warning(f"No {filter_type} sessions")
            return True

        self.display.console.print()
        table = Table(title=title)
        table.add_column("ID", style="cyan")
        table.add_column("Type", style="green")
        table.add_column("Target", style="white")
        table.add_column("User", style="yellow")
        table.add_column("Priv", style="bold")
        table.add_column("State", style="dim")
        table.add_column("Tags", style="magenta")

        current_id = manager._current_session_id

        for session in sessions:
            # Highlight current session
            id_style = "bold cyan" if session.id == current_id else "cyan"
            sess_id = f"* {session.id}" if session.id == current_id else session.id

            # Color privilege
            priv_colors = {
                "low": "dim",
                "medium": "white",
                "high": "yellow",
                "system": "red",
                "domain_admin": "bold red",
            }
            priv = session.privilege.value
            priv_display = f"[{priv_colors.get(priv, 'white')}]{priv}[/{priv_colors.get(priv, 'white')}]"

            # Color state
            state_colors = {
                "active": "green",
                "dormant": "yellow",
                "disconnected": "red",
                "closed": "dim",
            }
            state = session.state.value
            state_display = f"[{state_colors.get(state, 'white')}]{state}[/{state_colors.get(state, 'white')}]"

            user_display = ""
            if session.username:
                if session.domain:
                    user_display = f"{session.domain}\\{session.username}"
                else:
                    user_display = session.username

            table.add_row(
                sess_id,
                session.session_type.value,
                f"{session.target_host}:{session.target_port or '-'}",
                user_display,
                priv_display,
                state_display,
                ", ".join(session.tags) if session.tags else "",
            )

        self.display.console.print(table)

        if current_id:
            self.display.console.print(f"\n[dim]* = current session[/dim]")

        return True

    def _sessions_add(self, manager, args: List[str]) -> bool:
        """Add a session manually."""
        if len(args) < 2:
            self.display.print_error("Usage: sessions add <type> <host> [options]")
            self.display.print_info("Types: shell, ssh, winrm, meterpreter, beacon, smb_exec")
            return True

        session_type = args[0]
        target_host = args[1]

        # Parse options
        target_port = None
        username = None
        domain = None
        privilege = "low"
        os_info = None

        i = 2
        while i < len(args):
            if args[i] in ["-p", "--port"] and i + 1 < len(args):
                target_port = int(args[i + 1])
                i += 2
            elif args[i] in ["-u", "--user"] and i + 1 < len(args):
                username = args[i + 1]
                i += 2
            elif args[i] in ["-d", "--domain"] and i + 1 < len(args):
                domain = args[i + 1]
                i += 2
            elif args[i] == "--priv" and i + 1 < len(args):
                privilege = args[i + 1]
                i += 2
            elif args[i] == "--os" and i + 1 < len(args):
                os_info = args[i + 1]
                i += 2
            else:
                i += 1

        try:
            session = manager.create_session(
                session_type=session_type,
                target_host=target_host,
                target_port=target_port,
                username=username,
                domain=domain,
                privilege=privilege,
                os=os_info,
            )

            self.display.print_success(f"Created session: {session.id}")
            self.display.print_info(f"  Type: {session.session_type.value}")
            self.display.print_info(f"  Target: {target_host}")

        except ValueError as e:
            self.display.print_error(f"Invalid session type: {e}")

        return True

    def _sessions_select(self, manager, args: List[str]) -> bool:
        """Select a session."""
        if not args:
            self.display.print_error("Usage: sessions select <session_id>")
            return True

        session_id = args[0]

        if manager.select_session(session_id):
            session = manager.get_session(session_id)
            self.display.print_success(f"Selected session: {session.display_name}")
        else:
            self.display.print_error(f"Session not found: {session_id}")

        return True

    def _sessions_close(self, manager, args: List[str]) -> bool:
        """Close a session."""
        if not args:
            self.display.print_error("Usage: sessions close <session_id>")
            return True

        session_id = args[0]

        if manager.close_session(session_id):
            self.display.print_success(f"Closed session: {session_id}")
        else:
            self.display.print_error(f"Session not found: {session_id}")

        return True

    def _sessions_tag(self, manager, args: List[str], add: bool) -> bool:
        """Add or remove tag from session."""
        if len(args) < 2:
            cmd = "tag" if add else "untag"
            self.display.print_error(f"Usage: sessions {cmd} <session_id> <tag>")
            return True

        session_id = args[0]
        tag = args[1]

        if add:
            if manager.add_tag(session_id, tag):
                self.display.print_success(f"Added tag '{tag}' to {session_id}")
            else:
                self.display.print_error(f"Session not found: {session_id}")
        else:
            if manager.remove_tag(session_id, tag):
                self.display.print_success(f"Removed tag '{tag}' from {session_id}")
            else:
                self.display.print_error(f"Session not found or tag not present")

        return True

    def _sessions_info(self, manager, args: List[str]) -> bool:
        """Show session details."""
        if not args:
            # Show current session if set
            session = manager.current_session
            if not session:
                self.display.print_error("Usage: sessions info <session_id>")
                return True
        else:
            session = manager.get_session(args[0])

        if not session:
            self.display.print_error(f"Session not found: {args[0]}")
            return True

        self.display.console.print()
        self.display.console.print(f"[bold cyan]Session: {session.id}[/bold cyan]")
        self.display.console.print()
        self.display.console.print(f"[bold]Type:[/bold] {session.session_type.value}")
        self.display.console.print(f"[bold]Target:[/bold] {session.target_host}:{session.target_port or '-'}")
        self.display.console.print(f"[bold]State:[/bold] {session.state.value}")
        self.display.console.print(f"[bold]Privilege:[/bold] {session.privilege.value}")

        if session.username:
            user = f"{session.domain}\\{session.username}" if session.domain else session.username
            self.display.console.print(f"[bold]User:[/bold] {user}")

        if session.os:
            self.display.console.print(f"[bold]OS:[/bold] {session.os}")
        if session.arch:
            self.display.console.print(f"[bold]Arch:[/bold] {session.arch}")
        if session.process_name:
            self.display.console.print(f"[bold]Process:[/bold] {session.process_name} (PID: {session.process_id})")

        self.display.console.print(f"[bold]Established:[/bold] {session.established_at}")
        if session.last_checkin:
            self.display.console.print(f"[bold]Last Checkin:[/bold] {session.last_checkin}")

        if session.tags:
            self.display.console.print(f"[bold]Tags:[/bold] {', '.join(session.tags)}")
        if session.notes:
            self.display.console.print(f"[bold]Notes:[/bold] {session.notes}")

        # Show routes through this session
        routes = manager.get_routes_for_session(session.id)
        if routes:
            self.display.console.print(f"\n[bold]Routes ({len(routes)}):[/bold]")
            for route in routes:
                self.display.console.print(f"  • {route.subnet}/{route.netmask}")

        return True

    def _sessions_routes(self, manager) -> bool:
        """Show all routes."""
        from rich.table import Table

        routes = list(manager.routes.values())

        if not routes:
            self.display.print_warning("No routes configured")
            return True

        table = Table(title="Network Routes")
        table.add_column("ID", style="cyan")
        table.add_column("Session", style="green")
        table.add_column("Subnet", style="white")
        table.add_column("Netmask", style="dim")
        table.add_column("Active", style="bold")

        for route in routes:
            active = "[green]Yes[/green]" if route.active else "[red]No[/red]"
            table.add_row(
                route.id,
                route.session_id,
                route.subnet,
                route.netmask,
                active,
            )

        self.display.console.print(table)
        return True

    def _sessions_route(self, manager, args: List[str]) -> bool:
        """Manage routes."""
        if not args:
            self.display.print_error("Usage: sessions route <add|remove> ...")
            return True

        action = args[0].lower()

        if action == "add":
            if len(args) < 3:
                self.display.print_error("Usage: sessions route add <session_id> <subnet> [netmask]")
                return True

            session_id = args[1]
            subnet = args[2]
            netmask = args[3] if len(args) > 3 else "255.255.255.0"

            route = manager.add_route(session_id, subnet, netmask)
            if route:
                self.display.print_success(f"Added route: {route.id}")
            else:
                self.display.print_error("Failed to add route. Session may not be active.")

        elif action == "remove":
            if len(args) < 2:
                self.display.print_error("Usage: sessions route remove <route_id>")
                return True

            if manager.remove_route(args[1]):
                self.display.print_success(f"Removed route: {args[1]}")
            else:
                self.display.print_error(f"Route not found: {args[1]}")

        return True

    def _sessions_forwards(self, manager) -> bool:
        """Show port forwards."""
        from rich.table import Table

        forwards = list(manager.port_forwards.values())

        if not forwards:
            self.display.print_warning("No port forwards configured")
            return True

        table = Table(title="Port Forwards")
        table.add_column("ID", style="cyan")
        table.add_column("Local", style="green")
        table.add_column("Remote", style="white")
        table.add_column("Direction", style="dim")
        table.add_column("Active", style="bold")

        for fwd in forwards:
            active = "[green]Yes[/green]" if fwd.active else "[red]No[/red]"
            table.add_row(
                fwd.id,
                f"{fwd.local_host}:{fwd.local_port}",
                f"{fwd.remote_host}:{fwd.remote_port}",
                fwd.direction,
                active,
            )

        self.display.console.print(table)
        return True

    def _sessions_forward(self, manager, args: List[str]) -> bool:
        """Manage port forwards."""
        if not args:
            self.display.print_error("Usage: sessions forward <add|remove|start|stop> ...")
            return True

        action = args[0].lower()

        if action == "add":
            if len(args) < 4:
                self.display.print_error("Usage: sessions forward add <local_port> <remote_host> <remote_port>")
                return True

            local_port = int(args[1])
            remote_host = args[2]
            remote_port = int(args[3])

            fwd = manager.create_port_forward(local_port, remote_host, remote_port)
            self.display.print_success(f"Created port forward: {fwd.id}")
            self.display.print_info(f"  {fwd.local_host}:{fwd.local_port} → {fwd.remote_host}:{fwd.remote_port}")

        elif action == "start":
            if len(args) < 2:
                self.display.print_error("Usage: sessions forward start <forward_id>")
                return True

            if manager.start_port_forward(args[1]):
                self.display.print_success(f"Started port forward: {args[1]}")
            else:
                self.display.print_error(f"Forward not found: {args[1]}")

        elif action == "stop":
            if len(args) < 2:
                self.display.print_error("Usage: sessions forward stop <forward_id>")
                return True

            if manager.stop_port_forward(args[1]):
                self.display.print_success(f"Stopped port forward: {args[1]}")
            else:
                self.display.print_error(f"Forward not found: {args[1]}")

        elif action == "remove":
            if len(args) < 2:
                self.display.print_error("Usage: sessions forward remove <forward_id>")
                return True

            if manager.remove_port_forward(args[1]):
                self.display.print_success(f"Removed port forward: {args[1]}")
            else:
                self.display.print_error(f"Forward not found: {args[1]}")

        return True

    def _sessions_stats(self, manager) -> bool:
        """Show session statistics."""
        from rich.table import Table

        stats = manager.get_statistics()

        self.display.console.print()
        self.display.console.print("[bold cyan]Session Statistics[/bold cyan]")
        self.display.console.print()

        table = Table(show_header=False, box=None)
        table.add_column("Metric", style="bold")
        table.add_column("Value", style="cyan")

        table.add_row("Total Sessions", str(stats["total_sessions"]))
        table.add_row("Active Sessions", str(stats["active_sessions"]))
        table.add_row("Elevated Sessions", f"[yellow]{stats['elevated_sessions']}[/yellow]")
        table.add_row("", "")
        table.add_row("Total Routes", str(stats["total_routes"]))
        table.add_row("Active Routes", str(stats["active_routes"]))
        table.add_row("", "")
        table.add_row("Port Forwards", str(stats["port_forwards"]))
        table.add_row("Active Forwards", str(stats["active_forwards"]))

        self.display.console.print(table)

        # Sessions by type
        if stats["by_type"]:
            self.display.console.print("\n[bold]By Type:[/bold]")
            for t, count in stats["by_type"].items():
                self.display.console.print(f"  {t}: {count}")

        # Sessions by host
        if stats["by_host"]:
            self.display.console.print("\n[bold]By Host:[/bold]")
            for h, count in stats["by_host"].items():
                self.display.console.print(f"  {h}: {count}")

        return True

    def _sessions_export(self, manager, args: List[str]) -> bool:
        """Export sessions to JSON."""
        filename = args[0] if args else None

        json_data = manager.to_json(indent=2)

        if filename:
            with open(filename, 'w') as f:
                f.write(json_data)
            self.display.print_success(f"Exported sessions to {filename}")
        else:
            self.display.console.print(json_data)

        return True

    def _sessions_clear(self, manager) -> bool:
        """Clear all sessions."""
        manager.clear()
        self.display.print_success("All sessions cleared")
        return True

    def cmd_interact(self, args: List[str]) -> bool:
        """
        Interact with a session.

        Usage:
            interact                   - Interact with current session
            interact <session_id>      - Interact with specific session
            interact -c <command>      - Execute single command

        Examples:
            interact sess:abc123
            interact -c whoami
        """
        from purplesploit.core.session_manager import SessionInteraction

        # Get session manager
        if not hasattr(self, '_session_manager') or self._session_manager is None:
            self.display.print_error("No sessions available. Create one with 'sessions add'")
            return True

        manager = self._session_manager

        # Parse args
        session_id = None
        command = None

        if args:
            if args[0] == "-c" and len(args) > 1:
                command = " ".join(args[1:])
            else:
                session_id = args[0]
                if len(args) > 2 and args[1] == "-c":
                    command = " ".join(args[2:])

        # Get session
        if session_id:
            session = manager.get_session(session_id)
        else:
            session = manager.current_session

        if not session:
            self.display.print_error("No session specified. Use 'interact <session_id>' or 'sessions select <id>'")
            return True

        if not session.is_active:
            self.display.print_error(f"Session {session.id} is not active (state: {session.state.value})")
            return True

        interaction = SessionInteraction(session, self.framework)

        if command:
            # Execute single command
            result = interaction.execute(command)
            if result.get("output"):
                self.display.console.print(result["output"])
            if result.get("error"):
                self.display.print_error(result["error"])
        else:
            # Interactive mode info
            self.display.console.print()
            self.display.console.print(f"[bold cyan]Interacting with: {session.display_name}[/bold cyan]")
            self.display.console.print(f"Session ID: {session.id}")
            self.display.console.print(f"Type: {session.session_type.value}")
            self.display.console.print()
            self.display.print_info("Use 'interact -c <command>' to execute commands")
            self.display.print_info("Interactive shell mode is available for real sessions")

        return True
