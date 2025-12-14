"""
Module-related commands for PurpleSploit.

Handles module search, selection, loading, and execution.
"""

from typing import List, Any


class ModuleCommandsMixin:
    """
    Mixin providing module-related commands.

    Requires:
        - self.framework: Framework instance
        - self.display: Display instance
        - self.interactive: InteractiveSelector instance
        - self.last_search_results: List for storing search results
        - self.last_ops_results: List for storing operation results
        - self.service_shortcuts: Dict mapping service names to module paths
    """

    def _init_module_commands(self):
        """Register module-related commands."""
        self.register_command("search", self.cmd_search)
        self.register_command("module", self.cmd_module)
        self.register_command("use", self.cmd_use)
        self.register_command("back", self.cmd_back)
        self.register_command("info", self.cmd_info)
        self.register_command("options", self.cmd_options)
        self.register_command("show", self.cmd_show)
        self.register_command("set", self.cmd_set)
        self.register_command("unset", self.cmd_unset)
        self.register_command("run", self.cmd_run, aliases=["exploit"])
        self.register_command("check", self.cmd_check)
        self.register_command("ops", self.cmd_ops)
        self.register_command("recent", self.cmd_recent)
        self.register_command("operations", self.cmd_show_ops, aliases=["l"])

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
            return self._use_with_filter(args)

        module_identifier = args[0]
        module_path = self._resolve_module_path(module_identifier)

        if module_path is None:
            return True  # Error already printed

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

    def _use_with_filter(self, args: List[str]) -> bool:
        """Handle 'use smb auth' style commands."""
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

        # Fall through to regular use if no results
        return self.cmd_use([args[0]])

    def _resolve_module_path(self, module_identifier: str) -> str:
        """Resolve a module identifier to a path."""
        # Check if it's a service shortcut
        if module_identifier.lower() in self.service_shortcuts:
            return self.service_shortcuts[module_identifier.lower()]

        # Check if it's a number (selecting from search results or ops results)
        if module_identifier.isdigit():
            index = int(module_identifier) - 1  # Convert to 0-based index

            # Check for module search results first
            if self.last_search_results:
                if index < 0 or index >= len(self.last_search_results):
                    self.display.print_error(f"Invalid number. Must be 1-{len(self.last_search_results)}")
                    return None
                return self.last_search_results[index].path

            # Fall back to ops search results if available
            elif self.last_ops_results:
                if index < 0 or index >= len(self.last_ops_results):
                    self.display.print_error(f"Invalid number. Must be 1-{len(self.last_ops_results)}")
                    return None
                self.display.print_info(f"Loading module from operation result: {self.last_ops_results[index]['module']}")
                return self.last_ops_results[index]['module_path']

            else:
                self.display.print_error("No search or ops results available. Run 'search' or 'ops' first")
                return None

        return module_identifier

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

    def cmd_check(self, args: List[str]) -> bool:
        """Check if module can run."""
        module = self.framework.session.current_module
        if not module:
            self.display.print_error("No module loaded. Use 'use <module>' first")
            return True

        is_valid, errors = module.validate()
        if is_valid:
            self.display.print_success("Module is ready to run")
        else:
            self.display.print_error("Module validation failed:")
            for error in errors:
                self.display.print_error(f"  - {error}")

        return True

    def cmd_run(self, args: List[str]) -> bool:
        """Run the current module or a specific operation."""
        module = self.framework.session.current_module

        # If no module loaded, check if we can run from last ops results
        if not module:
            if args and args[0].isdigit() and self.last_ops_results:
                return self._run_from_ops_results(args)

            self.display.print_error("No module loaded. Use 'use <module>' first")
            return True

        # Module with operations
        if module.has_operations():
            return self._run_operation(module, args)

        # Simple module - just run it
        return self._run_simple_module(module)

    def _run_from_ops_results(self, args: List[str]) -> bool:
        """Run an operation from the last ops results."""
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
            else:
                self.display.print_error(f"Operation '{result['operation']}' not found")
        else:
            self.display.print_error(f"Invalid number. Must be 1-{len(self.last_ops_results)}")

        return True

    def _run_operation(self, module: Any, args: List[str]) -> bool:
        """Run an operation from a module with operations."""
        operations = module.get_operations()

        if args:
            # User specified an operation
            op_identifier = args[0]

            # Check if it's a number
            if op_identifier.isdigit():
                op_index = int(op_identifier) - 1
                if 0 <= op_index < len(operations):
                    operation = operations[op_index]
                    results = self._execute_operation(module, operation)
                    self.display.print_results(results)
                else:
                    self.display.print_error(f"Invalid operation number. Must be 1-{len(operations)}")
            else:
                # Try to find by name
                operation = None
                for op in operations:
                    if op['name'].lower() == op_identifier.lower():
                        operation = op
                        break

                if operation:
                    results = self._execute_operation(module, operation)
                    self.display.print_results(results)
                else:
                    self.display.print_error(f"Operation not found: {op_identifier}")
                    self.display.print_info("Use 'l' or 'operations' to see available operations")
        else:
            # Interactive operation selection
            selected_operation = self.interactive.select_operation(operations)
            if selected_operation:
                results = self._execute_operation(module, selected_operation)
                self.display.print_results(results)
            else:
                self.display.print_warning("No operation selected")

        return True

    def _run_simple_module(self, module: Any) -> bool:
        """Run a simple module without operations."""
        is_valid, errors = module.validate()
        if not is_valid:
            self.display.print_error("Module validation failed:")
            for error in errors:
                self.display.print_error(f"  - {error}")
            return True

        self.display.print_info(f"Running module: {module.name}")
        results = module.run()
        self.display.print_results(results)
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
            self._show_filtered_operations(module, operations, filter_term)
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

    def _show_filtered_operations(self, module: Any, operations: List[dict], filter_term: str):
        """Show operations filtered by subcategory or search term."""
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

    def cmd_ops(self, args: List[str]) -> bool:
        """Search operations globally across all modules."""
        if not args:
            self.display.print_error("Usage: ops <query>")
            self.display.print_info("       ops select  # Interactive operation selection")
            return True

        if args[0].lower() == "select":
            return self._ops_select()

        query = " ".join(args).lower()
        return self._ops_search(query)

    def _ops_select(self) -> bool:
        """Interactive operation selection."""
        # Gather all operations from all modules
        all_ops = []
        for module_info in self.framework.list_modules():
            module = self.framework.load_module(module_info.path)
            if module and module.has_operations():
                for op in module.get_operations():
                    all_ops.append({
                        'module': module_info.name,
                        'module_path': module_info.path,
                        'operation': op['name'],
                        'description': op['description']
                    })

        if not all_ops:
            self.display.print_warning("No operations found in any module")
            return True

        # Store for number selection
        self.last_ops_results = all_ops

        # Use interactive selector
        selected = self.interactive.select_from_list(
            [f"{op['module']}:{op['operation']} - {op['description']}" for op in all_ops],
            "Select operation"
        )
        if selected:
            # Find the matching operation
            for op in all_ops:
                if f"{op['module']}:{op['operation']}" in selected:
                    self.cmd_use([op['module_path']])
                    return self.cmd_run([op['operation']])

        return True

    def _ops_search(self, query: str) -> bool:
        """Search for operations matching a query."""
        results = []
        for module_info in self.framework.list_modules():
            module = self.framework.load_module(module_info.path)
            if module and module.has_operations():
                for op in module.get_operations():
                    if query in op['name'].lower() or query in op['description'].lower():
                        results.append({
                            'module': module_info.name,
                            'module_path': module_info.path,
                            'operation': op['name'],
                            'description': op['description']
                        })

        if results:
            self.last_ops_results = results
            self.display.print_ops_table(results)
            self.display.print_info("\nTip: Use 'use <number>' to load module or 'run <number>' to execute directly")
        else:
            self.display.print_warning(f"No operations found matching: {query}")

        return True

    def cmd_recent(self, args: List[str]) -> bool:
        """Show recently used modules."""
        if args and args[0].lower() == "select":
            # Interactive selection from recent
            recent = self.framework.get_recent_modules(20)
            if not recent:
                self.display.print_warning("No recently used modules")
                return True

            selected = self.interactive.select_from_list(
                [m.path for m in recent],
                "Select recent module"
            )
            if selected:
                return self.cmd_use([selected])
            return True

        recent = self.framework.get_recent_modules(10)
        if not recent:
            self.display.print_warning("No recently used modules")
            return True

        self.last_search_results = recent
        self.display.print_modules_table(recent)
        self.display.print_info("\nTip: Use 'use <number>' to load or 'recent select' for interactive selection")
        return True
