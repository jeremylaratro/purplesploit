"""
Context-related commands for PurpleSploit.

Handles targets, credentials, services, wordlists, and analysis.
"""

from typing import List, Dict, Any


class ContextCommandsMixin:
    """
    Mixin providing context management commands.

    Requires:
        - self.framework: Framework instance
        - self.display: Display instance
        - self.interactive: InteractiveSelector instance
    """

    def _init_context_commands(self):
        """Register context-related commands."""
        self.register_command("targets", self.cmd_targets)
        self.register_command("creds", self.cmd_creds)
        self.register_command("services", self.cmd_services)
        self.register_command("wordlists", self.cmd_wordlists)
        self.register_command("analysis", self.cmd_analysis, aliases=["webresults"])
        self.register_command("target", self.cmd_target_quick)
        self.register_command("cred", self.cmd_cred_quick)
        self.register_command("go", self.cmd_go)
        self.register_command("quick", self.cmd_quick)

    def cmd_targets(self, args: List[str]) -> bool:
        """Manage targets."""
        if not args or args[0] == "list":
            targets = self.framework.session.targets.list()
            self.display.print_targets_table(targets)
            return True

        subcommand = args[0].lower()

        # Handle "targets clear" - clear all
        if subcommand == "clear":
            count = self.framework.session.targets.clear()
            self.framework.database.clear_all_targets()

            try:
                from purplesploit.models.database import db_manager
                db_manager.clear_all_targets()
            except Exception as e:
                self.display.print_warning(f"Could not clear dashboard targets: {e}")

            self.display.print_success(f"Cleared {count} target(s) from session and databases")
            return True

        # Handle index or range operations
        if subcommand.isdigit() or '-' in subcommand:
            return self._handle_target_index_operation(subcommand, args)

        # Subcommands
        if subcommand == "add":
            return self._targets_add(args)
        elif subcommand == "select":
            return self._targets_select()
        elif subcommand == "set":
            return self._targets_set(args)
        elif subcommand == "remove":
            return self._targets_remove(args)
        elif subcommand == "modify":
            return self._targets_modify_interactive()
        else:
            self.display.print_error(f"Unknown subcommand: {subcommand}")
            self.display.print_info("Usage: targets [list|add|set|select|modify|remove|clear|<index> clear|<range> clear|<index> modify]")

        return True

    def _handle_target_index_operation(self, subcommand: str, args: List[str]) -> bool:
        """Handle targets by index or range."""
        if len(args) < 2:
            self.display.print_error("Usage: targets <index|range> <clear|modify> [options]")
            return True

        action = args[1].lower()

        if action == "clear":
            if '-' in subcommand:
                try:
                    start, end = subcommand.split('-')
                    count = self.framework.session.targets.remove_range(int(start), int(end))
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

    def _targets_add(self, args: List[str]) -> bool:
        """Add a target."""
        if len(args) < 2:
            self.display.print_error("Usage: targets add <ip|url> [name]")
            return True

        identifier = args[1]
        name = args[2] if len(args) > 2 else None
        target_type = "web" if identifier.startswith("http") else "network"
        was_empty = len(self.framework.session.targets.list()) == 0

        if self.framework.add_target(target_type, identifier, name):
            self.display.print_success(f"Added target: {identifier}")

            if was_empty:
                target = self.framework.session.targets.get_current()
                if target:
                    self.display.print_info(f"Auto-selected first target: {identifier}")
                    self._auto_set_target_in_module(target)
        else:
            self.display.print_warning("Target already exists")

        return True

    def _targets_select(self) -> bool:
        """Interactive target selection."""
        targets = self.framework.session.targets.list()
        if not targets:
            self.display.print_warning("No targets available. Add targets first with 'targets add'")
            return True

        selected = self.interactive.select_target(targets)
        if selected:
            for i, target in enumerate(targets):
                if target == selected:
                    self.framework.session.targets.current_index = i
                    identifier = selected.get('ip') or selected.get('url')
                    self.display.print_success(f"Selected target: {identifier}")
                    self._auto_set_target_in_module(selected)
                    break
        else:
            self.display.print_warning("No target selected")

        return True

    def _targets_set(self, args: List[str]) -> bool:
        """Set current target."""
        if len(args) < 2:
            self.display.print_error("Usage: targets set <index|identifier>")
            return True

        if self.framework.session.targets.set_current(args[1]):
            target = self.framework.session.targets.get_current()
            identifier = target.get('ip') or target.get('url')
            self.display.print_success(f"Current target set to: {identifier}")
            self._auto_set_target_in_module(target)
        else:
            self.display.print_error("Target not found")

        return True

    def _targets_remove(self, args: List[str]) -> bool:
        """Remove a target."""
        if len(args) < 2:
            self.display.print_error("Usage: targets remove <identifier>")
            return True

        if self.framework.session.targets.remove(args[1]):
            self.display.print_success(f"Removed target: {args[1]}")
        else:
            self.display.print_error("Target not found")

        return True

    def _targets_modify_interactive(self) -> bool:
        """Interactive target modification."""
        targets = self.framework.session.targets.list()
        if not targets:
            self.display.print_warning("No targets available. Add targets first with 'targets add' or 'target'")
            return True

        self.display.print_info("Select target to modify:")
        selected = self.interactive.select_target(targets)
        if not selected:
            self.display.print_warning("No target selected")
            return True

        # Find index
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
        self.display.print_info(f"\nModifying target: {selected_id}")
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

        return True

    def _auto_set_target_in_module(self, target: Dict) -> None:
        """Auto-set target values in the current module."""
        module = self.framework.session.current_module
        if not module:
            return

        target_value = target.get('ip') or target.get('url')

        if 'ip' in target and "RHOST" in module.options:
            module.set_option("RHOST", target['ip'])
            self.display.print_info(f"  → Set RHOST = {target['ip']}")

        if target_value and "TARGET" in module.options:
            module.set_option("TARGET", target_value)
            self.display.print_info(f"  → Set TARGET = {target_value}")

        if 'url' in target and "URL" in module.options:
            module.set_option("URL", target['url'])
            self.display.print_info(f"  → Set URL = {target['url']}")

    def cmd_creds(self, args: List[str]) -> bool:
        """Manage credentials."""
        if not args or args[0] == "list":
            creds = self.framework.session.credentials.list()
            self.display.print_credentials_table(creds)
            return True

        subcommand = args[0].lower()

        if subcommand == "clear":
            count = self.framework.session.credentials.clear()
            self.display.print_success(f"Cleared {count} credential(s)")
            return True

        # Handle index or range operations
        if subcommand.isdigit() or '-' in subcommand:
            return self._handle_cred_index_operation(subcommand, args)

        if subcommand == "add":
            return self._creds_add(args)
        elif subcommand == "select":
            return self._creds_select()
        elif subcommand == "set":
            return self._creds_set(args)
        elif subcommand == "remove":
            return self._creds_remove(args)
        elif subcommand == "modify":
            return self._creds_modify_interactive()
        else:
            self.display.print_error(f"Unknown subcommand: {subcommand}")
            self.display.print_info("Usage: creds [list|add|set|select|modify|remove|clear|<index> clear|<range> clear|<index> modify]")

        return True

    def _handle_cred_index_operation(self, subcommand: str, args: List[str]) -> bool:
        """Handle credentials by index or range."""
        if len(args) < 2:
            self.display.print_error("Usage: creds <index|range> <clear|modify> [options]")
            return True

        action = args[1].lower()

        if action == "clear":
            if '-' in subcommand:
                try:
                    start, end = subcommand.split('-')
                    count = self.framework.session.credentials.remove_range(int(start), int(end))
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

    def _creds_add(self, args: List[str]) -> bool:
        """Add a credential."""
        if len(args) < 2:
            self.display.print_error("Usage: creds add <username>:<password> [domain]")
            return True

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

        return True

    def _creds_select(self) -> bool:
        """Interactive credential selection."""
        creds = self.framework.session.credentials.list()
        selected = self.interactive.select_credential(creds)

        if selected == "ADD_NEW":
            return self._creds_add_interactive()

        if selected and selected != "ADD_NEW":
            for i, cred in enumerate(creds):
                if cred == selected:
                    self.framework.session.credentials.current_index = i
                    self.display.print_success(f"Selected credential: {selected['username']}")
                    self._auto_set_cred_in_module(selected)
                    break
        elif not selected:
            self.display.print_warning("No credential selected")

        return True

    def _creds_add_interactive(self) -> bool:
        """Interactively add a new credential."""
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

            creds = self.framework.session.credentials.list()
            if creds:
                self.framework.session.credentials.current_index = len(creds) - 1
                self._auto_set_cred_in_module(creds[-1])
        else:
            self.display.print_warning("Failed to add credential")

        return True

    def _creds_set(self, args: List[str]) -> bool:
        """Set current credential."""
        if len(args) < 2:
            self.display.print_error("Usage: creds set <index|username>")
            return True

        if self.framework.session.credentials.set_current(args[1]):
            cred = self.framework.session.credentials.get_current()
            self.display.print_success(f"Current credential set to: {cred['username']}")
        else:
            self.display.print_error("Credential not found")

        return True

    def _creds_remove(self, args: List[str]) -> bool:
        """Remove a credential."""
        if len(args) < 2:
            self.display.print_error("Usage: creds remove <identifier>")
            return True

        if self.framework.session.credentials.remove(args[1]):
            self.display.print_success(f"Removed credential: {args[1]}")
        else:
            self.display.print_error("Credential not found")

        return True

    def _creds_modify_interactive(self) -> bool:
        """Interactive credential modification."""
        creds = self.framework.session.credentials.list()
        if not creds:
            self.display.print_warning("No credentials available. Add credentials first with 'creds add'")
            return True

        self.display.print_info("Select credential to modify:")
        selected = self.interactive.select_credential(creds, allow_add_new=False)
        if not selected or selected == "ADD_NEW":
            self.display.print_warning("No credential selected")
            return True

        # Find index
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

        return True

    def _auto_set_cred_in_module(self, cred: Dict) -> None:
        """Auto-set credential values in the current module."""
        module = self.framework.session.current_module
        if not module:
            return

        if "USERNAME" in module.options:
            module.set_option("USERNAME", cred['username'])
            self.display.print_info(f"  → Set USERNAME = {cred['username']}")
        if cred.get('password') and "PASSWORD" in module.options:
            module.set_option("PASSWORD", cred['password'])
            self.display.print_info(f"  → Set PASSWORD = ****")
        if cred.get('domain') and "DOMAIN" in module.options:
            module.set_option("DOMAIN", cred['domain'])
            self.display.print_info(f"  → Set DOMAIN = {cred['domain']}")
        if cred.get('dcip') and "DCIP" in module.options:
            module.set_option("DCIP", cred['dcip'])
            self.display.print_info(f"  → Set DCIP = {cred['dcip']}")
        if cred.get('dns') and "DNS" in module.options:
            module.set_option("DNS", cred['dns'])
            self.display.print_info(f"  → Set DNS = {cred['dns']}")
        if cred.get('hash') and "HASH" in module.options:
            module.set_option("HASH", cred['hash'])
            self.display.print_info(f"  → Set HASH = ****")

    def cmd_services(self, args: List[str]) -> bool:
        """View detected services."""
        if args and args[0].lower() == "clear":
            count = self.framework.session.services.clear()
            self.framework.database.clear_all_services()

            try:
                from purplesploit.models.database import db_manager
                db_manager.clear_all_services()
            except Exception as e:
                self.display.print_warning(f"Could not clear dashboard services: {e}")

            self.display.print_success(f"Cleared {count} service target(s) from session and databases")
            return True

        if args and args[0].lower() == "select":
            services = self.framework.session.services.services
            if not services:
                self.display.print_warning("No services available")
                return True

            selected = self.interactive.select_service(services)
            if selected:
                self.display.print_success(f"Selected service: {selected.get('target')}:{selected.get('port')} - {selected.get('name')}")

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

        # Display results
        self.display.console.print("\n[bold cyan]═══ Web Scan Analysis Results ═══[/bold cyan]\n")

        for target, scans in results_by_target.items():
            target_info = f"[bold yellow]Target:[/bold yellow] {target}\n"
            target_info += f"[bold yellow]Total Scans:[/bold yellow] {len(scans)}\n\n"

            table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
            table.add_column("Scan Type", style="green", width=15)
            table.add_column("Timestamp", style="dim", width=20)
            table.add_column("Status", style="yellow", width=12)
            table.add_column("Findings", style="white")
            table.add_column("Log File", style="blue")

            for scan in scans:
                scan_name = scan['scan_name']
                timestamp = scan.get('timestamp', 'Unknown')
                status = scan.get('status', 'Unknown')
                log_file = scan.get('log_file', '')

                # Parse findings from data
                data = scan.get('data', {})
                findings = ""
                if isinstance(data, dict):
                    if 'urls_found' in data:
                        findings = f"{len(data['urls_found'])} URLs"
                    elif 'results' in data:
                        findings = f"{len(data['results'])} results"

                table.add_row(scan_name, str(timestamp), status, findings, log_file)

            self.display.console.print(Panel(target_info + "", title=f"[bold]{target}[/bold]",
                                             border_style="cyan", box=box.ROUNDED))
            self.display.console.print(table)
            self.display.console.print()

        return True

    def cmd_target_quick(self, args: List[str]) -> bool:
        """Quick target add and set."""
        if not args:
            self.display.print_error("Usage: target <ip|url>")
            return True

        identifier = args[0]
        target_type = "web" if identifier.startswith("http") else "network"

        self.framework.add_target(target_type, identifier)
        self.framework.session.targets.set_current(identifier)
        target = self.framework.session.targets.get_current()

        self.display.print_success(f"Target set to: {identifier}")
        self._auto_set_target_in_module(target)

        return True

    def cmd_cred_quick(self, args: List[str]) -> bool:
        """Quick credential add and set."""
        if not args:
            self.display.print_error("Usage: cred <username:password> [domain]")
            return True

        if ":" in args[0]:
            username, password = args[0].split(":", 1)
        else:
            username = args[0]
            password = None

        domain = args[1] if len(args) > 1 else None

        self.framework.add_credential(username, password, domain)
        self.framework.session.credentials.set_current(username)
        cred = self.framework.session.credentials.get_current()

        self.display.print_success(f"Credential set to: {username}")
        self._auto_set_cred_in_module(cred)

        return True

    def cmd_go(self, args: List[str]) -> bool:
        """All-in-one quick workflow."""
        if len(args) < 2:
            self.display.print_error("Usage: go <target> <user:pass> [operation]")
            return True

        # Set target
        self.cmd_target_quick([args[0]])

        # Set credential
        self.cmd_cred_quick([args[1]])

        # Run operation if specified
        if len(args) >= 3:
            operation = args[2]
            return self.cmd_run([operation])

        return True

    def cmd_quick(self, args: List[str]) -> bool:
        """Quick module load with auto-populate."""
        if not args:
            self.display.print_error("Usage: quick <module_shortcut> [operation_filter]")
            self.display.print_info("Shortcuts: smb, ldap, winrm, mssql, rdp, ssh, nmap, ferox, sqlmap, wfuzz, httpx")
            return True

        # Use cmd_use to handle the module loading
        return self.cmd_use(args)
