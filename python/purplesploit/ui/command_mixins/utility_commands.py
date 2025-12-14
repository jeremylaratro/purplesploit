"""
Utility commands for PurpleSploit.

Handles help, history, stats, shell, webserver, and other utilities.
"""

from typing import List, Dict, Any
from pathlib import Path


class UtilityCommandsMixin:
    """
    Mixin providing utility commands.

    Requires:
        - self.framework: Framework instance
        - self.display: Display instance
        - self.webserver_process: Process instance (or None)
    """

    def _init_utility_commands(self):
        """Register utility commands."""
        self.register_command("help", self.cmd_help, aliases=["?"])
        self.register_command("clear", self.cmd_clear)
        self.register_command("history", self.cmd_history)
        self.register_command("stats", self.cmd_stats)
        self.register_command("hosts", self.cmd_hosts)
        self.register_command("ligolo", self.cmd_ligolo)
        self.register_command("shell", self.cmd_shell)
        self.register_command("webserver", self.cmd_webserver)
        self.register_command("deploy", self.cmd_deploy)
        self.register_command("defaults", self.cmd_defaults)
        self.register_command("parse", self.cmd_parse)
        self.register_command("exit", self.cmd_exit, aliases=["quit"])

    def cmd_help(self, args: List[str]) -> bool:
        """Show help information with enhanced visual layout."""
        from rich.panel import Panel
        from rich.columns import Columns
        from rich import box

        self.display.console.print()
        self.display.console.print("[bold magenta]" + "=" * 67 + "[/bold magenta]")
        self.display.console.print("[bold cyan]                        PURPLESPLOIT HELP                          [/bold cyan]")
        self.display.console.print("[bold magenta]" + "=" * 67 + "[/bold magenta]")
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
        self.display.console.print(Panel(module_help, title="[bold cyan]Module Commands[/bold cyan]",
                                         border_style="cyan", box=box.ROUNDED, padding=(1, 2)))
        self.display.console.print()

        # Search panel (full width)
        self.display.console.print(Panel(search_help, title="[bold cyan]Smart Search[/bold cyan]",
                                         border_style="cyan", box=box.ROUNDED, padding=(1, 2)))
        self.display.console.print()

        # Two column layout for context management
        col1 = Panel(context_basic, title="[bold green]Targets & Credentials[/bold green]",
                    border_style="green", box=box.ROUNDED, padding=(1, 2))
        col2 = Panel(context_resources, title="[bold green]Resources & Services[/bold green]",
                    border_style="green", box=box.ROUNDED, padding=(1, 2))
        self.display.console.print(Columns([col1, col2], equal=True, expand=True))
        self.display.console.print()

        # Two column layout for shortcuts and show
        col3 = Panel(shortcuts_help, title="[bold yellow]Quick Shortcuts[/bold yellow]",
                    border_style="yellow", box=box.ROUNDED, padding=(1, 2))
        col4 = Panel(show_help, title="[bold magenta]Show Commands[/bold magenta]",
                    border_style="magenta", box=box.ROUNDED, padding=(1, 2))
        self.display.console.print(Columns([col3, col4], equal=True, expand=True))
        self.display.console.print()

        # Full width utility panel
        self.display.console.print(Panel(utility_help, title="[bold blue]Utility Commands[/bold blue]",
                                         border_style="blue", box=box.ROUNDED, padding=(1, 2)))

        self.display.console.print()
        self.display.console.print("[dim cyan]Tip: Most commands support interactive selection with fzf - look for 'select' options[/dim cyan]")
        self.display.console.print()

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
        """Launch or attach to ligolo-ng proxy interface."""
        import subprocess
        import os
        import shutil

        # Special commands
        if args and args[0] == "kill":
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
            check_session = subprocess.run(
                ["tmux", "has-session", "-t", "ligolo"],
                capture_output=True,
                text=True
            )

            if check_session.returncode == 0:
                self.display.print_info("Attaching to existing ligolo-ng session...")
                self.display.print_info("Press CTRL+B then D to detach (keeps session running)")
                self.display.console.print()
                os.system("tmux attach-session -t ligolo")
            else:
                self.display.print_info("Creating new ligolo-ng session...")
                self.display.print_info("Press CTRL+B then D to detach (keeps session running)")
                self.display.console.print()

                if args:
                    cmd_args = [ligolo_cmd] + args
                else:
                    cmd_args = [ligolo_cmd, "-selfcert"]

                cmd_str = " ".join(cmd_args)
                os.system(f"tmux new-session -s ligolo '{cmd_str}'")

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
        """Drop to localhost shell."""
        import subprocess
        import os

        try:
            if args:
                cmd = " ".join(args)
                self.display.print_info(f"Executing: {cmd}")
                subprocess.run(cmd, shell=True)
                return True
            else:
                self.display.print_info("Dropping to localhost shell...")
                self.display.print_info("Press CTRL+D (EOF) to return to PurpleSploit")
                self.display.console.print()

                user_shell = os.environ.get('SHELL', '/bin/bash')
                os.system(user_shell)

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
        """Deploy payloads, pivots, and tools to target systems."""
        module_map = {
            "ligolo": "deploy/ligolo",
            "c2": "deploy/c2",
            "beacon": "deploy/c2",
            "script": "deploy/script",
            "scripts": "deploy/script"
        }

        if not args:
            self._display_deploy_modules()
            return True

        subcommand = args[0].lower()

        if subcommand in module_map:
            module_path = module_map[subcommand]

            if module_path not in self.framework.modules:
                self.display.print_error(f"Deploy module not found: {module_path}")
                self.display.print_info("Run 'deploy' to see available modules")
                return True

            self.display.print_info(f"Loading {module_path}...")
            return self.cmd_use([module_path])

        else:
            self.display.print_error(f"Unknown deploy subcommand: {subcommand}")
            self.display.print_info("Usage: deploy [ligolo|c2|script]")
            return True

    def _display_deploy_modules(self):
        """Display available deployment modules."""
        self.display.console.print()
        self.display.console.print("[bold cyan]=== Deploy Modules ===[/bold cyan]")
        self.display.console.print()

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

        for idx, module in enumerate(modules, 1):
            self.display.console.print(f"[bold green]{idx}. {module['name']}[/bold green]")
            self.display.console.print(f"   [cyan]Command:[/cyan] {module['command']}")
            self.display.console.print(f"   [dim]{module['description']}[/dim]")
            self.display.console.print(f"   [yellow]Methods:[/yellow] {module['methods']}")
            self.display.console.print()

        self.display.print_info("Tip: Use 'deploy <type>' to load a deployment module")
        self.display.print_info("     Then use 'options' to set targets and credentials")
        self.display.print_info("     Use 'run' or 'operations' to see available operations")

    def cmd_webserver(self, args: List[str]) -> bool:
        """Manage the PurpleSploit web portal and API server."""
        import multiprocessing
        import time

        action = args[0].lower() if args else "start"

        if action == "start":
            if self.webserver_process and self.webserver_process.is_alive():
                self.display.print_warning("Web server is already running")
                self.display.print_info("Use 'webserver stop' to stop it first")
                return True

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
                try:
                    import uvicorn
                    import fastapi
                except ImportError as e:
                    self.display.print_error(f"Missing dependencies: {e}")
                    self.display.print_info("Install with: pip install fastapi uvicorn")
                    return True

                self.display.console.print()
                self.display.console.print("[bold magenta]" + "=" * 70 + "[/bold magenta]")
                self.display.console.print("[bold cyan]       Starting PurpleSploit Web Portal & API Server[/bold cyan]")
                self.display.console.print("[bold magenta]" + "=" * 70 + "[/bold magenta]")
                self.display.console.print()

                def run_server():
                    """Background server process"""
                    import sys
                    import os
                    import uvicorn

                    sys.stdout = open(os.devnull, 'w')
                    sys.stderr = open(os.devnull, 'w')

                    uvicorn.run(
                        "purplesploit.api.server:app",
                        host=host,
                        port=port,
                        reload=False,
                        log_level="error",
                        access_log=False
                    )

                self.webserver_process = multiprocessing.Process(
                    target=run_server,
                    daemon=True,
                    name="purplesploit-webserver"
                )
                self.webserver_process.start()

                time.sleep(1.5)

                if self.webserver_process.is_alive():
                    self.display.console.print(f"[green]Server started successfully on {host}:{port}[/green]")
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
        """Generate /etc/hosts file entries from session targets."""
        targets = self.framework.session.targets.list()

        if not args:
            if not targets:
                self.display.print_warning("No targets configured")
                self.display.print_info("Add targets with 'targets add <ip> [hostname]'")
                return True

            entries = self._generate_hosts_entries(targets)

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
            entries = self._generate_hosts_entries(targets)

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
            entries = self._generate_hosts_entries(targets)

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
            entries = self._generate_hosts_entries(targets)

            if entries:
                self.display.print_warning("This will modify /etc/hosts and requires sudo privileges")
                confirm = input("Continue? (y/n): ")

                if confirm.lower() != 'y':
                    self.display.print_info("Operation cancelled")
                    return True

                try:
                    import tempfile
                    import subprocess
                    import os

                    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.hosts') as tmp:
                        tmp.write("\n# PurpleSploit generated entries\n")
                        for entry in entries:
                            tmp.write(entry + "\n")
                        tmp_path = tmp.name

                    cmd = f"sudo bash -c 'cat {tmp_path} >> /etc/hosts'"
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

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

    def _generate_hosts_entries(self, targets: List[Dict]) -> List[str]:
        """Generate hosts file entries from targets."""
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
        return entries

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

            table = Table(title=f"Default Values for '{module_name}'")
            table.add_column("Option", style="cyan")
            table.add_column("Default Value", style="green")

            for option, value in sorted(defaults.items()):
                table.add_row(option, str(value))

            self.display.console.print(table)
            self.display.print_info(f"Total: {len(defaults)} custom defaults")

        elif subcommand == "set":
            if len(args) < 4:
                self.display.print_error("Usage: defaults set <module> <option> <value>")
                self.display.print_info("Example: defaults set nmap PORTS -")
                return True

            module_name = args[1].lower()
            option_name = args[2].upper()
            option_value = " ".join(args[3:])

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

        elif subcommand == "reset":
            if len(args) < 2:
                self.display.print_error("Usage: defaults reset <module>")
                self.display.print_info("Example: defaults reset nmap")
                return True

            module_name = args[1].lower()

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
            from purplesploit.modules.recon.nmap import NmapModule

            nmap_module = NmapModule(self.framework)

            self.display.print_info(f"Parsing {xml_file}...")
            parsed_xml = nmap_module.parse_xml_output(xml_file)

            if not parsed_xml.get("hosts"):
                self.display.print_warning("No hosts with open ports found in scan results")
                return True

            nmap_module.process_discovered_hosts(parsed_xml)

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
        self.cleanup()
        return False

    def cleanup(self):
        """Cleanup resources before exit."""
        if self.webserver_process and self.webserver_process.is_alive():
            self.display.print_info("Stopping web server...")
            self.webserver_process.terminate()
            self.webserver_process.join(timeout=3)
            if self.webserver_process.is_alive():
                self.webserver_process.kill()
