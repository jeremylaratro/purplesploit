"""
Bash Script Executor

Executes bash scripts and shell commands from the Python TUI
"""

import subprocess
import os
import shlex
from pathlib import Path
from typing import Optional, Tuple, Dict, List
from rich.console import Console
from rich.live import Live
from rich.spinner import Spinner
from rich.panel import Panel


class BashExecutor:
    """Execute bash scripts and commands while keeping the bash backend intact"""

    def __init__(self, project_root: Optional[Path] = None):
        """
        Initialize the bash executor

        Args:
            project_root: Path to the purplesploit project root
        """
        if project_root is None:
            # Try to find project root
            current = Path(__file__).resolve()
            while current.parent != current:
                if (current / "purplesploit-tui.sh").exists():
                    project_root = current
                    break
                current = current.parent
            else:
                project_root = Path.cwd()

        self.project_root = Path(project_root)
        self.console = Console()

        # Set up environment
        self.env = os.environ.copy()
        self.env["PURPLESPLOIT_ROOT"] = str(self.project_root)

    def execute_script(
        self,
        script_path: str,
        args: Optional[List[str]] = None,
        show_spinner: bool = True,
        capture_output: bool = True
    ) -> Tuple[int, str, str]:
        """
        Execute a bash script

        Args:
            script_path: Path to the bash script (relative to project root)
            args: Arguments to pass to the script
            show_spinner: Show a spinner while executing
            capture_output: Capture stdout and stderr

        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        script_full_path = self.project_root / script_path

        if not script_full_path.exists():
            return (1, "", f"Script not found: {script_full_path}")

        # Build command
        cmd = ["bash", str(script_full_path)]
        if args:
            cmd.extend(args)

        # Execute
        if show_spinner and capture_output:
            with Live(
                Spinner("dots", text="Executing..."),
                console=self.console,
                transient=True
            ):
                result = subprocess.run(
                    cmd,
                    env=self.env,
                    capture_output=capture_output,
                    text=True,
                    cwd=self.project_root
                )
        else:
            result = subprocess.run(
                cmd,
                env=self.env,
                capture_output=capture_output,
                text=True,
                cwd=self.project_root
            )

        return (result.returncode, result.stdout, result.stderr)

    def execute_command(
        self,
        command: str,
        shell: bool = True,
        show_spinner: bool = False,
        capture_output: bool = True
    ) -> Tuple[int, str, str]:
        """
        Execute a shell command

        Args:
            command: Command to execute
            shell: Execute in shell context
            show_spinner: Show a spinner while executing
            capture_output: Capture stdout and stderr

        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        if show_spinner and capture_output:
            with Live(
                Spinner("dots", text="Executing..."),
                console=self.console,
                transient=True
            ):
                result = subprocess.run(
                    command,
                    shell=shell,
                    executable='/bin/bash',  # Use bash explicitly instead of sh
                    env=self.env,
                    capture_output=capture_output,
                    text=True,
                    cwd=self.project_root
                )
        else:
            result = subprocess.run(
                command,
                shell=shell,
                executable='/bin/bash',  # Use bash explicitly instead of sh
                env=self.env,
                capture_output=capture_output,
                text=True,
                cwd=self.project_root
            )

        return (result.returncode, result.stdout, result.stderr)

    def source_and_call(
        self,
        source_file: str,
        function_name: str,
        args: Optional[List[str]] = None
    ) -> Tuple[int, str, str]:
        """
        Source a bash file and call a function from it

        Args:
            source_file: Path to the bash file to source (relative to project root)
            function_name: Name of the function to call
            args: Arguments to pass to the function

        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        source_full_path = self.project_root / source_file

        if not source_full_path.exists():
            return (1, "", f"Source file not found: {source_full_path}")

        # Build command to source and call function
        arg_str = " ".join(shlex.quote(arg) for arg in (args or []))
        command = f"source {shlex.quote(str(source_full_path))} && {function_name} {arg_str}"

        return self.execute_command(command)

    def get_bash_variable(self, source_file: str, variable_name: str) -> Optional[str]:
        """
        Get a variable value from a bash file

        Args:
            source_file: Path to the bash file (relative to project root)
            variable_name: Name of the variable

        Returns:
            Variable value or None if not found
        """
        source_full_path = self.project_root / source_file

        if not source_full_path.exists():
            return None

        # Source file and echo variable
        command = f"source {shlex.quote(str(source_full_path))} && echo ${variable_name}"
        returncode, stdout, _ = self.execute_command(command)

        if returncode == 0 and stdout.strip():
            return stdout.strip()
        return None

    def call_module_handler(
        self,
        module_type: str,
        module_name: str,
        operation: str,
        variables: Optional[Dict[str, str]] = None
    ) -> Tuple[int, str, str]:
        """
        Call a module handler function

        Args:
            module_type: Type of module (e.g., "web", "nxc", "impacket")
            module_name: Name of the module (e.g., "feroxbuster", "smb")
            operation: Operation to perform
            variables: Variables to set before calling

        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        # Determine module path
        module_path = self.project_root / "modules" / module_type / f"{module_name}.sh"

        if not module_path.exists():
            return (1, "", f"Module not found: {module_path}")

        # Build command with variable exports
        var_exports = ""
        if variables:
            var_exports = " ".join(
                f"export {k}={shlex.quote(str(v))};" for k, v in variables.items()
            )

        # Source module and call handler
        handler_function = f"handle_{module_name}"
        command = f"{var_exports} source {shlex.quote(str(module_path))} && {handler_function}"

        return self.execute_command(command)

    def interactive_bash(self):
        """
        Start an interactive bash shell in the project context
        """
        subprocess.run(
            ["bash"],
            env=self.env,
            cwd=self.project_root
        )
