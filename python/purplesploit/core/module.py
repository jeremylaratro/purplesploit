"""
Base Module Class for PurpleSploit

All PurpleSploit modules inherit from BaseModule and implement the required
abstract methods and properties.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class ModuleMetadata:
    """Metadata for a module"""
    path: str
    name: str
    category: str
    description: str
    author: str
    instance: Any = None  # Reference to the module class


class BaseModule(ABC):
    """
    Base class for all PurpleSploit modules.

    All modules must inherit from this class and implement the required
    abstract methods.
    """

    def __init__(self, framework):
        """
        Initialize the module.

        Args:
            framework: Reference to the main Framework instance
        """
        self.framework = framework
        self.options = {}
        self._init_options()

    @property
    @abstractmethod
    def name(self) -> str:
        """Module display name"""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Module description"""
        pass

    @property
    @abstractmethod
    def author(self) -> str:
        """Module author"""
        pass

    @property
    @abstractmethod
    def category(self) -> str:
        """
        Module category. Valid categories:
        - web: Web application testing
        - network: Network testing (NXC)
        - impacket: Impacket protocol tools
        - recon: Reconnaissance and scanning
        - c2: Command and control
        - post: Post-exploitation
        - ai: AI-assisted automation
        """
        pass

    @property
    def required_options(self) -> List[str]:
        """
        List of required option keys that must be set before running.
        Override in subclass if needed.
        """
        return []

    def _init_options(self):
        """
        Initialize module options. Override in subclass to add custom options.

        Option format:
        {
            "OPTION_NAME": {
                "value": <current_value>,
                "required": <bool>,
                "description": "<description>",
                "default": <default_value>
            }
        }
        """
        # Common options that most modules use
        self.options = {
            "RHOST": {
                "value": None,
                "required": False,
                "description": "Target host IP address",
                "default": None
            },
            "RPORT": {
                "value": None,
                "required": False,
                "description": "Target port",
                "default": None
            },
            "URL": {
                "value": None,
                "required": False,
                "description": "Target URL",
                "default": None
            },
        }

    def set_option(self, key: str, value: Any) -> bool:
        """
        Set an option value.

        Args:
            key: Option name
            value: Option value

        Returns:
            True if successful, False otherwise
        """
        key = key.upper()
        if key not in self.options:
            self.log(f"Unknown option: {key}", "error")
            return False

        self.options[key]["value"] = value
        return True

    def get_option(self, key: str) -> Any:
        """
        Get an option value.

        Args:
            key: Option name

        Returns:
            Option value or default
        """
        key = key.upper()
        if key not in self.options:
            return None

        option = self.options[key]
        value = option.get("value")

        # Return value if set, otherwise return default
        if value is not None:
            return value
        return option.get("default")

    def validate_options(self) -> tuple[bool, str]:
        """
        Validate that all required options are set.

        Returns:
            Tuple of (is_valid, error_message)
        """
        for key, option in self.options.items():
            if option.get("required", False):
                value = option.get("value")
                if value is None or value == "":
                    return False, f"Required option not set: {key}"

        return True, ""

    def show_options(self) -> Dict[str, Any]:
        """
        Get all options for display.

        Returns:
            Dictionary of all options
        """
        return self.options

    def log(self, message: str, level: str = "info"):
        """
        Log a message through the framework.

        Args:
            message: Message to log
            level: Log level (info, success, warning, error)
        """
        if hasattr(self.framework, 'log'):
            self.framework.log(message, level)
        else:
            print(f"[{level.upper()}] {message}")

    @abstractmethod
    def run(self) -> Dict[str, Any]:
        """
        Execute the module.

        This method must be implemented by all modules. It should perform
        the module's main functionality and return results.

        Returns:
            Dictionary containing results. Common keys:
            - success: bool indicating if module ran successfully
            - output: Command output or results
            - error: Error message if success is False
            - data: Additional data (can include tables, lists, etc.)
        """
        pass

    def check(self) -> Dict[str, Any]:
        """
        Check if the module can run successfully without actually running it.
        Used for validation and testing.

        Returns:
            Dictionary with check results
        """
        valid, error = self.validate_options()
        if not valid:
            return {"success": False, "error": error}

        return {"success": True, "message": "Module is ready to run"}

    def cleanup(self):
        """
        Perform any cleanup after module execution.
        Override in subclass if needed.
        """
        pass

    def get_context(self) -> Dict[str, Any]:
        """
        Get current context from framework (targets, creds, etc.).

        Returns:
            Dictionary with current context
        """
        if hasattr(self.framework, 'session'):
            return {
                'current_target': self.framework.session.get_current_target(),
                'current_cred': self.framework.session.get_current_credential(),
                'workspace': self.framework.session.workspace,
            }
        return {}

    def auto_set_from_context(self):
        """
        Automatically set options from current context.
        Called before running to populate options from persistent context.
        """
        context = self.get_context()

        # Auto-set target if available
        if context.get('current_target') and not self.get_option('RHOST'):
            target = context['current_target']
            if isinstance(target, dict):
                if 'ip' in target:
                    self.set_option('RHOST', target['ip'])
                if 'url' in target:
                    self.set_option('URL', target['url'])

        # Auto-set credentials if available
        if context.get('current_cred'):
            cred = context['current_cred']
            if isinstance(cred, dict):
                if 'username' in cred and 'USERNAME' in self.options:
                    self.set_option('USERNAME', cred['username'])
                if 'password' in cred and 'PASSWORD' in self.options:
                    self.set_option('PASSWORD', cred['password'])


class ExternalToolModule(BaseModule):
    """
    Base class for modules that wrap external tools.

    Provides helper methods for executing external commands and parsing output.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = None  # Set in subclass
        self.tool_path = None  # Auto-detected or set in subclass

    def check_tool_installed(self) -> bool:
        """
        Check if the external tool is installed.

        Returns:
            True if tool is available
        """
        import shutil
        if self.tool_path:
            return True

        self.tool_path = shutil.which(self.tool_name)
        return self.tool_path is not None

    def build_command(self) -> str:
        """
        Build the command to execute. Must be implemented by subclass.

        Returns:
            Command string to execute
        """
        raise NotImplementedError("Subclass must implement build_command()")

    def execute_command(self, command: str, timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Execute an external command.

        Args:
            command: Command to execute
            timeout: Timeout in seconds

        Returns:
            Dictionary with execution results
        """
        import subprocess

        try:
            self.log(f"Executing: {command}", "info")

            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            return {
                "success": result.returncode == 0,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "command": command
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": f"Command timed out after {timeout} seconds",
                "command": command
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "command": command
            }

    def run(self) -> Dict[str, Any]:
        """
        Default run implementation for external tools.
        """
        # Check tool is installed
        if not self.check_tool_installed():
            return {
                "success": False,
                "error": f"Tool not found: {self.tool_name}. Please install it first."
            }

        # Build and execute command
        try:
            command = self.build_command()
            result = self.execute_command(command)

            # Parse output if method exists
            if hasattr(self, 'parse_output'):
                result['parsed'] = self.parse_output(result.get('stdout', ''))

            return result
        except Exception as e:
            return {
                "success": False,
                "error": f"Error running module: {str(e)}"
            }
