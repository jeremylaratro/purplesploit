"""
Base Module Class for PurpleSploit

All PurpleSploit modules inherit from BaseModule and implement the required
abstract methods and properties.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from purplesploit.core.parameters import (
    get_parameter_registry,
    get_profile_registry,
    Parameter,
    ParameterProfile
)


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
        self.parameters: Dict[str, Parameter] = {}
        self._parameter_registry = get_parameter_registry()
        self._profile_registry = get_profile_registry()
        self._init_options()
        self._init_parameters()
        self._load_defaults_from_db()

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

    @property
    def parameter_profiles(self) -> List[str]:
        """
        List of parameter profile names to use for this module.

        Override in subclass to specify which parameter profiles this module uses.
        Profiles define which parameters are relevant for this module.

        Examples:
            - ["web_scan_basic"] - Basic web scanning
            - ["smb_auth", "smb_shares"] - SMB authentication and share operations
            - ["ldap_query"] - LDAP query operations

        Returns:
            List of profile names from ProfileRegistry
        """
        return []

    @property
    def custom_parameters(self) -> List[str]:
        """
        List of custom parameter names to add beyond profiles.

        Override in subclass to add additional parameters not in any profile.

        Returns:
            List of parameter names from ParameterRegistry
        """
        return []

    def _init_options(self):
        """
        Initialize module options. Override in subclass to add custom options.

        DEPRECATED: Use parameter_profiles and custom_parameters properties instead.

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
        # Legacy support: Common options that most modules use
        # New modules should use parameter_profiles instead
        if not self.parameter_profiles and not self.custom_parameters:
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

    def _init_parameters(self):
        """
        Initialize module parameters from profiles.

        This method loads parameters based on the parameter_profiles and
        custom_parameters properties. Parameters are loaded from the central
        registry and only relevant parameters are shown.
        """
        # If module uses legacy options system, convert to parameters
        if self.options and not self.parameter_profiles:
            return

        # Load parameters from profiles
        for profile_name in self.parameter_profiles:
            profile = self._profile_registry.get(profile_name)
            if profile:
                params = profile.get_parameters(self._parameter_registry)
                self.parameters.update(params)

        # Load custom parameters
        for param_name in self.custom_parameters:
            param = self._parameter_registry.get_copy(param_name)
            if param:
                self.parameters[param_name] = param

        # Convert parameters to legacy options format for backward compatibility
        for name, param in self.parameters.items():
            self.options[name] = param.to_dict()

    def _load_defaults_from_db(self):
        """
        Load default option values from the database.

        This method loads user-configured defaults from the database and applies
        them to options that haven't been explicitly set. This allows users to
        customize default values for module options persistently.
        """
        if not hasattr(self.framework, 'database'):
            return

        # Get module identifier (use category/name as module_name)
        module_identifier = self.category
        if hasattr(self, '__class__'):
            module_identifier = self.__class__.__name__.replace('Module', '').lower()

        # Load all defaults for this module
        defaults = self.framework.database.get_module_defaults(module_identifier)

        # Apply defaults to options that haven't been set
        for option_name, default_value in defaults.items():
            if option_name in self.options:
                # Only apply if the current value is None or matches the hardcoded default
                current_value = self.options[option_name].get("value")
                if current_value is None:
                    self.options[option_name]["value"] = default_value
                    self.options[option_name]["default"] = default_value

                    # Also update parameter if using new system
                    if option_name in self.parameters:
                        self.parameters[option_name].value = default_value
                        self.parameters[option_name].default = default_value

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

        # Update both legacy options and new parameters
        self.options[key]["value"] = value

        if key in self.parameters:
            self.parameters[key].value = value

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

        # Prefer parameter system if available
        if key in self.parameters:
            return self.parameters[key].get_value()

        # Fall back to legacy options
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
        # Validate new parameter system if available
        if self.parameters:
            for name, param in self.parameters.items():
                is_valid, error = param.validate()
                if not is_valid:
                    return False, error

        # Fall back to legacy validation
        else:
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

    def get_default_command(self) -> str:
        """
        Get the default command that would be executed with current options.
        Override in subclass to provide command preview.

        Returns:
            Command string or empty string if not applicable
        """
        return ""

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

    def get_operations(self) -> List[Dict[str, Any]]:
        """
        Get list of operations/submenus for this module.
        Override in subclass to provide granular operation selection.

        Returns:
            List of operation dictionaries with keys:
            - name: Operation name
            - description: Short description
            - handler: Method name (string) or callable
            - subcategory: Optional subcategory (e.g., 'authentication', 'shares', 'enumeration')

        If this returns an empty list, the module uses traditional run() method.
        If it returns operations, the user must select an operation before running.
        """
        return []

    def has_operations(self) -> bool:
        """Check if module has granular operations/submenu."""
        return len(self.get_operations()) > 0

    def get_subcategories(self) -> List[str]:
        """
        Get list of unique subcategories from operations.

        Returns:
            Sorted list of unique subcategory names
        """
        operations = self.get_operations()
        subcategories = set()
        for op in operations:
            if 'subcategory' in op and op['subcategory']:
                subcategories.add(op['subcategory'])
        return sorted(subcategories)

    def get_operations_by_subcategory(self, subcategory: str = None) -> List[Dict[str, Any]]:
        """
        Get operations filtered by subcategory.

        Args:
            subcategory: Subcategory to filter by (None returns all)

        Returns:
            List of operation dictionaries
        """
        operations = self.get_operations()
        if subcategory is None:
            return operations

        return [op for op in operations
                if op.get('subcategory', '').lower() == subcategory.lower()]


class ExternalToolModule(BaseModule):
    """
    Base class for modules that wrap external tools.

    Provides helper methods for executing external commands and parsing output.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = None  # Set in subclass
        self.tool_path = None  # Auto-detected or set in subclass

        # Add SWITCHES option for custom CLI switches
        if "SWITCHES" not in self.options:
            self.options["SWITCHES"] = {
                "value": "",
                "required": False,
                "description": "Custom command-line switches to append to command",
                "default": ""
            }

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

    def execute_command(self, command: str, timeout: Optional[int] = None, background: bool = False) -> Dict[str, Any]:
        """
        Execute an external command.

        Args:
            command: Command to execute
            timeout: Timeout in seconds
            background: If True, run in background and return immediately

        Returns:
            Dictionary with execution results
        """
        import subprocess

        # Append custom switches if provided
        switches = self.get_option("SWITCHES")
        if switches:
            command = f"{command} {switches}"

        try:
            self.log(f"Executing: {command}", "info")

            if background:
                # Run in background using nohup
                bg_command = f"nohup {command} &"
                process = subprocess.Popen(
                    bg_command,
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True
                )

                self.log(f"Started in background (PID: {process.pid})", "success")

                return {
                    "success": True,
                    "background": True,
                    "pid": process.pid,
                    "message": f"Command running in background (PID: {process.pid})",
                    "command": command
                }
            else:
                # Run synchronously (original behavior)
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

    def get_default_command(self) -> str:
        """
        Get the default command that would be executed.

        Returns:
            Command string
        """
        try:
            return self.build_command()
        except Exception:
            return ""

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
