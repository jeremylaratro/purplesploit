"""
Centralized Parameter/Options System for PurpleSploit

This module defines all possible parameters/options that can be used across modules,
and provides a profile system for grouping parameters by operation type.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from enum import Enum


class ParameterType(Enum):
    """Parameter data types"""
    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    PATH = "path"
    URL = "url"
    IP = "ip"
    PORT = "port"
    LIST = "list"


@dataclass
class Parameter:
    """Definition of a single parameter"""
    name: str
    description: str
    param_type: ParameterType = ParameterType.STRING
    required: bool = False
    default: Any = None
    value: Any = None
    validation: Optional[callable] = None
    choices: Optional[List[Any]] = None
    min_value: Optional[int] = None
    max_value: Optional[int] = None

    def validate(self) -> tuple[bool, str]:
        """
        Validate parameter value.

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check required
        if self.required and (self.value is None or self.value == ""):
            return False, f"{self.name} is required"

        # Skip validation if no value set and not required
        if self.value is None:
            return True, ""

        # Check choices
        if self.choices and self.value not in self.choices:
            return False, f"{self.name} must be one of: {', '.join(map(str, self.choices))}"

        # Check min/max for integers
        if self.param_type == ParameterType.INTEGER:
            try:
                int_val = int(self.value)
                if self.min_value is not None and int_val < self.min_value:
                    return False, f"{self.name} must be >= {self.min_value}"
                if self.max_value is not None and int_val > self.max_value:
                    return False, f"{self.name} must be <= {self.max_value}"
            except ValueError:
                return False, f"{self.name} must be an integer"

        # Check port range
        if self.param_type == ParameterType.PORT:
            try:
                port = int(self.value)
                if port < 1 or port > 65535:
                    return False, f"{self.name} must be between 1 and 65535"
            except ValueError:
                return False, f"{self.name} must be a valid port number"

        # Custom validation
        if self.validation:
            try:
                return self.validation(self.value)
            except Exception as e:
                return False, f"Validation error for {self.name}: {str(e)}"

        return True, ""

    def get_value(self) -> Any:
        """Get parameter value or default"""
        return self.value if self.value is not None else self.default

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for display/serialization"""
        return {
            "value": self.value,
            "required": self.required,
            "description": self.description,
            "default": self.default,
            "type": self.param_type.value,
        }


class ParameterRegistry:
    """
    Central registry of all parameters available in PurpleSploit.

    This ensures consistent parameter names and definitions across all modules.
    """

    def __init__(self):
        self.parameters: Dict[str, Parameter] = {}
        self._register_all_parameters()

    def _register_all_parameters(self):
        """Register all available parameters"""

        # ===== NETWORK PARAMETERS =====
        self.register(Parameter(
            name="RHOST",
            description="Remote target host IP address",
            param_type=ParameterType.IP,
            required=False
        ))

        self.register(Parameter(
            name="RPORT",
            description="Remote target port",
            param_type=ParameterType.PORT,
            required=False
        ))

        self.register(Parameter(
            name="LHOST",
            description="Local host IP address",
            param_type=ParameterType.IP,
            required=False
        ))

        self.register(Parameter(
            name="LPORT",
            description="Local port",
            param_type=ParameterType.PORT,
            required=False
        ))

        # ===== AUTHENTICATION PARAMETERS =====
        self.register(Parameter(
            name="USERNAME",
            description="Username for authentication",
            param_type=ParameterType.STRING,
            required=False
        ))

        self.register(Parameter(
            name="PASSWORD",
            description="Password for authentication",
            param_type=ParameterType.STRING,
            required=False
        ))

        self.register(Parameter(
            name="DOMAIN",
            description="Domain name for authentication",
            param_type=ParameterType.STRING,
            required=False,
            default="WORKGROUP"
        ))

        self.register(Parameter(
            name="HASH",
            description="NTLM hash for pass-the-hash",
            param_type=ParameterType.STRING,
            required=False
        ))

        # ===== WEB PARAMETERS =====
        self.register(Parameter(
            name="URL",
            description="Target URL",
            param_type=ParameterType.URL,
            required=False
        ))

        self.register(Parameter(
            name="WORDLIST",
            description="Path to wordlist file",
            param_type=ParameterType.PATH,
            required=False
        ))

        self.register(Parameter(
            name="EXTENSIONS",
            description="File extensions to scan for (comma-separated)",
            param_type=ParameterType.LIST,
            required=False,
            default="php,html,js,txt"
        ))

        self.register(Parameter(
            name="THREADS",
            description="Number of threads",
            param_type=ParameterType.INTEGER,
            required=False,
            default=10,
            min_value=1,
            max_value=100
        ))

        self.register(Parameter(
            name="TIMEOUT",
            description="Request timeout in seconds",
            param_type=ParameterType.INTEGER,
            required=False,
            default=10,
            min_value=1
        ))

        self.register(Parameter(
            name="USER_AGENT",
            description="User-Agent string",
            param_type=ParameterType.STRING,
            required=False
        ))

        self.register(Parameter(
            name="COOKIES",
            description="HTTP cookies",
            param_type=ParameterType.STRING,
            required=False
        ))

        self.register(Parameter(
            name="HEADERS",
            description="Custom HTTP headers",
            param_type=ParameterType.STRING,
            required=False
        ))

        # ===== SMB PARAMETERS =====
        self.register(Parameter(
            name="SHARE",
            description="SMB share name",
            param_type=ParameterType.STRING,
            required=False
        ))

        self.register(Parameter(
            name="SMB_PORT",
            description="SMB port",
            param_type=ParameterType.PORT,
            required=False,
            default=445
        ))

        # ===== LDAP PARAMETERS =====
        self.register(Parameter(
            name="LDAP_PORT",
            description="LDAP port",
            param_type=ParameterType.PORT,
            required=False,
            default=389
        ))

        self.register(Parameter(
            name="BASE_DN",
            description="LDAP base DN",
            param_type=ParameterType.STRING,
            required=False
        ))

        self.register(Parameter(
            name="LDAP_FILTER",
            description="LDAP search filter",
            param_type=ParameterType.STRING,
            required=False
        ))

        # ===== SCAN PARAMETERS =====
        self.register(Parameter(
            name="SCAN_TYPE",
            description="Type of scan",
            param_type=ParameterType.STRING,
            required=False,
            choices=["-sS", "-sT", "-sV", "-sC", "-A", "-Pn"]
        ))

        self.register(Parameter(
            name="PORTS",
            description="Ports to scan (e.g., 1-1000, 80,443)",
            param_type=ParameterType.STRING,
            required=False
        ))

        # ===== EXECUTION PARAMETERS =====
        self.register(Parameter(
            name="COMMAND",
            description="Command to execute",
            param_type=ParameterType.STRING,
            required=False
        ))

        self.register(Parameter(
            name="PAYLOAD",
            description="Payload to deliver",
            param_type=ParameterType.STRING,
            required=False
        ))

        # ===== FILE PARAMETERS =====
        self.register(Parameter(
            name="OUTPUT_FILE",
            description="Output file path",
            param_type=ParameterType.PATH,
            required=False
        ))

        self.register(Parameter(
            name="INPUT_FILE",
            description="Input file path",
            param_type=ParameterType.PATH,
            required=False
        ))

        # ===== KERBEROS PARAMETERS =====
        self.register(Parameter(
            name="DC_IP",
            description="Domain Controller IP address",
            param_type=ParameterType.IP,
            required=False
        ))

        self.register(Parameter(
            name="SPN",
            description="Service Principal Name",
            param_type=ParameterType.STRING,
            required=False
        ))

        # ===== DATABASE PARAMETERS =====
        self.register(Parameter(
            name="DATABASE",
            description="Database name",
            param_type=ParameterType.STRING,
            required=False
        ))

        self.register(Parameter(
            name="SQL_QUERY",
            description="SQL query to execute",
            param_type=ParameterType.STRING,
            required=False
        ))

        # ===== GENERAL PARAMETERS =====
        self.register(Parameter(
            name="VERBOSE",
            description="Enable verbose output",
            param_type=ParameterType.BOOLEAN,
            required=False,
            default=False
        ))

        self.register(Parameter(
            name="DEBUG",
            description="Enable debug mode",
            param_type=ParameterType.BOOLEAN,
            required=False,
            default=False
        ))

    def register(self, parameter: Parameter):
        """Register a parameter"""
        self.parameters[parameter.name] = parameter

    def get(self, name: str) -> Optional[Parameter]:
        """Get a parameter by name"""
        return self.parameters.get(name)

    def get_copy(self, name: str) -> Optional[Parameter]:
        """Get a copy of a parameter (for module use)"""
        param = self.parameters.get(name)
        if param:
            from copy import deepcopy
            return deepcopy(param)
        return None

    def get_multiple(self, names: List[str]) -> Dict[str, Parameter]:
        """Get multiple parameters by name"""
        from copy import deepcopy
        return {name: deepcopy(self.parameters[name])
                for name in names if name in self.parameters}


class ParameterProfile:
    """
    A profile groups related parameters for a specific operation type.

    Profiles ensure that modules only show relevant parameters.
    """

    def __init__(self, name: str, description: str, parameters: List[str]):
        """
        Initialize a parameter profile.

        Args:
            name: Profile name
            description: Profile description
            parameters: List of parameter names in this profile
        """
        self.name = name
        self.description = description
        self.parameter_names: Set[str] = set(parameters)

    def get_parameters(self, registry: ParameterRegistry) -> Dict[str, Parameter]:
        """
        Get all parameters for this profile from the registry.

        Args:
            registry: Parameter registry

        Returns:
            Dictionary of parameter name -> Parameter
        """
        return registry.get_multiple(list(self.parameter_names))

    def add_parameter(self, name: str):
        """Add a parameter to this profile"""
        self.parameter_names.add(name)

    def remove_parameter(self, name: str):
        """Remove a parameter from this profile"""
        self.parameter_names.discard(name)


class ProfileRegistry:
    """Registry of predefined parameter profiles"""

    def __init__(self):
        self.profiles: Dict[str, ParameterProfile] = {}
        self._register_default_profiles()

    def _register_default_profiles(self):
        """Register default profiles for common operation types"""

        # ===== BASIC TARGET PROFILE =====
        self.register(ParameterProfile(
            name="target_basic",
            description="Basic target information",
            parameters=["RHOST", "RPORT"]
        ))

        # ===== AUTHENTICATION PROFILES =====
        self.register(ParameterProfile(
            name="auth_basic",
            description="Basic authentication",
            parameters=["USERNAME", "PASSWORD"]
        ))

        self.register(ParameterProfile(
            name="auth_domain",
            description="Domain authentication",
            parameters=["USERNAME", "PASSWORD", "DOMAIN"]
        ))

        self.register(ParameterProfile(
            name="auth_pth",
            description="Pass-the-hash authentication",
            parameters=["USERNAME", "HASH", "DOMAIN"]
        ))

        # ===== WEB SCAN PROFILES =====
        self.register(ParameterProfile(
            name="web_scan_basic",
            description="Basic web scanning",
            parameters=["URL", "THREADS", "TIMEOUT"]
        ))

        self.register(ParameterProfile(
            name="web_scan_advanced",
            description="Advanced web scanning with authentication",
            parameters=["URL", "WORDLIST", "EXTENSIONS", "THREADS",
                       "USER_AGENT", "COOKIES", "HEADERS"]
        ))

        self.register(ParameterProfile(
            name="web_fuzzing",
            description="Web fuzzing operations",
            parameters=["URL", "WORDLIST", "THREADS", "TIMEOUT"]
        ))

        # ===== SMB PROFILES =====
        self.register(ParameterProfile(
            name="smb_auth",
            description="SMB authentication",
            parameters=["RHOST", "SMB_PORT", "USERNAME", "PASSWORD", "DOMAIN"]
        ))

        self.register(ParameterProfile(
            name="smb_shares",
            description="SMB share operations",
            parameters=["RHOST", "SMB_PORT", "USERNAME", "PASSWORD",
                       "DOMAIN", "SHARE"]
        ))

        self.register(ParameterProfile(
            name="smb_execution",
            description="SMB command execution",
            parameters=["RHOST", "SMB_PORT", "USERNAME", "PASSWORD",
                       "DOMAIN", "COMMAND"]
        ))

        # ===== LDAP PROFILES =====
        self.register(ParameterProfile(
            name="ldap_query",
            description="LDAP query operations",
            parameters=["RHOST", "LDAP_PORT", "USERNAME", "PASSWORD",
                       "DOMAIN", "BASE_DN", "LDAP_FILTER"]
        ))

        self.register(ParameterProfile(
            name="ldap_enum",
            description="LDAP enumeration",
            parameters=["RHOST", "LDAP_PORT", "USERNAME", "PASSWORD", "DOMAIN"]
        ))

        # ===== NETWORK SCAN PROFILES =====
        self.register(ParameterProfile(
            name="network_scan",
            description="Network scanning",
            parameters=["RHOST", "PORTS", "SCAN_TYPE"]
        ))

        # ===== IMPACKET PROFILES =====
        self.register(ParameterProfile(
            name="impacket_exec",
            description="Impacket execution tools",
            parameters=["RHOST", "USERNAME", "PASSWORD", "DOMAIN", "COMMAND"]
        ))

        self.register(ParameterProfile(
            name="impacket_secrets",
            description="Impacket credential dumping",
            parameters=["RHOST", "USERNAME", "PASSWORD", "DOMAIN"]
        ))

        self.register(ParameterProfile(
            name="kerberos_attack",
            description="Kerberos attacks",
            parameters=["DC_IP", "DOMAIN", "USERNAME"]
        ))

        # ===== DATABASE PROFILES =====
        self.register(ParameterProfile(
            name="mssql_query",
            description="MSSQL query operations",
            parameters=["RHOST", "RPORT", "USERNAME", "PASSWORD",
                       "DATABASE", "SQL_QUERY"]
        ))

    def register(self, profile: ParameterProfile):
        """Register a profile"""
        self.profiles[profile.name] = profile

    def get(self, name: str) -> Optional[ParameterProfile]:
        """Get a profile by name"""
        return self.profiles.get(name)

    def list_profiles(self) -> List[str]:
        """List all profile names"""
        return list(self.profiles.keys())


# Global instances
_parameter_registry = ParameterRegistry()
_profile_registry = ProfileRegistry()


def get_parameter_registry() -> ParameterRegistry:
    """Get the global parameter registry"""
    return _parameter_registry


def get_profile_registry() -> ProfileRegistry:
    """Get the global profile registry"""
    return _profile_registry
