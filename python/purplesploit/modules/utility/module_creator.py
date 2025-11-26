"""
Module Creator

Interactive module generator for creating simple PurpleSploit modules.
Helps users quickly scaffold new modules using templates.
"""

from purplesploit.core.module import BaseModule
from typing import Dict, Any, List
import os
from pathlib import Path


class ModuleCreatorModule(BaseModule):
    """
    Module creator for generating new PurpleSploit modules.

    Provides templates for:
    - Simple command execution modules (e.g., mount NFS, run tool)
    - External tool wrappers
    - Custom modules with operations
    """

    def __init__(self, framework):
        super().__init__(framework)

    @property
    def name(self) -> str:
        return "Module Creator"

    @property
    def description(self) -> str:
        return "Create new modules from templates"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "utility"

    def _init_options(self):
        """Initialize module-specific options."""
        # Don't need standard options for this utility
        self.options = {}

    def get_operations(self) -> List[Dict[str, Any]]:
        """
        Get list of module creation operations.

        Returns:
            List of operation dictionaries
        """
        return [
            {"name": "Simple Command Module", "description": "Create a module that runs a simple command", "handler": "op_simple_command"},
            {"name": "External Tool Wrapper", "description": "Create a wrapper for an external tool", "handler": "op_external_tool"},
            {"name": "Multi-Operation Module", "description": "Create a module with multiple operations", "handler": "op_multi_operation"},
        ]

    def _get_user_input(self, prompt: str, default: str = None) -> str:
        """Get user input with optional default."""
        if default:
            full_prompt = f"{prompt} [{default}]: "
        else:
            full_prompt = f"{prompt}: "

        value = input(full_prompt).strip()
        return value if value else default

    def _get_module_directory(self) -> Path:
        """Get the modules directory path."""
        # Navigate from current file to modules directory
        current_file = Path(__file__)
        modules_dir = current_file.parent.parent
        return modules_dir

    def op_simple_command(self) -> Dict[str, Any]:
        """Create a simple command execution module."""
        self.log("Creating Simple Command Module", "info")
        self.log("This template is perfect for modules that execute a single command", "info")
        self.log("Example: Mount NFS share, run a quick tool, etc.\n", "info")

        # Get module details
        module_name = self._get_user_input("Module name (e.g., 'NFS Mount')")
        if not module_name:
            return {"success": False, "error": "Module name is required"}

        module_category = self._get_user_input("Category (web/network/recon/post)", "network")
        module_desc = self._get_user_input("Description", f"{module_name} module")
        author = self._get_user_input("Author", "PurpleSploit User")

        # Get command details
        self.log("\nDefine the command to execute:", "info")
        self.log("Use {RHOST} for target IP, {RPORT} for port, etc.", "info")
        command_template = self._get_user_input("Command template")
        if not command_template:
            return {"success": False, "error": "Command template is required"}

        # Ask about required options
        self.log("\nWhich options are required for this module?", "info")
        needs_rhost = self._get_user_input("Needs RHOST (target IP)? (y/n)", "y").lower() == 'y'
        needs_rport = self._get_user_input("Needs RPORT (target port)? (y/n)", "n").lower() == 'y'
        needs_url = self._get_user_input("Needs URL (target URL)? (y/n)", "n").lower() == 'y'

        # Generate module code
        module_code = self._generate_simple_command_module(
            module_name,
            module_category,
            module_desc,
            author,
            command_template,
            needs_rhost,
            needs_rport,
            needs_url
        )

        # Save module
        return self._save_module(module_name, module_category, module_code)

    def op_external_tool(self) -> Dict[str, Any]:
        """Create an external tool wrapper module."""
        self.log("Creating External Tool Wrapper Module", "info")
        self.log("This template wraps an external command-line tool\n", "info")

        # Get module details
        module_name = self._get_user_input("Module name (e.g., 'Nikto Scanner')")
        if not module_name:
            return {"success": False, "error": "Module name is required"}

        tool_command = self._get_user_input("Tool command name (e.g., 'nikto')")
        if not tool_command:
            return {"success": False, "error": "Tool command is required"}

        module_category = self._get_user_input("Category (web/network/recon/post)", "web")
        module_desc = self._get_user_input("Description", f"{module_name} wrapper")
        author = self._get_user_input("Author", "PurpleSploit User")

        # Generate module code
        module_code = self._generate_external_tool_module(
            module_name,
            module_category,
            module_desc,
            author,
            tool_command
        )

        # Save module
        return self._save_module(module_name, module_category, module_code)

    def op_multi_operation(self) -> Dict[str, Any]:
        """Create a module with multiple operations."""
        self.log("Creating Multi-Operation Module", "info")
        self.log("This template creates a module with multiple sub-operations\n", "info")

        # Get module details
        module_name = self._get_user_input("Module name (e.g., 'Custom Scanner')")
        if not module_name:
            return {"success": False, "error": "Module name is required"}

        module_category = self._get_user_input("Category (web/network/recon/post)", "network")
        module_desc = self._get_user_input("Description", f"{module_name} with multiple operations")
        author = self._get_user_input("Author", "PurpleSploit User")

        # Get operations
        operations = []
        self.log("\nDefine operations (enter blank name to finish):", "info")
        while True:
            op_name = self._get_user_input(f"Operation {len(operations) + 1} name")
            if not op_name:
                break

            op_desc = self._get_user_input(f"  Description", f"{op_name} operation")
            op_command = self._get_user_input(f"  Command template")

            operations.append({
                'name': op_name,
                'description': op_desc,
                'command': op_command
            })

        if not operations:
            return {"success": False, "error": "At least one operation is required"}

        # Generate module code
        module_code = self._generate_multi_operation_module(
            module_name,
            module_category,
            module_desc,
            author,
            operations
        )

        # Save module
        return self._save_module(module_name, module_category, module_code)

    def _generate_simple_command_module(
        self,
        name: str,
        category: str,
        description: str,
        author: str,
        command_template: str,
        needs_rhost: bool,
        needs_rport: bool,
        needs_url: bool
    ) -> str:
        """Generate code for a simple command module."""
        class_name = ''.join(word.capitalize() for word in name.split()) + "Module"
        file_name = name.lower().replace(' ', '_')

        # Build required options
        required_opts = []
        if needs_rhost:
            required_opts.append('"RHOST": {"value": None, "required": True, "description": "Target host", "default": None}')
        if needs_rport:
            required_opts.append('"RPORT": {"value": None, "required": True, "description": "Target port", "default": None}')
        if needs_url:
            required_opts.append('"URL": {"value": None, "required": True, "description": "Target URL", "default": None}')

        options_code = ",\n            ".join(required_opts) if required_opts else ""

        template = f'''"""
{name} Module

{description}
"""

from purplesploit.core.module import ExternalToolModule
from typing import Dict, Any


class {class_name}(ExternalToolModule):
    """
    {name} module.

    {description}
    """

    def __init__(self, framework):
        super().__init__(framework)

    @property
    def name(self) -> str:
        return "{name}"

    @property
    def description(self) -> str:
        return "{description}"

    @property
    def author(self) -> str:
        return "{author}"

    @property
    def category(self) -> str:
        return "{category}"

    def _init_options(self):
        """Initialize module-specific options."""
        self.options = {{
            {options_code}
        }}

    def build_command(self) -> str:
        """Build the command to execute."""
        command = "{command_template}"

        # Replace placeholders with option values
        for key, option in self.options.items():
            value = option.get("value")
            if value:
                command = command.replace(f"{{{{{key}}}}}", str(value))

        return command

    def run(self) -> Dict[str, Any]:
        """Execute the module."""
        # Validate options
        valid, error = self.validate_options()
        if not valid:
            return {{"success": False, "error": error}}

        # Build and execute command
        command = self.build_command()
        self.log(f"Executing: {{command}}", "info")

        result = self.execute_command(command)
        return result
'''

        return template

    def _generate_external_tool_module(
        self,
        name: str,
        category: str,
        description: str,
        author: str,
        tool_command: str
    ) -> str:
        """Generate code for an external tool wrapper."""
        class_name = ''.join(word.capitalize() for word in name.split()) + "Module"

        template = f'''"""
{name} Module

{description}
"""

from purplesploit.core.module import ExternalToolModule
from typing import Dict, Any, List


class {class_name}(ExternalToolModule):
    """
    {name} module - wrapper for {tool_command}.

    {description}
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "{tool_command}"

    @property
    def name(self) -> str:
        return "{name}"

    @property
    def description(self) -> str:
        return "{description}"

    @property
    def author(self) -> str:
        return "{author}"

    @property
    def category(self) -> str:
        return "{category}"

    def _init_options(self):
        """Initialize module-specific options."""
        super()._init_options()

        # Add custom options here
        self.options.update({{
            "TARGET": {{
                "value": None,
                "required": True,
                "description": "Target (IP or URL)",
                "default": None
            }},
        }})

    def build_command(self) -> str:
        """Build the command to execute."""
        target = self.get_option("TARGET")

        # Build the command - customize this based on tool syntax
        command = f"{{self.tool_name}} {{target}}"

        return command

    def run(self) -> Dict[str, Any]:
        """Execute the tool."""
        # Check tool is installed
        if not self.check_tool_installed():
            return {{
                "success": False,
                "error": f"Tool not found: {{self.tool_name}}. Please install it first."
            }}

        # Validate options
        valid, error = self.validate_options()
        if not valid:
            return {{"success": False, "error": error}}

        # Build and execute command
        command = self.build_command()
        result = self.execute_command(command, timeout=300)

        return result
'''

        return template

    def _generate_multi_operation_module(
        self,
        name: str,
        category: str,
        description: str,
        author: str,
        operations: List[Dict[str, str]]
    ) -> str:
        """Generate code for a multi-operation module."""
        class_name = ''.join(word.capitalize() for word in name.split()) + "Module"

        # Generate operations list
        ops_list = []
        ops_methods = []
        for i, op in enumerate(operations):
            handler_name = f"op_{op['name'].lower().replace(' ', '_')}"
            ops_list.append(
                f'            {{"name": "{op["name"]}", "description": "{op["description"]}", "handler": "{handler_name}"}}'
            )

            # Use regular string (not f-string) to avoid interpolation issues
            ops_methods.append(f'''
    def {handler_name}(self) -> Dict[str, Any]:
        """Execute {op['name']}."""
        command = "{op['command']}"

        # Replace placeholders with option values
        for opt_key, opt_val in self.options.items():
            value = opt_val.get("value")
            if value:
                command = command.replace(f"{{{{opt_key}}}}", str(value))

        self.log(f"Executing: {{{{command}}}}", "info")
        return self.execute_command(command)
''')

        operations_code = ",\n".join(ops_list)
        operations_methods = "\n".join(ops_methods)

        template = f'''"""
{name} Module

{description}
"""

from purplesploit.core.module import ExternalToolModule
from typing import Dict, Any, List


class {class_name}(ExternalToolModule):
    """
    {name} module with multiple operations.

    {description}
    """

    def __init__(self, framework):
        super().__init__(framework)

    @property
    def name(self) -> str:
        return "{name}"

    @property
    def description(self) -> str:
        return "{description}"

    @property
    def author(self) -> str:
        return "{author}"

    @property
    def category(self) -> str:
        return "{category}"

    def _init_options(self):
        """Initialize module-specific options."""
        super()._init_options()

        self.options.update({{
            "RHOST": {{
                "value": None,
                "required": True,
                "description": "Target host",
                "default": None
            }},
        }})

    def get_operations(self) -> List[Dict[str, Any]]:
        """Get list of operations."""
        return [
{operations_code}
        ]
{operations_methods}
    def run(self) -> Dict[str, Any]:
        """Default run method - prompts for operation selection."""
        return {{
            "success": False,
            "error": "Please select an operation using the 'run' command"
        }}
'''

        return template

    def _save_module(self, name: str, category: str, code: str) -> Dict[str, Any]:
        """Save the generated module to a file."""
        try:
            # Get modules directory
            modules_dir = self._get_module_directory()
            category_dir = modules_dir / category

            # Create category directory if it doesn't exist
            category_dir.mkdir(exist_ok=True)

            # Generate filename
            filename = name.lower().replace(' ', '_') + '.py'
            filepath = category_dir / filename

            # Check if file already exists
            if filepath.exists():
                overwrite = self._get_user_input(f"File {filepath} already exists. Overwrite? (y/n)", "n")
                if overwrite.lower() != 'y':
                    return {"success": False, "error": "Module creation cancelled"}

            # Write file
            with open(filepath, 'w') as f:
                f.write(code)

            self.log(f"Module created successfully!", "success")
            self.log(f"Location: {filepath}", "info")
            self.log(f"\nTo use this module:", "info")
            self.log(f"  1. Restart PurpleSploit or reload modules", "info")
            self.log(f"  2. Use: use {category}/{filename[:-3]}", "info")

            return {
                "success": True,
                "output": f"Module created at {filepath}",
                "filepath": str(filepath)
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to create module: {str(e)}"
            }

    def run(self) -> Dict[str, Any]:
        """Default run method - should use operations."""
        return {
            "success": False,
            "error": "Please select a module template using the operation selector"
        }
