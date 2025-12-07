"""
Session and Context Management for PurpleSploit

Manages persistent state including targets, credentials, workspace data,
and module history. This is a key differentiator from Metasploit -
context persists across module switches.
"""

from datetime import datetime
from typing import Dict, List, Any, Optional
import json


class Session:
    """
    Session management for PurpleSploit.

    Maintains persistent context across module usage including:
    - Current loaded module
    - Target configurations (web and network)
    - Credential sets
    - Service detection results
    - Workspace data and module results
    - Command history
    """

    def __init__(self):
        """Initialize a new session."""
        self.created_at = datetime.now()

        # Module context
        self.current_module = None
        self.module_history = []

        # Persistent context (key differentiator from Metasploit)
        self.targets = TargetManager()
        self.credentials = CredentialManager()
        self.services = ServiceManager()
        self.wordlists = WordlistManager()

        # Workspace and results
        self.workspace = {}
        self.variables = {}

        # History tracking
        self.command_history = []

        # Run mode
        self.run_mode = "single"  # "single" or "all"

    def load_module(self, module):
        """
        Load a module into the session.

        Args:
            module: Module instance to load
        """
        if self.current_module:
            self.module_history.append({
                "module": self.current_module.name,
                "unloaded_at": datetime.now().isoformat()
            })

        self.current_module = module

        # Auto-set options from context
        if hasattr(module, 'auto_set_from_context'):
            module.auto_set_from_context()

    def unload_module(self):
        """Unload the current module."""
        if self.current_module:
            self.module_history.append({
                "module": self.current_module.name,
                "unloaded_at": datetime.now().isoformat()
            })
            self.current_module = None

    def store_results(self, module_name: str, results: Dict[str, Any]):
        """
        Store module execution results in workspace.

        Args:
            module_name: Name of the module
            results: Results dictionary
        """
        if module_name not in self.workspace:
            self.workspace[module_name] = []

        self.workspace[module_name].append({
            "timestamp": datetime.now().isoformat(),
            "results": results
        })

    def get_results(self, module_name: str) -> List[Dict]:
        """
        Get stored results for a module.

        Args:
            module_name: Name of the module

        Returns:
            List of result dictionaries
        """
        return self.workspace.get(module_name, [])

    def add_command(self, command: str):
        """
        Add a command to history.

        Args:
            command: Command string
        """
        self.command_history.append({
            "command": command,
            "timestamp": datetime.now().isoformat()
        })

    def get_current_target(self) -> Optional[Dict]:
        """Get the current active target."""
        return self.targets.get_current()

    def get_current_credential(self) -> Optional[Dict]:
        """Get the current active credential."""
        return self.credentials.get_current()

    def export_session(self) -> Dict:
        """
        Export the entire session state.

        Returns:
            Dictionary containing all session data
        """
        return {
            "created_at": self.created_at.isoformat(),
            "current_module": self.current_module.name if self.current_module else None,
            "targets": self.targets.export(),
            "credentials": self.credentials.export(),
            "services": self.services.export(),
            "wordlists": self.wordlists.export(),
            "workspace": self.workspace,
            "variables": self.variables,
            "command_history": self.command_history,
            "run_mode": self.run_mode
        }

    def import_session(self, data: Dict):
        """
        Import session state from dictionary.

        Args:
            data: Session data dictionary
        """
        if "targets" in data:
            self.targets.import_data(data["targets"])
        if "credentials" in data:
            self.credentials.import_data(data["credentials"])
        if "services" in data:
            self.services.import_data(data["services"])
        if "wordlists" in data:
            self.wordlists.import_data(data["wordlists"])
        if "workspace" in data:
            self.workspace = data["workspace"]
        if "variables" in data:
            self.variables = data["variables"]
        if "run_mode" in data:
            self.run_mode = data["run_mode"]


class TargetManager:
    """Manages target hosts (both web URLs and network IPs)."""

    def __init__(self):
        self.targets = []
        self.current_index = 0

    def add(self, target: Dict[str, Any]) -> bool:
        """
        Add a target.

        Args:
            target: Target dictionary with keys like 'ip', 'url', 'name', 'type'

        Returns:
            True if added successfully
        """
        # Check for duplicates
        for existing in self.targets:
            if existing.get('ip') == target.get('ip') and existing.get('url') == target.get('url'):
                return False

        target['added_at'] = datetime.now().isoformat()
        self.targets.append(target)

        # Auto-select first target
        if len(self.targets) == 1:
            self.current_index = 0

        return True

    def remove(self, identifier: str) -> bool:
        """
        Remove a target by IP, URL, or name.

        Args:
            identifier: IP, URL, or name to remove

        Returns:
            True if removed
        """
        for i, target in enumerate(self.targets):
            if (target.get('ip') == identifier or
                target.get('url') == identifier or
                target.get('name') == identifier):
                self.targets.pop(i)
                if self.current_index >= len(self.targets):
                    self.current_index = max(0, len(self.targets) - 1)
                return True
        return False

    def remove_by_index(self, index: int) -> bool:
        """
        Remove a target by index.

        Args:
            index: Index of target to remove (0-based)

        Returns:
            True if removed
        """
        if 0 <= index < len(self.targets):
            self.targets.pop(index)
            if self.current_index >= len(self.targets):
                self.current_index = max(0, len(self.targets) - 1)
            return True
        return False

    def remove_range(self, start_index: int, end_index: int) -> int:
        """
        Remove targets by index range.

        Args:
            start_index: Start index (0-based, inclusive)
            end_index: End index (0-based, inclusive)

        Returns:
            Number of targets removed
        """
        # Validate range
        if start_index < 0 or end_index >= len(self.targets) or start_index > end_index:
            return 0

        # Remove in reverse order to maintain indices
        count = 0
        for i in range(end_index, start_index - 1, -1):
            if self.remove_by_index(i):
                count += 1

        return count

    def clear(self) -> int:
        """
        Remove all targets.

        Returns:
            Number of targets removed
        """
        count = len(self.targets)
        self.targets = []
        self.current_index = 0
        return count

    def modify(self, index: int, **kwargs) -> bool:
        """
        Modify a target's attributes.

        Args:
            index: Index of target to modify (0-based)
            **kwargs: Attributes to update (e.g., name="NewName", ip="10.0.0.1")

        Returns:
            True if modified successfully
        """
        if 0 <= index < len(self.targets):
            for key, value in kwargs.items():
                if key in ['ip', 'url', 'name', 'type', 'metadata']:
                    self.targets[index][key] = value
            return True
        return False

    def list(self) -> List[Dict]:
        """Get all targets."""
        return self.targets

    def get_current(self) -> Optional[Dict]:
        """Get the current active target."""
        if not self.targets:
            return None
        return self.targets[self.current_index]

    def set_current(self, identifier: str) -> bool:
        """
        Set the current target by IP, URL, or index.

        Args:
            identifier: IP, URL, name, or index

        Returns:
            True if set successfully
        """
        # Try as index first
        try:
            index = int(identifier)
            if 0 <= index < len(self.targets):
                self.current_index = index
                return True
        except ValueError:
            pass

        # Try matching by identifier
        for i, target in enumerate(self.targets):
            if (target.get('ip') == identifier or
                target.get('url') == identifier or
                target.get('name') == identifier):
                self.current_index = i
                return True

        return False

    def export(self) -> Dict:
        """Export target data."""
        return {
            "targets": self.targets,
            "current_index": self.current_index
        }

    def import_data(self, data: Dict):
        """Import target data."""
        self.targets = data.get("targets", [])
        self.current_index = data.get("current_index", 0)


class CredentialManager:
    """Manages credential sets."""

    def __init__(self):
        self.credentials = []
        self.current_index = 0

    def add(self, cred: Dict[str, Any]) -> bool:
        """
        Add a credential set.

        Args:
            cred: Credential dictionary with keys like 'username', 'password', 'domain', 'hash'

        Returns:
            True if added successfully
        """
        # Check for duplicates
        for existing in self.credentials:
            if (existing.get('username') == cred.get('username') and
                existing.get('domain') == cred.get('domain')):
                return False

        cred['added_at'] = datetime.now().isoformat()
        self.credentials.append(cred)
        return True

    def remove(self, identifier: str) -> bool:
        """
        Remove a credential by username or name.

        Args:
            identifier: Username or name

        Returns:
            True if removed
        """
        for i, cred in enumerate(self.credentials):
            if (cred.get('username') == identifier or
                cred.get('name') == identifier):
                self.credentials.pop(i)
                if self.current_index >= len(self.credentials):
                    self.current_index = max(0, len(self.credentials) - 1)
                return True
        return False

    def remove_by_index(self, index: int) -> bool:
        """
        Remove a credential by index.

        Args:
            index: Index of credential to remove (0-based)

        Returns:
            True if removed
        """
        if 0 <= index < len(self.credentials):
            self.credentials.pop(index)
            if self.current_index >= len(self.credentials):
                self.current_index = max(0, len(self.credentials) - 1)
            return True
        return False

    def remove_range(self, start_index: int, end_index: int) -> int:
        """
        Remove credentials by index range.

        Args:
            start_index: Start index (0-based, inclusive)
            end_index: End index (0-based, inclusive)

        Returns:
            Number of credentials removed
        """
        # Validate range
        if start_index < 0 or end_index >= len(self.credentials) or start_index > end_index:
            return 0

        # Remove in reverse order to maintain indices
        count = 0
        for i in range(end_index, start_index - 1, -1):
            if self.remove_by_index(i):
                count += 1

        return count

    def clear(self) -> int:
        """
        Remove all credentials.

        Returns:
            Number of credentials removed
        """
        count = len(self.credentials)
        self.credentials = []
        self.current_index = 0
        return count

    def modify(self, index: int, **kwargs) -> bool:
        """
        Modify a credential's attributes.

        Args:
            index: Index of credential to modify (0-based)
            **kwargs: Attributes to update (e.g., username="admin", password="newpass")

        Returns:
            True if modified successfully
        """
        if 0 <= index < len(self.credentials):
            for key, value in kwargs.items():
                if key in ['username', 'password', 'domain', 'dcip', 'dns', 'hash', 'hash_type', 'name']:
                    self.credentials[index][key] = value
            return True
        return False

    def list(self) -> List[Dict]:
        """Get all credentials."""
        return self.credentials

    def get_current(self) -> Optional[Dict]:
        """Get the current active credential."""
        if not self.credentials:
            return None
        return self.credentials[self.current_index]

    def set_current(self, identifier: str) -> bool:
        """
        Set the current credential by username, name, or index.

        Args:
            identifier: Username, name, or index

        Returns:
            True if set successfully
        """
        # Try as index first
        try:
            index = int(identifier)
            if 0 <= index < len(self.credentials):
                self.current_index = index
                return True
        except ValueError:
            pass

        # Try matching by identifier
        for i, cred in enumerate(self.credentials):
            if (cred.get('username') == identifier or
                cred.get('name') == identifier):
                self.current_index = i
                return True

        return False

    def export(self) -> Dict:
        """Export credential data."""
        return {
            "credentials": self.credentials,
            "current_index": self.current_index
        }

    def import_data(self, data: Dict):
        """Import credential data."""
        self.credentials = data.get("credentials", [])
        self.current_index = data.get("current_index", 0)


class ServiceManager:
    """Manages detected services on targets."""

    def __init__(self):
        self.services = {}  # {target_ip: {service: [ports]}}

    def add_service(self, target: str, service: str, port: int):
        """
        Record a detected service.

        Args:
            target: Target IP or hostname
            service: Service name (e.g., 'smb', 'http', 'ssh')
            port: Port number
        """
        if target not in self.services:
            self.services[target] = {}

        if service not in self.services[target]:
            self.services[target][service] = []

        if port not in self.services[target][service]:
            self.services[target][service].append(port)

    def get_services(self, target: str) -> Dict[str, List[int]]:
        """
        Get all services for a target.

        Args:
            target: Target IP or hostname

        Returns:
            Dictionary of {service: [ports]}
        """
        return self.services.get(target, {})

    def has_service(self, target: str, service: str) -> bool:
        """
        Check if a target has a specific service.

        Args:
            target: Target IP or hostname
            service: Service name

        Returns:
            True if service is detected
        """
        return service in self.services.get(target, {})

    def clear(self) -> int:
        """
        Remove all services.

        Returns:
            Number of service entries removed
        """
        count = len(self.services)
        self.services = {}
        return count

    def export(self) -> Dict:
        """Export service data."""
        return {"services": self.services}

    def import_data(self, data: Dict):
        """Import service data."""
        self.services = data.get("services", {})


class WordlistManager:
    """Manages wordlists organized by attack type/category."""

    def __init__(self):
        self.wordlists = {
            "web_dir": [],       # Web directory/file fuzzing
            "dns_vhost": [],     # DNS/VHost fuzzing
            "username": [],      # Username wordlists
            "password": [],      # Password wordlists
            "subdomain": [],     # Subdomain enumeration
            "parameter": [],     # Parameter fuzzing
            "api": [],           # API endpoint discovery
            "general": []        # General-purpose wordlists
        }
        self.current_selections = {
            "web_dir": None,
            "dns_vhost": None,
            "username": None,
            "password": None,
            "subdomain": None,
            "parameter": None,
            "api": None,
            "general": None
        }

    def add(self, category: str, wordlist_path: str, name: str = None) -> bool:
        """
        Add a wordlist to a category.

        Args:
            category: Wordlist category
            wordlist_path: Path to wordlist file
            name: Optional friendly name

        Returns:
            True if added successfully
        """
        if category not in self.wordlists:
            return False

        # Check for duplicates
        for existing in self.wordlists[category]:
            if existing.get('path') == wordlist_path:
                return False

        import os
        if not os.path.isfile(wordlist_path):
            return False

        wordlist = {
            'path': wordlist_path,
            'name': name or os.path.basename(wordlist_path),
            'added_at': datetime.now().isoformat()
        }

        self.wordlists[category].append(wordlist)
        return True

    def remove(self, category: str, identifier: str) -> bool:
        """
        Remove a wordlist from a category.

        Args:
            category: Wordlist category
            identifier: Path or name of wordlist

        Returns:
            True if removed
        """
        if category not in self.wordlists:
            return False

        for i, wordlist in enumerate(self.wordlists[category]):
            if wordlist.get('path') == identifier or wordlist.get('name') == identifier:
                self.wordlists[category].pop(i)
                return True
        return False

    def list(self, category: str = None) -> Dict[str, List[Dict]]:
        """
        Get wordlists.

        Args:
            category: Filter by category (returns all if None)

        Returns:
            Dictionary of wordlists by category
        """
        if category:
            if category not in self.wordlists:
                return {}
            return {category: self.wordlists[category]}
        return self.wordlists

    def get_current(self, category: str) -> Optional[Dict]:
        """
        Get the currently selected wordlist for a category.

        Args:
            category: Wordlist category

        Returns:
            Wordlist dictionary or None
        """
        if category not in self.current_selections:
            return None

        selection_index = self.current_selections[category]
        if selection_index is None:
            return None

        if category in self.wordlists and 0 <= selection_index < len(self.wordlists[category]):
            return self.wordlists[category][selection_index]

        return None

    def set_current(self, category: str, identifier: str) -> bool:
        """
        Set the current wordlist for a category.

        Args:
            category: Wordlist category
            identifier: Path, name, or index

        Returns:
            True if set successfully
        """
        if category not in self.wordlists:
            return False

        # Try as index first
        try:
            index = int(identifier)
            if 0 <= index < len(self.wordlists[category]):
                self.current_selections[category] = index
                return True
        except ValueError:
            pass

        # Try matching by identifier
        for i, wordlist in enumerate(self.wordlists[category]):
            if wordlist.get('path') == identifier or wordlist.get('name') == identifier:
                self.current_selections[category] = i
                return True

        return False

    def get_categories(self) -> List[str]:
        """Get list of all wordlist categories."""
        return list(self.wordlists.keys())

    def export(self) -> Dict:
        """Export wordlist data."""
        return {
            "wordlists": self.wordlists,
            "current_selections": self.current_selections
        }

    def import_data(self, data: Dict):
        """Import wordlist data."""
        self.wordlists = data.get("wordlists", self.wordlists)
        self.current_selections = data.get("current_selections", self.current_selections)
