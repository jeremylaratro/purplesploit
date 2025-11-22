"""
PurpleSploit Framework Core

Main framework engine that manages modules, session, and execution.
"""

import os
import sys
import importlib.util
import inspect
from pathlib import Path
from typing import Dict, List, Optional, Type
from datetime import datetime

from .module import BaseModule, ModuleMetadata
from .session import Session
from .database import Database
from purplesploit.models.database import db_manager, TargetCreate, CredentialCreate


class Framework:
    """
    Main PurpleSploit Framework.

    Manages module registry, session state, database, and module execution.
    """

    def __init__(self, modules_path: str = None, db_path: str = None):
        """
        Initialize the framework.

        Args:
            modules_path: Path to modules directory
            db_path: Path to database file
        """
        # Determine modules path
        if modules_path is None:
            # Default to python/purplesploit/modules
            framework_dir = Path(__file__).parent.parent
            modules_path = str(framework_dir / "modules")

        self.modules_path = modules_path
        self.modules: Dict[str, ModuleMetadata] = {}

        # Initialize core components
        self.database = Database(db_path)
        self.session = Session()

        # Load persisted data
        self._load_persisted_data()

        # Logging
        self.log_messages = []

    def _load_persisted_data(self):
        """Load targets and credentials from database into session and sync to models DB."""
        # Load targets
        db_targets = self.database.get_targets()
        for target in db_targets:
            target_dict = {
                'type': target['type'],
                'name': target['name'],
            }
            if target['type'] == 'web':
                target_dict['url'] = target['identifier']
            else:
                target_dict['ip'] = target['identifier']

            # Add to session
            self.session.targets.add(target_dict)

            # Sync to models database (for webserver)
            if target['type'] == 'network':
                try:
                    identifier = target['identifier']
                    name = target.get('name') or identifier
                    target_create = TargetCreate(
                        name=name,
                        ip=identifier,
                        description=f"Loaded from legacy database - {target['type']}"
                    )
                    db_manager.add_target(target_create)
                except Exception:
                    # Target already exists in models DB, skip
                    pass

        # Load credentials
        db_creds = self.database.get_credentials()
        for cred in db_creds:
            cred_dict = {
                'username': cred['username'],
                'password': cred['password'],
                'domain': cred['domain'],
                'hash': cred['hash'],
                'hash_type': cred['hash_type'],
                'name': cred['name']
            }

            # Add to session
            self.session.credentials.add(cred_dict)

            # Sync to models database (for webserver)
            try:
                name = cred.get('name') or cred['username']
                cred_create = CredentialCreate(
                    name=name,
                    username=cred['username'],
                    password=cred.get('password'),
                    domain=cred.get('domain'),
                    hash=cred.get('hash')
                )
                db_manager.add_credential(cred_create)
            except Exception:
                # Credential already exists in models DB, skip
                pass

        # Load services
        services = self.database.get_services()
        for service in services:
            # Add to session
            self.session.services.add_service(
                service['target'],
                service['service'],
                service['port']
            )

            # Sync to models database (for webserver)
            try:
                db_manager.add_service(
                    service['target'],
                    service['service'],
                    service['port'],
                    service.get('version')
                )
            except Exception:
                # Service already exists in models DB, skip
                pass

    def discover_modules(self, base_path: str = None) -> int:
        """
        Discover and register all modules in the modules directory.

        Args:
            base_path: Base path to search for modules (defaults to self.modules_path)

        Returns:
            Number of modules discovered
        """
        if base_path is None:
            base_path = self.modules_path

        if not os.path.exists(base_path):
            self.log(f"Modules path not found: {base_path}", "warning")
            return 0

        base_path = Path(base_path)
        module_files = list(base_path.rglob("*.py"))

        count = 0
        for module_file in module_files:
            # Skip __init__.py and test files
            if module_file.name.startswith('__') or module_file.name.startswith('test_'):
                continue

            try:
                self._register_module(module_file, base_path)
                count += 1
            except Exception as e:
                self.log(f"Error loading module {module_file}: {e}", "warning")

        self.log(f"Discovered {count} modules", "success")
        return count

    def _register_module(self, module_file: Path, base_path: Path):
        """
        Register a single module file.

        Args:
            module_file: Path to module file
            base_path: Base modules directory path
        """
        # Calculate relative module path
        rel_path = module_file.relative_to(base_path)
        module_path = str(rel_path.with_suffix('')).replace(os.sep, '/')

        # Import the module
        spec = importlib.util.spec_from_file_location(
            f"purplesploit.modules.{module_path.replace('/', '.')}",
            module_file
        )
        if spec is None or spec.loader is None:
            return

        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        # Find all BaseModule subclasses
        for name, obj in inspect.getmembers(mod, inspect.isclass):
            if (issubclass(obj, BaseModule) and
                obj is not BaseModule and
                not inspect.isabstract(obj)):

                # Create temporary instance to extract metadata
                try:
                    instance = obj(self)
                    metadata = ModuleMetadata(
                        path=module_path,
                        name=instance.name,
                        category=instance.category,
                        description=instance.description,
                        author=instance.author,
                        instance=obj  # Store class, not instance
                    )
                    self.modules[module_path] = metadata
                    self.log(f"Registered module: {module_path}", "debug")
                except Exception as e:
                    self.log(f"Error registering {module_path}: {e}", "warning")

    def get_module(self, module_path: str) -> Optional[ModuleMetadata]:
        """
        Get module metadata by path.

        Args:
            module_path: Module path (e.g., 'web/feroxbuster')

        Returns:
            ModuleMetadata if found, None otherwise
        """
        return self.modules.get(module_path)

    def use_module(self, module_path: str) -> Optional[BaseModule]:
        """
        Load and activate a module.

        Args:
            module_path: Module path

        Returns:
            Module instance if found and loaded
        """
        metadata = self.get_module(module_path)
        if metadata is None:
            self.log(f"Module not found: {module_path}", "error")
            return None

        try:
            # Instantiate the module
            module_instance = metadata.instance(self)
            self.session.load_module(module_instance)
            self.log(f"Loaded module: {metadata.name}", "success")
            return module_instance
        except Exception as e:
            self.log(f"Error loading module: {e}", "error")
            return None

    def run_module(self, module: BaseModule = None) -> Dict:
        """
        Run a module.

        Args:
            module: Module to run (defaults to current module)

        Returns:
            Module execution results
        """
        if module is None:
            module = self.session.current_module

        if module is None:
            return {"success": False, "error": "No module loaded"}

        # Validate options
        valid, error = module.validate_options()
        if not valid:
            self.log(f"Validation failed: {error}", "error")
            return {"success": False, "error": error}

        # Auto-set from context
        module.auto_set_from_context()

        # Execute module
        self.log(f"Running module: {module.name}", "info")
        try:
            results = module.run()

            # Store results
            self.session.store_results(module.name, results)

            # Log to database
            self.database.add_module_execution(
                module_name=module.name,
                module_path=self.session.current_module.__class__.__module__,
                options=module.show_options(),
                results=results,
                success=results.get('success', False),
                error_message=results.get('error')
            )

            if results.get('success', False):
                self.log(f"Module completed successfully", "success")
            else:
                self.log(f"Module failed: {results.get('error', 'Unknown error')}", "error")

            return results
        except Exception as e:
            error_msg = f"Module execution error: {str(e)}"
            self.log(error_msg, "error")
            return {"success": False, "error": error_msg}

    def search_modules(self, query: str) -> List[ModuleMetadata]:
        """
        Search modules by name, description, or path.

        Args:
            query: Search query

        Returns:
            List of matching modules
        """
        query = query.lower()
        results = []

        for module in self.modules.values():
            if (query in module.name.lower() or
                query in module.description.lower() or
                query in module.path.lower() or
                query in module.category.lower()):
                results.append(module)

        return results

    def list_modules(self, category: str = None) -> List[ModuleMetadata]:
        """
        List all modules, optionally filtered by category.

        Args:
            category: Category to filter by

        Returns:
            List of modules
        """
        modules = list(self.modules.values())

        if category:
            modules = [m for m in modules if m.category == category]

        # Sort by category then name
        modules.sort(key=lambda m: (m.category, m.name))

        return modules

    def get_categories(self) -> List[str]:
        """
        Get all unique module categories.

        Returns:
            List of category names
        """
        categories = set(m.category for m in self.modules.values())
        return sorted(categories)

    def log(self, message: str, level: str = "info"):
        """
        Log a message.

        Args:
            message: Message to log
            level: Log level (debug, info, success, warning, error)
        """
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message
        }
        self.log_messages.append(log_entry)

        # In a real implementation, you might write to a file or display
        # For now, just store in memory

    def get_recent_logs(self, count: int = 100) -> List[Dict]:
        """
        Get recent log messages.

        Args:
            count: Number of messages to return

        Returns:
            List of log entries
        """
        return self.log_messages[-count:]

    # Context Management Methods
    def add_target(self, target_type: str, identifier: str, name: str = None) -> bool:
        """
        Add a target to both session and database.

        Args:
            target_type: 'web' or 'network'
            identifier: IP or URL
            name: Optional name

        Returns:
            True if added successfully
        """
        # Generate a name if not provided
        if not name:
            name = identifier

        target_dict = {'type': target_type, 'name': name}
        if target_type == 'web':
            target_dict['url'] = identifier
        else:
            target_dict['ip'] = identifier

        # Add to session
        if not self.session.targets.add(target_dict):
            return False

        # Add to old database (backwards compatibility)
        self.database.add_target(target_type, identifier, name)

        # Add to new models database (for webserver)
        try:
            target_create = TargetCreate(
                name=name,
                ip=identifier,
                description=f"Added via CLI - {target_type}"
            )
            db_manager.add_target(target_create)
        except Exception as e:
            # If target already exists, that's fine
            self.log(f"Target already exists in models database: {e}", "debug")

        return True

    def add_credential(self, username: str, password: str = None,
                      domain: str = None, hash_value: str = None,
                      name: str = None) -> bool:
        """
        Add a credential to both session and database.

        Args:
            username: Username
            password: Password
            domain: Domain
            hash_value: Password hash
            name: Optional name

        Returns:
            True if added successfully
        """
        # Generate a name if not provided
        if not name:
            name = f"{domain}/{username}" if domain else username

        cred_dict = {
            'username': username,
            'password': password,
            'domain': domain,
            'hash': hash_value,
            'name': name
        }

        # Add to session
        if not self.session.credentials.add(cred_dict):
            return False

        # Add to old database (backwards compatibility)
        self.database.add_credential(
            username=username,
            password=password,
            domain=domain,
            hash_value=hash_value,
            name=name
        )

        # Add to new models database (for webserver)
        try:
            cred_create = CredentialCreate(
                name=name,
                username=username,
                password=password,
                domain=domain,
                hash=hash_value
            )
            db_manager.add_credential(cred_create)
        except Exception as e:
            # If credential already exists, that's fine
            self.log(f"Credential already exists in models database: {e}", "debug")

        return True

    def get_stats(self) -> Dict:
        """
        Get framework statistics.

        Returns:
            Dictionary with stats
        """
        return {
            "modules": len(self.modules),
            "categories": len(self.get_categories()),
            "targets": len(self.session.targets.list()),
            "credentials": len(self.session.credentials.list()),
            "current_module": self.session.current_module.name if self.session.current_module else None,
            "session_age": (datetime.now() - self.session.created_at).total_seconds()
        }

    def export_state(self) -> Dict:
        """
        Export complete framework state.

        Returns:
            State dictionary
        """
        return {
            "session": self.session.export_session(),
            "stats": self.get_stats(),
            "logs": self.get_recent_logs()
        }

    def cleanup(self):
        """Cleanup framework resources."""
        if self.database:
            self.database.close()
