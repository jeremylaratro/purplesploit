"""
PurpleSploit Framework Core

Main framework engine that manages modules, session, and execution.
"""

import os
import sys
import importlib.util
import inspect
from urllib.parse import urlparse
from pathlib import Path
from typing import Dict, List, Optional, Type, TYPE_CHECKING
from datetime import datetime

from .module import BaseModule, ModuleMetadata
from .session import Session
from .database import Database

# Lazy import for models.database to avoid expensive SQLAlchemy import at startup
if TYPE_CHECKING:
    from purplesploit.models.database import DatabaseManager, TargetCreate, CredentialCreate


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

    def _get_db_manager(self):
        """Lazy load db_manager to avoid expensive SQLAlchemy import at startup."""
        # Import only when needed (for API/webserver integration)
        from purplesploit.models.database import db_manager
        return db_manager

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

            # Sync to models database (for webserver) - lazy load db_manager
            try:
                if target['type'] == 'network':
                    from purplesploit.models.database import TargetCreate
                    db_manager = self._get_db_manager()
                    identifier = target['identifier']
                    name = target.get('name') or identifier
                    target_create = TargetCreate(
                        name=name,
                        ip=identifier,
                        description=f"Loaded from legacy database - {target['type']}"
                    )
                    db_manager.upsert_target(target_create)
                else:
                    from purplesploit.models.database import WebTargetCreate
                    identifier = target['identifier']
                    name = target.get('name') or identifier
                    self._get_db_manager().upsert_web_target(WebTargetCreate(
                        name=name, url=identifier,
                        description="Loaded from legacy database - web",
                    ))
            except Exception:
                # Dashboard synchronization is best-effort during startup.
                pass

        # Load credentials
        db_creds = self.database.get_credentials()
        for cred in db_creds:
            cred_dict = {
                'username': cred['username'],
                'password': cred['password'],
                'domain': cred['domain'],
                'dcip': cred.get('dcip'),
                'dns': cred.get('dns'),
                'hash': cred['hash'],
                'hash_type': cred['hash_type'],
                'name': cred['name']
            }

            # Add to session
            self.session.credentials.add(cred_dict)

            # Sync to models database (for webserver) - lazy load db_manager
            try:
                from purplesploit.models.database import CredentialCreate
                db_manager = self._get_db_manager()
                name = cred.get('name') or cred['username']
                cred_create = CredentialCreate(
                    name=name,
                    username=cred['username'],
                    password=cred.get('password'),
                    domain=cred.get('domain'),
                    dcip=cred.get('dcip'),
                    dns=cred.get('dns'),
                    hash=cred.get('hash')
                )
                db_manager.upsert_credential(cred_create)
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

            # Sync to models database (for webserver) - lazy load db_manager
            try:
                db_manager = self._get_db_manager()
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

        # Optimize: Use os.walk instead of rglob for better performance
        for root, dirs, files in os.walk(base_path):
            # Skip __pycache__ directories
            dirs[:] = [d for d in dirs if d != '__pycache__']

            for filename in files:
                # Only process .py files, skip __init__.py and test files
                if not filename.endswith('.py'):
                    continue
                if filename.startswith('__') or filename.startswith('test_'):
                    continue

                module_file = Path(root) / filename

                try:
                    self._register_module(module_file, base_path)
                except Exception as e:
                    self.log(f"Error loading module {module_file}: {e}", "warning")

        count = len(self.modules)
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
        expected_module_name = f"purplesploit.modules.{module_path.replace('/', '.')}"
        for name, obj in inspect.getmembers(mod, inspect.isclass):
            if (issubclass(obj, BaseModule) and
                obj is not BaseModule and
                not inspect.isabstract(obj) and
                obj.__module__ == expected_module_name):

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

        # Populate implicit context before validating required parameters.
        module.auto_set_from_context()
        valid, error = module.validate_options()
        if not valid:
            self.log(f"Validation failed: {error}", "error")
            return {"success": False, "error": error}

        # Execute module
        self.log(f"Running module: {module.name}", "info")
        try:
            raw_results = module.run()
            if not isinstance(raw_results, dict):
                raw_results = {"success": True, "output": str(raw_results)}
            results = self._redact_module_results(module, raw_results)

            self._record_module_results(module, results)

            if results.get('success', False):
                self.log(f"Module completed successfully", "success")
            else:
                self.log(f"Module failed: {results.get('error', 'Unknown error')}", "error")

            return results
        except Exception as e:
            error_msg = f"Module execution error: {str(e)}"
            self.log(error_msg, "error")
            results = {"success": False, "error": error_msg}
            self._record_module_results(module, results)
            return results

    def run_operation(self, module: BaseModule, operation: Dict) -> Dict:
        """Execute a granular operation through the normal validation/audit pipeline."""
        if module is None:
            return {"success": False, "error": "No module loaded"}

        module.auto_set_from_context()
        valid, error = module.validate_options()
        if not valid:
            self.log(f"Validation failed: {error}", "error")
            return {"success": False, "error": error}

        handler = operation.get("handler")
        if handler is None:
            return {"success": False, "error": "No handler defined for operation"}

        try:
            if isinstance(handler, str):
                method = getattr(module, handler, None)
                if method is None or not callable(method):
                    return {"success": False, "error": f"Handler method not found: {handler}"}
                result = method()
            elif callable(handler):
                result = handler()
            else:
                return {"success": False, "error": f"Invalid handler type: {type(handler).__name__}"}

            results = result if isinstance(result, dict) else {"success": True, "output": str(result)}
            results = self._redact_module_results(module, results)
            self._record_module_results(module, results)
            return results
        except Exception as e:
            error_msg = f"Operation execution error: {e}"
            results = {"success": False, "error": error_msg}
            self._record_module_results(module, results)
            self.log(error_msg, "error")
            return results

    def _record_module_results(self, module: BaseModule, results: Dict) -> None:
        """Persist module output consistently for module and operation execution."""
        try:
            options = module.show_options()
            safe_options = {}
            for key, option in options.items():
                safe_option = dict(option)
                if self._is_sensitive_name(key) and safe_option.get("value") not in (None, ""):
                    safe_option["value"] = "[redacted]"
                safe_options[key] = safe_option
            self.session.store_results(module.name, results)
            self.database.add_module_execution(
                module_name=module.name,
                module_path=module.__class__.__module__,
                options=safe_options,
                results=results,
                success=results.get('success', False),
                error_message=results.get('error'),
            )
        except Exception as e:
            # An audit-store failure must not replace or crash a completed run.
            self.log(f"Unable to persist module execution: {e}", "warning")

    @staticmethod
    def _is_sensitive_name(name: str) -> bool:
        lowered = str(name).lower()
        return any(marker in lowered for marker in ("pass", "hash", "token", "secret", "api_key", "apikey"))

    def _redact_module_results(self, module: BaseModule, results: Dict) -> Dict:
        """Remove option secrets from returned, in-memory, and persisted results."""
        secrets_to_hide = []
        for key, option in module.show_options().items():
            value = option.get("value")
            if self._is_sensitive_name(key) and value not in (None, "", "[redacted]"):
                secrets_to_hide.append(str(value))

        def scrub(value, key=""):
            if self._is_sensitive_name(key) and value not in (None, ""):
                return "[redacted]"
            if isinstance(value, dict):
                return {item_key: scrub(item_value, item_key) for item_key, item_value in value.items()}
            if isinstance(value, list):
                return [scrub(item) for item in value]
            if isinstance(value, tuple):
                return tuple(scrub(item) for item in value)
            if isinstance(value, str):
                for secret in secrets_to_hide:
                    value = value.replace(secret, "[redacted]")
            return value

        return scrub(results)

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
        target_type = str(target_type).lower().strip()
        identifier = str(identifier).strip()
        if target_type not in {"network", "web"} or not identifier or any(
            char in identifier for char in "\r\n\0"
        ):
            return False
        if target_type == "web":
            parsed = urlparse(identifier)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                return False

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

        self._persist_target_record(target_dict)

        return True

    def add_credential(self, username: str, password: str = None,
                      domain: str = None, dcip: str = None, dns: str = None,
                      hash_value: str = None, name: str = None) -> bool:
        """
        Add a credential to both session and database.

        Args:
            username: Username
            password: Password
            domain: Domain
            dcip: Domain Controller IP
            dns: DNS server
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
            'dcip': dcip,
            'dns': dns,
            'hash': hash_value,
            'name': name
        }

        # Add to session
        if not self.session.credentials.add(cred_dict):
            return False

        self._persist_credential_record(cred_dict)

        return True

    def _persist_target_record(self, target: Dict) -> None:
        """Write one session target to both supported persistence stores."""
        target_type = target.get("type") or ("web" if target.get("url") else "network")
        identifier = target.get("url") if target_type == "web" else target.get("ip")
        name = target.get("name") or identifier
        self.database.add_target(target_type, identifier, name)
        try:
            from purplesploit.models.database import TargetCreate, WebTargetCreate
            db_manager = self._get_db_manager()
            if target_type == "web":
                db_manager.upsert_web_target(WebTargetCreate(
                    name=name, url=identifier, description="Added via CLI - web",
                ))
            else:
                db_manager.upsert_target(TargetCreate(
                    name=name, ip=identifier,
                    description=f"Added via CLI - {target_type}",
                ))
        except Exception as e:
            self.log(f"Dashboard target sync skipped: {e}", "debug")

    def _delete_target_record(self, target: Dict) -> None:
        """Delete one target from both persistence stores."""
        target_type = target.get("type") or ("web" if target.get("url") else "network")
        identifier = target.get("url") if target_type == "web" else target.get("ip")
        self.database.remove_target(identifier)
        try:
            self._get_db_manager().delete_target(identifier, target_type)
        except Exception as e:
            self.log(f"Dashboard target delete skipped: {e}", "warning")

    def remove_target(self, identifier: str) -> bool:
        """Remove a target from session and all persistence stores."""
        target = next((item for item in self.session.targets.list() if identifier in {
            item.get("ip"), item.get("url"), item.get("name")
        }), None)
        if target is None:
            return False
        self._delete_target_record(target)
        return self.session.targets.remove(identifier)

    def remove_targets_by_indices(self, indices: List[int]) -> int:
        """Remove valid target indices without allowing index shifts to change identity."""
        targets = self.session.targets.list()
        valid = sorted({index for index in indices if 0 <= index < len(targets)}, reverse=True)
        for index in valid:
            self._delete_target_record(targets[index])
            self.session.targets.remove_by_index(index)
        return len(valid)

    def clear_targets(self) -> int:
        """Clear targets from session and both databases."""
        count = self.session.targets.clear()
        self.database.clear_all_targets()
        try:
            self._get_db_manager().clear_all_targets()
        except Exception as e:
            self.log(f"Dashboard target clear skipped: {e}", "warning")
        return count

    def modify_target(self, index: int, **modifications) -> bool:
        """Update a target while keeping every persistence representation in sync."""
        targets = self.session.targets.list()
        if not 0 <= index < len(targets):
            return False
        allowed = {"ip", "url", "name", "type"}
        updated = dict(targets[index])
        updated.update({key: value for key, value in modifications.items() if key in allowed})
        if updated.get("type") == "web" or updated.get("url"):
            updated["type"] = "web"
            updated.pop("ip", None)
        else:
            updated["type"] = "network"
            updated.pop("url", None)
        identifier = updated.get("url") or updated.get("ip")
        if not identifier:
            return False
        self._delete_target_record(targets[index])
        if not self.session.targets.modify(index, **updated):
            self._persist_target_record(targets[index])
            return False
        self._persist_target_record(self.session.targets.list()[index])
        return True

    def _persist_credential_record(self, credential: Dict) -> None:
        """Write one session credential to both supported persistence stores."""
        self.database.add_credential(
            username=credential.get("username"), password=credential.get("password"),
            domain=credential.get("domain"), dcip=credential.get("dcip"),
            dns=credential.get("dns"), hash_value=credential.get("hash"),
            hash_type=credential.get("hash_type"), name=credential.get("name"),
        )
        try:
            from purplesploit.models.database import CredentialCreate
            self._get_db_manager().upsert_credential(CredentialCreate(
                name=credential.get("name") or credential.get("username"),
                username=credential.get("username"), password=credential.get("password"),
                domain=credential.get("domain"), dcip=credential.get("dcip"),
                dns=credential.get("dns"), hash=credential.get("hash"),
            ))
        except Exception as e:
            self.log(f"Dashboard credential sync skipped: {e}", "debug")

    def _delete_credential_record(self, credential: Dict) -> None:
        """Delete one credential from both persistence stores."""
        self.database.remove_credential_record(
            credential.get("username"), credential.get("domain"), credential.get("name"),
        )
        try:
            self._get_db_manager().delete_credential(
                credential.get("username"), credential.get("domain"), credential.get("name"),
            )
        except Exception as e:
            self.log(f"Dashboard credential delete skipped: {e}", "warning")

    def remove_credential(self, identifier: str) -> bool:
        """Remove a credential from session and all persistence stores."""
        credential = next((item for item in self.session.credentials.list() if identifier in {
            item.get("username"), item.get("name")
        }), None)
        if credential is None:
            return False
        self._delete_credential_record(credential)
        return self.session.credentials.remove(identifier)

    def remove_credentials_by_indices(self, indices: List[int]) -> int:
        """Remove valid credential indices using stable pre-removal identities."""
        credentials = self.session.credentials.list()
        valid = sorted({index for index in indices if 0 <= index < len(credentials)}, reverse=True)
        for index in valid:
            self._delete_credential_record(credentials[index])
            self.session.credentials.remove_by_index(index)
        return len(valid)

    def clear_credentials(self) -> int:
        """Clear credentials from session and both databases."""
        count = self.session.credentials.clear()
        self.database.clear_all_credentials()
        try:
            self._get_db_manager().clear_all_credentials()
        except Exception as e:
            self.log(f"Dashboard credential clear skipped: {e}", "warning")
        return count

    def modify_credential(self, index: int, **modifications) -> bool:
        """Update a credential while keeping persistence stores synchronized."""
        credentials = self.session.credentials.list()
        if not 0 <= index < len(credentials):
            return False
        allowed = {"username", "password", "domain", "dcip", "dns", "hash", "hash_type", "name"}
        updated = dict(credentials[index])
        updated.update({key: value for key, value in modifications.items() if key in allowed})
        if not updated.get("username"):
            return False
        self._delete_credential_record(credentials[index])
        if not self.session.credentials.modify(index, **updated):
            self._persist_credential_record(credentials[index])
            return False
        self._persist_credential_record(self.session.credentials.list()[index])
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
