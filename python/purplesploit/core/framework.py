"""
PurpleSploit Framework Core

Main framework engine that manages modules, session, and execution.
"""

import os
import importlib.util
import inspect
from urllib.parse import urlparse
from pathlib import Path
from typing import Dict, List, Optional, Union
from datetime import datetime
from threading import RLock

from .execution import (
    ExecutionRequest, ExecutionResult, ExecutionOutcome, ExecutionHandle, normalize_observations,
    normalize_operation, utc_now,
)

from .module import BaseModule, ModuleMetadata
from .session import Session
from .database import Database

class Framework:
    """
    Main PurpleSploit Framework.

    Manages module registry, session state, database, and module execution.
    """

    def __init__(
        self,
        modules_path: str = None,
        db_path: str = None,
        plugins_dir: Optional[Union[str, Path]] = None,
        plugin_config_dir: Optional[Union[str, Path]] = None,
        plugin_manager_kwargs: Optional[dict] = None,
    ):
        """
        Initialize the framework.

        Args:
            modules_path: Path to modules directory
            db_path: Path to database file
            plugins_dir: Optional local plugin installation directory
            plugin_config_dir: Optional local plugin state directory
        """
        # Determine modules path
        if modules_path is None:
            # Default to python/purplesploit/modules
            framework_dir = Path(__file__).parent.parent
            modules_path = str(framework_dir / "modules")

        self.modules_path = modules_path
        self.modules: Dict[str, ModuleMetadata] = {}
        self._execution_record_lock = RLock()

        # Initialize core components
        self.database = Database(db_path)
        self.session = Session()

        # Logging must exist before optional extensions register modules.
        self.log_messages = []

        # Load persisted data
        self._load_persisted_data()

        # Import lazily so the core module registry remains independently
        # usable. PluginManager discovers enabled local plugins at startup.
        from purplesploit.plugins.manager import PluginManager

        self.plugin_manager = PluginManager(
            plugins_dir=Path(plugins_dir) if plugins_dir is not None else None,
            config_dir=(
                Path(plugin_config_dir) if plugin_config_dir is not None else None
            ),
            framework=self,
            **(plugin_manager_kwargs or {}),
        )

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
                'account_ref': cred.get('account_ref'),
                'username': cred['username'],
                'password': cred['password'],
                'scope': cred.get('scope'),
                'domain': cred['domain'],
                'local_host': cred.get('local_host'),
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
                    account_ref=cred.get('account_ref'),
                    name=name,
                    username=cred['username'],
                    password=cred.get('password'),
                    scope=cred.get('scope'),
                    domain=cred.get('domain'),
                    local_host=cred.get('local_host'),
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
                getattr(obj, "discoverable", True) and
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

    def register_module(self, module_path: str, module_class: type[BaseModule]) -> ModuleMetadata:
        """Register a module class supplied by an extension.

        Re-registering the same class is idempotent. A different class may not
        silently replace an existing capability at the same path.
        """
        normalized_path = str(module_path).strip().strip("/")
        if not normalized_path or any(
            part in {"", ".", ".."} for part in normalized_path.split("/")
        ):
            raise ValueError(f"Invalid module path: {module_path!r}")
        if not inspect.isclass(module_class) or not issubclass(module_class, BaseModule):
            raise TypeError("module_class must be a BaseModule subclass")
        if inspect.isabstract(module_class):
            raise TypeError("module_class must be concrete")

        existing = self.modules.get(normalized_path)
        if existing is not None:
            if existing.instance is module_class:
                return existing
            raise ValueError(f"Module path already registered: {normalized_path}")

        instance = module_class(self)
        metadata = ModuleMetadata(
            path=normalized_path,
            name=instance.name,
            category=instance.category,
            description=instance.description,
            author=instance.author,
            instance=module_class,
        )
        self.modules[normalized_path] = metadata
        self.log(f"Registered extension module: {normalized_path}", "debug")
        return metadata

    def unregister_module(self, module_path: str) -> bool:
        """Remove an extension module and clear it from the active session."""
        normalized_path = str(module_path).strip().strip("/")
        metadata = self.modules.pop(normalized_path, None)
        if metadata is None:
            return False

        current = self.session.current_module
        if current is not None and isinstance(current, metadata.instance):
            self.session.current_module = None
        self.log(f"Unregistered extension module: {normalized_path}", "debug")
        return True

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
            module_instance = self.instantiate_module(module_path)
            self.session.load_module(module_instance)
            self.log(f"Loaded module: {metadata.name}", "success")
            return module_instance
        except Exception as e:
            self.log(f"Error loading module: {e}", "error")
            return None

    def instantiate_module(self, module_path: str) -> Optional[BaseModule]:
        """Create a fresh module without changing the operator's selected module."""
        metadata = self.get_module(module_path)
        if metadata is None:
            return None
        instance = metadata.instance(self)
        instance.module_path = module_path
        return instance

    def find_operation(self, module: BaseModule, selector: str) -> Optional[Dict]:
        """Resolve a registered stable ID, handler slug, or exact display name.

        Ambiguous aliases are rejected instead of selecting a different operation
        after an inventory change. Prefix and substring matches are not supported.
        """
        operations = [normalize_operation(item, module) for item in module.get_operations()]
        exact = [item for item in operations if item['id'] == selector or item['name'] == selector]
        if len(exact) == 1:
            return exact[0]
        if exact:
            return None
        normalized = str(selector).strip().casefold().replace('_', '-')
        matches = [item for item in operations if normalized in {
            str(item['id']).casefold().replace('_', '-'),
            str(item['name']).casefold().replace('_', '-'),
        }]
        return matches[0] if len(matches) == 1 else None

    def execute_request(self, request: ExecutionRequest) -> ExecutionResult:
        """Execute explicit options through the same pipeline used by the CLI."""
        started_at = utc_now()
        try:
            module = self.instantiate_module(request.module_path)
        except Exception as exc:
            return ExecutionResult(
                request_id=request.request_id, module_path=request.module_path,
                operation_name=request.operation_name, correlation_id=request.correlation_id,
                engagement_id=request.engagement_id, job_id=request.job_id,
                auth_context=request.auth_context,
                outcome=ExecutionOutcome.ERROR, started_at=started_at, finished_at=utc_now(),
                error=f'Module initialization failed: {exc}',
            )
        if module is None:
            return ExecutionResult(
                request_id=request.request_id, module_path=request.module_path,
                operation_name=request.operation_name, correlation_id=request.correlation_id,
                engagement_id=request.engagement_id, job_id=request.job_id,
                auth_context=request.auth_context,
                outcome=ExecutionOutcome.REJECTED, started_at=started_at, finished_at=utc_now(),
                error=f'Module not found: {request.module_path}',
            )
        module.execution_request = request
        module.execution_started_at = started_at
        module.options_locked = set(request.options_locked) | set(request.options)
        for key, value in request.options.items():
            if not module.set_option(key, value):
                result = self._complete_module_results(module, {'success': False, 'error': f'Unknown option: {key}'})
                return ExecutionResult.from_dict(result['execution'])
        if 'BACKGROUND' in module.options:
            module.set_option('BACKGROUND', request.background)
            module.options_locked.add('BACKGROUND')
        if request.operation_name:
            operation = self.find_operation(module, request.operation_name)
            if operation is None:
                result = self._complete_module_results(module, {'success': False, 'error': f'Operation not found or ambiguous: {request.operation_name}'})
            elif operation['interactive'] and request.stdin != 'inherit':
                result = self._complete_module_results(module, {'success': False, 'error': f'Operation requires interactive stdin: {operation["name"]}'})
            else:
                result = self.run_operation(module, operation)
        else:
            result = self.run_module(module)
        execution_result = ExecutionResult.from_dict(result['execution'])
        if execution_result.outcome is ExecutionOutcome.RUNNING and hasattr(module, 'background_process'):
            execution_result._handle = ExecutionHandle(module.background_process, execution_result)
        return execution_result

    def _complete_module_results(self, module: BaseModule, results: Dict) -> Dict:
        """Normalize the actual process outcome, then record one execution."""
        request = getattr(module, 'execution_request', None) or getattr(module, '_execution_context_request', None)
        if not isinstance(request, ExecutionRequest):
            module_path = getattr(module, 'module_path', None)
            request = ExecutionRequest(
                module_path=module_path if isinstance(module_path, str) else module.__class__.__module__,
                options={key: module.get_option(key) for key in module.options},
            )
        observations = normalize_observations(results, request)
        process_records = getattr(module, 'execution_records', [])
        if not isinstance(process_records, list):
            process_records = []
        process_record = results.get('execution') or (process_records[-1] if process_records else {})
        data = dict(process_record)
        data.update(
            request_id=request.request_id, module_path=request.module_path,
            operation_name=request.operation_name, correlation_id=request.correlation_id,
            engagement_id=request.engagement_id, job_id=request.job_id,
            auth_context=request.auth_context.to_dict() if request.auth_context else None,
            observations=[item.to_dict() for item in observations],
            raw_result={key: value for key, value in results.items() if key not in {'execution', 'observations'}},
        )
        started_at = getattr(module, 'execution_started_at', None)
        data.setdefault('started_at', started_at if isinstance(started_at, str) else utc_now())
        data.setdefault('finished_at', utc_now())
        tool_name = getattr(module, 'tool_name', None)
        data.setdefault('tool', tool_name if isinstance(tool_name, str) else None)
        success = bool(results.get('success', False))
        # A parser or wrapper cannot turn a failed/pending process into success.
        if process_records:
            success = success and all(item.get('success', False) for item in process_records)
        if 'returncode' in results:
            data['exit_code'] = results['returncode']
        if data.get('exit_code') is not None:
            success = success and data['exit_code'] == 0
        data['timed_out'] = bool(data.get('timed_out') or results.get('timed_out') or any(item.get('timed_out') for item in process_records))
        data['cancelled'] = bool(data.get('cancelled') or results.get('cancelled') or any(item.get('cancelled') for item in process_records))
        running = data.get('outcome') == ExecutionOutcome.RUNNING.value or bool(results.get('background'))
        success = success and not (data['timed_out'] or data['cancelled'] or running)
        data['success'] = success
        data['outcome'] = (
            ExecutionOutcome.CANCELLED.value if data['cancelled'] else
            ExecutionOutcome.TIMED_OUT.value if data['timed_out'] else
            ExecutionOutcome.RUNNING.value if running else
            ExecutionOutcome.SUCCESS.value if success else ExecutionOutcome.FAILED.value
        )
        data['error'] = results.get('error') or data.get('error')
        if running:
            data['finished_at'] = None
        results = dict(results, success=success, observations=data['observations'], execution=data)
        results = self._redact_module_results(module, results)
        self._record_module_results(module, results)
        return results

    def _begin_module_execution(self, module: BaseModule) -> None:
        module.execution_records = []
        request = getattr(module, 'execution_request', None)
        if not isinstance(request, ExecutionRequest):
            module_path = getattr(module, 'module_path', None)
            request = ExecutionRequest(
                module_path=module_path if isinstance(module_path, str) else module.__class__.__module__,
                options={key: module.get_option(key) for key in module.options},
            )
        module._execution_context_request = request

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
        self._begin_module_execution(module)
        module.auto_set_from_context()
        valid, error = module.validate_options()
        if not valid:
            self.log(f"Validation failed: {error}", "error")
            return self._complete_module_results(module, {"success": False, "error": error})

        # Execute module
        self.log(f"Running module: {module.name}", "info")
        try:
            raw_results = module.run()
            if not isinstance(raw_results, dict):
                raw_results = {"success": True, "output": str(raw_results)}
            results = self._complete_module_results(module, raw_results)

            if results.get('success', False):
                self.log("Module completed successfully", "success")
            else:
                self.log(f"Module failed: {results.get('error', 'Unknown error')}", "error")

            return results
        except Exception as e:
            error_msg = f"Module execution error: {str(e)}"
            self.log(error_msg, "error")
            results = {"success": False, "error": error_msg}
            return self._complete_module_results(module, results)

    def run_operation(self, module: BaseModule, operation: Dict) -> Dict:
        """Execute a granular operation through the normal validation/audit pipeline."""
        if module is None:
            return {"success": False, "error": "No module loaded"}

        self._begin_module_execution(module)
        module.auto_set_from_context()
        valid, error = module.validate_options()
        if not valid:
            self.log(f"Validation failed: {error}", "error")
            return self._complete_module_results(module, {"success": False, "error": error})

        handler = operation.get("handler")
        if handler is None:
            return self._complete_module_results(module, {"success": False, "error": "No handler defined for operation"})

        for key in operation.get('requires', []):
            if module.get_option(key) in (None, ''):
                return self._complete_module_results(module, {'success': False, 'error': f'Required option not set: {key}'})

        try:
            if isinstance(handler, str):
                method = getattr(module, handler, None)
                if method is None or not callable(method):
                    return self._complete_module_results(module, {"success": False, "error": f"Handler method not found: {handler}"})
                result = method()
            elif callable(handler):
                result = handler()
            else:
                return self._complete_module_results(module, {"success": False, "error": f"Invalid handler type: {type(handler).__name__}"})

            results = result if isinstance(result, dict) else {"success": True, "output": str(result)}
            return self._complete_module_results(module, results)
        except Exception as e:
            error_msg = f"Operation execution error: {e}"
            results = {"success": False, "error": error_msg}
            self.log(error_msg, "error")
            return self._complete_module_results(module, results)

    def _record_module_results(self, module: BaseModule, results: Dict) -> None:
        """Persist module output consistently for module and operation execution."""
        with self._execution_record_lock:
            self._store_module_results(module, results)

    def _store_module_results(self, module: BaseModule, results: Dict) -> None:
        try:
            options = module.show_options()
            safe_options = {}
            for key, option in options.items():
                safe_option = dict(option)
                if self._is_sensitive_name(key) and safe_option.get("value") not in (None, ""):
                    safe_option["value"] = "[redacted]"
                safe_options[key] = safe_option
            self.session.store_results(module.name, results)
            self.session.module_history.append({
                'module': module.name, 'execution': results.get('execution'),
            })
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
                      hash_value: str = None, name: str = None,
                      account_ref: str = None, scope: str = None,
                      local_host: str = None) -> bool:
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
            'account_ref': account_ref,
            'username': username,
            'password': password,
            'scope': scope,
            'domain': domain,
            'local_host': local_host,
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
            account_ref=credential.get("account_ref"), scope=credential.get("scope"),
            domain=credential.get("domain"), dcip=credential.get("dcip"),
            local_host=credential.get("local_host"),
            dns=credential.get("dns"), hash_value=credential.get("hash"),
            hash_type=credential.get("hash_type"), name=credential.get("name"),
        )
        try:
            from purplesploit.models.database import CredentialCreate
            self._get_db_manager().upsert_credential(CredentialCreate(
                account_ref=credential.get("account_ref"),
                name=credential.get("name") or credential.get("username"),
                username=credential.get("username"), password=credential.get("password"),
                scope=credential.get("scope"),
                domain=credential.get("domain"), dcip=credential.get("dcip"),
                local_host=credential.get("local_host"),
                dns=credential.get("dns"), hash=credential.get("hash"),
            ))
        except Exception as e:
            self.log(f"Dashboard credential sync skipped: {e}", "debug")

    def _delete_credential_record(self, credential: Dict) -> None:
        """Delete one credential from both persistence stores."""
        self.database.remove_credential_record(
            credential.get("username"), credential.get("domain"), credential.get("name"),
            credential.get("account_ref"), credential.get("scope"),
            credential.get("local_host"),
        )
        try:
            self._get_db_manager().delete_credential(
                credential.get("username"), credential.get("domain"), credential.get("name"),
                credential.get("account_ref"), credential.get("scope"),
                credential.get("local_host"),
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
        allowed = {
            "account_ref", "username", "password", "scope", "domain", "local_host",
            "dcip", "dns", "hash", "hash_type", "name",
        }
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
