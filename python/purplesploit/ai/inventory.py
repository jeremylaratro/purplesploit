"""Read-only module and operation inventory used by advisory consumers."""

import importlib
import inspect

from purplesploit.core.module import BaseModule


def module_manifest(framework, path):
    """Resolve only registered modules when a live framework is supplied.

    Standalone callers may inspect an installed built-in module. No module is
    activated, no operation is run, and absent capabilities return None.
    """
    try:
        if framework is not None:
            if path not in framework.modules:
                return None
            module = framework.instantiate_module(path)
        else:
            imported = importlib.import_module("purplesploit.modules." + path.replace("/", "."))
            candidates = [value for value in vars(imported).values()
                          if inspect.isclass(value) and issubclass(value, BaseModule)
                          and value is not BaseModule and value.__module__ == imported.__name__
                          and value.discoverable and not inspect.isabstract(value)]
            module = candidates[0](None) if candidates else None
        if module is None:
            return None
        return {"path": path, "name": module.name, "description": module.description,
                "options": {key: dict(value) for key, value in module.options.items()},
                "operations": [{key: value for key, value in operation.items() if key != "handler"}
                               for operation in module.get_operation_manifest()]}
    except (ImportError, AttributeError, TypeError, ValueError, KeyError):
        return None


def resolve_operation(manifest, selector=None):
    operations = manifest["operations"]
    if selector:
        matches = [operation for operation in operations
                   if selector in (operation["id"], operation["name"])]
    else:
        matches = operations
    return next((operation for operation in matches
                 if not operation.get("interactive") and not operation.get("background")), None)
