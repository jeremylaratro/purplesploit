# Local plugins

`hello-demo` is a runnable local example. From a Python session with PurpleSploit
installed, use the same Framework that powers your operator session:

```python
from pathlib import Path
from purplesploit.core.framework import Framework
from purplesploit.core.execution import ExecutionRequest

framework = Framework()
manager = framework.plugin_manager
manager.install_local(Path("examples/plugins/hello-demo"))
result = framework.execute_request(ExecutionRequest(
    module_path="plugin/hello-demo/hello", operation_name="greet",
))
assert result.success
manager.disable("hello-demo")
manager.enable("hello-demo")
manager.uninstall("hello-demo")
print(manager.last_uninstall_path)
```

Plugin directories contain `plugin.json` or `plugin.yaml`; directory names must
match manifest names. `module_path` selects one Python module using slash or dotted
notation, and `main_class` selects its concrete `BaseModule` subclass. A `src/`
layout and relative imports are supported. The registered path is
`plugin/<name>/<module_path>`, with normal Framework operations and execution.

Framework startup discovers installed directories and loads enabled plugins.
Disable unregisters the module and clears an active selection; enable imports and
registers it again. Failed loads report `BROKEN` and a persisted `last_error`.
Installation stages a copy before replacement and restores an existing install on
failure. Uninstall moves the exact plugin directory into `.uninstalled/` and
returns its location through `last_uninstall_path`; use `install_local` on that
directory to restore it. Plugin-owned files, including configuration, are retained
in that archive (`keep_config` remains accepted for compatibility).

Each manifest currently registers one module class, which can expose multiple
operations. Disable affects future dispatch; it cannot revoke Python references
or stop work already running. Signing, trust, sandboxing, marketplace expansion,
and remote acquisition are deferred to the later roadmap stages.
