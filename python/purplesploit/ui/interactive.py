"""
Interactive Selection Helper

Provides fzf-style interactive selection with mouse/keyboard support.
"""

import subprocess
import shutil
from typing import List, Optional, Dict, Any


class InteractiveSelector:
    """
    Interactive selection using fzf (if available) or fallback to simple input.

    Provides:
    - Mouse clickable selections
    - Keyboard navigation (up/down arrows)
    - Fuzzy search filtering
    - Multi-column display
    """

    def __init__(self):
        self.has_fzf = shutil.which('fzf') is not None

    def _get_attr(self, obj: Any, attr: str, default: Any = None) -> Any:
        """
        Get attribute from object or dict.

        Args:
            obj: Dictionary or object
            attr: Attribute name
            default: Default value if not found

        Returns:
            Attribute value or default
        """
        if isinstance(obj, dict):
            return obj.get(attr, default)
        else:
            return getattr(obj, attr, default)

    def select_from_list(
        self,
        items: List[str],
        prompt: str = "Select: ",
        multi: bool = False,
        preview: Optional[str] = None
    ) -> Optional[str]:
        """
        Interactive selection from a list.

        Args:
            items: List of strings to choose from
            prompt: Prompt message
            multi: Allow multiple selections
            preview: Preview command for fzf

        Returns:
            Selected item(s) or None if cancelled
        """
        if not items:
            return None

        if not self.has_fzf:
            # Fallback to simple selection
            return self._simple_select(items, prompt)

        return self._fzf_select(items, prompt, multi, preview)

    def select_module(
        self,
        modules: List[Any],
        auto_load_single: bool = True
    ) -> Optional[Any]:
        """
        Interactive module selection with details.

        Args:
            modules: List of module objects (ModuleMetadata) or dictionaries
            auto_load_single: Auto-select if only one module

        Returns:
            Selected module or None
        """
        if not modules:
            return None

        if auto_load_single and len(modules) == 1:
            return modules[0]

        # Format modules for display (handle both dicts and objects)
        lines = []
        for i, mod in enumerate(modules, 1):
            path = self._get_attr(mod, 'path', '')
            name = self._get_attr(mod, 'name', '')
            desc = self._get_attr(mod, 'description', '')[:50]
            category = self._get_attr(mod, 'category', '').upper()

            # Format: "1. [CATEGORY] path - description"
            line = f"{i:2d}. [{category:8s}] {path:30s} {desc}"
            lines.append(line)

        if not self.has_fzf:
            return self._simple_select_module(modules)

        # Use fzf
        selected_line = self._fzf_select(
            lines,
            prompt="Select Module: ",
            multi=False,
            preview=None
        )

        if selected_line:
            # Extract index from selected line
            try:
                index = int(selected_line.split('.')[0].strip()) - 1
                if 0 <= index < len(modules):
                    return modules[index]
            except (ValueError, IndexError):
                pass

        return None

    def select_operation(
        self,
        operations: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """
        Interactive operation selection.

        Args:
            operations: List of operation dictionaries

        Returns:
            Selected operation dict or None
        """
        if not operations:
            return None

        # Format operations for display
        lines = []
        for i, op in enumerate(operations, 1):
            name = op.get('name', '')
            desc = op.get('description', '')

            # Format: "1. Operation Name - description"
            line = f"{i:2d}. {name:35s} {desc}"
            lines.append(line)

        if not self.has_fzf:
            return self._simple_select_operation(operations)

        # Use fzf
        selected_line = self._fzf_select(
            lines,
            prompt="Select Operation: ",
            multi=False,
            preview=None
        )

        if selected_line:
            # Extract index from selected line
            try:
                index = int(selected_line.split('.')[0].strip()) - 1
                if 0 <= index < len(operations):
                    return operations[index]
            except (ValueError, IndexError):
                pass

        return None

    def select_target(
        self,
        targets: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """
        Interactive target selection.

        Args:
            targets: List of target dictionaries

        Returns:
            Selected target dict or None
        """
        if not targets:
            return None

        # Format targets for display
        lines = []
        for i, target in enumerate(targets, 1):
            identifier = target.get('ip') or target.get('url', '')
            name = target.get('name', '')
            target_type = target.get('type', '').upper()

            # Format: "1. [TYPE] identifier (name)"
            if name:
                line = f"{i:2d}. [{target_type:7s}] {identifier:25s} ({name})"
            else:
                line = f"{i:2d}. [{target_type:7s}] {identifier}"
            lines.append(line)

        if not self.has_fzf:
            return self._simple_select_target(targets)

        # Use fzf
        selected_line = self._fzf_select(
            lines,
            prompt="Select Target: ",
            multi=False,
            preview=None
        )

        if selected_line:
            # Extract index from selected line
            try:
                index = int(selected_line.split('.')[0].strip()) - 1
                if 0 <= index < len(targets):
                    return targets[index]
            except (ValueError, IndexError):
                pass

        return None

    def select_credential(
        self,
        credentials: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """
        Interactive credential selection.

        Args:
            credentials: List of credential dictionaries

        Returns:
            Selected credential dict or None
        """
        if not credentials:
            return None

        # Format credentials for display
        lines = []
        for i, cred in enumerate(credentials, 1):
            username = cred.get('username', '')
            domain = cred.get('domain', '')
            name = cred.get('name', '')
            has_password = '✓' if cred.get('password') else '✗'
            has_hash = '✓' if cred.get('hash') else '✗'

            # Format: "1. DOMAIN\username (name) [Pass:✓ Hash:✗]"
            if domain:
                user_str = f"{domain}\\{username}"
            else:
                user_str = username

            if name:
                line = f"{i:2d}. {user_str:30s} ({name:15s}) [Pass:{has_password} Hash:{has_hash}]"
            else:
                line = f"{i:2d}. {user_str:30s} [Pass:{has_password} Hash:{has_hash}]"
            lines.append(line)

        if not self.has_fzf:
            return self._simple_select_credential(credentials)

        # Use fzf
        selected_line = self._fzf_select(
            lines,
            prompt="Select Credential: ",
            multi=False,
            preview=None
        )

        if selected_line:
            # Extract index from selected line
            try:
                index = int(selected_line.split('.')[0].strip()) - 1
                if 0 <= index < len(credentials):
                    return credentials[index]
            except (ValueError, IndexError):
                pass

        return None

    def _fzf_select(
        self,
        items: List[str],
        prompt: str,
        multi: bool,
        preview: Optional[str]
    ) -> Optional[str]:
        """Use fzf for selection."""
        try:
            # Build fzf command
            fzf_cmd = [
                'fzf',
                '--ansi',  # Support ANSI colors
                '--height', '50%',
                '--reverse',
                '--border',
                '--prompt', prompt,
                '--header', 'Use arrows/mouse to select, Enter to confirm, Esc to cancel'
            ]

            if multi:
                fzf_cmd.extend(['--multi', '--bind', 'tab:toggle'])

            if preview:
                fzf_cmd.extend(['--preview', preview])

            # Run fzf
            input_data = '\n'.join(items)
            result = subprocess.run(
                fzf_cmd,
                input=input_data,
                text=True,
                capture_output=True
            )

            if result.returncode == 0:
                return result.stdout.strip()

        except Exception:
            # Fallback if fzf fails
            pass

        return None

    def _simple_select(self, items: List[str], prompt: str) -> Optional[str]:
        """Fallback simple selection without fzf."""
        print("\nAvailable options:")
        for i, item in enumerate(items, 1):
            print(f"  {i}. {item}")

        try:
            choice = input(f"\n{prompt}(1-{len(items)}): ")
            if choice.isdigit():
                index = int(choice) - 1
                if 0 <= index < len(items):
                    return items[index]
        except (ValueError, KeyboardInterrupt, EOFError):
            pass

        return None

    def _simple_select_module(self, modules: List[Any]) -> Optional[Any]:
        """Simple module selection fallback."""
        print("\nAvailable modules:")
        for i, mod in enumerate(modules, 1):
            path = self._get_attr(mod, 'path', '')
            desc = self._get_attr(mod, 'description', '')[:50]
            print(f"  {i}. {path} - {desc}")

        try:
            choice = input(f"\nSelect (1-{len(modules)}): ")
            if choice.isdigit():
                index = int(choice) - 1
                if 0 <= index < len(modules):
                    return modules[index]
        except (ValueError, KeyboardInterrupt, EOFError):
            pass

        return None

    def _simple_select_operation(self, operations: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Simple operation selection fallback."""
        print("\nAvailable operations:")
        for i, op in enumerate(operations, 1):
            print(f"  {i}. {op.get('name')} - {op.get('description')}")

        try:
            choice = input(f"\nSelect (1-{len(operations)}): ")
            if choice.isdigit():
                index = int(choice) - 1
                if 0 <= index < len(operations):
                    return operations[index]
        except (ValueError, KeyboardInterrupt, EOFError):
            pass

        return None

    def _simple_select_target(self, targets: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Simple target selection fallback."""
        print("\nAvailable targets:")
        for i, target in enumerate(targets, 1):
            identifier = target.get('ip') or target.get('url', '')
            name = target.get('name', '')
            if name:
                print(f"  {i}. {identifier} ({name})")
            else:
                print(f"  {i}. {identifier}")

        try:
            choice = input(f"\nSelect (1-{len(targets)}): ")
            if choice.isdigit():
                index = int(choice) - 1
                if 0 <= index < len(targets):
                    return targets[index]
        except (ValueError, KeyboardInterrupt, EOFError):
            pass

        return None

    def _simple_select_credential(self, credentials: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Simple credential selection fallback."""
        print("\nAvailable credentials:")
        for i, cred in enumerate(credentials, 1):
            username = cred.get('username', '')
            domain = cred.get('domain', '')
            if domain:
                print(f"  {i}. {domain}\\{username}")
            else:
                print(f"  {i}. {username}")

        try:
            choice = input(f"\nSelect (1-{len(credentials)}): ")
            if choice.isdigit():
                index = int(choice) - 1
                if 0 <= index < len(credentials):
                    return credentials[index]
        except (ValueError, KeyboardInterrupt, EOFError):
            pass

        return None
