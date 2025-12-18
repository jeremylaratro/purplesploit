"""
Tests for the BaseCommandMixin class.

Tests the command infrastructure including registration, aliases, and parsing.
"""

import pytest
from unittest.mock import MagicMock


class TestBaseCommandMixinInit:
    """Tests for BaseCommandMixin initialization."""

    def test_init_creates_empty_commands_dict(self):
        """Test that init creates empty commands dict."""
        from purplesploit.ui.command_mixins.base import BaseCommandMixin

        class TestHandler(BaseCommandMixin):
            def __init__(self):
                self._init_base_commands()

        handler = TestHandler()
        assert handler.commands == {}

    def test_init_creates_empty_aliases_dict(self):
        """Test that init creates empty aliases dict."""
        from purplesploit.ui.command_mixins.base import BaseCommandMixin

        class TestHandler(BaseCommandMixin):
            def __init__(self):
                self._init_base_commands()

        handler = TestHandler()
        assert handler.aliases == {}

    def test_init_creates_empty_search_results(self):
        """Test that init creates empty search results list."""
        from purplesploit.ui.command_mixins.base import BaseCommandMixin

        class TestHandler(BaseCommandMixin):
            def __init__(self):
                self._init_base_commands()

        handler = TestHandler()
        assert handler.last_search_results == []

    def test_init_creates_empty_ops_results(self):
        """Test that init creates empty ops results list."""
        from purplesploit.ui.command_mixins.base import BaseCommandMixin

        class TestHandler(BaseCommandMixin):
            def __init__(self):
                self._init_base_commands()

        handler = TestHandler()
        assert handler.last_ops_results == []


class TestRegisterCommand:
    """Tests for register_command method."""

    @pytest.fixture
    def handler(self):
        """Create test handler instance."""
        from purplesploit.ui.command_mixins.base import BaseCommandMixin

        class TestHandler(BaseCommandMixin):
            def __init__(self):
                self._init_base_commands()

        return TestHandler()

    def test_register_command_basic(self, handler):
        """Test registering a basic command."""
        def test_func(args):
            return True

        handler.register_command("test", test_func)
        assert "test" in handler.commands
        assert handler.commands["test"] == test_func

    def test_register_command_with_single_alias(self, handler):
        """Test registering command with single alias."""
        def test_func(args):
            return True

        handler.register_command("test", test_func, aliases=["t"])
        assert "test" in handler.commands
        assert "t" in handler.aliases
        assert handler.aliases["t"] == "test"

    def test_register_command_with_multiple_aliases(self, handler):
        """Test registering command with multiple aliases."""
        def test_func(args):
            return True

        handler.register_command("help", test_func, aliases=["?", "h"])
        assert "help" in handler.commands
        assert "?" in handler.aliases
        assert "h" in handler.aliases
        assert handler.aliases["?"] == "help"
        assert handler.aliases["h"] == "help"

    def test_register_command_without_aliases(self, handler):
        """Test registering command without aliases."""
        def test_func(args):
            return True

        handler.register_command("test", test_func)
        assert "test" in handler.commands
        assert len(handler.aliases) == 0

    def test_register_command_overwrites_existing(self, handler):
        """Test that registering overwrites existing command."""
        def func1(args):
            return 1

        def func2(args):
            return 2

        handler.register_command("test", func1)
        handler.register_command("test", func2)
        assert handler.commands["test"] == func2


class TestGetHandler:
    """Tests for get_handler method."""

    @pytest.fixture
    def handler(self):
        """Create test handler with commands."""
        from purplesploit.ui.command_mixins.base import BaseCommandMixin

        class TestHandler(BaseCommandMixin):
            def __init__(self):
                self._init_base_commands()

        h = TestHandler()

        def help_func(args):
            return "help"

        def exit_func(args):
            return "exit"

        h.register_command("help", help_func, aliases=["?", "h"])
        h.register_command("exit", exit_func, aliases=["quit"])
        return h

    def test_get_handler_by_name(self, handler):
        """Test getting handler by command name."""
        result = handler.get_handler("help")
        assert result is not None
        assert result([]) == "help"

    def test_get_handler_by_alias(self, handler):
        """Test getting handler by alias."""
        result = handler.get_handler("?")
        assert result is not None
        assert result([]) == "help"

    def test_get_handler_case_insensitive(self, handler):
        """Test that handler lookup is case insensitive."""
        result = handler.get_handler("HELP")
        assert result is not None
        assert result([]) == "help"

    def test_get_handler_alias_case_insensitive(self, handler):
        """Test that alias lookup is case insensitive."""
        result = handler.get_handler("QUIT")
        assert result is not None
        assert result([]) == "exit"

    def test_get_handler_returns_none_for_unknown(self, handler):
        """Test that None is returned for unknown command."""
        result = handler.get_handler("unknown")
        assert result is None


class TestParseCommand:
    """Tests for parse_command method."""

    @pytest.fixture
    def handler(self):
        """Create test handler instance."""
        from purplesploit.ui.command_mixins.base import BaseCommandMixin

        class TestHandler(BaseCommandMixin):
            def __init__(self):
                self._init_base_commands()

        return TestHandler()

    def test_parse_command_simple(self, handler):
        """Test parsing simple command."""
        cmd, args = handler.parse_command("help")
        assert cmd == "help"
        assert args == []

    def test_parse_command_with_args(self, handler):
        """Test parsing command with arguments."""
        cmd, args = handler.parse_command("search nmap")
        assert cmd == "search"
        assert args == ["nmap"]

    def test_parse_command_with_multiple_args(self, handler):
        """Test parsing command with multiple arguments."""
        cmd, args = handler.parse_command("set RHOST 192.168.1.1")
        assert cmd == "set"
        assert args == ["RHOST", "192.168.1.1"]

    def test_parse_command_case_insensitive(self, handler):
        """Test that command is lowercased."""
        cmd, args = handler.parse_command("HELP")
        assert cmd == "help"

    def test_parse_command_with_quotes(self, handler):
        """Test parsing command with quoted argument."""
        cmd, args = handler.parse_command('set DATA "user=admin&pass=test"')
        assert cmd == "set"
        assert args == ["DATA", "user=admin&pass=test"]

    def test_parse_command_empty(self, handler):
        """Test parsing empty command."""
        cmd, args = handler.parse_command("")
        assert cmd == ""
        assert args == []

    def test_parse_command_whitespace_only(self, handler):
        """Test parsing whitespace-only command."""
        cmd, args = handler.parse_command("   ")
        assert cmd == ""
        assert args == []

    def test_parse_command_unclosed_quotes(self, handler):
        """Test parsing command with unclosed quotes falls back to split."""
        cmd, args = handler.parse_command('set DATA "unclosed')
        assert cmd == "set"
        # Falls back to simple split
        assert "DATA" in args


class TestGetAllCommands:
    """Tests for get_all_commands method."""

    @pytest.fixture
    def handler(self):
        """Create test handler with commands."""
        from purplesploit.ui.command_mixins.base import BaseCommandMixin

        class TestHandler(BaseCommandMixin):
            def __init__(self):
                self._init_base_commands()

        h = TestHandler()
        h.register_command("zebra", lambda x: x)
        h.register_command("alpha", lambda x: x)
        h.register_command("beta", lambda x: x)
        return h

    def test_get_all_commands_returns_list(self, handler):
        """Test that get_all_commands returns a list."""
        result = handler.get_all_commands()
        assert isinstance(result, list)

    def test_get_all_commands_sorted(self, handler):
        """Test that commands are sorted alphabetically."""
        result = handler.get_all_commands()
        assert result == ["alpha", "beta", "zebra"]

    def test_get_all_commands_empty(self):
        """Test get_all_commands with no commands."""
        from purplesploit.ui.command_mixins.base import BaseCommandMixin

        class TestHandler(BaseCommandMixin):
            def __init__(self):
                self._init_base_commands()

        h = TestHandler()
        result = h.get_all_commands()
        assert result == []


class TestGetCommandAliases:
    """Tests for get_command_aliases method."""

    @pytest.fixture
    def handler(self):
        """Create test handler with commands and aliases."""
        from purplesploit.ui.command_mixins.base import BaseCommandMixin

        class TestHandler(BaseCommandMixin):
            def __init__(self):
                self._init_base_commands()

        h = TestHandler()
        h.register_command("help", lambda x: x, aliases=["?", "h"])
        h.register_command("exit", lambda x: x, aliases=["quit", "q"])
        h.register_command("search", lambda x: x)  # No aliases
        return h

    def test_get_aliases_returns_list(self, handler):
        """Test that get_command_aliases returns a list."""
        result = handler.get_command_aliases("help")
        assert isinstance(result, list)

    def test_get_aliases_multiple(self, handler):
        """Test getting multiple aliases."""
        result = handler.get_command_aliases("help")
        assert "?" in result
        assert "h" in result
        assert len(result) == 2

    def test_get_aliases_no_aliases(self, handler):
        """Test getting aliases for command without aliases."""
        result = handler.get_command_aliases("search")
        assert result == []

    def test_get_aliases_unknown_command(self, handler):
        """Test getting aliases for unknown command."""
        result = handler.get_command_aliases("unknown")
        assert result == []
