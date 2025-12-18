"""
Tests for the InteractiveSelector module.

Tests the fzf-style interactive selection with mouse/keyboard support.
"""

import pytest
from unittest.mock import MagicMock, patch, mock_open
from io import StringIO


class TestInteractiveSelectorInit:
    """Tests for InteractiveSelector initialization."""

    def test_init_checks_fzf_availability(self):
        """Test that init checks for fzf availability."""
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        # has_fzf should be a boolean
        assert isinstance(selector.has_fzf, bool)

    @patch('shutil.which')
    def test_init_sets_has_fzf_true_when_found(self, mock_which):
        """Test that has_fzf is True when fzf is found."""
        mock_which.return_value = '/usr/bin/fzf'
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        assert selector.has_fzf is True

    @patch('shutil.which')
    def test_init_sets_has_fzf_false_when_not_found(self, mock_which):
        """Test that has_fzf is False when fzf is not found."""
        mock_which.return_value = None
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        assert selector.has_fzf is False


class TestInteractiveSelectorGetAttr:
    """Tests for _get_attr helper method."""

    def test_get_attr_from_dict(self):
        """Test getting attribute from dictionary."""
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        obj = {'name': 'test', 'value': 42}
        assert selector._get_attr(obj, 'name') == 'test'
        assert selector._get_attr(obj, 'value') == 42

    def test_get_attr_from_object(self):
        """Test getting attribute from object."""
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        obj = MagicMock()
        obj.name = 'test'
        obj.value = 42
        assert selector._get_attr(obj, 'name') == 'test'
        assert selector._get_attr(obj, 'value') == 42

    def test_get_attr_returns_default_for_missing(self):
        """Test that default is returned for missing attribute."""
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        obj = {'name': 'test'}
        assert selector._get_attr(obj, 'missing', 'default') == 'default'

    def test_get_attr_returns_none_for_missing_no_default(self):
        """Test that None is returned when no default provided."""
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        obj = {'name': 'test'}
        assert selector._get_attr(obj, 'missing') is None


class TestSelectFromList:
    """Tests for select_from_list method."""

    def test_select_from_list_returns_none_for_empty(self):
        """Test that None is returned for empty list."""
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        result = selector.select_from_list([])
        assert result is None

    @patch('shutil.which')
    def test_select_from_list_uses_fzf_when_available(self, mock_which):
        """Test that fzf is used when available."""
        mock_which.return_value = '/usr/bin/fzf'
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        selector._fzf_select = MagicMock(return_value='selected')

        result = selector.select_from_list(['a', 'b', 'c'], prompt="Select: ")
        selector._fzf_select.assert_called_once()

    @patch('shutil.which')
    def test_select_from_list_uses_simple_fallback(self, mock_which):
        """Test that simple fallback is used when fzf not available."""
        mock_which.return_value = None
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        selector._simple_select = MagicMock(return_value='selected')

        result = selector.select_from_list(['a', 'b', 'c'], prompt="Select: ")
        selector._simple_select.assert_called_once()


class TestSelectModule:
    """Tests for select_module method."""

    def test_select_module_returns_none_for_empty(self):
        """Test that None is returned for empty modules list."""
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        result = selector.select_module([])
        assert result is None

    def test_select_module_auto_selects_single(self):
        """Test auto-selection when only one module."""
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        module = {'path': 'recon/nmap', 'name': 'Nmap', 'description': 'Scanner'}
        result = selector.select_module([module], auto_load_single=True)
        assert result == module

    def test_select_module_no_auto_select_when_disabled(self):
        """Test no auto-selection when disabled."""
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        selector.has_fzf = False
        selector._simple_select_module = MagicMock(return_value=None)

        module = {'path': 'recon/nmap', 'name': 'Nmap', 'description': 'Scanner'}
        result = selector.select_module([module], auto_load_single=False)
        selector._simple_select_module.assert_called_once()

    @patch('shutil.which')
    def test_select_module_formats_display(self, mock_which):
        """Test that modules are formatted for display."""
        mock_which.return_value = '/usr/bin/fzf'
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        selector._fzf_select = MagicMock(return_value=" 1. [RECON   ] recon/nmap                      Network scan")

        modules = [
            {'path': 'recon/nmap', 'name': 'Nmap', 'description': 'Network scanner', 'category': 'recon'}
        ]
        result = selector.select_module(modules, auto_load_single=False)
        assert result == modules[0]


class TestSelectOperation:
    """Tests for select_operation method."""

    def test_select_operation_returns_none_for_empty(self):
        """Test that None is returned for empty operations list."""
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        result = selector.select_operation([])
        assert result is None

    @patch('shutil.which')
    def test_select_operation_parses_selection(self, mock_which):
        """Test that selected operation is parsed correctly."""
        mock_which.return_value = '/usr/bin/fzf'
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        selector._fzf_select = MagicMock(return_value=" 1. Basic Scan                              Quick scan")

        operations = [
            {'name': 'Basic Scan', 'description': 'Quick scan', 'handler': 'op_basic'}
        ]
        result = selector.select_operation(operations)
        assert result == operations[0]


class TestSelectTarget:
    """Tests for select_target method."""

    def test_select_target_returns_none_for_empty(self):
        """Test that None is returned for empty targets list."""
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        result = selector.select_target([])
        assert result is None

    @patch('shutil.which')
    def test_select_target_formats_with_name(self, mock_which):
        """Test that targets are formatted with name."""
        mock_which.return_value = '/usr/bin/fzf'
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        selector._fzf_select = MagicMock(return_value=" 1. [NETWORK ] 192.168.1.1                (test-server)")

        targets = [
            {'ip': '192.168.1.1', 'name': 'test-server', 'type': 'network'}
        ]
        result = selector.select_target(targets)
        assert result == targets[0]

    @patch('shutil.which')
    def test_select_target_formats_without_name(self, mock_which):
        """Test that targets are formatted without name."""
        mock_which.return_value = '/usr/bin/fzf'
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        selector._fzf_select = MagicMock(return_value=" 1. [NETWORK ] 192.168.1.1")

        targets = [
            {'ip': '192.168.1.1', 'type': 'network'}
        ]
        result = selector.select_target(targets)
        assert result == targets[0]


class TestSelectCredential:
    """Tests for select_credential method."""

    def test_select_credential_returns_none_when_empty_no_add(self):
        """Test that None is returned for empty credentials without add option."""
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        result = selector.select_credential([], allow_add_new=False)
        assert result is None

    @patch('shutil.which')
    def test_select_credential_returns_add_new(self, mock_which):
        """Test that ADD_NEW is returned when add new selected."""
        mock_which.return_value = '/usr/bin/fzf'
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        selector._fzf_select = MagicMock(return_value="➕  Add New Credential")

        result = selector.select_credential([])
        assert result == "ADD_NEW"

    @patch('shutil.which')
    def test_select_credential_with_domain(self, mock_which):
        """Test credential selection with domain."""
        mock_which.return_value = '/usr/bin/fzf'
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        selector._fzf_select = MagicMock(return_value=" 1. CORP\\admin                        (admin-cred     ) [Pass:✓ Hash:✗]")

        credentials = [
            {'username': 'admin', 'domain': 'CORP', 'password': 'secret', 'name': 'admin-cred'}
        ]
        result = selector.select_credential(credentials)
        assert result == credentials[0]


class TestSelectService:
    """Tests for select_service method."""

    def test_select_service_returns_none_for_empty(self):
        """Test that None is returned for empty services list."""
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        result = selector.select_service([])
        assert result is None

    @patch('shutil.which')
    def test_select_service_parses_selection(self, mock_which):
        """Test that selected service is parsed correctly."""
        mock_which.return_value = '/usr/bin/fzf'
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        selector._fzf_select = MagicMock(return_value=" 1. 192.168.1.1           80    /tcp   http            nginx 1.18")

        services = [
            {'target': '192.168.1.1', 'port': '80', 'protocol': 'tcp', 'name': 'http', 'version': 'nginx 1.18'}
        ]
        result = selector.select_service(services)
        assert result == services[0]


class TestSelectWordlist:
    """Tests for select_wordlist method."""

    def test_select_wordlist_returns_none_for_empty(self):
        """Test that None is returned for empty wordlists list."""
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        result = selector.select_wordlist("directory", [])
        assert result is None

    @patch('shutil.which')
    def test_select_wordlist_parses_selection(self, mock_which):
        """Test that selected wordlist is parsed correctly."""
        mock_which.return_value = '/usr/bin/fzf'
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        selector._fzf_select = MagicMock(return_value=" 1. common                         /usr/share/wordlists/common.txt")

        wordlists = [
            {'name': 'common', 'path': '/usr/share/wordlists/common.txt'}
        ]
        result = selector.select_wordlist("directory", wordlists)
        assert result == wordlists[0]


class TestFzfSelect:
    """Tests for _fzf_select method."""

    @patch('subprocess.run')
    @patch('builtins.open', mock_open())
    def test_fzf_select_builds_correct_command(self, mock_run):
        """Test that fzf command is built correctly."""
        mock_run.return_value = MagicMock(returncode=0, stdout="selected\n")

        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        result = selector._fzf_select(['a', 'b', 'c'], "Select: ", False, None)

        # Verify fzf was called
        assert mock_run.called
        call_args = mock_run.call_args[0][0]
        assert 'fzf' in call_args

    @patch('subprocess.run')
    @patch('builtins.open', mock_open())
    def test_fzf_select_returns_selection(self, mock_run):
        """Test that fzf returns the selected item."""
        mock_run.return_value = MagicMock(returncode=0, stdout="selected item\n")

        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        result = selector._fzf_select(['a', 'b', 'c'], "Select: ", False, None)
        assert result == "selected item"

    @patch('subprocess.run')
    @patch('builtins.open', mock_open())
    def test_fzf_select_returns_none_on_cancel(self, mock_run):
        """Test that fzf returns None on cancel."""
        mock_run.return_value = MagicMock(returncode=1, stdout="")

        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        result = selector._fzf_select(['a', 'b', 'c'], "Select: ", False, None)
        assert result is None

    @patch('subprocess.run')
    @patch('builtins.open', side_effect=FileNotFoundError())
    def test_fzf_select_handles_file_not_found(self, mock_open_func, mock_run):
        """Test that fzf handles FileNotFoundError."""
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        result = selector._fzf_select(['a', 'b', 'c'], "Select: ", False, None)
        assert result is None

    @patch('subprocess.run')
    @patch('builtins.open', mock_open())
    def test_fzf_select_adds_multi_flag(self, mock_run):
        """Test that multi flag is added when requested."""
        mock_run.return_value = MagicMock(returncode=0, stdout="a\nb\n")

        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        result = selector._fzf_select(['a', 'b', 'c'], "Select: ", True, None)

        call_args = mock_run.call_args[0][0]
        assert '--multi' in call_args

    @patch('subprocess.run')
    @patch('builtins.open', mock_open())
    def test_fzf_select_adds_preview(self, mock_run):
        """Test that preview command is added when provided."""
        mock_run.return_value = MagicMock(returncode=0, stdout="selected\n")

        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        result = selector._fzf_select(['a', 'b', 'c'], "Select: ", False, "echo preview")

        call_args = mock_run.call_args[0][0]
        assert '--preview' in call_args


class TestSimpleSelectFallbacks:
    """Tests for simple selection fallback methods."""

    @patch('builtins.open')
    def test_simple_select_valid_choice(self, mock_open_func):
        """Test simple select with valid choice."""
        # Mock tty input/output
        mock_tty_in = MagicMock()
        mock_tty_in.readline.return_value = "2\n"
        mock_tty_out = MagicMock()

        mock_open_func.return_value.__enter__.side_effect = [mock_tty_in, mock_tty_out]

        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()

        result = selector._simple_select(['a', 'b', 'c'], "Select: ")
        assert result == 'b'

    @patch('builtins.open')
    def test_simple_select_invalid_choice(self, mock_open_func):
        """Test simple select with invalid choice."""
        mock_tty_in = MagicMock()
        mock_tty_in.readline.return_value = "invalid\n"
        mock_tty_out = MagicMock()

        mock_open_func.return_value.__enter__.side_effect = [mock_tty_in, mock_tty_out]

        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()

        result = selector._simple_select(['a', 'b', 'c'], "Select: ")
        assert result is None

    @patch('builtins.open')
    def test_simple_select_out_of_range(self, mock_open_func):
        """Test simple select with out of range choice."""
        mock_tty_in = MagicMock()
        mock_tty_in.readline.return_value = "10\n"
        mock_tty_out = MagicMock()

        mock_open_func.return_value.__enter__.side_effect = [mock_tty_in, mock_tty_out]

        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()

        result = selector._simple_select(['a', 'b', 'c'], "Select: ")
        assert result is None

    @patch('builtins.open')
    def test_simple_select_module_valid(self, mock_open_func):
        """Test simple module select with valid choice."""
        mock_tty_in = MagicMock()
        mock_tty_in.readline.return_value = "1\n"
        mock_tty_out = MagicMock()

        mock_open_func.return_value.__enter__.side_effect = [mock_tty_in, mock_tty_out]

        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()

        modules = [{'path': 'recon/nmap', 'description': 'Scanner'}]
        result = selector._simple_select_module(modules)
        assert result == modules[0]

    @patch('builtins.open')
    def test_simple_select_operation_valid(self, mock_open_func):
        """Test simple operation select with valid choice."""
        mock_tty_in = MagicMock()
        mock_tty_in.readline.return_value = "1\n"
        mock_tty_out = MagicMock()

        mock_open_func.return_value.__enter__.side_effect = [mock_tty_in, mock_tty_out]

        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()

        operations = [{'name': 'Basic Scan', 'description': 'Quick scan'}]
        result = selector._simple_select_operation(operations)
        assert result == operations[0]

    @patch('builtins.open')
    def test_simple_select_target_valid(self, mock_open_func):
        """Test simple target select with valid choice."""
        mock_tty_in = MagicMock()
        mock_tty_in.readline.return_value = "1\n"
        mock_tty_out = MagicMock()

        mock_open_func.return_value.__enter__.side_effect = [mock_tty_in, mock_tty_out]

        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()

        targets = [{'ip': '192.168.1.1', 'name': 'test'}]
        result = selector._simple_select_target(targets)
        assert result == targets[0]

    @patch('builtins.open')
    def test_simple_select_credential_valid(self, mock_open_func):
        """Test simple credential select with valid choice."""
        mock_tty_in = MagicMock()
        mock_tty_in.readline.return_value = "1\n"
        mock_tty_out = MagicMock()

        mock_open_func.return_value.__enter__.side_effect = [mock_tty_in, mock_tty_out]

        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()

        credentials = [{'username': 'admin', 'domain': 'CORP'}]
        result = selector._simple_select_credential(credentials)
        assert result == credentials[0]

    @patch('builtins.open')
    def test_simple_select_service_valid(self, mock_open_func):
        """Test simple service select with valid choice."""
        mock_tty_in = MagicMock()
        mock_tty_in.readline.return_value = "1\n"
        mock_tty_out = MagicMock()

        mock_open_func.return_value.__enter__.side_effect = [mock_tty_in, mock_tty_out]

        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()

        services = [{'target': '192.168.1.1', 'port': '80', 'name': 'http'}]
        result = selector._simple_select_service(services)
        assert result == services[0]

    @patch('builtins.open')
    def test_simple_select_wordlist_valid(self, mock_open_func):
        """Test simple wordlist select with valid choice."""
        mock_tty_in = MagicMock()
        mock_tty_in.readline.return_value = "1\n"
        mock_tty_out = MagicMock()

        mock_open_func.return_value.__enter__.side_effect = [mock_tty_in, mock_tty_out]

        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()

        wordlists = [{'name': 'common', 'path': '/path/to/common.txt'}]
        result = selector._simple_select_wordlist(wordlists)
        assert result == wordlists[0]


class TestInteractiveSelectorEdgeCases:
    """Tests for edge cases in InteractiveSelector."""

    def test_select_module_handles_object_attributes(self):
        """Test that select_module handles objects with attributes."""
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()

        # Create mock module object
        module = MagicMock()
        module.path = 'recon/nmap'
        module.name = 'Nmap'
        module.description = 'Network scanner'
        module.category = 'recon'

        result = selector.select_module([module], auto_load_single=True)
        assert result == module

    @patch('shutil.which')
    def test_select_handles_index_parsing_error(self, mock_which):
        """Test that selection handles index parsing errors."""
        mock_which.return_value = '/usr/bin/fzf'
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        selector._fzf_select = MagicMock(return_value="invalid line without index")

        operations = [{'name': 'Test', 'description': 'Test op'}]
        result = selector.select_operation(operations)
        assert result is None

    @patch('builtins.open', side_effect=KeyboardInterrupt())
    def test_simple_select_handles_keyboard_interrupt(self, mock_open_func):
        """Test that simple select handles KeyboardInterrupt."""
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()

        result = selector._simple_select(['a', 'b'], "Select: ")
        assert result is None

    @patch('builtins.open', side_effect=EOFError())
    def test_simple_select_handles_eof_error(self, mock_open_func):
        """Test that simple select handles EOFError."""
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()

        result = selector._simple_select(['a', 'b'], "Select: ")
        assert result is None

    @patch('shutil.which')
    def test_select_target_handles_url_type(self, mock_which):
        """Test that target selection handles URL type targets."""
        mock_which.return_value = '/usr/bin/fzf'
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()
        selector._fzf_select = MagicMock(return_value=" 1. [WEB     ] http://example.com")

        targets = [
            {'url': 'http://example.com', 'type': 'web'}
        ]
        result = selector.select_target(targets)
        assert result == targets[0]
