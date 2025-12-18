"""
Tests for the SQLMap module.

Tests the SQLMap SQL injection module properties, command building, and output parsing.
"""

import pytest
from unittest.mock import MagicMock


class TestSQLMapModuleProperties:
    """Tests for SQLMap module properties."""

    @pytest.fixture
    def sqlmap_module(self, mock_framework_minimal):
        """Create SQLMap module instance for testing."""
        from purplesploit.modules.web.sqlmap import SQLMapModule
        return SQLMapModule(mock_framework_minimal)

    def test_name(self, sqlmap_module):
        """Test module name."""
        assert sqlmap_module.name == "SQLMap"

    def test_description(self, sqlmap_module):
        """Test module description."""
        assert "SQL injection" in sqlmap_module.description

    def test_category(self, sqlmap_module):
        """Test module category is web."""
        assert sqlmap_module.category == "web"

    def test_tool_name(self, sqlmap_module):
        """Test tool name is sqlmap."""
        assert sqlmap_module.tool_name == "sqlmap"

    def test_author(self, sqlmap_module):
        """Test module author."""
        assert sqlmap_module.author == "PurpleSploit Team"

    def test_has_url_option(self, sqlmap_module):
        """Test that URL option exists."""
        assert "URL" in sqlmap_module.options

    def test_url_is_required(self, sqlmap_module):
        """Test that URL is required."""
        assert sqlmap_module.options["URL"]["required"] is True


class TestSQLMapCommandBuilding:
    """Tests for SQLMap command building."""

    @pytest.fixture
    def sqlmap_module(self, mock_framework_minimal):
        """Create SQLMap module instance for testing."""
        from purplesploit.modules.web.sqlmap import SQLMapModule
        return SQLMapModule(mock_framework_minimal)

    def test_build_command_basic(self, sqlmap_module):
        """Test building basic command."""
        sqlmap_module.set_option("URL", "http://target.com/page.php?id=1")
        cmd = sqlmap_module.build_command()
        assert "sqlmap -u 'http://target.com/page.php?id=1'" in cmd

    def test_build_command_with_post_data(self, sqlmap_module):
        """Test building command with POST data."""
        sqlmap_module.set_option("URL", "http://target.com/login.php")
        sqlmap_module.set_option("DATA", "user=admin&pass=test")
        cmd = sqlmap_module.build_command()
        assert "--data='user=admin&pass=test'" in cmd

    def test_build_command_with_cookie(self, sqlmap_module):
        """Test building command with cookie."""
        sqlmap_module.set_option("URL", "http://target.com/page.php?id=1")
        sqlmap_module.set_option("COOKIE", "session=abc123")
        cmd = sqlmap_module.build_command()
        assert "--cookie='session=abc123'" in cmd

    def test_build_command_with_level(self, sqlmap_module):
        """Test building command with level."""
        sqlmap_module.set_option("URL", "http://target.com/page.php?id=1")
        sqlmap_module.set_option("LEVEL", "3")
        cmd = sqlmap_module.build_command()
        assert "--level=3" in cmd

    def test_build_command_with_risk(self, sqlmap_module):
        """Test building command with risk."""
        sqlmap_module.set_option("URL", "http://target.com/page.php?id=1")
        sqlmap_module.set_option("RISK", "2")
        cmd = sqlmap_module.build_command()
        assert "--risk=2" in cmd

    def test_build_command_with_threads(self, sqlmap_module):
        """Test building command with threads."""
        sqlmap_module.set_option("URL", "http://target.com/page.php?id=1")
        sqlmap_module.set_option("THREADS", "5")
        cmd = sqlmap_module.build_command()
        assert "--threads=5" in cmd

    def test_build_command_batch_mode(self, sqlmap_module):
        """Test building command with batch mode."""
        sqlmap_module.set_option("URL", "http://target.com/page.php?id=1")
        sqlmap_module.set_option("BATCH", "true")
        cmd = sqlmap_module.build_command()
        assert "--batch" in cmd

    def test_build_command_dbs_enumeration(self, sqlmap_module):
        """Test building command with database enumeration."""
        sqlmap_module.set_option("URL", "http://target.com/page.php?id=1")
        sqlmap_module.set_option("DBS", "true")
        cmd = sqlmap_module.build_command()
        assert "--dbs" in cmd

    def test_build_command_tables_enumeration(self, sqlmap_module):
        """Test building command with table enumeration."""
        sqlmap_module.set_option("URL", "http://target.com/page.php?id=1")
        sqlmap_module.set_option("TABLES", "true")
        sqlmap_module.set_option("DB", "users_db")
        cmd = sqlmap_module.build_command()
        assert "--tables" in cmd
        assert "-D users_db" in cmd

    def test_build_command_dump(self, sqlmap_module):
        """Test building command with dump."""
        sqlmap_module.set_option("URL", "http://target.com/page.php?id=1")
        sqlmap_module.set_option("DUMP", "true")
        sqlmap_module.set_option("DB", "users_db")
        sqlmap_module.set_option("TBL", "users")
        cmd = sqlmap_module.build_command()
        assert "--dump" in cmd
        assert "-D users_db" in cmd
        assert "-T users" in cmd

    def test_build_command_dump_all(self, sqlmap_module):
        """Test building command with dump all."""
        sqlmap_module.set_option("URL", "http://target.com/page.php?id=1")
        sqlmap_module.set_option("DUMP_ALL", "true")
        cmd = sqlmap_module.build_command()
        assert "--dump-all" in cmd


class TestSQLMapOutputParsing:
    """Tests for SQLMap output parsing."""

    @pytest.fixture
    def sqlmap_module(self, mock_framework_minimal):
        """Create SQLMap module instance for testing."""
        from purplesploit.modules.web.sqlmap import SQLMapModule
        return SQLMapModule(mock_framework_minimal)

    def test_parse_output_empty(self, sqlmap_module):
        """Test parsing empty output."""
        result = sqlmap_module.parse_output("")
        assert result["vulnerable"] is False
        assert result["injection_type"] == []
        assert result["databases"] == []

    def test_parse_output_vulnerable(self, sqlmap_module):
        """Test parsing output indicating vulnerability."""
        output = """[INFO] target URL is vulnerable
Parameter: id (GET)
    Type: boolean-based blind
"""
        result = sqlmap_module.parse_output(output)
        assert result["vulnerable"] is True

    def test_parse_output_extracts_injection_type(self, sqlmap_module):
        """Test extracting injection type from output."""
        output = """[INFO] testing for SQL injection
    Type: boolean-based blind
    Type: time-based blind
"""
        result = sqlmap_module.parse_output(output)
        assert "boolean-based blind" in result["injection_type"]
        assert "time-based blind" in result["injection_type"]

    def test_parse_output_extracts_databases(self, sqlmap_module):
        """Test extracting databases from output."""
        output = """available databases [3]:
[*] information_schema
[*] mysql
[*] users_db
"""
        result = sqlmap_module.parse_output(output)
        assert "information_schema" in result["databases"]
        assert "mysql" in result["databases"]
        assert "users_db" in result["databases"]

    def test_parse_output_ignores_starting_marker(self, sqlmap_module):
        """Test that [*] starting markers are ignored."""
        output = """[*] starting @12:00:00 /2024-01-01/
[*] users_db
"""
        result = sqlmap_module.parse_output(output)
        # Should only include users_db, not the starting marker
        assert "users_db" in result["databases"]


class TestSQLMapModuleOptions:
    """Tests for SQLMap module option defaults."""

    @pytest.fixture
    def sqlmap_module(self, mock_framework_minimal):
        """Create SQLMap module instance for testing."""
        from purplesploit.modules.web.sqlmap import SQLMapModule
        return SQLMapModule(mock_framework_minimal)

    def test_default_level(self, sqlmap_module):
        """Test default level is 1."""
        assert sqlmap_module.options["LEVEL"]["default"] == "1"

    def test_default_risk(self, sqlmap_module):
        """Test default risk is 1."""
        assert sqlmap_module.options["RISK"]["default"] == "1"

    def test_default_threads(self, sqlmap_module):
        """Test default threads is 10."""
        assert sqlmap_module.options["THREADS"]["default"] == "10"

    def test_default_batch_enabled(self, sqlmap_module):
        """Test that batch mode is enabled by default."""
        assert sqlmap_module.options["BATCH"]["default"] == "true"

    def test_default_dbs_disabled(self, sqlmap_module):
        """Test that DBS is disabled by default."""
        assert sqlmap_module.options["DBS"]["default"] == "false"

    def test_default_dump_disabled(self, sqlmap_module):
        """Test that DUMP is disabled by default."""
        assert sqlmap_module.options["DUMP"]["default"] == "false"

    def test_optional_data_option(self, sqlmap_module):
        """Test that DATA option is optional."""
        assert sqlmap_module.options["DATA"]["required"] is False

    def test_optional_cookie_option(self, sqlmap_module):
        """Test that COOKIE option is optional."""
        assert sqlmap_module.options["COOKIE"]["required"] is False
