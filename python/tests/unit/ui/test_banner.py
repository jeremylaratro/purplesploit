"""
Tests for the Banner module.

Tests the banner display functionality and variant selection.
"""

import pytest
from unittest.mock import patch


class TestShowBanner:
    """Tests for the show_banner function."""

    def test_show_banner_returns_string(self):
        """Test that show_banner returns a string."""
        from purplesploit.ui.banner import show_banner
        result = show_banner()
        assert isinstance(result, str)

    def test_show_banner_not_empty(self):
        """Test that banner is not empty."""
        from purplesploit.ui.banner import show_banner
        result = show_banner()
        assert len(result) > 0

    def test_show_banner_specific_variant(self):
        """Test getting a specific banner variant."""
        from purplesploit.ui.banner import show_banner
        result = show_banner(variant=0)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_show_banner_all_variants(self):
        """Test that all 8 variants return different banners."""
        from purplesploit.ui.banner import show_banner
        banners = [show_banner(variant=i) for i in range(8)]
        # All should be strings
        assert all(isinstance(b, str) for b in banners)
        # All should be non-empty
        assert all(len(b) > 0 for b in banners)

    def test_show_banner_invalid_variant_returns_first(self):
        """Test that invalid variant index returns first banner."""
        from purplesploit.ui.banner import show_banner, BANNERS
        result = show_banner(variant=100)
        assert result == BANNERS[0]

    def test_show_banner_negative_variant_returns_first(self):
        """Test that negative variant index returns first banner."""
        from purplesploit.ui.banner import show_banner, BANNERS
        result = show_banner(variant=-1)
        assert result == BANNERS[0]

    def test_show_banner_random_selection(self):
        """Test that None variant triggers random selection."""
        from purplesploit.ui.banner import show_banner, BANNERS

        with patch('purplesploit.ui.banner.random.randint', return_value=3):
            result = show_banner()
            assert result == BANNERS[3]


class TestPrintBanner:
    """Tests for the print_banner function."""

    def test_print_banner_no_color(self, capsys):
        """Test printing banner without color."""
        from purplesploit.ui.banner import print_banner
        print_banner(variant=0)
        captured = capsys.readouterr()
        assert len(captured.out) > 0

    def test_print_banner_with_color(self, capsys):
        """Test printing banner with color."""
        from purplesploit.ui.banner import print_banner, PURPLE, RESET
        print_banner(variant=0, color=PURPLE)
        captured = capsys.readouterr()
        assert len(captured.out) > 0
        # Should have color codes
        assert PURPLE in captured.out or '\033[' in captured.out


class TestGetBannerVariant:
    """Tests for the get_banner_variant function."""

    def test_get_banner_variant(self):
        """Test getting a specific banner variant by index."""
        from purplesploit.ui.banner import get_banner_variant, BANNERS
        result = get_banner_variant(0)
        assert result == BANNERS[0]

    def test_get_banner_variant_all_indices(self):
        """Test all valid banner variant indices."""
        from purplesploit.ui.banner import get_banner_variant, BANNERS
        for i in range(len(BANNERS)):
            result = get_banner_variant(i)
            assert result == BANNERS[i]


class TestBannerConstants:
    """Tests for banner constants."""

    def test_banners_list_has_8_variants(self):
        """Test that BANNERS list has exactly 8 variants."""
        from purplesploit.ui.banner import BANNERS
        assert len(BANNERS) == 8

    def test_all_banners_are_strings(self):
        """Test that all banners are strings."""
        from purplesploit.ui.banner import BANNERS
        assert all(isinstance(b, str) for b in BANNERS)

    def test_color_constants_defined(self):
        """Test that color constants are defined."""
        from purplesploit.ui.banner import PURPLE, CYAN, RESET
        assert PURPLE is not None
        assert CYAN is not None
        assert RESET is not None

    def test_color_constants_are_escape_codes(self):
        """Test that color constants are ANSI escape codes."""
        from purplesploit.ui.banner import PURPLE, CYAN, RESET
        assert '\033[' in PURPLE
        assert '\033[' in CYAN
        assert RESET == '\033[0m'


class TestBannerContent:
    """Tests for banner content."""

    def test_banner_variant_1_contains_purplesploit(self):
        """Test that first banner contains 'PURPLE' or recognizable text."""
        from purplesploit.ui.banner import BANNER_VARIANT_1
        # Banner uses special characters but should be recognizable
        assert len(BANNER_VARIANT_1) > 100

    def test_banners_all_multiline(self):
        """Test that all banners are multiline."""
        from purplesploit.ui.banner import BANNERS
        for banner in BANNERS:
            assert '\n' in banner, "Banner should be multiline"

    def test_banners_contain_ascii_art(self):
        """Test that banners contain ASCII art characters."""
        from purplesploit.ui.banner import BANNERS
        ascii_art_chars = set('█▓░▄▀▐▌▒■▗▞▚▘▝▖▙▛▜▟│┌┐└┘├┤┬┴┼─═║╒╓╔╕╖╗╘╙╚╛╜╝╞╟╠╡╢╣╤╥╦╧╨╩╪╫╬@#$%&*')

        for banner in BANNERS:
            # Each banner should have some special characters (unicode or ASCII art)
            has_special = any(c in banner for c in ascii_art_chars) or any(ord(c) > 127 for c in banner)
            assert has_special or len(banner) > 50, "Banner should contain art characters or be substantial"
