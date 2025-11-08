"""
PurpleSploit Banner Module
Displays a random ASCII art banner from three variants
"""

import random


# Banner variants
BANNER_VARIANT_1 = """
 ██▓███   █    ██  ██▀███   ██▓███   ██▓    ▓█████   ██████  ██▓███   ██▓     ▒█████   ██▓▄▄▄█████▓
▓██░  ██▒ ██  ▓██▒▓██ ▒ ██▒▓██░  ██▒▓██▒    ▓█   ▀ ▒██    ▒ ▓██░  ██▒▓██▒    ▒██▒  ██▒▓██▒▓  ██▒ ▓▒
▓██░ ██▓▒▓██  ▒██░▓██ ░▄█ ▒▓██░ ██▓▒▒██░    ▒███   ░ ▓██▄   ▓██░ ██▓▒▒██░    ▒██░  ██▒▒██▒▒ ▓██░ ▒░
▒██▄█▓▒ ▒▓▓█  ░██░▒██▀▀█▄  ▒██▄█▓▒ ▒▒██░    ▒▓█  ▄   ▒   ██▒▒██▄█▓▒ ▒▒██░    ▒██   ██░░██░░ ▓██▓ ░
▒██▒ ░  ░▒▒█████▓ ░██▓ ▒██▒▒██▒ ░  ░░██████▒░▒████▒▒██████▒▒▒██▒ ░  ░░██████▒░ ████▓▒░░██░  ▒██▒ ░
▒▓▒░ ░  ░░▒▓▒ ▒ ▒ ░ ▒▓ ░▒▓░▒▓▒░ ░  ░░ ▒░▓  ░░░ ▒░ ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░░ ▒░▓  ░░ ▒░▒░▒░ ░▓    ▒ ░░
░▒ ░     ░░▒░ ░ ░   ░▒ ░ ▒░░▒ ░     ░ ░ ▒  ░ ░ ░  ░░ ░▒  ░ ░░▒ ░     ░ ░ ▒  ░  ░ ▒ ▒░  ▒ ░    ░
░░        ░░░ ░ ░   ░░   ░ ░░         ░ ░      ░   ░  ░  ░  ░░         ░ ░   ░ ░ ░ ▒   ▒ ░  ░
            ░        ░                  ░  ░   ░  ░      ░               ░  ░    ░ ░   ░
"""

BANNER_VARIANT_2 = """
▄▄▄▄  █  ▐▌ ▄▄▄ ▄▄▄▄  █ ▗▞▀▚▖ ▄▄▄ ▄▄▄▄  █  ▄▄▄  ▄    ■
█   █ ▀▄▄▞▘█    █   █ █ ▐▛▀▀▘▀▄▄  █   █ █ █   █ ▄ ▗▄▟▙▄▖
█▄▄▄▀      █    █▄▄▄▀ █ ▝▚▄▄▖▄▄▄▀ █▄▄▄▀ █ ▀▄▄▄▀ █   ▐▌
█               █     █           █     █       █   ▐▌
▀               ▀                 ▀                 ▐▌
"""

BANNER_VARIANT_3 = """
@@@@@@@  @@@  @@@ @@@@@@@  @@@@@@@  @@@      @@@@@@@@  @@@@@@ @@@@@@@  @@@       @@@@@@  @@@ @@@@@@@
@@!  @@@ @@!  @@@ @@!  @@@ @@!  @@@ @@!      @@!      !@@     @@!  @@@ @@!      @@!  @@@ @@!   @!!
@!@@!@!  @!@  !@! @!@!!@!  @!@@!@!  @!!      @!!!:!    !@@!!  @!@@!@!  @!!      @!@  !@! !!@   @!!
!!:      !!:  !!! !!: :!!  !!:      !!:      !!:          !:! !!:      !!:      !!:  !!! !!:   !!:
 :        :.:: :   :   : :  :       : ::.: : : :: ::  ::.: :   :       : ::.: :  : :. :  :      :
"""

BANNERS = [BANNER_VARIANT_1, BANNER_VARIANT_2, BANNER_VARIANT_3]


def show_banner(variant: int = None) -> str:
    """
    Return a banner string, either random or specific variant.

    Args:
        variant: Optional specific variant (0, 1, or 2). If None, random.

    Returns:
        Banner string
    """
    if variant is None:
        variant = random.randint(0, 2)

    if variant < 0 or variant >= len(BANNERS):
        variant = 0

    return BANNERS[variant]


def print_banner(variant: int = None, color: str = None) -> None:
    """
    Print a banner to stdout.

    Args:
        variant: Optional specific variant (0, 1, or 2). If None, random.
        color: Optional color code (e.g., '\033[95m' for purple)
    """
    banner = show_banner(variant)

    if color:
        print(f"{color}{banner}\033[0m")
    else:
        print(banner)


def get_banner_variant(variant: int) -> str:
    """
    Get a specific banner variant.

    Args:
        variant: Banner variant (0, 1, or 2)

    Returns:
        Banner string
    """
    return show_banner(variant)


# Purple color code for styling
PURPLE = '\033[95m'
CYAN = '\033[96m'
RESET = '\033[0m'
