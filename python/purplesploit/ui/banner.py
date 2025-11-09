"""
PurpleSploit Banner Module
Displays a random ASCII art banner from eight variants
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

BANNER_VARIANT_4 = """
                                       d8b                           d8b           d8,
                                       88P                           88P          `8P    d8P
                                      d88                           d88               d888888P
?88,.d88b,?88   d8P  88bd88b?88,.d88b,888   d8888b .d888b,?88,.d88b,888   d8888b   88b  ?88'
`?88'  ?88d88   88   88P'  ``?88'  ?88?88  d8b_,dP ?8b,   `?88'  ?88?88  d8P' ?88  88P  88P
  88b  d8P?8(  d88  d88       88b  d8P 88b 88b       `?8b   88b  d8P 88b 88b  d88 d88   88b
  888888P'`?88P'?8bd88'       888888P'  88b`?888P'`?888P'   888888P'  88b`?8888P'd88'   `?8b
  88P'                        88P'                          88P'
 d88                         d88                           d88
 ?8P                         ?8P                           ?8P
"""

BANNER_VARIANT_5 = """
             ,_      |\  _  ,      |\  _  o_|_
  |/\_|  |  /  | |/\_|/ |/ / \_|/\_|/ / \_| |
  |_/  \/|_/   |/|_/ |_/|_/ \/ |_/ |_/\_/ |/|_/
 (|             (|            (|
"""

BANNER_VARIANT_6 = """
                           8                      8         o   o
                           8                      8             8
.oPYo. o    o oPYo. .oPYo. 8 .oPYo. .oPYo. .oPYo. 8 .oPYo. o8  o8P
8    8 8    8 8  `' 8    8 8 8oooo8 Yb..   8    8 8 8    8  8   8
8    8 8    8 8     8    8 8 8.       'Yb. 8    8 8 8    8  8   8
8YooP' `YooP' 8     8YooP' 8 `Yooo' `YooP' 8YooP' 8 `YooP'  8   8
8 ....::.....:..::::8 ....:..:.....::.....:8 ....:..:.....::..::..:
8 ::::::::::::::::::8 :::::::::::::::::::::8 ::::::::::::::::::::::
..::::::::::::::::::..:::::::::::::::::::::..::::::::::::::::::::::
"""

BANNER_VARIANT_7 = """
                              `::.                          `::.          `::
                               ;;;                           ;;;        ;;,;;
         ,c  ,  =,,[[==        [[[,cc[[[cc.,cc[[[cc.         [[[ ,ccc,  =[[[[[[.
,$$$$$. $$'  $$$`$$$"``,$$$$$. $$'$$$___--'$$$____   ,$$$$$. $$'$$$"c$$$$$$$$
88""""88888   888888   88""""88\8o88b    ,o,.     88,88""''88\8o888   8888888,
MMoooMM' "YUM" MP"MM,  MMoooMM' MM;"YUMMMMP""YUMMMMP"MMoooMM' MM;"YUMMP MMMMMM
MMMP                   MMMP                          MMMP
###                    ###                           ###
"##b                   "##b                          "##b
"""

BANNER_VARIANT_8 = """
█ ▄▄   ▄   █▄▄▄▄ █ ▄▄  █     ▄███▄     ▄▄▄▄▄   █ ▄▄  █    ████▄ ▄█    ▄▄▄▄▀
█   █   █  █  ▄▀ █   █ █     █▀   ▀   █     ▀▄ █   █ █    █   █ ██ ▀▀▀ █
█▀▀▀ █   █ █▀▀▌  █▀▀▀  █     ██▄▄   ▄  ▀▀▀▀▄   █▀▀▀  █    █   █ ██     █
█    █   █ █  █  █     ███▄  █▄   ▄▀ ▀▄▄▄▄▀    █     ███▄ ▀████ ▐█    █
 █   █▄ ▄█   █    █        ▀ ▀███▀              █        ▀       ▐   ▀
  ▀   ▀▀▀   ▀      ▀                             ▀
"""

BANNERS = [
    BANNER_VARIANT_1,
    BANNER_VARIANT_2,
    BANNER_VARIANT_3,
    BANNER_VARIANT_4,
    BANNER_VARIANT_5,
    BANNER_VARIANT_6,
    BANNER_VARIANT_7,
    BANNER_VARIANT_8
]


def show_banner(variant: int = None) -> str:
    """
    Return a banner string, either random or specific variant.

    Args:
        variant: Optional specific variant (0-7). If None, random.

    Returns:
        Banner string
    """
    if variant is None:
        variant = random.randint(0, 7)

    if variant < 0 or variant >= len(BANNERS):
        variant = 0

    return BANNERS[variant]


def print_banner(variant: int = None, color: str = None) -> None:
    """
    Print a banner to stdout.

    Args:
        variant: Optional specific variant (0-7). If None, random.
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
        variant: Banner variant (0-7)

    Returns:
        Banner string
    """
    return show_banner(variant)


# Purple color code for styling
PURPLE = '\033[95m'
CYAN = '\033[96m'
RESET = '\033[0m'
