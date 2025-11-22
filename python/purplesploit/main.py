"""
PurpleSploit Main Entry Point

Offensive security framework with persistent context and improved usability.
"""

import sys
import argparse
from pathlib import Path

from .core.framework import Framework
from .ui.console import Console


def main():
    """Main entry point for PurpleSploit."""
    # Parse arguments
    parser = argparse.ArgumentParser(
        description="PurpleSploit - Offensive Security Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  purplesploit                    Start interactive console
  purplesploit --modules ./modules  Use custom modules directory
  purplesploit --db ./custom.db   Use custom database file

For more information, visit: https://github.com/jeremylaratro/purplesploit
"""
    )

    parser.add_argument(
        '--modules',
        type=str,
        help='Path to modules directory',
        default=None
    )

    parser.add_argument(
        '--db',
        type=str,
        help='Path to database file',
        default=None
    )

    parser.add_argument(
        '--version',
        action='version',
        version='PurpleSploit 6.1.0'
    )

    args = parser.parse_args()

    try:
        # Initialize framework
        # Use project-local database path to keep everything self-contained
        # Database stored in purplesploit project root directory
        import os
        if args.db:
            db_path = args.db
        elif os.getenv('PURPLESPLOIT_DB'):
            db_path = os.getenv('PURPLESPLOIT_DB')
        else:
            # Default: project_root/.data/purplesploit.db
            project_root = Path(__file__).parent.parent.parent
            data_dir = project_root / '.data'
            data_dir.mkdir(exist_ok=True)
            db_path = str(data_dir / 'purplesploit.db')

        framework = Framework(
            modules_path=args.modules,
            db_path=db_path
        )

        # Discover modules
        framework.discover_modules()

        # Start console
        console = Console(framework)
        console.start()

    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(0)

    except Exception as e:
        print(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
