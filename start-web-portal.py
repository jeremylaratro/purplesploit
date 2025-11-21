#!/usr/bin/env python3
"""
PurpleSploit Web Portal Launcher
Run this from the repository root to start the web portal and API server
"""

import sys
from pathlib import Path

# Add the python directory to the path so we can import purplesploit
repo_root = Path(__file__).parent
python_dir = repo_root / "python"

if python_dir.exists():
    sys.path.insert(0, str(python_dir))

# Now we can import and run the server
try:
    from purplesploit.api.server import main

    print("=" * 70)
    print("🔮 PurpleSploit Web Portal & API Server")
    print("=" * 70)
    print()
    print("Starting server...")
    print("Web Portal: http://localhost:5000")
    print("API Docs:   http://localhost:5000/api/docs")
    print()
    print("Press Ctrl+C to stop")
    print("=" * 70)
    print()

    main()

except ImportError as e:
    print(f"Error: Failed to import purplesploit module: {e}")
    print()
    print("Make sure you're running this from the repository root:")
    print("  cd /path/to/purplesploit")
    print("  python start-web-portal.py")
    sys.exit(1)
except KeyboardInterrupt:
    print("\n\nShutting down server...")
    sys.exit(0)
