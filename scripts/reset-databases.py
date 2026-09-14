#!/usr/bin/env python3
"""
PurpleSploit Database Reset Tool
Use this if you encounter database errors
"""

import sys
from pathlib import Path

# Add the python directory to the path
repo_root = Path(__file__).parent.parent  # Go up one level from scripts/
python_dir = repo_root / "python"

if python_dir.exists():
    sys.path.insert(0, str(python_dir))

try:
    from purplesploit.models.database import (
        db_manager, DatabaseManager,
        DB_DIR, CREDENTIALS_DB, TARGETS_DB, WEB_TARGETS_DB,
        AD_TARGETS_DB, SERVICES_DB, EXPLOITS_DB
    )

    print("=" * 70)
    print("🔮 PurpleSploit Database Reset Tool")
    print("=" * 70)
    print()
    print("This will remove all database files and recreate them.")
    print("⚠️  WARNING: This will delete ALL your saved data!")
    print()
    print(f"Database directory: {DB_DIR}")
    print()

    # List existing databases
    db_files = [
        ("Credentials", CREDENTIALS_DB),
        ("Targets", TARGETS_DB),
        ("Web Targets", WEB_TARGETS_DB),
        ("AD Targets", AD_TARGETS_DB),
        ("Services", SERVICES_DB),
        ("Exploits", EXPLOITS_DB),
    ]

    print("Databases found:")
    for name, db_path in db_files:
        if db_path.exists():
            size = db_path.stat().st_size
            print(f"  ✓ {name}: {db_path.name} ({size} bytes)")
        else:
            print(f"  - {name}: {db_path.name} (not found)")

    print()
    response = input("Do you want to reset all databases? (yes/no): ").strip().lower()

    if response not in ['yes', 'y']:
        print("Cancelled. No changes made.")
        sys.exit(0)

    print()
    print("Removing databases...")

    # Release every SQLAlchemy connection before unlinking database files.
    for engine in db_manager.engines.values():
        engine.dispose()

    # Remove all database files
    removed = 0
    for name, db_path in db_files:
        if db_path.exists():
            try:
                db_path.unlink()
                Path(f"{db_path}-wal").unlink(missing_ok=True)
                Path(f"{db_path}-shm").unlink(missing_ok=True)
                print(f"  ✓ Removed {name}")
                removed += 1
            except Exception as e:
                print(f"  ✗ Error removing {name}: {e}")
        else:
            print(f"  - {name} (not found)")

    print()
    print(f"Removed {removed} database file(s)")

    # Now recreate databases
    print()
    print("Recreating databases...")

    recreated_manager = DatabaseManager()
    recreated_manager.get_all_targets()

    print("  ✓ Database tables created successfully")
    print()
    print("=" * 70)
    print("✅ Database reset complete!")
    print("=" * 70)
    print()
    print("You can now start using PurpleSploit with fresh databases.")
    print()

except ImportError as e:
    print(f"Error: Failed to import purplesploit module: {e}")
    print()
    print("Make sure you're running this from the repository root:")
    print("  cd /path/to/purplesploit")
    print("  python scripts/reset-databases.py")
    sys.exit(1)
except KeyboardInterrupt:
    print("\n\nCancelled by user.")
    sys.exit(0)
except Exception as e:
    print(f"\n❌ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
