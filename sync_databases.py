#!/usr/bin/env python3
"""
Utility script to manually sync old database to new models database
"""

from pathlib import Path
import sys

# Add python directory to path
python_dir = Path(__file__).parent / "python"
sys.path.insert(0, str(python_dir))

from purplesploit.core.database import Database
from purplesploit.models.database import db_manager, TargetCreate, CredentialCreate

def main():
    """Sync old database to models database"""
    print("🔄 Syncing databases...")

    # Initialize old database
    old_db = Database()

    # Sync targets
    print("\n📍 Syncing targets...")
    targets = old_db.get_targets()
    print(f"Found {len(targets)} targets in old database")

    synced_targets = 0
    for target in targets:
        if target['type'] == 'network':
            try:
                identifier = target['identifier']
                name = target.get('name') or identifier
                target_create = TargetCreate(
                    name=name,
                    ip=identifier,
                    description=f"Synced from legacy database - {target['type']}"
                )
                db_manager.add_target(target_create)
                print(f"  ✓ Synced target: {identifier}")
                synced_targets += 1
            except Exception as e:
                print(f"  ℹ Target {identifier} already exists (or error: {e})")

    print(f"Synced {synced_targets} targets")

    # Sync credentials
    print("\n🔑 Syncing credentials...")
    creds = old_db.get_credentials()
    print(f"Found {len(creds)} credentials in old database")

    synced_creds = 0
    for cred in creds:
        try:
            name = cred.get('name') or cred['username']
            cred_create = CredentialCreate(
                name=name,
                username=cred['username'],
                password=cred.get('password'),
                domain=cred.get('domain'),
                hash=cred.get('hash')
            )
            db_manager.add_credential(cred_create)
            print(f"  ✓ Synced credential: {cred['username']}")
            synced_creds += 1
        except Exception as e:
            print(f"  ℹ Credential {cred['username']} already exists (or error: {e})")

    print(f"Synced {synced_creds} credentials")

    # Sync services
    print("\n🔧 Syncing services...")
    services = old_db.get_services()
    print(f"Found {len(services)} services in old database")

    synced_services = 0
    for service in services:
        try:
            db_manager.add_service(
                service['target'],
                service['service'],
                service['port'],
                service.get('version')
            )
            print(f"  ✓ Synced service: {service['target']}:{service['port']} ({service['service']})")
            synced_services += 1
        except Exception as e:
            print(f"  ℹ Service {service['target']}:{service['port']} already exists (or error: {e})")

    print(f"Synced {synced_services} services")

    # Show summary
    print("\n" + "="*60)
    print("SYNC SUMMARY")
    print("="*60)
    print(f"Targets:     {synced_targets}/{len(targets)}")
    print(f"Credentials: {synced_creds}/{len(creds)}")
    print(f"Services:    {synced_services}/{len(services)}")
    print("="*60)

    # Show what's in models database
    print("\n📊 Models database contents:")
    all_targets = db_manager.get_all_targets()
    all_creds = db_manager.get_all_credentials()

    print(f"\nTargets ({len(all_targets)}):")
    for t in all_targets:
        print(f"  - {t.name}: {t.ip}")

    print(f"\nCredentials ({len(all_creds)}):")
    for c in all_creds:
        print(f"  - {c.name}: {c.username}")

    print(f"\nServices:")
    services_session = db_manager.get_services_session()
    try:
        from purplesploit.models.database import Service
        all_services = services_session.query(Service).all()
        print(f"Total services: {len(all_services)}")

        # Group by target
        by_target = {}
        for s in all_services:
            if s.target not in by_target:
                by_target[s.target] = []
            by_target[s.target].append(s)

        for target, services_list in by_target.items():
            print(f"\n  {target}:")
            for s in services_list:
                version_str = f" ({s.version})" if s.version else ""
                print(f"    - {s.service}:{s.port}{version_str}")
    finally:
        services_session.close()

    print("\n✅ Sync complete!")

if __name__ == "__main__":
    main()
