# Database Sync Utility

## Problem

If you have existing targets, credentials, or services that aren't showing up on the webserver, you may need to manually sync the databases.

## Solution

Run the sync script:

```bash
python3 scripts/sync_databases.py
```

This will:
1. Read all data from the legacy database (`~/.purplesploit/purplesploit.db`)
2. Sync it to the new models database files used by the webserver
3. Show you a summary of what was synced

## When to Run This

- After upgrading to the new version
- If the webserver shows fewer items than the CLI
- If services from nmap scans don't appear on the webserver

## Normal Operation

Under normal circumstances, the sync happens automatically when purplesploit starts. However, if you:

1. Started purplesploit
2. Added data (targets/creds/services)
3. Then started the webserver

The webserver should see all the data within 10 seconds (auto-refresh interval).

## Troubleshooting

If data still doesn't show up after running the sync script:

1. **Restart purplesploit completely**
   ```bash
   # Stop any running webserver
   purplesploit> webserver stop
   # Exit purplesploit
   purplesploit> exit
   # Start fresh
   ./purplesploit
   purplesploit> webserver start
   ```

2. **Check the databases exist**
   ```bash
   ls -la ~/.purplesploit/*.db
   ```

3. **Run the sync script with verbose output**
   ```bash
   python3 scripts/sync_databases.py
   ```

4. **Check the webserver is running**
   ```bash
   curl http://localhost:5000/api/targets
   curl http://localhost:5000/api/credentials
   curl http://localhost:5000/api/services
   ```

## Database Locations

All databases are stored in `~/.purplesploit/`:

- `purplesploit.db` - Legacy unified database (used by CLI)
- `credentials.db` - Credentials (used by webserver)
- `targets.db` - Targets (used by webserver)
- `web_targets.db` - Web targets (used by webserver)
- `services.db` - Services (used by webserver)
- `exploits.db` - Exploits (used by webserver)
