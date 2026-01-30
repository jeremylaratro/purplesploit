"""
Database Layer for PurpleSploit

SQLite-based storage for:
- Module execution history
- Scan results and findings
- Persistent workspaces
- Credential and target storage

Thread-safe implementation using connection pooling and locking.
"""

import sqlite3
import json
import threading
from contextlib import contextmanager
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path


class Database:
    """
    Thread-safe database manager for PurpleSploit.

    Uses a threading lock to ensure safe concurrent access to the SQLite database.
    Each write operation acquires the lock to prevent race conditions.
    """

    def __init__(self, db_path: str = None):
        """
        Initialize database connection.

        Args:
            db_path: Path to SQLite database file
        """
        if db_path is None:
            # Default to ~/.purplesploit/purplesploit.db
            home = Path.home()
            ps_dir = home / ".purplesploit"
            ps_dir.mkdir(exist_ok=True)
            db_path = str(ps_dir / "purplesploit.db")

        # Ensure parent directory exists for custom paths
        db_path_obj = Path(db_path)
        db_path_obj.parent.mkdir(parents=True, exist_ok=True)

        self.db_path = db_path
        self.conn = None
        self._lock = threading.RLock()  # Reentrant lock for thread safety
        self._local = threading.local()  # Thread-local storage for connections

        # Simple LRU cache for frequently accessed queries
        self._cache = {}
        self._cache_ttl = {}  # Time-to-live for cached items
        self._cache_max_age = 60  # Cache items for 60 seconds

        self._connect()
        self._migrate_database()  # Run migrations before creating tables/indexes
        self._create_tables()

    def _connect(self):
        """Establish database connection."""
        # Use check_same_thread=False to allow async operations across threads
        # Combined with our lock, this ensures thread-safe access
        self.conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            timeout=30.0  # Wait up to 30 seconds for locks
        )
        self.conn.row_factory = sqlite3.Row  # Enable dict-like access
        # Enable WAL mode for better concurrent read performance
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")

    @contextmanager
    def _get_cursor(self):
        """
        Context manager for thread-safe cursor access.

        Yields:
            A cursor object with automatic commit/rollback on exit.
        """
        with self._lock:
            cursor = self.conn.cursor()
            try:
                yield cursor
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise

    def _create_tables(self):
        """Create database tables if they don't exist."""
        cursor = self.conn.cursor()

        # Module execution history
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS module_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                module_name TEXT NOT NULL,
                module_path TEXT NOT NULL,
                executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                options TEXT,
                results TEXT,
                success BOOLEAN,
                error_message TEXT
            )
        """)

        # Create indexes for module_history
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_module_history_name
            ON module_history(module_name)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_module_history_executed
            ON module_history(executed_at DESC)
        """)

        # Targets
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,  -- 'web' or 'network'
                identifier TEXT NOT NULL,  -- IP or URL
                name TEXT,
                metadata TEXT,  -- JSON
                status TEXT DEFAULT 'unverified',  -- 'unverified', 'verified', 'subnet'
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(type, identifier)
            )
        """)

        # Create indexes for targets
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_targets_type
            ON targets(type)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_targets_status
            ON targets(status)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_targets_identifier
            ON targets(identifier)
        """)

        # Credentials
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                username TEXT NOT NULL,
                password TEXT,
                domain TEXT,
                hash TEXT,
                hash_type TEXT,
                metadata TEXT,  -- JSON
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Services detected on targets
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                service TEXT NOT NULL,
                port INTEGER NOT NULL,
                version TEXT,
                detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(target, service, port)
            )
        """)

        # Create indexes for services
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_services_target
            ON services(target)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_services_port
            ON services(port)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_services_service
            ON services(service)
        """)

        # Scan results (nmap, etc.)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_name TEXT NOT NULL,
                target TEXT NOT NULL,
                scan_type TEXT,  -- 'nmap', 'masscan', etc.
                results TEXT,  -- JSON
                file_path TEXT,  -- Path to full results file
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create indexes for scan_results
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_results_target
            ON scan_results(target)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_results_type
            ON scan_results(scan_type)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_results_created
            ON scan_results(created_at DESC)
        """)

        # Findings/vulnerabilities
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT,  -- 'critical', 'high', 'medium', 'low', 'info'
                description TEXT,
                module_name TEXT,
                evidence TEXT,
                remediation TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create indexes for findings
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_target
            ON findings(target)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_severity
            ON findings(severity)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_created
            ON findings(created_at DESC)
        """)

        # Workspaces
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS workspaces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP
            )
        """)

        # Module default settings
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS module_defaults (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                module_name TEXT NOT NULL,
                option_name TEXT NOT NULL,
                option_value TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(module_name, option_name)
            )
        """)

        # Create index for module_defaults
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_module_defaults_lookup
            ON module_defaults(module_name, option_name)
        """)

        self.conn.commit()

    def _migrate_database(self):
        """Apply database migrations for schema changes."""
        cursor = self.conn.cursor()

        # Check if tables exist first - if not, skip migrations (they'll be created fresh)
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='targets'")
        if cursor.fetchone():
            # Migration: Add 'status' column to targets table if it doesn't exist
            try:
                cursor.execute("SELECT status FROM targets LIMIT 1")
            except sqlite3.OperationalError:
                # Column doesn't exist, add it
                cursor.execute("""
                    ALTER TABLE targets ADD COLUMN status TEXT DEFAULT 'unverified'
                """)
                self.conn.commit()

        # Check if credentials table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='credentials'")
        if cursor.fetchone():
            # Migration: Add 'dcip' and 'dns' columns to credentials table if they don't exist
            try:
                cursor.execute("SELECT dcip FROM credentials LIMIT 1")
            except sqlite3.OperationalError:
                cursor.execute("""
                    ALTER TABLE credentials ADD COLUMN dcip TEXT
                """)
                self.conn.commit()

            try:
                cursor.execute("SELECT dns FROM credentials LIMIT 1")
            except sqlite3.OperationalError:
                cursor.execute("""
                    ALTER TABLE credentials ADD COLUMN dns TEXT
                """)
                self.conn.commit()

    def _invalidate_cache(self, pattern: str = None):
        """
        Invalidate cache entries.

        Args:
            pattern: If provided, only invalidate keys containing this pattern
        """
        if pattern is None:
            self._cache.clear()
            self._cache_ttl.clear()
        else:
            keys_to_delete = [k for k in self._cache.keys() if pattern in k]
            for key in keys_to_delete:
                del self._cache[key]
                if key in self._cache_ttl:
                    del self._cache_ttl[key]

    def _get_cached(self, cache_key: str):
        """
        Get item from cache if not expired.

        Args:
            cache_key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        if cache_key in self._cache:
            # Check if expired
            if cache_key in self._cache_ttl:
                import time
                if time.time() - self._cache_ttl[cache_key] > self._cache_max_age:
                    # Expired, remove from cache
                    del self._cache[cache_key]
                    del self._cache_ttl[cache_key]
                    return None
            return self._cache[cache_key]
        return None

    def _set_cached(self, cache_key: str, value: Any):
        """
        Set item in cache.

        Args:
            cache_key: Cache key
            value: Value to cache
        """
        import time
        self._cache[cache_key] = value
        self._cache_ttl[cache_key] = time.time()

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()

    # Module History Methods
    def add_module_execution(self, module_name: str, module_path: str,
                            options: Dict, results: Dict, success: bool,
                            error_message: str = None) -> int:
        """
        Record module execution.

        Args:
            module_name: Module name
            module_path: Module path
            options: Options used
            results: Execution results
            success: Whether execution succeeded
            error_message: Error message if failed

        Returns:
            ID of inserted record
        """
        with self._get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO module_history
                (module_name, module_path, options, results, success, error_message)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                module_name,
                module_path,
                json.dumps(options),
                json.dumps(results),
                success,
                error_message
            ))
            return cursor.lastrowid

    def get_module_history(self, module_name: str = None, limit: int = 100) -> List[Dict]:
        """
        Get module execution history.

        Args:
            module_name: Filter by module name
            limit: Maximum number of records

        Returns:
            List of execution records
        """
        with self._lock:
            cursor = self.conn.cursor()

            if module_name:
                cursor.execute("""
                    SELECT * FROM module_history
                    WHERE module_name = ?
                    ORDER BY executed_at DESC
                    LIMIT ?
                """, (module_name, limit))
            else:
                cursor.execute("""
                    SELECT * FROM module_history
                    ORDER BY executed_at DESC
                    LIMIT ?
                """, (limit,))

            return [dict(row) for row in cursor.fetchall()]

    # Target Methods
    def add_target(self, target_type: str, identifier: str,
                  name: str = None, metadata: Dict = None) -> bool:
        """
        Add a target.

        Args:
            target_type: 'web' or 'network'
            identifier: IP or URL (can be CIDR notation like 192.168.1.0/24)
            name: Optional name
            metadata: Additional metadata

        Returns:
            True if added (False if duplicate)
        """
        try:
            # Determine status: subnet, unverified, or verified
            status = 'unverified'
            if '/' in identifier and target_type == 'network':
                status = 'subnet'

            with self._get_cursor() as cursor:
                cursor.execute("""
                    INSERT INTO targets (type, identifier, name, metadata, status)
                    VALUES (?, ?, ?, ?, ?)
                """, (target_type, identifier, name, json.dumps(metadata or {}), status))

            # Invalidate targets cache
            self._invalidate_cache('targets_')

            return True
        except sqlite3.IntegrityError:
            return False

    def get_targets(self, target_type: str = None, exclude_subnets: bool = False) -> List[Dict]:
        """
        Get all targets.

        Args:
            target_type: Filter by type ('web' or 'network')
            exclude_subnets: If True, exclude targets with status='subnet'

        Returns:
            List of target dictionaries
        """
        # Try cache first for common queries
        cache_key = f"targets_{target_type}_{exclude_subnets}"
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        with self._lock:
            cursor = self.conn.cursor()

            if target_type and exclude_subnets:
                cursor.execute("SELECT * FROM targets WHERE type = ? AND status != 'subnet'", (target_type,))
            elif target_type:
                cursor.execute("SELECT * FROM targets WHERE type = ?", (target_type,))
            elif exclude_subnets:
                cursor.execute("SELECT * FROM targets WHERE status != 'subnet'")
            else:
                cursor.execute("SELECT * FROM targets")

            targets = []
            for row in cursor.fetchall():
                target = dict(row)
                target['metadata'] = json.loads(target['metadata'])
                targets.append(target)

            # Cache the result
            self._set_cached(cache_key, targets)

            return targets

    def remove_target(self, identifier: str) -> bool:
        """
        Remove a target.

        Args:
            identifier: IP or URL

        Returns:
            True if removed
        """
        with self._get_cursor() as cursor:
            cursor.execute("DELETE FROM targets WHERE identifier = ?", (identifier,))
            return cursor.rowcount > 0

    def mark_target_verified(self, identifier: str) -> bool:
        """
        Mark a target as verified (responsive to scans).

        Args:
            identifier: IP or URL

        Returns:
            True if updated
        """
        with self._get_cursor() as cursor:
            cursor.execute("UPDATE targets SET status = 'verified' WHERE identifier = ?", (identifier,))
            return cursor.rowcount > 0

    def clear_all_targets(self) -> int:
        """
        Remove all targets from the database.

        Returns:
            Number of targets removed
        """
        with self._get_cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM targets")
            count = cursor.fetchone()[0]
            cursor.execute("DELETE FROM targets")
            return count

    # Credential Methods
    def add_credential(self, username: str, password: str = None,
                      domain: str = None, hash_value: str = None,
                      hash_type: str = None, name: str = None,
                      metadata: Dict = None) -> int:
        """
        Add a credential set.

        Args:
            username: Username
            password: Password
            domain: Domain
            hash_value: Password hash
            hash_type: Hash type (NTLM, etc.)
            name: Optional name
            metadata: Additional metadata

        Returns:
            ID of inserted record
        """
        with self._get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO credentials
                (username, password, domain, hash, hash_type, name, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                username, password, domain, hash_value, hash_type, name,
                json.dumps(metadata or {})
            ))
            return cursor.lastrowid

    def get_credentials(self) -> List[Dict]:
        """
        Get all credentials.

        Returns:
            List of credential dictionaries
        """
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM credentials")

            creds = []
            for row in cursor.fetchall():
                cred = dict(row)
                cred['metadata'] = json.loads(cred['metadata'])
                creds.append(cred)

            return creds

    def remove_credential(self, cred_id: int) -> bool:
        """
        Remove a credential.

        Args:
            cred_id: Credential ID

        Returns:
            True if removed
        """
        with self._get_cursor() as cursor:
            cursor.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
            return cursor.rowcount > 0

    # Service Methods
    def add_service(self, target: str, service: str, port: int,
                   version: str = None) -> bool:
        """
        Record a detected service.

        Args:
            target: Target IP/hostname
            service: Service name
            port: Port number
            version: Service version

        Returns:
            True if added
        """
        try:
            with self._get_cursor() as cursor:
                cursor.execute("""
                    INSERT INTO services (target, service, port, version)
                    VALUES (?, ?, ?, ?)
                """, (target, service, port, version))

            # Invalidate services cache
            self._invalidate_cache('services_')

            return True
        except sqlite3.IntegrityError:
            # Update version if service already exists
            with self._get_cursor() as cursor:
                cursor.execute("""
                    UPDATE services SET version = ?, detected_at = CURRENT_TIMESTAMP
                    WHERE target = ? AND service = ? AND port = ?
                """, (version, target, service, port))

            # Invalidate services cache
            self._invalidate_cache('services_')

            return True

    def get_services(self, target: str = None) -> List[Dict]:
        """
        Get detected services.

        Args:
            target: Filter by target

        Returns:
            List of service dictionaries
        """
        # Try cache first
        cache_key = f"services_{target}"
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        with self._lock:
            cursor = self.conn.cursor()

            if target:
                cursor.execute("SELECT * FROM services WHERE target = ?", (target,))
            else:
                cursor.execute("SELECT * FROM services")

            services = [dict(row) for row in cursor.fetchall()]

            # Cache the result
            self._set_cached(cache_key, services)

            return services

    def get_web_services(self) -> List[Dict]:
        """
        Get all detected web services (http/https).

        Returns:
            List of web service dictionaries with target:port URLs
        """
        with self._lock:
            cursor = self.conn.cursor()

            # Web services and common web ports
            web_services = ('http', 'https', 'http-proxy', 'http-alt', 'ssl/http', 'ssl/https')
            web_ports = (80, 443, 8080, 8443, 8000, 8888, 9090, 3000, 5000, 9000, 8001, 8008, 4443, 8081, 8082, 9443)

            # Get services that are either explicitly web services or on common web ports
            cursor.execute("""
                SELECT DISTINCT target, port, service
                FROM services
                WHERE service IN ({})
                OR port IN ({})
                ORDER BY target, port
            """.format(
                ','.join('?' * len(web_services)),
                ','.join('?' * len(web_ports))
            ), web_services + web_ports)

            web_targets = []
            for row in cursor.fetchall():
                target = row[0]
                port = row[1]
                service = row[2]

                # Determine protocol
                if service in ('https', 'ssl/https') or port in (443, 8443, 4443, 9443):
                    protocol = 'https'
                else:
                    protocol = 'http'

                # Build URL
                if (protocol == 'http' and port == 80) or (protocol == 'https' and port == 443):
                    url = f"{protocol}://{target}"
                else:
                    url = f"{protocol}://{target}:{port}"

                web_targets.append({
                    'target': target,
                    'port': port,
                    'service': service,
                    'protocol': protocol,
                    'url': url
                })

            return web_targets

    def clear_all_services(self) -> int:
        """
        Remove all services from the database.

        Returns:
            Number of services removed
        """
        with self._get_cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM services")
            count = cursor.fetchone()[0]
            cursor.execute("DELETE FROM services")
            return count

    # Scan Results Methods
    def save_scan_results(self, scan_name: str, target: str, scan_type: str,
                         results: Dict, file_path: str = None) -> int:
        """
        Save scan results.

        Args:
            scan_name: Scan name
            target: Target scanned
            scan_type: Type of scan
            results: Results data
            file_path: Path to full results file

        Returns:
            ID of inserted record
        """
        with self._get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO scan_results (scan_name, target, scan_type, results, file_path)
                VALUES (?, ?, ?, ?, ?)
            """, (scan_name, target, scan_type, json.dumps(results), file_path))
            return cursor.lastrowid

    def get_scan_results(self, target: str = None, scan_type: str = None) -> List[Dict]:
        """
        Get scan results.

        Args:
            target: Filter by target
            scan_type: Filter by scan type

        Returns:
            List of scan result dictionaries
        """
        with self._lock:
            cursor = self.conn.cursor()

            query = "SELECT * FROM scan_results WHERE 1=1"
            params = []

            if target:
                query += " AND target = ?"
                params.append(target)
            if scan_type:
                query += " AND scan_type = ?"
                params.append(scan_type)

            query += " ORDER BY created_at DESC"

            cursor.execute(query, params)

            results = []
            for row in cursor.fetchall():
                result = dict(row)
                result['results'] = json.loads(result['results'])
                results.append(result)

            return results

    # Finding Methods
    def add_finding(self, target: str, title: str, severity: str,
                   description: str = None, module_name: str = None,
                   evidence: str = None, remediation: str = None) -> int:
        """
        Add a finding/vulnerability.

        Args:
            target: Target where finding was discovered
            title: Finding title
            severity: Severity level
            description: Detailed description
            module_name: Module that discovered it
            evidence: Evidence/proof
            remediation: Remediation steps

        Returns:
            ID of inserted record
        """
        with self._get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO findings
                (target, title, severity, description, module_name, evidence, remediation)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (target, title, severity, description, module_name, evidence, remediation))
            return cursor.lastrowid

    def get_findings(self, target: str = None, severity: str = None) -> List[Dict]:
        """
        Get findings.

        Args:
            target: Filter by target
            severity: Filter by severity

        Returns:
            List of finding dictionaries
        """
        with self._lock:
            cursor = self.conn.cursor()

            query = "SELECT * FROM findings WHERE 1=1"
            params = []

            if target:
                query += " AND target = ?"
                params.append(target)
            if severity:
                query += " AND severity = ?"
                params.append(severity)

            query += " ORDER BY created_at DESC"

            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    # Module Defaults Methods
    def set_module_default(self, module_name: str, option_name: str, option_value: str) -> bool:
        """
        Set a default value for a module option.

        Args:
            module_name: Name of the module (e.g., 'nmap')
            option_name: Name of the option (e.g., 'SCAN_TYPE')
            option_value: Default value to set

        Returns:
            True if set successfully
        """
        try:
            with self._get_cursor() as cursor:
                cursor.execute("""
                    INSERT INTO module_defaults (module_name, option_name, option_value)
                    VALUES (?, ?, ?)
                    ON CONFLICT(module_name, option_name)
                    DO UPDATE SET option_value = ?, updated_at = CURRENT_TIMESTAMP
                """, (module_name, option_name, option_value, option_value))
            return True
        except Exception as e:
            print(f"Error setting module default: {e}")
            return False

    def get_module_default(self, module_name: str, option_name: str) -> Optional[str]:
        """
        Get a default value for a module option.

        Args:
            module_name: Name of the module
            option_name: Name of the option

        Returns:
            Default value if found, None otherwise
        """
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT option_value FROM module_defaults
                WHERE module_name = ? AND option_name = ?
            """, (module_name, option_name))

            row = cursor.fetchone()
            return row['option_value'] if row else None

    def get_module_defaults(self, module_name: str) -> Dict[str, str]:
        """
        Get all default values for a module.

        Args:
            module_name: Name of the module

        Returns:
            Dictionary of option_name -> option_value
        """
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT option_name, option_value FROM module_defaults
                WHERE module_name = ?
            """, (module_name,))

            return {row['option_name']: row['option_value'] for row in cursor.fetchall()}

    def delete_module_default(self, module_name: str, option_name: str) -> bool:
        """
        Delete a default value for a module option.

        Args:
            module_name: Name of the module
            option_name: Name of the option

        Returns:
            True if deleted
        """
        with self._get_cursor() as cursor:
            cursor.execute("""
                DELETE FROM module_defaults
                WHERE module_name = ? AND option_name = ?
            """, (module_name, option_name))
            return cursor.rowcount > 0

    def delete_all_module_defaults(self, module_name: str) -> bool:
        """
        Delete all default values for a module.

        Args:
            module_name: Name of the module

        Returns:
            True if any were deleted
        """
        with self._get_cursor() as cursor:
            cursor.execute("""
                DELETE FROM module_defaults WHERE module_name = ?
            """, (module_name,))
            return cursor.rowcount > 0
