"""
Database Layer for PurpleSploit

SQLite-based storage for:
- Module execution history
- Scan results and findings
- Persistent workspaces
- Credential and target storage
"""

import sqlite3
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path


class Database:
    """Database manager for PurpleSploit."""

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
        self._connect()
        self._create_tables()

    def _connect(self):
        """Establish database connection."""
        # Use check_same_thread=False to allow async operations across threads
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row  # Enable dict-like access

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

        self.conn.commit()

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
        cursor = self.conn.cursor()
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
        self.conn.commit()
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
        cursor = self.conn.cursor()
        try:
            # Determine status: subnet, unverified, or verified
            status = 'unverified'
            if '/' in identifier and target_type == 'network':
                status = 'subnet'

            cursor.execute("""
                INSERT INTO targets (type, identifier, name, metadata, status)
                VALUES (?, ?, ?, ?, ?)
            """, (target_type, identifier, name, json.dumps(metadata or {}), status))
            self.conn.commit()
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

        return targets

    def remove_target(self, identifier: str) -> bool:
        """
        Remove a target.

        Args:
            identifier: IP or URL

        Returns:
            True if removed
        """
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM targets WHERE identifier = ?", (identifier,))
        self.conn.commit()
        return cursor.rowcount > 0

    def mark_target_verified(self, identifier: str) -> bool:
        """
        Mark a target as verified (responsive to scans).

        Args:
            identifier: IP or URL

        Returns:
            True if updated
        """
        cursor = self.conn.cursor()
        cursor.execute("UPDATE targets SET status = 'verified' WHERE identifier = ?", (identifier,))
        self.conn.commit()
        return cursor.rowcount > 0

    def clear_all_targets(self) -> int:
        """
        Remove all targets from the database.

        Returns:
            Number of targets removed
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM targets")
        count = cursor.fetchone()[0]
        cursor.execute("DELETE FROM targets")
        self.conn.commit()
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
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO credentials
            (username, password, domain, hash, hash_type, name, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            username, password, domain, hash_value, hash_type, name,
            json.dumps(metadata or {})
        ))
        self.conn.commit()
        return cursor.lastrowid

    def get_credentials(self) -> List[Dict]:
        """
        Get all credentials.

        Returns:
            List of credential dictionaries
        """
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
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
        self.conn.commit()
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
        cursor = self.conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO services (target, service, port, version)
                VALUES (?, ?, ?, ?)
            """, (target, service, port, version))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Update version if service already exists
            cursor.execute("""
                UPDATE services SET version = ?, detected_at = CURRENT_TIMESTAMP
                WHERE target = ? AND service = ? AND port = ?
            """, (version, target, service, port))
            self.conn.commit()
            return True

    def get_services(self, target: str = None) -> List[Dict]:
        """
        Get detected services.

        Args:
            target: Filter by target

        Returns:
            List of service dictionaries
        """
        cursor = self.conn.cursor()

        if target:
            cursor.execute("SELECT * FROM services WHERE target = ?", (target,))
        else:
            cursor.execute("SELECT * FROM services")

        return [dict(row) for row in cursor.fetchall()]

    def clear_all_services(self) -> int:
        """
        Remove all services from the database.

        Returns:
            Number of services removed
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM services")
        count = cursor.fetchone()[0]
        cursor.execute("DELETE FROM services")
        self.conn.commit()
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
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO scan_results (scan_name, target, scan_type, results, file_path)
            VALUES (?, ?, ?, ?, ?)
        """, (scan_name, target, scan_type, json.dumps(results), file_path))
        self.conn.commit()
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
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO findings
            (target, title, severity, description, module_name, evidence, remediation)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (target, title, severity, description, module_name, evidence, remediation))
        self.conn.commit()
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
        cursor = self.conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO module_defaults (module_name, option_name, option_value)
                VALUES (?, ?, ?)
                ON CONFLICT(module_name, option_name)
                DO UPDATE SET option_value = ?, updated_at = CURRENT_TIMESTAMP
            """, (module_name, option_name, option_value, option_value))
            self.conn.commit()
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
        cursor = self.conn.cursor()
        cursor.execute("""
            DELETE FROM module_defaults
            WHERE module_name = ? AND option_name = ?
        """, (module_name, option_name))
        self.conn.commit()
        return cursor.rowcount > 0

    def delete_all_module_defaults(self, module_name: str) -> bool:
        """
        Delete all default values for a module.

        Args:
            module_name: Name of the module

        Returns:
            True if any were deleted
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            DELETE FROM module_defaults WHERE module_name = ?
        """, (module_name,))
        self.conn.commit()
        return cursor.rowcount > 0
