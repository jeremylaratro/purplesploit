"""Focused P1 account-identity checks for the ORM credential store."""

import json
import sqlite3

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from purplesploit.models.database import Credential, CredentialCreate, DatabaseManager


def _construct_manager(monkeypatch, tmp_path, credentials_path):
    import purplesploit.models.database as database_models

    monkeypatch.setattr(database_models, "DB_DIR", tmp_path)
    paths = {
        "CREDENTIALS_DB": credentials_path,
        "TARGETS_DB": tmp_path / "targets.db",
        "WEB_TARGETS_DB": tmp_path / "web-targets.db",
        "AD_TARGETS_DB": tmp_path / "ad-targets.db",
        "SERVICES_DB": tmp_path / "services.db",
        "EXPLOITS_DB": tmp_path / "exploits.db",
    }
    for name, path in paths.items():
        monkeypatch.setattr(database_models, name, path)
    return DatabaseManager()


def _dispose_manager(manager):
    for engine in manager.engines.values():
        engine.dispose()


def test_orm_null_scope_credentials_do_not_merge_by_display_name(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'credentials.db'}")
    Credential.__table__.create(engine)
    manager = DatabaseManager.__new__(DatabaseManager)
    manager.session_makers = {"credentials": sessionmaker(bind=engine)}

    for host in ("host-a", "host-b"):
        manager.upsert_credential(CredentialCreate(
            name="alice", username="alice", scope=None, local_host=host,
        ))
    repeated = manager.upsert_credential(CredentialCreate(
        name="alice", username="alice", scope=None, local_host="host-a",
    ))

    credentials = manager.get_all_credentials()
    assert len(credentials) == 2
    assert len({item.account_ref for item in credentials}) == 2
    assert repeated.account_ref == credentials[0].account_ref


def test_orm_migration_adds_and_backfills_account_identity_columns(tmp_path):
    path = tmp_path / "legacy-credentials.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            """CREATE TABLE credentials (
                   name TEXT PRIMARY KEY, username TEXT, password TEXT, domain TEXT,
                   dcip TEXT, dns TEXT, hash TEXT
               )"""
        )
        connection.execute(
            "INSERT INTO credentials (name, username) VALUES (?, ?)",
            ("alice", "alice"),
        )

    manager = DatabaseManager.__new__(DatabaseManager)
    manager.CREDENTIALS_DB = path
    manager._migrate_credentials_schema()

    with sqlite3.connect(path) as connection:
        connection.row_factory = sqlite3.Row
        credential = connection.execute("SELECT * FROM credentials").fetchone()
        assert credential["account_ref"]
        assert credential["display_name"] == "alice"
        assert credential["scope"] is None
        assert credential["local_host"] is None

    engine = create_engine(f"sqlite:///{path}")
    manager.session_makers = {"credentials": sessionmaker(bind=engine)}
    added = manager.upsert_credential(CredentialCreate(
        name="alice", username="alice", local_host="host-b",
    ))
    assert added.name == "alice"
    assert len(manager.get_all_credentials()) == 2


def test_orm_migration_folds_duplicate_account_candidates(tmp_path, monkeypatch):
    path = tmp_path / "legacy-credentials.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            """CREATE TABLE credentials (
                   name TEXT PRIMARY KEY, username TEXT, password TEXT, domain TEXT,
                   dcip TEXT, dns TEXT, hash TEXT
               )"""
        )
        connection.executemany(
            """INSERT INTO credentials
               (name, username, password, domain, dcip, dns, hash)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    "admin-primary", "admin", "password-one", "CORP",
                    "10.0.0.10", "dc01.corp.test", "hash-one",
                ),
                (
                    "admin-secondary", "admin", "password-two", "CORP",
                    "10.0.0.11", "dc02.corp.test", "hash-two",
                ),
                ("bob", "bob", "bob-password", "CORP", None, None, None),
            ],
        )

    manager = _construct_manager(monkeypatch, tmp_path, path)
    try:
        credentials = manager.get_all_credentials()
        assert sorted((item.name, item.password) for item in credentials) == [
            ("admin-primary", "password-one"),
            ("bob", "bob-password"),
        ]
    finally:
        _dispose_manager(manager)

    with sqlite3.connect(path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("SELECT * FROM credentials ORDER BY rowid").fetchall()
        before = [dict(row) for row in rows]
        admin_metadata = json.loads(rows[0]["metadata"])
        assert admin_metadata["folded_candidates"] == [{
            "name": "admin-secondary",
            "password": "password-two",
            "hash": "hash-two",
            "dcip": "10.0.0.11",
            "dns": "dc02.corp.test",
            "original_id": 2,
        }]
        assert rows[1]["name"] == "bob"
        assert rows[1]["password"] == "bob-password"
        assert rows[1]["metadata"] is None

    reconstructed = _construct_manager(monkeypatch, tmp_path, path)
    _dispose_manager(reconstructed)
    with sqlite3.connect(path) as connection:
        connection.row_factory = sqlite3.Row
        after = [
            dict(row)
            for row in connection.execute("SELECT * FROM credentials ORDER BY rowid")
        ]
    assert after == before


@pytest.mark.parametrize(
    ("kept_metadata", "preserved_metadata"),
    [
        ('{"source": "operator"}', {"source": "operator"}),
        (None, {}),
        ("not-json", {}),
    ],
)
def test_orm_migration_merges_or_repairs_kept_metadata(
    tmp_path, kept_metadata, preserved_metadata
):
    path = tmp_path / "legacy-credentials-with-metadata.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            """CREATE TABLE credentials (
                   name TEXT PRIMARY KEY, username TEXT, password TEXT, domain TEXT,
                   dcip TEXT, dns TEXT, hash TEXT, metadata TEXT
               )"""
        )
        connection.executemany(
            """INSERT INTO credentials (name, username, password, domain, metadata)
               VALUES (?, ?, ?, ?, ?)""",
            [
                ("admin-primary", "admin", "password-one", "CORP", kept_metadata),
                (
                    "admin-secondary", "admin", "password-two", "CORP",
                    '{"source": "second capture"}',
                ),
            ],
        )

    manager = DatabaseManager.__new__(DatabaseManager)
    manager.CREDENTIALS_DB = path
    manager._migrate_credentials_schema()
    with sqlite3.connect(path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("SELECT * FROM credentials").fetchall()
    assert len(rows) == 1
    metadata = json.loads(rows[0]["metadata"])
    assert {
        key: value for key, value in metadata.items() if key != "folded_candidates"
    } == preserved_metadata
    assert metadata["folded_candidates"][0]["metadata"] == {
        "source": "second capture"
    }


def test_pre_p1_store_migrations_and_startup_sync_share_account_ref(tmp_path, monkeypatch):
    from purplesploit.core.database import Database
    from purplesploit.core.framework import Framework
    from purplesploit.core.session import Session

    legacy_path = tmp_path / "purplesploit.db"
    with sqlite3.connect(legacy_path) as connection:
        connection.execute(
            """CREATE TABLE credentials (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   name TEXT, username TEXT NOT NULL, password TEXT, domain TEXT,
                   dcip TEXT, dns TEXT, hash TEXT, hash_type TEXT, metadata TEXT
               )"""
        )
        connection.executemany(
            """INSERT INTO credentials
               (name, username, password, domain, metadata)
               VALUES (?, ?, ?, ?, ?)""",
            [
                ("admin-primary", "admin", "password-one", "CORP", "{}"),
                ("admin-secondary", "admin", "password-two", "CORP", "{}"),
            ],
        )

    orm_path = tmp_path / "credentials.db"
    with sqlite3.connect(orm_path) as connection:
        connection.execute(
            """CREATE TABLE credentials (
                   name TEXT PRIMARY KEY, username TEXT, password TEXT, domain TEXT,
                   dcip TEXT, dns TEXT, hash TEXT
               )"""
        )
        connection.executemany(
            """INSERT INTO credentials
               (name, username, password, domain) VALUES (?, ?, ?, ?)""",
            [
                ("admin-primary", "admin", "password-one", "CORP"),
                ("admin-secondary", "admin", "password-two", "CORP"),
            ],
        )

    legacy = Database(str(legacy_path))
    manager = _construct_manager(monkeypatch, tmp_path, orm_path)

    framework = Framework.__new__(Framework)
    framework.database = legacy
    framework.session = Session()
    framework._get_db_manager = lambda: manager

    try:
        framework._load_persisted_data()
        credentials = manager.get_all_credentials()
        assert len(credentials) == 1
        legacy_credential = legacy.get_credentials()[0]
        assert credentials[0].account_ref == legacy_credential["account_ref"]

        legacy_passwords = {legacy_credential["password"]}
        legacy_passwords.update(
            item["password"]
            for item in legacy_credential["metadata"]["folded_candidates"]
        )
        with sqlite3.connect(orm_path) as connection:
            connection.row_factory = sqlite3.Row
            orm_credential = connection.execute("SELECT * FROM credentials").fetchone()
            orm_passwords = {orm_credential["password"]}
            orm_passwords.update(
                item["password"]
                for item in json.loads(orm_credential["metadata"])["folded_candidates"]
            )
        assert legacy_passwords == {"password-one", "password-two"}
        assert orm_passwords == {"password-one", "password-two"}

        manager._migrate_credentials_schema()
        framework._load_persisted_data()
        assert len(manager.get_all_credentials()) == 1
    finally:
        _dispose_manager(manager)
        legacy.close()


def test_orm_migration_never_rewrites_an_existing_account_ref(tmp_path, monkeypatch):
    credentials_path = tmp_path / "credentials.db"
    manager = _construct_manager(monkeypatch, tmp_path, credentials_path)
    manager.add_credential(CredentialCreate(
        name="svc", username="svc", domain="CORP", account_ref="aranum-acct-0001",
    ))
    renamed_ref = manager.add_credential(CredentialCreate(name="alice", username="alice")).account_ref
    _dispose_manager(manager)
    with sqlite3.connect(credentials_path) as connection:
        connection.execute("UPDATE credentials SET username = 'alice2' WHERE account_ref = ?", (renamed_ref,))

    for _ in range(2):
        manager = _construct_manager(monkeypatch, tmp_path, credentials_path)
        refs = {item.username: item.account_ref for item in manager.get_all_credentials()}
        _dispose_manager(manager)
        assert refs == {"svc": "aranum-acct-0001", "alice2": renamed_ref}
