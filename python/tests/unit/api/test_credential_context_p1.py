"""Direct P1 credential-route checks without an HTTP test-client transport."""

from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


@pytest.mark.asyncio
async def test_credential_routes_use_account_ref_and_preserve_display_alias(
    tmp_path, monkeypatch,
):
    from purplesploit.api import server
    from purplesploit.models.database import Credential, CredentialCreate, DatabaseManager

    engine = create_engine(f"sqlite:///{tmp_path / 'credentials.db'}")
    Credential.__table__.create(engine)
    manager = DatabaseManager.__new__(DatabaseManager)
    manager.session_makers = {"credentials": sessionmaker(bind=engine)}
    monkeypatch.setattr(server, "db_manager", manager)
    monkeypatch.setattr(server.framework, "database", MagicMock())
    monkeypatch.setattr(server, "_runtime_frameworks", lambda: [])

    first = await server.create_credential(CredentialCreate(
        name="alice", username="alice", local_host="host-a",
    ))
    second = await server.create_credential(CredentialCreate(
        name="alice", username="alice", local_host="host-b",
    ))

    assert first.name == second.name == "alice"
    assert first.account_ref != second.account_ref
    assert (await server.get_credential(first.account_ref)).local_host == "host-a"
    with pytest.raises(HTTPException, match="ambiguous") as error:
        await server.get_credential("alice")
    assert error.value.status_code == 409

    updated = await server.update_credential(first.account_ref, CredentialCreate(
        account_ref="ignored-replacement", name="alice", username="alice",
        scope="local", local_host="host-a",
    ))
    assert updated.account_ref == first.account_ref
    assert updated.scope == "local"

    response = await server.delete_credential(second.account_ref)
    assert second.account_ref in response["message"]


@pytest.mark.asyncio
async def test_credential_routes_accept_unique_display_name(tmp_path, monkeypatch):
    from purplesploit.api import server
    from purplesploit.models.database import Credential, CredentialCreate, DatabaseManager

    engine = create_engine(f"sqlite:///{tmp_path / 'credentials.db'}")
    Credential.__table__.create(engine)
    manager = DatabaseManager.__new__(DatabaseManager)
    manager.session_makers = {"credentials": sessionmaker(bind=engine)}
    monkeypatch.setattr(server, "db_manager", manager)
    monkeypatch.setattr(server.framework, "database", MagicMock())
    monkeypatch.setattr(server, "_runtime_frameworks", lambda: [])

    created = await server.create_credential(CredentialCreate(
        name="fixture-alias", username="alice", local_host="host-a",
    ))

    assert (await server.get_credential("fixture-alias")).account_ref == created.account_ref
    updated = await server.update_credential("fixture-alias", CredentialCreate(
        name="fixture-alias", username="alice", scope="local", local_host="host-a",
    ))
    assert updated.account_ref == created.account_ref
    response = await server.delete_credential("fixture-alias")
    assert created.account_ref in response["message"]
    assert manager.get_all_credentials() == []
