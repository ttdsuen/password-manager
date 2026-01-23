from __future__ import annotations

from pathlib import Path

from database import fetch_credential, list_credentials
from vault import (
    add_credential,
    delete_credential_entry,
    get_credential_password,
    initialize_vault_with_password,
    list_credential_identities,
)


def test_add_and_get_credential_roundtrip(tmp_path: Path) -> None:
    db_path = tmp_path / "vault.db"
    master_password = "topsecret"
    service = "example.com"
    username = "alice"
    stored_password = "P@ssw0rd!"

    initialize_vault_with_password(master_password, db_path=db_path)

    add_credential(
        master_password=master_password,
        service=service,
        username=username,
        password_plain=stored_password,
        db_path=db_path,
    )

    # Fetch decrypted password
    retrieved = get_credential_password(
        master_password=master_password,
        service=service,
        username=username,
        db_path=db_path,
    )
    assert retrieved == stored_password

    # Ensure something encrypted is actually stored in the database.
    row = fetch_credential(service=service, username=username, db_path=db_path)
    assert row is not None
    _, _, password_encrypted = row
    assert isinstance(password_encrypted, bytes)
    assert password_encrypted != stored_password.encode("utf-8")


def test_list_credential_identities_requires_valid_password(tmp_path: Path) -> None:
    db_path = tmp_path / "vault.db"
    master_password = "topsecret"

    initialize_vault_with_password(master_password, db_path=db_path)

    add_credential(
        master_password=master_password,
        service="example.com",
        username="alice",
        password_plain="x",
        db_path=db_path,
    )

    # Listing with correct password returns entries
    identities = list_credential_identities(master_password, db_path=db_path)
    assert ("example.com", "alice") in identities

    # Listing with wrong password should raise
    try:
        list_credential_identities("wrong", db_path=db_path)
    except ValueError as exc:
        assert "Invalid master password" in str(exc)
    else:
        raise AssertionError("Expected ValueError for invalid master password when listing")


def test_list_credentials_raw_matches_vault_helper(tmp_path: Path) -> None:
    db_path = tmp_path / "vault.db"
    master_password = "topsecret"

    initialize_vault_with_password(master_password, db_path=db_path)

    add_credential(
        master_password=master_password,
        service="example.com",
        username="alice",
        password_plain="x",
        db_path=db_path,
    )

    raw_list = list_credentials(db_path=db_path)
    vault_list = list_credential_identities(master_password, db_path=db_path)

    assert set(raw_list) == set(vault_list)


def test_delete_credential_entry(tmp_path: Path) -> None:
    db_path = tmp_path / "vault.db"
    master_password = "topsecret"

    initialize_vault_with_password(master_password, db_path=db_path)

    add_credential(
        master_password=master_password,
        service="example.com",
        username="alice",
        password_plain="x",
        db_path=db_path,
    )

    # Delete with correct password
    deleted = delete_credential_entry(
        master_password=master_password,
        service="example.com",
        username="alice",
        db_path=db_path,
    )
    assert deleted is True

    # Subsequent delete returns False (no such credential)
    deleted_again = delete_credential_entry(
        master_password=master_password,
        service="example.com",
        username="alice",
        db_path=db_path,
    )
    assert deleted_again is False

    # Wrong password raises
    try:
        delete_credential_entry(
            master_password="wrong",
            service="example.com",
            username="alice",
            db_path=db_path,
        )
    except ValueError as exc:
        assert "Invalid master password" in str(exc)
    else:
        raise AssertionError("Expected ValueError for invalid master password when deleting")
