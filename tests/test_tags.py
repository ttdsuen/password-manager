from __future__ import annotations

from pathlib import Path

from database import list_credentials_with_tag, list_tags_for_credential
from vault import (
    add_credential,
    add_credential_tags,
    get_credential_tags,
    initialize_vault_with_password,
    list_credential_identities_with_tag,
    set_credential_tags,
)


def test_set_and_get_tags_roundtrip(tmp_path: Path) -> None:
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

    set_credential_tags(
        master_password=master_password,
        service="example.com",
        username="alice",
        tags=["work", "email"],
        db_path=db_path,
    )

    tags = get_credential_tags(
        master_password=master_password,
        service="example.com",
        username="alice",
        db_path=db_path,
    )
    assert set(tags) == {"work", "email"}

    raw_tags = list_tags_for_credential(
        service="example.com",
        username="alice",
        db_path=db_path,
    )
    assert set(raw_tags) == {"work", "email"}


def test_list_credentials_with_tag(tmp_path: Path) -> None:
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
    add_credential(
        master_password=master_password,
        service="github.com",
        username="alice",
        password_plain="x",
        db_path=db_path,
    )

    set_credential_tags(
        master_password=master_password,
        service="example.com",
        username="alice",
        tags=["work"],
        db_path=db_path,
    )
    set_credential_tags(
        master_password=master_password,
        service="github.com",
        username="alice",
        tags=["personal"],
        db_path=db_path,
    )

    by_tag_work = list_credential_identities_with_tag(
        master_password=master_password,
        tag="work",
        db_path=db_path,
    )
    assert ("example.com", "alice") in by_tag_work
    assert ("github.com", "alice") not in by_tag_work

    raw_by_tag_personal = list_credentials_with_tag(tag="personal", db_path=db_path)
    assert ("github.com", "alice") in raw_by_tag_personal
    assert ("example.com", "alice") not in raw_by_tag_personal


def test_add_credential_tags_preserves_existing(tmp_path: Path) -> None:
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

    set_credential_tags(
        master_password=master_password,
        service="example.com",
        username="alice",
        tags=["work"],
        db_path=db_path,
    )

    # Add new tags, existing "work" should remain
    add_credential_tags(
        master_password=master_password,
        service="example.com",
        username="alice",
        tags=["email", "work"],
        db_path=db_path,
    )

    tags = get_credential_tags(
        master_password=master_password,
        service="example.com",
        username="alice",
        db_path=db_path,
    )
    assert set(tags) == {"work", "email"}
