from __future__ import annotations

from pathlib import Path

from database import get_connection, get_metadata, initialize_database
from vault import (
    initialize_vault_with_password,
    is_vault_initialized,
    verify_master_password,
)


def test_initialize_database_creates_expected_tables(tmp_path: Path) -> None:
    db_path = tmp_path / "vault.db"

    # Should not raise
    initialize_database(db_path=db_path)

    with get_connection(db_path=db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        table_names = {row[0] for row in cursor.fetchall()}

    assert "metadata" in table_names
    assert "credentials" in table_names


def test_initialize_vault_and_verify_password(tmp_path: Path) -> None:
    db_path = tmp_path / "vault.db"

    # Before initialization, vault should not be initialized and verification should fail.
    initialize_database(db_path=db_path)
    assert not is_vault_initialized(db_path=db_path)
    assert not verify_master_password("secret", db_path=db_path)

    initialize_vault_with_password("secret", db_path=db_path)

    assert is_vault_initialized(db_path=db_path)
    assert verify_master_password("secret", db_path=db_path)
    assert not verify_master_password("wrong", db_path=db_path)

    # Metadata should have salt and verifier entries.
    assert get_metadata("kdf_salt", db_path=db_path) is not None
    assert get_metadata("master_key_verifier", db_path=db_path) is not None


def test_initialize_vault_twice_raises(tmp_path: Path) -> None:
    db_path = tmp_path / "vault.db"

    initialize_vault_with_password("secret", db_path=db_path)

    try:
        initialize_vault_with_password("another", db_path=db_path)
    except RuntimeError as exc:
        assert "Vault is already initialized" in str(exc)
    else:
        raise AssertionError("Expected RuntimeError when initializing vault twice")
