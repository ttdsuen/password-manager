from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

DEFAULT_DB_PATH = Path("vault.db")


def get_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Return a SQLite connection to the vault database.

    By default, this uses ``vault.db`` in the current working directory.
    """
    path = db_path or DEFAULT_DB_PATH
    conn = sqlite3.connect(str(path))
    # Enable WAL mode for better concurrent access
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def initialize_database(db_path: Optional[Path] = None) -> None:
    """Initialize the credentials database if it does not already exist.

    This creates three tables:
    - ``metadata``: key/value store for configuration (e.g., salt, iterations, verifier)
    - ``credentials``: stored credentials with encrypted passwords
    - ``credential_tags``: tags associated with credentials
    """
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                password_encrypted BLOB NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(service, username)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS credential_tags (
                credential_id INTEGER NOT NULL,
                tag TEXT NOT NULL,
                UNIQUE(credential_id, tag),
                FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE CASCADE
            )
            """
        )
        conn.commit()


def set_metadata(key: str, value: bytes, db_path: Optional[Path] = None) -> None:
    """Set or update a value in the ``metadata`` table."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            (key, value),
        )
        conn.commit()


def get_metadata(key: str, db_path: Optional[Path] = None) -> Optional[bytes]:
    """Return a metadata value as bytes, or ``None`` if it is not set."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM metadata WHERE key = ?", (key,))
        row = cursor.fetchone()
    if row is None:
        return None
    value = row[0]
    # ``sqlite3`` returns BLOB columns as ``bytes`` by default.
    assert isinstance(value, (bytes, bytearray))
    return bytes(value)


def upsert_credential(
    service: str,
    username: str,
    password_encrypted: bytes,
    created_at: str,
    updated_at: str,
    db_path: Optional[Path] = None,
) -> None:
    """Insert or update a credential row.

    The combination of ``service`` and ``username`` is unique.
    """
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO credentials (service, username, password_encrypted, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(service, username) DO UPDATE SET
                password_encrypted = excluded.password_encrypted,
                updated_at = excluded.updated_at
            """,
            (service, username, password_encrypted, created_at, updated_at),
        )
        conn.commit()


def fetch_credential(
    service: str,
    username: str,
    db_path: Optional[Path] = None,
) -> Optional[Tuple[str, str, bytes]]:
    """Fetch a single credential row.

    Returns a tuple ``(service, username, password_encrypted)`` or ``None``.
    """
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT service, username, password_encrypted
            FROM credentials
            WHERE service = ? AND username = ?
            """,
            (service, username),
        )
        row = cursor.fetchone()
    if row is None:
        return None
    service_value, username_value, password_encrypted = row
    assert isinstance(password_encrypted, (bytes, bytearray))
    return str(service_value), str(username_value), bytes(password_encrypted)


def list_credentials(db_path: Optional[Path] = None) -> List[Tuple[str, str]]:
    """Return a list of ``(service, username)`` pairs sorted by service and username."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT service, username
            FROM credentials
            ORDER BY service, username
            """
        )
        rows: Sequence[Tuple[str, str]] = cursor.fetchall()
    return [(str(service), str(username)) for service, username in rows]


def _get_credential_id(
    service: str,
    username: str,
    db_path: Optional[Path] = None,
) -> Optional[int]:
    """Return the numeric credential ID for a (service, username) pair."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM credentials WHERE service = ? AND username = ?",
            (service, username),
        )
        row = cursor.fetchone()
    if row is None:
        return None
    credential_id_raw = row[0]
    assert isinstance(credential_id_raw, int)
    return int(credential_id_raw)


def replace_tags_for_credential(
    service: str,
    username: str,
    tags: List[str],
    db_path: Optional[Path] = None,
) -> None:
    """Replace all tags for the given credential with ``tags``.

    If the credential does not exist, this is a no-op.
    """
    credential_id = _get_credential_id(service=service, username=username, db_path=db_path)
    if credential_id is None:
        return

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM credential_tags WHERE credential_id = ?", (credential_id,))
        for tag in tags:
            normalized = tag.strip()
            if not normalized:
                continue
            cursor.execute(
                "INSERT OR IGNORE INTO credential_tags (credential_id, tag) VALUES (?, ?)",
                (credential_id, normalized),
            )
        conn.commit()


def list_tags_for_credential(
    service: str,
    username: str,
    db_path: Optional[Path] = None,
) -> List[str]:
    """Return all tags for the given credential, sorted alphabetically."""
    credential_id = _get_credential_id(service=service, username=username, db_path=db_path)
    if credential_id is None:
        return []

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT tag FROM credential_tags WHERE credential_id = ? ORDER BY tag",
            (credential_id,),
        )
        rows: Sequence[Tuple[str]] = cursor.fetchall()
    return [str(tag) for (tag,) in rows]


def list_credentials_with_tag(
    tag: str,
    db_path: Optional[Path] = None,
) -> List[Tuple[str, str]]:
    """Return all (service, username) pairs that have the given tag."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT c.service, c.username
            FROM credentials AS c
            JOIN credential_tags AS t ON c.id = t.credential_id
            WHERE t.tag = ?
            ORDER BY c.service, c.username
            """,
            (tag,),
        )
        rows: Sequence[Tuple[str, str]] = cursor.fetchall()
    return [(str(service), str(username)) for service, username in rows]


def delete_credential(
    service: str,
    username: str,
    db_path: Optional[Path] = None,
) -> bool:
    """Delete a credential row.

    Returns ``True`` if a row was deleted, ``False`` otherwise.
    """
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM credentials WHERE service = ? AND username = ?",
            (service, username),
        )
        deleted = cursor.rowcount
        conn.commit()
    return deleted > 0
