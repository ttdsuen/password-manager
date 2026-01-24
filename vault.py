from __future__ import annotations

import base64
import hashlib
import hmac
import os
from pathlib import Path
from typing import List, Optional, Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from database import (
    delete_credential,
    fetch_credential,
    get_metadata,
    initialize_database,
    list_credentials,
    list_credentials_with_tag,
    list_tags_for_credential,
    replace_tags_for_credential,
    set_metadata,
    upsert_credential,
)

# Metadata keys stored in the ``metadata`` table
_SALT_KEY = "kdf_salt"
_ITERATIONS_KEY = "kdf_iterations"
_VERIFIER_KEY = "master_key_verifier"

_DEFAULT_ITERATIONS = 390_000


def _derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    """Derive a symmetric key from the master password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def _hash_key(key: bytes) -> bytes:
    """Return a stable hash of the derived key for verification purposes."""
    digest = hashlib.sha256()
    digest.update(key)
    return digest.digest()


def _load_kdf_params(db_path: Optional[Path] = None) -> Optional[Tuple[bytes, int, bytes]]:
    """Load KDF parameters from metadata.

    Returns ``(salt, iterations, verifier)`` or ``None`` if not initialized.
    """
    salt = get_metadata(_SALT_KEY, db_path=db_path)
    iterations_bytes = get_metadata(_ITERATIONS_KEY, db_path=db_path)
    verifier = get_metadata(_VERIFIER_KEY, db_path=db_path)
    if salt is None or iterations_bytes is None or verifier is None:
        return None
    iterations_str = iterations_bytes.decode("ascii")
    iterations = int(iterations_str)
    return salt, iterations, verifier


def _make_fernet(key: bytes) -> Fernet:
    """Create a ``Fernet`` instance from a raw 32-byte key."""
    if len(key) != 32:
        msg = "Expected a 32-byte key for Fernet"
        raise ValueError(msg)
    fernet_key = base64.urlsafe_b64encode(key)
    return Fernet(fernet_key)


def is_vault_initialized(db_path: Optional[Path] = None) -> bool:
    """Return ``True`` if the vault has been initialized with a master password."""
    try:
        salt = get_metadata(_SALT_KEY, db_path=db_path)
        verifier = get_metadata(_VERIFIER_KEY, db_path=db_path)
        return salt is not None and verifier is not None
    except Exception:
        return False


def initialize_vault_with_password(password: str, db_path: Optional[Path] = None) -> None:
    """Initialize a new vault with the provided master password.

    This will create the database (if necessary), generate a random salt, derive a key
    from the password, and store the salt, iteration count, and a verifier hash in
    the ``metadata`` table.
    """
    initialize_database(db_path=db_path)
    if is_vault_initialized(db_path=db_path):
        msg = "Vault is already initialized"
        raise RuntimeError(msg)

    salt = os.urandom(16)
    iterations = _DEFAULT_ITERATIONS
    key = _derive_key(password, salt=salt, iterations=iterations)
    verifier = _hash_key(key)

    set_metadata(_SALT_KEY, salt, db_path=db_path)
    set_metadata(_ITERATIONS_KEY, str(iterations).encode("ascii"), db_path=db_path)
    set_metadata(_VERIFIER_KEY, verifier, db_path=db_path)


def verify_master_password(password: str, db_path: Optional[Path] = None) -> bool:
    """Return ``True`` if ``password`` matches the stored master password.

    If the vault is not initialized, this returns ``False``.
    """
    params = _load_kdf_params(db_path=db_path)
    if params is None:
        return False
    salt, iterations, verifier = params
    key = _derive_key(password, salt=salt, iterations=iterations)
    candidate_verifier = _hash_key(key)
    return hmac.compare_digest(verifier, candidate_verifier)


def get_encryption_key_from_password(password: str, db_path: Optional[Path] = None) -> bytes:
    """Return the derived encryption key for ``password``.

    Raises ``RuntimeError`` if the vault is not initialized and ``ValueError`` if the
    password is incorrect.
    """
    params = _load_kdf_params(db_path=db_path)
    if params is None:
        msg = "Vault is not initialized"
        raise RuntimeError(msg)
    salt, iterations, verifier = params
    key = _derive_key(password, salt=salt, iterations=iterations)
    candidate_verifier = _hash_key(key)
    if not hmac.compare_digest(verifier, candidate_verifier):
        msg = "Invalid master password"
        raise ValueError(msg)
    return key


def add_credential(
    master_password: str,
    service: str,
    username: str,
    password_plain: str,
    db_path: Optional[Path] = None,
) -> None:
    """Encrypt and store a credential (insert or update)."""
    key = get_encryption_key_from_password(master_password, db_path=db_path)
    f = _make_fernet(key)
    password_encrypted = f.encrypt(password_plain.encode("utf-8"))

    from datetime import datetime, timezone

    now = datetime.now(tz=timezone.utc).isoformat()
    upsert_credential(
        service=service,
        username=username,
        password_encrypted=password_encrypted,
        created_at=now,
        updated_at=now,
        db_path=db_path,
    )


def get_credential_password(
    master_password: str,
    service: str,
    username: str,
    db_path: Optional[Path] = None,
) -> Optional[str]:
    """Return the decrypted password for a credential, or ``None`` if not found."""
    key = get_encryption_key_from_password(master_password, db_path=db_path)
    f = _make_fernet(key)
    row = fetch_credential(service=service, username=username, db_path=db_path)
    if row is None:
        return None
    _service_value, _username_value, password_encrypted = row
    decrypted = f.decrypt(password_encrypted)
    return decrypted.decode("utf-8")


def list_credential_identities(
    master_password: str,
    db_path: Optional[Path] = None,
) -> List[Tuple[str, str]]:
    """Return a list of ``(service, username)`` for all credentials.

    The master password is verified but otherwise not used beyond that check.
    """
    # This will raise if the password is invalid or vault not initialized.
    _ = get_encryption_key_from_password(master_password, db_path=db_path)
    return list_credentials(db_path=db_path)


def set_credential_tags(
    master_password: str,
    service: str,
    username: str,
    tags: List[str],
    db_path: Optional[Path] = None,
) -> None:
    """Replace all tags for a credential after verifying the master password."""
    _ = get_encryption_key_from_password(master_password, db_path=db_path)
    replace_tags_for_credential(service=service, username=username, tags=tags, db_path=db_path)


def add_credential_tags(
    master_password: str,
    service: str,
    username: str,
    tags: List[str],
    db_path: Optional[Path] = None,
) -> None:
    """Add tags to an existing credential, preserving existing tags.

    Tags are normalized via ``strip()`` and de-duplicated.
    """
    _ = get_encryption_key_from_password(master_password, db_path=db_path)
    existing = list_tags_for_credential(service=service, username=username, db_path=db_path)
    merged = {t.strip() for t in existing if t.strip()}
    for tag in tags:
        normalized = tag.strip()
        if normalized:
            merged.add(normalized)
    replace_tags_for_credential(
        service=service,
        username=username,
        tags=sorted(merged),
        db_path=db_path,
    )


def get_credential_tags(
    master_password: str,
    service: str,
    username: str,
    db_path: Optional[Path] = None,
) -> List[str]:
    """Return all tags for a credential after verifying the master password."""
    _ = get_encryption_key_from_password(master_password, db_path=db_path)
    return list_tags_for_credential(service=service, username=username, db_path=db_path)


def list_credential_identities_with_tag(
    master_password: str,
    tag: str,
    db_path: Optional[Path] = None,
) -> List[Tuple[str, str]]:
    """Return all (service, username) pairs that have the given tag.

    The master password is verified but otherwise not used beyond that check.
    """
    _ = get_encryption_key_from_password(master_password, db_path=db_path)
    return list_credentials_with_tag(tag=tag, db_path=db_path)


def delete_credential_entry(
    master_password: str,
    service: str,
    username: str,
    db_path: Optional[Path] = None,
) -> bool:
    """Delete a credential after verifying the master password.

    Returns ``True`` if a row was deleted, ``False`` if no such credential exists.
    Raises ``RuntimeError`` if the vault is not initialized, and ``ValueError`` if the
    master password is invalid.
    """
    # This will raise if password invalid / vault uninitialized.
    _ = get_encryption_key_from_password(master_password, db_path=db_path)
    return delete_credential(service=service, username=username, db_path=db_path)
