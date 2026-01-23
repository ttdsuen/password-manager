from __future__ import annotations

import sys
from pathlib import Path

# Ensure the project root is on sys.path so we can import the modules when running via `uv run`.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def test_imports_and_stubs() -> None:
    """Basic sanity test that project modules import and expose stubs."""
    import database  # noqa: F401
    import main  # noqa: F401
    import vault  # noqa: F401

    assert hasattr(main, "main")
    assert hasattr(vault, "initialize_vault_with_password")
    assert hasattr(vault, "is_vault_initialized")
    assert hasattr(vault, "verify_master_password")
    assert hasattr(database, "initialize_database")
