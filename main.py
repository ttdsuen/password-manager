from __future__ import annotations

import argparse
import sys
from getpass import getpass
from pathlib import Path
from typing import Optional

from vault import (
    add_credential,
    delete_credential_entry,
    get_credential_password,
    initialize_vault_with_password,
    is_vault_initialized,
    list_credential_identities,
    verify_master_password,
)


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="password-manager", description="Simple password manager MVP"
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=Path("vault.db"),
        help="Path to the vault database file (default: ./vault.db)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Initialize vault
    subparsers.add_parser("init", help="Initialize a new vault with a master password")

    # Show vault status
    subparsers.add_parser("status", help="Show whether the vault is initialized")

    # Verify master password
    subparsers.add_parser("verify", help="Verify the master password")

    # Add a credential
    parser_add = subparsers.add_parser("add", help="Add or update a credential")
    parser_add.add_argument("service", help="Service name (e.g., example.com)")
    parser_add.add_argument("username", help="Username for the service")

    # Get a credential
    parser_get = subparsers.add_parser("get", help="Retrieve and show a credential password")
    parser_get.add_argument("service", help="Service name (e.g., example.com)")
    parser_get.add_argument("username", help="Username for the service")

    # List stored credentials (service/username only)
    subparsers.add_parser("list", help="List all stored credentials")

    # Delete a credential
    parser_delete = subparsers.add_parser("delete", help="Delete a credential")
    parser_delete.add_argument("service", help="Service name (e.g., example.com)")
    parser_delete.add_argument("username", help="Username for the service")

    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    """Entry point for the password manager CLI."""

    args = _parse_args(argv)
    db_path: Path = args.db

    if args.command == "init":
        if is_vault_initialized(db_path=db_path):
            print("Vault is already initialized.")
            return 1

        pwd1 = getpass("Set master password: ")
        pwd2 = getpass("Confirm master password: ")
        if pwd1 != pwd2:
            print("Passwords do not match.")
            return 1

        initialize_vault_with_password(pwd1, db_path=db_path)
        print(f"Vault initialized at {db_path}.")
        return 0

    if args.command == "status":
        if is_vault_initialized(db_path=db_path):
            print(f"Vault at {db_path} is initialized.")
        else:
            print(f"Vault at {db_path} is not initialized.")
        return 0

    if args.command == "verify":
        pwd = getpass("Master password: ")
        if verify_master_password(pwd, db_path=db_path):
            print("Master password is correct.")
            return 0

        print("Master password is incorrect.")
        return 1

    if args.command == "add":
        if not is_vault_initialized(db_path=db_path):
            print("Vault is not initialized. Run 'init' first.")
            return 1

        service: str = args.service
        username: str = args.username

        master_pwd = getpass("Master password: ")
        try:
            # This will raise if the password is invalid.
            password_to_store = getpass("Password to store: ")
            add_credential(
                master_password=master_pwd,
                service=service,
                username=username,
                password_plain=password_to_store,
                db_path=db_path,
            )
        except ValueError:
            print("Invalid master password.")
            return 1
        except RuntimeError as exc:
            print(str(exc))
            return 1

        print(f"Credential stored for service={service!r}, username={username!r}.")
        return 0

    if args.command == "get":
        if not is_vault_initialized(db_path=db_path):
            print("Vault is not initialized. Run 'init' first.")
            return 1

        service = args.service
        username = args.username
        master_pwd = getpass("Master password: ")
        try:
            password_value = get_credential_password(
                master_password=master_pwd,
                service=service,
                username=username,
                db_path=db_path,
            )
        except ValueError:
            print("Invalid master password.")
            return 1
        except RuntimeError as exc:
            print(str(exc))
            return 1

        if password_value is None:
            print("No credential found.")
            return 1

        print(password_value)
        return 0

    if args.command == "list":
        if not is_vault_initialized(db_path=db_path):
            print("Vault is not initialized. Run 'init' first.")
            return 1

        master_pwd = getpass("Master password: ")
        try:
            identities = list_credential_identities(master_pwd, db_path=db_path)
        except ValueError:
            print("Invalid master password.")
            return 1
        except RuntimeError as exc:
            print(str(exc))
            return 1

        if not identities:
            print("No credentials stored.")
            return 0

        for service, username in identities:
            print(f"{service} {username}")
        return 0

    if args.command == "delete":
        if not is_vault_initialized(db_path=db_path):
            print("Vault is not initialized. Run 'init' first.")
            return 1

        service = args.service
        username = args.username
        master_pwd = getpass("Master password: ")
        try:
            deleted = delete_credential_entry(
                master_password=master_pwd,
                service=service,
                username=username,
                db_path=db_path,
            )
        except ValueError:
            print("Invalid master password.")
            return 1
        except RuntimeError as exc:
            print(str(exc))
            return 1

        if not deleted:
            print("No credential found to delete.")
            return 1

        print(f"Deleted credential for service={service!r}, username={username!r}.")
        return 0

    # This should be unreachable because subparsers are required
    print("Unknown command.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
