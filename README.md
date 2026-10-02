# Password Manager

This is a small, command-line password manager written in Python. It stores
credentials in a local SQLite database and encrypts passwords using a key derived from a
master password.

> Warning: This is not a production-ready password
> manager. It has not been audited and is intentionally simple.

## Features

- Local SQLite database (`vault.db` by default)
- Master password–protected vault
- Key derivation with PBKDF2-HMAC-SHA256
- Symmetric encryption using Fernet (via the `cryptography` library)
- CLI commands to:
  - initialize the vault
  - check status
  - verify the master password
  - add/update a credential
  - get a credential
  - list credentials (optionally filtered by tag)
  - search credentials by service, username, or free-text query
  - show or add tags on a credential
  - delete a credential

## Installation

This project uses [`uv`](https://github.com/astral-sh/uv) to manage the virtual environment
and dependencies.

```bash
# Create a virtual environment (if you have not already)
uv venv

# Install dependencies
uv sync

# Run tests (optional)
uv run pytest
```

## Usage

All commands are run from the project root. By default, the vault is stored in `vault.db`
next to the code. You can override this with `--db PATH`.

```bash
# Show CLI help
uv run python main.py --help
```

### Initialize the vault

```bash
uv run python main.py init
```

- Prompts you to enter and confirm a master password.
- Creates (or updates) the SQLite database.
- Stores password-derived key material in the `metadata` table.

### Check vault status

```bash
uv run python main.py status
```

- Prints whether the vault at the given DB path is initialized.

### Verify the master password

```bash
uv run python main.py verify
```

- Prompts for the master password.
- Tells you whether it matches the stored verifier.

### Add or update a credential

```bash
uv run python main.py add SERVICE USERNAME
```

Example:

```bash
uv run python main.py add example.com alice
```

- Prompts for the master password.
- Prompts for the password to store.
- Encrypts the password and stores it in the `credentials` table.
- If a credential for the same `(service, username)` already exists, it is updated.
- Optionally attach tags at the same time with a repeatable `--tag TAG`:

  ```bash
  uv run python main.py add example.com alice --tag work --tag email
  ```

### Get a credential

```bash
uv run python main.py get SERVICE USERNAME
```

Example:

```bash
uv run python main.py get example.com alice
```

- Prompts for the master password.
- If the password is correct and a credential exists, prints the decrypted password to
  standard output.

### List credentials

```bash
uv run python main.py list
```

- Prompts for the master password.
- Prints each stored credential as a `service username` pair.
- Does **not** print any passwords.
- Optionally filter by tag with `--tag TAG`:

  ```bash
  uv run python main.py list --tag work
  ```

### Search credentials

```bash
uv run python main.py search
```

- Prompts for the master password.
- Prints matching `service username` pairs (no passwords).
- Filters are case-insensitive substrings and can be combined:
  - `--service TEXT`: match part of the service name
  - `--username TEXT`: match part of the username
  - `--query TEXT`: match part of either the service or the username
  - `--tag TAG`: restrict to credentials carrying the tag, before the other filters

Example:

```bash
uv run python main.py search --query git
uv run python main.py search --service example --tag work
```

### Show or add tags

```bash
uv run python main.py tags SERVICE USERNAME
uv run python main.py tag-add SERVICE USERNAME --tag TAG [--tag TAG ...]
```

Example:

```bash
uv run python main.py tags example.com alice
uv run python main.py tag-add example.com alice --tag work --tag email
```

- `tags` prompts for the master password and prints the credential's tags, one per line.
- `tag-add` prompts for the master password and adds the given tags, preserving any that
  already exist. Tags are stripped of surrounding whitespace and de-duplicated.

### Delete a credential

```bash
uv run python main.py delete SERVICE USERNAME
```

Example:

```bash
uv run python main.py delete example.com alice
```

- Prompts for the master password.
- Deletes the credential if it exists.

## Encryption and key-derivation design

> File references below are relative to the project root.

### Database layout

Defined in `database.py`:

- `metadata` table: key/value store for vault configuration
  - `kdf_salt`: random salt used for PBKDF2
  - `kdf_iterations`: iteration count (stored as ASCII text)
  - `master_key_verifier`: hash of the derived key, used to check passwords
- `credentials` table: stored credentials
  - `service`: service name (e.g. `example.com`)
  - `username`: username for that service
  - `password_encrypted`: encrypted password bytes
  - `created_at`, `updated_at`: ISO 8601 timestamps (UTC)
  - `(service, username)` is unique; re-adding the same pair updates it in place
- `credential_tags` table: tags attached to credentials
  - `credential_id`: foreign key into `credentials` (cascades on delete)
  - `tag`: a single normalized tag string; `(credential_id, tag)` is unique

### Master password and key derivation

Defined in `vault.py`:

1. **Initialization (`initialize_vault_with_password`)**

   - Generates a random 16-byte salt with `os.urandom`.
   - Uses PBKDF2-HMAC-SHA256 (via `cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC`) to
     derive a 32-byte key from the master password, salt, and an iteration count
     (`_DEFAULT_ITERATIONS`).
   - Computes `SHA-256(key)` and stores this digest as `master_key_verifier`.
   - Stores: `kdf_salt`, `kdf_iterations`, and `master_key_verifier` in the `metadata` table.

2. **Verifying the master password**

   - Loads the salt, iteration count and stored verifier from `metadata`.
   - Derives a key from the candidate password using the same PBKDF2 parameters.
   - Computes `SHA-256(derived_key)` and compares it to `master_key_verifier` using
     `hmac.compare_digest` to avoid timing attacks.

3. **Getting the encryption key (`get_encryption_key_from_password`)**

   - Same as verification, but instead of returning a boolean, it:
     - Raises `RuntimeError` if the vault is not initialized.
     - Raises `ValueError` if the password is incorrect.
     - Returns the 32-byte derived key if the password is correct.

### Password encryption and decryption

This project uses Fernet (from `cryptography.fernet`) as a simple, authenticated symmetric
cipher.

1. **Constructing a Fernet key**

   - The PBKDF2-derived key is 32 raw bytes.
   - Fernet expects a URL-safe base64-encoded 32-byte key.
   - `_make_fernet` base64-encodes the raw key with `base64.urlsafe_b64encode` and constructs
     a `Fernet` instance.

2. **Encrypting a credential (`add_credential`)**

   - Calls `get_encryption_key_from_password` to validate the master password and get the
     encryption key.
   - Builds a `Fernet` instance from that key.
   - Encrypts the UTF-8 encoded password (`password_plain.encode("utf-8")`).
   - Stores the resulting ciphertext bytes in the `credentials.password_encrypted` column via
     `upsert_credential`.

3. **Decrypting a credential (`get_credential_password`)**

   - Validates the master password and obtains the encryption key.
   - Loads the encrypted password bytes from the `credentials` table with `fetch_credential`.
   - Uses the same `Fernet` key to decrypt the ciphertext.
   - Decodes the plaintext bytes as UTF-8 and returns it as a `str`.

### Why this design

- **PBKDF2 with a salt and many iterations** slows down brute-force attempts against the
  master password.
- **Verifier as `SHA-256(derived_key)`** allows password checks without storing the master
  password or the raw key directly.
- **Fernet** provides authenticated encryption (AES in CBC mode with HMAC, managed by the
  library), so:
  - Passwords are not stored in plaintext.
  - Modifications to ciphertext are detected during decryption.
- **SQLite** keeps the persistence simple and transparent.

Again, this is intentionally minimal and not meant to replace a mature password manager.
It is a good starting point to learn about key derivation, symmetric encryption, and
structuring a small CLI security-focused tool.
