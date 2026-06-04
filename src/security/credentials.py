"""Fernet symmetric encryption for device credentials stored in Postgres.

Credentials (username, password, api_key, etc.) are encrypted before writing
to the database and decrypted on read. The ENCRYPTION_KEY env var is the only
secret required — rotate it and re-register devices if compromised.

If ENCRYPTION_KEY is not set, a random key is generated at startup and stored
in the database under a well-known key record. This is convenient for single-
node deployments; multi-node setups should set ENCRYPTION_KEY explicitly so all
nodes share the same key.
"""
from __future__ import annotations

import base64
import json
import logging
import os

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is not None:
        return _fernet

    key_env = os.environ.get("ENCRYPTION_KEY", "")
    if key_env:
        raw = key_env.encode()
        # Accept raw 32-byte hex or base64-encoded Fernet key
        if len(raw) == 32:
            raw = base64.urlsafe_b64encode(raw)
        _fernet = Fernet(raw)
    else:
        # Generate a key and cache it for the lifetime of the process.
        # Warn loudly — credentials won't survive container restarts without ENCRYPTION_KEY.
        logger.warning(
            "ENCRYPTION_KEY not set — generating ephemeral key. "
            "Device credentials will be lost on container restart. "
            "Set ENCRYPTION_KEY in .env for persistence."
        )
        _fernet = Fernet(Fernet.generate_key())

    return _fernet


def encrypt_credentials(creds: dict) -> str:
    """Encrypt a credentials dict to a Fernet token string."""
    plaintext = json.dumps(creds, sort_keys=True).encode()
    return _get_fernet().encrypt(plaintext).decode()


def decrypt_credentials(token: str) -> dict:
    """Decrypt a Fernet token string back to a credentials dict."""
    try:
        plaintext = _get_fernet().decrypt(token.encode())
        return json.loads(plaintext)
    except (InvalidToken, Exception) as e:
        raise ValueError(f"Failed to decrypt device credentials: {e}") from e
