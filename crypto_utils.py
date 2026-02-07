import base64
import hashlib
import os
from typing import Tuple

from cryptography.fernet import Fernet


def get_fernet_from_key(raw_key: str | None, key_file_path: str = "encryption_key.key") -> Fernet:
    """
    Create a Fernet instance from a raw key string or load from persistent file.

    For academic/demo use, if no key is provided, we generate one and save it to a file
    so it persists across app restarts. In production, store this securely (e.g., env var, vault).
    """
    if not raw_key:
        # Check if key file exists, if so load it
        if os.path.exists(key_file_path):
            with open(key_file_path, "rb") as f:
                fernet_key = f.read()
            return Fernet(fernet_key)
        else:
            # Generate new key and save it for persistence
            fernet_key = Fernet.generate_key()
            with open(key_file_path, "wb") as f:
                f.write(fernet_key)
            return Fernet(fernet_key)
    
    # If key is provided via config, derive Fernet key from it
    digest = hashlib.sha256(raw_key.encode("utf-8")).digest()
    fernet_key = base64.urlsafe_b64encode(digest)
    return Fernet(fernet_key)


def sha256_bytes(data: bytes) -> str:
    """Return the hex-encoded SHA-256 hash of the given bytes."""
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def encrypt_evidence(data: bytes, fernet: Fernet) -> bytes:
    """
    Encrypt evidence bytes using Fernet (AES + HMAC).

    Returns the encrypted bytes to be stored on disk.
    """
    return fernet.encrypt(data)


def decrypt_evidence(token: bytes, fernet: Fernet) -> bytes:
    """
    Decrypt previously encrypted evidence bytes.
    """
    return fernet.decrypt(token)


