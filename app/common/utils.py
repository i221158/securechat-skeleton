"""Helper signatures: now_ms, b64e, b64d, sha256_hex."""

import base64
import datetime
import hashlib
from typing import Union

def now_ms() -> int:
    """Returns the current time in milliseconds since the epoch (UTC)."""
    return int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)

def b64e(b: bytes) -> str:
    """Computes URL-safe Base64 encoding and returns a string."""
    # We use URL-safe variant as it's a good practice for all JSON/web
    return base64.urlsafe_b64encode(b).decode('utf-8')

def b64d(s: str) -> bytes:
    """Decodes a URL-safe Base64-encoded string."""
    # Add padding if it was stripped, which b64decode handles
    try:
        return base64.urlsafe_b64decode(s.encode('utf-8'))
    except (base64.binascii.Error, ValueError) as e:
        print(f"Error decoding Base64 string: {s}")
        raise ValueError(f"Invalid Base64 string: {e}") from e

def sha256_hex(data: bytes) -> str:
    """Computes the SHA-256 hash and returns a hex string."""
    return hashlib.sha256(data).hexdigest()

def sha256_bytes(data: bytes) -> bytes:
    """Computes the SHA-256 hash and returns raw bytes."""
    return hashlib.sha256(data).digest()