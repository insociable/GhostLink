"""Device identity primitives for GhostLink."""

from __future__ import annotations

import base64
import hashlib

_DEVICE_ID_PREFIX = "device1:"
_DOMAIN_SEPARATOR = b"ghostlink-device"
_FORMAT_VERSION = b"\x01"
_KEY_TYPE = b"ed25519"


def derive_device_id(public_key: bytes) -> str:
    """Derive a versioned DeviceID from a canonical Ed25519 public key."""
    if len(public_key) != 32:
        raise ValueError("Ed25519 public key must contain exactly 32 bytes")

    payload = (
        _DOMAIN_SEPARATOR
        + _FORMAT_VERSION
        + _KEY_TYPE
        + public_key
    )

    digest = hashlib.sha256(payload).digest()

    encoded_digest = (
        base64.b32encode(digest)
        .decode("ascii")
        .rstrip("=")
        .lower()
    )

    return f"{_DEVICE_ID_PREFIX}{encoded_digest}"