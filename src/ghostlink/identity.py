"""GhostLink identity and self-certifying identifier primitives."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from nacl.signing import SigningKey, VerifyKey

_GHOST_ID_PREFIX = "ghost1:"
_DOMAIN_SEPARATOR = b"ghostlink-identity"
_FORMAT_VERSION = b"\x01"
_KEY_TYPE = b"ed25519"


def derive_ghost_id(public_key: bytes) -> str:
    """Derive a versioned GhostID from a canonical Ed25519 public key."""
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

    return f"{_GHOST_ID_PREFIX}{encoded_digest}"


@dataclass(frozen=True, slots=True)
class Identity:
    """A stable GhostLink identity backed by an Ed25519 signing key."""

    signing_key: SigningKey

    @classmethod
    def generate(cls) -> Identity:
        """Generate a new identity using libsodium secure randomness."""
        return cls(signing_key=SigningKey.generate())

    @property
    def verify_key(self) -> VerifyKey:
        """Return the public Ed25519 verification key."""
        return self.signing_key.verify_key

    @property
    def ghost_id(self) -> str:
        """Return the self-certifying identifier for this identity."""
        return derive_ghost_id(bytes(self.verify_key))

    def export_public_key(self) -> str:
        """Export the public identity key as unpadded Base64 text."""
        return base64.b64encode(bytes(self.verify_key)).decode("ascii")