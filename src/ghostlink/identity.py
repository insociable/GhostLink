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
_GHOST_ID_PAYLOAD_LENGTH = 52
_BASE32_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz234567")
_FINGERPRINT_DOMAIN = b"ghostlink-contact-fingerprint-v2"
_FINGERPRINT_KEY_TYPE = b"ed25519"
_FINGERPRINT_PREFIX = "GLF2:"


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


def derive_identity_fingerprint(public_key: bytes) -> str:
    """Derive the domain-separated Fingerprint v2 for one Ed25519 identity."""
    if len(public_key) != 32:
        raise ValueError("Ed25519 public key must contain exactly 32 bytes")

    digest = hashlib.sha256(
        _FINGERPRINT_DOMAIN
        + b"\x00"
        + _FINGERPRINT_KEY_TYPE
        + b"\x00"
        + public_key
    ).digest()
    encoded = base64.b32encode(digest).decode("ascii").rstrip("=")
    groups = [encoded[index : index + 4] for index in range(0, len(encoded), 4)]
    return _FINGERPRINT_PREFIX + "-".join(groups)


def format_ghost_id_fingerprint(ghost_id: str) -> str:
    """Render the legacy Fingerprint v1 grouped GhostID payload."""
    if not ghost_id.startswith(_GHOST_ID_PREFIX):
        raise ValueError("ghost_id must use the ghost1 format")

    payload = ghost_id[len(_GHOST_ID_PREFIX) :]

    if len(payload) != _GHOST_ID_PAYLOAD_LENGTH:
        raise ValueError("ghost_id payload has an invalid length")
    if any(character not in _BASE32_ALPHABET for character in payload):
        raise ValueError("ghost_id payload is not valid lowercase Base32")

    groups = [
        payload[index : index + 4].upper()
        for index in range(0, len(payload), 4)
    ]
    return "-".join(groups)


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
