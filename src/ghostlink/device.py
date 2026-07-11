"""Device identity primitives for GhostLink."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from nacl.public import PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey

from ghostlink.device_certificate import SignedGhostDeviceCertificate

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


@dataclass(frozen=True, slots=True)
class GhostDevice:
    """A GhostLink device with separate signing and encryption keys."""

    signing_key: SigningKey
    encryption_key: PrivateKey

    @classmethod
    def generate(cls) -> GhostDevice:
        """Generate independent device signing and encryption keys."""
        return cls(
            signing_key=SigningKey.generate(),
            encryption_key=PrivateKey.generate(),
        )

    @property
    def signing_verify_key(self) -> VerifyKey:
        """Return the device signing public key."""
        return self.signing_key.verify_key

    @property
    def encryption_public_key(self) -> PublicKey:
        """Return the device encryption public key."""
        return self.encryption_key.public_key

    @property
    def device_id(self) -> str:
        """Return the self-certifying DeviceID."""
        return derive_device_id(bytes(self.signing_verify_key))


@dataclass(frozen=True, slots=True)
class EnrolledGhostDevice:
    """A GhostDevice associated with its signed certificate."""

    device: GhostDevice
    certificate: SignedGhostDeviceCertificate

    @property
    def device_id(self) -> str:
        """Return the enrolled device identifier."""
        return self.device.device_id