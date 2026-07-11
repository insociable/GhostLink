"""GhostLink device certificate primitives."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

_CERTIFICATE_DOMAIN = b"ghostlink-device-certificate"
_CERTIFICATE_VERSION = 1
_PUBLIC_KEY_SIZE = 32


def _encode_bytes(value: bytes) -> bytes:
    """Encode bytes with a deterministic length prefix."""
    return struct.pack(">I", len(value)) + value


def _encode_text(value: str) -> bytes:
    """Encode UTF-8 text with a deterministic length prefix."""
    return _encode_bytes(value.encode("utf-8"))


@dataclass(frozen=True, slots=True)
class GhostDeviceCertificate:
    """Unsigned description of a GhostLink device."""

    ghost_id: str
    device_id: str
    signing_public_key: bytes
    encryption_public_key: bytes

    def __post_init__(self) -> None:
        """Validate certificate fields."""
        if not self.ghost_id.startswith("ghost1:"):
            raise ValueError("ghost_id must use the ghost1 format")

        if not self.device_id.startswith("device1:"):
            raise ValueError("device_id must use the device1 format")

        if len(self.signing_public_key) != _PUBLIC_KEY_SIZE:
            raise ValueError("signing_public_key must contain exactly 32 bytes")

        if len(self.encryption_public_key) != _PUBLIC_KEY_SIZE:
            raise ValueError("encryption_public_key must contain exactly 32 bytes")

    def canonical_bytes(self) -> bytes:
        """Return the deterministic byte representation used for signing."""
        return b"".join(
            (
                _encode_bytes(_CERTIFICATE_DOMAIN),
                struct.pack(">B", _CERTIFICATE_VERSION),
                _encode_text(self.ghost_id),
                _encode_text(self.device_id),
                _encode_bytes(self.signing_public_key),
                _encode_bytes(self.encryption_public_key),
            )
        )


@dataclass(frozen=True, slots=True)
class SignedGhostDeviceCertificate:
    """Device certificate accompanied by its identity signature."""

    certificate: GhostDeviceCertificate
    signature: bytes


def sign_device_certificate(
    certificate: GhostDeviceCertificate,
    identity_signing_key: SigningKey,
) -> SignedGhostDeviceCertificate:
    """Sign a device certificate with the GhostEntity identity key."""
    signature = identity_signing_key.sign(
        certificate.canonical_bytes()
    ).signature

    return SignedGhostDeviceCertificate(
        certificate=certificate,
        signature=signature,
    )


def verify_device_certificate(
    signed_certificate: SignedGhostDeviceCertificate,
    identity_verify_key: VerifyKey,
) -> bool:
    """Return whether the certificate signature is valid."""
    try:
        identity_verify_key.verify(
            signed_certificate.certificate.canonical_bytes(),
            signed_certificate.signature,
        )
    except BadSignatureError:
        return False

    return True