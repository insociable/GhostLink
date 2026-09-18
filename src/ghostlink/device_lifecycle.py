"""Identity-authorized monotonic lifecycle state for one active GhostLink device."""

from __future__ import annotations

import base64
import binascii
import json
import struct
import time
from dataclasses import dataclass

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from ghostlink.device import EnrolledGhostDevice, PublicGhostDevice
from ghostlink.device_certificate import (
    GhostDeviceCertificate,
    SignedGhostDeviceCertificate,
)
from ghostlink.entity import GhostEntity
from ghostlink.identity import derive_ghost_id

_LIFECYCLE_VERSION = 1
_LIFECYCLE_DOMAIN = b"ghostlink-device-lifecycle"
_MAX_EPOCH = (1 << 53) - 1
_MAX_SERIALIZED_BYTES = 16_384
_PUBLIC_KEY_BYTES = 32
_SIGNATURE_BYTES = 64

_FIELDS = {
    "version",
    "ghost_id",
    "epoch",
    "issued_at",
    "device_id",
    "device_signing_public_key",
    "device_encryption_public_key",
    "device_certificate_signature",
    "identity_signature",
}


class DeviceLifecycleError(ValueError):
    """Raised when device lifecycle state is malformed or unauthentic."""


def _encode_bytes(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def _encode_text(value: str) -> bytes:
    return _encode_bytes(value.encode("utf-8"))


def _encode_base64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode_base64(value: object, field: str, size: int) -> bytes:
    if not isinstance(value, str) or not value:
        raise DeviceLifecycleError(f"{field} must be non-empty Base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DeviceLifecycleError(f"{field} must be valid Base64") from exc
    if len(decoded) != size:
        raise DeviceLifecycleError(
            f"{field} must decode to exactly {size} bytes"
        )
    if _encode_base64(decoded) != value:
        raise DeviceLifecycleError(f"{field} must use canonical Base64")
    return decoded


def _require_text(document: dict[str, object], field: str) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not value:
        raise DeviceLifecycleError(f"{field} must be non-empty text")
    return value


def _require_integer(document: dict[str, object], field: str) -> int:
    value = document.get(field)
    if not isinstance(value, int) or isinstance(value, bool):
        raise DeviceLifecycleError(f"{field} must be an integer")
    return value


@dataclass(frozen=True, slots=True)
class DeviceLifecycleStatement:
    """Unsigned statement naming the only active device at one identity epoch."""

    ghost_id: str
    epoch: int
    issued_at: int
    device_certificate: SignedGhostDeviceCertificate

    def __post_init__(self) -> None:
        certificate = self.device_certificate.certificate
        if not self.ghost_id.startswith("ghost1:"):
            raise DeviceLifecycleError("ghost_id must use the ghost1 format")
        if certificate.ghost_id != self.ghost_id:
            raise DeviceLifecycleError(
                "device certificate GhostID does not match lifecycle GhostID"
            )
        if (
            not isinstance(self.epoch, int)
            or isinstance(self.epoch, bool)
            or not 1 <= self.epoch <= _MAX_EPOCH
        ):

            raise DeviceLifecycleError(
                "device lifecycle epoch is outside the supported range"
            )
        if (
            not isinstance(self.issued_at, int)
            or isinstance(self.issued_at, bool)
            or self.issued_at < 0
        ):
            raise DeviceLifecycleError(
                "device lifecycle issued_at must be a non-negative integer"
            )
        if len(self.device_certificate.signature) != _SIGNATURE_BYTES:
            raise DeviceLifecycleError(
                "device certificate signature must contain exactly 64 bytes"
            )

    @property
    def device_id(self) -> str:
        """Return the active DeviceID."""

        return self.device_certificate.certificate.device_id

    def canonical_bytes(self) -> bytes:
        """Return deterministic domain-separated bytes signed by the identity."""

        certificate = self.device_certificate
        return b"".join(
            (
                _encode_bytes(_LIFECYCLE_DOMAIN),
                struct.pack(">B", _LIFECYCLE_VERSION),
                _encode_text(self.ghost_id),

                struct.pack(">Q", self.epoch),
                struct.pack(">Q", self.issued_at),
                _encode_bytes(certificate.certificate.canonical_bytes()),
                _encode_bytes(certificate.signature),
            )
        )


@dataclass(frozen=True, slots=True)
class SignedDeviceLifecycleStatement:
    """Lifecycle state authenticated by the long-term GhostID identity key."""

    statement: DeviceLifecycleStatement
    identity_signature: bytes

    def __post_init__(self) -> None:
        if len(self.identity_signature) != _SIGNATURE_BYTES:
            raise DeviceLifecycleError(
                "identity signature must contain exactly 64 bytes"
            )


def create_device_lifecycle_statement(
    entity: GhostEntity,
    device: EnrolledGhostDevice,
    *,
    epoch: int,
    issued_at: int | None = None,
) -> SignedDeviceLifecycleStatement:
    """Create and identity-sign lifecycle state for one enrolled device."""

    try:
        PublicGhostDevice.from_certificate(
            device.certificate,
            entity.verify_key,
        )
    except ValueError as exc:
        raise DeviceLifecycleError(str(exc)) from exc

    statement = DeviceLifecycleStatement(
        ghost_id=entity.ghost_id,
        epoch=epoch,
        issued_at=int(time.time()) if issued_at is None else issued_at,
        device_certificate=device.certificate,
    )
    signature = entity.signing_key.sign(statement.canonical_bytes()).signature
    return SignedDeviceLifecycleStatement(
        statement=statement,
        identity_signature=signature,
    )


def verify_device_lifecycle_statement(
    signed: SignedDeviceLifecycleStatement,
    identity_verify_key: VerifyKey,
) -> PublicGhostDevice:
    """Verify identity authority, device certificate and active-device binding."""

    statement = signed.statement
    expected_ghost_id = derive_ghost_id(bytes(identity_verify_key))
    if statement.ghost_id != expected_ghost_id:
        raise DeviceLifecycleError(
            "lifecycle GhostID does not match identity verification key"
        )

    try:
        identity_verify_key.verify(
            statement.canonical_bytes(),
            signed.identity_signature,
        )
    except BadSignatureError as exc:
        raise DeviceLifecycleError(
            "device lifecycle identity signature is invalid"
        ) from exc

    try:
        return PublicGhostDevice.from_certificate(
            statement.device_certificate,
            identity_verify_key,
        )
    except ValueError as exc:
        raise DeviceLifecycleError(str(exc)) from exc


def export_device_lifecycle_statement(
    signed: SignedDeviceLifecycleStatement,
) -> str:
    """Serialize signed lifecycle state as deterministic canonical JSON."""

    statement = signed.statement
    certificate = statement.device_certificate
    public = certificate.certificate
    document: dict[str, object] = {
        "version": _LIFECYCLE_VERSION,
        "ghost_id": statement.ghost_id,
        "epoch": statement.epoch,
        "issued_at": statement.issued_at,
        "device_id": public.device_id,
        "device_signing_public_key": _encode_base64(public.signing_public_key),

        "device_encryption_public_key": _encode_base64(
            public.encryption_public_key
        ),
        "device_certificate_signature": _encode_base64(certificate.signature),
        "identity_signature": _encode_base64(signed.identity_signature),
    }
    serialized = json.dumps(document, sort_keys=True, separators=(",", ":"))
    if len(serialized.encode("utf-8")) > _MAX_SERIALIZED_BYTES:
        raise DeviceLifecycleError("device lifecycle statement is too large")
    return serialized


def import_device_lifecycle_statement(
    serialized: str,
) -> SignedDeviceLifecycleStatement:
    """Parse canonical signed lifecycle state without trusting it yet."""

    if len(serialized.encode("utf-8")) > _MAX_SERIALIZED_BYTES:
        raise DeviceLifecycleError("device lifecycle statement is too large")
    try:
        parsed: object = json.loads(serialized)
    except json.JSONDecodeError as exc:
        raise DeviceLifecycleError(
            "device lifecycle statement must be valid JSON"
        ) from exc
    if not isinstance(parsed, dict):
        raise DeviceLifecycleError(
            "device lifecycle statement must be a JSON object"
        )

    document: dict[str, object] = {}
    for key, value in parsed.items():
        if not isinstance(key, str):
            raise DeviceLifecycleError(
                "device lifecycle field names must be text"
            )
        document[key] = value
    if set(document) != _FIELDS:
        raise DeviceLifecycleError(
            "device lifecycle fields do not match version 1"
        )
    if _require_integer(document, "version") != _LIFECYCLE_VERSION:
        raise DeviceLifecycleError("unsupported device lifecycle version")

    ghost_id = _require_text(document, "ghost_id")
    certificate = SignedGhostDeviceCertificate(
        certificate=GhostDeviceCertificate(
            ghost_id=ghost_id,
            device_id=_require_text(document, "device_id"),
            signing_public_key=_decode_base64(
                document["device_signing_public_key"],
                "device_signing_public_key",
                _PUBLIC_KEY_BYTES,
            ),
            encryption_public_key=_decode_base64(
                document["device_encryption_public_key"],
                "device_encryption_public_key",
                _PUBLIC_KEY_BYTES,
            ),
        ),

        signature=_decode_base64(
            document["device_certificate_signature"],
            "device_certificate_signature",
            _SIGNATURE_BYTES,
        ),
    )
    signed = SignedDeviceLifecycleStatement(
        statement=DeviceLifecycleStatement(
            ghost_id=ghost_id,
            epoch=_require_integer(document, "epoch"),
            issued_at=_require_integer(document, "issued_at"),
            device_certificate=certificate,
        ),
        identity_signature=_decode_base64(
            document["identity_signature"],
            "identity_signature",
            _SIGNATURE_BYTES,
        ),
    )

    if export_device_lifecycle_statement(signed) != serialized:
        raise DeviceLifecycleError(
            "device lifecycle statement must use canonical JSON"
        )
    return signed


def require_newer_device_lifecycle(
    current: SignedDeviceLifecycleStatement,
    candidate: SignedDeviceLifecycleStatement,

    identity_verify_key: VerifyKey,
) -> PublicGhostDevice:
    """Accept only a strict next-or-newer epoch for the same GhostID."""

    verify_device_lifecycle_statement(current, identity_verify_key)
    candidate_device = verify_device_lifecycle_statement(
        candidate,
        identity_verify_key,
    )
    old = current.statement
    new = candidate.statement
    if new.ghost_id != old.ghost_id:
        raise DeviceLifecycleError("device lifecycle identity changed")
    if new.epoch <= old.epoch:
        raise DeviceLifecycleError(
            "device lifecycle candidate is not newer than current state"
        )
    if new.issued_at < old.issued_at:
        raise DeviceLifecycleError(
            "device lifecycle candidate predates current state"
        )
    return candidate_device
