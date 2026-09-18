"""Cryptographic binding between verified GhostLink devices and libsignal pre-key bundles."""

from __future__ import annotations

import base64
import binascii
import json
import secrets
import struct
import time
from dataclasses import dataclass

from nacl.exceptions import BadSignatureError

from ghostlink.contact import VerifiedContact
from ghostlink.device import EnrolledGhostDevice

_BINDING_VERSION = 2
_BINDING_DOMAIN = b"ghostlink-ratchet-prekey-binding"
_RATCHET_SUITE = "libsignal-v4-pqxdh-triple-ratchet"
_SIGNAL_DEVICE_ID = 1
_MAX_REGISTRATION_ID = 16_380
_MAX_BUNDLE_BYTES = 32_768
_MAX_LIFETIME_SECONDS = 7 * 24 * 60 * 60
_CLOCK_SKEW_SECONDS = 5 * 60
_BUNDLE_ID_BYTES = 16
_EC_PUBLIC_KEY_BYTES = 33
_SIGNATURE_BYTES = 64
_MAX_KYBER_PUBLIC_KEY_BYTES = 4_096
_MAX_PUBLICATION_SEQUENCE = (1 << 53) - 1
_BUNDLE_KINDS = {"one_time", "fallback"}

_UNSIGNED_FIELDS = {
    "version",
    "suite",
    "ghost_id",
    "device_id",
    "signal_address_name",
    "signal_device_id",
    "registration_id",
    "publication_sequence",
    "bundle_kind",
    "bundle_id",
    "issued_at",
    "expires_at",
    "identity_key",
    "pre_key_id",
    "pre_key",
    "signed_pre_key_id",
    "signed_pre_key",
    "signed_pre_key_signature",
    "kyber_pre_key_id",
    "kyber_pre_key",
    "kyber_pre_key_signature",
}
_SIGNED_FIELDS = _UNSIGNED_FIELDS | {"device_signature"}


class RatchetBindingError(ValueError):
    """Raised when a ratchet pre-key binding is malformed or unauthentic."""


@dataclass(frozen=True, slots=True)
class RatchetPreKeyMaterial:
    """Public libsignal material safe to bind and publish."""

    registration_id: int
    identity_key: bytes
    pre_key_id: int | None
    pre_key: bytes | None
    signed_pre_key_id: int
    signed_pre_key: bytes
    signed_pre_key_signature: bytes
    kyber_pre_key_id: int
    kyber_pre_key: bytes
    kyber_pre_key_signature: bytes


@dataclass(frozen=True, slots=True)
class RatchetPreKeyBinding:
    """Unsigned GhostLink-to-libsignal identity binding."""

    ghost_id: str
    device_id: str
    signal_address_name: str
    signal_device_id: int
    registration_id: int
    publication_sequence: int
    bundle_kind: str
    bundle_id: bytes
    issued_at: int
    expires_at: int
    identity_key: bytes
    pre_key_id: int | None
    pre_key: bytes | None
    signed_pre_key_id: int
    signed_pre_key: bytes
    signed_pre_key_signature: bytes
    kyber_pre_key_id: int
    kyber_pre_key: bytes
    kyber_pre_key_signature: bytes

    def __post_init__(self) -> None:
        """Validate all fields before a binding can be signed or trusted."""
        if not self.ghost_id.startswith("ghost1:"):
            raise RatchetBindingError("ghost_id must use the ghost1 format")
        if not self.device_id.startswith("device1:"):
            raise RatchetBindingError("device_id must use the device1 format")
        if self.signal_address_name != self.device_id:
            raise RatchetBindingError(
                "signal_address_name must equal the verified DeviceID"
            )
        if self.signal_device_id != _SIGNAL_DEVICE_ID:
            raise RatchetBindingError("signal_device_id must equal 1")
        _validate_identifier(
            self.registration_id,
            "registration_id",
            _MAX_REGISTRATION_ID,
        )
        _validate_identifier(
            self.publication_sequence,
            "publication_sequence",
            _MAX_PUBLICATION_SEQUENCE,
        )
        if self.bundle_kind not in _BUNDLE_KINDS:
            raise RatchetBindingError("bundle_kind must be one_time or fallback")
        _validate_identifier(self.signed_pre_key_id, "signed_pre_key_id")
        _validate_identifier(self.kyber_pre_key_id, "kyber_pre_key_id")

        if len(self.bundle_id) != _BUNDLE_ID_BYTES:
            raise RatchetBindingError("bundle_id must contain exactly 16 bytes")
        if self.issued_at < 0 or self.expires_at < 0:
            raise RatchetBindingError("binding timestamps must be non-negative")
        if self.expires_at <= self.issued_at:
            raise RatchetBindingError("expires_at must be later than issued_at")
        if self.expires_at - self.issued_at > _MAX_LIFETIME_SECONDS:
            raise RatchetBindingError("binding lifetime exceeds seven days")

        _validate_exact_bytes(self.identity_key, "identity_key", _EC_PUBLIC_KEY_BYTES)

        if (self.pre_key_id is None) != (self.pre_key is None):
            raise RatchetBindingError(
                "pre_key_id and pre_key must either both be present or both be null"
            )
        if self.pre_key_id is not None:
            _validate_identifier(self.pre_key_id, "pre_key_id")
            if self.pre_key is None:
                raise RatchetBindingError(
                    "pre_key_id and pre_key must either both be present or both be null"
                )
            _validate_exact_bytes(self.pre_key, "pre_key", _EC_PUBLIC_KEY_BYTES)

        if self.bundle_kind == "one_time" and self.pre_key_id is None:
            raise RatchetBindingError("one_time binding requires an EC one-time pre-key")
        if self.bundle_kind == "fallback" and self.pre_key_id is not None:
            raise RatchetBindingError(
                "fallback binding must not contain an EC one-time pre-key"
            )

        _validate_exact_bytes(
            self.signed_pre_key,
            "signed_pre_key",
            _EC_PUBLIC_KEY_BYTES,
        )
        _validate_exact_bytes(
            self.signed_pre_key_signature,
            "signed_pre_key_signature",
            _SIGNATURE_BYTES,
        )
        if not self.kyber_pre_key:
            raise RatchetBindingError("kyber_pre_key must not be empty")
        if len(self.kyber_pre_key) > _MAX_KYBER_PUBLIC_KEY_BYTES:
            raise RatchetBindingError("kyber_pre_key exceeds the size limit")
        _validate_exact_bytes(
            self.kyber_pre_key_signature,
            "kyber_pre_key_signature",
            _SIGNATURE_BYTES,
        )

    def canonical_bytes(self) -> bytes:
        """Return domain-separated deterministic bytes signed by the device."""
        optional_pre_key = (
            b"\x00"
            if self.pre_key_id is None
            else b"\x01"
            + struct.pack(">I", self.pre_key_id)
            + _encode_bytes(self.pre_key or b"")
        )

        return b"".join(
            (
                _encode_bytes(_BINDING_DOMAIN),
                struct.pack(">B", _BINDING_VERSION),
                _encode_text(_RATCHET_SUITE),
                _encode_text(self.ghost_id),
                _encode_text(self.device_id),
                _encode_text(self.signal_address_name),
                struct.pack(">I", self.signal_device_id),
                struct.pack(">I", self.registration_id),
                struct.pack(">Q", self.publication_sequence),
                _encode_text(self.bundle_kind),
                _encode_bytes(self.bundle_id),
                struct.pack(">Q", self.issued_at),
                struct.pack(">Q", self.expires_at),
                _encode_bytes(self.identity_key),
                optional_pre_key,
                struct.pack(">I", self.signed_pre_key_id),
                _encode_bytes(self.signed_pre_key),
                _encode_bytes(self.signed_pre_key_signature),
                struct.pack(">I", self.kyber_pre_key_id),
                _encode_bytes(self.kyber_pre_key),
                _encode_bytes(self.kyber_pre_key_signature),
            )
        )


@dataclass(frozen=True, slots=True)
class SignedRatchetPreKeyBinding:
    """Ratchet binding authenticated by the GhostLink device signing key."""

    binding: RatchetPreKeyBinding
    device_signature: bytes

    def __post_init__(self) -> None:
        _validate_exact_bytes(
            self.device_signature,
            "device_signature",
            _SIGNATURE_BYTES,
        )


def _validate_identifier(
    value: int,
    field: str,
    maximum: int = 0x7FFF_FFFF,
) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise RatchetBindingError(f"{field} must be an integer")
    if value <= 0 or value > maximum:
        raise RatchetBindingError(f"{field} is outside the supported range")


def _validate_exact_bytes(value: bytes, field: str, size: int) -> None:
    if len(value) != size:
        raise RatchetBindingError(f"{field} must contain exactly {size} bytes")


def _encode_bytes(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def _encode_text(value: str) -> bytes:
    return _encode_bytes(value.encode("utf-8"))


def _encode_base64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode_base64(
    value: object,
    field: str,
    *,
    exact_size: int | None = None,
    max_size: int | None = None,
) -> bytes:
    if not isinstance(value, str) or not value:
        raise RatchetBindingError(f"{field} must be non-empty Base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RatchetBindingError(f"{field} must be valid Base64") from exc

    if base64.b64encode(decoded).decode("ascii") != value:
        raise RatchetBindingError(f"{field} must use canonical Base64")
    if exact_size is not None and len(decoded) != exact_size:
        raise RatchetBindingError(
            f"{field} must decode to exactly {exact_size} bytes"
        )
    if max_size is not None and len(decoded) > max_size:
        raise RatchetBindingError(f"{field} exceeds the size limit")
    return decoded


def _require_integer(document: dict[str, object], field: str) -> int:
    value = document.get(field)
    if not isinstance(value, int) or isinstance(value, bool):
        raise RatchetBindingError(f"{field} must be an integer")
    return value


def _require_text(document: dict[str, object], field: str) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not value:
        raise RatchetBindingError(f"{field} must be non-empty text")
    return value


def _parse_optional_pre_key(
    document: dict[str, object],
) -> tuple[int | None, bytes | None]:
    raw_id = document.get("pre_key_id")
    raw_key = document.get("pre_key")

    if raw_id is None and raw_key is None:
        return None, None
    if raw_id is None or raw_key is None:
        raise RatchetBindingError(
            "pre_key_id and pre_key must either both be present or both be null"
        )

    pre_key_id = _require_integer(document, "pre_key_id")
    pre_key = _decode_base64(
        raw_key,
        "pre_key",
        exact_size=_EC_PUBLIC_KEY_BYTES,
    )
    return pre_key_id, pre_key




def _validate_local_enrolled_device(device: EnrolledGhostDevice) -> None:
    certificate = device.certificate.certificate
    if device.device_id != certificate.device_id:
        raise RatchetBindingError("enrolled device does not match its certificate")
    if bytes(device.device.signing_verify_key) != certificate.signing_public_key:
        raise RatchetBindingError("device signing key does not match its certificate")
    if (
        bytes(device.device.encryption_public_key)
        != certificate.encryption_public_key
    ):
        raise RatchetBindingError("device encryption key does not match its certificate")


def create_ratchet_prekey_binding(
    device: EnrolledGhostDevice,
    material: RatchetPreKeyMaterial,
    *,
    publication_sequence: int,
    bundle_kind: str,
    issued_at: int | None = None,
    lifetime_seconds: int = 24 * 60 * 60,
    bundle_id: bytes | None = None,
) -> RatchetPreKeyBinding:
    """Bind public libsignal material to one enrolled GhostLink device."""
    if lifetime_seconds <= 0 or lifetime_seconds > _MAX_LIFETIME_SECONDS:
        raise RatchetBindingError("lifetime_seconds must be between 1 and seven days")

    _validate_local_enrolled_device(device)
    certificate = device.certificate.certificate

    now = int(time.time()) if issued_at is None else issued_at

    return RatchetPreKeyBinding(
        ghost_id=certificate.ghost_id,
        device_id=certificate.device_id,
        signal_address_name=certificate.device_id,
        signal_device_id=_SIGNAL_DEVICE_ID,
        registration_id=material.registration_id,
        publication_sequence=publication_sequence,
        bundle_kind=bundle_kind,
        bundle_id=secrets.token_bytes(_BUNDLE_ID_BYTES) if bundle_id is None else bundle_id,
        issued_at=now,
        expires_at=now + lifetime_seconds,
        identity_key=material.identity_key,
        pre_key_id=material.pre_key_id,
        pre_key=material.pre_key,
        signed_pre_key_id=material.signed_pre_key_id,
        signed_pre_key=material.signed_pre_key,
        signed_pre_key_signature=material.signed_pre_key_signature,
        kyber_pre_key_id=material.kyber_pre_key_id,
        kyber_pre_key=material.kyber_pre_key,
        kyber_pre_key_signature=material.kyber_pre_key_signature,
    )


def sign_ratchet_prekey_binding(
    binding: RatchetPreKeyBinding,
    device: EnrolledGhostDevice,
) -> SignedRatchetPreKeyBinding:
    """Authenticate a ratchet binding with the enrolled device signing key."""
    _validate_local_enrolled_device(device)
    certificate = device.certificate.certificate
    if binding.ghost_id != certificate.ghost_id:
        raise RatchetBindingError("binding GhostID does not match local device")
    if binding.device_id != certificate.device_id:
        raise RatchetBindingError("binding DeviceID does not match local device")

    signature = device.device.signing_key.sign(binding.canonical_bytes()).signature
    return SignedRatchetPreKeyBinding(
        binding=binding,
        device_signature=signature,
    )


def verify_ratchet_prekey_binding(
    signed: SignedRatchetPreKeyBinding,
    contact: VerifiedContact,
    *,
    now: int | None = None,
) -> RatchetPreKeyBinding:
    """Verify that ratchet material belongs to an already verified GhostLink device."""
    binding = signed.binding

    if binding.ghost_id != contact.ghost_id:
        raise RatchetBindingError("binding GhostID does not match verified contact")
    if binding.device_id != contact.device_id:
        raise RatchetBindingError("binding DeviceID does not match verified contact")
    if binding.signal_address_name != contact.device_id:
        raise RatchetBindingError(
            "libsignal address is not bound to the verified DeviceID"
        )

    current_time = int(time.time()) if now is None else now
    if binding.issued_at > current_time + _CLOCK_SKEW_SECONDS:
        raise RatchetBindingError("binding was issued too far in the future")
    if binding.expires_at < current_time - _CLOCK_SKEW_SECONDS:
        raise RatchetBindingError("binding has expired")

    try:
        contact.device.signing_verify_key.verify(
            binding.canonical_bytes(),
            signed.device_signature,
        )
    except BadSignatureError as exc:
        raise RatchetBindingError("device signature is invalid") from exc

    return binding


def export_ratchet_prekey_binding(
    signed: SignedRatchetPreKeyBinding,
) -> str:
    """Serialize a signed ratchet binding as deterministic public JSON."""
    binding = signed.binding
    document: dict[str, object] = {
        "version": _BINDING_VERSION,
        "suite": _RATCHET_SUITE,
        "ghost_id": binding.ghost_id,
        "device_id": binding.device_id,
        "signal_address_name": binding.signal_address_name,
        "signal_device_id": binding.signal_device_id,
        "registration_id": binding.registration_id,
        "publication_sequence": binding.publication_sequence,
        "bundle_kind": binding.bundle_kind,
        "bundle_id": binding.bundle_id.hex(),
        "issued_at": binding.issued_at,
        "expires_at": binding.expires_at,
        "identity_key": _encode_base64(binding.identity_key),
        "pre_key_id": binding.pre_key_id,
        "pre_key": None if binding.pre_key is None else _encode_base64(binding.pre_key),
        "signed_pre_key_id": binding.signed_pre_key_id,
        "signed_pre_key": _encode_base64(binding.signed_pre_key),
        "signed_pre_key_signature": _encode_base64(
            binding.signed_pre_key_signature
        ),
        "kyber_pre_key_id": binding.kyber_pre_key_id,
        "kyber_pre_key": _encode_base64(binding.kyber_pre_key),
        "kyber_pre_key_signature": _encode_base64(
            binding.kyber_pre_key_signature
        ),
        "device_signature": _encode_base64(signed.device_signature),
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


def import_ratchet_prekey_binding(serialized: str) -> SignedRatchetPreKeyBinding:
    """Parse a signed ratchet binding without trusting it yet."""
    if len(serialized.encode("utf-8")) > _MAX_BUNDLE_BYTES:
        raise RatchetBindingError("ratchet binding is too large")

    try:
        parsed: object = json.loads(serialized)
    except json.JSONDecodeError as exc:
        raise RatchetBindingError("ratchet binding must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise RatchetBindingError("ratchet binding must be a JSON object")

    document: dict[str, object] = {}
    for key, value in parsed.items():
        if not isinstance(key, str):
            raise RatchetBindingError("ratchet binding field names must be text")
        document[key] = value

    if set(document) != _SIGNED_FIELDS:
        raise RatchetBindingError("ratchet binding fields do not match version 1")
    if _require_integer(document, "version") != _BINDING_VERSION:
        raise RatchetBindingError("unsupported ratchet binding version")
    if _require_text(document, "suite") != _RATCHET_SUITE:
        raise RatchetBindingError("unsupported ratchet suite")

    raw_bundle_id = _require_text(document, "bundle_id")
    if len(raw_bundle_id) != _BUNDLE_ID_BYTES * 2:
        raise RatchetBindingError("bundle_id must be 128-bit lowercase hexadecimal")
    try:
        bundle_id = bytes.fromhex(raw_bundle_id)
    except ValueError as exc:
        raise RatchetBindingError(
            "bundle_id must be 128-bit lowercase hexadecimal"
        ) from exc
    if bundle_id.hex() != raw_bundle_id:
        raise RatchetBindingError("bundle_id must use lowercase hexadecimal")

    pre_key_id, pre_key = _parse_optional_pre_key(document)

    binding = RatchetPreKeyBinding(
        ghost_id=_require_text(document, "ghost_id"),
        device_id=_require_text(document, "device_id"),
        signal_address_name=_require_text(document, "signal_address_name"),
        signal_device_id=_require_integer(document, "signal_device_id"),
        registration_id=_require_integer(document, "registration_id"),
        publication_sequence=_require_integer(document, "publication_sequence"),
        bundle_kind=_require_text(document, "bundle_kind"),
        bundle_id=bundle_id,
        issued_at=_require_integer(document, "issued_at"),
        expires_at=_require_integer(document, "expires_at"),
        identity_key=_decode_base64(
            document["identity_key"],
            "identity_key",
            exact_size=_EC_PUBLIC_KEY_BYTES,
        ),
        pre_key_id=pre_key_id,
        pre_key=pre_key,
        signed_pre_key_id=_require_integer(document, "signed_pre_key_id"),
        signed_pre_key=_decode_base64(
            document["signed_pre_key"],
            "signed_pre_key",
            exact_size=_EC_PUBLIC_KEY_BYTES,
        ),
        signed_pre_key_signature=_decode_base64(
            document["signed_pre_key_signature"],
            "signed_pre_key_signature",
            exact_size=_SIGNATURE_BYTES,
        ),
        kyber_pre_key_id=_require_integer(document, "kyber_pre_key_id"),
        kyber_pre_key=_decode_base64(
            document["kyber_pre_key"],
            "kyber_pre_key",
            max_size=_MAX_KYBER_PUBLIC_KEY_BYTES,
        ),
        kyber_pre_key_signature=_decode_base64(
            document["kyber_pre_key_signature"],
            "kyber_pre_key_signature",
            exact_size=_SIGNATURE_BYTES,
        ),
    )
    return SignedRatchetPreKeyBinding(
        binding=binding,
        device_signature=_decode_base64(
            document["device_signature"],
            "device_signature",
            exact_size=_SIGNATURE_BYTES,
        ),
    )