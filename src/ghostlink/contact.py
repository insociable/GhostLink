"""Portable public contact bundles for GhostLink peers."""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass

from nacl.signing import VerifyKey

from ghostlink.device import EnrolledGhostDevice, PublicGhostDevice
from ghostlink.device_certificate import (
    GhostDeviceCertificate,
    SignedGhostDeviceCertificate,
)
from ghostlink.device_lifecycle import (
    DeviceLifecycleError,
    SignedDeviceLifecycleStatement,
    export_device_lifecycle_statement,
    import_device_lifecycle_statement,
    verify_device_lifecycle_statement,
)
from ghostlink.entity import GhostEntity

_LEGACY_CONTACT_VERSION = 1
_LIFECYCLE_CONTACT_VERSION = 2
_MAX_BUNDLE_BYTES = 16_384
_PUBLIC_KEY_SIZE = 32
_SIGNATURE_SIZE = 64
_QR_SCHEME_PREFIX = "ghostlink:contact:"
_QR_V1_PREFIX = "ghostlink:contact:1:"
_QR_V2_PREFIX = "ghostlink:contact:2:"
_BASE64URL_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
_EXPECTED_FIELDS_V1 = {
    "version",
    "ghost_id",
    "identity_public_key",
    "device_id",
    "device_signing_public_key",
    "device_encryption_public_key",
    "device_certificate_signature",
}
_EXPECTED_FIELDS_V2 = {
    "version",
    "identity_public_key",
    "device_lifecycle",
}


class ContactBundleError(ValueError):
    """Raised when a contact bundle cannot be safely imported or exported."""


@dataclass(frozen=True, slots=True)
class ValidatedContact:
    """A cryptographically verified remote identity and active device."""

    identity_verify_key: VerifyKey
    device: PublicGhostDevice
    lifecycle_epoch: int | None = None
    lifecycle_issued_at: int | None = None
    lifecycle_statement: str | None = None

    @property
    def ghost_id(self) -> str:
        """Return the cryptographically validated remote GhostID."""
        return self.device.ghost_id

    @property
    def device_id(self) -> str:
        """Return the cryptographically validated active DeviceID."""
        return self.device.device_id

    @property
    def is_lifecycle_aware(self) -> bool:
        """Return whether this contact carries monotonic device lifecycle state."""
        return self.lifecycle_epoch is not None


def _encode_base64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode_base64(value: object, field: str, expected_size: int) -> bytes:
    if not isinstance(value, str):
        raise ContactBundleError(f"{field} must be Base64 text")

    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ContactBundleError(f"{field} must be valid Base64") from exc

    if len(decoded) != expected_size:
        raise ContactBundleError(
            f"{field} must decode to exactly {expected_size} bytes"
        )

    if _encode_base64(decoded) != value:
        raise ContactBundleError(f"{field} must use canonical Base64")
    return decoded


def _require_text(document: dict[str, object], field: str) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not value:
        raise ContactBundleError(f"{field} must be non-empty text")
    return value


def _require_mapping(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ContactBundleError(f"{context} must be a JSON object")
    document: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ContactBundleError(f"{context} field names must be text")
        document[key] = item
    return document


def _require_exact_fields(
    document: dict[str, object],
    expected: set[str],
) -> None:
    fields = set(document)
    if fields == expected:
        return

    missing = sorted(expected - fields)
    unknown = sorted(fields - expected)
    details: list[str] = []
    if missing:
        details.append(f"missing fields: {', '.join(missing)}")
    if unknown:
        details.append(f"unknown fields: {', '.join(unknown)}")
    raise ContactBundleError("; ".join(details))


def _parse_document(serialized: str) -> tuple[int, dict[str, object]]:
    if len(serialized.encode("utf-8")) > _MAX_BUNDLE_BYTES:
        raise ContactBundleError("contact bundle is too large")

    try:
        parsed: object = json.loads(serialized)
    except json.JSONDecodeError as exc:
        raise ContactBundleError("contact bundle must be valid JSON") from exc

    document = _require_mapping(parsed, "contact bundle")
    version = document.get("version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise ContactBundleError("version must be an integer")
    if version == _LEGACY_CONTACT_VERSION:
        _require_exact_fields(document, _EXPECTED_FIELDS_V1)
    elif version == _LIFECYCLE_CONTACT_VERSION:
        _require_exact_fields(document, _EXPECTED_FIELDS_V2)
    else:
        raise ContactBundleError("unsupported contact bundle version")

    return version, document


def export_contact_bundle(
    entity: GhostEntity,
    device: EnrolledGhostDevice,
) -> str:
    """Export the legacy version-1 single-device public contact bundle."""
    try:
        public_device = PublicGhostDevice.from_certificate(
            device.certificate,
            entity.verify_key,
        )
    except ValueError as exc:
        raise ContactBundleError(str(exc)) from exc

    certificate = device.certificate.certificate
    document = {
        "version": _LEGACY_CONTACT_VERSION,
        "ghost_id": public_device.ghost_id,
        "identity_public_key": _encode_base64(bytes(entity.verify_key)),
        "device_id": public_device.device_id,
        "device_signing_public_key": _encode_base64(
            certificate.signing_public_key
        ),
        "device_encryption_public_key": _encode_base64(
            certificate.encryption_public_key
        ),

        "device_certificate_signature": _encode_base64(
            device.certificate.signature
        ),
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


def export_verified_lifecycle_contact_bundle(
    identity_verify_key: VerifyKey,
    lifecycle: SignedDeviceLifecycleStatement,
) -> str:
    """Export lifecycle contact material already anchored to a verified identity key."""
    try:
        verify_device_lifecycle_statement(
            lifecycle,
            identity_verify_key,
        )
    except DeviceLifecycleError as exc:
        raise ContactBundleError(str(exc)) from exc

    lifecycle_document = json.loads(
        export_device_lifecycle_statement(lifecycle)
    )
    document: dict[str, object] = {
        "version": _LIFECYCLE_CONTACT_VERSION,
        "identity_public_key": _encode_base64(bytes(identity_verify_key)),
        "device_lifecycle": lifecycle_document,
    }
    serialized = json.dumps(document, sort_keys=True, separators=(",", ":"))
    if len(serialized.encode("utf-8")) > _MAX_BUNDLE_BYTES:
        raise ContactBundleError("contact bundle is too large")
    return serialized


def export_lifecycle_contact_bundle(
    entity: GhostEntity,
    lifecycle: SignedDeviceLifecycleStatement,
) -> str:
    """Export a version-2 contact bundle with monotonic device lifecycle state."""
    serialized = export_verified_lifecycle_contact_bundle(
        entity.verify_key,
        lifecycle,
    )
    contact = import_contact_bundle(serialized)
    if contact.ghost_id != entity.ghost_id:
        raise ContactBundleError("lifecycle contact GhostID does not match entity")
    return serialized


def _import_legacy_contact(document: dict[str, object]) -> ValidatedContact:
    ghost_id = _require_text(document, "ghost_id")
    device_id = _require_text(document, "device_id")
    identity_public_key = _decode_base64(
        document["identity_public_key"],
        "identity_public_key",
        _PUBLIC_KEY_SIZE,
    )
    signing_public_key = _decode_base64(
        document["device_signing_public_key"],
        "device_signing_public_key",
        _PUBLIC_KEY_SIZE,
    )
    encryption_public_key = _decode_base64(
        document["device_encryption_public_key"],
        "device_encryption_public_key",
        _PUBLIC_KEY_SIZE,
    )
    signature = _decode_base64(
        document["device_certificate_signature"],
        "device_certificate_signature",
        _SIGNATURE_SIZE,
    )

    try:
        certificate = GhostDeviceCertificate(
            ghost_id=ghost_id,
            device_id=device_id,
            signing_public_key=signing_public_key,
            encryption_public_key=encryption_public_key,

        )
        signed_certificate = SignedGhostDeviceCertificate(
            certificate=certificate,
            signature=signature,
        )
        identity_verify_key = VerifyKey(identity_public_key)
        public_device = PublicGhostDevice.from_certificate(
            signed_certificate,
            identity_verify_key,
        )
    except ValueError as exc:
        raise ContactBundleError(str(exc)) from exc

    return ValidatedContact(
        identity_verify_key=identity_verify_key,
        device=public_device,
    )


def _import_lifecycle_contact(document: dict[str, object]) -> ValidatedContact:
    identity_public_key = _decode_base64(
        document["identity_public_key"],
        "identity_public_key",
        _PUBLIC_KEY_SIZE,
    )
    identity_verify_key = VerifyKey(identity_public_key)
    lifecycle_document = _require_mapping(
        document["device_lifecycle"],
        "device_lifecycle",
    )
    serialized_lifecycle = json.dumps(
        lifecycle_document,
        sort_keys=True,
        separators=(",", ":"),
    )

    try:
        lifecycle = import_device_lifecycle_statement(serialized_lifecycle)
        public_device = verify_device_lifecycle_statement(
            lifecycle,
            identity_verify_key,
        )
    except (DeviceLifecycleError, ValueError) as exc:
        raise ContactBundleError(str(exc)) from exc

    return ValidatedContact(
        identity_verify_key=identity_verify_key,
        device=public_device,
        lifecycle_epoch=lifecycle.statement.epoch,
        lifecycle_issued_at=lifecycle.statement.issued_at,
        lifecycle_statement=serialized_lifecycle,
    )


def import_contact_bundle(serialized: str) -> ValidatedContact:
    """Import and cryptographically verify a versioned public contact bundle."""
    version, document = _parse_document(serialized)
    if version == _LEGACY_CONTACT_VERSION:
        return _import_legacy_contact(document)
    return _import_lifecycle_contact(document)


def _encode_qr_bundle(bundle: str, prefix: str) -> str:
    encoded = base64.urlsafe_b64encode(
        bundle.encode("utf-8")
    ).decode("ascii").rstrip("=")
    return prefix + encoded


def export_contact_qr_payload(

    entity: GhostEntity,
    device: EnrolledGhostDevice,
) -> str:
    """Encode a legacy version-1 contact bundle as QR payload text."""
    return _encode_qr_bundle(
        export_contact_bundle(entity, device),
        _QR_V1_PREFIX,
    )


def export_lifecycle_contact_qr_payload(
    entity: GhostEntity,
    lifecycle: SignedDeviceLifecycleStatement,
) -> str:
    """Encode a lifecycle-aware version-2 contact bundle as QR payload text."""
    return _encode_qr_bundle(
        export_lifecycle_contact_bundle(entity, lifecycle),
        _QR_V2_PREFIX,
    )


def decode_contact_qr_payload(payload: str) -> str:
    """Decode a versioned QR payload into a canonical verified contact bundle."""
    if not isinstance(payload, str):
        raise ContactBundleError("QR payload must be text")
    if not payload.startswith(_QR_SCHEME_PREFIX):
        raise ContactBundleError("invalid GhostLink contact QR prefix")
    if payload.startswith(_QR_V1_PREFIX):
        prefix = _QR_V1_PREFIX
    elif payload.startswith(_QR_V2_PREFIX):
        prefix = _QR_V2_PREFIX
    else:
        raise ContactBundleError("unsupported GhostLink contact QR version")

    encoded = payload[len(prefix) :]
    if not encoded:
        raise ContactBundleError("QR payload is empty")
    if any(character not in _BASE64URL_ALPHABET for character in encoded):
        raise ContactBundleError("QR payload must be unpadded Base64url")
    if len(encoded) > ((_MAX_BUNDLE_BYTES * 4 + 2) // 3):
        raise ContactBundleError("QR contact bundle is too large")

    padding = "=" * (-len(encoded) % 4)
    try:
        decoded = base64.b64decode(
            encoded + padding,
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise ContactBundleError("QR payload must be valid Base64url") from exc

    if len(decoded) > _MAX_BUNDLE_BYTES:
        raise ContactBundleError("QR contact bundle is too large")
    try:
        serialized = decoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContactBundleError("QR contact bundle must be UTF-8") from exc

    try:
        parsed: object = json.loads(serialized)
    except json.JSONDecodeError as exc:
        raise ContactBundleError("QR contact bundle must be valid JSON") from exc
    canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
    if canonical != serialized:
        raise ContactBundleError("QR contact bundle must use canonical JSON")

    import_contact_bundle(serialized)
    return serialized


def import_contact_qr_payload(payload: str) -> ValidatedContact:
    """Decode and cryptographically validate a versioned public QR payload."""
    return import_contact_bundle(decode_contact_qr_payload(payload))
