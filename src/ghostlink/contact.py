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
from ghostlink.entity import GhostEntity

_CONTACT_VERSION = 1
_MAX_BUNDLE_BYTES = 16_384
_PUBLIC_KEY_SIZE = 32
_SIGNATURE_SIZE = 64
_EXPECTED_FIELDS = {
    "version",
    "ghost_id",
    "identity_public_key",
    "device_id",
    "device_signing_public_key",
    "device_encryption_public_key",
    "device_certificate_signature",
}


class ContactBundleError(ValueError):
    """Raised when a contact bundle cannot be safely imported or exported."""


@dataclass(frozen=True, slots=True)
class VerifiedContact:
    """A remote identity and device whose public certificate was verified."""

    identity_verify_key: VerifyKey
    device: PublicGhostDevice

    @property
    def ghost_id(self) -> str:
        """Return the verified remote GhostID."""
        return self.device.ghost_id

    @property
    def device_id(self) -> str:
        """Return the verified remote DeviceID."""
        return self.device.device_id


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

    return decoded


def _require_text(document: dict[str, object], field: str) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not value:
        raise ContactBundleError(f"{field} must be non-empty text")
    return value


def _parse_document(serialized: str) -> dict[str, object]:
    if len(serialized.encode("utf-8")) > _MAX_BUNDLE_BYTES:
        raise ContactBundleError("contact bundle is too large")

    try:
        parsed: object = json.loads(serialized)
    except json.JSONDecodeError as exc:
        raise ContactBundleError("contact bundle must be valid JSON") from exc

    if not isinstance(parsed, dict):
        raise ContactBundleError("contact bundle must be a JSON object")

    document: dict[str, object] = {}
    for key, value in parsed.items():
        if not isinstance(key, str):
            raise ContactBundleError("contact bundle field names must be text")
        document[key] = value

    fields = set(document)
    if fields != _EXPECTED_FIELDS:
        missing = sorted(_EXPECTED_FIELDS - fields)
        unknown = sorted(fields - _EXPECTED_FIELDS)
        details: list[str] = []
        if missing:
            details.append(f"missing fields: {', '.join(missing)}")
        if unknown:
            details.append(f"unknown fields: {', '.join(unknown)}")
        raise ContactBundleError("; ".join(details))

    version = document["version"]
    if not isinstance(version, int) or isinstance(version, bool):
        raise ContactBundleError("version must be an integer")
    if version != _CONTACT_VERSION:
        raise ContactBundleError("unsupported contact bundle version")

    return document


def export_contact_bundle(
    entity: GhostEntity,
    device: EnrolledGhostDevice,
) -> str:
    """Export a deterministic JSON bundle containing public contact data only."""
    try:
        public_device = PublicGhostDevice.from_certificate(
            device.certificate,
            entity.verify_key,
        )
    except ValueError as exc:
        raise ContactBundleError(str(exc)) from exc

    certificate = device.certificate.certificate

    document = {
        "version": _CONTACT_VERSION,
        "ghost_id": public_device.ghost_id,
        "identity_public_key": _encode_base64(bytes(entity.verify_key)),
        "device_id": public_device.device_id,
        "device_signing_public_key": _encode_base64(certificate.signing_public_key),
        "device_encryption_public_key": _encode_base64(
            certificate.encryption_public_key
        ),
        "device_certificate_signature": _encode_base64(device.certificate.signature),
    }

    return json.dumps(document, sort_keys=True, separators=(",", ":"))


def import_contact_bundle(serialized: str) -> VerifiedContact:
    """Import and cryptographically verify a public GhostLink contact bundle."""
    document = _parse_document(serialized)

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

    return VerifiedContact(
        identity_verify_key=identity_verify_key,
        device=public_device,
    )
