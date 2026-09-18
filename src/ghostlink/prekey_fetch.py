"""Authenticated requester proof and wire models for ratchet pre-key fetch."""

from __future__ import annotations

import base64
import binascii
import json
import secrets
from typing import Literal

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from pydantic import BaseModel, ConfigDict, field_validator

from ghostlink.device import EnrolledGhostDevice, derive_device_id

_FETCH_VERSION = 1
_FETCH_DOMAIN = b"ghostlink-prekey-fetch-v1\x00"
_DEVICE_ID_PREFIX = "device1:"
_DEVICE_ID_PAYLOAD_LENGTH = 52
_BASE32_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz234567")
_DEVICE_SIGNING_PUBLIC_KEY_BYTES = 32
_SIGNATURE_BYTES = 64
_REQUEST_ID_BYTES = 16
_MAX_SAFE_INTEGER = (1 << 53) - 1
_CLOCK_SKEW_SECONDS = 5 * 60
_MAX_BINDING_BYTES = 32 * 1024


class PreKeyFetchProofError(ValueError):
    """Raised when a pre-key fetch requester proof is invalid."""


def _is_device_id(value: str) -> bool:
    if not value.startswith(_DEVICE_ID_PREFIX):
        return False
    payload = value[len(_DEVICE_ID_PREFIX) :]
    return (
        len(payload) == _DEVICE_ID_PAYLOAD_LENGTH
        and all(character in _BASE32_ALPHABET for character in payload)
    )


def _decode_canonical_base64(
    value: str,
    *,
    field: str,
    exact_size: int,
) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"{field} must be valid Base64") from exc
    if len(decoded) != exact_size:
        raise ValueError(f"{field} has an invalid decoded length")
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f"{field} must use canonical Base64")
    return decoded


def _validate_request_id(value: str) -> str:
    if len(value) != _REQUEST_ID_BYTES * 2:
        raise ValueError("request_id must be 128-bit lowercase hexadecimal")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(
            "request_id must be 128-bit lowercase hexadecimal"
        ) from exc
    if decoded.hex() != value:
        raise ValueError("request_id must use lowercase hexadecimal")
    return value


def _canonical_fetch_bytes(
    *,
    target_device_id: str,
    requester_device_id: str,
    request_id: str,
    issued_at: int,
) -> bytes:
    if not _is_device_id(target_device_id):
        raise PreKeyFetchProofError("target DeviceID is not canonical")
    if not _is_device_id(requester_device_id):
        raise PreKeyFetchProofError("requester DeviceID is not canonical")
    _validate_request_id(request_id)
    if (
        not isinstance(issued_at, int)
        or isinstance(issued_at, bool)
        or issued_at < 0
        or issued_at > _MAX_SAFE_INTEGER
    ):
        raise PreKeyFetchProofError("issued_at is outside the supported range")

    document = {
        "version": _FETCH_VERSION,
        "target_device_id": target_device_id,
        "requester_device_id": requester_device_id,
        "request_id": request_id,
        "issued_at": issued_at,
    }
    return _FETCH_DOMAIN + json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class PreKeyFetchRequest(BaseModel):
    """Device-authenticated request to allocate one target pre-key binding."""

    model_config = ConfigDict(extra="forbid", strict=True)

    version: int
    requester_device_id: str
    requester_signing_public_key: str
    request_id: str
    issued_at: int
    signature: str

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: int) -> int:
        if value != _FETCH_VERSION:
            raise ValueError("unsupported pre-key fetch request version")
        return value

    @field_validator("requester_device_id")
    @classmethod
    def validate_requester_device_id(cls, value: str) -> str:
        if not _is_device_id(value):
            raise ValueError("requester_device_id must be a canonical DeviceID")
        return value

    @field_validator("requester_signing_public_key")
    @classmethod
    def validate_requester_signing_public_key(cls, value: str) -> str:
        _decode_canonical_base64(
            value,
            field="requester_signing_public_key",
            exact_size=_DEVICE_SIGNING_PUBLIC_KEY_BYTES,
        )
        return value

    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, value: str) -> str:
        return _validate_request_id(value)

    @field_validator("issued_at")
    @classmethod
    def validate_issued_at(cls, value: int) -> int:
        if value < 0 or value > _MAX_SAFE_INTEGER:
            raise ValueError("issued_at is outside the supported range")
        return value

    @field_validator("signature")
    @classmethod
    def validate_signature(cls, value: str) -> str:
        _decode_canonical_base64(
            value,
            field="signature",
            exact_size=_SIGNATURE_BYTES,
        )
        return value


class PreKeyFetchResponse(BaseModel):
    """One idempotently allocated signed target pre-key binding."""

    model_config = ConfigDict(extra="forbid", strict=True)

    version: int
    target_device_id: str
    requester_device_id: str
    publication_sequence: int
    expires_at: int
    bundle_kind: Literal["one_time", "fallback"]
    binding: str
    remaining_one_time_count: int

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: int) -> int:
        if value != _FETCH_VERSION:
            raise ValueError("unsupported pre-key fetch response version")
        return value

    @field_validator("target_device_id", "requester_device_id")
    @classmethod
    def validate_device_id(cls, value: str) -> str:
        if not _is_device_id(value):
            raise ValueError("fetch response contains a non-canonical DeviceID")
        return value

    @field_validator("publication_sequence")
    @classmethod
    def validate_publication_sequence(cls, value: int) -> int:
        if value <= 0 or value > _MAX_SAFE_INTEGER:
            raise ValueError("publication_sequence is outside the supported range")
        return value

    @field_validator("expires_at")
    @classmethod
    def validate_expires_at(cls, value: int) -> int:
        if value < 0 or value > _MAX_SAFE_INTEGER:
            raise ValueError("expires_at is outside the supported range")
        return value

    @field_validator("binding")
    @classmethod
    def validate_binding(cls, value: str) -> str:
        if not value or len(value.encode("utf-8")) > _MAX_BINDING_BYTES:
            raise ValueError("binding exceeds the size limit")
        return value

    @field_validator("remaining_one_time_count")
    @classmethod
    def validate_remaining_one_time_count(cls, value: int) -> int:
        if value < 0 or value > 256:
            raise ValueError("remaining_one_time_count is outside the supported range")
        return value


def create_prekey_fetch_request(
    requester: EnrolledGhostDevice,
    target_device_id: str,
    *,
    issued_at: int,
    request_id: str | None = None,
) -> PreKeyFetchRequest:
    """Create a target-bound fetch request signed by the requester DeviceID key."""
    certificate = requester.certificate.certificate
    if requester.device_id != certificate.device_id:
        raise PreKeyFetchProofError("enrolled requester does not match its certificate")
    signing_public_key = bytes(requester.device.signing_verify_key)
    if signing_public_key != certificate.signing_public_key:
        raise PreKeyFetchProofError(
            "requester signing key does not match its certificate"
        )

    resolved_request_id = (
        secrets.token_hex(_REQUEST_ID_BYTES)
        if request_id is None
        else _validate_request_id(request_id)
    )
    canonical = _canonical_fetch_bytes(
        target_device_id=target_device_id,
        requester_device_id=requester.device_id,
        request_id=resolved_request_id,
        issued_at=issued_at,
    )
    signature = requester.device.signing_key.sign(canonical).signature
    return PreKeyFetchRequest(
        version=_FETCH_VERSION,
        requester_device_id=requester.device_id,
        requester_signing_public_key=base64.b64encode(signing_public_key).decode(
            "ascii"
        ),
        request_id=resolved_request_id,
        issued_at=issued_at,
        signature=base64.b64encode(signature).decode("ascii"),
    )


def verify_prekey_fetch_request(
    request: PreKeyFetchRequest,
    target_device_id: str,
    *,
    now: int,
) -> str:
    """Verify requester DeviceID control and freshness for one target-bound fetch."""
    if not _is_device_id(target_device_id):
        raise PreKeyFetchProofError("target DeviceID is not canonical")
    if request.issued_at > now + _CLOCK_SKEW_SECONDS:
        raise PreKeyFetchProofError("fetch request was issued too far in the future")
    if request.issued_at < now - _CLOCK_SKEW_SECONDS:
        raise PreKeyFetchProofError("fetch request is too old")

    signing_public_key = _decode_canonical_base64(
        request.requester_signing_public_key,
        field="requester_signing_public_key",
        exact_size=_DEVICE_SIGNING_PUBLIC_KEY_BYTES,
    )
    if derive_device_id(signing_public_key) != request.requester_device_id:
        raise PreKeyFetchProofError(
            "requester DeviceID does not match requester signing public key"
        )

    canonical = _canonical_fetch_bytes(
        target_device_id=target_device_id,
        requester_device_id=request.requester_device_id,
        request_id=request.request_id,
        issued_at=request.issued_at,
    )
    signature = _decode_canonical_base64(
        request.signature,
        field="signature",
        exact_size=_SIGNATURE_BYTES,
    )
    try:
        VerifyKey(signing_public_key).verify(canonical, signature)
    except BadSignatureError as exc:
        raise PreKeyFetchProofError("requester signature is invalid") from exc

    return request.requester_device_id
