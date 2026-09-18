"""GhostLink protocol-v2 authenticated encrypted messages."""

from __future__ import annotations

import secrets
import struct
import time
from dataclasses import dataclass

from nacl.exceptions import CryptoError
from nacl.public import Box

from ghostlink.device import EnrolledGhostDevice, PublicGhostDevice

MESSAGE_VERSION = 2
MESSAGE_ID_BYTES = 16
MESSAGE_DEFAULT_TTL_SECONDS = 24 * 60 * 60
MESSAGE_MAX_LIFETIME_SECONDS = 7 * 24 * 60 * 60
MESSAGE_CLOCK_SKEW_SECONDS = 5 * 60
_MAX_UINT64 = (1 << 64) - 1


class MessageV2DecryptionError(ValueError):
    """Raised when a protocol-v2 message cannot be authenticated or validated."""


@dataclass(frozen=True, slots=True)
class GhostMessageV2:
    """Outer relay envelope for one protocol-v2 encrypted message."""

    version: int
    message_id: str
    sender_device_id: str
    recipient_device_id: str
    created_at: int
    expires_at: int
    ciphertext: bytes


def _encode_bytes(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def _encode_text(value: str) -> bytes:
    return _encode_bytes(value.encode("utf-8"))


def _read_bytes(payload: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(payload):
        raise MessageV2DecryptionError("message payload is truncated")

    length = struct.unpack(">I", payload[offset : offset + 4])[0]
    start = offset + 4
    end = start + length

    if end > len(payload):
        raise MessageV2DecryptionError("message payload is truncated")

    return payload[start:end], end


def _read_uint64(payload: bytes, offset: int) -> tuple[int, int]:
    end = offset + 8
    if end > len(payload):
        raise MessageV2DecryptionError("message payload is truncated")
    return struct.unpack(">Q", payload[offset:end])[0], end


def _decode_text(value: bytes, field: str) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MessageV2DecryptionError(
            f"encrypted {field} is not valid UTF-8"
        ) from exc


def _is_canonical_message_id(value: str) -> bool:
    return (
        len(value) == MESSAGE_ID_BYTES * 2
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


def _validate_encrypt_time(created_at: int, ttl_seconds: int) -> tuple[int, int]:
    if isinstance(created_at, bool) or not isinstance(created_at, int):
        raise ValueError("created_at must be an integer Unix timestamp")
    if created_at < 0 or created_at > _MAX_UINT64:
        raise ValueError("created_at is outside the supported timestamp range")
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int):
        raise ValueError("ttl_seconds must be an integer")
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be greater than zero")
    if ttl_seconds > MESSAGE_MAX_LIFETIME_SECONDS:
        raise ValueError("ttl_seconds exceeds the maximum message lifetime")

    expires_at = created_at + ttl_seconds
    if expires_at > _MAX_UINT64:
        raise ValueError("expires_at is outside the supported timestamp range")

    return created_at, expires_at


def _validate_decrypted_lifecycle(
    created_at: int,
    expires_at: int,
    now: int,
) -> None:
    if expires_at <= created_at:
        raise MessageV2DecryptionError("message expiration is not after creation")
    if expires_at - created_at > MESSAGE_MAX_LIFETIME_SECONDS:
        raise MessageV2DecryptionError("message lifetime exceeds protocol maximum")
    if created_at > now + MESSAGE_CLOCK_SKEW_SECONDS:
        raise MessageV2DecryptionError("message creation time is too far in the future")
    if expires_at < now - MESSAGE_CLOCK_SKEW_SECONDS:
        raise MessageV2DecryptionError("message has expired")


def encrypt_message_v2(
    sender: EnrolledGhostDevice,
    recipient: PublicGhostDevice,
    plaintext: bytes,
    *,
    ttl_seconds: int = MESSAGE_DEFAULT_TTL_SECONDS,
    created_at: int | None = None,
) -> GhostMessageV2:
    """Encrypt one protocol-v2 message with authenticated lifecycle metadata."""
    if not plaintext:
        raise ValueError("plaintext must not be empty")

    timestamp = int(time.time()) if created_at is None else created_at
    timestamp, expires_at = _validate_encrypt_time(timestamp, ttl_seconds)
    message_id = secrets.token_hex(MESSAGE_ID_BYTES)

    payload = b"".join(
        (
            struct.pack(">B", MESSAGE_VERSION),
            _encode_text(message_id),
            _encode_text(sender.device_id),
            _encode_text(recipient.device_id),
            struct.pack(">Q", timestamp),
            struct.pack(">Q", expires_at),
            _encode_bytes(plaintext),
        )
    )

    box = Box(
        sender.device.encryption_key,
        recipient.encryption_public_key,
    )

    return GhostMessageV2(
        version=MESSAGE_VERSION,
        message_id=message_id,
        sender_device_id=sender.device_id,
        recipient_device_id=recipient.device_id,
        created_at=timestamp,
        expires_at=expires_at,
        ciphertext=bytes(box.encrypt(payload)),
    )


def decrypt_message_v2(
    recipient: EnrolledGhostDevice,
    sender: PublicGhostDevice,
    message: GhostMessageV2,
    *,
    now: int | None = None,
) -> bytes:
    """Decrypt, authenticate, and validate one protocol-v2 message."""
    if message.version != MESSAGE_VERSION:
        raise MessageV2DecryptionError("unsupported message version")
    if message.sender_device_id != sender.device_id:
        raise MessageV2DecryptionError("sender device does not match message")
    if message.recipient_device_id != recipient.device_id:
        raise MessageV2DecryptionError("recipient device does not match message")

    box = Box(
        recipient.device.encryption_key,
        sender.encryption_public_key,
    )

    try:
        payload = bytes(box.decrypt(message.ciphertext))
    except CryptoError as exc:
        raise MessageV2DecryptionError(
            "message authentication or decryption failed"
        ) from exc

    if not payload or payload[0] != MESSAGE_VERSION:
        raise MessageV2DecryptionError("invalid encrypted message version")

    offset = 1
    message_id_bytes, offset = _read_bytes(payload, offset)
    sender_id_bytes, offset = _read_bytes(payload, offset)
    recipient_id_bytes, offset = _read_bytes(payload, offset)
    created_at, offset = _read_uint64(payload, offset)
    expires_at, offset = _read_uint64(payload, offset)
    plaintext, offset = _read_bytes(payload, offset)

    if offset != len(payload):
        raise MessageV2DecryptionError("unexpected trailing message data")
    if not plaintext:
        raise MessageV2DecryptionError("decrypted plaintext must not be empty")

    inner_message_id = _decode_text(message_id_bytes, "message identifier")
    inner_sender_id = _decode_text(sender_id_bytes, "sender identifier")
    inner_recipient_id = _decode_text(recipient_id_bytes, "recipient identifier")

    if not _is_canonical_message_id(inner_message_id):
        raise MessageV2DecryptionError("invalid encrypted message identifier")
    if inner_message_id != message.message_id:
        raise MessageV2DecryptionError("encrypted message identifier mismatch")
    if inner_sender_id != message.sender_device_id:
        raise MessageV2DecryptionError("encrypted sender identifier mismatch")
    if inner_recipient_id != message.recipient_device_id:
        raise MessageV2DecryptionError("encrypted recipient identifier mismatch")
    if created_at != message.created_at:
        raise MessageV2DecryptionError("encrypted creation timestamp mismatch")
    if expires_at != message.expires_at:
        raise MessageV2DecryptionError("encrypted expiration timestamp mismatch")

    current_time = int(time.time()) if now is None else now
    _validate_decrypted_lifecycle(created_at, expires_at, current_time)

    return plaintext
