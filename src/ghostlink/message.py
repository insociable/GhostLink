"""Encrypted GhostLink messages."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from nacl.exceptions import CryptoError
from nacl.public import Box

from ghostlink.device import EnrolledGhostDevice

_MESSAGE_VERSION = 1


class MessageDecryptionError(ValueError):
    """Raised when an encrypted GhostLink message cannot be validated."""


def _encode_bytes(value: bytes) -> bytes:
    """Encode bytes with a deterministic length prefix."""
    return struct.pack(">I", len(value)) + value


def _encode_text(value: str) -> bytes:
    """Encode text with a deterministic length prefix."""
    return _encode_bytes(value.encode("utf-8"))


def _read_bytes(payload: bytes, offset: int) -> tuple[bytes, int]:
    """Read one length-prefixed byte field."""
    if offset + 4 > len(payload):
        raise MessageDecryptionError("message payload is truncated")

    length = struct.unpack(">I", payload[offset : offset + 4])[0]
    start = offset + 4
    end = start + length

    if end > len(payload):
        raise MessageDecryptionError("message payload is truncated")

    return payload[start:end], end


@dataclass(frozen=True, slots=True)
class GhostMessage:
    """An encrypted message exchanged between two GhostLink devices."""

    version: int
    sender_device_id: str
    recipient_device_id: str
    ciphertext: bytes


def encrypt_message(
    sender: EnrolledGhostDevice,
    recipient: EnrolledGhostDevice,
    plaintext: bytes,
) -> GhostMessage:
    """Encrypt and authenticate a message for one recipient device."""
    if not plaintext:
        raise ValueError("plaintext must not be empty")

    payload = b"".join(
        (
            struct.pack(">B", _MESSAGE_VERSION),
            _encode_text(sender.device_id),
            _encode_text(recipient.device_id),
            _encode_bytes(plaintext),
        )
    )

    box = Box(
        sender.device.encryption_key,
        recipient.device.encryption_public_key,
    )

    return GhostMessage(
        version=_MESSAGE_VERSION,
        sender_device_id=sender.device_id,
        recipient_device_id=recipient.device_id,
        ciphertext=bytes(box.encrypt(payload)),
    )


def decrypt_message(
    recipient: EnrolledGhostDevice,
    sender: EnrolledGhostDevice,
    message: GhostMessage,
) -> bytes:
    """Decrypt and validate a message received from one sender device."""
    if message.version != _MESSAGE_VERSION:
        raise MessageDecryptionError("unsupported message version")

    if message.sender_device_id != sender.device_id:
        raise MessageDecryptionError("sender device does not match message")

    if message.recipient_device_id != recipient.device_id:
        raise MessageDecryptionError("recipient device does not match message")

    box = Box(
        recipient.device.encryption_key,
        sender.device.encryption_public_key,
    )

    try:
        payload = bytes(box.decrypt(message.ciphertext))
    except CryptoError as exc:
        raise MessageDecryptionError(
            "message authentication or decryption failed"
        ) from exc

    if not payload or payload[0] != _MESSAGE_VERSION:
        raise MessageDecryptionError("invalid encrypted message version")

    offset = 1

    sender_id_bytes, offset = _read_bytes(payload, offset)
    recipient_id_bytes, offset = _read_bytes(payload, offset)
    plaintext, offset = _read_bytes(payload, offset)

    if offset != len(payload):
        raise MessageDecryptionError("unexpected trailing message data")

    sender_id = sender_id_bytes.decode("utf-8")
    recipient_id = recipient_id_bytes.decode("utf-8")

    if sender_id != message.sender_device_id:
        raise MessageDecryptionError("encrypted sender identifier mismatch")

    if recipient_id != message.recipient_device_id:
        raise MessageDecryptionError("encrypted recipient identifier mismatch")

    return plaintext
