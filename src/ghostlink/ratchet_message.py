"""GhostLink ratcheted message protocol v3.

Protocol v3 keeps relay-visible routing/lifecycle metadata outside libsignal while
binding the exact canonical metadata inside the encrypted plaintext prefix. The
ratchet engine verifies that prefix inside the same durable transaction as
libsignal decryption so relay metadata tampering rolls the ratchet state back.
"""

from __future__ import annotations

import secrets
import struct
import time
from dataclasses import dataclass

from ghostlink.contact import VerifiedContact
from ghostlink.message import (
    MESSAGE_CLOCK_SKEW_SECONDS,
    MESSAGE_DEFAULT_TTL_SECONDS,
    MESSAGE_ID_BYTES,
    MESSAGE_MAX_LIFETIME_SECONDS,
)
from ghostlink.ratchet_engine import RatchetCiphertext, RatchetEngineClient
from ghostlink.replay import SQLiteReplayCache

RATCHET_MESSAGE_VERSION = 3
RATCHET_MESSAGE_MAX_CIPHERTEXT_BYTES = 1024 * 1024
RATCHET_MESSAGE_MAX_PLAINTEXT_BYTES = 512 * 1024

_CONTEXT_DOMAIN = b"ghostlink-ratchet-message-v3\x00"
_DEVICE_ID_PREFIX = "device1:"
_DEVICE_ID_PAYLOAD_LENGTH = 52
_BASE32_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz234567")
_HEX_ALPHABET = frozenset("0123456789abcdef")
_MAX_UINT64 = (1 << 64) - 1
_MAX_CIPHERTEXT_TYPE = 255


class RatchetMessageError(ValueError):
    """Base class for ratcheted message validation failures."""


class RatchetMessageReplayError(RatchetMessageError):
    """Raised when a cryptographically authenticated message ID was seen before."""


@dataclass(frozen=True, slots=True)
class RatchetMessage:
    """Outer ciphertext-only relay envelope for GhostLink message protocol v3."""

    version: int
    message_id: str
    sender_device_id: str
    recipient_device_id: str
    created_at: int
    expires_at: int
    ciphertext_type: int
    ciphertext: bytes

    def __post_init__(self) -> None:
        _validate_version(self.version)
        _validate_message_id(self.message_id)
        _validate_device_id(self.sender_device_id, "sender_device_id")
        _validate_device_id(self.recipient_device_id, "recipient_device_id")
        _validate_lifecycle(self.created_at, self.expires_at)
        _validate_ciphertext_type(self.ciphertext_type)
        if not isinstance(self.ciphertext, bytes) or not self.ciphertext:
            raise RatchetMessageError("ciphertext must be non-empty bytes")
        if len(self.ciphertext) > RATCHET_MESSAGE_MAX_CIPHERTEXT_BYTES:
            raise RatchetMessageError("ciphertext exceeds the 1 MiB relay limit")


def _validate_version(value: int) -> None:
    if value != RATCHET_MESSAGE_VERSION:
        raise RatchetMessageError("unsupported ratcheted message version")


def _validate_message_id(value: str) -> None:
    if (
        len(value) != MESSAGE_ID_BYTES * 2
        or value != value.lower()
        or any(character not in _HEX_ALPHABET for character in value)
    ):
        raise RatchetMessageError(
            "message_id must be 128-bit lowercase hexadecimal"
        )


def _validate_device_id(value: str, field: str) -> None:
    if not isinstance(value, str) or not value.startswith(_DEVICE_ID_PREFIX):
        raise RatchetMessageError(f"{field} must use the device1 format")
    payload = value[len(_DEVICE_ID_PREFIX) :]
    if (
        len(payload) != _DEVICE_ID_PAYLOAD_LENGTH
        or any(character not in _BASE32_ALPHABET for character in payload)
    ):
        raise RatchetMessageError(f"{field} is not a canonical DeviceID")


def _validate_lifecycle(created_at: int, expires_at: int) -> None:
    for field, value in (("created_at", created_at), ("expires_at", expires_at)):
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 0
            or value > _MAX_UINT64
        ):
            raise RatchetMessageError(
                f"{field} is outside the supported timestamp range"
            )
    if expires_at <= created_at:
        raise RatchetMessageError("expires_at must be after created_at")
    if expires_at - created_at > MESSAGE_MAX_LIFETIME_SECONDS:
        raise RatchetMessageError("message lifetime exceeds protocol maximum")


def _validate_ciphertext_type(value: int) -> None:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > _MAX_CIPHERTEXT_TYPE
    ):
        raise RatchetMessageError(
            "ciphertext_type is outside the supported integer range"
        )


def _encode_text(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return struct.pack(">H", len(encoded)) + encoded


def canonical_ratchet_context(
    *,
    message_id: str,
    sender_device_id: str,
    recipient_device_id: str,
    created_at: int,
    expires_at: int,
    ciphertext_type: int,
) -> bytes:
    """Return the exact context prefix authenticated inside libsignal plaintext."""
    _validate_message_id(message_id)
    _validate_device_id(sender_device_id, "sender_device_id")
    _validate_device_id(recipient_device_id, "recipient_device_id")
    _validate_lifecycle(created_at, expires_at)
    _validate_ciphertext_type(ciphertext_type)

    return b"".join(
        (
            _CONTEXT_DOMAIN,
            struct.pack(">B", RATCHET_MESSAGE_VERSION),
            _encode_text(message_id),
            _encode_text(sender_device_id),
            _encode_text(recipient_device_id),
            struct.pack(">Q", created_at),
            struct.pack(">Q", expires_at),
            struct.pack(">B", ciphertext_type),
        )
    )


def _validate_receive_time(
    message: RatchetMessage,
    *,
    now: int,
) -> None:
    if (
        not isinstance(now, int)
        or isinstance(now, bool)
        or now < 0
        or now > _MAX_UINT64
    ):
        raise ValueError("now must be a non-negative Unix timestamp")
    if message.created_at > now + MESSAGE_CLOCK_SKEW_SECONDS:
        raise RatchetMessageError("message creation time is too far in the future")
    if message.expires_at < now - MESSAGE_CLOCK_SKEW_SECONDS:
        raise RatchetMessageError("message has expired")


def encrypt_ratchet_message(
    engine: RatchetEngineClient,
    contact: VerifiedContact,
    plaintext: bytes,
    *,
    ttl_seconds: int = MESSAGE_DEFAULT_TTL_SECONDS,
    created_at: int | None = None,
) -> RatchetMessage:
    """Encrypt one application payload using an existing libsignal session."""
    if not isinstance(plaintext, bytes) or not plaintext:
        raise ValueError("plaintext must be non-empty bytes")
    if len(plaintext) > RATCHET_MESSAGE_MAX_PLAINTEXT_BYTES:
        raise ValueError("plaintext exceeds the ratcheted message size limit")
    if (
        not isinstance(ttl_seconds, int)
        or isinstance(ttl_seconds, bool)
        or ttl_seconds <= 0
        or ttl_seconds > MESSAGE_MAX_LIFETIME_SECONDS
    ):
        raise ValueError("ttl_seconds is outside the supported lifetime range")

    timestamp = int(time.time()) if created_at is None else created_at
    expires_at = timestamp + ttl_seconds
    _validate_lifecycle(timestamp, expires_at)

    message_id = secrets.token_hex(MESSAGE_ID_BYTES)

    # libsignal chooses the ciphertext type (PreKey or Whisper). The type is part
    # of the authenticated context, so encrypt once with a provisional context,
    # then require the resulting type to match the final context. Existing
    # sessions normally yield Whisper; a freshly established sender session
    # yields PreKey. We authenticate the selected type by prefixing it in a
    # second encryption transaction only when necessary.
    base_context = canonical_ratchet_context(
        message_id=message_id,
        sender_device_id=engine.local_device_id,
        recipient_device_id=contact.device_id,
        created_at=timestamp,
        expires_at=expires_at,
        ciphertext_type=0,
    )
    provisional = engine.encrypt(contact, base_context + plaintext)

    context = canonical_ratchet_context(
        message_id=message_id,
        sender_device_id=engine.local_device_id,
        recipient_device_id=contact.device_id,
        created_at=timestamp,
        expires_at=expires_at,
        ciphertext_type=provisional.message_type,
    )

    if provisional.message_type == 0:
        ciphertext = provisional
    else:
        ciphertext = engine.encrypt(contact, context + plaintext)

    return RatchetMessage(
        version=RATCHET_MESSAGE_VERSION,
        message_id=message_id,
        sender_device_id=engine.local_device_id,
        recipient_device_id=contact.device_id,
        created_at=timestamp,
        expires_at=expires_at,
        ciphertext_type=ciphertext.message_type,
        ciphertext=ciphertext.ciphertext,
    )


def decrypt_ratchet_message(
    engine: RatchetEngineClient,
    contact: VerifiedContact,
    message: RatchetMessage,
    replay_cache: SQLiteReplayCache,
    *,
    now: int | None = None,
) -> bytes:
    """Decrypt, authenticate context, enforce replay protection, then expose plaintext."""
    if message.sender_device_id != contact.device_id:
        raise RatchetMessageError("sender device does not match verified contact")
    if message.recipient_device_id != engine.local_device_id:
        raise RatchetMessageError("recipient device does not match local ratchet engine")

    current_time = int(time.time()) if now is None else now
    _validate_receive_time(message, now=current_time)

    context = canonical_ratchet_context(
        message_id=message.message_id,
        sender_device_id=message.sender_device_id,
        recipient_device_id=message.recipient_device_id,
        created_at=message.created_at,
        expires_at=message.expires_at,
        ciphertext_type=message.ciphertext_type,
    )

    plaintext = engine.decrypt_context_bound(
        contact,
        RatchetCiphertext(
            message_type=message.ciphertext_type,
            ciphertext=message.ciphertext,
        ),
        context,
    )
    if not plaintext:
        raise RatchetMessageError("decrypted plaintext must not be empty")

    if not replay_cache.accept(
        contact.device_id,
        message.message_id,
        now=current_time,
    ):
        raise RatchetMessageReplayError("ratcheted message replay detected")

    return plaintext
