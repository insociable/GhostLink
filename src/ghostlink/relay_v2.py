"""Protocol-v2 GhostNode relay routes and ciphertext storage."""

from __future__ import annotations

import base64
import binascii
import os
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Protocol, cast

from fastapi import APIRouter, Header, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from ghostlink.config import NodeSettings
from ghostlink.message_v2 import (
    MESSAGE_CLOCK_SKEW_SECONDS,
    MESSAGE_MAX_LIFETIME_SECONDS,
    MESSAGE_VERSION,
)
from ghostlink.relay_auth import require_relay_access

_MAX_CIPHERTEXT_BYTES = 1_048_576
_DEVICE_ID_PREFIX = "device1:"
_DEVICE_ID_PAYLOAD_LENGTH = 52
_BASE32_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz234567")
_MESSAGE_ID_LENGTH = 32
_HEX_ALPHABET = frozenset("0123456789abcdef")


class V2MessageConflictError(RuntimeError):
    """Raised when a message ID is reused for a different envelope."""


def _unix_time() -> int:
    return int(time.time())


def _validate_message_id_text(value: str) -> str:
    if len(value) != _MESSAGE_ID_LENGTH:
        raise ValueError("message_id must contain exactly 32 hexadecimal characters")
    if value != value.lower() or any(character not in _HEX_ALPHABET for character in value):
        raise ValueError("message_id must be lowercase hexadecimal")
    return value


def _validate_device_id_text(value: str) -> str:
    if not value.startswith(_DEVICE_ID_PREFIX):
        raise ValueError("device ID must use the device1 format")

    payload = value[len(_DEVICE_ID_PREFIX) :]
    if len(payload) != _DEVICE_ID_PAYLOAD_LENGTH:
        raise ValueError("device ID payload has an invalid length")
    if any(character not in _BASE32_ALPHABET for character in payload):
        raise ValueError("device ID payload is not valid lowercase Base32")

    return value


class V2MessageEnvelope(BaseModel):
    """Ciphertext-only protocol-v2 relay envelope."""

    model_config = ConfigDict(extra="forbid", strict=True)

    version: int
    message_id: str
    sender_device_id: str
    recipient_device_id: str
    created_at: int
    expires_at: int
    ciphertext: str

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: int) -> int:
        if value != MESSAGE_VERSION:
            raise ValueError("unsupported message version")
        return value

    @field_validator("message_id")
    @classmethod
    def validate_message_id(cls, value: str) -> str:
        return _validate_message_id_text(value)

    @field_validator("sender_device_id", "recipient_device_id")
    @classmethod
    def validate_device_id(cls, value: str) -> str:
        return _validate_device_id_text(value)

    @field_validator("ciphertext")
    @classmethod
    def validate_ciphertext(cls, value: str) -> str:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("ciphertext must be valid Base64") from exc

        if not decoded:
            raise ValueError("ciphertext must not be empty")
        if len(decoded) > _MAX_CIPHERTEXT_BYTES:
            raise ValueError("ciphertext exceeds the 1 MiB relay limit")

        return value

    @model_validator(mode="after")
    def validate_lifecycle(self) -> V2MessageEnvelope:
        if self.created_at < 0 or self.expires_at < 0:
            raise ValueError("timestamps must be non-negative")
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")
        if self.expires_at - self.created_at > MESSAGE_MAX_LIFETIME_SECONDS:
            raise ValueError("message lifetime exceeds protocol maximum")
        return self


class V2MessageStore(Protocol):
    """Storage contract for protocol-v2 relay envelopes."""

    def add(self, envelope: V2MessageEnvelope) -> V2MessageEnvelope:
        """Store one envelope idempotently."""

    def list_for_recipient(self, recipient_device_id: str) -> list[V2MessageEnvelope]:
        """Return non-expired envelopes for a recipient."""

    def delete(self, recipient_device_id: str, message_id: str) -> bool:
        """Delete one envelope."""

    def is_healthy(self) -> bool:
        """Return whether storage is available."""


def _envelope_key(envelope: V2MessageEnvelope) -> tuple[str, str]:
    return envelope.recipient_device_id, envelope.message_id


def _relay_time_valid(envelope: V2MessageEnvelope, now: int) -> bool:
    return (
        envelope.created_at <= now + MESSAGE_CLOCK_SKEW_SECONDS
        and envelope.expires_at >= now - MESSAGE_CLOCK_SKEW_SECONDS
    )


@dataclass(slots=True)
class InMemoryV2MessageStore:
    """In-memory protocol-v2 store used for tests and development."""

    _messages: dict[tuple[str, str], V2MessageEnvelope] = field(default_factory=dict)

    def add(self, envelope: V2MessageEnvelope) -> V2MessageEnvelope:
        existing = self._messages.get(_envelope_key(envelope))
        if existing is not None:
            if existing == envelope:
                return existing
            raise V2MessageConflictError("message_id already exists for recipient")

        self._messages[_envelope_key(envelope)] = envelope
        return envelope

    def list_for_recipient(self, recipient_device_id: str) -> list[V2MessageEnvelope]:
        cutoff = _unix_time() - MESSAGE_CLOCK_SKEW_SECONDS
        expired = [
            key
            for key, message in self._messages.items()
            if message.expires_at < cutoff
        ]
        for key in expired:
            self._messages.pop(key, None)

        return [
            message
            for message in self._messages.values()
            if message.recipient_device_id == recipient_device_id
        ]

    def delete(self, recipient_device_id: str, message_id: str) -> bool:
        return self._messages.pop((recipient_device_id, message_id), None) is not None

    def is_healthy(self) -> bool:
        return True


@dataclass(slots=True)
class SQLiteV2MessageStore:
    """Persistent protocol-v2 SQLite ciphertext store."""

    path: Path

    def __post_init__(self) -> None:
        if self.path.exists() and self.path.is_dir():
            raise ValueError("node.database_path must point to a file")

        self.path.parent.mkdir(parents=True, exist_ok=True)

        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS messages_v2 (
                    message_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    sender_device_id TEXT NOT NULL,
                    recipient_device_id TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    ciphertext TEXT NOT NULL,
                    PRIMARY KEY (recipient_device_id, message_id)
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_messages_v2_recipient_expiry
                ON messages_v2 (recipient_device_id, expires_at)
                """
            )

        if os.name == "posix":
            self.path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5.0)

    @staticmethod
    def _from_row(row: tuple[object, ...]) -> V2MessageEnvelope:
        return V2MessageEnvelope(
            message_id=cast(str, row[0]),
            version=cast(int, row[1]),
            sender_device_id=cast(str, row[2]),
            recipient_device_id=cast(str, row[3]),
            created_at=cast(int, row[4]),
            expires_at=cast(int, row[5]),
            ciphertext=cast(str, row[6]),
        )

    def add(self, envelope: V2MessageEnvelope) -> V2MessageEnvelope:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO messages_v2 (
                    message_id,
                    version,
                    sender_device_id,
                    recipient_device_id,
                    created_at,
                    expires_at,
                    ciphertext
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    envelope.message_id,
                    envelope.version,
                    envelope.sender_device_id,
                    envelope.recipient_device_id,
                    envelope.created_at,
                    envelope.expires_at,
                    envelope.ciphertext,
                ),
            )
            row = connection.execute(
                """
                SELECT
                    message_id,
                    version,
                    sender_device_id,
                    recipient_device_id,
                    created_at,
                    expires_at,
                    ciphertext
                FROM messages_v2
                WHERE recipient_device_id = ? AND message_id = ?
                """,
                (envelope.recipient_device_id, envelope.message_id),
            ).fetchone()

        if row is None:
            raise RuntimeError("stored protocol-v2 message could not be reloaded")

        stored = self._from_row(row)
        if stored != envelope:
            raise V2MessageConflictError("message_id already exists for recipient")
        return stored

    def list_for_recipient(self, recipient_device_id: str) -> list[V2MessageEnvelope]:
        cutoff = _unix_time() - MESSAGE_CLOCK_SKEW_SECONDS

        with self._connect() as connection:
            connection.execute(
                "DELETE FROM messages_v2 WHERE expires_at < ?",
                (cutoff,),
            )
            rows = connection.execute(
                """
                SELECT
                    message_id,
                    version,
                    sender_device_id,
                    recipient_device_id,
                    created_at,
                    expires_at,
                    ciphertext
                FROM messages_v2
                WHERE recipient_device_id = ?
                ORDER BY created_at, rowid
                """,
                (recipient_device_id,),
            ).fetchall()

        return [self._from_row(row) for row in rows]

    def delete(self, recipient_device_id: str, message_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                DELETE FROM messages_v2
                WHERE recipient_device_id = ? AND message_id = ?
                """,
                (recipient_device_id, message_id),
            )

        return cursor.rowcount > 0

    def is_healthy(self) -> bool:
        try:
            with self._connect() as connection:
                connection.execute("SELECT 1").fetchone()
        except sqlite3.Error:
            return False
        return True


def create_v2_message_store(settings: NodeSettings) -> V2MessageStore:
    if settings.database_path is None:
        return InMemoryV2MessageStore()
    return SQLiteV2MessageStore(settings.database_path)


def create_v2_router(
    settings: NodeSettings,
    store: V2MessageStore,
) -> APIRouter:
    """Create protocol-v2 relay routes."""
    router = APIRouter()

    @router.post(
        "/v2/messages",
        response_model=V2MessageEnvelope,
        status_code=status.HTTP_201_CREATED,
    )
    def submit_v2_message(
        envelope: V2MessageEnvelope,
        authorization: Annotated[str | None, Header()] = None,
    ) -> V2MessageEnvelope:
        require_relay_access(settings, authorization)

        if not _relay_time_valid(envelope, _unix_time()):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="message lifecycle is outside relay acceptance window",
            )

        try:
            return store.add(envelope)
        except V2MessageConflictError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc

    @router.get(
        "/v2/messages/{recipient_device_id}",
        response_model=list[V2MessageEnvelope],
    )
    def receive_v2_messages(
        recipient_device_id: str,
        authorization: Annotated[str | None, Header()] = None,
    ) -> list[V2MessageEnvelope]:
        require_relay_access(settings, authorization)

        try:
            _validate_device_id_text(recipient_device_id)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc

        return store.list_for_recipient(recipient_device_id)

    @router.delete(
        "/v2/messages/{recipient_device_id}/{message_id}",
        status_code=status.HTTP_204_NO_CONTENT,
    )
    def delete_v2_message(
        recipient_device_id: str,
        message_id: str,
        authorization: Annotated[str | None, Header()] = None,
    ) -> Response:
        require_relay_access(settings, authorization)

        try:
            _validate_device_id_text(recipient_device_id)
            _validate_message_id_text(message_id)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc

        if not store.delete(recipient_device_id, message_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="message not found",
            )

        return Response(status_code=status.HTTP_204_NO_CONTENT)

    return router