"""Minimal GhostNode relay API."""

from __future__ import annotations

import base64
import binascii
import os
import sqlite3
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Protocol

from fastapi import FastAPI, Header, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, field_validator

from ghostlink.config import NodeSettings, load_settings
from ghostlink.relay_auth import require_relay_access
from ghostlink.relay_v2 import create_v2_message_store, create_v2_router

_MESSAGE_VERSION = 1
_MAX_CIPHERTEXT_BYTES = 1_048_576
_DEVICE_ID_PREFIX = "device1:"
_DEVICE_ID_PAYLOAD_LENGTH = 52
_BASE32_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz234567")


class MessageEnvelope(BaseModel):
    """Encrypted message envelope accepted by GhostNode."""

    model_config = ConfigDict(extra="forbid")

    version: int
    sender_device_id: str
    recipient_device_id: str
    ciphertext: str

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: int) -> int:
        """Accept only the protocol version implemented by this relay."""
        if value != _MESSAGE_VERSION:
            raise ValueError("unsupported message version")
        return value

    @field_validator("sender_device_id", "recipient_device_id")
    @classmethod
    def validate_device_id(cls, value: str) -> str:
        """Require the canonical syntactic DeviceID representation."""
        if not value.startswith(_DEVICE_ID_PREFIX):
            raise ValueError("device ID must use the device1 format")

        payload = value[len(_DEVICE_ID_PREFIX) :]
        if len(payload) != _DEVICE_ID_PAYLOAD_LENGTH:
            raise ValueError("device ID payload has an invalid length")
        if any(character not in _BASE32_ALPHABET for character in payload):
            raise ValueError("device ID payload is not valid lowercase Base32")

        return value

    @field_validator("ciphertext")
    @classmethod
    def validate_ciphertext(cls, value: str) -> str:
        """Require non-empty valid Base64 ciphertext."""
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("ciphertext must be valid Base64") from exc

        if not decoded:
            raise ValueError("ciphertext must not be empty")
        if len(decoded) > _MAX_CIPHERTEXT_BYTES:
            raise ValueError("ciphertext exceeds the 1 MiB relay limit")

        return value


class StoredMessage(MessageEnvelope):
    """Encrypted envelope stored by GhostNode."""

    message_id: str


class MessageStore(Protocol):
    """Storage contract for ciphertext-only relay envelopes."""

    def add(self, envelope: MessageEnvelope) -> StoredMessage:
        """Store one encrypted envelope."""

    def list_for_recipient(self, recipient_device_id: str) -> list[StoredMessage]:
        """Return encrypted envelopes for one recipient."""

    def delete(self, message_id: str) -> bool:
        """Delete one stored message."""

    def is_healthy(self) -> bool:
        """Return whether the store is available for relay operations."""


@dataclass(slots=True)
class InMemoryMessageStore:
    """Temporary in-memory encrypted message store."""

    _messages: dict[str, StoredMessage] = field(default_factory=dict)

    def add(self, envelope: MessageEnvelope) -> StoredMessage:
        """Store one encrypted envelope."""
        stored_message = StoredMessage(
            message_id=uuid.uuid4().hex,
            **envelope.model_dump(),
        )

        self._messages[stored_message.message_id] = stored_message
        return stored_message

    def list_for_recipient(self, recipient_device_id: str) -> list[StoredMessage]:
        """Return encrypted envelopes for one recipient."""
        return [
            message
            for message in self._messages.values()
            if message.recipient_device_id == recipient_device_id
        ]

    def delete(self, message_id: str) -> bool:
        """Delete one stored message."""
        return self._messages.pop(message_id, None) is not None

    def is_healthy(self) -> bool:
        """The in-memory development store is always available."""
        return True


@dataclass(slots=True)
class SQLiteMessageStore:
    """Persistent SQLite store containing encrypted relay envelopes only."""

    path: Path

    def __post_init__(self) -> None:
        if self.path.exists() and self.path.is_dir():
            raise ValueError("node.database_path must point to a file")

        self.path.parent.mkdir(parents=True, exist_ok=True)

        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    message_id TEXT PRIMARY KEY,
                    version INTEGER NOT NULL,
                    sender_device_id TEXT NOT NULL,
                    recipient_device_id TEXT NOT NULL,
                    ciphertext TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_messages_recipient
                ON messages (recipient_device_id)
                """
            )

        if os.name == "posix":
            self.path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5.0)

    def add(self, envelope: MessageEnvelope) -> StoredMessage:
        """Persist one encrypted envelope."""
        stored_message = StoredMessage(
            message_id=uuid.uuid4().hex,
            **envelope.model_dump(),
        )

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO messages (
                    message_id,
                    version,
                    sender_device_id,
                    recipient_device_id,
                    ciphertext
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    stored_message.message_id,
                    stored_message.version,
                    stored_message.sender_device_id,
                    stored_message.recipient_device_id,
                    stored_message.ciphertext,
                ),
            )

        return stored_message

    def list_for_recipient(self, recipient_device_id: str) -> list[StoredMessage]:
        """Load encrypted envelopes for one recipient."""
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    message_id,
                    version,
                    sender_device_id,
                    recipient_device_id,
                    ciphertext
                FROM messages
                WHERE recipient_device_id = ?
                ORDER BY rowid
                """,
                (recipient_device_id,),
            ).fetchall()

        return [
            StoredMessage(
                message_id=str(row[0]),
                version=int(row[1]),
                sender_device_id=str(row[2]),
                recipient_device_id=str(row[3]),
                ciphertext=str(row[4]),
            )
            for row in rows
        ]

    def delete(self, message_id: str) -> bool:
        """Delete one persisted encrypted envelope."""
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM messages WHERE message_id = ?",
                (message_id,),
            )

        return cursor.rowcount > 0

    def is_healthy(self) -> bool:
        """Return whether SQLite can be opened and queried."""
        try:
            with self._connect() as connection:
                connection.execute("SELECT 1").fetchone()
        except sqlite3.Error:
            return False

        return True


def create_message_store(settings: NodeSettings) -> MessageStore:
    """Create the configured GhostNode message store."""
    if settings.database_path is None:
        return InMemoryMessageStore()

    return SQLiteMessageStore(settings.database_path)


def create_app(
    store: MessageStore | None = None,
    settings: NodeSettings | None = None,
) -> FastAPI:
    """Create the GhostNode FastAPI application."""
    node_settings = settings or NodeSettings()
    message_store = (
        store
        if store is not None
        else create_message_store(node_settings)
    )
    v2_message_store = create_v2_message_store(node_settings)

    app = FastAPI(
        title="GhostNode",
        version="0.1.0",
        description="Ciphertext-only relay for GhostLink.",
    )
    app.state.settings = node_settings
    app.include_router(create_v2_router(node_settings, v2_message_store))

    @app.get("/health")
    def health() -> dict[str, str]:
        """Return node health status, including relay storage availability."""
        if not message_store.is_healthy() or not v2_message_store.is_healthy():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="storage unavailable",
            )

        return {"status": "ok"}

    @app.post(
        "/v1/messages",
        response_model=StoredMessage,
        status_code=status.HTTP_201_CREATED,
    )
    def submit_message(
        envelope: MessageEnvelope,
        authorization: Annotated[str | None, Header()] = None,
    ) -> StoredMessage:
        """Store one encrypted message envelope."""
        require_relay_access(node_settings, authorization)
        return message_store.add(envelope)

    @app.get(
        "/v1/messages/{recipient_device_id}",
        response_model=list[StoredMessage],
    )
    def receive_messages(
        recipient_device_id: str,
        authorization: Annotated[str | None, Header()] = None,
    ) -> list[StoredMessage]:
        """Return encrypted messages addressed to one device."""
        require_relay_access(node_settings, authorization)
        return message_store.list_for_recipient(recipient_device_id)

    @app.delete(
        "/v1/messages/{message_id}",
        status_code=status.HTTP_204_NO_CONTENT,
    )
    def delete_message(
        message_id: str,
        authorization: Annotated[str | None, Header()] = None,
    ) -> Response:
        """Delete a delivered encrypted message."""
        require_relay_access(node_settings, authorization)
        if not message_store.delete(message_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="message not found",
            )

        return Response(status_code=status.HTTP_204_NO_CONTENT)

    return app


def main() -> None:
    """Run GhostNode using settings from ghostlink.toml."""
    import uvicorn

    settings = load_settings()
    application = create_app(settings=settings)
    uvicorn.run(
        application,
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
    )


app = create_app(settings=load_settings())


if __name__ == "__main__":
    main()