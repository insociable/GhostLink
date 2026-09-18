"""Minimal GhostNode relay API."""

from __future__ import annotations

import base64
import binascii
import os
import sqlite3
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from fastapi import FastAPI, HTTPException, Response, status
from pydantic import BaseModel, field_validator

from ghostlink.config import NodeSettings, load_settings


class MessageEnvelope(BaseModel):
    """Encrypted message envelope accepted by GhostNode."""

    version: int
    sender_device_id: str
    recipient_device_id: str
    ciphertext: str

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

    app = FastAPI(
        title="GhostNode",
        version="0.1.0",
        description="Ciphertext-only relay for GhostLink.",
    )
    app.state.settings = node_settings

    @app.get("/health")
    def health() -> dict[str, str]:
        """Return node health status."""
        return {"status": "ok"}

    @app.post(
        "/v1/messages",
        response_model=StoredMessage,
        status_code=status.HTTP_201_CREATED,
    )
    def submit_message(envelope: MessageEnvelope) -> StoredMessage:
        """Store one encrypted message envelope."""
        return message_store.add(envelope)

    @app.get(
        "/v1/messages/{recipient_device_id}",
        response_model=list[StoredMessage],
    )
    def receive_messages(recipient_device_id: str) -> list[StoredMessage]:
        """Return encrypted messages addressed to one device."""
        return message_store.list_for_recipient(recipient_device_id)

    @app.delete(
        "/v1/messages/{message_id}",
        status_code=status.HTTP_204_NO_CONTENT,
    )
    def delete_message(message_id: str) -> Response:
        """Delete a delivered encrypted message."""
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
