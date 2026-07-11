"""Minimal GhostNode relay API."""

from __future__ import annotations

import base64
import binascii
import uuid
from dataclasses import dataclass, field

from fastapi import FastAPI, HTTPException, Response, status
from pydantic import BaseModel, field_validator


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


def create_app(
    store: InMemoryMessageStore | None = None,
) -> FastAPI:
    """Create the GhostNode FastAPI application."""
    message_store = store or InMemoryMessageStore()

    app = FastAPI(
        title="GhostNode",
        version="0.1.0",
        description="Ciphertext-only relay for GhostLink.",
    )

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


app = create_app()

