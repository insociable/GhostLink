"""Protocol-v3 GhostNode relay routes for opaque libsignal ciphertext envelopes."""

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
from ghostlink.message_lifecycle import (
    MESSAGE_CLOCK_SKEW_SECONDS,
    MESSAGE_MAX_LIFETIME_SECONDS,
)
from ghostlink.ratchet_message import (
    RATCHET_MESSAGE_MAX_CIPHERTEXT_BYTES,
    RATCHET_MESSAGE_VERSION,
)
from ghostlink.relay_auth import require_relay_access
from ghostlink.relay_request_auth import (
    AUTH_DEVICE_ID_HEADER,
    AUTH_ISSUED_AT_HEADER,
    AUTH_REQUEST_ID_HEADER,
    AUTH_SIGNATURE_HEADER,
    AUTH_SIGNING_KEY_HEADER,
    RelayRequestProofError,
    RelayRequestReplayStore,
    authenticate_relay_request,
    create_relay_request_replay_store,
)
from ghostlink.relay_state import RelayStateCoordinator

_DEVICE_ID_PREFIX = "device1:"
_DEVICE_ID_PAYLOAD_LENGTH = 52
_BASE32_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz234567")
_MESSAGE_ID_LENGTH = 32
_HEX_ALPHABET = frozenset("0123456789abcdef")
_MAX_CIPHERTEXT_TYPE = 255


class V3MessageConflictError(RuntimeError):
    """Raised when a v3 message ID is reused for a different envelope."""


def _unix_time() -> int:
    return int(time.time())


def _validate_message_id_text(value: str) -> str:
    if len(value) != _MESSAGE_ID_LENGTH:
        raise ValueError("message_id must contain exactly 32 hexadecimal characters")
    if value != value.lower() or any(
        character not in _HEX_ALPHABET for character in value
    ):
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


class V3MessageEnvelope(BaseModel):
    """Ciphertext-only protocol-v3 ratcheted relay envelope."""

    model_config = ConfigDict(extra="forbid", strict=True)

    version: int
    message_id: str
    sender_device_id: str
    recipient_device_id: str
    created_at: int
    expires_at: int
    ciphertext_type: int
    ciphertext: str

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: int) -> int:
        if value != RATCHET_MESSAGE_VERSION:
            raise ValueError("unsupported ratcheted message version")
        return value

    @field_validator("message_id")
    @classmethod
    def validate_message_id(cls, value: str) -> str:
        return _validate_message_id_text(value)

    @field_validator("sender_device_id", "recipient_device_id")
    @classmethod
    def validate_device_id(cls, value: str) -> str:
        return _validate_device_id_text(value)

    @field_validator("ciphertext_type")
    @classmethod
    def validate_ciphertext_type(cls, value: int) -> int:
        if value < 0 or value > _MAX_CIPHERTEXT_TYPE:
            raise ValueError("ciphertext_type is outside the supported range")
        return value

    @field_validator("ciphertext")
    @classmethod
    def validate_ciphertext(cls, value: str) -> str:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("ciphertext must be valid Base64") from exc
        if not decoded:
            raise ValueError("ciphertext must not be empty")
        if len(decoded) > RATCHET_MESSAGE_MAX_CIPHERTEXT_BYTES:
            raise ValueError("ciphertext exceeds the 1 MiB relay limit")
        if base64.b64encode(decoded).decode("ascii") != value:
            raise ValueError("ciphertext must use canonical Base64")
        return value

    @model_validator(mode="after")
    def validate_lifecycle(self) -> V3MessageEnvelope:
        if self.created_at < 0 or self.expires_at < 0:
            raise ValueError("timestamps must be non-negative")
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")
        if self.expires_at - self.created_at > MESSAGE_MAX_LIFETIME_SECONDS:
            raise ValueError("message lifetime exceeds protocol maximum")
        return self


class V3MessageStore(Protocol):
    """Storage contract for ratcheted protocol-v3 envelopes."""

    def add(self, envelope: V3MessageEnvelope) -> V3MessageEnvelope:
        """Store one envelope idempotently."""

    def list_for_recipient(self, recipient_device_id: str) -> list[V3MessageEnvelope]:
        """Return non-expired envelopes for one recipient."""

    def delete(self, recipient_device_id: str, message_id: str) -> bool:
        """Delete one envelope."""

    def is_healthy(self) -> bool:
        """Return whether storage is available."""


def _envelope_key(envelope: V3MessageEnvelope) -> tuple[str, str]:
    return envelope.recipient_device_id, envelope.message_id


def _relay_time_valid(envelope: V3MessageEnvelope, now: int) -> bool:
    return (
        envelope.created_at <= now + MESSAGE_CLOCK_SKEW_SECONDS
        and envelope.expires_at >= now - MESSAGE_CLOCK_SKEW_SECONDS
    )


@dataclass(slots=True)
class InMemoryV3MessageStore:
    """In-memory ratcheted message store for tests/development."""

    _messages: dict[tuple[str, str], V3MessageEnvelope] = field(
        default_factory=dict
    )

    def add(self, envelope: V3MessageEnvelope) -> V3MessageEnvelope:
        existing = self._messages.get(_envelope_key(envelope))
        if existing is not None:
            if existing == envelope:
                return existing
            raise V3MessageConflictError(
                "message_id already exists for recipient"
            )
        self._messages[_envelope_key(envelope)] = envelope
        return envelope

    def list_for_recipient(
        self,
        recipient_device_id: str,
    ) -> list[V3MessageEnvelope]:
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
        return (
            self._messages.pop((recipient_device_id, message_id), None)
            is not None
        )

    def is_healthy(self) -> bool:
        return True


@dataclass(slots=True)
class SQLiteV3MessageStore:
    """Persistent SQLite store isolated from legacy static-v2 envelopes."""

    path: Path
    coordinator: RelayStateCoordinator | None = None

    def __post_init__(self) -> None:
        if (
            self.coordinator is not None
            and self.coordinator.path.resolve() != self.path.resolve()
        ):
            raise ValueError("relay state coordinator path does not match message store")
        if self.path.exists() and self.path.is_dir():
            raise ValueError("node.database_path must point to a file")
        self.path.parent.mkdir(parents=True, exist_ok=True)

        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS messages_v3 (
                    message_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    sender_device_id TEXT NOT NULL,
                    recipient_device_id TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    ciphertext_type INTEGER NOT NULL,
                    ciphertext TEXT NOT NULL,
                    PRIMARY KEY (recipient_device_id, message_id)
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_messages_v3_recipient_expiry
                ON messages_v3 (recipient_device_id, expires_at)
                """
            )

        if os.name == "posix":
            self.path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5.0)

    @staticmethod
    def _from_row(row: tuple[object, ...]) -> V3MessageEnvelope:
        return V3MessageEnvelope(
            message_id=cast(str, row[0]),
            version=cast(int, row[1]),
            sender_device_id=cast(str, row[2]),
            recipient_device_id=cast(str, row[3]),
            created_at=cast(int, row[4]),
            expires_at=cast(int, row[5]),
            ciphertext_type=cast(int, row[6]),
            ciphertext=cast(str, row[7]),
        )

    def _add(
        self,
        connection: sqlite3.Connection,
        envelope: V3MessageEnvelope,
    ) -> V3MessageEnvelope:
        connection.execute(
            """
            INSERT OR IGNORE INTO messages_v3 (
                message_id,
                version,
                sender_device_id,
                recipient_device_id,
                created_at,
                expires_at,
                ciphertext_type,
                ciphertext
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                envelope.message_id,
                envelope.version,
                envelope.sender_device_id,
                envelope.recipient_device_id,
                envelope.created_at,
                envelope.expires_at,
                envelope.ciphertext_type,
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
                ciphertext_type,
                ciphertext
            FROM messages_v3
            WHERE recipient_device_id = ? AND message_id = ?
            """,
            (envelope.recipient_device_id, envelope.message_id),
        ).fetchone()

        if row is None:
            raise RuntimeError("stored protocol-v3 message could not be reloaded")
        stored = self._from_row(row)
        if stored != envelope:
            raise V3MessageConflictError(
                "message_id already exists for recipient"
            )
        return stored

    def add(self, envelope: V3MessageEnvelope) -> V3MessageEnvelope:
        if self.coordinator is not None:
            return self.coordinator.mutate(
                lambda connection: self._add(connection, envelope)
            )
        with self._connect() as connection:
            return self._add(connection, envelope)

    def _list_for_recipient(
        self,
        connection: sqlite3.Connection,
        recipient_device_id: str,
        cutoff: int,
    ) -> list[V3MessageEnvelope]:
        connection.execute(
            "DELETE FROM messages_v3 WHERE expires_at < ?",
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
                ciphertext_type,
                ciphertext
            FROM messages_v3
            WHERE recipient_device_id = ?
            ORDER BY created_at, rowid
            """,
            (recipient_device_id,),
        ).fetchall()
        return [self._from_row(tuple(row)) for row in rows]

    def list_for_recipient(
        self,
        recipient_device_id: str,
    ) -> list[V3MessageEnvelope]:
        cutoff = _unix_time() - MESSAGE_CLOCK_SKEW_SECONDS
        if self.coordinator is not None:
            return self.coordinator.mutate(
                lambda connection: self._list_for_recipient(
                    connection,
                    recipient_device_id,
                    cutoff,
                )
            )
        with self._connect() as connection:
            return self._list_for_recipient(
                connection,
                recipient_device_id,
                cutoff,
            )

    def _delete(
        self,
        connection: sqlite3.Connection,
        recipient_device_id: str,
        message_id: str,
    ) -> bool:
        cursor = connection.execute(
            """
            DELETE FROM messages_v3
            WHERE recipient_device_id = ? AND message_id = ?
            """,
            (recipient_device_id, message_id),
        )
        return cursor.rowcount > 0

    def delete(self, recipient_device_id: str, message_id: str) -> bool:
        if self.coordinator is not None:
            return self.coordinator.mutate(
                lambda connection: self._delete(
                    connection,
                    recipient_device_id,
                    message_id,
                )
            )
        with self._connect() as connection:
            return self._delete(connection, recipient_device_id, message_id)

    def is_healthy(self) -> bool:
        if self.coordinator is not None and not self.coordinator.is_healthy():
            return False
        try:
            with self._connect() as connection:
                connection.execute("SELECT 1").fetchone()
        except sqlite3.Error:
            return False
        return True


def create_v3_message_store(settings: NodeSettings) -> V3MessageStore:
    if settings.database_path is None:
        return InMemoryV3MessageStore()
    return SQLiteV3MessageStore(settings.database_path)


def _require_v3_device_auth(
    *,
    replay_store: RelayRequestReplayStore,
    expected_device_id: str,
    method: str,
    path: str,
    payload: dict[str, object] | None,
    device_id: str | None,
    signing_public_key: str | None,
    request_id: str | None,
    issued_at: str | None,
    signature: str | None,
) -> None:
    try:
        authenticate_relay_request(
            expected_device_id=expected_device_id,
            method=method,
            path=path,
            payload=payload,
            device_id=device_id,
            signing_public_key=signing_public_key,
            request_id=request_id,
            issued_at=issued_at,
            signature=signature,
            now=_unix_time(),
            replay_store=replay_store,
        )
    except RelayRequestProofError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="unauthorized",
        ) from exc


def create_v3_router(
    settings: NodeSettings,
    store: V3MessageStore,
    request_replay_store: RelayRequestReplayStore | None = None,
) -> APIRouter:
    """Create explicitly ratcheted protocol-v3 relay routes."""
    router = APIRouter()
    replay_store = request_replay_store or create_relay_request_replay_store(
        settings
    )

    @router.post(
        "/v3/messages",
        response_model=V3MessageEnvelope,
        status_code=status.HTTP_201_CREATED,
    )
    def submit_v3_message(
        envelope: V3MessageEnvelope,
        authorization: Annotated[str | None, Header()] = None,
        auth_device_id: Annotated[
            str | None, Header(alias=AUTH_DEVICE_ID_HEADER)
        ] = None,
        auth_signing_key: Annotated[
            str | None, Header(alias=AUTH_SIGNING_KEY_HEADER)
        ] = None,
        auth_request_id: Annotated[
            str | None, Header(alias=AUTH_REQUEST_ID_HEADER)
        ] = None,
        auth_issued_at: Annotated[
            str | None, Header(alias=AUTH_ISSUED_AT_HEADER)
        ] = None,
        auth_signature: Annotated[
            str | None, Header(alias=AUTH_SIGNATURE_HEADER)
        ] = None,
    ) -> V3MessageEnvelope:
        require_relay_access(settings, authorization)
        _require_v3_device_auth(
            replay_store=replay_store,
            expected_device_id=envelope.sender_device_id,
            method="POST",
            path="/v3/messages",
            payload=envelope.model_dump(),
            device_id=auth_device_id,
            signing_public_key=auth_signing_key,
            request_id=auth_request_id,
            issued_at=auth_issued_at,
            signature=auth_signature,
        )
        if not _relay_time_valid(envelope, _unix_time()):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="message lifecycle is outside relay acceptance window",
            )
        try:
            return store.add(envelope)
        except V3MessageConflictError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc

    @router.get(
        "/v3/messages/{recipient_device_id}",
        response_model=list[V3MessageEnvelope],
    )
    def receive_v3_messages(
        recipient_device_id: str,
        authorization: Annotated[str | None, Header()] = None,
        auth_device_id: Annotated[
            str | None, Header(alias=AUTH_DEVICE_ID_HEADER)
        ] = None,
        auth_signing_key: Annotated[
            str | None, Header(alias=AUTH_SIGNING_KEY_HEADER)
        ] = None,
        auth_request_id: Annotated[
            str | None, Header(alias=AUTH_REQUEST_ID_HEADER)
        ] = None,
        auth_issued_at: Annotated[
            str | None, Header(alias=AUTH_ISSUED_AT_HEADER)
        ] = None,
        auth_signature: Annotated[
            str | None, Header(alias=AUTH_SIGNATURE_HEADER)
        ] = None,
    ) -> list[V3MessageEnvelope]:
        require_relay_access(settings, authorization)
        try:
            _validate_device_id_text(recipient_device_id)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc
        path = f"/v3/messages/{recipient_device_id}"
        _require_v3_device_auth(
            replay_store=replay_store,
            expected_device_id=recipient_device_id,
            method="GET",
            path=path,
            payload=None,
            device_id=auth_device_id,
            signing_public_key=auth_signing_key,
            request_id=auth_request_id,
            issued_at=auth_issued_at,
            signature=auth_signature,
        )
        return store.list_for_recipient(recipient_device_id)

    @router.delete(
        "/v3/messages/{recipient_device_id}/{message_id}",
        status_code=status.HTTP_204_NO_CONTENT,
    )
    def delete_v3_message(
        recipient_device_id: str,
        message_id: str,
        authorization: Annotated[str | None, Header()] = None,
        auth_device_id: Annotated[
            str | None, Header(alias=AUTH_DEVICE_ID_HEADER)
        ] = None,
        auth_signing_key: Annotated[
            str | None, Header(alias=AUTH_SIGNING_KEY_HEADER)
        ] = None,
        auth_request_id: Annotated[
            str | None, Header(alias=AUTH_REQUEST_ID_HEADER)
        ] = None,
        auth_issued_at: Annotated[
            str | None, Header(alias=AUTH_ISSUED_AT_HEADER)
        ] = None,
        auth_signature: Annotated[
            str | None, Header(alias=AUTH_SIGNATURE_HEADER)
        ] = None,
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

        path = f"/v3/messages/{recipient_device_id}/{message_id}"
        _require_v3_device_auth(
            replay_store=replay_store,
            expected_device_id=recipient_device_id,
            method="DELETE",
            path=path,
            payload=None,
            device_id=auth_device_id,
            signing_public_key=auth_signing_key,
            request_id=auth_request_id,
            issued_at=auth_issued_at,
            signature=auth_signature,
        )
        if not store.delete(recipient_device_id, message_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="message not found",
            )
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    return router
