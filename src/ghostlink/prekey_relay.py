"""Authenticated GhostNode storage for signed ratchet pre-key publications."""

from __future__ import annotations

import base64
import binascii
import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Protocol

from fastapi import APIRouter, Header, HTTPException, status
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from pydantic import BaseModel, ConfigDict, field_validator

from ghostlink.config import NodeSettings
from ghostlink.device import derive_device_id
from ghostlink.ratchet_binding import (
    RatchetBindingError,
    export_ratchet_prekey_binding,
)
from ghostlink.ratchet_publication import (
    export_ratchet_prekey_publication,
    import_ratchet_prekey_publication,
)
from ghostlink.relay_auth import require_relay_access

_PUBLICATION_REQUEST_VERSION = 1
_DEVICE_SIGNING_PUBLIC_KEY_BYTES = 32
_MAX_PUBLICATION_BYTES = 1024 * 1024


class PreKeyPublicationConflictError(RuntimeError):
    """Raised when a publication violates monotonic replacement semantics."""


class PreKeyPublicationRequest(BaseModel):
    """Exact public material submitted by one self-certifying GhostLink device."""

    model_config = ConfigDict(extra="forbid", strict=True)

    version: int
    device_signing_public_key: str
    publication: str

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: int) -> int:
        if value != _PUBLICATION_REQUEST_VERSION:
            raise ValueError("unsupported pre-key publication request version")
        return value

    @field_validator("device_signing_public_key")
    @classmethod
    def validate_device_signing_public_key(cls, value: str) -> str:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError(
                "device_signing_public_key must be valid Base64"
            ) from exc
        if len(decoded) != _DEVICE_SIGNING_PUBLIC_KEY_BYTES:
            raise ValueError(
                "device_signing_public_key must decode to exactly 32 bytes"
            )
        if base64.b64encode(decoded).decode("ascii") != value:
            raise ValueError(
                "device_signing_public_key must use canonical Base64"
            )
        return value

    @field_validator("publication")
    @classmethod
    def validate_publication_size(cls, value: str) -> str:
        if not value or len(value.encode("utf-8")) > _MAX_PUBLICATION_BYTES:
            raise ValueError("publication exceeds the size limit")
        return value


class PreKeyPublicationReceipt(BaseModel):
    """Relay acknowledgement for one active pre-key generation."""

    model_config = ConfigDict(extra="forbid", strict=True)

    version: int
    device_id: str
    publication_sequence: int
    expires_at: int
    one_time_count: int


@dataclass(frozen=True, slots=True)
class RelayPreKeyGeneration:
    """Canonical public generation stored by GhostNode."""

    device_id: str
    publication_sequence: int
    expires_at: int
    publication_payload: str
    one_time_bindings: tuple[str, ...]
    fallback_binding: str

    def receipt(self) -> PreKeyPublicationReceipt:
        return PreKeyPublicationReceipt(
            version=_PUBLICATION_REQUEST_VERSION,
            device_id=self.device_id,
            publication_sequence=self.publication_sequence,
            expires_at=self.expires_at,
            one_time_count=len(self.one_time_bindings),
        )


class PreKeyPublicationStore(Protocol):
    """Atomic persistence contract for active public pre-key generations."""

    def publish(self, generation: RelayPreKeyGeneration) -> RelayPreKeyGeneration:
        """Publish the initial or exactly next generation atomically."""

    def is_healthy(self) -> bool:
        """Return whether publication storage is available."""


@dataclass(slots=True)
class InMemoryPreKeyPublicationStore:
    """Locked in-memory publication store for tests/development."""

    _generations: dict[str, RelayPreKeyGeneration] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def publish(self, generation: RelayPreKeyGeneration) -> RelayPreKeyGeneration:
        with self._lock:
            existing = self._generations.get(generation.device_id)
            if existing is None:
                if generation.publication_sequence != 1:
                    raise PreKeyPublicationConflictError(
                        "initial publication_sequence must equal 1"
                    )
                self._generations[generation.device_id] = generation
                return generation

            if generation.publication_sequence < existing.publication_sequence:
                raise PreKeyPublicationConflictError(
                    "publication_sequence is older than the active generation"
                )
            if generation.publication_sequence == existing.publication_sequence:
                if generation == existing:
                    return existing
                raise PreKeyPublicationConflictError(
                    "publication_sequence already exists with different payload"
                )
            if generation.publication_sequence != existing.publication_sequence + 1:
                raise PreKeyPublicationConflictError(
                    "publication_sequence must advance by exactly one"
                )

            self._generations[generation.device_id] = generation
            return generation

    def is_healthy(self) -> bool:
        return True


@dataclass(slots=True)
class SQLitePreKeyPublicationStore:
    """Persistent SQLite store with atomic generation replacement."""

    path: Path

    def __post_init__(self) -> None:
        if self.path.exists() and self.path.is_dir():
            raise ValueError("node.database_path must point to a file")

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS prekey_publications (
                    device_id TEXT PRIMARY KEY,
                    publication_sequence INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    publication_payload TEXT NOT NULL,
                    fallback_binding TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS prekey_one_time (
                    device_id TEXT NOT NULL,
                    publication_sequence INTEGER NOT NULL,
                    position INTEGER NOT NULL,
                    binding TEXT NOT NULL,
                    PRIMARY KEY (device_id, publication_sequence, position)
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_prekey_one_time_device
                ON prekey_one_time (device_id, publication_sequence, position)
                """
            )

        if os.name == "posix":
            self.path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5.0)

    @staticmethod
    def _same_generation(
        row: tuple[object, ...],
        generation: RelayPreKeyGeneration,
        one_time_bindings: tuple[str, ...],
    ) -> bool:
        return (
            row[0] == generation.publication_sequence
            and row[1] == generation.expires_at
            and row[2] == generation.publication_payload
            and row[3] == generation.fallback_binding
            and one_time_bindings == generation.one_time_bindings
        )

    def publish(self, generation: RelayPreKeyGeneration) -> RelayPreKeyGeneration:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT
                    publication_sequence,
                    expires_at,
                    publication_payload,
                    fallback_binding
                FROM prekey_publications
                WHERE device_id = ?
                """,
                (generation.device_id,),
            ).fetchone()

            if row is None:
                if generation.publication_sequence != 1:
                    raise PreKeyPublicationConflictError(
                        "initial publication_sequence must equal 1"
                    )
            else:
                existing_sequence = int(row[0])
                one_time_rows = connection.execute(
                    """
                    SELECT binding
                    FROM prekey_one_time
                    WHERE device_id = ? AND publication_sequence = ?
                    ORDER BY position
                    """,
                    (generation.device_id, existing_sequence),
                ).fetchall()
                existing_one_time = tuple(str(item[0]) for item in one_time_rows)

                if generation.publication_sequence < existing_sequence:
                    raise PreKeyPublicationConflictError(
                        "publication_sequence is older than the active generation"
                    )
                if generation.publication_sequence == existing_sequence:
                    if self._same_generation(
                        row,
                        generation,
                        existing_one_time,
                    ):
                        return generation
                    raise PreKeyPublicationConflictError(
                        "publication_sequence already exists with different payload"
                    )
                if generation.publication_sequence != existing_sequence + 1:
                    raise PreKeyPublicationConflictError(
                        "publication_sequence must advance by exactly one"
                    )

            connection.execute(
                "DELETE FROM prekey_one_time WHERE device_id = ?",
                (generation.device_id,),
            )
            connection.execute(
                """
                INSERT INTO prekey_publications (
                    device_id,
                    publication_sequence,
                    expires_at,
                    publication_payload,
                    fallback_binding
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    publication_sequence = excluded.publication_sequence,
                    expires_at = excluded.expires_at,
                    publication_payload = excluded.publication_payload,
                    fallback_binding = excluded.fallback_binding
                """,
                (
                    generation.device_id,
                    generation.publication_sequence,
                    generation.expires_at,
                    generation.publication_payload,
                    generation.fallback_binding,
                ),
            )
            connection.executemany(
                """
                INSERT INTO prekey_one_time (
                    device_id,
                    publication_sequence,
                    position,
                    binding
                ) VALUES (?, ?, ?, ?)
                """,
                [
                    (
                        generation.device_id,
                        generation.publication_sequence,
                        index,
                        binding,
                    )
                    for index, binding in enumerate(
                        generation.one_time_bindings
                    )
                ],
            )

        return generation

    def is_healthy(self) -> bool:
        try:
            with self._connect() as connection:
                connection.execute("SELECT 1").fetchone()
        except sqlite3.Error:
            return False
        return True


def create_prekey_publication_store(
    settings: NodeSettings,
) -> PreKeyPublicationStore:
    if settings.database_path is None:
        return InMemoryPreKeyPublicationStore()
    return SQLitePreKeyPublicationStore(settings.database_path)


def _verified_generation(
    request: PreKeyPublicationRequest,
    route_device_id: str,
    *,
    now: int,
) -> RelayPreKeyGeneration:
    try:
        publication = import_ratchet_prekey_publication(request.publication)
    except RatchetBindingError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    signing_public_key = base64.b64decode(
        request.device_signing_public_key,
        validate=True,
    )
    if derive_device_id(signing_public_key) != route_device_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="route DeviceID does not match device signing public key",
        )

    if export_ratchet_prekey_publication(publication) != request.publication:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="publication must use canonical JSON serialization",
        )

    verify_key = VerifyKey(signing_public_key)
    try:
        for signed in (*publication.one_time, publication.fallback):
            binding = signed.binding
            if binding.device_id != route_device_id:
                raise RatchetBindingError(
                    "binding DeviceID does not match publication route"
                )
            if binding.signal_address_name != route_device_id:
                raise RatchetBindingError(
                    "binding protocol address does not match publication route"
                )
            if binding.issued_at > now + 5 * 60:
                raise RatchetBindingError(
                    "binding was issued too far in the future"
                )
            verify_key.verify(
                binding.canonical_bytes(),
                signed.device_signature,
            )
    except (BadSignatureError, RatchetBindingError) as exc:
        detail = (
            "device signature is invalid"
            if isinstance(exc, BadSignatureError)
            else str(exc)
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=detail,
        ) from exc

    expires_at = publication.fallback.binding.expires_at
    if expires_at <= now:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="publication is already expired",
        )

    return RelayPreKeyGeneration(
        device_id=route_device_id,
        publication_sequence=publication.publication_sequence,
        expires_at=expires_at,
        publication_payload=request.publication,
        one_time_bindings=tuple(
            export_ratchet_prekey_binding(binding)
            for binding in publication.one_time
        ),
        fallback_binding=export_ratchet_prekey_binding(publication.fallback),
    )


def create_prekey_publication_router(
    settings: NodeSettings,
    store: PreKeyPublicationStore,
) -> APIRouter:
    """Create authenticated ratchet pre-key publication routes."""
    router = APIRouter()

    @router.put(
        "/v2/prekeys/{device_id}",
        response_model=PreKeyPublicationReceipt,
    )
    def publish_prekeys(
        device_id: str,
        request: PreKeyPublicationRequest,
        authorization: Annotated[str | None, Header()] = None,
    ) -> PreKeyPublicationReceipt:
        require_relay_access(settings, authorization)

        generation = _verified_generation(
            request,
            device_id,
            now=int(time.time()),
        )
        try:
            stored = store.publish(generation)
        except PreKeyPublicationConflictError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc

        return stored.receipt()

    return router
