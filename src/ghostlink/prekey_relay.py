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
from typing import Annotated, Literal, Protocol, cast

from fastapi import APIRouter, Header, HTTPException, status
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from pydantic import BaseModel, ConfigDict, field_validator

from ghostlink.config import NodeSettings
from ghostlink.device import derive_device_id
from ghostlink.prekey_fetch import (
    PreKeyFetchProofError,
    PreKeyFetchRequest,
    PreKeyFetchResponse,
    verify_prekey_fetch_request,
)
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
_FETCH_REQUEST_CLOCK_SKEW_SECONDS = 5 * 60


class PreKeyPublicationConflictError(RuntimeError):
    """Raised when a publication violates monotonic replacement semantics."""


class PreKeyFetchNotFoundError(RuntimeError):
    """Raised when no active target pre-key generation exists."""


class PreKeyFetchExpiredError(RuntimeError):
    """Raised when the target generation or prior allocation is expired."""


class PreKeyFetchRateLimitError(RuntimeError):
    """Raised when new one-time allocations exceed the target drain limit."""

    def __init__(self, retry_after: int) -> None:
        super().__init__("pre-key fetch allocation rate limit exceeded")
        self.retry_after = max(1, retry_after)


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

    def fetch(
        self,
        target_device_id: str,
        requester_device_id: str,
        request_id: str,
        *,
        now: int,
    ) -> PreKeyFetchResponse:
        """Idempotently allocate at most one binding for one requester/generation."""

    def is_healthy(self) -> bool:
        """Return whether publication storage is available."""


@dataclass(slots=True)
class InMemoryPreKeyPublicationStore:
    """Locked in-memory publication/fetch store for tests and development."""

    fetch_window_seconds: int = 60
    fetch_max_new_allocations: int = 10
    _generations: dict[str, RelayPreKeyGeneration] = field(default_factory=dict)
    _remaining: dict[tuple[str, int], list[str]] = field(default_factory=dict)
    _allocations: dict[
        tuple[str, int, str],
        PreKeyFetchResponse,
    ] = field(default_factory=dict)
    _request_allocations: dict[
        tuple[str, str, str],
        PreKeyFetchResponse,
    ] = field(default_factory=dict)
    _fetch_events: dict[str, list[int]] = field(default_factory=dict)
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
                self._remaining[
                    (generation.device_id, generation.publication_sequence)
                ] = list(generation.one_time_bindings)
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
            self._remaining = {
                key: value
                for key, value in self._remaining.items()
                if key[0] != generation.device_id
            }
            self._remaining[
                (generation.device_id, generation.publication_sequence)
            ] = list(generation.one_time_bindings)
            return generation

    def _check_rate_limit(self, target_device_id: str, now: int) -> None:
        cutoff = now - self.fetch_window_seconds
        events = [
            timestamp
            for timestamp in self._fetch_events.get(target_device_id, [])
            if timestamp > cutoff
        ]
        self._fetch_events[target_device_id] = events
        if len(events) < self.fetch_max_new_allocations:
            return

        retry_after = events[0] + self.fetch_window_seconds - now
        raise PreKeyFetchRateLimitError(retry_after)

    def fetch(
        self,
        target_device_id: str,
        requester_device_id: str,
        request_id: str,
        *,
        now: int,
    ) -> PreKeyFetchResponse:
        with self._lock:
            request_key = (
                target_device_id,
                requester_device_id,
                request_id,
            )
            prior_request = self._request_allocations.get(request_key)
            if prior_request is not None:
                if prior_request.expires_at <= now:
                    raise PreKeyFetchExpiredError(
                        "previous pre-key allocation is expired"
                    )
                return prior_request

            generation = self._generations.get(target_device_id)
            if generation is None:
                raise PreKeyFetchNotFoundError(
                    "target has no active pre-key generation"
                )
            if generation.expires_at <= now:
                raise PreKeyFetchExpiredError(
                    "target pre-key generation is expired"
                )

            allocation_key = (
                target_device_id,
                generation.publication_sequence,
                requester_device_id,
            )
            prior = self._allocations.get(allocation_key)
            if prior is not None:
                return prior

            remaining = self._remaining[
                (target_device_id, generation.publication_sequence)
            ]
            bundle_kind: Literal["one_time", "fallback"]
            if remaining:
                self._check_rate_limit(target_device_id, now)
                binding = remaining.pop(0)
                bundle_kind = "one_time"
                self._fetch_events.setdefault(target_device_id, []).append(now)
            else:
                return PreKeyFetchResponse(
                    version=1,
                    target_device_id=target_device_id,
                    requester_device_id=requester_device_id,
                    publication_sequence=generation.publication_sequence,
                    expires_at=generation.expires_at,
                    bundle_kind="fallback",
                    binding=generation.fallback_binding,
                    remaining_one_time_count=0,
                )

            allocation = PreKeyFetchResponse(
                version=1,
                target_device_id=target_device_id,
                requester_device_id=requester_device_id,
                publication_sequence=generation.publication_sequence,
                expires_at=generation.expires_at,
                bundle_kind=bundle_kind,
                binding=binding,
                remaining_one_time_count=len(remaining),
            )
            self._allocations[allocation_key] = allocation
            self._request_allocations[request_key] = allocation
            return allocation

    def is_healthy(self) -> bool:
        return True


@dataclass(slots=True)
class SQLitePreKeyPublicationStore:
    """Persistent SQLite store with atomic generation replacement and fetch."""

    path: Path
    fetch_window_seconds: int = 60
    fetch_max_new_allocations: int = 10

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
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS prekey_allocations (
                    target_device_id TEXT NOT NULL,
                    publication_sequence INTEGER NOT NULL,
                    requester_device_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    bundle_kind TEXT NOT NULL,
                    binding TEXT NOT NULL,
                    remaining_one_time_count INTEGER NOT NULL,
                    allocated_at INTEGER NOT NULL,
                    PRIMARY KEY (
                        target_device_id,
                        publication_sequence,
                        requester_device_id
                    ),
                    UNIQUE (
                        target_device_id,
                        requester_device_id,
                        request_id
                    )
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_prekey_allocations_request
                ON prekey_allocations (
                    target_device_id,
                    requester_device_id,
                    request_id
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS prekey_fetch_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_device_id TEXT NOT NULL,
                    allocated_at INTEGER NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_prekey_fetch_events_target_time
                ON prekey_fetch_events (target_device_id, allocated_at)
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_prekey_fetch_events_time
                ON prekey_fetch_events (allocated_at)
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
    ) -> bool:
        return (
            row[0] == generation.publication_sequence
            and row[1] == generation.expires_at
            and row[2] == generation.publication_payload
            and row[3] == generation.fallback_binding
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
                if generation.publication_sequence < existing_sequence:
                    raise PreKeyPublicationConflictError(
                        "publication_sequence is older than the active generation"
                    )
                if generation.publication_sequence == existing_sequence:
                    if self._same_generation(row, generation):
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

    @staticmethod
    def _allocation_from_row(
        row: tuple[object, ...],
    ) -> PreKeyFetchResponse:
        if not all(isinstance(row[index], int) for index in (2, 3, 6)):
            raise RuntimeError("stored pre-key allocation integer fields are invalid")
        raw_kind = str(row[4])
        if raw_kind not in {"one_time", "fallback"}:
            raise RuntimeError("stored pre-key allocation bundle kind is invalid")
        return PreKeyFetchResponse(
            version=1,
            target_device_id=str(row[0]),
            requester_device_id=str(row[1]),
            publication_sequence=cast(int, row[2]),
            expires_at=cast(int, row[3]),
            bundle_kind=cast(Literal["one_time", "fallback"], raw_kind),
            binding=str(row[5]),
            remaining_one_time_count=cast(int, row[6]),
        )

    def _existing_request_allocation(
        self,
        connection: sqlite3.Connection,
        target_device_id: str,
        requester_device_id: str,
        request_id: str,
    ) -> PreKeyFetchResponse | None:
        row = connection.execute(
            """
            SELECT
                target_device_id,
                requester_device_id,
                publication_sequence,
                expires_at,
                bundle_kind,
                binding,
                remaining_one_time_count
            FROM prekey_allocations
            WHERE target_device_id = ?
              AND requester_device_id = ?
              AND request_id = ?
            """,
            (target_device_id, requester_device_id, request_id),
        ).fetchone()
        return None if row is None else self._allocation_from_row(row)

    def _existing_generation_allocation(
        self,
        connection: sqlite3.Connection,
        target_device_id: str,
        publication_sequence: int,
        requester_device_id: str,
    ) -> PreKeyFetchResponse | None:
        row = connection.execute(
            """
            SELECT
                target_device_id,
                requester_device_id,
                publication_sequence,
                expires_at,
                bundle_kind,
                binding,
                remaining_one_time_count
            FROM prekey_allocations
            WHERE target_device_id = ?
              AND publication_sequence = ?
              AND requester_device_id = ?
            """,
            (
                target_device_id,
                publication_sequence,
                requester_device_id,
            ),
        ).fetchone()
        return None if row is None else self._allocation_from_row(row)

    def _check_rate_limit(
        self,
        connection: sqlite3.Connection,
        target_device_id: str,
        now: int,
    ) -> None:
        cutoff = now - self.fetch_window_seconds
        connection.execute(
            """
            DELETE FROM prekey_fetch_events
            WHERE allocated_at <= ?
            """,
            (cutoff,),
        )
        row = connection.execute(
            """
            SELECT COUNT(*), MIN(allocated_at)
            FROM prekey_fetch_events
            WHERE target_device_id = ? AND allocated_at > ?
            """,
            (target_device_id, cutoff),
        ).fetchone()
        count = 0 if row is None else int(row[0])
        if count < self.fetch_max_new_allocations:
            return

        earliest = now if row is None or row[1] is None else int(row[1])
        retry_after = earliest + self.fetch_window_seconds - now
        raise PreKeyFetchRateLimitError(retry_after)

    def fetch(
        self,
        target_device_id: str,
        requester_device_id: str,
        request_id: str,
        *,
        now: int,
    ) -> PreKeyFetchResponse:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                DELETE FROM prekey_allocations
                WHERE expires_at < ?
                """,
                (now - _FETCH_REQUEST_CLOCK_SKEW_SECONDS,),
            )

            prior_request = self._existing_request_allocation(
                connection,
                target_device_id,
                requester_device_id,
                request_id,
            )
            if prior_request is not None:
                if prior_request.expires_at <= now:
                    raise PreKeyFetchExpiredError(
                        "previous pre-key allocation is expired"
                    )
                return prior_request

            generation = connection.execute(
                """
                SELECT
                    publication_sequence,
                    expires_at,
                    fallback_binding
                FROM prekey_publications
                WHERE device_id = ?
                """,
                (target_device_id,),
            ).fetchone()
            if generation is None:
                raise PreKeyFetchNotFoundError(
                    "target has no active pre-key generation"
                )

            publication_sequence = int(generation[0])
            expires_at = int(generation[1])
            fallback_binding = str(generation[2])
            if expires_at <= now:
                raise PreKeyFetchExpiredError(
                    "target pre-key generation is expired"
                )

            prior = self._existing_generation_allocation(
                connection,
                target_device_id,
                publication_sequence,
                requester_device_id,
            )
            if prior is not None:
                return prior

            one_time = connection.execute(
                """
                SELECT position, binding
                FROM prekey_one_time
                WHERE device_id = ? AND publication_sequence = ?
                ORDER BY position
                LIMIT 1
                """,
                (target_device_id, publication_sequence),
            ).fetchone()

            bundle_kind: Literal["one_time", "fallback"]
            if one_time is None:
                return PreKeyFetchResponse(
                    version=1,
                    target_device_id=target_device_id,
                    requester_device_id=requester_device_id,
                    publication_sequence=publication_sequence,
                    expires_at=expires_at,
                    bundle_kind="fallback",
                    binding=fallback_binding,
                    remaining_one_time_count=0,
                )

            self._check_rate_limit(connection, target_device_id, now)
            position = int(one_time[0])
            binding = str(one_time[1])
            deleted = connection.execute(
                """
                DELETE FROM prekey_one_time
                WHERE device_id = ?
                  AND publication_sequence = ?
                  AND position = ?
                """,
                (target_device_id, publication_sequence, position),
            )
            if deleted.rowcount != 1:
                raise RuntimeError(
                    "pre-key one-time allocation lost atomic ownership"
                )
            bundle_kind = "one_time"
            connection.execute(
                """
                INSERT INTO prekey_fetch_events (
                    target_device_id,
                    allocated_at
                ) VALUES (?, ?)
                """,
                (target_device_id, now),
            )

            remaining_row = connection.execute(
                """
                SELECT COUNT(*)
                FROM prekey_one_time
                WHERE device_id = ? AND publication_sequence = ?
                """,
                (target_device_id, publication_sequence),
            ).fetchone()
            remaining_count = 0 if remaining_row is None else int(remaining_row[0])

            allocation = PreKeyFetchResponse(
                version=1,
                target_device_id=target_device_id,
                requester_device_id=requester_device_id,
                publication_sequence=publication_sequence,
                expires_at=expires_at,
                bundle_kind=bundle_kind,
                binding=binding,
                remaining_one_time_count=remaining_count,
            )
            connection.execute(
                """
                INSERT INTO prekey_allocations (
                    target_device_id,
                    publication_sequence,
                    requester_device_id,
                    request_id,
                    expires_at,
                    bundle_kind,
                    binding,
                    remaining_one_time_count,
                    allocated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    target_device_id,
                    publication_sequence,
                    requester_device_id,
                    request_id,
                    expires_at,
                    bundle_kind,
                    binding,
                    remaining_count,
                    now,
                ),
            )
            return allocation

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
        return InMemoryPreKeyPublicationStore(
            fetch_window_seconds=settings.prekey_fetch_window_seconds,
            fetch_max_new_allocations=(
                settings.prekey_fetch_max_new_allocations
            ),
        )
    return SQLitePreKeyPublicationStore(
        settings.database_path,
        fetch_window_seconds=settings.prekey_fetch_window_seconds,
        fetch_max_new_allocations=settings.prekey_fetch_max_new_allocations,
    )


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
    """Create authenticated ratchet pre-key publication and fetch routes."""
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

    @router.post(
        "/v2/prekeys/{device_id}/fetch",
        response_model=PreKeyFetchResponse,
    )
    def fetch_prekey(
        device_id: str,
        request: PreKeyFetchRequest,
        authorization: Annotated[str | None, Header()] = None,
    ) -> PreKeyFetchResponse:
        require_relay_access(settings, authorization)
        now = int(time.time())
        try:
            requester_device_id = verify_prekey_fetch_request(
                request,
                device_id,
                now=now,
            )
        except PreKeyFetchProofError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(exc),
            ) from exc

        try:
            return store.fetch(
                device_id,
                requester_device_id,
                request.request_id,
                now=now,
            )
        except PreKeyFetchNotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(exc),
            ) from exc
        except PreKeyFetchExpiredError as exc:
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail=str(exc),
            ) from exc
        except PreKeyFetchRateLimitError as exc:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=str(exc),
                headers={"Retry-After": str(exc.retry_after)},
            ) from exc

    return router
