"""GhostNode registry for identity-signed monotonic device lifecycle state."""

from __future__ import annotations

import base64
import binascii
import os
import sqlite3
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Protocol

from fastapi import APIRouter, Header, HTTPException, status
from nacl.signing import VerifyKey
from pydantic import BaseModel, ConfigDict, field_validator

from ghostlink.config import NodeSettings
from ghostlink.device_lifecycle import (
    DeviceLifecycleError,
    export_device_lifecycle_statement,
    import_device_lifecycle_statement,
    verify_device_lifecycle_statement,
)
from ghostlink.relay_auth import require_relay_access
from ghostlink.relay_state import RelayStateCoordinator

_LIFECYCLE_RELAY_VERSION = 1
_IDENTITY_PUBLIC_KEY_BYTES = 32
_MAX_STATEMENT_BYTES = 16_384


class DeviceLifecycleConflictError(RuntimeError):
    """Raised when relay lifecycle state violates monotonic semantics."""


class DeviceLifecycleStoreError(RuntimeError):
    """Raised when relay lifecycle persistence is inconsistent or unavailable."""


@dataclass(frozen=True, slots=True)
class RelayDeviceLifecycle:
    """Canonical relay record for one GhostID lifecycle head."""

    ghost_id: str
    epoch: int
    issued_at: int
    active_device_id: str
    identity_public_key: str
    statement: str


class DeviceLifecycleStore(Protocol):
    """Storage contract for relay-side lifecycle enforcement."""

    def publish(self, record: RelayDeviceLifecycle) -> RelayDeviceLifecycle:
        """Accept an idempotent or strictly newer lifecycle record."""

    def get(self, ghost_id: str) -> RelayDeviceLifecycle | None:
        """Return the highest accepted lifecycle record for one GhostID."""

    def is_device_revoked(self, device_id: str) -> bool:
        """Return whether a known DeviceID is superseded by a newer head."""

    def is_healthy(self) -> bool:
        """Return whether lifecycle state is available and trustworthy."""


def _validate_transition(
    current: RelayDeviceLifecycle,
    candidate: RelayDeviceLifecycle,
) -> None:
    if candidate.ghost_id != current.ghost_id:
        raise DeviceLifecycleConflictError("device lifecycle identity changed")
    if candidate.epoch < current.epoch:
        raise DeviceLifecycleConflictError(
            "device lifecycle epoch is older than relay state"
        )
    if candidate.epoch == current.epoch:
        if candidate != current:
            raise DeviceLifecycleConflictError(
                "device lifecycle epoch already exists with different state"
            )
        return
    if candidate.issued_at < current.issued_at:
        raise DeviceLifecycleConflictError(
            "device lifecycle candidate predates relay state"
        )


@dataclass(slots=True)
class InMemoryDeviceLifecycleStore:
    """Process-local lifecycle registry for tests and development."""

    _records: dict[str, RelayDeviceLifecycle] = field(default_factory=dict)
    _device_owners: dict[str, str] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def publish(self, record: RelayDeviceLifecycle) -> RelayDeviceLifecycle:
        with self._lock:
            current = self._records.get(record.ghost_id)
            owner = self._device_owners.get(record.active_device_id)
            if owner is not None and owner != record.ghost_id:
                raise DeviceLifecycleConflictError(
                    "DeviceID is already bound to another lifecycle identity"
                )

            if current is not None:
                current_owner = self._device_owners.get(current.active_device_id)
                if current_owner != current.ghost_id:
                    raise DeviceLifecycleStoreError(
                        "lifecycle device index is inconsistent"
                    )
                _validate_transition(current, record)
                if record == current:
                    return current

            self._records[record.ghost_id] = record
            self._device_owners[record.active_device_id] = record.ghost_id
            return record

    def get(self, ghost_id: str) -> RelayDeviceLifecycle | None:
        with self._lock:
            return self._records.get(ghost_id)

    def is_device_revoked(self, device_id: str) -> bool:
        with self._lock:
            ghost_id = self._device_owners.get(device_id)
            if ghost_id is None:
                return False
            record = self._records.get(ghost_id)
            if record is None:
                raise DeviceLifecycleStoreError(
                    "lifecycle device index references missing identity state"
                )
            return record.active_device_id != device_id

    def is_healthy(self) -> bool:
        return True


@dataclass(slots=True)
class SQLiteDeviceLifecycleStore:
    """Persistent lifecycle registry coordinated with relay rollback state."""

    path: Path
    coordinator: RelayStateCoordinator | None = None

    def __post_init__(self) -> None:
        if (
            self.coordinator is not None
            and self.coordinator.path.resolve() != self.path.resolve()
        ):
            raise ValueError(
                "relay state coordinator path does not match lifecycle store"
            )
        if self.path.exists() and self.path.is_dir():
            raise ValueError("node.database_path must point to a file")
        self.path.parent.mkdir(parents=True, exist_ok=True)

        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS device_lifecycle_v1 (
                    ghost_id TEXT PRIMARY KEY,
                    epoch INTEGER NOT NULL,
                    issued_at INTEGER NOT NULL,
                    active_device_id TEXT NOT NULL,
                    identity_public_key TEXT NOT NULL,
                    statement TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS device_lifecycle_devices_v1 (
                    device_id TEXT PRIMARY KEY,
                    ghost_id TEXT NOT NULL,
                    lifecycle_epoch INTEGER NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_device_lifecycle_devices_ghost
                ON device_lifecycle_devices_v1 (ghost_id, lifecycle_epoch)
                """
            )

        if os.name == "posix":
            self.path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5.0)

    @staticmethod
    def _record_from_row(row: tuple[object, ...]) -> RelayDeviceLifecycle:
        if len(row) != 6:
            raise DeviceLifecycleStoreError(
                "stored lifecycle row has an invalid shape"
            )
        ghost_id, epoch, issued_at, active_device_id, identity_public_key, statement = row
        if (
            not isinstance(ghost_id, str)
            or not isinstance(epoch, int)
            or isinstance(epoch, bool)
            or not isinstance(issued_at, int)
            or isinstance(issued_at, bool)
            or not isinstance(active_device_id, str)
            or not isinstance(identity_public_key, str)
            or not isinstance(statement, str)
        ):
            raise DeviceLifecycleStoreError(
                "stored lifecycle row has invalid field types"
            )
        return RelayDeviceLifecycle(
            ghost_id=ghost_id,
            epoch=epoch,
            issued_at=issued_at,
            active_device_id=active_device_id,
            identity_public_key=identity_public_key,
            statement=statement,
        )

    @staticmethod
    def _read_record(
        connection: sqlite3.Connection,
        ghost_id: str,
    ) -> RelayDeviceLifecycle | None:
        row = connection.execute(
            """
            SELECT
                ghost_id,
                epoch,
                issued_at,
                active_device_id,
                identity_public_key,
                statement
            FROM device_lifecycle_v1
            WHERE ghost_id = ?
            """,
            (ghost_id,),
        ).fetchone()
        if row is None:
            return None
        return SQLiteDeviceLifecycleStore._record_from_row(tuple(row))

    @staticmethod
    def _read_device_owner(
        connection: sqlite3.Connection,
        device_id: str,
    ) -> str | None:
        row = connection.execute(
            """
            SELECT ghost_id
            FROM device_lifecycle_devices_v1
            WHERE device_id = ?
            """,
            (device_id,),
        ).fetchone()
        if row is None:
            return None
        if len(row) != 1 or not isinstance(row[0], str):
            raise DeviceLifecycleStoreError(
                "stored lifecycle device index is malformed"
            )
        return row[0]

    def _publish(
        self,
        connection: sqlite3.Connection,
        record: RelayDeviceLifecycle,
    ) -> RelayDeviceLifecycle:
        current = self._read_record(connection, record.ghost_id)
        owner = self._read_device_owner(connection, record.active_device_id)
        if owner is not None and owner != record.ghost_id:
            raise DeviceLifecycleConflictError(
                "DeviceID is already bound to another lifecycle identity"
            )

        if current is not None:
            current_owner = self._read_device_owner(
                connection,
                current.active_device_id,
            )
            if current_owner != current.ghost_id:
                raise DeviceLifecycleStoreError(
                    "lifecycle device index is inconsistent"
                )
            _validate_transition(current, record)
            if record == current:
                return current

            connection.execute(
                """
                UPDATE device_lifecycle_v1
                SET
                    epoch = ?,
                    issued_at = ?,
                    active_device_id = ?,
                    identity_public_key = ?,
                    statement = ?
                WHERE ghost_id = ?
                """,
                (
                    record.epoch,
                    record.issued_at,
                    record.active_device_id,
                    record.identity_public_key,
                    record.statement,
                    record.ghost_id,
                ),
            )
        else:
            connection.execute(
                """
                INSERT INTO device_lifecycle_v1 (
                    ghost_id,
                    epoch,
                    issued_at,
                    active_device_id,
                    identity_public_key,
                    statement
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    record.ghost_id,
                    record.epoch,
                    record.issued_at,
                    record.active_device_id,
                    record.identity_public_key,
                    record.statement,
                ),
            )

        connection.execute(
            """
            INSERT INTO device_lifecycle_devices_v1 (
                device_id,
                ghost_id,
                lifecycle_epoch
            ) VALUES (?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                ghost_id = excluded.ghost_id,
                lifecycle_epoch = excluded.lifecycle_epoch
            """,
            (
                record.active_device_id,
                record.ghost_id,
                record.epoch,
            ),
        )
        return record

    def publish(self, record: RelayDeviceLifecycle) -> RelayDeviceLifecycle:
        try:
            if self.coordinator is not None:
                return self.coordinator.mutate(
                    lambda connection: self._publish(connection, record)
                )
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                return self._publish(connection, record)
        except sqlite3.Error as exc:
            raise DeviceLifecycleStoreError(
                "unable to persist device lifecycle state"
            ) from exc

    def get(self, ghost_id: str) -> RelayDeviceLifecycle | None:
        if self.coordinator is not None:
            self.coordinator.require_healthy()
        try:
            with self._connect() as connection:
                return self._read_record(connection, ghost_id)
        except sqlite3.Error as exc:
            raise DeviceLifecycleStoreError(
                "unable to read device lifecycle state"
            ) from exc

    def is_device_revoked(self, device_id: str) -> bool:
        if self.coordinator is not None:
            self.coordinator.require_healthy()
        try:
            with self._connect() as connection:
                ghost_id = self._read_device_owner(connection, device_id)
                if ghost_id is None:
                    return False
                record = self._read_record(connection, ghost_id)
                if record is None:
                    raise DeviceLifecycleStoreError(
                        "lifecycle device index references missing identity state"
                    )
                return record.active_device_id != device_id
        except sqlite3.Error as exc:
            raise DeviceLifecycleStoreError(
                "unable to read device lifecycle status"
            ) from exc

    def is_healthy(self) -> bool:
        if self.coordinator is not None and not self.coordinator.is_healthy():
            return False
        try:
            with self._connect() as connection:
                connection.execute("SELECT 1").fetchone()
        except sqlite3.Error:
            return False
        return True


def create_device_lifecycle_store(
    settings: NodeSettings,
    coordinator: RelayStateCoordinator | None = None,
) -> DeviceLifecycleStore:
    """Create in-memory or persistent relay lifecycle storage."""
    if settings.database_path is None:
        return InMemoryDeviceLifecycleStore()
    return SQLiteDeviceLifecycleStore(
        settings.database_path,
        coordinator=coordinator,
    )


class DeviceLifecyclePublicationRequest(BaseModel):
    """Identity-authorized lifecycle state submitted to GhostNode."""

    model_config = ConfigDict(extra="forbid", strict=True)

    version: int
    identity_public_key: str
    statement: str

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: int) -> int:
        if value != _LIFECYCLE_RELAY_VERSION:
            raise ValueError("unsupported relay lifecycle version")
        return value

    @field_validator("identity_public_key")
    @classmethod
    def validate_identity_public_key(cls, value: str) -> str:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("identity_public_key must be valid Base64") from exc
        if len(decoded) != _IDENTITY_PUBLIC_KEY_BYTES:
            raise ValueError(
                "identity_public_key must decode to exactly 32 bytes"
            )
        if base64.b64encode(decoded).decode("ascii") != value:
            raise ValueError("identity_public_key must use canonical Base64")
        return value

    @field_validator("statement")
    @classmethod
    def validate_statement(cls, value: str) -> str:
        if not value or len(value.encode("utf-8")) > _MAX_STATEMENT_BYTES:
            raise ValueError("device lifecycle statement exceeds size limit")
        return value


class DeviceLifecycleRecordResponse(BaseModel):
    """Current relay lifecycle head for one GhostID."""

    model_config = ConfigDict(extra="forbid", strict=True)

    version: int
    ghost_id: str
    epoch: int
    issued_at: int
    active_device_id: str
    identity_public_key: str
    statement: str


def _response(record: RelayDeviceLifecycle) -> DeviceLifecycleRecordResponse:
    return DeviceLifecycleRecordResponse(
        version=_LIFECYCLE_RELAY_VERSION,
        ghost_id=record.ghost_id,
        epoch=record.epoch,
        issued_at=record.issued_at,
        active_device_id=record.active_device_id,
        identity_public_key=record.identity_public_key,
        statement=record.statement,
    )


def _verified_record(
    request: DeviceLifecyclePublicationRequest,
    route_ghost_id: str,
) -> RelayDeviceLifecycle:
    identity_public_key = base64.b64decode(
        request.identity_public_key,
        validate=True,
    )
    verify_key = VerifyKey(identity_public_key)

    try:
        signed = import_device_lifecycle_statement(request.statement)
        device = verify_device_lifecycle_statement(signed, verify_key)
    except (DeviceLifecycleError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    if signed.statement.ghost_id != route_ghost_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="route GhostID does not match device lifecycle statement",
        )
    if export_device_lifecycle_statement(signed) != request.statement:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="device lifecycle statement must use canonical JSON",
        )

    return RelayDeviceLifecycle(
        ghost_id=signed.statement.ghost_id,
        epoch=signed.statement.epoch,
        issued_at=signed.statement.issued_at,
        active_device_id=device.device_id,
        identity_public_key=request.identity_public_key,
        statement=request.statement,
    )


def require_active_relay_device(
    store: DeviceLifecycleStore,
    device_id: str,
) -> None:
    """Fail closed only for DeviceIDs known to have been superseded."""
    try:
        revoked = store.is_device_revoked(device_id)
    except DeviceLifecycleStoreError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="storage unavailable",
        ) from exc

    if revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="unauthorized",
        )


def create_device_lifecycle_router(
    settings: NodeSettings,
    store: DeviceLifecycleStore,
) -> APIRouter:
    """Create identity-authorized lifecycle publication and lookup routes."""
    router = APIRouter()

    @router.put(
        "/v3/device-lifecycle/{ghost_id}",
        response_model=DeviceLifecycleRecordResponse,
    )
    def publish_device_lifecycle(
        ghost_id: str,
        request: DeviceLifecyclePublicationRequest,
        authorization: Annotated[str | None, Header()] = None,
    ) -> DeviceLifecycleRecordResponse:
        require_relay_access(settings, authorization)
        record = _verified_record(request, ghost_id)
        try:
            return _response(store.publish(record))
        except DeviceLifecycleConflictError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        except DeviceLifecycleStoreError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="storage unavailable",
            ) from exc

    @router.get(
        "/v3/device-lifecycle/{ghost_id}",
        response_model=DeviceLifecycleRecordResponse,
    )
    def get_device_lifecycle(
        ghost_id: str,
        authorization: Annotated[str | None, Header()] = None,
    ) -> DeviceLifecycleRecordResponse:
        require_relay_access(settings, authorization)
        try:
            record = store.get(ghost_id)
        except DeviceLifecycleStoreError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="storage unavailable",
            ) from exc
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="device lifecycle not found",
            )
        return _response(record)

    return router
