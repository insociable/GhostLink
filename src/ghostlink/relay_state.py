"""Rollback-aware coordination primitives for persistent GhostNode SQLite state.

The reference SQLite witness is development-only. It detects rollback of the GhostNode
database only while the witness database remains newer than the protected relay state.
A whole-filesystem or VM snapshot can roll both back together.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, TypeVar

RELAY_STATE_VERSION = 1
RELAY_WITNESS_RECORD_VERSION = 1
MAX_RELAY_REVISION = (1 << 53) - 1

_RELAY_CHECKPOINT_DOMAIN = b"ghostlink-relay-state-checkpoint-v1\x00"
_RELAY_WITNESS_DOMAIN = b"ghostlink-relay-state-witness-record-v1\x00"
_HEX = frozenset("0123456789abcdef")
_T = TypeVar("_T")


class RelayStateError(RuntimeError):
    """Base class for persistent relay-state coordination failures."""


class RelayStateFormatError(RelayStateError):
    """Raised when protected relay state is malformed or unsupported."""


class RelayStateLegacyError(RelayStateError):
    """Raised when a legacy database requires explicit witness migration."""


class RelayStateRollbackError(RelayStateError):
    """Raised when the relay database is older than its monotonic witness."""


class RelayStateDivergenceError(RelayStateError):
    """Raised when equal/adjacent revisions do not authenticate valid lineage."""


class RelayStateGapError(RelayStateError):
    """Raised when the database is more than one revision ahead of its witness."""


class RelayWitnessError(RelayStateError):
    """Base class for relay monotonic-witness failures."""


class RelayWitnessMissingError(RelayWitnessError):
    """Raised when an enrolled relay-state witness record is missing."""


class RelayWitnessConflictError(RelayWitnessError):
    """Raised when relay witness compare-and-set sees unexpected state."""


class RelayWitnessCorruptionError(RelayWitnessError):
    """Raised when a relay witness record fails validation/authentication."""


@dataclass(frozen=True, slots=True)
class _ColumnSpec:
    name: str
    declared_type: str
    not_null: bool
    primary_key_position: int


@dataclass(frozen=True, slots=True)
class _TableSpec:
    name: str
    columns: tuple[_ColumnSpec, ...]
    order_by: tuple[str, ...]


_PROTECTED_TABLES = (
    _TableSpec(
        "messages_v3",
        (
            _ColumnSpec("message_id", "TEXT", True, 2),
            _ColumnSpec("version", "INTEGER", True, 0),
            _ColumnSpec("sender_device_id", "TEXT", True, 0),
            _ColumnSpec("recipient_device_id", "TEXT", True, 1),
            _ColumnSpec("created_at", "INTEGER", True, 0),
            _ColumnSpec("expires_at", "INTEGER", True, 0),
            _ColumnSpec("ciphertext_type", "INTEGER", True, 0),
            _ColumnSpec("ciphertext", "TEXT", True, 0),
        ),
        ("recipient_device_id", "message_id"),
    ),
    _TableSpec(
        "prekey_publications",
        (
            _ColumnSpec("device_id", "TEXT", False, 1),
            _ColumnSpec("publication_sequence", "INTEGER", True, 0),
            _ColumnSpec("expires_at", "INTEGER", True, 0),
            _ColumnSpec("publication_payload", "TEXT", True, 0),
            _ColumnSpec("fallback_binding", "TEXT", True, 0),
        ),
        ("device_id",),
    ),
    _TableSpec(
        "prekey_one_time",
        (
            _ColumnSpec("device_id", "TEXT", True, 1),
            _ColumnSpec("publication_sequence", "INTEGER", True, 2),
            _ColumnSpec("position", "INTEGER", True, 3),
            _ColumnSpec("binding", "TEXT", True, 0),
        ),
        ("device_id", "publication_sequence", "position"),
    ),
    _TableSpec(
        "prekey_allocations",
        (
            _ColumnSpec("target_device_id", "TEXT", True, 1),
            _ColumnSpec("publication_sequence", "INTEGER", True, 2),
            _ColumnSpec("requester_device_id", "TEXT", True, 3),
            _ColumnSpec("request_id", "TEXT", True, 0),
            _ColumnSpec("expires_at", "INTEGER", True, 0),
            _ColumnSpec("bundle_kind", "TEXT", True, 0),
            _ColumnSpec("binding", "TEXT", True, 0),
            _ColumnSpec("remaining_one_time_count", "INTEGER", True, 0),
            _ColumnSpec("allocated_at", "INTEGER", True, 0),
        ),
        ("target_device_id", "publication_sequence", "requester_device_id"),
    ),
    _TableSpec(
        "prekey_fetch_events",
        (
            _ColumnSpec("event_id", "INTEGER", False, 1),
            _ColumnSpec("target_device_id", "TEXT", True, 0),
            _ColumnSpec("allocated_at", "INTEGER", True, 0),
        ),
        ("event_id",),
    ),
    _TableSpec(
        "relay_request_replay_v1",
        (
            _ColumnSpec("device_id", "TEXT", True, 1),
            _ColumnSpec("request_id", "TEXT", True, 2),
            _ColumnSpec("expires_at", "INTEGER", True, 0),
        ),
        ("device_id", "request_id"),
    ),
)

_OPTIONAL_PROTECTED_TABLES = (
    _TableSpec(
        "device_lifecycle_v1",
        (
            _ColumnSpec("ghost_id", "TEXT", False, 1),
            _ColumnSpec("epoch", "INTEGER", True, 0),
            _ColumnSpec("issued_at", "INTEGER", True, 0),
            _ColumnSpec("active_device_id", "TEXT", True, 0),
            _ColumnSpec("identity_public_key", "TEXT", True, 0),
            _ColumnSpec("statement", "TEXT", True, 0),
        ),
        ("ghost_id",),
    ),
    _TableSpec(
        "device_lifecycle_devices_v1",
        (
            _ColumnSpec("device_id", "TEXT", False, 1),
            _ColumnSpec("ghost_id", "TEXT", True, 0),
            _ColumnSpec("lifecycle_epoch", "INTEGER", True, 0),
        ),
        ("device_id",),
    ),
)


@dataclass(frozen=True, slots=True)
class RelayStateMetadata:
    """Authenticated lineage inputs persisted inside the GhostNode database."""

    relay_state_id: str
    revision: int
    previous_digest: str | None

    def __post_init__(self) -> None:
        _validate_state_id(self.relay_state_id)
        _validate_revision(self.revision)
        _validate_previous_digest(self.previous_digest, revision=self.revision)


@dataclass(frozen=True, slots=True)
class RelayCheckpoint:
    """Authenticated checkpoint for one complete logical relay-state revision."""

    relay_state_id: str
    revision: int
    previous_digest: str | None
    digest: str

    def __post_init__(self) -> None:
        _validate_state_id(self.relay_state_id)
        _validate_revision(self.revision)
        _validate_previous_digest(self.previous_digest, revision=self.revision)
        _validate_digest(self.digest)


@dataclass(frozen=True, slots=True)
class RelayWitnessRecord:
    """Latest monotonic relay checkpoint remembered outside the main database."""

    relay_state_id: str
    revision: int
    digest: str

    def __post_init__(self) -> None:
        _validate_state_id(self.relay_state_id)
        _validate_revision(self.revision)
        _validate_digest(self.digest)


class RelayMonotonicWitness(Protocol):
    """Storage contract for one relay-state monotonic witness."""

    def get(self) -> RelayWitnessRecord | None:
        """Return the current witness record."""

    def initialize(self, record: RelayWitnessRecord) -> None:
        """Initialize the witness exactly once."""

    def compare_and_set(
        self,
        expected: RelayWitnessRecord,
        next_record: RelayWitnessRecord,
    ) -> None:
        """Advance the exact current record by one revision."""


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def _validate_state_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 32
        or value != value.lower()
        or any(character not in _HEX for character in value)
    ):
        raise RelayStateFormatError(
            "relay_state_id must be 128-bit lowercase hexadecimal"
        )
    return value


def _validate_coordination_key(value: object) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise RelayStateFormatError(
            "relay state coordination key must contain exactly 32 bytes"
        )
    return value


def _validate_revision(value: object) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
        or value > MAX_RELAY_REVISION
    ):
        raise RelayStateFormatError(
            "relay state revision must be a positive JSON-safe integer"
        )
    return value


def _validate_digest(value: object, field: str = "digest") -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(character not in _HEX for character in value)
    ):
        raise RelayStateFormatError(
            f"{field} must be 32-byte lowercase hexadecimal"
        )
    return value


def _validate_previous_digest(
    value: object,
    *,
    revision: int,
) -> str | None:
    if revision == 1:
        if value is not None:
            raise RelayStateFormatError(
                "initial relay state must not have a previous digest"
            )
        return None
    if value is None:
        raise RelayStateFormatError(
            "non-initial relay state requires a previous digest"
        )
    return _validate_digest(value, "previous_digest")


def _create_metadata_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS relay_state_meta_v1 (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            version INTEGER NOT NULL,
            relay_state_id TEXT NOT NULL,
            revision INTEGER NOT NULL,
            previous_digest TEXT
        )
        """
    )


def _read_metadata(
    connection: sqlite3.Connection,
) -> RelayStateMetadata | None:
    row = connection.execute(
        """
        SELECT version, relay_state_id, revision, previous_digest
        FROM relay_state_meta_v1
        WHERE singleton = 1
        """
    ).fetchone()
    if row is None:
        return None
    if len(row) != 4 or row[0] != RELAY_STATE_VERSION:
        raise RelayStateFormatError("relay state metadata is malformed")
    return RelayStateMetadata(
        relay_state_id=_validate_state_id(row[1]),
        revision=_validate_revision(row[2]),
        previous_digest=_validate_previous_digest(
            row[3],
            revision=_validate_revision(row[2]),
        ),
    )


def _write_metadata(
    connection: sqlite3.Connection,
    metadata: RelayStateMetadata,
) -> None:
    connection.execute(
        """
        INSERT INTO relay_state_meta_v1 (
            singleton,
            version,
            relay_state_id,
            revision,
            previous_digest
        ) VALUES (1, ?, ?, ?, ?)
        ON CONFLICT(singleton) DO UPDATE SET
            version = excluded.version,
            relay_state_id = excluded.relay_state_id,
            revision = excluded.revision,
            previous_digest = excluded.previous_digest
        """,
        (
            RELAY_STATE_VERSION,
            metadata.relay_state_id,
            metadata.revision,
            metadata.previous_digest,
        ),
    )


def _schema_signature(
    connection: sqlite3.Connection,
    table: _TableSpec,
) -> tuple[tuple[object, ...], ...]:
    rows = connection.execute(
        """
        SELECT name, type, "notnull", pk
        FROM pragma_table_info(?)
        ORDER BY cid
        """,
        (table.name,),
    ).fetchall()
    return tuple(tuple(row) for row in rows)


def _validate_protected_schema(
    connection: sqlite3.Connection,
    table: _TableSpec,
) -> None:
    actual = _schema_signature(connection, table)
    expected = tuple(
        (
            column.name,
            column.declared_type,
            1 if column.not_null else 0,
            column.primary_key_position,
        )
        for column in table.columns
    )
    if actual != expected:
        raise RelayStateFormatError(
            f"protected relay table schema is invalid: {table.name}"
        )


def _validate_row(
    table: _TableSpec,
    row: tuple[object, ...],
) -> list[object]:
    if len(row) != len(table.columns):
        raise RelayStateFormatError(
            f"protected relay row shape is invalid: {table.name}"
        )

    validated: list[object] = []
    for column, value in zip(table.columns, row, strict=True):
        if column.declared_type == "INTEGER":
            if not isinstance(value, int) or isinstance(value, bool):
                raise RelayStateFormatError(
                    f"{table.name}.{column.name} must be an integer"
                )
            validated.append(value)
            continue

        if column.declared_type == "TEXT":
            if not isinstance(value, str):
                raise RelayStateFormatError(
                    f"{table.name}.{column.name} must be text"
                )
            validated.append(value)
            continue

        raise RelayStateFormatError(
            f"unsupported protected relay column type: {column.declared_type}"
        )

    return validated


def _table_exists(
    connection: sqlite3.Connection,
    table_name: str,
) -> bool:
    row = connection.execute(
        """
        SELECT 1
        FROM sqlite_master
        WHERE type = 'table' AND name = ?
        """,
        (table_name,),
    ).fetchone()
    return row is not None


def _protected_table_payload(
    connection: sqlite3.Connection,
    table: _TableSpec,
) -> dict[str, object]:
    _validate_protected_schema(connection, table)
    column_sql = ", ".join(f'"{column.name}"' for column in table.columns)
    order_sql = ", ".join(f'"{column}"' for column in table.order_by)
    query = (
        f'SELECT {column_sql} FROM "{table.name}" ORDER BY {order_sql}'  # noqa: S608
    )
    rows = connection.execute(query).fetchall()
    return {
        "name": table.name,
        "rows": [
            _validate_row(table, tuple(row))
            for row in rows
        ],
    }


def canonical_relay_payload(connection: sqlite3.Connection) -> bytes:
    """Return the strict canonical logical snapshot of protected relay tables."""
    tables = [
        _protected_table_payload(connection, table)
        for table in _PROTECTED_TABLES
    ]

    for table in _OPTIONAL_PROTECTED_TABLES:
        if not _table_exists(connection, table.name):
            continue
        payload = _protected_table_payload(connection, table)
        if payload["rows"]:
            tables.append(payload)

    return _canonical_json(
        {
            "tables": tables,
            "version": RELAY_STATE_VERSION,
        }
    )


def derive_relay_checkpoint(
    coordination_key: bytes,
    metadata: RelayStateMetadata,
    payload: bytes,
) -> RelayCheckpoint:
    """Authenticate one logical relay-state revision."""
    key = _validate_coordination_key(coordination_key)
    if not isinstance(payload, bytes):
        raise RelayStateFormatError("relay checkpoint payload must be bytes")

    document: dict[str, object] = {
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "previous_digest": metadata.previous_digest,
        "relay_state_id": metadata.relay_state_id,
        "revision": metadata.revision,
        "version": RELAY_STATE_VERSION,
    }
    digest = hmac.new(
        key,
        _RELAY_CHECKPOINT_DOMAIN + _canonical_json(document),
        hashlib.sha256,
    ).hexdigest()
    return RelayCheckpoint(
        relay_state_id=metadata.relay_state_id,
        revision=metadata.revision,
        previous_digest=metadata.previous_digest,
        digest=digest,
    )


def witness_record(checkpoint: RelayCheckpoint) -> RelayWitnessRecord:
    """Project one checkpoint into the witness record."""
    return RelayWitnessRecord(
        relay_state_id=checkpoint.relay_state_id,
        revision=checkpoint.revision,
        digest=checkpoint.digest,
    )


@dataclass(slots=True)
class SQLiteRelayMonotonicWitness:
    """Authenticated sidecar witness for development and deterministic tests."""

    path: Path
    relay_state_id: str
    coordination_key: bytes

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        _validate_state_id(self.relay_state_id)
        _validate_coordination_key(self.coordination_key)
        if self.path.exists() and self.path.is_dir():
            raise ValueError("relay witness path must point to a file")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS relay_witness_v1 (
                        relay_state_id TEXT PRIMARY KEY,
                        revision INTEGER NOT NULL,
                        digest TEXT NOT NULL,
                        record_mac TEXT NOT NULL
                    )
                    """
                )
        except sqlite3.Error as exc:
            raise RelayWitnessError(
                "unable to initialize relay monotonic witness"
            ) from exc

        if os.name == "posix":
            self.path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _record_mac(self, record: RelayWitnessRecord) -> str:
        document: dict[str, object] = {
            "digest": record.digest,
            "relay_state_id": record.relay_state_id,
            "revision": record.revision,
            "version": RELAY_WITNESS_RECORD_VERSION,
        }
        return hmac.new(
            self.coordination_key,
            _RELAY_WITNESS_DOMAIN + _canonical_json(document),
            hashlib.sha256,
        ).hexdigest()

    def _decode_row(self, row: tuple[object, ...]) -> RelayWitnessRecord:
        if len(row) != 3:
            raise RelayWitnessCorruptionError(
                "relay witness row shape is invalid"
            )
        revision, digest, record_mac = row
        try:
            record = RelayWitnessRecord(
                relay_state_id=self.relay_state_id,
                revision=_validate_revision(revision),
                digest=_validate_digest(digest),
            )
            validated_mac = _validate_digest(record_mac, "record_mac")
        except RelayStateFormatError as exc:
            raise RelayWitnessCorruptionError(
                "relay witness record is malformed"
            ) from exc

        if not hmac.compare_digest(
            self._record_mac(record),
            validated_mac,
        ):
            raise RelayWitnessCorruptionError(
                "relay witness record authentication failed"
            )
        return record

    def _read(
        self,
        connection: sqlite3.Connection,
    ) -> RelayWitnessRecord | None:
        row = connection.execute(
            """
            SELECT revision, digest, record_mac
            FROM relay_witness_v1
            WHERE relay_state_id = ?
            """,
            (self.relay_state_id,),
        ).fetchone()
        return None if row is None else self._decode_row(tuple(row))

    def get(self) -> RelayWitnessRecord | None:
        """Read and authenticate the current witness record."""
        try:
            with self._connect() as connection:
                return self._read(connection)
        except sqlite3.Error as exc:
            raise RelayWitnessError(
                "unable to read relay monotonic witness"
            ) from exc

    def _validate_scoped_record(
        self,
        record: RelayWitnessRecord,
    ) -> None:
        if record.relay_state_id != self.relay_state_id:
            raise RelayStateFormatError(
                "relay witness record belongs to another relay_state_id"
            )

    def initialize(self, record: RelayWitnessRecord) -> None:
        """Initialize the witness exactly once at revision 1."""
        self._validate_scoped_record(record)
        if record.revision != 1:
            raise RelayStateFormatError(
                "relay witness initialization requires revision 1"
            )

        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                if self._read(connection) is not None:
                    raise RelayWitnessConflictError(
                        "relay monotonic witness is already initialized"
                    )
                connection.execute(
                    """
                    INSERT INTO relay_witness_v1 (
                        relay_state_id,
                        revision,
                        digest,
                        record_mac
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        record.relay_state_id,
                        record.revision,
                        record.digest,
                        self._record_mac(record),
                    ),
                )
        except sqlite3.Error as exc:
            raise RelayWitnessError(
                "unable to initialize relay witness"
            ) from exc

    def compare_and_set(
        self,
        expected: RelayWitnessRecord,
        next_record: RelayWitnessRecord,
    ) -> None:
        """Atomically advance the exact witness record by one revision."""
        self._validate_scoped_record(expected)
        self._validate_scoped_record(next_record)
        if next_record.revision != expected.revision + 1:
            raise RelayStateFormatError(
                "relay witness transition must advance exactly one revision"
            )

        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                current = self._read(connection)
                if current is None:
                    raise RelayWitnessMissingError(
                        "required relay witness record is missing"
                    )
                if current != expected:
                    raise RelayWitnessConflictError(
                        "relay witness compare-and-set conflict"
                    )
                connection.execute(
                    """
                    UPDATE relay_witness_v1
                    SET revision = ?, digest = ?, record_mac = ?
                    WHERE relay_state_id = ?
                    """,
                    (
                        next_record.revision,
                        next_record.digest,
                        self._record_mac(next_record),
                        self.relay_state_id,
                    ),
                )
        except sqlite3.Error as exc:
            raise RelayWitnessError(
                "unable to advance relay monotonic witness"
            ) from exc


class RelayStateCoordinator:
    """Serialize and witness all protected mutations for one relay database."""

    def __init__(
        self,
        path: str | Path,
        relay_state_id: str,
        coordination_key: bytes,
        witness: RelayMonotonicWitness,
    ) -> None:
        self.path = Path(path)
        self.relay_state_id = _validate_state_id(relay_state_id)
        self.coordination_key = _validate_coordination_key(coordination_key)
        self.witness = witness
        self._lock = threading.Lock()
        self._checkpoint: RelayCheckpoint | None = None
        self._unsafe = False

        if self.path.exists() and self.path.is_dir():
            raise ValueError("relay database path must point to a file")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _state_from_connection(
        self,
        connection: sqlite3.Connection,
    ) -> tuple[RelayCheckpoint, bytes]:
        metadata = _read_metadata(connection)
        if metadata is None:
            raise RelayStateLegacyError(
                "legacy relay database requires explicit rollback-state migration"
            )
        if metadata.relay_state_id != self.relay_state_id:
            raise RelayStateDivergenceError(
                "relay database belongs to a different relay_state_id"
            )
        payload = canonical_relay_payload(connection)
        return (
            derive_relay_checkpoint(
                self.coordination_key,
                metadata,
                payload,
            ),
            payload,
        )

    def _checkpoint_from_connection(
        self,
        connection: sqlite3.Connection,
    ) -> RelayCheckpoint:
        checkpoint, _payload = self._state_from_connection(connection)
        return checkpoint

    def _reconcile_locked(self) -> RelayCheckpoint:
        try:
            with self._connect() as connection:
                _create_metadata_schema(connection)
                checkpoint = self._checkpoint_from_connection(connection)

            current = self.witness.get()
            if current is None:
                raise RelayWitnessMissingError(
                    "required relay monotonic witness record is missing"
                )
            if current.relay_state_id != checkpoint.relay_state_id:
                raise RelayStateDivergenceError(
                    "relay witness belongs to a different relay_state_id"
                )

            if checkpoint.revision < current.revision:
                raise RelayStateRollbackError(
                    "relay database revision is older than monotonic witness"
                )

            if checkpoint.revision == current.revision:
                if not hmac.compare_digest(checkpoint.digest, current.digest):
                    raise RelayStateDivergenceError(
                        "relay database digest diverges at witnessed revision"
                    )
                self._checkpoint = checkpoint
                self._unsafe = False
                return checkpoint

            if checkpoint.revision > current.revision + 1:
                raise RelayStateGapError(
                    "relay database is more than one revision ahead of witness"
                )

            if checkpoint.previous_digest is None or not hmac.compare_digest(
                checkpoint.previous_digest,
                current.digest,
            ):
                raise RelayStateDivergenceError(
                    "relay database successor does not link to witnessed digest"
                )

            self.witness.compare_and_set(
                current,
                witness_record(checkpoint),
            )
            self._checkpoint = checkpoint
            self._unsafe = False
            return checkpoint
        except RelayStateError:
            self._unsafe = True
            raise
        except sqlite3.Error as exc:
            self._unsafe = True
            raise RelayStateError(
                "unable to reconcile persistent relay state"
            ) from exc

    def reconcile(self) -> RelayCheckpoint:
        """Verify database freshness, including one-step crash recovery."""
        with self._lock:
            return self._reconcile_locked()

    def migrate_legacy(self) -> RelayCheckpoint:
        """Explicitly enroll one legacy protected database at revision 1."""
        with self._lock:
            try:
                with self._connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    _create_metadata_schema(connection)
                    existing = _read_metadata(connection)
                    if existing is not None:
                        raise RelayStateFormatError(
                            "relay database already has rollback-state metadata"
                        )

                    payload = canonical_relay_payload(connection)
                    metadata = RelayStateMetadata(
                        relay_state_id=self.relay_state_id,
                        revision=1,
                        previous_digest=None,
                    )
                    checkpoint = derive_relay_checkpoint(
                        self.coordination_key,
                        metadata,
                        payload,
                    )
                    expected_record = witness_record(checkpoint)
                    current = self.witness.get()
                    if current is None:
                        self.witness.initialize(expected_record)
                    elif current != expected_record:
                        raise RelayWitnessConflictError(
                            "existing relay witness does not match legacy database"
                        )

                    _write_metadata(connection, metadata)
                    connection.commit()

                self._checkpoint = checkpoint
                self._unsafe = False
                return checkpoint
            except RelayStateError:
                self._unsafe = True
                raise
            except sqlite3.Error as exc:
                self._unsafe = True
                raise RelayStateError(
                    "unable to migrate legacy relay database"
                ) from exc

    def mutate(
        self,
        operation: Callable[[sqlite3.Connection], _T],
    ) -> _T:
        """Run one protected mutation and advance only when logical state changed."""
        with self._lock:
            if self._unsafe:
                raise RelayStateError(
                    "relay state coordinator is unsafe; restart/reconcile required"
                )

            current = self._reconcile_locked()

            try:
                connection = self._connect()
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    observed, payload_before = self._state_from_connection(
                        connection
                    )
                    if observed != current:
                        raise RelayStateDivergenceError(
                            "relay state changed concurrently before mutation"
                        )

                    result = operation(connection)
                    payload_after = canonical_relay_payload(connection)

                    if payload_after == payload_before:
                        connection.commit()
                        return result

                    if current.revision >= MAX_RELAY_REVISION:
                        raise RelayStateFormatError(
                            "relay state revision is exhausted"
                        )

                    next_metadata = RelayStateMetadata(
                        relay_state_id=self.relay_state_id,
                        revision=current.revision + 1,
                        previous_digest=current.digest,
                    )
                    _write_metadata(connection, next_metadata)
                    next_checkpoint = derive_relay_checkpoint(
                        self.coordination_key,
                        next_metadata,
                        payload_after,
                    )
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
                finally:
                    connection.close()
            except RelayStateError:
                self._unsafe = True
                raise
            except sqlite3.Error as exc:
                self._unsafe = True
                raise RelayStateError(
                    "unable to commit protected relay mutation"
                ) from exc

            try:
                self.witness.compare_and_set(
                    witness_record(current),
                    witness_record(next_checkpoint),
                )
            except RelayStateError:
                self._unsafe = True
                raise

            self._checkpoint = next_checkpoint
            return result

    def require_healthy(self) -> None:
        """Fail closed when protected relay state is not currently trusted."""
        if not self.is_healthy():
            raise RelayStateError(
                "relay state coordinator is unsafe or not reconciled"
            )

    def is_healthy(self) -> bool:
        """Return whether the coordinator currently trusts its relay state."""
        return not self._unsafe and self._checkpoint is not None
