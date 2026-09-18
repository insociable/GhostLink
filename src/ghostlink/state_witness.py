"""Rollback-aware client-state checkpoint and monotonic witness primitives.

The SQLite witness in this module is a development/reference backend. It is rollback-aware
only while its database remains newer than the protected component state; a whole-machine
or filesystem snapshot can roll the witness back too.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

CHECKPOINT_VERSION = 1
WITNESS_RECORD_VERSION = 1
MAX_REVISION = (1 << 53) - 1

StateComponent = Literal["profile", "contacts", "ratchet", "replay"]
_ALLOWED_COMPONENTS = frozenset({"profile", "contacts", "ratchet", "replay"})
_HEX = frozenset("0123456789abcdef")
_CHECKPOINT_DOMAIN = b"ghostlink-client-state-checkpoint-v1\x00"
_WITNESS_RECORD_DOMAIN = b"ghostlink-client-state-witness-record-v1\x00"


class StateCheckpointError(ValueError):
    """Raised when checkpoint material is malformed."""


class StateWitnessError(RuntimeError):
    """Base class for monotonic witness failures."""


class WitnessMissingError(StateWitnessError):
    """Raised when an initialized component has no witness record."""


class WitnessConflictError(StateWitnessError):
    """Raised when witness compare-and-set observes unexpected state."""


class WitnessCorruptionError(StateWitnessError):
    """Raised when a witness record fails strict validation or authentication."""


class StateRollbackError(StateWitnessError):
    """Raised when a component is older than its monotonic witness."""


class StateDivergenceError(StateWitnessError):
    """Raised when equal or adjacent revisions do not have valid lineage."""


class WitnessGapError(StateWitnessError):
    """Raised when a component is more than one revision ahead of its witness."""


def _canonical_json(document: dict[str, object]) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def _require_coordination_key(key: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) != 32:
        raise StateCheckpointError(
            "state coordination key must contain exactly 32 bytes"
        )
    return key


def _validate_state_id(value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 32
        or value != value.lower()
        or any(character not in _HEX for character in value)
    ):
        raise StateCheckpointError(
            "client_state_id must be 128-bit lowercase hexadecimal"
        )
    return value


def _validate_component(value: str) -> StateComponent:
    if value not in _ALLOWED_COMPONENTS:
        raise StateCheckpointError("unsupported client-state component")
    return value  # type: ignore[return-value]


def _validate_revision(value: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
        or value > MAX_REVISION
    ):
        raise StateCheckpointError("revision must be a positive JSON-safe integer")
    return value


def _validate_digest(value: object, field: str = "digest") -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(character not in _HEX for character in value)
    ):
        raise StateCheckpointError(
            f"{field} must be 32-byte lowercase hexadecimal"
        )
    return value


def _checkpoint_digest(
    key: bytes,
    *,
    state_id: str,
    component: StateComponent,
    revision: int,
    previous_digest: str | None,
    payload: bytes,
) -> str:
    _require_coordination_key(key)
    _validate_state_id(state_id)
    _validate_component(component)
    _validate_revision(revision)
    if not isinstance(payload, bytes):
        raise StateCheckpointError("checkpoint payload must be bytes")
    if revision == 1:
        if previous_digest is not None:
            raise StateCheckpointError(
                "initial checkpoint must not have a previous digest"
            )
    else:
        if previous_digest is None:
            raise StateCheckpointError(
                "non-initial checkpoint requires a previous digest"
            )
        _validate_digest(previous_digest, "previous_digest")

    document: dict[str, object] = {
        "component": component,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "previous_digest": previous_digest,
        "revision": revision,
        "state_id": state_id,
        "version": CHECKPOINT_VERSION,
    }
    return hmac.new(
        key,
        _CHECKPOINT_DOMAIN + _canonical_json(document),
        hashlib.sha256,
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class ComponentCheckpoint:
    """Authenticated lineage metadata for one local-state component revision."""

    state_id: str
    component: StateComponent
    revision: int
    previous_digest: str | None
    digest: str

    def __post_init__(self) -> None:
        _validate_state_id(self.state_id)
        _validate_component(self.component)
        _validate_revision(self.revision)
        _validate_digest(self.digest)
        if self.revision == 1:
            if self.previous_digest is not None:
                raise StateCheckpointError(
                    "initial checkpoint must not have a previous digest"
                )
        elif self.previous_digest is None:
            raise StateCheckpointError(
                "non-initial checkpoint requires a previous digest"
            )
        else:
            _validate_digest(self.previous_digest, "previous_digest")


@dataclass(frozen=True, slots=True)
class WitnessRecord:
    """Latest monotonic checkpoint remembered for one component."""

    state_id: str
    component: StateComponent
    revision: int
    digest: str

    def __post_init__(self) -> None:
        _validate_state_id(self.state_id)
        _validate_component(self.component)
        _validate_revision(self.revision)
        _validate_digest(self.digest)


class MonotonicWitness(Protocol):
    """Storage contract required by rollback-aware component coordination."""

    def get(self, component: StateComponent) -> WitnessRecord | None:
        """Return the latest witnessed record for a component."""

    def initialize(self, record: WitnessRecord) -> None:
        """Initialize one component exactly once."""

    def compare_and_set(
        self,
        expected: WitnessRecord,
        next_record: WitnessRecord,
    ) -> None:
        """Atomically replace exactly the expected record with its successor."""


def create_initial_checkpoint(
    key: bytes,
    state_id: str,
    component: StateComponent,
    payload: bytes,
) -> ComponentCheckpoint:
    """Create authenticated checkpoint revision 1 for explicit migration/init."""
    digest = _checkpoint_digest(
        key,
        state_id=state_id,
        component=component,
        revision=1,
        previous_digest=None,
        payload=payload,
    )
    return ComponentCheckpoint(
        state_id=state_id,
        component=component,
        revision=1,
        previous_digest=None,
        digest=digest,
    )


def advance_checkpoint(
    key: bytes,
    current: ComponentCheckpoint,
    payload: bytes,
) -> ComponentCheckpoint:
    """Create the exactly next authenticated component checkpoint."""
    if current.revision >= MAX_REVISION:
        raise StateCheckpointError("checkpoint revision is exhausted")
    revision = current.revision + 1
    digest = _checkpoint_digest(
        key,
        state_id=current.state_id,
        component=current.component,
        revision=revision,
        previous_digest=current.digest,
        payload=payload,
    )
    return ComponentCheckpoint(
        state_id=current.state_id,
        component=current.component,
        revision=revision,
        previous_digest=current.digest,
        digest=digest,
    )


def witness_record(checkpoint: ComponentCheckpoint) -> WitnessRecord:
    """Project a component checkpoint into its monotonic witness record."""
    return WitnessRecord(
        state_id=checkpoint.state_id,
        component=checkpoint.component,
        revision=checkpoint.revision,
        digest=checkpoint.digest,
    )


def verify_checkpoint(
    coordination_key: bytes,
    checkpoint: ComponentCheckpoint,
    payload: bytes,
) -> None:
    """Authenticate checkpoint metadata against the exact component payload."""
    expected_digest = _checkpoint_digest(
        coordination_key,
        state_id=checkpoint.state_id,
        component=checkpoint.component,
        revision=checkpoint.revision,
        previous_digest=checkpoint.previous_digest,
        payload=payload,
    )
    if not hmac.compare_digest(expected_digest, checkpoint.digest):
        raise StateCheckpointError(
            "checkpoint digest does not authenticate component payload"
        )


def initialize_witness(
    witness: MonotonicWitness,
    checkpoint: ComponentCheckpoint,
    *,
    coordination_key: bytes,
    payload: bytes,
) -> None:
    """Explicitly initialize a witness from authenticated checkpoint revision 1."""
    verify_checkpoint(coordination_key, checkpoint, payload)
    if checkpoint.revision != 1 or checkpoint.previous_digest is not None:
        raise StateCheckpointError(
            "witness initialization requires an initial checkpoint"
        )
    witness.initialize(witness_record(checkpoint))


def reconcile_checkpoint(
    witness: MonotonicWitness,
    checkpoint: ComponentCheckpoint,
    *,
    coordination_key: bytes,
    payload: bytes,
) -> Literal["current", "witness_advanced"]:
    """Authenticate freshness and perform the sole crash-safe one-step catch-up."""
    verify_checkpoint(coordination_key, checkpoint, payload)
    current = witness.get(checkpoint.component)
    if current is None:
        raise WitnessMissingError(
            "required monotonic witness record is missing"
        )
    if (
        current.state_id != checkpoint.state_id
        or current.component != checkpoint.component
    ):
        raise WitnessCorruptionError(
            "witness record is bound to different client state"
        )

    if checkpoint.revision < current.revision:
        raise StateRollbackError(
            "component revision is older than monotonic witness"
        )

    if checkpoint.revision == current.revision:
        if not hmac.compare_digest(checkpoint.digest, current.digest):
            raise StateDivergenceError(
                "component digest diverges at witnessed revision"
            )
        return "current"

    if checkpoint.revision > current.revision + 1:
        raise WitnessGapError(
            "component is more than one revision ahead of witness"
        )

    if checkpoint.previous_digest is None or not hmac.compare_digest(
        checkpoint.previous_digest,
        current.digest,
    ):
        raise StateDivergenceError(
            "component successor does not link to witnessed digest"
        )

    witness.compare_and_set(current, witness_record(checkpoint))
    return "witness_advanced"


@dataclass(slots=True)
class SQLiteMonotonicWitness:
    """Authenticated file-backed witness for development and deterministic tests."""

    path: Path
    state_id: str
    coordination_key: bytes

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        _validate_state_id(self.state_id)
        _require_coordination_key(self.coordination_key)
        if self.path.exists() and self.path.is_dir():
            raise ValueError("witness path must point to a file")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS witness_records (
                        state_id TEXT NOT NULL,
                        component TEXT NOT NULL,
                        revision INTEGER NOT NULL,
                        digest TEXT NOT NULL,
                        record_mac TEXT NOT NULL,
                        PRIMARY KEY (state_id, component)
                    )
                    """
                )
        except sqlite3.Error as exc:
            raise StateWitnessError(
                "unable to initialize monotonic witness"
            ) from exc
        if os.name == "posix":
            self.path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _record_mac(self, record: WitnessRecord) -> str:
        document: dict[str, object] = {
            "component": record.component,
            "digest": record.digest,
            "revision": record.revision,
            "state_id": record.state_id,
            "version": WITNESS_RECORD_VERSION,
        }
        return hmac.new(
            self.coordination_key,
            _WITNESS_RECORD_DOMAIN + _canonical_json(document),
            hashlib.sha256,
        ).hexdigest()

    def _decode_row(
        self,
        component: StateComponent,
        row: tuple[object, ...],
    ) -> WitnessRecord:
        if len(row) != 3:
            raise WitnessCorruptionError("witness row shape is invalid")
        revision, digest, record_mac = row
        try:
            record = WitnessRecord(
                state_id=self.state_id,
                component=component,
                revision=revision,  # type: ignore[arg-type]
                digest=digest,  # type: ignore[arg-type]
            )
            validated_mac = _validate_digest(record_mac, "record_mac")
        except StateCheckpointError as exc:
            raise WitnessCorruptionError(
                "witness record is malformed"
            ) from exc
        expected_mac = self._record_mac(record)
        if not hmac.compare_digest(expected_mac, validated_mac):
            raise WitnessCorruptionError(
                "witness record authentication failed"
            )
        return record

    def _read_record(
        self,
        connection: sqlite3.Connection,
        component: StateComponent,
    ) -> WitnessRecord | None:
        row = connection.execute(
            """
            SELECT revision, digest, record_mac
            FROM witness_records
            WHERE state_id = ? AND component = ?
            """,
            (self.state_id, component),
        ).fetchone()
        if row is None:
            return None
        return self._decode_row(component, row)

    def get(self, component: StateComponent) -> WitnessRecord | None:
        """Read and authenticate the current witness record."""
        component = _validate_component(component)
        try:
            with self._connect() as connection:
                return self._read_record(connection, component)
        except sqlite3.Error as exc:
            raise StateWitnessError(
                "unable to read monotonic witness"
            ) from exc

    def _validate_scoped_record(self, record: WitnessRecord) -> None:
        if record.state_id != self.state_id:
            raise StateCheckpointError(
                "witness record belongs to a different client_state_id"
            )

    def initialize(self, record: WitnessRecord) -> None:
        """Initialize one component record exactly once at revision 1."""
        self._validate_scoped_record(record)
        if record.revision != 1:
            raise StateCheckpointError(
                "witness initialization requires revision 1"
            )
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                if self._read_record(connection, record.component) is not None:
                    raise WitnessConflictError(
                        "monotonic witness is already initialized"
                    )
                connection.execute(
                    """
                    INSERT INTO witness_records (
                        state_id,
                        component,
                        revision,
                        digest,
                        record_mac
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        record.state_id,
                        record.component,
                        record.revision,
                        record.digest,
                        self._record_mac(record),
                    ),
                )
        except sqlite3.Error as exc:
            raise StateWitnessError(
                "unable to initialize witness record"
            ) from exc

    def compare_and_set(
        self,
        expected: WitnessRecord,
        next_record: WitnessRecord,
    ) -> None:
        """Atomically advance an exact record by one revision."""
        self._validate_scoped_record(expected)
        self._validate_scoped_record(next_record)
        if expected.component != next_record.component:
            raise StateCheckpointError(
                "witness transition changes component"
            )
        if next_record.revision != expected.revision + 1:
            raise StateCheckpointError(
                "witness transition must advance exactly one revision"
            )
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                current = self._read_record(
                    connection,
                    expected.component,
                )
                if current is None:
                    raise WitnessMissingError(
                        "required monotonic witness record is missing"
                    )
                if current != expected:
                    raise WitnessConflictError(
                        "monotonic witness compare-and-set conflict"
                    )
                connection.execute(
                    """
                    UPDATE witness_records
                    SET revision = ?, digest = ?, record_mac = ?
                    WHERE state_id = ? AND component = ?
                    """,
                    (
                        next_record.revision,
                        next_record.digest,
                        self._record_mac(next_record),
                        self.state_id,
                        next_record.component,
                    ),
                )
        except sqlite3.Error as exc:
            raise StateWitnessError(
                "unable to advance monotonic witness"
            ) from exc
