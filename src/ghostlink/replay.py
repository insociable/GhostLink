"""Persistent replay protection for authenticated GhostLink messages."""

from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from ghostlink.message_lifecycle import (
    MESSAGE_CLOCK_SKEW_SECONDS,
    MESSAGE_MAX_LIFETIME_SECONDS,
)
from ghostlink.state_witness import (
    ComponentCheckpoint,
    MonotonicWitness,
    StateCheckpointError,
    StateWitnessError,
    advance_checkpoint,
    derive_checkpoint,
    finalize_witness_bootstrap,
    reconcile_checkpoint,
    witness_record,
)

REPLAY_RETENTION_SECONDS = (
    MESSAGE_MAX_LIFETIME_SECONDS + MESSAGE_CLOCK_SKEW_SECONDS
)
_REPLAY_STATE_VERSION = 1
_MAX_REVISION = (1 << 53) - 1


class ReplayCacheError(RuntimeError):
    """Raised when the persistent replay cache cannot be used safely."""


class ReplayCache(Protocol):
    """Minimal replay-cache contract used by authenticated message delivery."""

    def has_seen(self, sender_device_id: str, message_id: str) -> bool:
        """Return whether one authenticated message ID is already retained."""

    def accept(
        self,
        sender_device_id: str,
        message_id: str,
        *,
        now: int | None = None,
    ) -> bool:
        """Atomically accept one new authenticated message ID."""


@dataclass(slots=True)
class SQLiteReplayCache:
    """Legacy/basic persistent replay cache without rollback witnessing."""

    path: Path

    def __post_init__(self) -> None:
        if self.path.exists() and self.path.is_dir():
            raise ValueError("replay cache path must point to a file")

        self.path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with self._connect() as connection:
                _create_seen_schema(connection)
        except sqlite3.Error as exc:
            raise ReplayCacheError("unable to initialize replay cache") from exc

        if os.name == "posix":
            self.path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5.0)

    def has_seen(
        self,
        sender_device_id: str,
        message_id: str,
    ) -> bool:
        """Return whether one previously authenticated message ID is retained."""
        try:
            with self._connect() as connection:
                row = connection.execute(
                    """
                    SELECT 1
                    FROM seen_messages
                    WHERE sender_device_id = ? AND message_id = ?
                    """,
                    (sender_device_id, message_id),
                ).fetchone()
        except sqlite3.Error as exc:
            raise ReplayCacheError("unable to read replay cache") from exc
        return row is not None

    def accept(
        self,
        sender_device_id: str,
        message_id: str,
        *,
        now: int | None = None,
    ) -> bool:
        """Atomically accept a new message ID or reject an already-seen replay."""
        timestamp = _validate_timestamp(now)
        cutoff = timestamp - REPLAY_RETENTION_SECONDS

        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "DELETE FROM seen_messages WHERE seen_at < ?",
                    (cutoff,),
                )
                cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO seen_messages (
                        sender_device_id,
                        message_id,
                        seen_at
                    ) VALUES (?, ?, ?)
                    """,
                    (sender_device_id, message_id, timestamp),
                )
                accepted = cursor.rowcount == 1
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise ReplayCacheError("unable to update replay cache") from exc

        return accepted


def _validate_timestamp(now: int | None) -> int:
    timestamp = int(time.time()) if now is None else now
    if isinstance(timestamp, bool) or not isinstance(timestamp, int):
        raise ValueError("now must be an integer Unix timestamp")
    if timestamp < 0:
        raise ValueError("now must be non-negative")
    return timestamp


def _create_seen_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS seen_messages (
            sender_device_id TEXT NOT NULL,
            message_id TEXT NOT NULL,
            seen_at INTEGER NOT NULL,
            PRIMARY KEY (sender_device_id, message_id)
        )
        """
    )
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_seen_messages_seen_at
        ON seen_messages (seen_at)
        """
    )


def _create_witness_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS replay_state_meta (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            state_id TEXT NOT NULL,
            revision INTEGER NOT NULL,
            previous_digest TEXT
        )
        """
    )


def _validate_state_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 32
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ReplayCacheError(
            "replay state_id must be 128-bit lowercase hexadecimal"
        )
    return value


def _validate_revision(value: object) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
        or value > _MAX_REVISION
    ):
        raise ReplayCacheError(
            "replay revision must be a positive JSON-safe integer"
        )
    return value


def _validate_previous_digest(value: object, *, revision: int) -> str | None:
    if revision == 1:
        if value is not None:
            raise ReplayCacheError(
                "initial replay state must not have a previous digest"
            )
        return None
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ReplayCacheError(
            "replay previous_digest must be 32-byte lowercase hexadecimal"
        )
    return value


@dataclass(slots=True)
class WitnessedSQLiteReplayCache:
    """Replay cache coordinated with an external monotonic witness."""

    path: Path
    state_id: str
    coordination_key: bytes
    witness: MonotonicWitness
    _allow_legacy_migration: bool = field(default=False, repr=False)
    _checkpoint: ComponentCheckpoint | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _witness_pending: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        existed = self.path.exists()
        if existed and self.path.is_dir():
            raise ValueError("replay cache path must point to a file")
        self.state_id = _validate_state_id(self.state_id)
        if (
            not isinstance(self.coordination_key, bytes)
            or len(self.coordination_key) != 32
        ):
            raise ReplayCacheError(
                "replay state coordination key must contain exactly 32 bytes"
            )

        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not existed:
            try:
                if self.witness.get("replay") is not None:
                    raise ReplayCacheError(
                        "replay cache is missing while its witness is initialized"
                    )
                self.witness.prepare_bootstrap("replay")
            except StateWitnessError as exc:
                raise ReplayCacheError(
                    f"unable to prepare replay bootstrap witness: {exc}"
                ) from exc
        try:
            with self._connect() as connection:
                _create_seen_schema(connection)
                _create_witness_schema(connection)
        except sqlite3.Error as exc:
            raise ReplayCacheError("unable to initialize replay cache") from exc

        if os.name == "posix":
            self.path.chmod(0o600)

        if not existed:
            self._initialize_new_state()
            return

        try:
            with self._connect() as connection:
                metadata = self._read_metadata(connection)
        except sqlite3.Error as exc:
            raise ReplayCacheError("unable to read replay state metadata") from exc

        if metadata is None:
            try:
                bootstrap_pending = self.witness.has_bootstrap_intent("replay")
            except StateWitnessError as exc:
                raise ReplayCacheError(
                    f"unable to read replay bootstrap witness: {exc}"
                ) from exc
            if bootstrap_pending:
                self._initialize_new_state()
                return
            if not self._allow_legacy_migration:
                raise ReplayCacheError(
                    "legacy replay cache requires explicit rollback-state migration"
                )
            self._migrate_legacy_state()
            return

        self._reconcile()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _read_metadata(
        self,
        connection: sqlite3.Connection,
    ) -> tuple[str, int, str | None] | None:
        row = connection.execute(
            """
            SELECT state_id, revision, previous_digest
            FROM replay_state_meta
            WHERE singleton = 1
            """
        ).fetchone()
        if row is None:
            return None
        if len(row) != 3:
            raise ReplayCacheError("replay state metadata shape is invalid")
        state_id = _validate_state_id(row[0])
        revision = _validate_revision(row[1])
        previous_digest = _validate_previous_digest(
            row[2],
            revision=revision,
        )
        if state_id != self.state_id:
            raise ReplayCacheError(
                "replay cache belongs to a different client state"
            )
        return state_id, revision, previous_digest

    def _payload(
        self,
        connection: sqlite3.Connection,
        *,
        state_id: str,
        revision: int,
        previous_digest: str | None,
    ) -> bytes:
        rows = connection.execute(
            """
            SELECT sender_device_id, message_id, seen_at
            FROM seen_messages
            ORDER BY sender_device_id, message_id
            """
        ).fetchall()
        messages: list[dict[str, object]] = []
        for sender_device_id, message_id, seen_at in rows:
            if not isinstance(sender_device_id, str) or not sender_device_id:
                raise ReplayCacheError("replay sender_device_id is malformed")
            if not isinstance(message_id, str) or not message_id:
                raise ReplayCacheError("replay message_id is malformed")
            if (
                not isinstance(seen_at, int)
                or isinstance(seen_at, bool)
                or seen_at < 0
            ):
                raise ReplayCacheError("replay seen_at is malformed")
            messages.append(
                {
                    "message_id": message_id,
                    "seen_at": seen_at,
                    "sender_device_id": sender_device_id,
                }
            )
        return json.dumps(
            {
                "previous_digest": previous_digest,
                "revision": revision,
                "seen_messages": messages,
                "state_id": state_id,
                "version": _REPLAY_STATE_VERSION,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")

    def _checkpoint_from_connection(
        self,
        connection: sqlite3.Connection,
    ) -> tuple[ComponentCheckpoint, bytes]:
        metadata = self._read_metadata(connection)
        if metadata is None:
            raise ReplayCacheError(
                "replay cache is missing rollback-state metadata"
            )
        state_id, revision, previous_digest = metadata
        payload = self._payload(
            connection,
            state_id=state_id,
            revision=revision,
            previous_digest=previous_digest,
        )
        try:
            checkpoint = derive_checkpoint(
                self.coordination_key,
                state_id=state_id,
                component="replay",
                revision=revision,
                previous_digest=previous_digest,
                payload=payload,
            )
        except StateCheckpointError as exc:
            raise ReplayCacheError(
                f"replay checkpoint is invalid: {exc}"
            ) from exc
        return checkpoint, payload

    def _initialize_new_state(self) -> None:
        try:
            if self.witness.get("replay") is not None:
                raise ReplayCacheError(
                    "replay cache is missing while its witness is initialized"
                )
            self.witness.prepare_bootstrap("replay")
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    INSERT INTO replay_state_meta (
                        singleton,
                        state_id,
                        revision,
                        previous_digest
                    ) VALUES (1, ?, 1, NULL)
                    """,
                    (self.state_id,),
                )
                connection.commit()
            with self._connect() as connection:
                checkpoint, payload = self._checkpoint_from_connection(connection)
            finalize_witness_bootstrap(
                self.witness,
                checkpoint,
                coordination_key=self.coordination_key,
                payload=payload,
            )
        except (sqlite3.Error, StateCheckpointError, StateWitnessError) as exc:
            raise ReplayCacheError(
                f"unable to initialize witnessed replay state: {exc}"
            ) from exc
        self._checkpoint = checkpoint

    def _migrate_legacy_state(self) -> None:
        try:
            if self.witness.get("replay") is not None:
                raise ReplayCacheError(
                    "replay witness already exists for legacy cache"
                )
            self.witness.prepare_bootstrap("replay")
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    INSERT INTO replay_state_meta (
                        singleton,
                        state_id,
                        revision,
                        previous_digest
                    ) VALUES (1, ?, 1, NULL)
                    """,
                    (self.state_id,),
                )
                connection.commit()
            with self._connect() as connection:
                checkpoint, payload = self._checkpoint_from_connection(connection)
            finalize_witness_bootstrap(
                self.witness,
                checkpoint,
                coordination_key=self.coordination_key,
                payload=payload,
            )
        except (sqlite3.Error, StateCheckpointError, StateWitnessError) as exc:
            raise ReplayCacheError(
                f"unable to migrate replay cache into witness: {exc}"
            ) from exc
        self._checkpoint = checkpoint

    def _reconcile(self) -> ComponentCheckpoint:
        if self._witness_pending:
            raise ReplayCacheError(
                "replay mutation is waiting for witness reconciliation"
            )
        try:
            with self._connect() as connection:
                checkpoint, payload = self._checkpoint_from_connection(connection)
            reconcile_checkpoint(
                self.witness,
                checkpoint,
                coordination_key=self.coordination_key,
                payload=payload,
            )
        except (sqlite3.Error, StateCheckpointError, StateWitnessError) as exc:
            raise ReplayCacheError(
                f"replay rollback verification failed: {exc}"
            ) from exc
        self._checkpoint = checkpoint
        return checkpoint

    def has_seen(
        self,
        sender_device_id: str,
        message_id: str,
    ) -> bool:
        """Check one ID only after replay-state freshness verification."""
        self._reconcile()
        try:
            with self._connect() as connection:
                row = connection.execute(
                    """
                    SELECT 1
                    FROM seen_messages
                    WHERE sender_device_id = ? AND message_id = ?
                    """,
                    (sender_device_id, message_id),
                ).fetchone()
        except sqlite3.Error as exc:
            raise ReplayCacheError("unable to read replay cache") from exc
        return row is not None

    def accept(
        self,
        sender_device_id: str,
        message_id: str,
        *,
        now: int | None = None,
    ) -> bool:
        """Accept/prune atomically, then advance the replay witness."""
        timestamp = _validate_timestamp(now)
        cutoff = timestamp - REPLAY_RETENTION_SECONDS
        current = self._reconcile()

        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                db_current, _payload = self._checkpoint_from_connection(connection)
                if db_current != current:
                    raise ReplayCacheError(
                        "replay state changed concurrently before mutation"
                    )

                deleted = connection.execute(
                    "DELETE FROM seen_messages WHERE seen_at < ?",
                    (cutoff,),
                ).rowcount
                cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO seen_messages (
                        sender_device_id,
                        message_id,
                        seen_at
                    ) VALUES (?, ?, ?)
                    """,
                    (sender_device_id, message_id, timestamp),
                )
                accepted = cursor.rowcount == 1

                if deleted == 0 and not accepted:
                    connection.commit()
                    return False

                next_revision = current.revision + 1
                connection.execute(
                    """
                    UPDATE replay_state_meta
                    SET revision = ?, previous_digest = ?
                    WHERE singleton = 1
                    """,
                    (next_revision, current.digest),
                )
                next_payload = self._payload(
                    connection,
                    state_id=self.state_id,
                    revision=next_revision,
                    previous_digest=current.digest,
                )
                next_checkpoint = advance_checkpoint(
                    self.coordination_key,
                    current,
                    next_payload,
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise ReplayCacheError("unable to update replay cache") from exc
        except StateCheckpointError as exc:
            raise ReplayCacheError(
                f"unable to advance replay checkpoint: {exc}"
            ) from exc

        try:
            self.witness.compare_and_set(
                witness_record(current),
                witness_record(next_checkpoint),
            )
        except StateWitnessError as exc:
            self._witness_pending = True
            raise ReplayCacheError(
                f"replay witness update failed after durable commit: {exc}"
            ) from exc

        self._checkpoint = next_checkpoint
        return accepted


def migrate_replay_cache_to_witness(
    path: Path,
    *,
    state_id: str,
    coordination_key: bytes,
    witness: MonotonicWitness,
) -> WitnessedSQLiteReplayCache:
    """Explicitly enroll a legacy replay database into rollback coordination."""
    return WitnessedSQLiteReplayCache(
        path,
        state_id,
        coordination_key,
        witness,
        _allow_legacy_migration=True,
    )
