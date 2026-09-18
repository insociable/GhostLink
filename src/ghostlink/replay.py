"""Persistent replay protection for authenticated GhostLink messages."""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from ghostlink.message import (
    MESSAGE_CLOCK_SKEW_SECONDS,
    MESSAGE_MAX_LIFETIME_SECONDS,
)

REPLAY_RETENTION_SECONDS = (
    MESSAGE_MAX_LIFETIME_SECONDS + MESSAGE_CLOCK_SKEW_SECONDS
)


class ReplayCacheError(RuntimeError):
    """Raised when the persistent replay cache cannot be used safely."""


@dataclass(slots=True)
class SQLiteReplayCache:
    """Persistent replay cache scoped by sender device and message ID."""

    path: Path

    def __post_init__(self) -> None:
        if self.path.exists() and self.path.is_dir():
            raise ValueError("replay cache path must point to a file")

        self.path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with self._connect() as connection:
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
        timestamp = int(time.time()) if now is None else now
        if isinstance(timestamp, bool) or not isinstance(timestamp, int):
            raise ValueError("now must be an integer Unix timestamp")
        if timestamp < 0:
            raise ValueError("now must be non-negative")

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