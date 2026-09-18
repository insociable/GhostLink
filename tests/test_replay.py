import os
from pathlib import Path

import pytest
from ghostlink.replay import (
    REPLAY_RETENTION_SECONDS,
    ReplayCacheError,
    SQLiteReplayCache,
    WitnessedSQLiteReplayCache,
    migrate_replay_cache_to_witness,
)
from ghostlink.state_witness import (
    SQLiteMonotonicWitness,
    StateWitnessError,
)

ALICE_DEVICE_ID = "device1:" + ("a" * 52)
BOB_DEVICE_ID = "device1:" + ("b" * 52)
MESSAGE_ID = "1" * 32


def test_replay_cache_accepts_message_only_once(tmp_path: Path) -> None:
    cache = SQLiteReplayCache(tmp_path / "replay.sqlite3")

    assert cache.accept(ALICE_DEVICE_ID, MESSAGE_ID, now=1_000_000)
    assert not cache.accept(ALICE_DEVICE_ID, MESSAGE_ID, now=1_000_001)


def test_replay_cache_is_scoped_by_sender_device(tmp_path: Path) -> None:
    cache = SQLiteReplayCache(tmp_path / "replay.sqlite3")

    assert cache.accept(ALICE_DEVICE_ID, MESSAGE_ID, now=1_000_000)
    assert cache.accept(BOB_DEVICE_ID, MESSAGE_ID, now=1_000_000)


def test_replay_cache_survives_recreation(tmp_path: Path) -> None:
    path = tmp_path / "replay.sqlite3"

    first = SQLiteReplayCache(path)
    assert first.accept(ALICE_DEVICE_ID, MESSAGE_ID, now=1_000_000)

    second = SQLiteReplayCache(path)
    assert not second.accept(ALICE_DEVICE_ID, MESSAGE_ID, now=1_000_001)


def test_replay_entries_are_retained_for_protocol_window(tmp_path: Path) -> None:
    cache = SQLiteReplayCache(tmp_path / "replay.sqlite3")
    start = 1_000_000

    assert cache.accept(ALICE_DEVICE_ID, MESSAGE_ID, now=start)
    assert not cache.accept(
        ALICE_DEVICE_ID,
        MESSAGE_ID,
        now=start + REPLAY_RETENTION_SECONDS,
    )
    assert cache.accept(
        ALICE_DEVICE_ID,
        MESSAGE_ID,
        now=start + REPLAY_RETENTION_SECONDS + 1,
    )


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_replay_database_is_private_on_posix(tmp_path: Path) -> None:
    path = tmp_path / "replay.sqlite3"

    SQLiteReplayCache(path)

    assert path.stat().st_mode & 0o777 == 0o600


def test_replay_database_path_cannot_be_directory(tmp_path: Path) -> None:
    directory = tmp_path / "replay"
    directory.mkdir()

    with pytest.raises(ValueError, match="must point to a file"):
        SQLiteReplayCache(directory)


def test_replay_cache_can_precheck_already_authenticated_id(
    tmp_path: Path,
) -> None:
    cache = SQLiteReplayCache(tmp_path / "replay.sqlite3")

    assert not cache.has_seen(ALICE_DEVICE_ID, MESSAGE_ID)
    assert cache.accept(ALICE_DEVICE_ID, MESSAGE_ID, now=1_000_000)
    assert cache.has_seen(ALICE_DEVICE_ID, MESSAGE_ID)
    assert not cache.has_seen(BOB_DEVICE_ID, MESSAGE_ID)


_STATE_ID = "00112233445566778899aabbccddeeff"
_COORDINATION_KEY = bytes(range(32))


def _replay_witness(tmp_path: Path) -> SQLiteMonotonicWitness:
    return SQLiteMonotonicWitness(
        tmp_path / "replay-witness.sqlite3",
        _STATE_ID,
        _COORDINATION_KEY,
    )


def test_witnessed_replay_cache_advances_witness_on_accept(tmp_path: Path) -> None:
    path = tmp_path / "replay.sqlite3"
    witness = _replay_witness(tmp_path)
    cache = WitnessedSQLiteReplayCache(
        path,
        _STATE_ID,
        _COORDINATION_KEY,
        witness,
    )

    assert witness.get("replay").revision == 1
    assert cache.accept(ALICE_DEVICE_ID, MESSAGE_ID, now=1_000_000)
    assert witness.get("replay").revision == 2
    assert cache.has_seen(ALICE_DEVICE_ID, MESSAGE_ID)


def test_witnessed_replay_cache_detects_database_rollback(tmp_path: Path) -> None:
    path = tmp_path / "replay.sqlite3"
    witness = _replay_witness(tmp_path)
    cache = WitnessedSQLiteReplayCache(
        path,
        _STATE_ID,
        _COORDINATION_KEY,
        witness,
    )
    assert cache.accept(ALICE_DEVICE_ID, MESSAGE_ID, now=1_000_000)
    revision_two = path.read_bytes()

    assert cache.accept(
        ALICE_DEVICE_ID,
        "2" * 32,
        now=1_000_001,
    )
    assert witness.get("replay").revision == 3

    path.write_bytes(revision_two)

    with pytest.raises(ReplayCacheError, match="older than monotonic witness"):
        WitnessedSQLiteReplayCache(
            path,
            _STATE_ID,
            _COORDINATION_KEY,
            witness,
        )


def test_witnessed_replay_cache_detects_same_revision_divergence(
    tmp_path: Path,
) -> None:
    import sqlite3

    path = tmp_path / "replay.sqlite3"
    witness = _replay_witness(tmp_path)
    cache = WitnessedSQLiteReplayCache(
        path,
        _STATE_ID,
        _COORDINATION_KEY,
        witness,
    )
    assert cache.accept(ALICE_DEVICE_ID, MESSAGE_ID, now=1_000_000)

    with sqlite3.connect(path) as connection:
        connection.execute("DELETE FROM seen_messages")

    with pytest.raises(ReplayCacheError, match="digest diverges"):
        WitnessedSQLiteReplayCache(
            path,
            _STATE_ID,
            _COORDINATION_KEY,
            witness,
        )


def test_missing_replay_database_fails_when_witness_exists(tmp_path: Path) -> None:
    path = tmp_path / "replay.sqlite3"
    witness = _replay_witness(tmp_path)
    WitnessedSQLiteReplayCache(
        path,
        _STATE_ID,
        _COORDINATION_KEY,
        witness,
    )
    path.unlink()

    with pytest.raises(
        ReplayCacheError,
        match="missing while its witness is initialized",
    ):
        WitnessedSQLiteReplayCache(
            path,
            _STATE_ID,
            _COORDINATION_KEY,
            witness,
        )


def test_legacy_replay_cache_requires_explicit_migration(tmp_path: Path) -> None:
    path = tmp_path / "replay.sqlite3"
    witness = _replay_witness(tmp_path)
    legacy = SQLiteReplayCache(path)
    assert legacy.accept(ALICE_DEVICE_ID, MESSAGE_ID, now=1_000_000)

    with pytest.raises(
        ReplayCacheError,
        match="requires explicit rollback-state migration",
    ):
        WitnessedSQLiteReplayCache(
            path,
            _STATE_ID,
            _COORDINATION_KEY,
            witness,
        )

    migrated = migrate_replay_cache_to_witness(
        path,
        state_id=_STATE_ID,
        coordination_key=_COORDINATION_KEY,
        witness=witness,
    )
    assert migrated.has_seen(ALICE_DEVICE_ID, MESSAGE_ID)
    assert witness.get("replay").revision == 1


class _FailingReplayWitness:
    def __init__(self, delegate: SQLiteMonotonicWitness) -> None:
        self.delegate = delegate

    def get(self, component):
        return self.delegate.get(component)

    def initialize(self, record) -> None:
        self.delegate.initialize(record)

    def compare_and_set(self, expected, next_record) -> None:
        raise StateWitnessError("simulated replay witness failure")


def test_replay_cache_recovers_one_step_after_witness_commit_crash(
    tmp_path: Path,
) -> None:
    path = tmp_path / "replay.sqlite3"
    witness = _replay_witness(tmp_path)
    cache = WitnessedSQLiteReplayCache(
        path,
        _STATE_ID,
        _COORDINATION_KEY,
        _FailingReplayWitness(witness),
    )

    with pytest.raises(
        ReplayCacheError,
        match="simulated replay witness failure",
    ):
        cache.accept(ALICE_DEVICE_ID, MESSAGE_ID, now=1_000_000)

    assert witness.get("replay").revision == 1

    recovered = WitnessedSQLiteReplayCache(
        path,
        _STATE_ID,
        _COORDINATION_KEY,
        witness,
    )
    assert recovered.has_seen(ALICE_DEVICE_ID, MESSAGE_ID)
    assert witness.get("replay").revision == 2
