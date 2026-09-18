import os
from pathlib import Path

import pytest
from ghostlink.replay import REPLAY_RETENTION_SECONDS, SQLiteReplayCache

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
