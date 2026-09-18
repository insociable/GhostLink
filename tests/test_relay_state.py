from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

import pytest
from ghostlink.prekey_relay import (
    RelayPreKeyGeneration,
    SQLitePreKeyPublicationStore,
)
from ghostlink.relay_request_auth import SQLiteRelayRequestReplayStore
from ghostlink.relay_state import (
    RelayStateCoordinator,
    RelayStateDivergenceError,
    RelayStateError,
    RelayStateGapError,
    RelayStateLegacyError,
    RelayStateRollbackError,
    RelayWitnessError,
    RelayWitnessMissingError,
    SQLiteRelayMonotonicWitness,
    canonical_relay_payload,
)
from ghostlink.relay_v3 import SQLiteV3MessageStore, V3MessageEnvelope

_STATE_ID = "00112233445566778899aabbccddeeff"
_COORDINATION_KEY = bytes(range(32))


def _initialize_protected_schema(path: Path) -> None:
    SQLiteV3MessageStore(path)
    SQLitePreKeyPublicationStore(path)
    SQLiteRelayRequestReplayStore(path)


def _witness(tmp_path: Path) -> SQLiteRelayMonotonicWitness:
    return SQLiteRelayMonotonicWitness(
        tmp_path / "relay-witness.sqlite3",
        _STATE_ID,
        _COORDINATION_KEY,
    )


def _coordinator(
    tmp_path: Path,
    path: Path,
    *,
    witness=None,
) -> RelayStateCoordinator:
    return RelayStateCoordinator(
        path,
        _STATE_ID,
        _COORDINATION_KEY,
        witness or _witness(tmp_path),
    )


def _insert_message(connection: sqlite3.Connection, message_id: str) -> None:
    connection.execute(
        """
        INSERT INTO messages_v3 (
            message_id,
            version,
            sender_device_id,
            recipient_device_id,
            created_at,
            expires_at,
            ciphertext_type,
            ciphertext
        ) VALUES (?, 3, ?, ?, 1000, 2000, 3, ?)
        """,
        (
            message_id,
            "device1:" + ("a" * 52),
            "device1:" + ("b" * 52),
            "Y2lwaGVydGV4dA==",
        ),
    )


def test_canonical_relay_payload_is_strict_and_ignores_unprotected_tables(
    tmp_path: Path,
) -> None:
    path = tmp_path / "relay.sqlite3"
    _initialize_protected_schema(path)

    with sqlite3.connect(path) as connection:
        before = canonical_relay_payload(connection)
        document = json.loads(before.decode("ascii"))
        assert document["version"] == 1
        assert [table["name"] for table in document["tables"]] == [
            "messages_v3",
            "prekey_publications",
            "prekey_one_time",
            "prekey_allocations",
            "prekey_fetch_events",
            "relay_request_replay_v1",
        ]

        connection.execute(
            """
            CREATE TABLE messages_v2 (
                message_id TEXT PRIMARY KEY,
                body TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "INSERT INTO messages_v2 (message_id, body) VALUES ('legacy', 'x')"
        )
        after = canonical_relay_payload(connection)

    assert after == before


def test_canonical_relay_payload_rejects_protected_schema_change(
    tmp_path: Path,
) -> None:
    path = tmp_path / "relay.sqlite3"
    _initialize_protected_schema(path)

    with sqlite3.connect(path) as connection:
        connection.execute(
            "ALTER TABLE messages_v3 ADD COLUMN unexpected TEXT"
        )
        with pytest.raises(
            Exception,
            match="protected relay table schema is invalid",
        ):
            canonical_relay_payload(connection)


def test_legacy_relay_database_requires_explicit_migration(
    tmp_path: Path,
) -> None:
    path = tmp_path / "relay.sqlite3"
    _initialize_protected_schema(path)

    coordinator = _coordinator(tmp_path, path)
    with pytest.raises(
        RelayStateLegacyError,
        match="requires explicit rollback-state migration",
    ):
        coordinator.reconcile()


def test_relay_state_migration_initializes_revision_one(
    tmp_path: Path,
) -> None:
    path = tmp_path / "relay.sqlite3"
    _initialize_protected_schema(path)
    witness = _witness(tmp_path)
    coordinator = _coordinator(tmp_path, path, witness=witness)

    checkpoint = coordinator.migrate_legacy()

    assert checkpoint.revision == 1
    assert checkpoint.previous_digest is None
    assert witness.get() is not None
    assert witness.get().revision == 1
    assert coordinator.reconcile() == checkpoint
    assert coordinator.is_healthy()


def test_noop_mutation_does_not_advance_relay_revision(tmp_path: Path) -> None:
    path = tmp_path / "relay.sqlite3"
    _initialize_protected_schema(path)
    witness = _witness(tmp_path)
    coordinator = _coordinator(tmp_path, path, witness=witness)
    coordinator.migrate_legacy()

    result = coordinator.mutate(lambda connection: "unchanged")

    assert result == "unchanged"
    assert witness.get().revision == 1
    assert coordinator.reconcile().revision == 1


def test_protected_mutation_advances_database_and_witness_together(
    tmp_path: Path,
) -> None:
    path = tmp_path / "relay.sqlite3"
    _initialize_protected_schema(path)
    witness = _witness(tmp_path)
    coordinator = _coordinator(tmp_path, path, witness=witness)
    first = coordinator.migrate_legacy()

    def operation(connection: sqlite3.Connection) -> str:
        _insert_message(connection, "1" * 32)
        return "inserted"

    assert coordinator.mutate(operation) == "inserted"
    current = witness.get()
    assert current is not None
    assert current.revision == 2

    reopened = _coordinator(tmp_path, path, witness=witness)
    checkpoint = reopened.reconcile()
    assert checkpoint.revision == 2
    assert checkpoint.previous_digest == first.digest


def test_relay_database_snapshot_rollback_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "relay.sqlite3"
    _initialize_protected_schema(path)
    witness = _witness(tmp_path)
    coordinator = _coordinator(tmp_path, path, witness=witness)
    coordinator.migrate_legacy()
    revision_one = path.read_bytes()

    def operation(connection: sqlite3.Connection) -> None:
        _insert_message(connection, "2" * 32)

    coordinator.mutate(operation)
    assert witness.get().revision == 2

    path.write_bytes(revision_one)

    reopened = _coordinator(tmp_path, path, witness=witness)
    with pytest.raises(
        RelayStateRollbackError,
        match="older than monotonic witness",
    ):
        reopened.reconcile()


def test_same_revision_relay_divergence_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "relay.sqlite3"
    _initialize_protected_schema(path)
    witness = _witness(tmp_path)
    coordinator = _coordinator(tmp_path, path, witness=witness)
    coordinator.migrate_legacy()

    with sqlite3.connect(path) as connection:
        _insert_message(connection, "3" * 32)

    reopened = _coordinator(tmp_path, path, witness=witness)
    with pytest.raises(
        RelayStateDivergenceError,
        match="digest diverges",
    ):
        reopened.reconcile()


def test_relay_revision_gap_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "relay.sqlite3"
    _initialize_protected_schema(path)
    witness = _witness(tmp_path)
    coordinator = _coordinator(tmp_path, path, witness=witness)
    coordinator.migrate_legacy()
    current = witness.get()
    assert current is not None

    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            UPDATE relay_state_meta_v1
            SET revision = 3, previous_digest = ?
            WHERE singleton = 1
            """,
            (current.digest,),
        )

    reopened = _coordinator(tmp_path, path, witness=witness)
    with pytest.raises(
        RelayStateGapError,
        match="more than one revision ahead",
    ):
        reopened.reconcile()


def test_missing_enrolled_relay_witness_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "relay.sqlite3"
    witness_path = tmp_path / "relay-witness.sqlite3"
    _initialize_protected_schema(path)
    witness = SQLiteRelayMonotonicWitness(
        witness_path,
        _STATE_ID,
        _COORDINATION_KEY,
    )
    coordinator = _coordinator(tmp_path, path, witness=witness)
    coordinator.migrate_legacy()

    with sqlite3.connect(witness_path) as connection:
        connection.execute(
            "DELETE FROM relay_witness_v1 WHERE relay_state_id = ?",
            (_STATE_ID,),
        )

    reopened = _coordinator(tmp_path, path, witness=witness)
    with pytest.raises(
        RelayWitnessMissingError,
        match="required relay monotonic witness record is missing",
    ):
        reopened.reconcile()


class _FailingWitness:
    def __init__(self, delegate: SQLiteRelayMonotonicWitness) -> None:
        self.delegate = delegate
        self.fail_compare = False

    def get(self):
        return self.delegate.get()

    def initialize(self, record) -> None:
        self.delegate.initialize(record)

    def compare_and_set(self, expected, next_record) -> None:
        if self.fail_compare:
            raise RelayWitnessError("simulated relay witness failure")
        self.delegate.compare_and_set(expected, next_record)


def test_relay_state_recovers_one_step_after_witness_commit_crash(
    tmp_path: Path,
) -> None:
    path = tmp_path / "relay.sqlite3"
    _initialize_protected_schema(path)
    delegate = _witness(tmp_path)
    failing = _FailingWitness(delegate)
    coordinator = _coordinator(tmp_path, path, witness=failing)
    coordinator.migrate_legacy()

    failing.fail_compare = True

    def operation(connection: sqlite3.Connection) -> None:
        _insert_message(connection, "4" * 32)

    with pytest.raises(
        RelayWitnessError,
        match="simulated relay witness failure",
    ):
        coordinator.mutate(operation)

    assert delegate.get().revision == 1
    assert not coordinator.is_healthy()

    recovered = _coordinator(tmp_path, path, witness=delegate)
    checkpoint = recovered.reconcile()

    assert checkpoint.revision == 2
    assert delegate.get().revision == 2
    assert recovered.is_healthy()


def test_shared_relay_coordinator_advances_across_all_persistent_stores(
    tmp_path: Path,
) -> None:
    path = tmp_path / "relay.sqlite3"
    _initialize_protected_schema(path)
    witness = _witness(tmp_path)
    coordinator = _coordinator(tmp_path, path, witness=witness)
    coordinator.migrate_legacy()

    message_store = SQLiteV3MessageStore(path, coordinator=coordinator)
    prekey_store = SQLitePreKeyPublicationStore(path, coordinator=coordinator)
    replay_store = SQLiteRelayRequestReplayStore(path, coordinator=coordinator)

    now = int(time.time())
    envelope = V3MessageEnvelope(
        version=3,
        message_id="a" * 32,
        sender_device_id="device1:" + ("a" * 52),
        recipient_device_id="device1:" + ("b" * 52),
        created_at=now,
        expires_at=now + 3_600,
        ciphertext_type=3,
        ciphertext="Y2lwaGVydGV4dA==",
    )
    message_store.add(envelope)
    assert witness.get().revision == 2

    message_store.add(envelope)
    assert witness.get().revision == 2

    target_device_id = "device1:" + ("c" * 52)
    requester_device_id = "device1:" + ("d" * 52)
    prekey_store.publish(
        RelayPreKeyGeneration(
            device_id=target_device_id,
            publication_sequence=1,
            expires_at=now + 3_600,
            publication_payload='{"generation":1}',
            one_time_bindings=("one",),
            fallback_binding="fallback",
        )
    )
    assert witness.get().revision == 3

    fetched = prekey_store.fetch(
        target_device_id,
        requester_device_id,
        "1" * 32,
        now=now,
    )
    assert fetched.bundle_kind == "one_time"
    assert witness.get().revision == 4

    assert replay_store.accept(
        requester_device_id,
        "2" * 32,
        expires_at=now + 300,
        now=now,
    )
    assert witness.get().revision == 5

    assert not replay_store.accept(
        requester_device_id,
        "2" * 32,
        expires_at=now + 300,
        now=now,
    )
    assert witness.get().revision == 5

    assert message_store.delete(envelope.recipient_device_id, envelope.message_id)
    assert witness.get().revision == 6
    assert message_store.is_healthy()
    assert prekey_store.is_healthy()
    assert replay_store.is_healthy()


def test_shared_relay_coordinator_latches_all_stores_unsafe_after_witness_failure(
    tmp_path: Path,
) -> None:
    path = tmp_path / "relay.sqlite3"
    _initialize_protected_schema(path)
    delegate = _witness(tmp_path)
    failing = _FailingWitness(delegate)
    coordinator = _coordinator(tmp_path, path, witness=failing)
    coordinator.migrate_legacy()

    message_store = SQLiteV3MessageStore(path, coordinator=coordinator)
    prekey_store = SQLitePreKeyPublicationStore(path, coordinator=coordinator)
    replay_store = SQLiteRelayRequestReplayStore(path, coordinator=coordinator)

    failing.fail_compare = True
    now = int(time.time())
    envelope = V3MessageEnvelope(
        version=3,
        message_id="b" * 32,
        sender_device_id="device1:" + ("a" * 52),
        recipient_device_id="device1:" + ("b" * 52),
        created_at=now,
        expires_at=now + 3_600,
        ciphertext_type=3,
        ciphertext="Y2lwaGVydGV4dA==",
    )

    with pytest.raises(RelayWitnessError, match="simulated relay witness failure"):
        message_store.add(envelope)

    assert not message_store.is_healthy()
    assert not prekey_store.is_healthy()
    assert not replay_store.is_healthy()

    with pytest.raises(RelayStateError, match="unsafe or not reconciled"):
        prekey_store.status("device1:" + ("c" * 52))
