from __future__ import annotations

import base64
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

from ghostlink.contact import export_lifecycle_contact_bundle, import_contact_bundle
from ghostlink.contact_store import (
    ContactTrustError,
    ContactTrustState,
    ContactTrustStore,
    load_contact_store_witnessed,
    new_witnessed_contact_store,
    save_contact_store_witnessed,
)
from ghostlink.device_lifecycle import create_device_lifecycle_statement
from ghostlink.entity import GhostEntity
from ghostlink.identity import derive_identity_fingerprint
from ghostlink.prekey_relay import RelayPreKeyGeneration, SQLitePreKeyPublicationStore
from ghostlink.relay_device_lifecycle import (
    DeviceLifecycleConflictError,
    RelayDeviceLifecycle,
    SQLiteDeviceLifecycleStore,
)
from ghostlink.relay_request_auth import SQLiteRelayRequestReplayStore
from ghostlink.relay_state import (
    RelayStateCoordinator,
    SQLiteRelayMonotonicWitness,
)
from ghostlink.relay_v3 import SQLiteV3MessageStore, V3MessageEnvelope
from ghostlink.state_witness import SQLiteMonotonicWitness
from nacl import utils
from nacl.secret import SecretBox

_STATE_ID = "00112233445566778899aabbccddeeff"
_COORDINATION_KEY = bytes(range(32))


def _ghost_id(char: str) -> str:
    return "ghost1:" + (char * 52)


def _device_id(char: str) -> str:
    return "device1:" + (char * 52)


def _lifecycle(
    ghost_char: str,
    device_char: str,
    *,
    epoch: int,
    issued_at: int,
    shared_device_id: str | None = None,
) -> RelayDeviceLifecycle:
    return RelayDeviceLifecycle(
        ghost_id=_ghost_id(ghost_char),
        epoch=epoch,
        issued_at=issued_at,
        active_device_id=shared_device_id or _device_id(device_char),
        identity_public_key=base64.b64encode(bytes([ord(ghost_char)]) * 32).decode(
            "ascii"
        ),
        statement=f"statement-{ghost_char}-{device_char}-{epoch}-{issued_at}",
    )


def _protected_relay(
    tmp_path: Path,
) -> tuple[
    RelayStateCoordinator,
    SQLiteRelayMonotonicWitness,
    SQLiteDeviceLifecycleStore,
    SQLiteV3MessageStore,
    SQLitePreKeyPublicationStore,
    SQLiteRelayRequestReplayStore,
]:
    path = tmp_path / "relay.sqlite3"

    # Create the complete protected schema before enrolling revision 1.
    SQLiteV3MessageStore(path)
    SQLitePreKeyPublicationStore(path)
    SQLiteRelayRequestReplayStore(path)
    SQLiteDeviceLifecycleStore(path)

    witness = SQLiteRelayMonotonicWitness(
        tmp_path / "relay-witness.sqlite3",
        _STATE_ID,
        _COORDINATION_KEY,
    )
    coordinator = RelayStateCoordinator(
        path,
        _STATE_ID,
        _COORDINATION_KEY,
        witness,
    )
    coordinator.migrate_legacy()

    return (
        coordinator,
        witness,
        SQLiteDeviceLifecycleStore(path, coordinator=coordinator),
        SQLiteV3MessageStore(path, coordinator=coordinator),
        SQLitePreKeyPublicationStore(path, coordinator=coordinator),
        SQLiteRelayRequestReplayStore(path, coordinator=coordinator),
    )


def _run_pair(first, second):
    barrier = Barrier(2)

    def run(operation):
        barrier.wait()
        try:
            return ("ok", operation())
        except Exception as exc:  # test captures the exact allowed conflict below
            return ("error", exc)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(run, first), executor.submit(run, second)]
        return [future.result() for future in futures]


def test_concurrent_identical_lifecycle_publication_is_idempotent(
    tmp_path: Path,
) -> None:
    coordinator, witness, lifecycle, *_rest = _protected_relay(tmp_path)
    candidate = _lifecycle("a", "b", epoch=1, issued_at=100)

    results = _run_pair(
        lambda: lifecycle.publish(candidate),
        lambda: lifecycle.publish(candidate),
    )

    assert [status for status, _value in results] == ["ok", "ok"]
    assert lifecycle.get(candidate.ghost_id) == candidate
    assert witness.get().revision == 2
    assert coordinator.is_healthy()


def test_concurrent_same_epoch_divergence_has_one_winner(
    tmp_path: Path,
) -> None:
    coordinator, witness, lifecycle, *_rest = _protected_relay(tmp_path)
    initial = _lifecycle("a", "b", epoch=1, issued_at=100)
    first = _lifecycle("a", "c", epoch=2, issued_at=200)
    second = _lifecycle("a", "d", epoch=2, issued_at=200)
    lifecycle.publish(initial)

    results = _run_pair(
        lambda: lifecycle.publish(first),
        lambda: lifecycle.publish(second),
    )

    successes = [value for status, value in results if status == "ok"]
    errors = [value for status, value in results if status == "error"]
    assert len(successes) == 1
    assert len(errors) == 1
    assert isinstance(errors[0], DeviceLifecycleConflictError)
    assert lifecycle.get(initial.ghost_id) in {first, second}
    assert witness.get().revision == 3
    assert coordinator.is_healthy()


def test_concurrent_newer_epochs_finish_at_highest_epoch(
    tmp_path: Path,
) -> None:
    coordinator, witness, lifecycle, *_rest = _protected_relay(tmp_path)
    initial = _lifecycle("a", "b", epoch=1, issued_at=100)
    epoch_two = _lifecycle("a", "c", epoch=2, issued_at=200)
    epoch_three = _lifecycle("a", "d", epoch=3, issued_at=300)
    lifecycle.publish(initial)

    results = _run_pair(
        lambda: lifecycle.publish(epoch_two),
        lambda: lifecycle.publish(epoch_three),
    )

    for status, value in results:
        if status == "error":
            assert isinstance(value, DeviceLifecycleConflictError)
    assert lifecycle.get(initial.ghost_id) == epoch_three
    assert witness.get().revision in {3, 4}
    assert coordinator.is_healthy()


def test_concurrent_stale_and_new_lifecycle_cannot_roll_back_head(
    tmp_path: Path,
) -> None:
    coordinator, _witness, lifecycle, *_rest = _protected_relay(tmp_path)
    initial = _lifecycle("a", "b", epoch=1, issued_at=100)
    newer = _lifecycle("a", "c", epoch=2, issued_at=200)
    lifecycle.publish(initial)

    results = _run_pair(
        lambda: lifecycle.publish(initial),
        lambda: lifecycle.publish(newer),
    )

    for status, value in results:
        if status == "error":
            assert isinstance(value, DeviceLifecycleConflictError)
    assert lifecycle.get(initial.ghost_id) == newer
    assert coordinator.is_healthy()


def test_concurrent_cross_identity_device_claim_has_one_owner(
    tmp_path: Path,
) -> None:
    coordinator, witness, lifecycle, *_rest = _protected_relay(tmp_path)
    shared = _device_id("z")
    first = _lifecycle(
        "a",
        "b",
        epoch=1,
        issued_at=100,
        shared_device_id=shared,
    )
    second = _lifecycle(
        "c",
        "d",
        epoch=1,
        issued_at=100,
        shared_device_id=shared,
    )

    results = _run_pair(
        lambda: lifecycle.publish(first),
        lambda: lifecycle.publish(second),
    )

    successes = [value for status, value in results if status == "ok"]
    errors = [value for status, value in results if status == "error"]
    assert len(successes) == 1
    assert len(errors) == 1
    assert isinstance(errors[0], DeviceLifecycleConflictError)
    winner = successes[0]
    assert lifecycle.get(winner.ghost_id) == winner
    loser = second if winner == first else first
    assert lifecycle.get(loser.ghost_id) is None
    assert witness.get().revision == 2
    assert coordinator.is_healthy()


def _message(message_id: str) -> V3MessageEnvelope:
    now = int(time.time())
    return V3MessageEnvelope(
        version=3,
        message_id=message_id,
        sender_device_id=_device_id("m"),
        recipient_device_id=_device_id("n"),
        created_at=now,
        expires_at=now + 3600,
        ciphertext_type=3,
        ciphertext=base64.b64encode(b"ciphertext").decode("ascii"),
    )


def test_shared_coordinator_serializes_lifecycle_and_message_mutation(
    tmp_path: Path,
) -> None:
    coordinator, witness, lifecycle, messages, *_rest = _protected_relay(tmp_path)
    record = _lifecycle("a", "b", epoch=1, issued_at=100)
    envelope = _message("1" * 32)

    results = _run_pair(
        lambda: lifecycle.publish(record),
        lambda: messages.add(envelope),
    )

    assert [status for status, _value in results] == ["ok", "ok"]
    assert lifecycle.get(record.ghost_id) == record
    assert messages.list_for_recipient(envelope.recipient_device_id) == [envelope]
    assert witness.get().revision == 3
    assert coordinator.is_healthy()


def test_shared_coordinator_serializes_lifecycle_and_prekey_mutation(
    tmp_path: Path,
) -> None:
    coordinator, witness, lifecycle, _messages, prekeys, _replay = _protected_relay(
        tmp_path
    )
    record = _lifecycle("a", "b", epoch=1, issued_at=100)
    now = int(time.time())
    generation = RelayPreKeyGeneration(
        device_id=_device_id("p"),
        publication_sequence=1,
        expires_at=now + 3600,
        publication_payload="{\"generation\":1}",
        one_time_bindings=("one",),
        fallback_binding="fallback",
    )

    results = _run_pair(
        lambda: lifecycle.publish(record),
        lambda: prekeys.publish(generation),
    )

    assert [status for status, _value in results] == ["ok", "ok"]
    assert lifecycle.get(record.ghost_id) == record
    assert prekeys.status(generation.device_id).publication_sequence == 1
    assert witness.get().revision == 3
    assert coordinator.is_healthy()


def test_shared_coordinator_serializes_lifecycle_and_request_replay_mutation(
    tmp_path: Path,
) -> None:
    coordinator, witness, lifecycle, _messages, _prekeys, replay = _protected_relay(
        tmp_path
    )
    record = _lifecycle("a", "b", epoch=1, issued_at=100)
    now = int(time.time())
    requester = _device_id("r")
    request_id = "2" * 32

    results = _run_pair(
        lambda: lifecycle.publish(record),
        lambda: replay.accept(
            requester,
            request_id,
            expires_at=now + 300,
            now=now,
        ),
    )

    assert [status for status, _value in results] == ["ok", "ok"]
    assert lifecycle.get(record.ghost_id) == record
    assert replay.accept(
        requester,
        request_id,
        expires_at=now + 300,
        now=now,
    ) is False
    assert witness.get().revision == 3
    assert coordinator.is_healthy()


def _contact_lifecycle_bundle(
    entity: GhostEntity,
    *,
    epoch: int,
    issued_at: int,
) -> str:
    signed = create_device_lifecycle_statement(
        entity,
        entity.enroll_device(),
        epoch=epoch,
        issued_at=issued_at,
    )
    return export_lifecycle_contact_bundle(entity, signed)


def _contact_fingerprint(bundle: str) -> str:
    contact = import_contact_bundle(bundle)
    return derive_identity_fingerprint(bytes(contact.identity_verify_key))


def test_concurrent_identical_contact_lifecycle_refresh_is_idempotent() -> None:
    alice = GhostEntity.generate()
    initial = _contact_lifecycle_bundle(alice, epoch=1, issued_at=100)
    replacement = _contact_lifecycle_bundle(alice, epoch=2, issued_at=200)
    store = ContactTrustStore()
    imported = store.add_contact("Alice", initial)
    verified = store.verify_identity(imported.record_id, _contact_fingerprint(initial))
    barrier = Barrier(2)

    def refresh():
        barrier.wait()
        try:
            return ("ok", store.update_contact_bundle(verified.record_id, replacement))
        except Exception as exc:
            return ("error", exc)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = [executor.submit(refresh), executor.submit(refresh)]
        resolved = [future.result() for future in results]

    assert [status for status, _value in resolved] == ["ok", "ok"]
    final = store.get(verified.record_id)
    assert final.state is ContactTrustState.VERIFIED
    assert final.current_contact.lifecycle_epoch == 2
    assert final.current_contact.device_id == import_contact_bundle(
        replacement
    ).device_id


def test_concurrent_stale_and_new_contact_refresh_cannot_roll_back() -> None:
    alice = GhostEntity.generate()
    initial = _contact_lifecycle_bundle(alice, epoch=1, issued_at=100)
    replacement = _contact_lifecycle_bundle(alice, epoch=2, issued_at=200)
    store = ContactTrustStore()
    imported = store.add_contact("Alice", initial)
    verified = store.verify_identity(imported.record_id, _contact_fingerprint(initial))
    barrier = Barrier(2)

    def refresh(bundle: str):
        barrier.wait()
        try:
            return ("ok", store.update_contact_bundle(verified.record_id, bundle))
        except Exception as exc:
            return ("error", exc)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(refresh, initial),
            executor.submit(refresh, replacement),
        ]
        results = [future.result() for future in futures]

    for status, value in results:
        if status == "error":
            assert isinstance(value, ContactTrustError)
            assert "rollback" in str(value)
    assert store.get(verified.record_id).current_contact.lifecycle_epoch == 2


def test_concurrent_same_epoch_contact_equivocation_has_one_winner() -> None:
    alice = GhostEntity.generate()
    initial = _contact_lifecycle_bundle(alice, epoch=1, issued_at=100)
    first = _contact_lifecycle_bundle(alice, epoch=2, issued_at=200)
    second = _contact_lifecycle_bundle(alice, epoch=2, issued_at=201)
    store = ContactTrustStore()
    imported = store.add_contact("Alice", initial)
    verified = store.verify_identity(imported.record_id, _contact_fingerprint(initial))
    barrier = Barrier(2)

    def refresh(bundle: str):
        barrier.wait()
        try:
            return ("ok", store.update_contact_bundle(verified.record_id, bundle))
        except Exception as exc:
            return ("error", exc)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(refresh, first), executor.submit(refresh, second)]
        results = [future.result() for future in futures]

    successes = [value for status, value in results if status == "ok"]
    errors = [value for status, value in results if status == "error"]
    assert len(successes) == 1
    assert len(errors) == 1
    assert isinstance(errors[0], ContactTrustError)
    assert "equivocation" in str(errors[0])
    final_device = store.get(verified.record_id).current_contact.device_id
    assert final_device in {
        import_contact_bundle(first).device_id,
        import_contact_bundle(second).device_id,
    }


class _BarrierWitness:
    def __init__(
        self,
        delegate: SQLiteMonotonicWitness,
        barrier: Barrier,
    ) -> None:
        self.delegate = delegate
        self.barrier = barrier

    def get(self, component):
        return self.delegate.get(component)

    def initialize(self, record) -> None:
        self.delegate.initialize(record)

    def compare_and_set(self, expected, next_record) -> None:
        self.barrier.wait()
        self.delegate.compare_and_set(expected, next_record)


def _saved_verified_contact_store(
    tmp_path: Path,
) -> tuple[Path, bytes, SQLiteMonotonicWitness, GhostEntity, str, str]:
    path = tmp_path / "contacts.sec"
    key = utils.random(SecretBox.KEY_SIZE)
    witness = SQLiteMonotonicWitness(
        tmp_path / "contacts-witness.sqlite3",
        _STATE_ID,
        _COORDINATION_KEY,
    )
    alice = GhostEntity.generate()
    initial = _contact_lifecycle_bundle(alice, epoch=1, issued_at=100)
    store = new_witnessed_contact_store(_STATE_ID)
    imported = store.add_contact("Alice", initial)
    store.verify_identity(imported.record_id, _contact_fingerprint(initial))
    save_contact_store_witnessed(
        path,
        key,
        store,
        state_id=_STATE_ID,
        coordination_key=_COORDINATION_KEY,
        witness=witness,
    )
    return path, key, witness, alice, initial, imported.record_id


def test_concurrent_identical_persistent_contact_writers_converge(
    tmp_path: Path,
) -> None:
    path, key, witness, alice, _initial, record_id = _saved_verified_contact_store(
        tmp_path
    )
    replacement = _contact_lifecycle_bundle(alice, epoch=2, issued_at=200)
    first = load_contact_store_witnessed(
        path,
        key,
        state_id=_STATE_ID,
        coordination_key=_COORDINATION_KEY,
        witness=witness,
    )
    second = load_contact_store_witnessed(
        path,
        key,
        state_id=_STATE_ID,
        coordination_key=_COORDINATION_KEY,
        witness=witness,
    )
    first.update_contact_bundle(record_id, replacement)
    second.update_contact_bundle(record_id, replacement)
    barrier = Barrier(2)

    def save(store: ContactTrustStore):
        try:
            save_contact_store_witnessed(
                path,
                key,
                store,
                state_id=_STATE_ID,
                coordination_key=_COORDINATION_KEY,
                witness=_BarrierWitness(witness, barrier),
            )
            return ("ok", None)
        except Exception as exc:
            return ("error", exc)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(save, first), executor.submit(save, second)]
        results = [future.result() for future in futures]

    statuses = sorted(status for status, _value in results)
    assert statuses == ["error", "ok"]
    error = next(value for status, value in results if status == "error")
    assert isinstance(error, ContactTrustError)
    current = load_contact_store_witnessed(
        path,
        key,
        state_id=_STATE_ID,
        coordination_key=_COORDINATION_KEY,
        witness=witness,
    )
    assert current.revision == 2
    assert current.get(record_id).current_contact.lifecycle_epoch == 2


def test_concurrent_divergent_persistent_contact_writers_never_accept_unwitnessed_state(
    tmp_path: Path,
) -> None:
    path, key, witness, alice, _initial, record_id = _saved_verified_contact_store(
        tmp_path
    )
    first_bundle = _contact_lifecycle_bundle(alice, epoch=2, issued_at=200)
    second_bundle = _contact_lifecycle_bundle(alice, epoch=2, issued_at=201)
    first = load_contact_store_witnessed(
        path,
        key,
        state_id=_STATE_ID,
        coordination_key=_COORDINATION_KEY,
        witness=witness,
    )
    second = load_contact_store_witnessed(
        path,
        key,
        state_id=_STATE_ID,
        coordination_key=_COORDINATION_KEY,
        witness=witness,
    )
    first.update_contact_bundle(record_id, first_bundle)
    second.update_contact_bundle(record_id, second_bundle)
    barrier = Barrier(2)

    def save(store: ContactTrustStore):
        try:
            save_contact_store_witnessed(
                path,
                key,
                store,
                state_id=_STATE_ID,
                coordination_key=_COORDINATION_KEY,
                witness=_BarrierWitness(witness, barrier),
            )
            return ("ok", store)
        except Exception as exc:
            return ("error", exc)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(save, first), executor.submit(save, second)]
        results = [future.result() for future in futures]

    assert sorted(status for status, _value in results) == ["error", "ok"]
    error = next(value for status, value in results if status == "error")
    assert isinstance(error, ContactTrustError)

    # There is intentionally no cross-writer file lock. If the losing writer was
    # the last atomic file replacement, reconciliation must reject that file as
    # divergent. If the winning file is last, it is accepted and matches witness.
    try:
        current = load_contact_store_witnessed(
            path,
            key,
            state_id=_STATE_ID,
            coordination_key=_COORDINATION_KEY,
            witness=witness,
        )
    except ContactTrustError as exc:
        assert "diverges" in str(exc)
    else:
        assert current.revision == 2
        assert current.get(record_id).current_contact.lifecycle_epoch == 2
