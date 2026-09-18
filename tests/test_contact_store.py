import base64
import json
import os
import stat

import pytest
from ghostlink.contact import export_contact_bundle, import_contact_bundle
from ghostlink.contact_store import (
    ContactTrustError,
    ContactTrustState,
    ContactTrustStore,
    decrypt_contact_store,
    encrypt_contact_store,
    load_contact_store,
    load_contact_store_witnessed,
    migrate_contact_store_to_witness,
    new_witnessed_contact_store,
    save_contact_store,
    save_contact_store_witnessed,
)
from ghostlink.entity import GhostEntity
from ghostlink.identity import derive_identity_fingerprint
from ghostlink.state_witness import (
    SQLiteMonotonicWitness,
    StateWitnessError,
)
from nacl import utils
from nacl.secret import SecretBox


def _identity_bundle(entity: GhostEntity | None = None) -> tuple[GhostEntity, str]:
    owner = GhostEntity.generate() if entity is None else entity
    device = owner.enroll_device()
    return owner, export_contact_bundle(owner, device)


def _fingerprint(bundle: str) -> str:
    contact = import_contact_bundle(bundle)
    return derive_identity_fingerprint(bytes(contact.identity_verify_key))


def test_new_contact_is_imported_but_not_human_verified() -> None:
    _alice, bundle = _identity_bundle()
    store = ContactTrustStore()

    record = store.add_contact("Alice", bundle)

    assert record.state is ContactTrustState.IMPORTED
    assert record.pinned_ghost_id is None
    assert record.candidate_bundle is None
    assert len(record.record_id) == 32
    with pytest.raises(
        ContactTrustError,
        match="has not been human-verified",
    ):
        store.require_verified_contact(record.record_id)


def test_complete_fingerprint_promotes_imported_contact_to_verified() -> None:
    _alice, bundle = _identity_bundle()
    store = ContactTrustStore()
    imported = store.add_contact("Alice", bundle)

    verified = store.verify_identity(imported.record_id, _fingerprint(bundle))

    assert verified.state is ContactTrustState.VERIFIED
    assert verified.pinned_ghost_id == verified.current_contact.ghost_id
    trusted = store.require_verified_contact(imported.record_id)
    assert trusted.ghost_id == verified.pinned_ghost_id


def test_wrong_fingerprint_cannot_promote_contact() -> None:
    _alice, bundle = _identity_bundle()
    store = ContactTrustStore()
    imported = store.add_contact("Alice", bundle)

    with pytest.raises(ContactTrustError, match="fingerprint does not match"):
        store.verify_identity(imported.record_id, "GLF2:" + ("A" * 52))

    assert store.get(imported.record_id).state is ContactTrustState.IMPORTED


def test_unverified_identity_replacement_remains_imported() -> None:
    _alice, alice_bundle = _identity_bundle()
    _bob, bob_bundle = _identity_bundle()
    store = ContactTrustStore()
    imported = store.add_contact("Peer", alice_bundle)

    updated = store.update_contact_bundle(imported.record_id, bob_bundle)

    assert updated.state is ContactTrustState.IMPORTED
    assert updated.pinned_ghost_id is None
    assert updated.current_contact.ghost_id == import_contact_bundle(
        bob_bundle
    ).ghost_id


def test_verified_same_identity_can_update_device_without_losing_trust() -> None:
    alice = GhostEntity.generate()
    _alice, first_bundle = _identity_bundle(alice)
    _alice, second_bundle = _identity_bundle(alice)
    store = ContactTrustStore()
    imported = store.add_contact("Alice", first_bundle)
    verified = store.verify_identity(imported.record_id, _fingerprint(first_bundle))

    updated = store.update_contact_bundle(verified.record_id, second_bundle)

    assert updated.state is ContactTrustState.VERIFIED
    assert updated.pinned_ghost_id == verified.pinned_ghost_id
    assert updated.current_contact.device_id != verified.current_contact.device_id
    assert (
        store.require_verified_contact(updated.record_id).device_id
        == updated.current_contact.device_id
    )


def test_verified_identity_change_is_quarantined_and_blocks_trusted_use() -> None:
    _alice, alice_bundle = _identity_bundle()
    _mallory, replacement_bundle = _identity_bundle()
    store = ContactTrustStore()
    imported = store.add_contact("Alice", alice_bundle)
    verified = store.verify_identity(imported.record_id, _fingerprint(alice_bundle))
    old_ghost_id = verified.current_contact.ghost_id

    changed = store.update_contact_bundle(verified.record_id, replacement_bundle)

    assert changed.state is ContactTrustState.CHANGED
    assert changed.current_contact.ghost_id == old_ghost_id
    assert changed.pinned_ghost_id == old_ghost_id
    assert changed.candidate_contact is not None
    assert changed.candidate_contact.ghost_id != old_ghost_id
    with pytest.raises(ContactTrustError, match="identity changed"):
        store.require_verified_contact(changed.record_id)


def test_changed_candidate_requires_its_own_explicit_fingerprint() -> None:
    _alice, alice_bundle = _identity_bundle()
    _bob, bob_bundle = _identity_bundle()
    store = ContactTrustStore()
    imported = store.add_contact("Alice", alice_bundle)
    verified = store.verify_identity(imported.record_id, _fingerprint(alice_bundle))
    changed = store.update_contact_bundle(verified.record_id, bob_bundle)

    with pytest.raises(ContactTrustError, match="fingerprint does not match"):
        store.verify_identity(changed.record_id, _fingerprint(alice_bundle))

    promoted = store.verify_identity(changed.record_id, _fingerprint(bob_bundle))

    assert promoted.state is ContactTrustState.VERIFIED
    assert promoted.candidate_bundle is None
    assert promoted.pinned_ghost_id == import_contact_bundle(bob_bundle).ghost_id
    assert (
        store.require_verified_contact(promoted.record_id).ghost_id
        == promoted.pinned_ghost_id
    )


def test_rejecting_changed_candidate_restores_previous_verified_identity() -> None:
    _alice, alice_bundle = _identity_bundle()
    _bob, bob_bundle = _identity_bundle()
    store = ContactTrustStore()
    imported = store.add_contact("Alice", alice_bundle)
    verified = store.verify_identity(imported.record_id, _fingerprint(alice_bundle))
    changed = store.update_contact_bundle(verified.record_id, bob_bundle)

    restored = store.reject_identity_change(changed.record_id)

    assert restored.state is ContactTrustState.VERIFIED
    assert restored.candidate_bundle is None
    assert restored.current_bundle == verified.current_bundle
    assert restored.pinned_ghost_id == verified.pinned_ghost_id


def test_changed_record_refuses_further_replacement_until_user_decides() -> None:
    _alice, alice_bundle = _identity_bundle()
    _bob, bob_bundle = _identity_bundle()
    _carol, carol_bundle = _identity_bundle()
    store = ContactTrustStore()
    imported = store.add_contact("Alice", alice_bundle)
    verified = store.verify_identity(imported.record_id, _fingerprint(alice_bundle))
    changed = store.update_contact_bundle(verified.record_id, bob_bundle)

    with pytest.raises(
        ContactTrustError,
        match="requires explicit verification or rejection",
    ):
        store.update_contact_bundle(changed.record_id, carol_bundle)

    assert store.get(changed.record_id) == changed


def test_encrypted_store_round_trip_survives_restart(tmp_path) -> None:
    _alice, bundle = _identity_bundle()
    key = utils.random(SecretBox.KEY_SIZE)
    path = tmp_path / "contacts.store"
    store = ContactTrustStore()
    imported = store.add_contact("Alice", bundle)
    store.verify_identity(imported.record_id, _fingerprint(bundle))

    save_contact_store(path, key, store)
    restored = load_contact_store(path, key)

    record = restored.get(imported.record_id)
    assert record.state is ContactTrustState.VERIFIED
    assert restored.require_verified_contact(record.record_id).ghost_id == (
        import_contact_bundle(bundle).ghost_id
    )


def test_encrypted_store_does_not_expose_label_bundle_or_trust_state() -> None:
    _alice, bundle = _identity_bundle()
    key = utils.random(SecretBox.KEY_SIZE)
    store = ContactTrustStore()
    imported = store.add_contact("Alice Secret Label", bundle)
    store.verify_identity(imported.record_id, _fingerprint(bundle))

    serialized = encrypt_contact_store(store, key)

    assert "Alice Secret Label" not in serialized
    assert bundle not in serialized
    assert '"verified"' not in serialized


def test_store_rejects_wrong_key_and_modified_ciphertext() -> None:
    _alice, bundle = _identity_bundle()
    key = utils.random(SecretBox.KEY_SIZE)
    store = ContactTrustStore()
    store.add_contact("Alice", bundle)
    serialized = encrypt_contact_store(store, key)

    with pytest.raises(
        ContactTrustError,
        match="incorrect or store data was modified",
    ):
        decrypt_contact_store(serialized, utils.random(SecretBox.KEY_SIZE))

    document = json.loads(serialized)
    encoded = document["ciphertext"]
    document["ciphertext"] = ("A" if encoded[0] != "A" else "B") + encoded[1:]
    with pytest.raises(ContactTrustError):
        decrypt_contact_store(json.dumps(document), key)


def test_store_rejects_forged_verified_metadata_after_decryption() -> None:
    _alice, bundle = _identity_bundle()
    _bob, bob_bundle = _identity_bundle()
    key = utils.random(SecretBox.KEY_SIZE)
    bob_ghost_id = import_contact_bundle(bob_bundle).ghost_id
    payload = {
        "version": 1,
        "records": [
            {
                "record_id": "a" * 32,
                "label": "Alice",
                "state": "verified",
                "current_bundle": bundle,
                "pinned_ghost_id": bob_ghost_id,
                "candidate_bundle": None,
            }
        ],
    }
    plaintext = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    ciphertext = bytes(SecretBox(key).encrypt(plaintext))
    serialized = json.dumps(
        {
            "version": 1,
            "cipher": "secretbox",
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )

    with pytest.raises(
        ContactTrustError,
        match="does not match pinned identity",
    ):
        decrypt_contact_store(serialized, key)


def test_store_file_is_private_on_posix(tmp_path) -> None:
    _alice, bundle = _identity_bundle()
    key = utils.random(SecretBox.KEY_SIZE)
    path = tmp_path / "contacts.store"
    store = ContactTrustStore()
    store.add_contact("Alice", bundle)

    save_contact_store(path, key, store)

    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


_STATE_ID = "00112233445566778899aabbccddeeff"
_COORDINATION_KEY = bytes(range(32))


def _contact_witness(tmp_path):
    return SQLiteMonotonicWitness(
        tmp_path / "contact-witness.sqlite3",
        _STATE_ID,
        _COORDINATION_KEY,
    )


def test_witnessed_contact_store_detects_rollback(tmp_path) -> None:
    path = tmp_path / "contacts.sec"
    key = utils.random(SecretBox.KEY_SIZE)
    witness = _contact_witness(tmp_path)
    _alice, bundle = _identity_bundle()

    store = new_witnessed_contact_store(_STATE_ID)
    store.add_contact("Alice", bundle)
    save_contact_store_witnessed(
        path,
        key,
        store,
        state_id=_STATE_ID,
        coordination_key=_COORDINATION_KEY,
        witness=witness,
    )
    revision_one = path.read_bytes()

    loaded = load_contact_store_witnessed(
        path,
        key,
        state_id=_STATE_ID,
        coordination_key=_COORDINATION_KEY,
        witness=witness,
    )
    loaded.verify_identity(
        loaded.list_records()[0].record_id,
        _fingerprint(bundle),
    )
    save_contact_store_witnessed(
        path,
        key,
        loaded,
        state_id=_STATE_ID,
        coordination_key=_COORDINATION_KEY,
        witness=witness,
    )

    path.write_bytes(revision_one)
    with pytest.raises(ContactTrustError, match="older than monotonic witness"):
        load_contact_store_witnessed(
            path,
            key,
            state_id=_STATE_ID,
            coordination_key=_COORDINATION_KEY,
            witness=witness,
        )


def test_witnessed_contact_store_detects_same_revision_divergence(tmp_path) -> None:
    path = tmp_path / "contacts.sec"
    key = utils.random(SecretBox.KEY_SIZE)
    witness = _contact_witness(tmp_path)
    _alice, bundle = _identity_bundle()

    store = new_witnessed_contact_store(_STATE_ID)
    store.add_contact("Alice", bundle)
    save_contact_store_witnessed(
        path,
        key,
        store,
        state_id=_STATE_ID,
        coordination_key=_COORDINATION_KEY,
        witness=witness,
    )

    loaded = load_contact_store_witnessed(
        path,
        key,
        state_id=_STATE_ID,
        coordination_key=_COORDINATION_KEY,
        witness=witness,
    )
    loaded.add_contact("Alice second device", _identity_bundle()[1])
    save_contact_store(path, key, loaded)

    with pytest.raises(ContactTrustError, match="digest diverges"):
        load_contact_store_witnessed(
            path,
            key,
            state_id=_STATE_ID,
            coordination_key=_COORDINATION_KEY,
            witness=witness,
        )


def test_missing_contact_store_fails_when_witness_exists(tmp_path) -> None:
    path = tmp_path / "contacts.sec"
    key = utils.random(SecretBox.KEY_SIZE)
    witness = _contact_witness(tmp_path)

    store = new_witnessed_contact_store(_STATE_ID)
    save_contact_store_witnessed(
        path,
        key,
        store,
        state_id=_STATE_ID,
        coordination_key=_COORDINATION_KEY,
        witness=witness,
    )
    path.unlink()

    with pytest.raises(
        ContactTrustError,
        match="missing while its witness is initialized",
    ):
        load_contact_store_witnessed(
            path,
            key,
            state_id=_STATE_ID,
            coordination_key=_COORDINATION_KEY,
            witness=witness,
        )


def test_legacy_contact_store_requires_explicit_witness_migration(tmp_path) -> None:
    path = tmp_path / "contacts.sec"
    key = utils.random(SecretBox.KEY_SIZE)
    witness = _contact_witness(tmp_path)
    _alice, bundle = _identity_bundle()

    legacy = ContactTrustStore()
    legacy.add_contact("Alice", bundle)
    save_contact_store(path, key, legacy)

    with pytest.raises(
        ContactTrustError,
        match="requires explicit rollback-state migration",
    ):
        load_contact_store_witnessed(
            path,
            key,
            state_id=_STATE_ID,
            coordination_key=_COORDINATION_KEY,
            witness=witness,
        )

    migrated = migrate_contact_store_to_witness(
        path,
        key,
        state_id=_STATE_ID,
        coordination_key=_COORDINATION_KEY,
        witness=witness,
    )
    assert migrated.revision == 1
    assert migrated.state_id == _STATE_ID
    assert migrated.checkpoint_digest is not None
    assert len(migrated.records) == 1

    reopened = load_contact_store_witnessed(
        path,
        key,
        state_id=_STATE_ID,
        coordination_key=_COORDINATION_KEY,
        witness=witness,
    )
    assert reopened.list_records()[0].label == "Alice"


class _FailingCompareAndSetWitness:
    def __init__(self, delegate: SQLiteMonotonicWitness) -> None:
        self.delegate = delegate

    def get(self, component):
        return self.delegate.get(component)

    def initialize(self, record) -> None:
        self.delegate.initialize(record)

    def compare_and_set(self, expected, next_record) -> None:
        raise StateWitnessError("simulated witness commit failure")


def test_contact_store_recovers_one_step_after_witness_commit_crash(tmp_path) -> None:
    path = tmp_path / "contacts.sec"
    key = utils.random(SecretBox.KEY_SIZE)
    witness = _contact_witness(tmp_path)
    _alice, bundle = _identity_bundle()

    store = new_witnessed_contact_store(_STATE_ID)
    store.add_contact("Alice", bundle)
    save_contact_store_witnessed(
        path,
        key,
        store,
        state_id=_STATE_ID,
        coordination_key=_COORDINATION_KEY,
        witness=witness,
    )

    loaded = load_contact_store_witnessed(
        path,
        key,
        state_id=_STATE_ID,
        coordination_key=_COORDINATION_KEY,
        witness=witness,
    )
    loaded.verify_identity(
        loaded.list_records()[0].record_id,
        _fingerprint(bundle),
    )

    with pytest.raises(ContactTrustError, match="simulated witness commit failure"):
        save_contact_store_witnessed(
            path,
            key,
            loaded,
            state_id=_STATE_ID,
            coordination_key=_COORDINATION_KEY,
            witness=_FailingCompareAndSetWitness(witness),
        )

    assert witness.get("contacts").revision == 1
    recovered = load_contact_store_witnessed(
        path,
        key,
        state_id=_STATE_ID,
        coordination_key=_COORDINATION_KEY,
        witness=witness,
    )
    assert recovered.revision == 2
    assert recovered.list_records()[0].state is ContactTrustState.VERIFIED
    assert witness.get("contacts").revision == 2
