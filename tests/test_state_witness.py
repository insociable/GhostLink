from __future__ import annotations

import os
import sqlite3
import stat
from pathlib import Path

import pytest
from ghostlink.state_witness import (
    ComponentCheckpoint,
    SQLiteMonotonicWitness,
    StateCheckpointError,
    StateDivergenceError,
    StateRollbackError,
    WitnessConflictError,
    WitnessCorruptionError,
    WitnessGapError,
    WitnessMissingError,
    WitnessRecord,
    advance_checkpoint,
    create_initial_checkpoint,
    initialize_witness,
    reconcile_checkpoint,
    verify_checkpoint,
    witness_record,
)

KEY = bytes(range(32))
STATE_ID = "00112233445566778899aabbccddeeff"
OTHER_STATE_ID = "ffeeddccbbaa99887766554433221100"
PAYLOAD_V1 = b'{"records":[],"version":1}'
PAYLOAD_V2 = b'{"records":[{"id":"a"}],"version":1}'


def _witness(tmp_path: Path) -> SQLiteMonotonicWitness:
    return SQLiteMonotonicWitness(
        tmp_path / "state-witness.sqlite3",
        STATE_ID,
        KEY,
    )


def _initialize(
    witness: SQLiteMonotonicWitness,
    checkpoint: ComponentCheckpoint,
    payload: bytes = PAYLOAD_V1,
) -> None:
    initialize_witness(
        witness,
        checkpoint,
        coordination_key=KEY,
        payload=payload,
    )


def _reconcile(
    witness: SQLiteMonotonicWitness,
    checkpoint: ComponentCheckpoint,
    payload: bytes,
) -> str:
    return reconcile_checkpoint(
        witness,
        checkpoint,
        coordination_key=KEY,
        payload=payload,
    )


def test_checkpoint_digest_has_stable_cross_language_vector() -> None:
    checkpoint = create_initial_checkpoint(
        KEY,
        STATE_ID,
        "contacts",
        PAYLOAD_V1,
    )

    assert checkpoint.revision == 1
    assert checkpoint.previous_digest is None
    assert (
        checkpoint.digest
        == "9fd5aba6d04d705529255c2ba24a4c3ffce468d349897370251a51801ec5b800"
    )


def test_checkpoint_advance_links_exact_previous_digest() -> None:
    first = create_initial_checkpoint(
        KEY,
        STATE_ID,
        "contacts",
        PAYLOAD_V1,
    )
    second = advance_checkpoint(KEY, first, PAYLOAD_V2)

    assert second.revision == 2
    assert second.previous_digest == first.digest
    assert second.digest != first.digest
    assert second.state_id == first.state_id
    assert second.component == first.component


def test_verify_checkpoint_rejects_payload_substitution() -> None:
    checkpoint = create_initial_checkpoint(
        KEY,
        STATE_ID,
        "contacts",
        PAYLOAD_V1,
    )

    with pytest.raises(
        StateCheckpointError,
        match="does not authenticate component payload",
    ):
        verify_checkpoint(KEY, checkpoint, PAYLOAD_V2)


@pytest.mark.parametrize(
    ("key", "state_id"),
    [
        (b"short", STATE_ID),
        (KEY, "ABCDEF"),
        (KEY, "A" * 32),
        (KEY, "z" * 32),
    ],
)
def test_checkpoint_rejects_invalid_root_material(
    key: bytes,
    state_id: str,
) -> None:
    with pytest.raises(StateCheckpointError):
        create_initial_checkpoint(
            key,
            state_id,
            "contacts",
            PAYLOAD_V1,
        )


def test_checkpoint_rejects_unknown_component() -> None:
    with pytest.raises(
        StateCheckpointError,
        match="unsupported client-state component",
    ):
        create_initial_checkpoint(
            KEY,
            STATE_ID,
            "unknown",  # type: ignore[arg-type]
            PAYLOAD_V1,
        )


def test_component_checkpoint_requires_lineage_after_revision_one() -> None:
    with pytest.raises(
        StateCheckpointError,
        match="requires a previous digest",
    ):
        ComponentCheckpoint(
            state_id=STATE_ID,
            component="contacts",
            revision=2,
            previous_digest=None,
            digest="0" * 64,
        )


def test_sqlite_witness_initializes_and_survives_reopen(tmp_path: Path) -> None:
    checkpoint = create_initial_checkpoint(
        KEY,
        STATE_ID,
        "contacts",
        PAYLOAD_V1,
    )
    path = tmp_path / "state-witness.sqlite3"
    witness = SQLiteMonotonicWitness(path, STATE_ID, KEY)

    _initialize(witness, checkpoint)

    reopened = SQLiteMonotonicWitness(path, STATE_ID, KEY)
    assert reopened.get("contacts") == witness_record(checkpoint)

    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_witness_initialization_is_explicit_and_one_time(tmp_path: Path) -> None:
    witness = _witness(tmp_path)
    checkpoint = create_initial_checkpoint(
        KEY,
        STATE_ID,
        "contacts",
        PAYLOAD_V1,
    )

    assert witness.get("contacts") is None
    _initialize(witness, checkpoint)

    with pytest.raises(
        WitnessConflictError,
        match="already initialized",
    ):
        _initialize(witness, checkpoint)


def test_witness_initialization_rejects_non_initial_checkpoint(
    tmp_path: Path,
) -> None:
    witness = _witness(tmp_path)
    first = create_initial_checkpoint(
        KEY,
        STATE_ID,
        "contacts",
        PAYLOAD_V1,
    )
    second = advance_checkpoint(KEY, first, PAYLOAD_V2)

    with pytest.raises(
        StateCheckpointError,
        match="requires an initial checkpoint",
    ):
        _initialize(witness, second, PAYLOAD_V2)


def test_reconcile_accepts_exact_current_checkpoint(tmp_path: Path) -> None:
    witness = _witness(tmp_path)
    checkpoint = create_initial_checkpoint(
        KEY,
        STATE_ID,
        "contacts",
        PAYLOAD_V1,
    )
    _initialize(witness, checkpoint)

    assert _reconcile(witness, checkpoint, PAYLOAD_V1) == "current"


def test_reconcile_rolls_witness_forward_one_crash_safe_revision(
    tmp_path: Path,
) -> None:
    witness = _witness(tmp_path)
    first = create_initial_checkpoint(
        KEY,
        STATE_ID,
        "contacts",
        PAYLOAD_V1,
    )
    second = advance_checkpoint(KEY, first, PAYLOAD_V2)
    _initialize(witness, first)

    assert _reconcile(witness, second, PAYLOAD_V2) == "witness_advanced"
    assert witness.get("contacts") == witness_record(second)
    assert _reconcile(witness, second, PAYLOAD_V2) == "current"


def test_reconcile_rejects_component_rollback(tmp_path: Path) -> None:
    witness = _witness(tmp_path)
    first = create_initial_checkpoint(
        KEY,
        STATE_ID,
        "contacts",
        PAYLOAD_V1,
    )
    second = advance_checkpoint(KEY, first, PAYLOAD_V2)
    _initialize(witness, first)
    witness.compare_and_set(
        witness_record(first),
        witness_record(second),
    )

    with pytest.raises(
        StateRollbackError,
        match="older than monotonic witness",
    ):
        _reconcile(witness, first, PAYLOAD_V1)


def test_reconcile_rejects_same_revision_divergence(
    tmp_path: Path,
) -> None:
    witness = _witness(tmp_path)
    accepted = create_initial_checkpoint(
        KEY,
        STATE_ID,
        "contacts",
        PAYLOAD_V1,
    )
    divergent = create_initial_checkpoint(
        KEY,
        STATE_ID,
        "contacts",
        PAYLOAD_V2,
    )
    _initialize(witness, accepted)

    with pytest.raises(
        StateDivergenceError,
        match="diverges at witnessed revision",
    ):
        _reconcile(witness, divergent, PAYLOAD_V2)


def test_reconcile_rejects_invalid_one_step_lineage(tmp_path: Path) -> None:
    witness = _witness(tmp_path)
    first = create_initial_checkpoint(
        KEY,
        STATE_ID,
        "contacts",
        PAYLOAD_V1,
    )
    fake_first = ComponentCheckpoint(
        state_id=STATE_ID,
        component="contacts",
        revision=1,
        previous_digest=None,
        digest="f" * 64,
    )
    invalid_second = advance_checkpoint(KEY, fake_first, PAYLOAD_V2)
    _initialize(witness, first)

    with pytest.raises(
        StateDivergenceError,
        match="does not link",
    ):
        _reconcile(witness, invalid_second, PAYLOAD_V2)


def test_reconcile_rejects_more_than_one_revision_gap(tmp_path: Path) -> None:
    witness = _witness(tmp_path)
    first = create_initial_checkpoint(
        KEY,
        STATE_ID,
        "contacts",
        PAYLOAD_V1,
    )
    second = advance_checkpoint(KEY, first, PAYLOAD_V2)
    third = advance_checkpoint(KEY, second, b"revision-three")
    _initialize(witness, first)

    with pytest.raises(
        WitnessGapError,
        match="more than one revision ahead",
    ):
        _reconcile(witness, third, b"revision-three")


def test_reconcile_never_auto_initializes_missing_witness(
    tmp_path: Path,
) -> None:
    witness = _witness(tmp_path)
    checkpoint = create_initial_checkpoint(
        KEY,
        STATE_ID,
        "contacts",
        PAYLOAD_V1,
    )

    with pytest.raises(
        WitnessMissingError,
        match="witness record is missing",
    ):
        _reconcile(witness, checkpoint, PAYLOAD_V1)

    assert witness.get("contacts") is None


def test_deleted_witness_file_is_not_silently_reinitialized(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state-witness.sqlite3"
    checkpoint = create_initial_checkpoint(
        KEY,
        STATE_ID,
        "contacts",
        PAYLOAD_V1,
    )
    witness = SQLiteMonotonicWitness(path, STATE_ID, KEY)
    _initialize(witness, checkpoint)

    path.unlink()
    replacement = SQLiteMonotonicWitness(path, STATE_ID, KEY)

    with pytest.raises(WitnessMissingError):
        _reconcile(replacement, checkpoint, PAYLOAD_V1)


def test_witness_record_tampering_fails_authentication(tmp_path: Path) -> None:
    witness = _witness(tmp_path)
    checkpoint = create_initial_checkpoint(
        KEY,
        STATE_ID,
        "contacts",
        PAYLOAD_V1,
    )
    _initialize(witness, checkpoint)

    with sqlite3.connect(witness.path) as connection:
        connection.execute(
            """
            UPDATE witness_records
            SET digest = ?
            WHERE state_id = ? AND component = ?
            """,
            ("0" * 64, STATE_ID, "contacts"),
        )

    with pytest.raises(
        WitnessCorruptionError,
        match="authentication failed",
    ):
        witness.get("contacts")


def test_stale_compare_and_set_fails_under_two_writers(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state-witness.sqlite3"
    first_writer = SQLiteMonotonicWitness(path, STATE_ID, KEY)
    second_writer = SQLiteMonotonicWitness(path, STATE_ID, KEY)
    first = create_initial_checkpoint(
        KEY,
        STATE_ID,
        "contacts",
        PAYLOAD_V1,
    )
    second = advance_checkpoint(KEY, first, PAYLOAD_V2)
    _initialize(first_writer, first)

    stale = second_writer.get("contacts")
    assert stale == witness_record(first)

    first_writer.compare_and_set(
        witness_record(first),
        witness_record(second),
    )

    with pytest.raises(
        WitnessConflictError,
        match="compare-and-set conflict",
    ):
        second_writer.compare_and_set(
            stale,
            witness_record(second),
        )


def test_witness_compare_and_set_requires_exact_next_revision(
    tmp_path: Path,
) -> None:
    witness = _witness(tmp_path)
    first = create_initial_checkpoint(
        KEY,
        STATE_ID,
        "contacts",
        PAYLOAD_V1,
    )
    _initialize(witness, first)
    skipped = WitnessRecord(
        state_id=STATE_ID,
        component="contacts",
        revision=3,
        digest="3" * 64,
    )

    with pytest.raises(
        StateCheckpointError,
        match="advance exactly one revision",
    ):
        witness.compare_and_set(
            witness_record(first),
            skipped,
        )


def test_shared_witness_allows_independent_component_revisions(
    tmp_path: Path,
) -> None:
    witness = _witness(tmp_path)
    profile_v1 = create_initial_checkpoint(
        KEY,
        STATE_ID,
        "profile",
        b"profile-v1",
    )
    contacts_v1 = create_initial_checkpoint(
        KEY,
        STATE_ID,
        "contacts",
        b"contacts-v1",
    )
    initialize_witness(
        witness,
        profile_v1,
        coordination_key=KEY,
        payload=b"profile-v1",
    )
    initialize_witness(
        witness,
        contacts_v1,
        coordination_key=KEY,
        payload=b"contacts-v1",
    )

    profile_v2 = advance_checkpoint(KEY, profile_v1, b"profile-v2")
    assert _reconcile(witness, profile_v2, b"profile-v2") == "witness_advanced"

    assert _reconcile(witness, contacts_v1, b"contacts-v1") == "current"
    assert witness.get("profile").revision == 2
    assert witness.get("contacts").revision == 1

    contacts_v2 = advance_checkpoint(KEY, contacts_v1, b"contacts-v2")
    assert _reconcile(witness, contacts_v2, b"contacts-v2") == "witness_advanced"
    assert witness.get("profile").revision == 2
    assert witness.get("contacts").revision == 2


def test_witness_database_can_scope_multiple_client_states(
    tmp_path: Path,
) -> None:
    path = tmp_path / "shared-witness.sqlite3"
    first_state = SQLiteMonotonicWitness(path, STATE_ID, KEY)
    second_state = SQLiteMonotonicWitness(path, OTHER_STATE_ID, KEY)
    first_checkpoint = create_initial_checkpoint(
        KEY,
        STATE_ID,
        "contacts",
        PAYLOAD_V1,
    )
    second_checkpoint = create_initial_checkpoint(
        KEY,
        OTHER_STATE_ID,
        "contacts",
        PAYLOAD_V1,
    )

    _initialize(first_state, first_checkpoint)
    assert second_state.get("contacts") is None

    _initialize(second_state, second_checkpoint)

    assert first_state.get("contacts") == witness_record(first_checkpoint)
    assert second_state.get("contacts") == witness_record(second_checkpoint)


def test_witness_rejects_directory_path(tmp_path: Path) -> None:
    directory = tmp_path / "witness-dir"
    directory.mkdir()

    with pytest.raises(ValueError, match="must point to a file"):
        SQLiteMonotonicWitness(directory, STATE_ID, KEY)


def test_witness_rejects_wrong_coordination_key_on_reopen(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state-witness.sqlite3"
    checkpoint = create_initial_checkpoint(
        KEY,
        STATE_ID,
        "contacts",
        PAYLOAD_V1,
    )
    witness = SQLiteMonotonicWitness(path, STATE_ID, KEY)
    _initialize(witness, checkpoint)

    wrong_key = bytes(reversed(range(32)))
    reopened = SQLiteMonotonicWitness(path, STATE_ID, wrong_key)

    with pytest.raises(
        WitnessCorruptionError,
        match="authentication failed",
    ):
        reopened.get("contacts")
