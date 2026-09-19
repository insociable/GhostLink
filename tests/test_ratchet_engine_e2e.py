import base64
import os
import shutil
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from ghostlink.cli import run as run_cli
from ghostlink.client.node_client import GhostNodeClient, GhostNodeRequestError
from ghostlink.contact import export_contact_bundle, import_contact_bundle
from ghostlink.entity import GhostEntity
from ghostlink.node import create_app
from ghostlink.profile import (
    decrypt_local_profile,
    encrypt_local_profile,
    reconcile_profile_witness,
    rotate_local_profile_device,
)
from ghostlink.ratchet_binding import (
    RatchetBindingError,
    SignedRatchetPreKeyBinding,
    create_ratchet_prekey_binding,
    sign_ratchet_prekey_binding,
)
from ghostlink.ratchet_engine import RatchetEngineClient, RatchetEngineError
from ghostlink.ratchet_fetch import establish_session_from_relay
from ghostlink.ratchet_maintenance import maintain_prekeys
from ghostlink.ratchet_message import (
    decrypt_ratchet_message,
    encrypt_ratchet_message,
)
from ghostlink.ratchet_publication import (
    import_ratchet_prekey_publication,
    verify_local_ratchet_prekey_publication,
)
from ghostlink.ratchet_publish import publish_prekey_generation
from ghostlink.replay import SQLiteReplayCache
from ghostlink.state_witness import (
    SQLiteMonotonicWitness,
    StateWitnessError,
)

_ROOT = Path(__file__).resolve().parents[1]
_ENGINE = _ROOT / "ratchet-engine" / "dist" / "src" / "rpc-server.js"
_NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(
    _NODE is None or not _ENGINE.exists(),
    reason="built ratchet-engine and Node.js are required for cross-language smoke",
)


def _node_client_factory(
    api_client: TestClient,
) -> Callable[[str], GhostNodeClient]:
    def requester(
        method: str,
        url: str,
        payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        assert timeout > 0
        path = urllib.parse.urlparse(url).path
        response = api_client.request(
            method,
            path,
            json=payload,
            headers=headers,
        )
        return (
            response.status_code,
            response.json() if response.content else None,
        )

    def factory(base_url: str) -> GhostNodeClient:
        return GhostNodeClient(base_url, requester=requester)

    return factory


def test_python_to_node_ratchet_round_trip_survives_restart(tmp_path: Path) -> None:
    alice = GhostEntity.generate()
    bob = GhostEntity.generate()
    alice_device = alice.enroll_device()
    bob_device = bob.enroll_device()

    alice_contact = import_contact_bundle(
        export_contact_bundle(alice, alice_device),
    )
    bob_contact = import_contact_bundle(
        export_contact_bundle(bob, bob_device),
    )

    alice_key = os.urandom(32)
    bob_key = os.urandom(32)
    alice_vault = tmp_path / "alice.ratchet"
    bob_vault = tmp_path / "bob.ratchet"
    command = [_NODE or "node", str(_ENGINE)]

    alice_engine = RatchetEngineClient(
        command,
        alice_device,
        alice_vault,
        alice_key,
    )
    bob_engine = RatchetEngineClient(
        command,
        bob_device,
        bob_vault,
        bob_key,
    )

    for engine, key in (
        (alice_engine, alice_key),
        (bob_engine, bob_key),
    ):
        proc_root = Path("/proc") / str(engine.process_id)
        if proc_root.exists():
            encoded_key = base64.b64encode(key)
            assert encoded_key not in (proc_root / "cmdline").read_bytes()
            assert encoded_key not in (proc_root / "environ").read_bytes()

    try:
        bob_material = bob_engine.create_prekey_material()
        bob_binding = create_ratchet_prekey_binding(
            bob_device,
            bob_material,
            publication_sequence=1,
            bundle_kind="one_time",
        )
        signed_bob_binding = sign_ratchet_prekey_binding(
            bob_binding,
            bob_device,
        )

        invalid_signature = SignedRatchetPreKeyBinding(
            binding=bob_binding,
            device_signature=b"\x00" * 64,
        )
        with pytest.raises(
            RatchetBindingError,
            match="device signature is invalid",
        ):
            alice_engine.establish_session(
                invalid_signature,
                bob_contact,
            )

        alice_engine.establish_session(
            signed_bob_binding,
            bob_contact,
        )

        binary_payload = bytes((0x00, 0xFF, 0x01, 0x80, 0x42, 0x00, 0x7F))
        encrypted = alice_engine.encrypt(bob_contact, binary_payload)
        assert encrypted.ciphertext != binary_payload
        assert bob_engine.decrypt(alice_contact, encrypted) == binary_payload

        reply = b"ratcheted reply from Bob"
        encrypted_reply = bob_engine.encrypt(alice_contact, reply)
        assert alice_engine.decrypt(bob_contact, encrypted_reply) == reply
    finally:
        alice_engine.close()
        bob_engine.close()

    assert alice_vault.exists()
    assert bob_vault.exists()

    with RatchetEngineClient(
        command,
        alice_device,
        alice_vault,
        alice_key,
    ) as reopened_alice:
        with RatchetEngineClient(
            command,
            bob_device,
            bob_vault,
            bob_key,
        ) as reopened_bob:
            after_restart = b"same session after Python and Node restart"
            ciphertext = reopened_alice.encrypt(
                bob_contact,
                after_restart,
            )
            assert (
                reopened_bob.decrypt(alice_contact, ciphertext)
                == after_restart
            )


def test_prekey_publication_staging_survives_restart_exactly(tmp_path: Path) -> None:
    alice = GhostEntity.generate()
    bob = GhostEntity.generate()
    alice_device = alice.enroll_device()
    bob_device = bob.enroll_device()

    alice_contact = import_contact_bundle(
        export_contact_bundle(alice, alice_device),
    )
    bob_contact = import_contact_bundle(
        export_contact_bundle(bob, bob_device),
    )

    alice_key = os.urandom(32)
    bob_key = os.urandom(32)
    alice_vault = tmp_path / "alice-publication.ratchet"
    bob_vault = tmp_path / "bob-publication.ratchet"
    command = [_NODE or "node", str(_ENGINE)]

    with RatchetEngineClient(
        command,
        bob_device,
        bob_vault,
        bob_key,
    ) as bob_engine:
        payload = bob_engine.prepare_prekey_publication(
            one_time_count=3,
            issued_at=1_000,
            lifetime_seconds=3_600,
        )
        pending = bob_engine.get_pending_prekey_generation()
        assert pending is not None
        assert pending.public_payload == payload

        publication = import_ratchet_prekey_publication(payload)
        verify_local_ratchet_prekey_publication(publication, bob_device)
        assert publication.publication_sequence == 1
        assert len(publication.one_time) == 3
        assert publication.fallback.binding.bundle_kind == "fallback"

    with RatchetEngineClient(
        command,
        bob_device,
        bob_vault,
        bob_key,
    ) as reopened_bob:
        exact_retry = reopened_bob.prepare_prekey_publication(
            one_time_count=99,
            issued_at=9_999,
            lifetime_seconds=1,
        )
        assert exact_retry == payload

        reopened_bob.commit_prekey_publication(
            publication.publication_sequence,
            published_at=1_200,
        )
        assert reopened_bob.get_pending_prekey_generation() is None
        reopened_bob.commit_prekey_publication(
            publication.publication_sequence,
            published_at=1_300,
        )

        with RatchetEngineClient(
            command,
            alice_device,
            alice_vault,
            alice_key,
        ) as alice_engine:
            alice_engine.establish_session(
                publication.one_time[0],
                bob_contact,
                now=1_100,
            )
            encrypted = alice_engine.encrypt(
                bob_contact,
                b"publication-backed session",
            )
            assert (
                reopened_bob.decrypt(alice_contact, encrypted)
                == b"publication-backed session"
            )


def test_full_prekey_publication_flow_survives_engine_restart(
    tmp_path: Path,
) -> None:
    bob = GhostEntity.generate()
    bob_device = bob.enroll_device()
    bob_key = os.urandom(32)
    bob_vault = tmp_path / "bob-full-publication.ratchet"
    command = [_NODE or "node", str(_ENGINE)]
    api_client = TestClient(create_app())

    def requester(
        method: str,
        url: str,
        payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        assert timeout > 0
        parsed = urllib.parse.urlparse(url)
        response = api_client.request(
            method,
            parsed.path,
            json=payload,
            headers=headers,
        )
        return (
            response.status_code,
            response.json() if response.content else None,
        )

    node = GhostNodeClient(
        "http://ghostnode.test",
        requester=requester,
    )
    now = int(time.time())

    with RatchetEngineClient(
        command,
        bob_device,
        bob_vault,
        bob_key,
    ) as engine:
        receipt = publish_prekey_generation(
            engine,
            node,
            bob_device,
            one_time_count=3,
            issued_at=now,
            lifetime_seconds=3_600,
            acknowledged_at=now + 1,
        )
        assert receipt.device_id == bob_device.device_id
        assert receipt.publication_sequence == 1
        assert receipt.expires_at == now + 3_600
        assert receipt.one_time_count == 3
        assert engine.get_pending_prekey_generation() is None

    with RatchetEngineClient(
        command,
        bob_device,
        bob_vault,
        bob_key,
    ) as reopened:
        assert reopened.get_pending_prekey_generation() is None
        second = reopened.prepare_prekey_generation(
            one_time_count=2,
            issued_at=now + 2,
            lifetime_seconds=3_600,
        )
        assert second.publication_sequence == 2


def test_remote_publication_sequence_rollback_rejected_after_restart(
    tmp_path: Path,
) -> None:
    alice = GhostEntity.generate()
    bob = GhostEntity.generate()
    alice_device = alice.enroll_device()
    bob_device = bob.enroll_device()
    bob_contact = import_contact_bundle(
        export_contact_bundle(bob, bob_device),
    )

    alice_key = os.urandom(32)
    bob_key = os.urandom(32)
    alice_vault = tmp_path / "alice-remote-sequence.ratchet"
    bob_vault = tmp_path / "bob-remote-sequence.ratchet"
    command = [_NODE or "node", str(_ENGINE)]

    with RatchetEngineClient(
        command,
        bob_device,
        bob_vault,
        bob_key,
    ) as bob_engine:
        first_material = bob_engine.create_prekey_material()
        current = sign_ratchet_prekey_binding(
            create_ratchet_prekey_binding(
                bob_device,
                first_material,
                publication_sequence=2,
                bundle_kind="one_time",
                issued_at=1_000,
            ),
            bob_device,
        )

        with RatchetEngineClient(
            command,
            alice_device,
            alice_vault,
            alice_key,
        ) as alice_engine:
            alice_engine.establish_session(
                current,
                bob_contact,
                now=1_100,
            )

        rollback_material = bob_engine.create_prekey_material()
        rollback = sign_ratchet_prekey_binding(
            create_ratchet_prekey_binding(
                bob_device,
                rollback_material,
                publication_sequence=1,
                bundle_kind="one_time",
                issued_at=1_000,
            ),
            bob_device,
        )

        with RatchetEngineClient(
            command,
            alice_device,
            alice_vault,
            alice_key,
        ) as reopened_alice:
            with pytest.raises(
                RatchetEngineError,
                match="remote publication sequence regressed",
            ):
                reopened_alice.establish_session(
                    rollback,
                    bob_contact,
                    now=1_100,
                )



class _FailingRatchetWitness:
    def __init__(self, delegate: SQLiteMonotonicWitness) -> None:
        self.delegate = delegate
        self.fail_compare = False

    def get(self, component):
        return self.delegate.get(component)

    def initialize(self, record) -> None:
        self.delegate.initialize(record)

    def compare_and_set(self, expected, next_record) -> None:
        if self.fail_compare:
            raise StateWitnessError("simulated ratchet witness failure")
        self.delegate.compare_and_set(expected, next_record)


def test_rollback_aware_ratchet_vault_detects_highest_seen_rollback(
    tmp_path: Path,
) -> None:
    alice = GhostEntity.generate()
    bob = GhostEntity.generate()
    alice_device = alice.enroll_device()
    bob_device = bob.enroll_device()
    bob_contact = import_contact_bundle(
        export_contact_bundle(bob, bob_device),
    )

    command = [_NODE or "node", str(_ENGINE)]
    alice_key = os.urandom(32)
    bob_key = os.urandom(32)
    coordination_key = os.urandom(32)
    state_id = os.urandom(16).hex()
    alice_vault = tmp_path / "alice-witnessed.ratchet"
    bob_vault = tmp_path / "bob-witnessed-peer.ratchet"
    witness = SQLiteMonotonicWitness(
        tmp_path / "ratchet-witness.sqlite3",
        state_id,
        coordination_key,
    )

    with RatchetEngineClient(
        command,
        bob_device,
        bob_vault,
        bob_key,
    ) as bob_engine:
        first_material = bob_engine.create_prekey_material()
        sequence_two = sign_ratchet_prekey_binding(
            create_ratchet_prekey_binding(
                bob_device,
                first_material,
                publication_sequence=2,
                bundle_kind="one_time",
                issued_at=1_000,
            ),
            bob_device,
        )

        with RatchetEngineClient(
            command,
            alice_device,
            alice_vault,
            alice_key,
            state_id=state_id,
            coordination_key=coordination_key,
            witness=witness,
        ) as alice_engine:
            assert witness.get("ratchet").revision == 1
            alice_engine.establish_session(
                sequence_two,
                bob_contact,
                now=1_100,
            )
            assert witness.get("ratchet").revision == 2

        rollback_snapshot = alice_vault.read_bytes()

        second_material = bob_engine.create_prekey_material()
        sequence_three = sign_ratchet_prekey_binding(
            create_ratchet_prekey_binding(
                bob_device,
                second_material,
                publication_sequence=3,
                bundle_kind="one_time",
                issued_at=1_000,
            ),
            bob_device,
        )

        with RatchetEngineClient(
            command,
            alice_device,
            alice_vault,
            alice_key,
            state_id=state_id,
            coordination_key=coordination_key,
            witness=witness,
        ) as alice_engine:
            alice_engine.establish_session(
                sequence_three,
                bob_contact,
                now=1_100,
            )
            assert witness.get("ratchet").revision == 3

    alice_vault.write_bytes(rollback_snapshot)

    with pytest.raises(
        RatchetEngineError,
        match="older than monotonic witness",
    ):
        RatchetEngineClient(
            command,
            alice_device,
            alice_vault,
            alice_key,
            state_id=state_id,
            coordination_key=coordination_key,
            witness=witness,
        )


def test_ratchet_vault_recovers_one_step_after_witness_commit_crash(
    tmp_path: Path,
) -> None:
    local = GhostEntity.generate().enroll_device()
    command = [_NODE or "node", str(_ENGINE)]
    master_key = os.urandom(32)
    coordination_key = os.urandom(32)
    state_id = os.urandom(16).hex()
    vault_path = tmp_path / "crash-recovery.ratchet"
    witness = SQLiteMonotonicWitness(
        tmp_path / "crash-recovery-witness.sqlite3",
        state_id,
        coordination_key,
    )
    failing = _FailingRatchetWitness(witness)

    engine = RatchetEngineClient(
        command,
        local,
        vault_path,
        master_key,
        state_id=state_id,
        coordination_key=coordination_key,
        witness=failing,
    )
    assert witness.get("ratchet").revision == 1

    failing.fail_compare = True
    with pytest.raises(
        RatchetEngineError,
        match="simulated ratchet witness failure",
    ):
        engine.create_prekey_material()
    engine.close()

    assert witness.get("ratchet").revision == 1

    with RatchetEngineClient(
        command,
        local,
        vault_path,
        master_key,
        state_id=state_id,
        coordination_key=coordination_key,
        witness=witness,
    ):
        assert witness.get("ratchet").revision == 2


def test_legacy_ratchet_vault_requires_explicit_witness_migration(
    tmp_path: Path,
) -> None:
    local = GhostEntity.generate().enroll_device()
    command = [_NODE or "node", str(_ENGINE)]
    master_key = os.urandom(32)
    coordination_key = os.urandom(32)
    state_id = os.urandom(16).hex()
    vault_path = tmp_path / "legacy-migration.ratchet"
    witness = SQLiteMonotonicWitness(
        tmp_path / "legacy-migration-witness.sqlite3",
        state_id,
        coordination_key,
    )

    with RatchetEngineClient(
        command,
        local,
        vault_path,
        master_key,
    ) as legacy:
        legacy.create_prekey_material()

    with pytest.raises(
        RatchetEngineError,
        match="requires explicit rollback-state migration",
    ):
        RatchetEngineClient(
            command,
            local,
            vault_path,
            master_key,
            state_id=state_id,
            coordination_key=coordination_key,
            witness=witness,
        )

    with RatchetEngineClient(
        command,
        local,
        vault_path,
        master_key,
        state_id=state_id,
        coordination_key=coordination_key,
        witness=witness,
        allow_legacy_migration=True,
    ):
        assert witness.get("ratchet").revision == 1


def test_relay_fetch_establishes_one_time_and_fallback_sessions(
    tmp_path: Path,
) -> None:
    alice = GhostEntity.generate()
    bob = GhostEntity.generate()
    charlie = GhostEntity.generate()
    alice_device = alice.enroll_device()
    bob_device = bob.enroll_device()
    charlie_device = charlie.enroll_device()

    alice_contact = import_contact_bundle(
        export_contact_bundle(alice, alice_device)
    )
    bob_contact = import_contact_bundle(
        export_contact_bundle(bob, bob_device)
    )
    charlie_contact = import_contact_bundle(
        export_contact_bundle(charlie, charlie_device)
    )

    command = [_NODE or "node", str(_ENGINE)]
    api_client = TestClient(create_app())

    def requester(
        method: str,
        url: str,
        payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        assert timeout > 0
        parsed = urllib.parse.urlparse(url)
        response = api_client.request(
            method,
            parsed.path,
            json=payload,
            headers=headers,
        )
        return (
            response.status_code,
            response.json() if response.content else None,
        )

    node = GhostNodeClient(
        "http://ghostnode.test",
        requester=requester,
    )
    now = int(time.time())

    with RatchetEngineClient(
        command,
        bob_device,
        tmp_path / "bob-relay-fetch.ratchet",
        os.urandom(32),
    ) as bob_engine:
        receipt = publish_prekey_generation(
            bob_engine,
            node,
            bob_device,
            one_time_count=1,
            issued_at=now,
            lifetime_seconds=3_600,
            acknowledged_at=now + 1,
        )
        assert receipt.one_time_count == 1

        with RatchetEngineClient(
            command,
            alice_device,
            tmp_path / "alice-relay-fetch.ratchet",
            os.urandom(32),
        ) as alice_engine:
            alice_fetch = establish_session_from_relay(
                alice_engine,
                node,
                alice_device,
                bob_contact,
                issued_at=now + 1,
                verification_time=now + 1,
            )
            assert alice_fetch.bundle_kind == "one_time"
            assert alice_fetch.remaining_one_time_count == 0

            alice_message = alice_engine.encrypt(
                bob_contact,
                b"one-time session through GhostNode",
            )
            assert (
                bob_engine.decrypt(alice_contact, alice_message)
                == b"one-time session through GhostNode"
            )

        with RatchetEngineClient(
            command,
            charlie_device,
            tmp_path / "charlie-relay-fetch.ratchet",
            os.urandom(32),
        ) as charlie_engine:
            charlie_fetch = establish_session_from_relay(
                charlie_engine,
                node,
                charlie_device,
                bob_contact,
                issued_at=now + 2,
                verification_time=now + 2,
            )
            assert charlie_fetch.bundle_kind == "fallback"
            assert charlie_fetch.remaining_one_time_count == 0

            charlie_message = charlie_engine.encrypt(
                bob_contact,
                b"fallback session through GhostNode",
            )
            assert (
                bob_engine.decrypt(charlie_contact, charlie_message)
                == b"fallback session through GhostNode"
            )



def test_prekey_maintenance_replenishes_exhausted_relay_pool(
    tmp_path: Path,
) -> None:
    bob = GhostEntity.generate()
    alice = GhostEntity.generate()
    charlie = GhostEntity.generate()
    bob_device = bob.enroll_device()
    alice_device = alice.enroll_device()
    charlie_device = charlie.enroll_device()
    command = [_NODE or "node", str(_ENGINE)]
    api_client = TestClient(create_app())

    def requester(
        method: str,
        url: str,
        payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        assert timeout > 0
        parsed = urllib.parse.urlparse(url)
        response = api_client.request(
            method,
            parsed.path,
            json=payload,
            headers=headers,
        )
        return (
            response.status_code,
            response.json() if response.content else None,
        )

    node = GhostNodeClient(
        "http://ghostnode.test",
        requester=requester,
    )
    now = int(time.time())

    with RatchetEngineClient(
        command,
        bob_device,
        tmp_path / "bob-maintenance.ratchet",
        os.urandom(32),
    ) as bob_engine:
        initial = maintain_prekeys(
            bob_engine,
            node,
            bob_device,
            now=now,
            pool_target=2,
            replenish_threshold=0,
            refresh_before_seconds=60,
            replenish_cooldown_seconds=0,
            lifetime_seconds=3_600,
        )
        assert initial.action == "published_initial"
        assert initial.publication_sequence == 1
        assert initial.remaining_one_time_count == 2

        first = node.fetch_prekey(
            alice_device,
            bob_device.device_id,
            issued_at=now,
        )
        second = node.fetch_prekey(
            charlie_device,
            bob_device.device_id,
            issued_at=now,
        )
        assert first.bundle_kind == "one_time"
        assert first.remaining_one_time_count == 1
        assert second.bundle_kind == "one_time"
        assert second.remaining_one_time_count == 0

        depleted = node.prekey_status(
            bob_device,
            issued_at=now,
        )
        assert depleted.publication_sequence == 1
        assert depleted.remaining_one_time_count == 0

        replenished = maintain_prekeys(
            bob_engine,
            node,
            bob_device,
            now=now + 1,
            pool_target=2,
            replenish_threshold=0,
            refresh_before_seconds=60,
            replenish_cooldown_seconds=0,
            lifetime_seconds=3_600,
        )
        assert replenished.action == "replenished"
        assert replenished.publication_sequence == 2
        assert replenished.remaining_one_time_count == 2

        relay_after = node.prekey_status(
            bob_device,
            issued_at=now + 1,
        )
        assert relay_after.publication_sequence == 2
        assert relay_after.remaining_one_time_count == 2

        local_after = bob_engine.get_prekey_lifecycle_status()
        assert local_after.pending is None
        assert local_after.active is not None
        assert local_after.active.publication_sequence == 2
        assert local_after.retired_count == 1



def test_prekey_gc_round_trips_python_rpc_and_survives_restart(
    tmp_path: Path,
) -> None:
    bob = GhostEntity.generate()
    bob_device = bob.enroll_device()
    bob_key = os.urandom(32)
    bob_vault = tmp_path / "bob-gc-rpc.ratchet"
    command = [_NODE or "node", str(_ENGINE)]

    with RatchetEngineClient(
        command,
        bob_device,
        bob_vault,
        bob_key,
    ) as engine:
        first_payload = engine.prepare_prekey_publication(
            one_time_count=2,
            issued_at=1_000,
            lifetime_seconds=3_600,
        )
        first = import_ratchet_prekey_publication(first_payload)
        engine.commit_prekey_publication(
            first.publication_sequence,
            published_at=1_100,
        )

        second_payload = engine.prepare_prekey_publication(
            one_time_count=2,
            issued_at=1_200,
            lifetime_seconds=3_600,
        )
        second = import_ratchet_prekey_publication(second_payload)
        engine.commit_prekey_publication(
            second.publication_sequence,
            published_at=1_300,
        )

        before = engine.get_prekey_lifecycle_status()
        assert before.active is not None
        assert before.active.publication_sequence == 2
        assert before.retired_count == 1

        collected = engine.garbage_collect_prekeys(
            now=1_300 + 15 * 24 * 60 * 60,
        )
        assert collected.retired_generations_removed == 1
        assert collected.pre_keys_removed == 2
        assert collected.signed_pre_keys_removed == 1
        assert collected.kyber_pre_keys_removed == 3

        after = engine.get_prekey_lifecycle_status()
        assert after.pending is None
        assert after.active is not None
        assert after.active.publication_sequence == 2
        assert after.retired_count == 0

    with RatchetEngineClient(
        command,
        bob_device,
        bob_vault,
        bob_key,
    ) as reopened:
        persisted = reopened.get_prekey_lifecycle_status()
        assert persisted.pending is None
        assert persisted.active is not None
        assert persisted.active.publication_sequence == 2
        assert persisted.retired_count == 0



def test_ratchet_v3_relay_round_trip_and_tamper_rollback(
    tmp_path: Path,
) -> None:
    alice = GhostEntity.generate()
    bob = GhostEntity.generate()
    alice_device = alice.enroll_device()
    bob_device = bob.enroll_device()
    alice_contact = import_contact_bundle(
        export_contact_bundle(alice, alice_device)
    )
    bob_contact = import_contact_bundle(
        export_contact_bundle(bob, bob_device)
    )

    command = [_NODE or "node", str(_ENGINE)]
    api_client = TestClient(create_app())

    def requester(
        method: str,
        url: str,
        payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        assert timeout > 0
        parsed = urllib.parse.urlparse(url)
        response = api_client.request(
            method,
            parsed.path,
            json=payload,
            headers=headers,
        )
        return (
            response.status_code,
            response.json() if response.content else None,
        )

    node = GhostNodeClient(
        "http://ghostnode.test",
        requester=requester,
    )
    now = int(time.time())
    alice_key = os.urandom(32)
    bob_key = os.urandom(32)
    alice_vault = tmp_path / "alice-v3.ratchet"
    bob_vault = tmp_path / "bob-v3.ratchet"
    bob_replay = SQLiteReplayCache(tmp_path / "bob-v3-replay.sqlite3")
    alice_replay = SQLiteReplayCache(tmp_path / "alice-v3-replay.sqlite3")

    with RatchetEngineClient(
        command,
        bob_device,
        bob_vault,
        bob_key,
    ) as bob_engine:
        publish_prekey_generation(
            bob_engine,
            node,
            bob_device,
            one_time_count=2,
            issued_at=now,
            lifetime_seconds=3_600,
            acknowledged_at=now,
        )

        with RatchetEngineClient(
            command,
            alice_device,
            alice_vault,
            alice_key,
        ) as alice_engine:
            establish_session_from_relay(
                alice_engine,
                node,
                alice_device,
                bob_contact,
                issued_at=now,
                verification_time=now,
            )

            outbound = encrypt_ratchet_message(
                alice_engine,
                bob_contact,
                b"ratcheted v3 through GhostNode",
                created_at=now,
            )
            assert outbound.version == 3
            assert node.send_ratchet(alice_device, outbound) == outbound.message_id

            received = node.receive_ratchet(bob_device)
            assert received == [outbound]

            tampered = replace(
                received[0],
                message_id="f" * 32,
            )
            with pytest.raises(
                RatchetEngineError,
                match="decrypted ratchet context does not match",
            ):
                decrypt_ratchet_message(
                    bob_engine,
                    alice_contact,
                    tampered,
                    bob_replay,
                    now=now,
                )

            plaintext = decrypt_ratchet_message(
                bob_engine,
                alice_contact,
                received[0],
                bob_replay,
                now=now,
            )
            assert plaintext == b"ratcheted v3 through GhostNode"

            reply = encrypt_ratchet_message(
                bob_engine,
                alice_contact,
                b"ratcheted v3 reply",
                created_at=now + 1,
            )
            node.send_ratchet(bob_device, reply)
            reply_received = node.receive_ratchet(alice_device)
            assert reply_received == [reply]
            assert (
                decrypt_ratchet_message(
                    alice_engine,
                    bob_contact,
                    reply_received[0],
                    alice_replay,
                    now=now + 1,
                )
                == b"ratcheted v3 reply"
            )

            node.delete_ratchet(
                bob_device,
                outbound.message_id,
            )
            node.delete_ratchet(
                alice_device,
                reply.message_id,
            )
            assert node.receive_ratchet(bob_device) == []
            assert node.receive_ratchet(alice_device) == []



def test_cli_v3_cutover_round_trip_survives_process_restarts(
    tmp_path: Path,
    capsys,
) -> None:
    api_client = TestClient(create_app())

    def requester(
        method: str,
        url: str,
        payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        assert timeout > 0
        parsed = urllib.parse.urlparse(url)
        response = api_client.request(
            method,
            parsed.path,
            json=payload,
            headers=headers,
        )
        return (
            response.status_code,
            response.json() if response.content else None,
        )

    def node_client_factory(base_url: str) -> GhostNodeClient:
        return GhostNodeClient(base_url, requester=requester)

    unlock_phrase = "cross-language CLI password"

    def password_reader(prompt: str) -> str:
        del prompt
        return unlock_phrase

    alice_profile = tmp_path / "alice-cli-v3.ghost"
    bob_profile = tmp_path / "bob-cli-v3.ghost"
    alice_contact = tmp_path / "alice-cli-v3.contact"
    bob_contact = tmp_path / "bob-cli-v3.contact"
    node_url = "http://ghostnode.test"

    for profile_path in (alice_profile, bob_profile):
        assert run_cli(
            ["init", "--profile", str(profile_path)],
            password_reader=password_reader,
            node_client_factory=node_client_factory,
        ) == 0

    assert run_cli(
        [
            "contact-export",
            "--profile",
            str(alice_profile),
            "--output",
            str(alice_contact),
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0
    assert run_cli(
        [
            "contact-export",
            "--profile",
            str(bob_profile),
            "--output",
            str(bob_contact),
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0
    capsys.readouterr()

    # Bob explicitly publishes pre-keys before Alice's first-contact send.
    assert run_cli(
        [
            "prekey-sync",
            "--profile",
            str(bob_profile),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0
    capsys.readouterr()

    assert run_cli(
        [
            "send",
            "--profile",
            str(alice_profile),
            "--contact",
            str(bob_contact),
            "--node",
            node_url,
            "hello Bob over ratcheted v3",
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0

    bob_profile_data = decrypt_local_profile(
        bob_profile.read_text(encoding="utf-8"),
        unlock_phrase,
    )
    assert api_client.get(
        f"/v2/messages/{bob_profile_data.device.device_id}"
    ).status_code == 404
    assert len(
        api_client.get(
            f"/v3/messages/{bob_profile_data.device.device_id}"
        ).json()
    ) == 1

    assert run_cli(
        [
            "inbox",
            "--profile",
            str(bob_profile),
            "--contact",
            str(alice_contact),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0
    bob_inbox = capsys.readouterr()
    assert "hello Bob over ratcheted v3" in bob_inbox.out

    # Bob's incoming PreKey message established a durable session to Alice.
    alice_profile_data = decrypt_local_profile(
        alice_profile.read_text(encoding="utf-8"),
        unlock_phrase,
    )
    node_client = node_client_factory(node_url)
    alice_pool_before_reply = node_client.prekey_status(
        alice_profile_data.device,
    )
    assert alice_pool_before_reply.remaining_one_time_count == 100

    assert run_cli(
        [
            "send",
            "--profile",
            str(bob_profile),
            "--contact",
            str(alice_contact),
            "--node",
            node_url,
            "hello Alice over the persisted ratchet",
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0

    alice_pool_after_reply = node_client.prekey_status(
        alice_profile_data.device,
    )
    assert (
        alice_pool_after_reply.remaining_one_time_count
        == alice_pool_before_reply.remaining_one_time_count
    )
    assert api_client.get(
        f"/v2/messages/{alice_profile_data.device.device_id}"
    ).status_code == 404

    assert run_cli(
        [
            "inbox",
            "--profile",
            str(alice_profile),
            "--contact",
            str(bob_contact),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0
    alice_inbox = capsys.readouterr()
    assert "hello Alice over the persisted ratchet" in alice_inbox.out


def test_ratchet_vault_device_recovery_links_to_current_witness(
    tmp_path: Path,
) -> None:
    entity = GhostEntity.generate()
    old_device = entity.enroll_device()
    new_device = entity.enroll_device()
    peer = GhostEntity.generate()
    peer_device = peer.enroll_device()
    peer_contact = import_contact_bundle(
        export_contact_bundle(peer, peer_device),
    )
    command = [_NODE or "node", str(_ENGINE)]
    master_key = os.urandom(32)
    coordination_key = os.urandom(32)
    state_id = os.urandom(16).hex()
    vault_path = tmp_path / "device-recovery.ratchet"
    witness = SQLiteMonotonicWitness(
        tmp_path / "device-recovery-witness.sqlite3",
        state_id,
        coordination_key,
    )
    with RatchetEngineClient(
        command,
        old_device,
        vault_path,
        master_key,
        state_id=state_id,
        coordination_key=coordination_key,
        witness=witness,
    ) as old_engine:
        peer_engine = RatchetEngineClient(
            command,
            peer_device,
            tmp_path / "peer-recovery.ratchet",
            os.urandom(32),
        )
        try:
            material = peer_engine.create_prekey_material()
            binding = create_ratchet_prekey_binding(
                peer_device,
                material,
                publication_sequence=1,
                bundle_kind="one_time",
            )
            old_engine.establish_session(
                sign_ratchet_prekey_binding(binding, peer_device),
                peer_contact,
            )
            assert old_engine.has_session(peer_contact)
        finally:
            peer_engine.close()

    previous = witness.get("ratchet")
    assert previous is not None
    previous_revision = previous.revision
    vault_path.unlink()

    with RatchetEngineClient(
        command,
        new_device,
        vault_path,
        master_key,
        state_id=state_id,
        coordination_key=coordination_key,
        witness=witness,
        recovery_previous_checkpoint=previous,
    ) as recovered:
        assert recovered.local_device_id == new_device.device_id
        assert not recovered.has_session(peer_contact)

    current = witness.get("ratchet")
    assert current is not None
    assert current.revision == previous_revision + 1
    assert current.digest != previous.digest


def test_ratchet_vault_device_recovery_refuses_existing_vault(
    tmp_path: Path,
) -> None:
    entity = GhostEntity.generate()
    old_device = entity.enroll_device()
    new_device = entity.enroll_device()
    command = [_NODE or "node", str(_ENGINE)]
    master_key = os.urandom(32)
    coordination_key = os.urandom(32)
    state_id = os.urandom(16).hex()
    vault_path = tmp_path / "device-recovery-existing.ratchet"
    witness = SQLiteMonotonicWitness(
        tmp_path / "device-recovery-existing-witness.sqlite3",
        state_id,
        coordination_key,
    )

    with RatchetEngineClient(
        command,
        old_device,
        vault_path,
        master_key,
        state_id=state_id,
        coordination_key=coordination_key,
        witness=witness,
    ):
        pass

    previous = witness.get("ratchet")
    assert previous is not None

    with pytest.raises(
        RatchetEngineError,
        match="previous vault to be removed after verification",
    ):
        RatchetEngineClient(
            command,
            new_device,
            vault_path,
            master_key,
            state_id=state_id,
            coordination_key=coordination_key,
            witness=witness,
            recovery_previous_checkpoint=previous,
        )


def test_ratchet_vault_device_recovery_refuses_stale_checkpoint(
    tmp_path: Path,
) -> None:
    entity = GhostEntity.generate()
    old_device = entity.enroll_device()
    new_device = entity.enroll_device()
    command = [_NODE or "node", str(_ENGINE)]
    master_key = os.urandom(32)
    coordination_key = os.urandom(32)
    state_id = os.urandom(16).hex()
    vault_path = tmp_path / "device-recovery-stale.ratchet"
    witness = SQLiteMonotonicWitness(
        tmp_path / "device-recovery-stale-witness.sqlite3",
        state_id,
        coordination_key,
    )

    with RatchetEngineClient(
        command,
        old_device,
        vault_path,
        master_key,
        state_id=state_id,
        coordination_key=coordination_key,
        witness=witness,
    ) as engine:
        stale = witness.get("ratchet")
        assert stale is not None
        engine.create_prekey_material()

    vault_path.unlink()
    with pytest.raises(
        RatchetEngineError,
        match="not the current witnessed state",
    ):
        RatchetEngineClient(
            command,
            new_device,
            vault_path,
            master_key,
            state_id=state_id,
            coordination_key=coordination_key,
            witness=witness,
            recovery_previous_checkpoint=stale,
        )


def test_device_recover_cli_rotates_profile_without_ratchet_state(
    tmp_path: Path,
) -> None:
    api_client = TestClient(create_app())
    node_client_factory = _node_client_factory(api_client)
    node_url = "http://ghostnode.test"
    profile_path = tmp_path / "recover-profile-only.ghost"
    password = os.urandom(24).hex()

    def password_reader(prompt: str) -> str:
        del prompt
        return password

    assert run_cli(
        ["init", "--profile", str(profile_path)],
        password_reader=password_reader,
    ) == 0
    before = decrypt_local_profile(
        profile_path.read_text(encoding="utf-8"),
        password,
    )
    assert before.device_lifecycle is not None

    assert run_cli(
        [
            "device-recover",
            "--profile",
            str(profile_path),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0

    after = decrypt_local_profile(
        profile_path.read_text(encoding="utf-8"),
        password,
    )
    assert after.device_lifecycle is not None
    assert after.entity.ghost_id == before.entity.ghost_id
    assert after.device.device_id != before.device.device_id
    assert (
        after.device_lifecycle.statement.epoch
        == before.device_lifecycle.statement.epoch + 1
    )
    assert after.state_revision == before.state_revision + 1
    assert not Path(f"{profile_path}.device-recovery.pending").exists()
    assert not Path(
        f"{profile_path}.ratchet.device-recovery-old"
    ).exists()

    assert after.client_state_id is not None
    assert after.state_coordination_key is not None
    witness = SQLiteMonotonicWitness(
        Path(f"{profile_path}.witness.sqlite3"),
        after.client_state_id,
        after.state_coordination_key,
    )
    profile_record = witness.get("profile")
    assert profile_record is not None
    assert profile_record.revision == after.state_revision

    relay = node_client_factory(node_url)
    relay_lifecycle = relay.get_device_lifecycle(after.entity.ghost_id)
    assert relay_lifecycle.active_device_id == after.device.device_id
    assert relay_lifecycle.epoch == after.device_lifecycle.statement.epoch
    with pytest.raises(GhostNodeRequestError) as revoked:
        relay.prekey_status(before.device)
    assert revoked.value.status_code == 401


def test_device_recover_cli_resets_existing_ratchet_vault(
    tmp_path: Path,
) -> None:
    api_client = TestClient(create_app())
    node_client_factory = _node_client_factory(api_client)
    node_url = "http://ghostnode.test"
    profile_path = tmp_path / "recover-with-ratchet.ghost"
    password = os.urandom(24).hex()
    def password_reader(prompt: str) -> str:
        del prompt
        return password

    assert run_cli(
        ["init", "--profile", str(profile_path)],
        password_reader=password_reader,
    ) == 0
    before = decrypt_local_profile(
        profile_path.read_text(encoding="utf-8"),
        password,
    )
    assert before.client_state_id is not None
    assert before.state_coordination_key is not None
    assert before.ratchet_master_key is not None
    witness = SQLiteMonotonicWitness(
        Path(f"{profile_path}.witness.sqlite3"),
        before.client_state_id,
        before.state_coordination_key,
    )
    command = [_NODE or "node", str(_ENGINE)]
    vault_path = Path(f"{profile_path}.ratchet")

    with RatchetEngineClient(
        command,
        before.device,
        vault_path,
        before.ratchet_master_key,
        state_id=before.client_state_id,
        coordination_key=before.state_coordination_key,
        witness=witness,
    ) as engine:
        engine.create_prekey_material()

    old_ratchet = witness.get("ratchet")
    assert old_ratchet is not None

    assert run_cli(
        [
            "device-recover",
            "--profile",
            str(profile_path),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0

    after = decrypt_local_profile(
        profile_path.read_text(encoding="utf-8"),
        password,
    )
    assert after.device.device_id != before.device.device_id
    new_ratchet = witness.get("ratchet")
    assert new_ratchet is not None
    assert new_ratchet.revision == old_ratchet.revision + 1
    assert new_ratchet.digest != old_ratchet.digest
    assert not Path(
        f"{profile_path}.ratchet.device-recovery-old"
    ).exists()
    assert not Path(f"{profile_path}.device-recovery.pending").exists()

    assert after.ratchet_master_key is not None
    assert after.client_state_id is not None
    assert after.state_coordination_key is not None
    with RatchetEngineClient(
        command,
        after.device,
        vault_path,
        after.ratchet_master_key,
        state_id=after.client_state_id,
        coordination_key=after.state_coordination_key,
        witness=witness,
    ) as recovered:
        assert recovered.local_device_id == after.device.device_id


def test_device_recover_cli_resumes_after_old_vault_archive(
    tmp_path: Path,
) -> None:
    api_client = TestClient(create_app())
    node_client_factory = _node_client_factory(api_client)
    node_url = "http://ghostnode.test"
    profile_path = tmp_path / "recover-resume.ghost"
    password = os.urandom(24).hex()

    def password_reader(prompt: str) -> str:
        del prompt
        return password

    assert run_cli(
        ["init", "--profile", str(profile_path)],
        password_reader=password_reader,
    ) == 0
    active = decrypt_local_profile(
        profile_path.read_text(encoding="utf-8"),
        password,
    )
    assert active.client_state_id is not None
    assert active.state_coordination_key is not None
    assert active.ratchet_master_key is not None
    witness = SQLiteMonotonicWitness(
        Path(f"{profile_path}.witness.sqlite3"),
        active.client_state_id,
        active.state_coordination_key,
    )
    command = [_NODE or "node", str(_ENGINE)]
    vault_path = Path(f"{profile_path}.ratchet")
    backup_path = Path(f"{profile_path}.ratchet.device-recovery-old")
    pending_path = Path(f"{profile_path}.device-recovery.pending")

    with RatchetEngineClient(
        command,
        active.device,
        vault_path,
        active.ratchet_master_key,
        state_id=active.client_state_id,
        coordination_key=active.state_coordination_key,
        witness=witness,
    ) as engine:
        engine.create_prekey_material()

    checkpoint = reconcile_profile_witness(active, witness)
    candidate = rotate_local_profile_device(active, checkpoint, issued_at=123456)
    pending_path.write_text(
        encrypt_local_profile(candidate, password),
        encoding="utf-8",
    )
    if os.name == "posix":
        pending_path.chmod(0o600)
    vault_path.replace(backup_path)
    old_ratchet = witness.get("ratchet")
    assert old_ratchet is not None

    assert run_cli(
        [
            "device-recover",
            "--profile",
            str(profile_path),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0

    recovered = decrypt_local_profile(
        profile_path.read_text(encoding="utf-8"),
        password,
    )
    assert recovered.device.device_id == candidate.device.device_id
    assert not pending_path.exists()
    assert not backup_path.exists()
    assert vault_path.exists()

    new_ratchet = witness.get("ratchet")
    assert new_ratchet is not None
    assert new_ratchet.revision == old_ratchet.revision + 1
