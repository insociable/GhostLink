import base64
import os
import shutil
import time
import urllib.parse
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from ghostlink.cli import run as run_cli
from ghostlink.client.node_client import GhostNodeClient
from ghostlink.contact import export_contact_bundle, import_contact_bundle
from ghostlink.entity import GhostEntity
from ghostlink.node import create_app
from ghostlink.profile import decrypt_local_profile
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

_ROOT = Path(__file__).resolve().parents[1]
_ENGINE = _ROOT / "ratchet-engine" / "dist" / "src" / "rpc-server.js"
_NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(
    _NODE is None or not _ENGINE.exists(),
    reason="built ratchet-engine and Node.js are required for cross-language smoke",
)


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
            assert node.send_ratchet(outbound) == outbound.message_id

            received = node.receive_ratchet(bob_device.device_id)
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
            node.send_ratchet(reply)
            reply_received = node.receive_ratchet(alice_device.device_id)
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
                bob_device.device_id,
                outbound.message_id,
            )
            node.delete_ratchet(
                alice_device.device_id,
                reply.message_id,
            )
            assert node.receive_ratchet(bob_device.device_id) == []
            assert node.receive_ratchet(alice_device.device_id) == []



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

    password = "cross-language CLI password"

    def password_reader(prompt: str) -> str:
        del prompt
        return password

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
        password,
    )
    assert (
        api_client.get(
            f"/v2/messages/{bob_profile_data.device.device_id}"
        ).json()
        == []
    )
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
        password,
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
    assert (
        api_client.get(
            f"/v2/messages/{alice_profile_data.device.device_id}"
        ).json()
        == []
    )

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
