import base64
import os
import shutil
import time
import urllib.parse
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from ghostlink.client.node_client import GhostNodeClient
from ghostlink.contact import export_contact_bundle, import_contact_bundle
from ghostlink.entity import GhostEntity
from ghostlink.node import create_app
from ghostlink.ratchet_binding import (
    RatchetBindingError,
    SignedRatchetPreKeyBinding,
    create_ratchet_prekey_binding,
    sign_ratchet_prekey_binding,
)
from ghostlink.ratchet_engine import RatchetEngineClient, RatchetEngineError
from ghostlink.ratchet_publication import (
    import_ratchet_prekey_publication,
    verify_local_ratchet_prekey_publication,
)
from ghostlink.ratchet_publish import publish_prekey_generation

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
