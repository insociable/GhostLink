import base64
import os
import shutil
from pathlib import Path

import pytest
from ghostlink.contact import export_contact_bundle, import_contact_bundle
from ghostlink.entity import GhostEntity
from ghostlink.ratchet_binding import (
    RatchetBindingError,
    SignedRatchetPreKeyBinding,
    create_ratchet_prekey_binding,
    sign_ratchet_prekey_binding,
)
from ghostlink.ratchet_engine import RatchetEngineClient

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