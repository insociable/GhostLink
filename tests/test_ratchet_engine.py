import sys
from pathlib import Path

import pytest
from ghostlink.contact import export_contact_bundle, import_contact_bundle
from ghostlink.entity import GhostEntity
from ghostlink.ratchet_binding import (
    create_ratchet_prekey_binding,
    sign_ratchet_prekey_binding,
)
from ghostlink.ratchet_engine import (
    RatchetCiphertext,
    RatchetEngineClient,
    RatchetEngineConnectionError,
)

_FAKE_ENGINE = Path(__file__).with_name("fake_ratchet_engine.py")


def test_ratchet_ciphertext_validation() -> None:
    with pytest.raises(ValueError, match="message_type"):
        RatchetCiphertext(message_type=-1, ciphertext=b"x")

    with pytest.raises(ValueError, match="ciphertext"):
        RatchetCiphertext(message_type=3, ciphertext=b"")


def test_ratchet_engine_rejects_invalid_start_configuration(tmp_path: Path) -> None:
    local = GhostEntity.generate().enroll_device()

    with pytest.raises(ValueError, match="command"):
        RatchetEngineClient([], local, tmp_path / "vault", b"x" * 32)

    with pytest.raises(ValueError, match="master_key"):
        RatchetEngineClient(
            [sys.executable, str(_FAKE_ENGINE)],
            local,
            tmp_path / "vault",
            b"short",
        )

    with pytest.raises(RatchetEngineConnectionError, match="START_FAILED"):
        RatchetEngineClient(
            [str(tmp_path / "missing-engine")],
            local,
            tmp_path / "vault",
            b"x" * 32,
        )


def test_python_client_public_api_over_framed_rpc(tmp_path: Path) -> None:
    alice = GhostEntity.generate()
    bob = GhostEntity.generate()
    alice_device = alice.enroll_device()
    bob_device = bob.enroll_device()

    bob_contact = import_contact_bundle(
        export_contact_bundle(bob, bob_device),
    )

    command = [sys.executable, "-u", str(_FAKE_ENGINE)]
    with RatchetEngineClient(
        command,
        alice_device,
        tmp_path / "alice.ratchet",
        b"\x11" * 32,
    ) as client:
        assert client.process_id > 0

        material = client.create_prekey_material()
        assert material.registration_id == 4200
        assert material.pre_key_id == 1001

        binding = create_ratchet_prekey_binding(
            bob_device,
            material,
            publication_sequence=1,
            bundle_kind="one_time",
            issued_at=1000,
        )
        signed = sign_ratchet_prekey_binding(binding, bob_device)
        client.establish_session(signed, bob_contact, now=1100)

        plaintext = b"\x00arbitrary\xffbytes"
        encrypted = client.encrypt(bob_contact, plaintext)
        assert encrypted.message_type == 3
        assert encrypted.ciphertext.startswith(b"cipher:")
        assert client.decrypt(bob_contact, encrypted) == plaintext

        with pytest.raises(ValueError, match="1 MiB"):
            client.encrypt(bob_contact, b"x" * (1024 * 1024 + 1))

    client.close()