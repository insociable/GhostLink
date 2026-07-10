import pytest
from ghostlink.crypto import (
    Identity,
    decrypt_message,
    encrypt_message,
    import_public_key,
)
from nacl.exceptions import CryptoError


def test_two_identities_can_exchange_an_encrypted_message() -> None:
    alice = Identity.generate()
    bob = Identity.generate()

    encrypted = encrypt_message(alice, bob.public_key, b"GhostLink test message")
    decrypted = decrypt_message(bob, alice.public_key, encrypted)

    assert decrypted == b"GhostLink test message"
    assert b"GhostLink test message" not in encrypted


def test_public_key_export_round_trip() -> None:
    identity = Identity.generate()

    imported = import_public_key(identity.export_public_key())

    assert bytes(imported) == bytes(identity.public_key)


def test_wrong_recipient_cannot_decrypt() -> None:
    alice = Identity.generate()
    bob = Identity.generate()
    mallory = Identity.generate()

    encrypted = encrypt_message(alice, bob.public_key, b"private")

    with pytest.raises(CryptoError):
        decrypt_message(mallory, alice.public_key, encrypted)


def test_empty_plaintext_is_rejected() -> None:
    alice = Identity.generate()
    bob = Identity.generate()

    with pytest.raises(ValueError, match="plaintext must not be empty"):
        encrypt_message(alice, bob.public_key, b"")
