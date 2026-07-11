from dataclasses import replace

import pytest
from ghostlink.entity import GhostEntity
from ghostlink.message import (
    MessageDecryptionError,
    decrypt_message,
    encrypt_message,
)


def create_two_devices():
    alice = GhostEntity.generate()
    bob = GhostEntity.generate()

    return alice.enroll_device(), bob.enroll_device()


def test_message_can_be_encrypted_and_decrypted() -> None:
    alice_device, bob_device = create_two_devices()

    message = encrypt_message(
        sender=alice_device,
        recipient=bob_device,
        plaintext=b"Bonjour Bob",
    )

    plaintext = decrypt_message(
        recipient=bob_device,
        sender=alice_device,
        message=message,
    )

    assert plaintext == b"Bonjour Bob"


def test_plaintext_is_not_visible_in_ciphertext() -> None:
    alice_device, bob_device = create_two_devices()
    plaintext = b"message secret GhostLink"

    message = encrypt_message(
        sender=alice_device,
        recipient=bob_device,
        plaintext=plaintext,
    )

    assert plaintext not in message.ciphertext


def test_wrong_recipient_cannot_decrypt_message() -> None:
    alice_device, bob_device = create_two_devices()
    mallory_device = GhostEntity.generate().enroll_device()

    message = encrypt_message(
        sender=alice_device,
        recipient=bob_device,
        plaintext=b"secret",
    )

    with pytest.raises(
        MessageDecryptionError,
        match="recipient device does not match message",
    ):
        decrypt_message(
            recipient=mallory_device,
            sender=alice_device,
            message=message,
        )


def test_modified_ciphertext_is_rejected() -> None:
    alice_device, bob_device = create_two_devices()

    message = encrypt_message(
        sender=alice_device,
        recipient=bob_device,
        plaintext=b"secret",
    )

    modified_message = replace(
        message,
        ciphertext=message.ciphertext[:-1] + b"\x00",
    )

    with pytest.raises(
        MessageDecryptionError,
        match="authentication or decryption failed",
    ):
        decrypt_message(
            recipient=bob_device,
            sender=alice_device,
            message=modified_message,
        )


def test_empty_plaintext_is_rejected() -> None:
    alice_device, bob_device = create_two_devices()

    with pytest.raises(
        ValueError,
        match="plaintext must not be empty",
    ):
        encrypt_message(
            sender=alice_device,
            recipient=bob_device,
            plaintext=b"",
        )


def test_unsupported_message_version_is_rejected() -> None:
    alice_device, bob_device = create_two_devices()

    message = encrypt_message(
        sender=alice_device,
        recipient=bob_device,
        plaintext=b"secret",
    )

    invalid_message = replace(message, version=99)

    with pytest.raises(
        MessageDecryptionError,
        match="unsupported message version",
    ):
        decrypt_message(
            recipient=bob_device,
            sender=alice_device,
            message=invalid_message,
        )