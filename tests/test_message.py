from dataclasses import replace

import pytest
from ghostlink.entity import GhostEntity
from ghostlink.message import (
    MESSAGE_CLOCK_SKEW_SECONDS,
    MESSAGE_DEFAULT_TTL_SECONDS,
    MESSAGE_MAX_LIFETIME_SECONDS,
    MESSAGE_VERSION,
    MessageDecryptionError,
    decrypt_message,
    encrypt_message,
)


def create_two_devices():
    alice = GhostEntity.generate()
    bob = GhostEntity.generate()
    return alice.enroll_device(), bob.enroll_device()


def test_v2_message_round_trip() -> None:
    alice_device, bob_device = create_two_devices()
    created_at = 1_800_000_000

    message = encrypt_message(
        sender=alice_device,
        recipient=bob_device.public_device(),
        plaintext=b"Bonjour Bob V2",
        created_at=created_at,
    )

    plaintext = decrypt_message(
        recipient=bob_device,
        sender=alice_device.public_device(),
        message=message,
        now=created_at,
    )

    assert message.version == MESSAGE_VERSION
    assert plaintext == b"Bonjour Bob V2"
    assert message.expires_at - message.created_at == MESSAGE_DEFAULT_TTL_SECONDS


def test_v2_message_id_is_random_128_bit_hex() -> None:
    alice_device, bob_device = create_two_devices()

    first = encrypt_message(
        alice_device,
        bob_device.public_device(),
        b"first",
        created_at=1_800_000_000,
    )
    second = encrypt_message(
        alice_device,
        bob_device.public_device(),
        b"second",
        created_at=1_800_000_000,
    )

    assert len(first.message_id) == 32
    assert first.message_id != second.message_id
    assert all(character in "0123456789abcdef" for character in first.message_id)


def test_v2_plaintext_is_not_visible_in_ciphertext() -> None:
    alice_device, bob_device = create_two_devices()
    plaintext = b"message secret GhostLink V2"

    message = encrypt_message(
        alice_device,
        bob_device.public_device(),
        plaintext,
        created_at=1_800_000_000,
    )

    assert plaintext not in message.ciphertext


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("message_id", "0" * 32, "message identifier mismatch"),
        ("created_at", 1_800_000_001, "creation timestamp mismatch"),
        ("expires_at", 1_800_086_401, "expiration timestamp mismatch"),
    ],
)
def test_v2_outer_metadata_tampering_is_detected(
    field: str,
    value: str | int,
    error: str,
) -> None:
    alice_device, bob_device = create_two_devices()
    message = encrypt_message(
        alice_device,
        bob_device.public_device(),
        b"secret",
        created_at=1_800_000_000,
    )
    modified = replace(message, **{field: value})

    with pytest.raises(MessageDecryptionError, match=error):
        decrypt_message(
            bob_device,
            alice_device.public_device(),
            modified,
            now=1_800_000_000,
        )


def test_v2_wrong_recipient_is_rejected() -> None:
    alice_device, bob_device = create_two_devices()
    mallory_device = GhostEntity.generate().enroll_device()
    message = encrypt_message(
        alice_device,
        bob_device.public_device(),
        b"secret",
        created_at=1_800_000_000,
    )

    with pytest.raises(
        MessageDecryptionError,
        match="recipient device does not match message",
    ):
        decrypt_message(
            mallory_device,
            alice_device.public_device(),
            message,
            now=1_800_000_000,
        )


def test_v2_modified_ciphertext_is_rejected() -> None:
    alice_device, bob_device = create_two_devices()
    message = encrypt_message(
        alice_device,
        bob_device.public_device(),
        b"secret",
        created_at=1_800_000_000,
    )
    modified = replace(
        message,
        ciphertext=message.ciphertext[:-1] + b"\x00",
    )

    with pytest.raises(
        MessageDecryptionError,
        match="authentication or decryption failed",
    ):
        decrypt_message(
            bob_device,
            alice_device.public_device(),
            modified,
            now=1_800_000_000,
        )


def test_v2_message_expiration_is_enforced() -> None:
    alice_device, bob_device = create_two_devices()
    message = encrypt_message(
        alice_device,
        bob_device.public_device(),
        b"expires",
        ttl_seconds=60,
        created_at=1_800_000_000,
    )

    with pytest.raises(MessageDecryptionError, match="message has expired"):
        decrypt_message(
            bob_device,
            alice_device.public_device(),
            message,
            now=message.expires_at + MESSAGE_CLOCK_SKEW_SECONDS + 1,
        )


def test_v2_expiration_clock_skew_is_tolerated() -> None:
    alice_device, bob_device = create_two_devices()
    message = encrypt_message(
        alice_device,
        bob_device.public_device(),
        b"within skew",
        ttl_seconds=60,
        created_at=1_800_000_000,
    )

    assert decrypt_message(
        bob_device,
        alice_device.public_device(),
        message,
        now=message.expires_at + MESSAGE_CLOCK_SKEW_SECONDS,
    ) == b"within skew"


def test_v2_future_creation_time_is_rejected() -> None:
    alice_device, bob_device = create_two_devices()
    message = encrypt_message(
        alice_device,
        bob_device.public_device(),
        b"future",
        created_at=1_800_000_000,
    )

    with pytest.raises(
        MessageDecryptionError,
        match="creation time is too far in the future",
    ):
        decrypt_message(
            bob_device,
            alice_device.public_device(),
            message,
            now=message.created_at - MESSAGE_CLOCK_SKEW_SECONDS - 1,
        )


def test_v2_maximum_lifetime_is_enforced_at_encryption() -> None:
    alice_device, bob_device = create_two_devices()

    with pytest.raises(ValueError, match="maximum message lifetime"):
        encrypt_message(
            alice_device,
            bob_device.public_device(),
            b"too long",
            ttl_seconds=MESSAGE_MAX_LIFETIME_SECONDS + 1,
            created_at=1_800_000_000,
        )


@pytest.mark.parametrize("ttl_seconds", [0, -1])
def test_v2_non_positive_ttl_is_rejected(ttl_seconds: int) -> None:
    alice_device, bob_device = create_two_devices()

    with pytest.raises(ValueError, match="greater than zero"):
        encrypt_message(
            alice_device,
            bob_device.public_device(),
            b"invalid ttl",
            ttl_seconds=ttl_seconds,
            created_at=1_800_000_000,
        )


def test_v2_empty_plaintext_is_rejected() -> None:
    alice_device, bob_device = create_two_devices()

    with pytest.raises(ValueError, match="plaintext must not be empty"):
        encrypt_message(
            alice_device,
            bob_device.public_device(),
            b"",
            created_at=1_800_000_000,
        )