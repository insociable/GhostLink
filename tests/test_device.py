import pytest
from ghostlink.device import derive_device_id
from nacl.signing import SigningKey


def test_device_id_has_expected_prefix_and_length() -> None:
    public_key = bytes(SigningKey.generate().verify_key)

    device_id = derive_device_id(public_key)

    assert device_id.startswith("device1:")
    assert len(device_id) == 60


def test_same_public_key_always_produces_same_device_id() -> None:
    public_key = bytes(SigningKey.generate().verify_key)

    first = derive_device_id(public_key)
    second = derive_device_id(public_key)

    assert first == second


def test_different_public_keys_produce_different_device_ids() -> None:
    first_public_key = bytes(SigningKey.generate().verify_key)
    second_public_key = bytes(SigningKey.generate().verify_key)

    assert derive_device_id(first_public_key) != derive_device_id(
        second_public_key,
    )


def test_invalid_public_key_length_is_rejected() -> None:
    with pytest.raises(
        ValueError,
        match="Ed25519 public key must contain exactly 32 bytes",
    ):
        derive_device_id(b"invalid")