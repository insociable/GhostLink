import json

import pytest
from ghostlink.profile import (
    ProfileError,
    ProfileUnlockError,
    create_local_profile,
    decrypt_local_profile,
    encrypt_local_profile,
)


def test_encrypted_profile_round_trip_preserves_identity_and_device() -> None:
    profile = create_local_profile()

    serialized = encrypt_local_profile(profile, "correct horse battery staple")
    restored = decrypt_local_profile(
        serialized,
        "correct horse battery staple",
    )

    assert restored.entity.ghost_id == profile.entity.ghost_id
    assert restored.device.device_id == profile.device.device_id
    assert bytes(restored.entity.signing_key) == bytes(profile.entity.signing_key)
    assert bytes(restored.device.device.signing_key) == bytes(
        profile.device.device.signing_key
    )
    assert bytes(restored.device.device.encryption_key) == bytes(
        profile.device.device.encryption_key
    )


def test_encrypted_profile_does_not_expose_private_key_material() -> None:
    profile = create_local_profile()

    serialized = encrypt_local_profile(profile, "a reasonably long password")

    assert bytes(profile.entity.signing_key).hex() not in serialized
    assert bytes(profile.device.device.signing_key).hex() not in serialized
    assert bytes(profile.device.device.encryption_key).hex() not in serialized


def test_wrong_password_is_rejected() -> None:
    profile = create_local_profile()
    serialized = encrypt_local_profile(profile, "right password")

    with pytest.raises(
        ProfileUnlockError,
        match="password is incorrect or profile data was modified",
    ):
        decrypt_local_profile(serialized, "wrong password")


def test_modified_ciphertext_is_rejected() -> None:
    profile = create_local_profile()
    document = json.loads(encrypt_local_profile(profile, "password"))
    ciphertext = document["ciphertext"]
    document["ciphertext"] = (
        ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
    )

    with pytest.raises(ProfileUnlockError):
        decrypt_local_profile(json.dumps(document), "password")


def test_profile_rejects_modified_kdf_parameters_before_derivation() -> None:
    profile = create_local_profile()
    document = json.loads(encrypt_local_profile(profile, "password"))
    document["kdf"]["memlimit"] = 2**63

    with pytest.raises(
        ProfileError,
        match="unsupported profile KDF parameters",
    ):
        decrypt_local_profile(json.dumps(document), "password")


def test_empty_password_is_rejected() -> None:
    profile = create_local_profile()

    with pytest.raises(ProfileError, match="password must not be empty"):
        encrypt_local_profile(profile, "")
