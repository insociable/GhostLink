import base64
import json

from nacl import utils
from nacl.pwhash import argon2id
from nacl.secret import SecretBox
import pytest

from ghostlink.profile import (
    ProfileError,
    ProfileUnlockError,
    create_local_profile,
    decrypt_local_profile,
    encrypt_local_profile,
    upgrade_local_profile,
)


def _legacy_v1_profile(profile, password: str) -> str:
    certificate = profile.device.certificate.certificate
    secret = {
        "identity_signing_seed": base64.b64encode(
            bytes(profile.entity.signing_key)
        ).decode("ascii"),
        "device_signing_seed": base64.b64encode(
            bytes(profile.device.device.signing_key)
        ).decode("ascii"),
        "device_encryption_private_key": base64.b64encode(
            bytes(profile.device.device.encryption_key)
        ).decode("ascii"),
        "ghost_id": certificate.ghost_id,
        "device_id": certificate.device_id,
        "device_signing_public_key": base64.b64encode(
            certificate.signing_public_key
        ).decode("ascii"),
        "device_encryption_public_key": base64.b64encode(
            certificate.encryption_public_key
        ).decode("ascii"),
        "device_certificate_signature": base64.b64encode(
            profile.device.certificate.signature
        ).decode("ascii"),
    }
    plaintext = json.dumps(
        secret,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    salt = utils.random(argon2id.SALTBYTES)
    key = argon2id.kdf(
        SecretBox.KEY_SIZE,
        password.encode("utf-8"),
        salt,
        opslimit=argon2id.OPSLIMIT_INTERACTIVE,
        memlimit=argon2id.MEMLIMIT_INTERACTIVE,
    )
    ciphertext = bytes(SecretBox(key).encrypt(plaintext))
    return json.dumps(
        {
            "version": 1,
            "kdf": {
                "name": "argon2id",
                "salt": base64.b64encode(salt).decode("ascii"),
                "opslimit": argon2id.OPSLIMIT_INTERACTIVE,
                "memlimit": argon2id.MEMLIMIT_INTERACTIVE,
            },
            "cipher": "secretbox",
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        },
        sort_keys=True,
        separators=(",", ":"),
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
    assert restored.ratchet_master_key == profile.ratchet_master_key
    assert restored.ratchet_master_key is not None
    assert len(restored.ratchet_master_key) == 32


def test_encrypted_profile_does_not_expose_private_key_material() -> None:
    profile = create_local_profile()

    serialized = encrypt_local_profile(profile, "a reasonably long password")

    assert profile.ratchet_master_key is not None
    private_values = [
        bytes(profile.entity.signing_key),
        bytes(profile.device.device.signing_key),
        bytes(profile.device.device.encryption_key),
        profile.ratchet_master_key,
    ]

    for value in private_values:
        assert base64.b64encode(value).decode("ascii") not in serialized
        assert value.hex() not in serialized


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



def test_profile_v2_outer_version_is_explicit() -> None:
    profile = create_local_profile()

    document = json.loads(encrypt_local_profile(profile, "password"))

    assert document["version"] == 2


def test_legacy_v1_profile_is_readable_but_has_no_ratchet_key() -> None:
    profile = create_local_profile()
    serialized = _legacy_v1_profile(profile, "legacy password")

    restored = decrypt_local_profile(serialized, "legacy password")

    assert restored.entity.ghost_id == profile.entity.ghost_id
    assert restored.device.device_id == profile.device.device_id
    assert restored.ratchet_master_key is None


def test_legacy_profile_requires_explicit_upgrade_before_reencrypt() -> None:
    profile = create_local_profile()
    legacy = decrypt_local_profile(
        _legacy_v1_profile(profile, "legacy password"),
        "legacy password",
    )

    with pytest.raises(
        ProfileError,
        match="must contain a 32-byte ratchet master key",
    ):
        encrypt_local_profile(legacy, "legacy password")


def test_upgrade_legacy_profile_adds_ratchet_key_without_changing_identity() -> None:
    profile = create_local_profile()
    legacy = decrypt_local_profile(
        _legacy_v1_profile(profile, "legacy password"),
        "legacy password",
    )

    upgraded = upgrade_local_profile(legacy)

    assert upgraded.entity.ghost_id == legacy.entity.ghost_id
    assert upgraded.device.device_id == legacy.device.device_id
    assert upgraded.ratchet_master_key is not None
    assert len(upgraded.ratchet_master_key) == 32

    serialized = encrypt_local_profile(upgraded, "legacy password")
    restored = decrypt_local_profile(serialized, "legacy password")
    assert restored.ratchet_master_key == upgraded.ratchet_master_key


def test_upgrade_is_idempotent_for_profile_v2() -> None:
    profile = create_local_profile()

    assert upgrade_local_profile(profile) is profile
