import base64
import json

import pytest
from ghostlink.profile import (
    ProfileError,
    ProfileUnlockError,
    create_local_profile,
    decrypt_local_profile,
    encrypt_local_profile,
    initialize_profile_witness,
    reconcile_profile_witness,
    rotate_local_profile_device,
    upgrade_local_profile,
)
from ghostlink.state_witness import SQLiteMonotonicWitness
from nacl import utils
from nacl.pwhash import argon2id
from nacl.secret import SecretBox


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


def _legacy_v2_profile(profile, password: str) -> str:
    certificate = profile.device.certificate.certificate
    assert profile.ratchet_master_key is not None
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
        "ratchet_master_key": base64.b64encode(profile.ratchet_master_key).decode(
            "ascii"
        ),
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
            "version": 2,
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


def _legacy_v3_profile(profile, password: str) -> str:
    certificate = profile.device.certificate.certificate
    assert profile.ratchet_master_key is not None
    assert profile.contact_store_key is not None
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
        "ratchet_master_key": base64.b64encode(profile.ratchet_master_key).decode(
            "ascii"
        ),
        "contact_store_key": base64.b64encode(profile.contact_store_key).decode(
            "ascii"
        ),
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
            "version": 3,
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


def _legacy_v4_profile(profile, password: str) -> str:
    current = json.loads(encrypt_local_profile(profile, password))
    salt = base64.b64decode(current["kdf"]["salt"])
    key = argon2id.kdf(
        SecretBox.KEY_SIZE,
        password.encode("utf-8"),
        salt,
        opslimit=argon2id.OPSLIMIT_INTERACTIVE,
        memlimit=argon2id.MEMLIMIT_INTERACTIVE,
    )
    plaintext = SecretBox(key).decrypt(
        base64.b64decode(current["ciphertext"])
    )
    secret = json.loads(plaintext)
    secret.pop("device_lifecycle")
    legacy_plaintext = json.dumps(
        secret,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    current["version"] = 4
    current["ciphertext"] = base64.b64encode(
        bytes(SecretBox(key).encrypt(legacy_plaintext))
    ).decode("ascii")
    return json.dumps(current, sort_keys=True, separators=(",", ":"))


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
    assert restored.contact_store_key == profile.contact_store_key
    assert restored.contact_store_key is not None
    assert len(restored.contact_store_key) == 32
    assert restored.contact_store_key != restored.ratchet_master_key
    assert restored.client_state_id == profile.client_state_id
    assert restored.client_state_id is not None
    assert len(restored.client_state_id) == 32
    assert restored.state_coordination_key == profile.state_coordination_key
    assert restored.state_coordination_key is not None
    assert len(restored.state_coordination_key) == 32
    assert restored.state_coordination_key not in {
        restored.ratchet_master_key,
        restored.contact_store_key,
    }
    assert restored.state_revision == 1
    assert restored.state_previous_digest is None
    assert restored.device_lifecycle == profile.device_lifecycle
    assert restored.device_lifecycle is not None
    assert restored.device_lifecycle.statement.epoch == 1


def test_encrypted_profile_does_not_expose_private_key_material() -> None:
    profile = create_local_profile()

    serialized = encrypt_local_profile(profile, "a reasonably long password")

    assert profile.ratchet_master_key is not None
    assert profile.contact_store_key is not None
    assert profile.state_coordination_key is not None
    assert profile.client_state_id is not None
    private_values = [
        bytes(profile.entity.signing_key),
        bytes(profile.device.device.signing_key),
        bytes(profile.device.device.encryption_key),
        profile.ratchet_master_key,
        profile.contact_store_key,
        profile.state_coordination_key,
        bytes.fromhex(profile.client_state_id),
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



def test_profile_v5_outer_version_is_explicit() -> None:
    profile = create_local_profile()

    document = json.loads(encrypt_local_profile(profile, "password"))

    assert document["version"] == 5


def test_legacy_v1_profile_is_readable_but_has_no_ratchet_key() -> None:
    profile = create_local_profile()
    serialized = _legacy_v1_profile(profile, "legacy password")

    restored = decrypt_local_profile(serialized, "legacy password")

    assert restored.entity.ghost_id == profile.entity.ghost_id
    assert restored.device.device_id == profile.device.device_id
    assert restored.ratchet_master_key is None
    assert restored.contact_store_key is None
    assert restored.client_state_id is None
    assert restored.state_coordination_key is None
    assert restored.state_revision is None
    assert restored.state_previous_digest is None


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


def test_upgrade_legacy_profile_adds_independent_keys_without_changing_identity() -> None:
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
    assert upgraded.contact_store_key is not None
    assert len(upgraded.contact_store_key) == 32
    assert upgraded.contact_store_key != upgraded.ratchet_master_key

    serialized = encrypt_local_profile(upgraded, "legacy password")
    restored = decrypt_local_profile(serialized, "legacy password")
    assert restored.ratchet_master_key == upgraded.ratchet_master_key
    assert restored.contact_store_key == upgraded.contact_store_key


def test_profile_v2_is_readable_and_preserves_ratchet_key() -> None:
    profile = create_local_profile()
    serialized = _legacy_v2_profile(profile, "v2 password")

    restored = decrypt_local_profile(serialized, "v2 password")

    assert restored.entity.ghost_id == profile.entity.ghost_id
    assert restored.device.device_id == profile.device.device_id
    assert restored.ratchet_master_key == profile.ratchet_master_key
    assert restored.contact_store_key is None
    assert restored.client_state_id is None
    assert restored.state_coordination_key is None
    assert restored.state_revision is None
    assert restored.state_previous_digest is None


def test_profile_v2_requires_explicit_upgrade_before_reencrypt() -> None:
    profile = create_local_profile()
    legacy = decrypt_local_profile(
        _legacy_v2_profile(profile, "v2 password"),
        "v2 password",
    )

    with pytest.raises(
        ProfileError,
        match="must contain a 32-byte contact store key",
    ):
        encrypt_local_profile(legacy, "v2 password")


def test_upgrade_v2_preserves_ratchet_key_and_adds_contact_store_key() -> None:
    profile = create_local_profile()
    legacy = decrypt_local_profile(
        _legacy_v2_profile(profile, "v2 password"),
        "v2 password",
    )
    original_ratchet_key = legacy.ratchet_master_key

    upgraded = upgrade_local_profile(legacy)

    assert original_ratchet_key is not None
    assert upgraded.ratchet_master_key == original_ratchet_key
    assert upgraded.contact_store_key is not None
    assert len(upgraded.contact_store_key) == 32
    assert upgraded.contact_store_key != original_ratchet_key

    serialized = encrypt_local_profile(upgraded, "v2 password")
    restored = decrypt_local_profile(serialized, "v2 password")
    assert restored.ratchet_master_key == original_ratchet_key
    assert restored.contact_store_key == upgraded.contact_store_key


def test_profile_v3_is_readable_and_requires_state_identity_upgrade() -> None:
    profile = create_local_profile()
    serialized = _legacy_v3_profile(profile, "v3 password")

    restored = decrypt_local_profile(serialized, "v3 password")

    assert restored.ratchet_master_key == profile.ratchet_master_key
    assert restored.contact_store_key == profile.contact_store_key
    assert restored.client_state_id is None
    assert restored.state_coordination_key is None
    assert restored.state_revision is None
    assert restored.state_previous_digest is None

    with pytest.raises(
        ProfileError,
        match="must contain a client state ID",
    ):
        encrypt_local_profile(restored, "v3 password")


def test_upgrade_v3_preserves_existing_keys_and_adds_state_identity() -> None:
    profile = create_local_profile()
    legacy = decrypt_local_profile(
        _legacy_v3_profile(profile, "v3 password"),
        "v3 password",
    )

    upgraded = upgrade_local_profile(legacy)

    assert upgraded.ratchet_master_key == legacy.ratchet_master_key
    assert upgraded.contact_store_key == legacy.contact_store_key
    assert upgraded.client_state_id is not None
    assert len(upgraded.client_state_id) == 32
    assert upgraded.state_coordination_key is not None
    assert len(upgraded.state_coordination_key) == 32
    assert upgraded.state_coordination_key not in {
        upgraded.ratchet_master_key,
        upgraded.contact_store_key,
    }
    assert upgraded.state_revision == 1
    assert upgraded.state_previous_digest is None

    restored = decrypt_local_profile(
        encrypt_local_profile(upgraded, "v3 password"),
        "v3 password",
    )
    assert restored.client_state_id == upgraded.client_state_id
    assert restored.state_coordination_key == upgraded.state_coordination_key
    assert restored.state_revision == 1
    assert restored.state_previous_digest is None


def test_profile_rejects_partial_state_coordination_identity() -> None:
    profile = create_local_profile()
    partial = type(profile)(
        entity=profile.entity,
        device=profile.device,
        ratchet_master_key=profile.ratchet_master_key,
        contact_store_key=profile.contact_store_key,
        client_state_id=profile.client_state_id,
        state_coordination_key=None,
    )

    with pytest.raises(
        ProfileError,
        match="only partially present",
    ):
        upgrade_local_profile(partial)


def test_profile_rejects_noncanonical_client_state_id_before_encryption() -> None:
    profile = create_local_profile()
    malformed = type(profile)(
        entity=profile.entity,
        device=profile.device,
        ratchet_master_key=profile.ratchet_master_key,
        contact_store_key=profile.contact_store_key,
        client_state_id="A" * 32,
        state_coordination_key=profile.state_coordination_key,
    )

    with pytest.raises(
        ProfileError,
        match="128-bit lowercase hexadecimal",
    ):
        encrypt_local_profile(malformed, "password")


def test_upgrade_is_idempotent_for_profile_v4() -> None:
    profile = create_local_profile()

    assert upgrade_local_profile(profile) is profile


def test_profile_witness_initialization_and_reconciliation(tmp_path) -> None:
    profile = create_local_profile()
    assert profile.client_state_id is not None
    assert profile.state_coordination_key is not None
    witness = SQLiteMonotonicWitness(
        tmp_path / "profile.witness.sqlite3",
        profile.client_state_id,
        profile.state_coordination_key,
    )

    initialized = initialize_profile_witness(profile, witness)
    reconciled = reconcile_profile_witness(profile, witness)

    assert reconciled == initialized
    assert reconciled.component == "profile"
    assert reconciled.revision == 1


def test_profile_witness_rejects_same_revision_divergence(tmp_path) -> None:
    profile = create_local_profile()
    assert profile.client_state_id is not None
    assert profile.state_coordination_key is not None
    witness = SQLiteMonotonicWitness(
        tmp_path / "profile.witness.sqlite3",
        profile.client_state_id,
        profile.state_coordination_key,
    )
    initialize_profile_witness(profile, witness)
    divergent = type(profile)(
        entity=profile.entity,
        device=profile.device,
        ratchet_master_key=utils.random(32),
        contact_store_key=profile.contact_store_key,
        client_state_id=profile.client_state_id,
        state_coordination_key=profile.state_coordination_key,
        state_revision=profile.state_revision,
        state_previous_digest=profile.state_previous_digest,
        device_lifecycle=profile.device_lifecycle,
    )

    with pytest.raises(ProfileError, match="diverges"):
        reconcile_profile_witness(divergent, witness)


def test_profile_device_rotation_advances_lifecycle_and_checkpoint(tmp_path) -> None:
    profile = create_local_profile()
    assert profile.client_state_id is not None
    assert profile.state_coordination_key is not None
    assert profile.device_lifecycle is not None
    witness = SQLiteMonotonicWitness(
        tmp_path / "profile.witness.sqlite3",
        profile.client_state_id,
        profile.state_coordination_key,
    )
    current = initialize_profile_witness(profile, witness)

    rotated = rotate_local_profile_device(
        profile,
        current,
        issued_at=profile.device_lifecycle.statement.issued_at + 1,
    )
    assert rotated.entity.ghost_id == profile.entity.ghost_id
    assert rotated.device.device_id != profile.device.device_id
    assert rotated.device_lifecycle is not None
    assert rotated.device_lifecycle.statement.epoch == 2
    assert rotated.state_revision == 2
    assert rotated.state_previous_digest == current.digest
    assert rotated.ratchet_master_key == profile.ratchet_master_key
    assert rotated.contact_store_key == profile.contact_store_key

    recovered = reconcile_profile_witness(rotated, witness)
    assert recovered.revision == 2
    assert witness.get("profile") is not None
    assert witness.get("profile").revision == 2  # type: ignore[union-attr]

    with pytest.raises(ProfileError, match="older than monotonic witness"):
        reconcile_profile_witness(profile, witness)


def test_profile_and_reference_witness_coherent_rollback_is_not_detected(
    tmp_path,
) -> None:
    profile = create_local_profile()
    assert profile.client_state_id is not None
    assert profile.state_coordination_key is not None
    assert profile.device_lifecycle is not None
    witness_path = tmp_path / "profile-coherent-rollback-witness.sqlite3"
    witness = SQLiteMonotonicWitness(
        witness_path,
        profile.client_state_id,
        profile.state_coordination_key,
    )
    current = initialize_profile_witness(profile, witness)
    witness_at_revision_one = witness_path.read_bytes()

    rotated = rotate_local_profile_device(
        profile,
        current,
        issued_at=profile.device_lifecycle.statement.issued_at + 1,
    )
    assert reconcile_profile_witness(rotated, witness).revision == 2
    assert witness.get("profile").revision == 2

    witness_path.write_bytes(witness_at_revision_one)
    restored_witness = SQLiteMonotonicWitness(
        witness_path,
        profile.client_state_id,
        profile.state_coordination_key,
    )

    restored = reconcile_profile_witness(profile, restored_witness)
    assert restored.revision == 1
    assert restored_witness.get("profile").revision == 1


def test_profile_device_rotation_requires_verified_current_checkpoint(
    tmp_path,
) -> None:
    profile = create_local_profile()
    assert profile.client_state_id is not None
    assert profile.state_coordination_key is not None
    witness = SQLiteMonotonicWitness(
        tmp_path / "profile.witness.sqlite3",
        profile.client_state_id,
        profile.state_coordination_key,
    )
    current = initialize_profile_witness(profile, witness)
    divergent = type(current)(
        state_id=current.state_id,
        component=current.component,
        revision=current.revision,
        previous_digest=current.previous_digest,
        digest="0" * 64,
    )

    with pytest.raises(ProfileError, match="current verified checkpoint"):
        rotate_local_profile_device(profile, divergent)


def test_profile_v4_is_readable_and_requires_lifecycle_upgrade() -> None:
    profile = create_local_profile()
    serialized = _legacy_v4_profile(profile, "v4 password")

    restored = decrypt_local_profile(serialized, "v4 password")

    assert restored.entity.ghost_id == profile.entity.ghost_id
    assert restored.device.device_id == profile.device.device_id
    assert restored.ratchet_master_key == profile.ratchet_master_key
    assert restored.contact_store_key == profile.contact_store_key
    assert restored.client_state_id == profile.client_state_id
    assert restored.state_coordination_key == profile.state_coordination_key
    assert restored.state_revision == 1
    assert restored.state_previous_digest is None
    assert restored.device_lifecycle is None

    with pytest.raises(ProfileError, match="device lifecycle state"):
        encrypt_local_profile(restored, "v4 password")


def test_upgrade_v4_adds_epoch_one_lifecycle_without_changing_device() -> None:
    profile = create_local_profile()
    legacy = decrypt_local_profile(
        _legacy_v4_profile(profile, "v4 password"),
        "v4 password",
    )

    upgraded = upgrade_local_profile(legacy)

    assert upgraded.entity.ghost_id == legacy.entity.ghost_id
    assert upgraded.device.device_id == legacy.device.device_id
    assert upgraded.ratchet_master_key == legacy.ratchet_master_key
    assert upgraded.contact_store_key == legacy.contact_store_key
    assert upgraded.client_state_id == legacy.client_state_id
    assert upgraded.state_coordination_key == legacy.state_coordination_key
    assert upgraded.state_revision == 1
    assert upgraded.state_previous_digest is None
    assert upgraded.device_lifecycle is not None
    assert upgraded.device_lifecycle.statement.epoch == 1
    assert upgraded.device_lifecycle.statement.device_id == legacy.device.device_id

    restored = decrypt_local_profile(
        encrypt_local_profile(upgraded, "v4 password"),
        "v4 password",
    )
    assert restored.device_lifecycle == upgraded.device_lifecycle
