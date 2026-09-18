"""Encrypted local GhostLink identity profiles."""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass

from nacl import utils
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey
from nacl.pwhash import argon2id
from nacl.secret import SecretBox
from nacl.signing import SigningKey

from ghostlink.device import EnrolledGhostDevice, GhostDevice, PublicGhostDevice
from ghostlink.device_certificate import (
    GhostDeviceCertificate,
    SignedGhostDeviceCertificate,
)
from ghostlink.entity import GhostEntity

_PROFILE_VERSION = 4
_LEGACY_PROFILE_VERSION = 1
_RATCHET_PROFILE_VERSION = 2
_CONTACT_PROFILE_VERSION = 3
_MAX_PROFILE_BYTES = 65_536
_KDF_NAME = "argon2id"
_CIPHER_NAME = "secretbox"
_KDF_OPSLIMIT = argon2id.OPSLIMIT_INTERACTIVE
_KDF_MEMLIMIT = argon2id.MEMLIMIT_INTERACTIVE
_PRIVATE_KEY_SIZE = 32
_RATCHET_MASTER_KEY_SIZE = 32
_CONTACT_STORE_KEY_SIZE = 32
_CLIENT_STATE_ID_BYTES = 16
_STATE_COORDINATION_KEY_SIZE = 32
_MAX_STATE_REVISION = (1 << 53) - 1
_SIGNATURE_SIZE = 64

_OUTER_FIELDS = {"version", "kdf", "cipher", "ciphertext"}
_KDF_FIELDS = {"name", "salt", "opslimit", "memlimit"}
_SECRET_FIELDS_V1 = {
    "identity_signing_seed",
    "device_signing_seed",
    "device_encryption_private_key",
    "ghost_id",
    "device_id",
    "device_signing_public_key",
    "device_encryption_public_key",
    "device_certificate_signature",
}
_SECRET_FIELDS_V2 = _SECRET_FIELDS_V1 | {"ratchet_master_key"}
_SECRET_FIELDS_V3 = _SECRET_FIELDS_V2 | {"contact_store_key"}
_SECRET_FIELDS_V4 = _SECRET_FIELDS_V3 | {
    "client_state_id",
    "state_coordination_key",
    "state_revision",
    "state_previous_digest",
}


class ProfileError(ValueError):
    """Base error for local GhostLink profile handling."""


class ProfileUnlockError(ProfileError):
    """Raised when a profile cannot be decrypted or authenticated."""


@dataclass(frozen=True, slots=True)
class LocalProfile:
    """A local GhostLink identity, enrolled device and independent local secrets."""

    entity: GhostEntity
    device: EnrolledGhostDevice
    ratchet_master_key: bytes | None
    contact_store_key: bytes | None = None
    client_state_id: str | None = None
    state_coordination_key: bytes | None = None
    state_revision: int | None = None
    state_previous_digest: str | None = None


def create_local_profile() -> LocalProfile:
    """Generate a fresh local identity and one enrolled device."""
    entity = GhostEntity.generate()
    return LocalProfile(
        entity=entity,
        device=entity.enroll_device(),
        ratchet_master_key=utils.random(_RATCHET_MASTER_KEY_SIZE),
        contact_store_key=utils.random(_CONTACT_STORE_KEY_SIZE),
        client_state_id=utils.random(_CLIENT_STATE_ID_BYTES).hex(),
        state_coordination_key=utils.random(_STATE_COORDINATION_KEY_SIZE),
        state_revision=1,
        state_previous_digest=None,
    )


def _encode_base64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode_base64(value: object, field: str, expected_size: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise ProfileError(f"{field} must be Base64 text")

    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ProfileError(f"{field} must be valid Base64") from exc

    if expected_size is not None and len(decoded) != expected_size:
        raise ProfileError(
            f"{field} must decode to exactly {expected_size} bytes"
        )

    return decoded


def _validate_client_state_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != _CLIENT_STATE_ID_BYTES * 2
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProfileError(
            "client_state_id must be 128-bit lowercase hexadecimal"
        )
    return value


def _validate_state_revision(value: object) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
        or value > _MAX_STATE_REVISION
    ):
        raise ProfileError(
            "state_revision must be a positive JSON-safe integer"
        )
    return value


def _validate_previous_digest(
    value: object,
    *,
    revision: int,
) -> str | None:
    if revision == 1:
        if value is not None:
            raise ProfileError(
                "initial profile state must not have a previous digest"
            )
        return None
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProfileError(
            "state_previous_digest must be 32-byte lowercase hexadecimal"
        )
    return value


def _require_mapping(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ProfileError(f"{context} must be a JSON object")

    document: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ProfileError(f"{context} field names must be text")
        document[key] = item

    return document


def _require_exact_fields(
    document: dict[str, object],
    expected: set[str],
    context: str,
) -> None:
    fields = set(document)
    if fields == expected:
        return

    missing = sorted(expected - fields)
    unknown = sorted(fields - expected)
    details: list[str] = []

    if missing:
        details.append(f"missing fields: {', '.join(missing)}")
    if unknown:
        details.append(f"unknown fields: {', '.join(unknown)}")

    raise ProfileError(f"{context}: {'; '.join(details)}")


def _require_text(document: dict[str, object], field: str) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not value:
        raise ProfileError(f"{field} must be non-empty text")
    return value


def _require_integer(document: dict[str, object], field: str) -> int:
    value = document.get(field)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ProfileError(f"{field} must be an integer")
    return value


def _parse_json_object(serialized: bytes, context: str) -> dict[str, object]:
    try:
        parsed: object = json.loads(serialized.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"{context} must be valid UTF-8 JSON") from exc

    return _require_mapping(parsed, context)


def _password_bytes(password: str) -> bytes:
    if not password:
        raise ProfileError("password must not be empty")

    encoded = password.encode("utf-8")
    if len(encoded) > argon2id.PASSWD_MAX:
        raise ProfileError("password is too long")

    return encoded


def _serialize_secret(profile: LocalProfile) -> bytes:
    certificate = profile.device.certificate.certificate
    if (
        profile.ratchet_master_key is None
        or not isinstance(profile.ratchet_master_key, bytes)
        or len(profile.ratchet_master_key) != _RATCHET_MASTER_KEY_SIZE
    ):
        raise ProfileError(
            "profile must contain a 32-byte ratchet master key before encryption"
        )

    if (
        profile.contact_store_key is None
        or not isinstance(profile.contact_store_key, bytes)
        or len(profile.contact_store_key) != _CONTACT_STORE_KEY_SIZE
    ):
        raise ProfileError(
            "profile must contain a 32-byte contact store key before encryption"
        )

    if profile.client_state_id is None:
        raise ProfileError(
            "profile must contain a client state ID before encryption"
        )
    client_state_id = _validate_client_state_id(profile.client_state_id)
    if (
        profile.state_coordination_key is None
        or not isinstance(profile.state_coordination_key, bytes)
        or len(profile.state_coordination_key) != _STATE_COORDINATION_KEY_SIZE
    ):
        raise ProfileError(
            "profile must contain a 32-byte state coordination key before encryption"
        )
    state_revision = _validate_state_revision(profile.state_revision)
    state_previous_digest = _validate_previous_digest(
        profile.state_previous_digest,
        revision=state_revision,
    )

    # Validate the complete public/private relationship before persisting it.
    PublicGhostDevice.from_certificate(
        profile.device.certificate,
        profile.entity.verify_key,
    )

    if bytes(profile.device.device.signing_verify_key) != certificate.signing_public_key:
        raise ProfileError("device signing key does not match certificate")
    if (
        bytes(profile.device.device.encryption_public_key)
        != certificate.encryption_public_key
    ):
        raise ProfileError("device encryption key does not match certificate")

    secret = {
        "identity_signing_seed": _encode_base64(bytes(profile.entity.signing_key)),
        "device_signing_seed": _encode_base64(
            bytes(profile.device.device.signing_key)
        ),
        "device_encryption_private_key": _encode_base64(
            bytes(profile.device.device.encryption_key)
        ),
        "ghost_id": certificate.ghost_id,
        "device_id": certificate.device_id,
        "device_signing_public_key": _encode_base64(
            certificate.signing_public_key
        ),
        "device_encryption_public_key": _encode_base64(
            certificate.encryption_public_key
        ),
        "device_certificate_signature": _encode_base64(
            profile.device.certificate.signature
        ),
        "ratchet_master_key": _encode_base64(profile.ratchet_master_key),
        "contact_store_key": _encode_base64(profile.contact_store_key),
        "client_state_id": client_state_id,
        "state_coordination_key": _encode_base64(
            profile.state_coordination_key
        ),
        "state_revision": state_revision,
        "state_previous_digest": state_previous_digest,
    }

    return json.dumps(
        secret,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _deserialize_secret(serialized: bytes, version: int) -> LocalProfile:
    secret = _parse_json_object(serialized, "decrypted profile")
    if version == _LEGACY_PROFILE_VERSION:
        expected_fields = _SECRET_FIELDS_V1
    elif version == _RATCHET_PROFILE_VERSION:
        expected_fields = _SECRET_FIELDS_V2
    elif version == _CONTACT_PROFILE_VERSION:
        expected_fields = _SECRET_FIELDS_V3
    else:
        expected_fields = _SECRET_FIELDS_V4
    _require_exact_fields(secret, expected_fields, "decrypted profile")

    identity_seed = _decode_base64(
        secret["identity_signing_seed"],
        "identity_signing_seed",
        _PRIVATE_KEY_SIZE,
    )
    device_signing_seed = _decode_base64(
        secret["device_signing_seed"],
        "device_signing_seed",
        _PRIVATE_KEY_SIZE,
    )
    device_encryption_private_key = _decode_base64(
        secret["device_encryption_private_key"],
        "device_encryption_private_key",
        _PRIVATE_KEY_SIZE,
    )
    signing_public_key = _decode_base64(
        secret["device_signing_public_key"],
        "device_signing_public_key",
        _PRIVATE_KEY_SIZE,
    )
    encryption_public_key = _decode_base64(
        secret["device_encryption_public_key"],
        "device_encryption_public_key",
        _PRIVATE_KEY_SIZE,
    )
    signature = _decode_base64(
        secret["device_certificate_signature"],
        "device_certificate_signature",
        _SIGNATURE_SIZE,
    )
    ratchet_master_key = (
        None
        if version == _LEGACY_PROFILE_VERSION
        else _decode_base64(
            secret["ratchet_master_key"],
            "ratchet_master_key",
            _RATCHET_MASTER_KEY_SIZE,
        )
    )
    contact_store_key = (
        None
        if version in {_LEGACY_PROFILE_VERSION, _RATCHET_PROFILE_VERSION}
        else _decode_base64(
            secret["contact_store_key"],
            "contact_store_key",
            _CONTACT_STORE_KEY_SIZE,
        )
    )
    client_state_id = (
        None
        if version != _PROFILE_VERSION
        else _validate_client_state_id(secret["client_state_id"])
    )
    state_coordination_key = (
        None
        if version != _PROFILE_VERSION
        else _decode_base64(
            secret["state_coordination_key"],
            "state_coordination_key",
            _STATE_COORDINATION_KEY_SIZE,
        )
    )
    if version == _PROFILE_VERSION:
        state_revision = _validate_state_revision(secret["state_revision"])
        state_previous_digest = _validate_previous_digest(
            secret["state_previous_digest"],
            revision=state_revision,
        )
    else:
        state_revision = None
        state_previous_digest = None

    entity = GhostEntity(signing_key=SigningKey(identity_seed))
    device = GhostDevice(
        signing_key=SigningKey(device_signing_seed),
        encryption_key=PrivateKey(device_encryption_private_key),
    )

    certificate = GhostDeviceCertificate(
        ghost_id=_require_text(secret, "ghost_id"),
        device_id=_require_text(secret, "device_id"),
        signing_public_key=signing_public_key,
        encryption_public_key=encryption_public_key,
    )
    signed_certificate = SignedGhostDeviceCertificate(
        certificate=certificate,
        signature=signature,
    )
    enrolled_device = EnrolledGhostDevice(
        device=device,
        certificate=signed_certificate,
    )

    if bytes(device.signing_verify_key) != signing_public_key:
        raise ProfileError("device signing private key does not match certificate")
    if bytes(device.encryption_public_key) != encryption_public_key:
        raise ProfileError("device encryption private key does not match certificate")

    try:
        PublicGhostDevice.from_certificate(
            signed_certificate,
            entity.verify_key,
        )
    except ValueError as exc:
        raise ProfileError(str(exc)) from exc

    return LocalProfile(
        entity=entity,
        device=enrolled_device,
        ratchet_master_key=ratchet_master_key,
        contact_store_key=contact_store_key,
        client_state_id=client_state_id,
        state_coordination_key=state_coordination_key,
        state_revision=state_revision,
        state_previous_digest=state_previous_digest,
    )


def encrypt_local_profile(profile: LocalProfile, password: str) -> str:
    """Encrypt a local profile using Argon2id and SecretBox."""
    password_bytes = _password_bytes(password)
    salt = utils.random(argon2id.SALTBYTES)
    key = argon2id.kdf(
        SecretBox.KEY_SIZE,
        password_bytes,
        salt,
        opslimit=_KDF_OPSLIMIT,
        memlimit=_KDF_MEMLIMIT,
    )
    ciphertext = bytes(SecretBox(key).encrypt(_serialize_secret(profile)))

    document = {
        "version": _PROFILE_VERSION,
        "kdf": {
            "name": _KDF_NAME,
            "salt": _encode_base64(salt),
            "opslimit": _KDF_OPSLIMIT,
            "memlimit": _KDF_MEMLIMIT,
        },
        "cipher": _CIPHER_NAME,
        "ciphertext": _encode_base64(ciphertext),
    }

    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
    )


def decrypt_local_profile(serialized: str, password: str) -> LocalProfile:
    """Decrypt and validate a local GhostLink profile."""
    raw_profile = serialized.encode("utf-8")
    if len(raw_profile) > _MAX_PROFILE_BYTES:
        raise ProfileError("profile is too large")

    document = _parse_json_object(raw_profile, "profile")
    _require_exact_fields(document, _OUTER_FIELDS, "profile")

    version = _require_integer(document, "version")
    if version not in {
        _LEGACY_PROFILE_VERSION,
        _RATCHET_PROFILE_VERSION,
        _CONTACT_PROFILE_VERSION,
        _PROFILE_VERSION,
    }:
        raise ProfileError("unsupported profile version")

    cipher = _require_text(document, "cipher")
    if cipher != _CIPHER_NAME:
        raise ProfileError("unsupported profile cipher")

    kdf = _require_mapping(document["kdf"], "profile kdf")
    _require_exact_fields(kdf, _KDF_FIELDS, "profile kdf")

    if _require_text(kdf, "name") != _KDF_NAME:
        raise ProfileError("unsupported profile KDF")

    opslimit = _require_integer(kdf, "opslimit")
    memlimit = _require_integer(kdf, "memlimit")

    # v1 accepts only the parameters it emits. This prevents a tampered profile
    # from forcing an unexpectedly expensive KDF invocation.
    if opslimit != _KDF_OPSLIMIT or memlimit != _KDF_MEMLIMIT:
        raise ProfileError("unsupported profile KDF parameters")

    salt = _decode_base64(
        kdf["salt"],
        "profile kdf salt",
        argon2id.SALTBYTES,
    )
    ciphertext = _decode_base64(
        document["ciphertext"],
        "profile ciphertext",
    )
    if not ciphertext:
        raise ProfileError("profile ciphertext must not be empty")

    password_bytes = _password_bytes(password)
    key = argon2id.kdf(
        SecretBox.KEY_SIZE,
        password_bytes,
        salt,
        opslimit=_KDF_OPSLIMIT,
        memlimit=_KDF_MEMLIMIT,
    )

    try:
        plaintext = SecretBox(key).decrypt(ciphertext)
    except CryptoError as exc:
        raise ProfileUnlockError(
            "profile password is incorrect or profile data was modified"
        ) from exc

    return _deserialize_secret(plaintext, version)



def upgrade_local_profile(profile: LocalProfile) -> LocalProfile:
    """Upgrade a decrypted v1/v2/v3 profile to the current independent secrets."""
    ratchet_master_key = profile.ratchet_master_key
    if (
        ratchet_master_key is not None
        and len(ratchet_master_key) != _RATCHET_MASTER_KEY_SIZE
    ):
        raise ProfileError("ratchet master key has an invalid length")

    contact_store_key = profile.contact_store_key
    if (
        contact_store_key is not None
        and len(contact_store_key) != _CONTACT_STORE_KEY_SIZE
    ):
        raise ProfileError("contact store key has an invalid length")

    client_state_id = profile.client_state_id
    state_coordination_key = profile.state_coordination_key
    state_revision = profile.state_revision
    state_previous_digest = profile.state_previous_digest

    has_state_identity = (
        client_state_id is not None or state_coordination_key is not None
    )
    has_checkpoint_metadata = (
        state_revision is not None or state_previous_digest is not None
    )
    if (client_state_id is None) != (state_coordination_key is None):
        raise ProfileError(
            "profile state coordination identity is only partially present"
        )
    if not has_state_identity and has_checkpoint_metadata:
        raise ProfileError(
            "profile checkpoint metadata exists without state coordination identity"
        )
    if has_state_identity:
        if client_state_id is None or state_coordination_key is None:
            raise ProfileError(
                "profile state coordination identity is only partially present"
            )
        _validate_client_state_id(client_state_id)
        if len(state_coordination_key) != _STATE_COORDINATION_KEY_SIZE:
            raise ProfileError("state coordination key has an invalid length")
        if state_revision is None:
            raise ProfileError(
                "profile state coordination identity is missing checkpoint revision"
            )
        state_revision = _validate_state_revision(state_revision)
        state_previous_digest = _validate_previous_digest(
            state_previous_digest,
            revision=state_revision,
        )

    if (
        ratchet_master_key is not None
        and contact_store_key is not None
        and client_state_id is not None
        and state_coordination_key is not None
        and state_revision is not None
    ):
        return profile

    return LocalProfile(
        entity=profile.entity,
        device=profile.device,
        ratchet_master_key=(
            ratchet_master_key
            if ratchet_master_key is not None
            else utils.random(_RATCHET_MASTER_KEY_SIZE)
        ),
        contact_store_key=(
            contact_store_key
            if contact_store_key is not None
            else utils.random(_CONTACT_STORE_KEY_SIZE)
        ),
        client_state_id=(
            client_state_id
            if client_state_id is not None
            else utils.random(_CLIENT_STATE_ID_BYTES).hex()
        ),
        state_coordination_key=(
            state_coordination_key
            if state_coordination_key is not None
            else utils.random(_STATE_COORDINATION_KEY_SIZE)
        ),
        state_revision=(
            state_revision if state_revision is not None else 1
        ),
        state_previous_digest=(
            state_previous_digest
            if state_revision is not None
            else None
        ),
    )
