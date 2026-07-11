import pytest
from ghostlink.device import derive_device_id
from ghostlink.device_certificate import (
    GhostDeviceCertificate,
    SignedGhostDeviceCertificate,
    sign_device_certificate,
    verify_device_certificate,
)
from ghostlink.identity import Identity
from nacl.public import PrivateKey
from nacl.signing import SigningKey


def create_certificate() -> tuple[
    Identity,
    GhostDeviceCertificate,
]:
    identity = Identity.generate()
    device_signing_key = SigningKey.generate()
    device_encryption_key = PrivateKey.generate()

    certificate = GhostDeviceCertificate(
        ghost_id=identity.ghost_id,
        device_id=derive_device_id(bytes(device_signing_key.verify_key)),
        signing_public_key=bytes(device_signing_key.verify_key),
        encryption_public_key=bytes(device_encryption_key.public_key),
    )

    return identity, certificate


def test_certificate_can_be_signed_and_verified() -> None:
    identity, certificate = create_certificate()

    signed_certificate = sign_device_certificate(
        certificate,
        identity.signing_key,
    )

    assert verify_device_certificate(
        signed_certificate,
        identity.verify_key,
    )


def test_modified_certificate_fails_verification() -> None:
    identity, certificate = create_certificate()

    signed_certificate = sign_device_certificate(
        certificate,
        identity.signing_key,
    )

    modified_certificate = GhostDeviceCertificate(
        ghost_id=certificate.ghost_id,
        device_id=certificate.device_id,
        signing_public_key=certificate.signing_public_key,
        encryption_public_key=bytes(PrivateKey.generate().public_key),
    )

    modified_signed_certificate = SignedGhostDeviceCertificate(
        certificate=modified_certificate,
        signature=signed_certificate.signature,
    )

    assert not verify_device_certificate(
        modified_signed_certificate,
        identity.verify_key,
    )


def test_wrong_identity_key_fails_verification() -> None:
    identity, certificate = create_certificate()
    other_identity = Identity.generate()

    signed_certificate = sign_device_certificate(
        certificate,
        identity.signing_key,
    )

    assert not verify_device_certificate(
        signed_certificate,
        other_identity.verify_key,
    )


def test_canonical_representation_is_deterministic() -> None:
    _, certificate = create_certificate()

    assert certificate.canonical_bytes() == certificate.canonical_bytes()


@pytest.mark.parametrize(
    ("field_name", "invalid_value", "expected_message"),
    [
        ("ghost_id", "invalid", "ghost_id must use the ghost1 format"),
        ("device_id", "invalid", "device_id must use the device1 format"),
        (
            "signing_public_key",
            b"invalid",
            "signing_public_key must contain exactly 32 bytes",
        ),
        (
            "encryption_public_key",
            b"invalid",
            "encryption_public_key must contain exactly 32 bytes",
        ),
    ],
)
def test_invalid_certificate_fields_are_rejected(
    field_name: str,
    invalid_value: str | bytes,
    expected_message: str,
) -> None:
    identity, certificate = create_certificate()

    values: dict[str, str | bytes] = {
        "ghost_id": identity.ghost_id,
        "device_id": certificate.device_id,
        "signing_public_key": certificate.signing_public_key,
        "encryption_public_key": certificate.encryption_public_key,
    }
    values[field_name] = invalid_value

    with pytest.raises(ValueError, match=expected_message):
        GhostDeviceCertificate(
            ghost_id=str(values["ghost_id"]),
            device_id=str(values["device_id"]),
            signing_public_key=bytes(values["signing_public_key"]),
            encryption_public_key=bytes(values["encryption_public_key"]),
        )