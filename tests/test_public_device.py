from dataclasses import replace

import pytest

from ghostlink.device import PublicGhostDevice
from ghostlink.entity import GhostEntity


def test_public_device_can_be_built_from_valid_certificate() -> None:
    entity = GhostEntity.generate()
    enrolled_device = entity.enroll_device()

    public_device = PublicGhostDevice.from_certificate(
        enrolled_device.certificate,
        entity.verify_key,
    )

    assert public_device.ghost_id == entity.ghost_id
    assert public_device.device_id == enrolled_device.device_id
    assert bytes(public_device.signing_verify_key) == bytes(
        enrolled_device.device.signing_verify_key
    )
    assert bytes(public_device.encryption_public_key) == bytes(
        enrolled_device.device.encryption_public_key
    )


def test_public_device_rejects_wrong_identity_key() -> None:
    entity = GhostEntity.generate()
    enrolled_device = entity.enroll_device()
    other_entity = GhostEntity.generate()

    with pytest.raises(
        ValueError,
        match="certificate GhostID does not match identity key",
    ):
        PublicGhostDevice.from_certificate(
            enrolled_device.certificate,
            other_entity.verify_key,
        )


def test_public_device_rejects_invalid_certificate_signature() -> None:
    entity = GhostEntity.generate()
    enrolled_device = entity.enroll_device()
    invalid_certificate = replace(
        enrolled_device.certificate,
        signature=b"\x00" * 64,
    )

    with pytest.raises(
        ValueError,
        match="device certificate signature is invalid",
    ):
        PublicGhostDevice.from_certificate(
            invalid_certificate,
            entity.verify_key,
        )
