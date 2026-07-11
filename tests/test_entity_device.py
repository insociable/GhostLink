from ghostlink.device import GhostDevice
from ghostlink.device_certificate import verify_device_certificate
from ghostlink.entity import GhostEntity


def test_ghost_entity_can_be_generated() -> None:
    entity = GhostEntity.generate()

    assert entity.ghost_id.startswith("ghost1:")
    assert len(bytes(entity.verify_key)) == 32


def test_distinct_entities_have_distinct_ids() -> None:
    first = GhostEntity.generate()
    second = GhostEntity.generate()

    assert first.ghost_id != second.ghost_id


def test_ghost_device_can_be_generated() -> None:
    device = GhostDevice.generate()

    assert device.device_id.startswith("device1:")
    assert len(bytes(device.signing_verify_key)) == 32
    assert len(bytes(device.encryption_public_key)) == 32


def test_device_signing_and_encryption_keys_are_independent() -> None:
    device = GhostDevice.generate()

    assert bytes(device.signing_verify_key) != bytes(
        device.encryption_public_key,
    )


def test_distinct_devices_have_distinct_ids() -> None:
    first = GhostDevice.generate()
    second = GhostDevice.generate()

    assert first.device_id != second.device_id
def test_entity_can_authorize_a_device() -> None:
    entity = GhostEntity.generate()
    device = GhostDevice.generate()

    signed_certificate = entity.authorize_device(device)

    assert signed_certificate.certificate.ghost_id == entity.ghost_id
    assert signed_certificate.certificate.device_id == device.device_id

    assert verify_device_certificate(
        signed_certificate,
        entity.verify_key,
    )
def test_entity_can_enroll_device() -> None:
    entity = GhostEntity.generate()

    enrolled_device = entity.enroll_device()

    assert enrolled_device.device_id == enrolled_device.device.device_id
    assert enrolled_device.certificate.certificate.ghost_id == entity.ghost_id
    assert enrolled_device.certificate.certificate.device_id == enrolled_device.device_id

    assert verify_device_certificate(
        enrolled_device.certificate,
        entity.verify_key,
    )       