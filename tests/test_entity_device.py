from ghostlink.device import GhostDevice
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