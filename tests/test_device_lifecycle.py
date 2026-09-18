from __future__ import annotations

import base64
import json

import pytest
from ghostlink.device import GhostDevice
from ghostlink.device_lifecycle import (
    DeviceLifecycleError,
    create_device_lifecycle_statement,
    export_device_lifecycle_statement,
    import_device_lifecycle_statement,
    require_newer_device_lifecycle,
    verify_device_lifecycle_statement,
)
from ghostlink.entity import GhostEntity


def _statement(
    entity: GhostEntity,
    *,
    epoch: int = 1,
    issued_at: int = 1_700_000_000,
):
    return create_device_lifecycle_statement(
        entity,
        entity.enroll_device(),
        epoch=epoch,
        issued_at=issued_at,
    )


def test_lifecycle_round_trip_and_verification() -> None:
    entity = GhostEntity.generate()
    signed = _statement(entity)

    serialized = export_device_lifecycle_statement(signed)
    parsed = import_device_lifecycle_statement(serialized)
    public = verify_device_lifecycle_statement(parsed, entity.verify_key)

    assert parsed == signed
    assert public.ghost_id == entity.ghost_id
    assert public.device_id == signed.statement.device_id
    assert json.dumps(
        json.loads(serialized),
        sort_keys=True,
        separators=(",", ":"),
    ) == serialized


def test_lifecycle_rejects_wrong_identity() -> None:
    entity = GhostEntity.generate()
    signed = _statement(entity)

    with pytest.raises(DeviceLifecycleError, match="GhostID"):
        verify_device_lifecycle_statement(
            signed,
            GhostEntity.generate().verify_key,
        )


def test_lifecycle_rejects_identity_signature_tampering() -> None:
    entity = GhostEntity.generate()
    serialized = export_device_lifecycle_statement(_statement(entity))
    document = json.loads(serialized)
    signature = bytearray(base64.b64decode(document["identity_signature"]))
    signature[-1] ^= 1
    document["identity_signature"] = base64.b64encode(signature).decode("ascii")
    tampered = json.dumps(document, sort_keys=True, separators=(",", ":"))

    parsed = import_device_lifecycle_statement(tampered)
    with pytest.raises(DeviceLifecycleError, match="identity signature"):
        verify_device_lifecycle_statement(parsed, entity.verify_key)


def test_lifecycle_rejects_device_certificate_tampering() -> None:
    entity = GhostEntity.generate()
    serialized = export_device_lifecycle_statement(_statement(entity))
    document = json.loads(serialized)
    replacement = GhostDevice.generate()
    document["device_encryption_public_key"] = base64.b64encode(
        bytes(replacement.encryption_public_key)
    ).decode("ascii")
    tampered = json.dumps(document, sort_keys=True, separators=(",", ":"))

    parsed = import_device_lifecycle_statement(tampered)
    with pytest.raises(DeviceLifecycleError, match="identity signature"):
        verify_device_lifecycle_statement(parsed, entity.verify_key)


def test_lifecycle_rejects_noncanonical_serialization() -> None:
    entity = GhostEntity.generate()
    serialized = export_device_lifecycle_statement(_statement(entity))
    pretty = json.dumps(json.loads(serialized), indent=2)

    with pytest.raises(DeviceLifecycleError, match="canonical JSON"):
        import_device_lifecycle_statement(pretty)


@pytest.mark.parametrize("epoch", [0, -1, 1 << 53, True])
def test_lifecycle_rejects_invalid_epoch(epoch: object) -> None:
    entity = GhostEntity.generate()

    with pytest.raises(DeviceLifecycleError, match="epoch"):
        create_device_lifecycle_statement(
            entity,
            entity.enroll_device(),
            epoch=epoch,  # type: ignore[arg-type]
            issued_at=1_700_000_000,
        )


def test_lifecycle_rejects_device_from_another_identity() -> None:
    entity = GhostEntity.generate()
    foreign_device = GhostEntity.generate().enroll_device()

    with pytest.raises(DeviceLifecycleError, match="GhostID"):
        create_device_lifecycle_statement(
            entity,

            foreign_device,
            epoch=1,
            issued_at=1_700_000_000,
        )


def test_require_newer_lifecycle_accepts_rotation() -> None:
    entity = GhostEntity.generate()
    current = _statement(entity, epoch=4, issued_at=100)
    candidate = _statement(entity, epoch=5, issued_at=101)

    public = require_newer_device_lifecycle(
        current,
        candidate,
        entity.verify_key,
    )

    assert public.device_id == candidate.statement.device_id
    assert public.device_id != current.statement.device_id


def test_require_newer_lifecycle_rejects_rollback() -> None:
    entity = GhostEntity.generate()
    current = _statement(entity, epoch=5, issued_at=101)
    older = _statement(entity, epoch=4, issued_at=100)

    with pytest.raises(DeviceLifecycleError, match="not newer"):
        require_newer_device_lifecycle(
            current,
            older,
            entity.verify_key,
        )


def test_require_newer_lifecycle_rejects_same_epoch_divergence() -> None:
    entity = GhostEntity.generate()
    current = _statement(entity, epoch=5, issued_at=100)
    divergent = _statement(entity, epoch=5, issued_at=101)

    with pytest.raises(DeviceLifecycleError, match="not newer"):
        require_newer_device_lifecycle(
            current,
            divergent,
            entity.verify_key,
        )


def test_require_newer_lifecycle_rejects_timestamp_regression() -> None:
    entity = GhostEntity.generate()
    current = _statement(entity, epoch=5, issued_at=100)
    candidate = _statement(entity, epoch=6, issued_at=99)

    with pytest.raises(DeviceLifecycleError, match="predates"):
        require_newer_device_lifecycle(
            current,
            candidate,
            entity.verify_key,
        )


def test_lifecycle_rejects_forged_device_certificate() -> None:
    entity = GhostEntity.generate()
    device = GhostDevice.generate()

    signed = create_device_lifecycle_statement(
        entity,
        entity.enroll_device(),
        epoch=1,
        issued_at=100,
    )
    original = signed.statement.device_certificate
    forged_certificate = type(original)(
        certificate=type(original.certificate)(
            ghost_id=entity.ghost_id,
            device_id=device.device_id,
            signing_public_key=bytes(device.signing_verify_key),
            encryption_public_key=bytes(device.encryption_public_key),
        ),
        signature=original.signature,
    )
    forged_statement = type(signed.statement)(
        ghost_id=entity.ghost_id,
        epoch=1,
        issued_at=100,
        device_certificate=forged_certificate,
    )
    forged = type(signed)(
        statement=forged_statement,
        identity_signature=entity.signing_key.sign(
            forged_statement.canonical_bytes()
        ).signature,
    )

    with pytest.raises(DeviceLifecycleError, match="certificate signature"):
        verify_device_lifecycle_statement(forged, entity.verify_key)
