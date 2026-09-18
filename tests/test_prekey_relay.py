import base64
import json
import time
from pathlib import Path

from fastapi.testclient import TestClient
from ghostlink.config import NodeSettings
from ghostlink.device import EnrolledGhostDevice
from ghostlink.entity import GhostEntity
from ghostlink.node import create_app
from ghostlink.ratchet_binding import RatchetPreKeyMaterial
from ghostlink.ratchet_publication import (
    create_ratchet_prekey_publication,
    export_ratchet_prekey_publication,
)


def material(
    *,
    seed: int,
    pre_key_id: int | None,
    signed_pre_key_id: int,
    kyber_pre_key_id: int,
) -> RatchetPreKeyMaterial:
    return RatchetPreKeyMaterial(
        registration_id=4_200,
        identity_key=bytes([1]) * 33,
        pre_key_id=pre_key_id,
        pre_key=None if pre_key_id is None else bytes([seed]) * 33,
        signed_pre_key_id=signed_pre_key_id,
        signed_pre_key=bytes([seed + 1]) * 33,
        signed_pre_key_signature=bytes([seed + 2]) * 64,
        kyber_pre_key_id=kyber_pre_key_id,
        kyber_pre_key=bytes([seed + 3]) * 1_184,
        kyber_pre_key_signature=bytes([seed + 4]) * 64,
    )


def publication_request(
    entity: GhostEntity,
    device: EnrolledGhostDevice,
    *,
    sequence: int,
    issued_at: int | None = None,
    lifetime_seconds: int = 3_600,
) -> dict[str, object]:
    now = int(time.time()) if issued_at is None else issued_at
    base = sequence * 100
    signed_pre_key_id = 2_000 + sequence

    publication = create_ratchet_prekey_publication(
        device,
        publication_sequence=sequence,
        issued_at=now,
        expires_at=now + lifetime_seconds,
        one_time_material=(
            material(
                seed=10,
                pre_key_id=1_000 + base + 1,
                signed_pre_key_id=signed_pre_key_id,
                kyber_pre_key_id=3_000 + base + 1,
            ),
            material(
                seed=20,
                pre_key_id=1_000 + base + 2,
                signed_pre_key_id=signed_pre_key_id,
                kyber_pre_key_id=3_000 + base + 2,
            ),
        ),
        fallback_material=material(
            seed=30,
            pre_key_id=None,
            signed_pre_key_id=signed_pre_key_id,
            kyber_pre_key_id=3_000 + base + 99,
        ),
    )
    return {
        "version": 1,
        "device_signing_public_key": base64.b64encode(
            bytes(device.device.signing_verify_key)
        ).decode("ascii"),
        "publication": export_ratchet_prekey_publication(publication),
    }


def test_prekey_publication_is_cryptographically_verified_and_acknowledged() -> None:

    entity = GhostEntity.generate()
    device = entity.enroll_device()
    request = publication_request(entity, device, sequence=1)
    client = TestClient(create_app())

    response = client.put(f"/v2/prekeys/{device.device_id}", json=request)

    assert response.status_code == 200
    assert response.json()["device_id"] == device.device_id
    assert response.json()["publication_sequence"] == 1
    assert response.json()["one_time_count"] == 2


def test_prekey_publication_rejects_route_device_mismatch() -> None:

    entity = GhostEntity.generate()
    device = entity.enroll_device()
    request = publication_request(entity, device, sequence=1)
    other_device_id = GhostEntity.generate().enroll_device().device_id

    response = TestClient(create_app()).put(
        f"/v2/prekeys/{other_device_id}",
        json=request,
    )

    assert response.status_code == 422
    assert response.json() == {
        "detail": "route DeviceID does not match device signing public key"
    }


def test_prekey_publication_rejects_structurally_valid_signature_tampering() -> None:

    entity = GhostEntity.generate()
    device = entity.enroll_device()
    request = publication_request(entity, device, sequence=1)
    document = json.loads(str(request["publication"]))
    document["one_time"][0]["pre_key"] = base64.b64encode(
        bytes([0x99]) * 33
    ).decode("ascii")
    request["publication"] = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
    )

    response = TestClient(create_app()).put(
        f"/v2/prekeys/{device.device_id}",
        json=request,
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "device signature is invalid"}


def test_prekey_publication_sequence_is_strictly_monotonic_and_idempotent() -> None:

    entity = GhostEntity.generate()
    device = entity.enroll_device()
    client = TestClient(create_app())

    first = publication_request(entity, device, sequence=1)
    assert client.put(f"/v2/prekeys/{device.device_id}", json=first).status_code == 200
    assert client.put(f"/v2/prekeys/{device.device_id}", json=first).status_code == 200

    skipped = publication_request(entity, device, sequence=3)
    response = client.put(f"/v2/prekeys/{device.device_id}", json=skipped)
    assert response.status_code == 409
    assert response.json() == {
        "detail": "publication_sequence must advance by exactly one"
    }

    second = publication_request(entity, device, sequence=2)
    accepted = client.put(f"/v2/prekeys/{device.device_id}", json=second)
    assert accepted.status_code == 200
    assert accepted.json()["publication_sequence"] == 2

    stale = client.put(f"/v2/prekeys/{device.device_id}", json=first)
    assert stale.status_code == 409


def test_prekey_publication_requires_shared_relay_bearer_when_enabled() -> None:

    token = "prekey-relay-secret"  # noqa: S105
    entity = GhostEntity.generate()
    device = entity.enroll_device()
    request = publication_request(entity, device, sequence=1)
    client = TestClient(
        create_app(settings=NodeSettings(access_token=token))
    )

    missing = client.put(f"/v2/prekeys/{device.device_id}", json=request)
    accepted = client.put(
        f"/v2/prekeys/{device.device_id}",
        json=request,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert missing.status_code == 401
    assert accepted.status_code == 200


def test_prekey_publication_rejects_already_expired_generation() -> None:

    entity = GhostEntity.generate()
    device = entity.enroll_device()
    now = int(time.time())
    request = publication_request(
        entity,
        device,
        sequence=1,
        issued_at=now - 100,
        lifetime_seconds=50,
    )

    response = TestClient(create_app()).put(
        f"/v2/prekeys/{device.device_id}",
        json=request,
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "publication is already expired"}


def test_prekey_publication_sqlite_replacement_survives_app_recreation(
    tmp_path: Path,
) -> None:

    database_path = tmp_path / "relay.sqlite3"
    settings = NodeSettings(database_path=database_path)
    entity = GhostEntity.generate()
    device = entity.enroll_device()

    first = publication_request(entity, device, sequence=1)
    first_client = TestClient(create_app(settings=settings))
    assert (
        first_client.put(
            f"/v2/prekeys/{device.device_id}",
            json=first,
        ).status_code
        == 200
    )

    second_client = TestClient(create_app(settings=settings))
    retry = second_client.put(
        f"/v2/prekeys/{device.device_id}",
        json=first,
    )
    assert retry.status_code == 200
    assert retry.json()["publication_sequence"] == 1

    second = publication_request(entity, device, sequence=2)
    replaced = second_client.put(
        f"/v2/prekeys/{device.device_id}",
        json=second,
    )
    assert replaced.status_code == 200
    assert replaced.json()["publication_sequence"] == 2
