import base64
import shutil
import time
from pathlib import Path
from sqlite3 import connect

import pytest
from fastapi.testclient import TestClient

from ghostlink.config import NodeSettings
from ghostlink.device import EnrolledGhostDevice
from ghostlink.device_lifecycle import (
    create_device_lifecycle_statement,
    export_device_lifecycle_statement,
)
from ghostlink.entity import GhostEntity
from ghostlink.node import create_app, migrate_relay_state
from ghostlink.prekey_fetch import create_prekey_fetch_request
from ghostlink.prekey_status import create_prekey_status_request
from ghostlink.relay_request_auth import create_relay_request_headers
from ghostlink.relay_state import RelayStateRollbackError

_RELAY_STATE_ID = "00112233445566778899aabbccddeeff"
_RELAY_STATE_KEY = bytes(range(32))


def _lifecycle_request(
    entity: GhostEntity,
    device: EnrolledGhostDevice,
    *,
    epoch: int,
    issued_at: int,
) -> dict[str, object]:
    signed = create_device_lifecycle_statement(
        entity,
        device,
        epoch=epoch,
        issued_at=issued_at,
    )
    return {
        "version": 1,
        "identity_public_key": base64.b64encode(
            bytes(entity.verify_key)
        ).decode("ascii"),
        "statement": export_device_lifecycle_statement(signed),
    }


def _publish_lifecycle(
    client: TestClient,
    entity: GhostEntity,
    device: EnrolledGhostDevice,
    *,
    epoch: int,
    issued_at: int,
):
    return client.put(
        f"/v3/device-lifecycle/{entity.ghost_id}",
        json=_lifecycle_request(
            entity,
            device,
            epoch=epoch,
            issued_at=issued_at,
        ),
    )


def _message_payload(
    sender: EnrolledGhostDevice,
    recipient: EnrolledGhostDevice,
    *,
    message_id: str = "1" * 32,
    now: int,
) -> dict[str, object]:
    return {
        "version": 3,
        "message_id": message_id,
        "sender_device_id": sender.device_id,
        "recipient_device_id": recipient.device_id,
        "created_at": now,
        "expires_at": now + 3600,
        "ciphertext_type": 3,
        "ciphertext": base64.b64encode(b"ciphertext").decode("ascii"),
    }


def _migrated_settings(tmp_path: Path) -> NodeSettings:
    settings = NodeSettings(
        database_path=tmp_path / "relay.sqlite3",
        relay_state_id=_RELAY_STATE_ID,
        relay_witness_path=tmp_path / "relay-witness.sqlite3",
        relay_state_coordination_key=_RELAY_STATE_KEY,
    )
    migrate_relay_state(settings)
    return settings


def test_lifecycle_registry_is_monotonic_and_lookup_returns_latest() -> None:
    entity = GhostEntity.generate()
    first = entity.enroll_device()
    second = entity.enroll_device()
    divergent = entity.enroll_device()
    client = TestClient(create_app())

    first_response = _publish_lifecycle(
        client,
        entity,
        first,
        epoch=1,
        issued_at=100,
    )
    assert first_response.status_code == 200
    assert first_response.json()["active_device_id"] == first.device_id

    retry = _publish_lifecycle(
        client,
        entity,
        first,
        epoch=1,
        issued_at=100,
    )
    assert retry.status_code == 200
    assert retry.json() == first_response.json()

    same_epoch_divergence = _publish_lifecycle(
        client,
        entity,
        divergent,
        epoch=1,
        issued_at=100,
    )
    assert same_epoch_divergence.status_code == 409

    newer = _publish_lifecycle(
        client,
        entity,
        second,
        epoch=2,
        issued_at=200,
    )
    assert newer.status_code == 200
    assert newer.json()["epoch"] == 2
    assert newer.json()["active_device_id"] == second.device_id

    rollback = _publish_lifecycle(
        client,
        entity,
        first,
        epoch=1,
        issued_at=100,
    )
    assert rollback.status_code == 409

    predating = _publish_lifecycle(
        client,
        entity,
        divergent,
        epoch=3,
        issued_at=199,
    )
    assert predating.status_code == 409

    lookup = client.get(f"/v3/device-lifecycle/{entity.ghost_id}")
    assert lookup.status_code == 200
    assert lookup.json() == newer.json()


def test_revoked_device_is_rejected_by_message_routes() -> None:
    entity = GhostEntity.generate()
    revoked = entity.enroll_device()
    active = entity.enroll_device()
    peer = GhostEntity.generate().enroll_device()
    client = TestClient(create_app())
    now = int(time.time())

    assert _publish_lifecycle(
        client,
        entity,
        revoked,
        epoch=1,
        issued_at=now - 1,
    ).status_code == 200
    assert _publish_lifecycle(
        client,
        entity,
        active,
        epoch=2,
        issued_at=now,
    ).status_code == 200

    revoked_sender_payload = _message_payload(
        revoked,
        peer,
        now=now,
    )
    revoked_sender_headers = create_relay_request_headers(
        revoked,
        method="POST",
        path="/v3/messages",
        payload=revoked_sender_payload,
        issued_at=now,
        request_id="1" * 32,
    )
    revoked_sender = client.post(
        "/v3/messages",
        json=revoked_sender_payload,
        headers=revoked_sender_headers,
    )
    assert revoked_sender.status_code == 401
    assert revoked_sender.json() == {"detail": "unauthorized"}

    revoked_recipient_payload = _message_payload(
        peer,
        revoked,
        message_id="2" * 32,
        now=now,
    )
    peer_headers = create_relay_request_headers(
        peer,
        method="POST",
        path="/v3/messages",
        payload=revoked_recipient_payload,
        issued_at=now,
        request_id="2" * 32,
    )
    revoked_recipient = client.post(
        "/v3/messages",
        json=revoked_recipient_payload,
        headers=peer_headers,
    )
    assert revoked_recipient.status_code == 401

    inbox_path = f"/v3/messages/{revoked.device_id}"
    inbox_headers = create_relay_request_headers(
        revoked,
        method="GET",
        path=inbox_path,
        payload=None,
        issued_at=now,
        request_id="3" * 32,
    )
    inbox = client.get(inbox_path, headers=inbox_headers)
    assert inbox.status_code == 401

    delete_path = f"{inbox_path}/{'3' * 32}"
    delete_headers = create_relay_request_headers(
        revoked,
        method="DELETE",
        path=delete_path,
        payload=None,
        issued_at=now,
        request_id="4" * 32,
    )
    deleted = client.delete(delete_path, headers=delete_headers)
    assert deleted.status_code == 401


def test_revoked_device_is_rejected_by_prekey_status_and_fetch() -> None:
    entity = GhostEntity.generate()
    revoked = entity.enroll_device()
    active = entity.enroll_device()
    peer = GhostEntity.generate().enroll_device()
    client = TestClient(create_app())
    now = int(time.time())

    assert _publish_lifecycle(
        client,
        entity,
        revoked,
        epoch=1,
        issued_at=now - 1,
    ).status_code == 200
    assert _publish_lifecycle(
        client,
        entity,
        active,
        epoch=2,
        issued_at=now,
    ).status_code == 200

    status_request = create_prekey_status_request(
        revoked,
        issued_at=now,
        request_id="5" * 32,
    )
    status_response = client.post(
        f"/v2/prekeys/{revoked.device_id}/status",
        json=status_request.model_dump(),
    )
    assert status_response.status_code == 401
    assert status_response.json() == {"detail": "unauthorized"}

    revoked_requester = create_prekey_fetch_request(
        revoked,
        peer.device_id,
        issued_at=now,
        request_id="6" * 32,
    )
    requester_response = client.post(
        f"/v2/prekeys/{peer.device_id}/fetch",
        json=revoked_requester.model_dump(),
    )
    assert requester_response.status_code == 401
    assert requester_response.json() == {"detail": "unauthorized"}

    stale_target = create_prekey_fetch_request(
        peer,
        revoked.device_id,
        issued_at=now,
        request_id="7" * 32,
    )
    target_response = client.post(
        f"/v2/prekeys/{revoked.device_id}/fetch",
        json=stale_target.model_dump(),
    )
    assert target_response.status_code == 401
    assert target_response.json() == {"detail": "unauthorized"}


def test_persistent_lifecycle_state_survives_restart_and_detects_rollback(
    tmp_path: Path,
) -> None:
    settings = _migrated_settings(tmp_path)
    entity = GhostEntity.generate()
    first = entity.enroll_device()
    second = entity.enroll_device()

    first_client = TestClient(create_app(settings=settings))
    assert _publish_lifecycle(
        first_client,
        entity,
        first,
        epoch=1,
        issued_at=100,
    ).status_code == 200

    snapshot = tmp_path / "relay-revision-2.sqlite3"
    shutil.copy2(settings.database_path, snapshot)

    assert _publish_lifecycle(
        first_client,
        entity,
        second,
        epoch=2,
        issued_at=200,
    ).status_code == 200

    restarted = TestClient(create_app(settings=settings))
    current = restarted.get(f"/v3/device-lifecycle/{entity.ghost_id}")
    assert current.status_code == 200
    assert current.json()["active_device_id"] == second.device_id

    shutil.copy2(snapshot, settings.database_path)

    with pytest.raises(RelayStateRollbackError):
        create_app(settings=settings)


def test_empty_lifecycle_tables_are_backward_compatible_with_enrolled_digest(
    tmp_path: Path,
) -> None:
    settings = _migrated_settings(tmp_path)

    with connect(settings.database_path) as connection:
        connection.execute("DROP TABLE device_lifecycle_devices_v1")
        connection.execute("DROP TABLE device_lifecycle_v1")

    client = TestClient(create_app(settings=settings))
    assert client.get("/health").status_code == 200
