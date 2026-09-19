import shutil
import time
import urllib.parse
from collections.abc import Callable
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from ghostlink.client import GhostNodeClient, GhostNodeRequestError
from ghostlink.config import NodeSettings
from ghostlink.device import EnrolledGhostDevice
from ghostlink.device_lifecycle import create_device_lifecycle_statement
from ghostlink.entity import GhostEntity
from ghostlink.node import create_app, migrate_relay_state
from ghostlink.ratchet_message import RatchetMessage

_RELAY_STATE_ID = "102132435465768798a9bacbdcedfe0f"
_RELAY_STATE_KEY = bytes(reversed(range(32)))


def _requester(
    client: TestClient,
) -> Callable[
    [str, str, dict[str, object] | None, float, dict[str, str]],
    tuple[int, object | None],
]:
    def request(
        method: str,
        url: str,
        payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        assert timeout > 0
        path = urllib.parse.urlparse(url).path
        response = client.request(
            method,
            path,
            json=payload,
            headers=headers,
        )
        return (
            response.status_code,
            response.json() if response.content else None,
        )

    return request


def _node(client: TestClient) -> GhostNodeClient:
    return GhostNodeClient(
        "http://ghostnode.test",
        requester=_requester(client),
    )


def _message(
    sender: EnrolledGhostDevice,
    recipient: EnrolledGhostDevice,
    message_id: str,
) -> RatchetMessage:
    now = int(time.time())
    return RatchetMessage(
        version=3,
        message_id=message_id,
        sender_device_id=sender.device_id,
        recipient_device_id=recipient.device_id,
        created_at=now,
        expires_at=now + 3_600,
        ciphertext_type=3,
        ciphertext=b"multi-relay-matrix",
    )


def _persistent_settings(tmp_path: Path) -> NodeSettings:
    settings = NodeSettings(
        database_path=tmp_path / "relay.sqlite3",
        relay_state_id=_RELAY_STATE_ID,
        relay_witness_path=tmp_path / "relay-witness.sqlite3",
        relay_state_coordination_key=_RELAY_STATE_KEY,
    )
    migrate_relay_state(settings)
    return settings


def test_multi_relay_lifecycle_knowledge_produces_scoped_revocation() -> None:
    entity = GhostEntity.generate()
    device_a = entity.enroll_device()
    device_b = entity.enroll_device()
    peer = GhostEntity.generate().enroll_device()

    lifecycle_n = create_device_lifecycle_statement(
        entity,
        device_a,
        epoch=1,
        issued_at=100,
    )
    lifecycle_n_plus_1 = create_device_lifecycle_statement(
        entity,
        device_b,
        epoch=2,
        issued_at=200,
    )

    relay_a = _node(TestClient(create_app()))
    relay_b = _node(TestClient(create_app()))
    relay_c = _node(TestClient(create_app()))

    for relay in (relay_a, relay_b):
        relay.publish_device_lifecycle(
            bytes(entity.verify_key),
            lifecycle_n,
        )
    relay_a.publish_device_lifecycle(
        bytes(entity.verify_key),
        lifecycle_n_plus_1,
    )

    assert relay_a.get_device_lifecycle(entity.ghost_id).epoch == 2
    assert relay_a.get_device_lifecycle(
        entity.ghost_id
    ).active_device_id == device_b.device_id

    assert relay_b.get_device_lifecycle(entity.ghost_id).epoch == 1
    assert relay_b.get_device_lifecycle(
        entity.ghost_id
    ).active_device_id == device_a.device_id

    with pytest.raises(GhostNodeRequestError) as absent:
        relay_c.get_device_lifecycle(entity.ghost_id)
    assert absent.value.status_code == 404

    with pytest.raises(GhostNodeRequestError) as stale_a:
        relay_a.send_ratchet(
            device_a,
            _message(device_a, peer, "1" * 32),
        )
    assert stale_a.value.status_code == 401

    assert relay_a.send_ratchet(
        device_b,
        _message(device_b, peer, "2" * 32),
    ) == "2" * 32

    assert relay_b.send_ratchet(
        device_a,
        _message(device_a, peer, "3" * 32),
    ) == "3" * 32
    assert relay_b.send_ratchet(
        device_b,
        _message(device_b, peer, "4" * 32),
    ) == "4" * 32

    assert relay_c.send_ratchet(
        device_a,
        _message(device_a, peer, "5" * 32),
    ) == "5" * 32
    assert relay_c.send_ratchet(
        device_b,
        _message(device_b, peer, "6" * 32),
    ) == "6" * 32

    replayed = relay_a.publish_device_lifecycle(
        bytes(entity.verify_key),
        lifecycle_n_plus_1,
    )
    assert replayed.epoch == 2
    assert replayed.active_device_id == device_b.device_id

    with pytest.raises(GhostNodeRequestError) as rollback:
        relay_a.publish_device_lifecycle(
            bytes(entity.verify_key),
            lifecycle_n,
        )
    assert rollback.value.status_code == 409


def test_restoring_relay_database_and_reference_witness_together_is_not_detected(
    tmp_path: Path,
) -> None:
    settings = _persistent_settings(tmp_path)
    entity = GhostEntity.generate()
    device_a = entity.enroll_device()
    device_b = entity.enroll_device()
    lifecycle_n = create_device_lifecycle_statement(
        entity,
        device_a,
        epoch=1,
        issued_at=100,
    )
    lifecycle_n_plus_1 = create_device_lifecycle_statement(
        entity,
        device_b,
        epoch=2,
        issued_at=200,
    )

    node = _node(TestClient(create_app(settings=settings)))
    node.publish_device_lifecycle(
        bytes(entity.verify_key),
        lifecycle_n,
    )

    database_snapshot = tmp_path / "relay-n.sqlite3"
    witness_snapshot = tmp_path / "relay-witness-n.sqlite3"
    assert settings.database_path is not None
    assert settings.relay_witness_path is not None
    shutil.copy2(settings.database_path, database_snapshot)
    shutil.copy2(settings.relay_witness_path, witness_snapshot)

    node.publish_device_lifecycle(
        bytes(entity.verify_key),
        lifecycle_n_plus_1,
    )
    assert node.get_device_lifecycle(entity.ghost_id).epoch == 2

    shutil.copy2(database_snapshot, settings.database_path)
    shutil.copy2(witness_snapshot, settings.relay_witness_path)

    restored = _node(TestClient(create_app(settings=settings)))
    observed = restored.get_device_lifecycle(entity.ghost_id)
    assert observed.epoch == 1
    assert observed.active_device_id == device_a.device_id
