import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from ghostlink.config import NodeSettings
from ghostlink.node import create_app, migrate_relay_state
from ghostlink.relay_request_auth import InMemoryRelayRequestReplayStore
from ghostlink.relay_state import (
    RelayStateRollbackError,
    RelayWitnessCorruptionError,
)
from ghostlink.relay_v3 import InMemoryV3MessageStore


def test_health_endpoint() -> None:
    client = TestClient(create_app())

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_remains_public_when_relay_authentication_is_enabled() -> None:
    settings = NodeSettings(access_token="relay-secret")  # noqa: S106
    client = TestClient(create_app(settings=settings))

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_runtime_exposes_current_routes_and_retires_static_v2_messages() -> None:
    client = TestClient(create_app())

    paths = client.get("/openapi.json").json()["paths"]

    assert "/v2/messages" not in paths
    assert "/v2/messages/{recipient_device_id}" not in paths
    assert "/v2/messages/{recipient_device_id}/{message_id}" not in paths
    assert "/v2/prekeys/{device_id}" in paths
    assert "/v3/messages" in paths
    assert "/v3/messages/{recipient_device_id}" in paths
    assert "/v3/messages/{recipient_device_id}/{message_id}" in paths
    assert all(not path.startswith("/v1/") for path in paths)


def test_retired_static_v2_message_route_is_not_available() -> None:
    client = TestClient(create_app())

    response = client.get("/v2/messages/device1:" + ("a" * 52))

    assert response.status_code == 404


def test_legacy_v1_route_is_not_available() -> None:
    client = TestClient(create_app())

    response = client.get("/v1/messages/device1:" + ("a" * 52))

    assert response.status_code == 404


class UnhealthyRatchetMessageStore(InMemoryV3MessageStore):
    def is_healthy(self) -> bool:
        return False


def test_health_includes_ratcheted_v3_storage() -> None:
    client = TestClient(
        create_app(ratchet_store=UnhealthyRatchetMessageStore())
    )

    response = client.get("/health")

    assert response.status_code == 503
    assert response.json() == {"detail": "storage unavailable"}


class UnhealthyRelayRequestReplayStore(InMemoryRelayRequestReplayStore):
    def is_healthy(self) -> bool:
        return False


def test_health_includes_relay_request_replay_storage() -> None:
    client = TestClient(
        create_app(
            request_replay_store=UnhealthyRelayRequestReplayStore(),
        )
    )

    response = client.get("/health")

    assert response.status_code == 503
    assert response.json() == {"detail": "storage unavailable"}


_RELAY_STATE_ID = "00112233445566778899aabbccddeeff"
_RELAY_STATE_KEY = bytes(range(32))


def _persistent_settings(tmp_path: Path) -> NodeSettings:
    return NodeSettings(
        database_path=tmp_path / "relay.sqlite3",
        relay_state_id=_RELAY_STATE_ID,
        relay_witness_path=tmp_path / "relay-witness.sqlite3",
        relay_state_coordination_key=_RELAY_STATE_KEY,
    )


def test_persistent_node_requires_relay_rollback_configuration(
    tmp_path: Path,
) -> None:
    settings = NodeSettings(database_path=tmp_path / "relay.sqlite3")

    with pytest.raises(ValueError, match="persistent GhostNode requires"):
        create_app(settings=settings)


def test_persistent_node_starts_after_explicit_relay_state_migration(
    tmp_path: Path,
) -> None:
    settings = _persistent_settings(tmp_path)

    assert migrate_relay_state(settings) == 1
    app = create_app(settings=settings)
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert app.state.relay_state_coordinator.is_healthy()


def test_persistent_node_rejects_database_rollback_on_restart(
    tmp_path: Path,
) -> None:
    settings = _persistent_settings(tmp_path)
    assert migrate_relay_state(settings) == 1
    assert settings.database_path is not None
    revision_one = settings.database_path.read_bytes()

    app = create_app(settings=settings)
    coordinator = app.state.relay_state_coordinator
    coordinator.mutate(
        lambda connection: connection.execute(
            """
            INSERT INTO relay_request_replay_v1 (
                device_id,
                request_id,
                expires_at
            ) VALUES (?, ?, ?)
            """,
            (
                "device1:" + ("a" * 52),
                "1" * 32,
                2_000_000_000,
            ),
        )
    )

    settings.database_path.write_bytes(revision_one)

    with pytest.raises(
        RelayStateRollbackError,
        match="older than monotonic witness",
    ):
        create_app(settings=settings)


def test_health_fails_after_relay_witness_corruption_is_detected(
    tmp_path: Path,
) -> None:
    settings = _persistent_settings(tmp_path)
    assert migrate_relay_state(settings) == 1
    assert settings.relay_witness_path is not None

    app = create_app(settings=settings)
    client = TestClient(app)

    with sqlite3.connect(settings.relay_witness_path) as connection:
        connection.execute(
            """
            UPDATE relay_witness_v1
            SET digest = ?
            WHERE relay_state_id = ?
            """,
            ("f" * 64, _RELAY_STATE_ID),
        )

    with pytest.raises(RelayWitnessCorruptionError):
        app.state.relay_state_coordinator.reconcile()

    response = client.get("/health")

    assert response.status_code == 503
    assert response.json() == {"detail": "storage unavailable"}
