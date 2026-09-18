from fastapi.testclient import TestClient
from ghostlink.config import NodeSettings
from ghostlink.node import create_app
from ghostlink.relay_request_auth import InMemoryRelayRequestReplayStore
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
