from fastapi.testclient import TestClient
from ghostlink.config import NodeSettings
from ghostlink.node import create_app
from ghostlink.relay_v2 import InMemoryV2MessageStore
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


class UnhealthyMessageStore(InMemoryV2MessageStore):
    def is_healthy(self) -> bool:
        return False


def test_health_returns_service_unavailable_when_store_is_unhealthy() -> None:
    client = TestClient(create_app(store=UnhealthyMessageStore()))

    response = client.get("/health")

    assert response.status_code == 503
    assert response.json() == {"detail": "storage unavailable"}


def test_runtime_exposes_v2_routes_and_not_v1_routes() -> None:
    client = TestClient(create_app())

    paths = client.get("/openapi.json").json()["paths"]

    assert "/v2/messages" in paths
    assert "/v2/messages/{recipient_device_id}" in paths
    assert "/v2/messages/{recipient_device_id}/{message_id}" in paths
    assert "/v2/prekeys/{device_id}" in paths
    assert "/v3/messages" in paths
    assert "/v3/messages/{recipient_device_id}" in paths
    assert "/v3/messages/{recipient_device_id}/{message_id}" in paths
    assert all(not path.startswith("/v1/") for path in paths)


def test_legacy_v1_route_is_not_available() -> None:
    client = TestClient(create_app())

    response = client.get(
        "/v1/messages/device1:"
        + ("a" * 52)
    )

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
