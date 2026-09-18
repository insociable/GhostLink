import urllib.parse
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient
from ghostlink.client.node_client import (
    GhostNodeClient,
    GhostNodeProtocolError,
    GhostNodeRequestError,
)
from ghostlink.entity import GhostEntity
from ghostlink.message import decrypt_message, encrypt_message
from ghostlink.node import create_app


def create_test_requester(
    api_client: TestClient,
) -> Callable[
    [str, str, dict[str, object] | None, float],
    tuple[int, object | None],
]:
    def requester(
        method: str,
        url: str,
        payload: dict[str, object] | None,
        timeout: float,
    ) -> tuple[int, object | None]:
        assert timeout > 0

        parsed = urllib.parse.urlparse(url)
        response = api_client.request(
            method,
            parsed.path,
            json=payload,
        )

        body: object | None
        if response.content:
            body = response.json()
        else:
            body = None

        return response.status_code, body

    return requester


def test_node_client_reports_health() -> None:
    api_client = TestClient(create_app())
    client = GhostNodeClient(
        "http://ghostnode.test",
        requester=create_test_requester(api_client),
    )

    assert client.health()


def test_encrypted_message_can_round_trip_through_node_client() -> None:
    api_client = TestClient(create_app())
    client = GhostNodeClient(
        "http://ghostnode.test",
        requester=create_test_requester(api_client),
    )

    alice = GhostEntity.generate()
    bob = GhostEntity.generate()
    alice_device = alice.enroll_device()
    bob_device = bob.enroll_device()

    message = encrypt_message(
        sender=alice_device,
        recipient=bob_device.public_device(),
        plaintext=b"Bonjour depuis Alice",
    )

    message_id = client.send(message)
    received = client.receive(bob_device.device_id)

    assert len(received) == 1
    assert received[0].message_id == message_id
    assert received[0].message == message

    plaintext = decrypt_message(
        recipient=bob_device,
        sender=alice_device.public_device(),
        message=received[0].message,
    )

    assert plaintext == b"Bonjour depuis Alice"

    client.delete(message_id)

    assert client.receive(bob_device.device_id) == []


def test_node_client_surfaces_relay_errors() -> None:
    api_client = TestClient(create_app())
    client = GhostNodeClient(
        "http://ghostnode.test",
        requester=create_test_requester(api_client),
    )

    with pytest.raises(
        GhostNodeRequestError,
        match="message not found",
    ):
        client.delete("unknown")


def test_node_client_rejects_invalid_health_payload() -> None:
    def requester(
        method: str,
        url: str,
        payload: dict[str, object] | None,
        timeout: float,
    ) -> tuple[int, object | None]:
        return 200, ["not", "an", "object"]

    client = GhostNodeClient(
        "http://ghostnode.test",
        requester=requester,
    )

    with pytest.raises(
        GhostNodeProtocolError,
        match="health response must be a JSON object",
    ):
        client.health()


@pytest.mark.parametrize(
    "base_url",
    [
        "ghostnode.test",
        "ftp://ghostnode.test",
        "http://user:password@ghostnode.test",
    ],
)
def test_node_client_rejects_unsafe_or_invalid_base_urls(base_url: str) -> None:
    with pytest.raises(ValueError):
        GhostNodeClient(base_url)
