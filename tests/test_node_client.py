import base64
import time
import urllib.parse
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient
from ghostlink.client.node_client import (
    GhostNodeClient,
    GhostNodeProtocolError,
    GhostNodeRequestError,
)
from ghostlink.config import NodeSettings
from ghostlink.entity import GhostEntity
from ghostlink.message import decrypt_message, encrypt_message
from ghostlink.node import create_app

ALICE_DEVICE_ID = "device1:" + ("a" * 52)
BOB_DEVICE_ID = "device1:" + ("b" * 52)


def create_test_requester(
    api_client: TestClient,
) -> Callable[
    [str, str, dict[str, object] | None, float, dict[str, str]],
    tuple[int, object | None],
]:
    def requester(
        method: str,
        url: str,
        payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        assert timeout > 0

        parsed = urllib.parse.urlparse(url)
        response = api_client.request(
            method,
            parsed.path,
            json=payload,
            headers=headers,
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


def test_encrypted_message_round_trip_through_node_client() -> None:
    api_client = TestClient(create_app())
    client = GhostNodeClient(
        "http://ghostnode.test",
        requester=create_test_requester(api_client),
    )

    alice = GhostEntity.generate()
    bob = GhostEntity.generate()
    alice_device = alice.enroll_device()
    bob_device = bob.enroll_device()
    now = int(time.time())

    message = encrypt_message(
        alice_device,
        bob_device.public_device(),
        b"Bonjour Bob protocol v2",
        created_at=now,
    )

    message_id = client.send(message)
    received = client.receive(bob_device.device_id)

    assert message_id == message.message_id
    assert received == [message]

    plaintext = decrypt_message(
        bob_device,
        alice_device.public_device(),
        received[0],
        now=now,
    )
    assert plaintext == b"Bonjour Bob protocol v2"

    client.delete(bob_device.device_id, message.message_id)
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
        client.delete(BOB_DEVICE_ID, "a" * 32)


def test_node_client_rejects_invalid_health_payload() -> None:
    def requester(
        method: str,
        url: str,
        payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
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


def test_node_client_sends_bearer_access_token() -> None:
    token = "test-relay-token"  # noqa: S105
    api_client = TestClient(
        create_app(settings=NodeSettings(access_token=token))
    )
    client = GhostNodeClient(
        "http://ghostnode.test",
        access_token=token,
        requester=create_test_requester(api_client),
    )

    assert client.receive(BOB_DEVICE_ID) == []


def test_node_client_without_required_token_is_rejected() -> None:
    token = "test-relay-token"  # noqa: S105
    api_client = TestClient(
        create_app(settings=NodeSettings(access_token=token))
    )
    client = GhostNodeClient(
        "http://ghostnode.test",
        requester=create_test_requester(api_client),
    )

    with pytest.raises(GhostNodeRequestError) as error:
        client.receive(BOB_DEVICE_ID)

    assert error.value.status_code == 401


def test_node_client_rejects_unexpected_message_fields() -> None:
    def requester(
        method: str,
        url: str,
        payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        return 200, [
            {
                "version": 2,
                "message_id": "a" * 32,
                "sender_device_id": ALICE_DEVICE_ID,
                "recipient_device_id": BOB_DEVICE_ID,
                "created_at": 1,
                "expires_at": 2,
                "ciphertext": base64.b64encode(b"ciphertext").decode("ascii"),
                "unexpected": "field",
            }
        ]

    client = GhostNodeClient(
        "http://ghostnode.test",
        requester=requester,
    )

    with pytest.raises(
        GhostNodeProtocolError,
        match="fields do not match",
    ):
        client.receive(BOB_DEVICE_ID)


def test_node_client_rejects_unsupported_message_version() -> None:
    def requester(
        method: str,
        url: str,
        payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        return 200, [
            {
                "version": 99,
                "message_id": "a" * 32,
                "sender_device_id": ALICE_DEVICE_ID,
                "recipient_device_id": BOB_DEVICE_ID,
                "created_at": 1,
                "expires_at": 2,
                "ciphertext": base64.b64encode(b"ciphertext").decode("ascii"),
            }
        ]

    client = GhostNodeClient(
        "http://ghostnode.test",
        requester=requester,
    )

    with pytest.raises(
        GhostNodeProtocolError,
        match="unsupported message version",
    ):
        client.receive(BOB_DEVICE_ID)


def test_node_client_rejects_invalid_ciphertext() -> None:
    def requester(
        method: str,
        url: str,
        payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        return 200, [
            {
                "version": 2,
                "message_id": "a" * 32,
                "sender_device_id": ALICE_DEVICE_ID,
                "recipient_device_id": BOB_DEVICE_ID,
                "created_at": 1,
                "expires_at": 2,
                "ciphertext": "not-base64!",
            }
        ]

    client = GhostNodeClient(
        "http://ghostnode.test",
        requester=requester,
    )

    with pytest.raises(
        GhostNodeProtocolError,
        match="valid Base64",
    ):
        client.receive(BOB_DEVICE_ID)


def test_node_client_rejects_noncanonical_recipient_device_id() -> None:
    client = GhostNodeClient("http://ghostnode.test")

    with pytest.raises(ValueError, match="invalid length"):
        client.receive("device1:bob")


def test_node_client_rejects_invalid_message_id_before_delete() -> None:
    client = GhostNodeClient("http://ghostnode.test")

    with pytest.raises(ValueError, match="message_id"):
        client.delete(BOB_DEVICE_ID, "bad-id")