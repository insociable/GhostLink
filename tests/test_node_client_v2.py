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
from ghostlink.message_v2 import decrypt_message_v2, encrypt_message_v2
from ghostlink.node import create_app


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


def test_v2_encrypted_message_round_trip_through_node_client() -> None:
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

    message = encrypt_message_v2(
        alice_device,
        bob_device.public_device(),
        b"Bonjour Bob depuis V2",
        created_at=now,
    )

    message_id = client.send_v2(message)
    received = client.receive_v2(bob_device.device_id)

    assert message_id == message.message_id
    assert received == [message]

    plaintext = decrypt_message_v2(
        bob_device,
        alice_device.public_device(),
        received[0],
        now=now,
    )
    assert plaintext == b"Bonjour Bob depuis V2"

    client.delete_v2(bob_device.device_id, message.message_id)
    assert client.receive_v2(bob_device.device_id) == []


def test_v2_client_uses_bearer_token() -> None:
    token = "v2-test-token"  # noqa: S105
    api_client = TestClient(
        create_app(settings=NodeSettings(access_token=token))
    )

    unauthenticated = GhostNodeClient(
        "http://ghostnode.test",
        requester=create_test_requester(api_client),
    )

    alice = GhostEntity.generate()
    bob = GhostEntity.generate()
    message = encrypt_message_v2(
        alice.enroll_device(),
        bob.enroll_device().public_device(),
        b"auth",
    )

    with pytest.raises(GhostNodeRequestError) as error:
        unauthenticated.send_v2(message)

    assert error.value.status_code == 401

    authenticated = GhostNodeClient(
        "http://ghostnode.test",
        access_token=token,
        requester=create_test_requester(api_client),
    )

    assert authenticated.send_v2(message) == message.message_id


def test_v2_client_rejects_unexpected_response_fields() -> None:
    device_id = "device1:" + ("a" * 52)

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
                "sender_device_id": device_id,
                "recipient_device_id": device_id,
                "created_at": 1,
                "expires_at": 2,
                "ciphertext": "YQ==",
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
        client.receive_v2(device_id)


def test_v2_client_rejects_invalid_message_id_before_delete() -> None:
    device_id = "device1:" + ("a" * 52)
    client = GhostNodeClient("http://ghostnode.test")

    with pytest.raises(ValueError, match="message_id"):
        client.delete_v2(device_id, "bad-id")