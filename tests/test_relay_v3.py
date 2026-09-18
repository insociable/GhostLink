import base64
import time
import urllib.parse
from collections.abc import Callable
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from ghostlink.client import GhostNodeClient, GhostNodeRequestError
from ghostlink.config import NodeSettings
from ghostlink.device import EnrolledGhostDevice
from ghostlink.entity import GhostEntity
from ghostlink.node import create_app
from ghostlink.ratchet_message import RatchetMessage
from ghostlink.relay_request_auth import create_relay_request_headers


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
        parsed = urllib.parse.urlparse(url)
        response = client.request(
            method,
            parsed.path,
            json=payload,
            headers=headers,
        )
        return (
            response.status_code,
            response.json() if response.content else None,
        )

    return request


def _node(
    client: TestClient,
    *,
    access_token: str | None = None,
) -> GhostNodeClient:
    return GhostNodeClient(
        "http://ghostnode.test",
        access_token=access_token,
        requester=_requester(client),
    )


def _message(
    sender: EnrolledGhostDevice,
    recipient: EnrolledGhostDevice,
    *,
    message_id: str = "1" * 32,
    created_at: int | None = None,
    ciphertext: bytes = b"libsignal-ciphertext",
) -> RatchetMessage:
    now = int(time.time()) if created_at is None else created_at
    return RatchetMessage(
        version=3,
        message_id=message_id,
        sender_device_id=sender.device_id,
        recipient_device_id=recipient.device_id,
        created_at=now,
        expires_at=now + 3_600,
        ciphertext_type=3,
        ciphertext=ciphertext,
    )


def _payload(message: RatchetMessage) -> dict[str, object]:
    return {
        "version": message.version,
        "message_id": message.message_id,
        "sender_device_id": message.sender_device_id,
        "recipient_device_id": message.recipient_device_id,
        "created_at": message.created_at,
        "expires_at": message.expires_at,
        "ciphertext_type": message.ciphertext_type,
        "ciphertext": base64.b64encode(message.ciphertext).decode("ascii"),
    }


def test_v3_message_round_trip_is_device_authenticated_and_static_v2_absent() -> None:
    alice = GhostEntity.generate().enroll_device()
    bob = GhostEntity.generate().enroll_device()
    api_client = TestClient(create_app())
    node = _node(api_client)
    message = _message(alice, bob)

    assert node.send_ratchet(alice, message) == message.message_id
    assert node.receive_ratchet(bob) == [message]

    static = api_client.get(f"/v2/messages/{bob.device_id}")
    assert static.status_code == 404

    node.delete_ratchet(bob, message.message_id)
    assert node.receive_ratchet(bob) == []


def test_v3_exact_retry_is_idempotent_and_conflict_is_rejected() -> None:
    alice = GhostEntity.generate().enroll_device()
    bob = GhostEntity.generate().enroll_device()
    api_client = TestClient(create_app())
    node = _node(api_client)
    now = int(time.time())
    message = _message(alice, bob, created_at=now)

    assert node.send_ratchet(
        alice,
        message,
        issued_at=now,
        request_id="1" * 32,
    ) == message.message_id
    assert node.send_ratchet(
        alice,
        message,
        issued_at=now,
        request_id="2" * 32,
    ) == message.message_id

    conflicting = _message(
        alice,
        bob,
        message_id=message.message_id,
        created_at=now,
        ciphertext=b"different",
    )
    with pytest.raises(GhostNodeRequestError) as exc_info:
        node.send_ratchet(
            alice,
            conflicting,
            issued_at=now,
            request_id="3" * 32,
        )
    assert exc_info.value.status_code == 409


def test_v3_sender_and_recipient_ownership_mismatch_is_unauthorized() -> None:
    alice = GhostEntity.generate().enroll_device()
    bob = GhostEntity.generate().enroll_device()
    api_client = TestClient(create_app())
    now = int(time.time())
    message = _message(alice, bob, created_at=now)
    payload = _payload(message)

    wrong_sender_headers = create_relay_request_headers(
        bob,
        method="POST",
        path="/v3/messages",
        payload=payload,
        issued_at=now,
        request_id="4" * 32,
    )
    posted = api_client.post(
        "/v3/messages",
        json=payload,
        headers=wrong_sender_headers,
    )
    assert posted.status_code == 401
    assert posted.json() == {"detail": "unauthorized"}

    mailbox_path = f"/v3/messages/{bob.device_id}"
    wrong_recipient_headers = create_relay_request_headers(
        alice,
        method="GET",
        path=mailbox_path,
        payload=None,
        issued_at=now,
        request_id="5" * 32,
    )
    listed = api_client.get(mailbox_path, headers=wrong_recipient_headers)
    assert listed.status_code == 401
    assert listed.json() == {"detail": "unauthorized"}

    delete_path = f"{mailbox_path}/{'9' * 32}"
    wrong_delete_headers = create_relay_request_headers(
        alice,
        method="DELETE",
        path=delete_path,
        payload=None,
        issued_at=now,
        request_id="6" * 32,
    )
    deleted = api_client.delete(delete_path, headers=wrong_delete_headers)
    assert deleted.status_code == 401
    assert deleted.json() == {"detail": "unauthorized"}


def test_v3_missing_device_proof_is_unauthorized() -> None:
    alice = GhostEntity.generate().enroll_device()
    bob = GhostEntity.generate().enroll_device()
    client = TestClient(create_app())

    response = client.post("/v3/messages", json=_payload(_message(alice, bob)))

    assert response.status_code == 401
    assert response.json() == {"detail": "unauthorized"}


def test_v3_device_auth_composes_with_shared_bearer() -> None:
    alice = GhostEntity.generate().enroll_device()
    bob = GhostEntity.generate().enroll_device()
    settings = NodeSettings(access_token="relay-secret")  # noqa: S106
    api_client = TestClient(create_app(settings=settings))
    message = _message(alice, bob)

    without_bearer = _node(api_client)
    with pytest.raises(GhostNodeRequestError) as exc_info:
        without_bearer.send_ratchet(alice, message)
    assert exc_info.value.status_code == 401

    with_bearer = _node(api_client, access_token="relay-secret")  # noqa: S106
    assert with_bearer.send_ratchet(alice, message) == message.message_id
    assert with_bearer.receive_ratchet(bob) == [message]


def test_v3_rejects_unknown_fields_and_wrong_version() -> None:
    alice = GhostEntity.generate().enroll_device()
    bob = GhostEntity.generate().enroll_device()
    client = TestClient(create_app())

    unknown = _payload(_message(alice, bob))
    unknown["unexpected"] = True
    assert client.post("/v3/messages", json=unknown).status_code == 422

    wrong_version = _payload(_message(alice, bob))
    wrong_version["version"] = 2
    assert client.post("/v3/messages", json=wrong_version).status_code == 422


def test_v3_rejects_noncanonical_base64_and_invalid_ciphertext_type() -> None:
    alice = GhostEntity.generate().enroll_device()
    bob = GhostEntity.generate().enroll_device()
    client = TestClient(create_app())

    noncanonical = _payload(_message(alice, bob))
    noncanonical["ciphertext"] = "YQ==\n"
    assert client.post("/v3/messages", json=noncanonical).status_code == 422

    invalid_type = _payload(_message(alice, bob, message_id="2" * 32))
    invalid_type["ciphertext_type"] = 256
    assert client.post("/v3/messages", json=invalid_type).status_code == 422


def test_v3_rejects_messages_outside_relay_time_window_after_auth() -> None:
    alice = GhostEntity.generate().enroll_device()
    bob = GhostEntity.generate().enroll_device()
    api_client = TestClient(create_app())
    node = _node(api_client)
    current = int(time.time())
    old = _message(alice, bob, created_at=current - 10_000)

    with pytest.raises(GhostNodeRequestError) as exc_info:
        node.send_ratchet(
            alice,
            old,
            issued_at=current,
            request_id="7" * 32,
        )

    assert exc_info.value.status_code == 422
    assert exc_info.value.detail == "message lifecycle is outside relay acceptance window"


def test_v3_request_replay_is_rejected_after_sqlite_app_restart(
    tmp_path: Path,
) -> None:
    bob = GhostEntity.generate().enroll_device()
    settings = NodeSettings(database_path=tmp_path / "ghostnode.sqlite3")
    now = int(time.time())
    path = f"/v3/messages/{bob.device_id}"
    headers = create_relay_request_headers(
        bob,
        method="GET",
        path=path,
        payload=None,
        issued_at=now,
        request_id="8" * 32,
    )

    first_client = TestClient(create_app(settings=settings))
    first = first_client.get(path, headers=headers)
    assert first.status_code == 200
    assert first.json() == []

    restarted_client = TestClient(create_app(settings=settings))
    replay = restarted_client.get(path, headers=headers)
    assert replay.status_code == 401
    assert replay.json() == {"detail": "unauthorized"}
