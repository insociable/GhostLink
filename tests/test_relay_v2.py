import base64
import time
from pathlib import Path

from fastapi.testclient import TestClient
from ghostlink.config import NodeSettings
from ghostlink.message import MESSAGE_CLOCK_SKEW_SECONDS
from ghostlink.node import create_app

ALICE_DEVICE_ID = "device1:" + ("a" * 52)
BOB_DEVICE_ID = "device1:" + ("b" * 52)


def create_v2_payload(*, message_id: str = "a" * 32) -> dict[str, int | str]:
    now = int(time.time())
    return {
        "version": 2,
        "message_id": message_id,
        "sender_device_id": ALICE_DEVICE_ID,
        "recipient_device_id": BOB_DEVICE_ID,
        "created_at": now,
        "expires_at": now + 3600,
        "ciphertext": base64.b64encode(b"encrypted-v2-message").decode("ascii"),
    }


def test_v2_envelope_can_be_stored_retrieved_and_deleted() -> None:
    client = TestClient(create_app())
    payload = create_v2_payload()

    created = client.post("/v2/messages", json=payload)

    assert created.status_code == 201
    assert created.json() == payload

    inbox = client.get(f"/v2/messages/{BOB_DEVICE_ID}")

    assert inbox.status_code == 200
    assert inbox.json() == [payload]

    deleted = client.delete(
        f"/v2/messages/{BOB_DEVICE_ID}/{payload['message_id']}"
    )

    assert deleted.status_code == 204
    assert client.get(f"/v2/messages/{BOB_DEVICE_ID}").json() == []


def test_v2_exact_retry_is_idempotent() -> None:
    client = TestClient(create_app())
    payload = create_v2_payload()

    first = client.post("/v2/messages", json=payload)
    second = client.post("/v2/messages", json=payload)

    assert first.status_code == 201
    assert second.status_code == 201
    assert second.json() == first.json()
    assert len(client.get(f"/v2/messages/{BOB_DEVICE_ID}").json()) == 1


def test_v2_conflicting_message_id_is_rejected() -> None:
    client = TestClient(create_app())
    payload = create_v2_payload()

    assert client.post("/v2/messages", json=payload).status_code == 201

    conflict = dict(payload)
    conflict["ciphertext"] = base64.b64encode(b"different").decode("ascii")

    response = client.post("/v2/messages", json=conflict)

    assert response.status_code == 409
    assert response.json() == {
        "detail": "message_id already exists for recipient"
    }


def test_v2_expired_message_is_rejected_by_relay() -> None:
    client = TestClient(create_app())
    payload = create_v2_payload()
    now = int(time.time())
    payload["created_at"] = now - 1000
    payload["expires_at"] = now - 301

    response = client.post("/v2/messages", json=payload)

    assert response.status_code == 422


def test_v2_far_future_message_is_rejected_by_relay() -> None:
    client = TestClient(create_app())
    payload = create_v2_payload()
    now = int(time.time())
    payload["created_at"] = now + MESSAGE_CLOCK_SKEW_SECONDS + 60
    payload["expires_at"] = payload["created_at"] + 3600

    response = client.post("/v2/messages", json=payload)

    assert response.status_code == 422


def test_v2_sqlite_store_survives_app_recreation(tmp_path: Path) -> None:
    database_path = tmp_path / "messages.sqlite3"
    settings = NodeSettings(database_path=database_path)
    payload = create_v2_payload()

    first_client = TestClient(create_app(settings=settings))
    assert first_client.post("/v2/messages", json=payload).status_code == 201

    second_client = TestClient(create_app(settings=settings))
    inbox = second_client.get(f"/v2/messages/{BOB_DEVICE_ID}")

    assert inbox.status_code == 200
    assert inbox.json() == [payload]


def test_v2_relay_authentication_uses_shared_bearer_policy() -> None:
    token = "relay-v2-secret"  # noqa: S105
    client = TestClient(
        create_app(settings=NodeSettings(access_token=token))
    )
    payload = create_v2_payload()

    missing = client.post("/v2/messages", json=payload)
    accepted = client.post(
        "/v2/messages",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert missing.status_code == 401
    assert accepted.status_code == 201


def test_v2_unknown_fields_are_rejected() -> None:
    client = TestClient(create_app())
    payload = create_v2_payload()
    payload["unexpected"] = "value"

    response = client.post("/v2/messages", json=payload)

    assert response.status_code == 422


def test_v2_invalid_message_id_is_rejected() -> None:
    client = TestClient(create_app())
    payload = create_v2_payload(message_id="NOT-HEX")

    response = client.post("/v2/messages", json=payload)

    assert response.status_code == 422