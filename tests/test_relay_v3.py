import base64
import time

from fastapi.testclient import TestClient
from ghostlink.node import create_app

ALICE_DEVICE_ID = "device1:" + ("a" * 52)
BOB_DEVICE_ID = "device1:" + ("b" * 52)


def envelope(
    *,
    message_id: str = "1" * 32,
    created_at: int | None = None,
) -> dict[str, object]:
    now = int(time.time()) if created_at is None else created_at
    return {
        "version": 3,
        "message_id": message_id,
        "sender_device_id": ALICE_DEVICE_ID,
        "recipient_device_id": BOB_DEVICE_ID,
        "created_at": now,
        "expires_at": now + 3_600,
        "ciphertext_type": 3,
        "ciphertext": base64.b64encode(b"libsignal-ciphertext").decode("ascii"),
    }


def test_v3_message_round_trip_is_isolated_from_static_v2() -> None:
    client = TestClient(create_app())
    payload = envelope()

    stored = client.post("/v3/messages", json=payload)
    assert stored.status_code == 201
    assert stored.json() == payload

    listed = client.get(f"/v3/messages/{BOB_DEVICE_ID}")
    assert listed.status_code == 200
    assert listed.json() == [payload]

    static = client.get(f"/v2/messages/{BOB_DEVICE_ID}")
    assert static.status_code == 200
    assert static.json() == []

    deleted = client.delete(
        f"/v3/messages/{BOB_DEVICE_ID}/{payload['message_id']}"
    )
    assert deleted.status_code == 204
    assert client.get(f"/v3/messages/{BOB_DEVICE_ID}").json() == []


def test_v3_exact_retry_is_idempotent_and_conflict_is_rejected() -> None:
    client = TestClient(create_app())
    payload = envelope()

    first = client.post("/v3/messages", json=payload)
    retry = client.post("/v3/messages", json=payload)

    conflicting = dict(payload)
    conflicting["ciphertext"] = base64.b64encode(b"different").decode("ascii")
    conflict = client.post("/v3/messages", json=conflicting)

    assert first.status_code == 201
    assert retry.status_code == 201
    assert retry.json() == first.json()
    assert conflict.status_code == 409


def test_v3_rejects_unknown_fields_and_wrong_version() -> None:
    client = TestClient(create_app())

    unknown = envelope()
    unknown["unexpected"] = True
    assert client.post("/v3/messages", json=unknown).status_code == 422

    wrong_version = envelope()
    wrong_version["version"] = 2
    assert client.post("/v3/messages", json=wrong_version).status_code == 422


def test_v3_rejects_noncanonical_base64_and_invalid_ciphertext_type() -> None:
    client = TestClient(create_app())

    noncanonical = envelope()
    noncanonical["ciphertext"] = "YQ==\n"
    assert client.post("/v3/messages", json=noncanonical).status_code == 422

    invalid_type = envelope(message_id="2" * 32)
    invalid_type["ciphertext_type"] = 256
    assert client.post("/v3/messages", json=invalid_type).status_code == 422


def test_v3_rejects_messages_outside_relay_time_window() -> None:
    client = TestClient(create_app())
    old = envelope(created_at=int(time.time()) - 10_000)
    old["expires_at"] = int(time.time()) - 1_000

    response = client.post("/v3/messages", json=old)

    assert response.status_code == 422
    assert response.json() == {
        "detail": "message lifecycle is outside relay acceptance window"
    }
