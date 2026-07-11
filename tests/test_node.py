import base64

from fastapi.testclient import TestClient
from ghostlink.node import create_app


def create_message_payload() -> dict[str, int | str]:
    ciphertext = base64.b64encode(b"encrypted-message").decode("ascii")

    return {
        "version": 1,
        "sender_device_id": "device1:alice",
        "recipient_device_id": "device1:bob",
        "ciphertext": ciphertext,
    }


def test_health_endpoint() -> None:
    client = TestClient(create_app())

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_encrypted_message_can_be_stored_and_retrieved() -> None:
    client = TestClient(create_app())
    payload = create_message_payload()

    create_response = client.post("/v1/messages", json=payload)

    assert create_response.status_code == 201

    stored_message = create_response.json()

    assert stored_message["message_id"]
    assert stored_message["ciphertext"] == payload["ciphertext"]

    receive_response = client.get("/v1/messages/device1:bob")

    assert receive_response.status_code == 200
    assert receive_response.json() == [stored_message]


def test_messages_are_filtered_by_recipient() -> None:
    client = TestClient(create_app())
    payload = create_message_payload()

    client.post("/v1/messages", json=payload)

    response = client.get("/v1/messages/device1:mallory")

    assert response.status_code == 200
    assert response.json() == []


def test_invalid_base64_ciphertext_is_rejected() -> None:
    client = TestClient(create_app())
    payload = create_message_payload()
    payload["ciphertext"] = "not-valid-base64!"

    response = client.post("/v1/messages", json=payload)

    assert response.status_code == 422


def test_message_can_be_deleted_after_delivery() -> None:
    client = TestClient(create_app())
    payload = create_message_payload()

    create_response = client.post("/v1/messages", json=payload)
    message_id = create_response.json()["message_id"]

    delete_response = client.delete(f"/v1/messages/{message_id}")

    assert delete_response.status_code == 204

    receive_response = client.get("/v1/messages/device1:bob")

    assert receive_response.json() == []


def test_unknown_message_cannot_be_deleted() -> None:
    client = TestClient(create_app())

    response = client.delete("/v1/messages/unknown")

    assert response.status_code == 404
    assert response.json() == {"detail": "message not found"}