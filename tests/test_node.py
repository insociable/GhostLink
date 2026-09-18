import base64
from pathlib import Path

from fastapi.testclient import TestClient
from ghostlink.config import NodeSettings
from ghostlink.node import InMemoryMessageStore, SQLiteMessageStore, create_app

ALICE_DEVICE_ID = "device1:" + ("a" * 52)
BOB_DEVICE_ID = "device1:" + ("b" * 52)
MALLORY_DEVICE_ID = "device1:" + ("c" * 52)


def create_message_payload() -> dict[str, int | str]:
    ciphertext = base64.b64encode(b"encrypted-message").decode("ascii")

    return {
        "version": 1,
        "sender_device_id": ALICE_DEVICE_ID,
        "recipient_device_id": BOB_DEVICE_ID,
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

    receive_response = client.get(f"/v1/messages/{BOB_DEVICE_ID}")

    assert receive_response.status_code == 200
    assert receive_response.json() == [stored_message]


def test_messages_are_filtered_by_recipient() -> None:
    client = TestClient(create_app())
    payload = create_message_payload()

    client.post("/v1/messages", json=payload)

    response = client.get(f"/v1/messages/{MALLORY_DEVICE_ID}")

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

    receive_response = client.get(f"/v1/messages/{BOB_DEVICE_ID}")

    assert receive_response.json() == []


def test_unknown_message_cannot_be_deleted() -> None:
    client = TestClient(create_app())

    response = client.delete("/v1/messages/unknown")

    assert response.status_code == 404
    assert response.json() == {"detail": "message not found"}


def test_sqlite_store_survives_app_recreation(tmp_path: Path) -> None:
    database_path = tmp_path / "data" / "messages.sqlite3"
    settings = NodeSettings(database_path=database_path)
    payload = create_message_payload()

    first_client = TestClient(create_app(settings=settings))
    create_response = first_client.post("/v1/messages", json=payload)

    assert create_response.status_code == 201
    stored_message = create_response.json()
    assert database_path.exists()

    second_client = TestClient(create_app(settings=settings))
    receive_response = second_client.get(f"/v1/messages/{BOB_DEVICE_ID}")

    assert receive_response.status_code == 200
    assert receive_response.json() == [stored_message]


def test_sqlite_store_delete_is_persistent(tmp_path: Path) -> None:
    database_path = tmp_path / "messages.sqlite3"
    store = SQLiteMessageStore(database_path)
    client = TestClient(create_app(store=store))
    payload = create_message_payload()

    create_response = client.post("/v1/messages", json=payload)
    message_id = create_response.json()["message_id"]

    assert client.delete(f"/v1/messages/{message_id}").status_code == 204

    reloaded_client = TestClient(
        create_app(store=SQLiteMessageStore(database_path))
    )
    assert reloaded_client.get(f"/v1/messages/{BOB_DEVICE_ID}").json() == []


def test_database_path_cannot_be_a_directory(tmp_path: Path) -> None:
    directory = tmp_path / "database"
    directory.mkdir()

    try:
        SQLiteMessageStore(directory)
    except ValueError as exc:
        assert "must point to a file" in str(exc)
    else:
        raise AssertionError("directory database path should be rejected")


def test_relay_operations_require_configured_access_token() -> None:
    settings = NodeSettings(access_token="relay-secret")  # noqa: S106
    client = TestClient(create_app(settings=settings))
    payload = create_message_payload()

    missing = client.post("/v1/messages", json=payload)
    wrong = client.post(
        "/v1/messages",
        json=payload,
        headers={"Authorization": "Bearer wrong-secret"},
    )
    accepted = client.post(
        "/v1/messages",
        json=payload,
        headers={"Authorization": "Bearer relay-secret"},
    )

    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"
    assert wrong.status_code == 401
    assert accepted.status_code == 201

    message_id = accepted.json()["message_id"]

    inbox = client.get(
        f"/v1/messages/{BOB_DEVICE_ID}",
        headers={"Authorization": "Bearer relay-secret"},
    )
    deleted = client.delete(
        f"/v1/messages/{message_id}",
        headers={"Authorization": "Bearer relay-secret"},
    )

    assert inbox.status_code == 200
    assert len(inbox.json()) == 1
    assert deleted.status_code == 204


def test_health_remains_public_when_relay_authentication_is_enabled() -> None:
    settings = NodeSettings(access_token="relay-secret")  # noqa: S106
    client = TestClient(create_app(settings=settings))

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


class UnhealthyMessageStore(InMemoryMessageStore):
    def is_healthy(self) -> bool:
        return False


def test_health_returns_service_unavailable_when_store_is_unhealthy() -> None:
    client = TestClient(create_app(store=UnhealthyMessageStore()))

    response = client.get("/health")

    assert response.status_code == 503
    assert response.json() == {"detail": "storage unavailable"}


def test_sqlite_store_reports_healthy_when_database_is_available(tmp_path: Path) -> None:
    store = SQLiteMessageStore(tmp_path / "messages.sqlite3")

    assert store.is_healthy()


def test_unsupported_message_version_is_rejected_by_relay() -> None:
    client = TestClient(create_app())
    payload = create_message_payload()
    payload["version"] = 2

    response = client.post("/v1/messages", json=payload)

    assert response.status_code == 422


def test_noncanonical_device_id_is_rejected_by_relay() -> None:
    client = TestClient(create_app())
    payload = create_message_payload()
    payload["sender_device_id"] = "device1:alice"

    response = client.post("/v1/messages", json=payload)

    assert response.status_code == 422


def test_unknown_envelope_fields_are_rejected() -> None:
    client = TestClient(create_app())
    payload = create_message_payload()
    payload["unexpected"] = "value"

    response = client.post("/v1/messages", json=payload)

    assert response.status_code == 422


def test_oversized_ciphertext_is_rejected() -> None:
    client = TestClient(create_app())
    payload = create_message_payload()
    payload["ciphertext"] = base64.b64encode(
        b"x" * (1_048_576 + 1)
    ).decode("ascii")

    response = client.post("/v1/messages", json=payload)

    assert response.status_code == 422
