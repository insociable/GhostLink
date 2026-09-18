import base64
import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient
from ghostlink.config import NodeSettings
from ghostlink.node import create_app


def create_payload() -> dict[str, int | str]:
    return {
        "version": 1,
        "sender_device_id": "device1:alice",
        "recipient_device_id": "device1:bob",
        "ciphertext": base64.b64encode(b"encrypted-message").decode("ascii"),
    }


def test_sqlite_store_survives_app_restart(tmp_path: Path) -> None:
    database_path = tmp_path / "relay" / "messages.sqlite3"
    settings = NodeSettings(database_path=database_path)
    payload = create_payload()

    first_client = TestClient(create_app(settings=settings))
    create_response = first_client.post("/v1/messages", json=payload)

    assert create_response.status_code == 201
    stored_message = create_response.json()

    second_client = TestClient(create_app(settings=settings))
    receive_response = second_client.get("/v1/messages/device1:bob")

    assert receive_response.status_code == 200
    assert receive_response.json() == [stored_message]


def test_sqlite_store_persists_only_envelope_fields(tmp_path: Path) -> None:
    database_path = tmp_path / "messages.sqlite3"
    settings = NodeSettings(database_path=database_path)
    payload = create_payload()
    client = TestClient(create_app(settings=settings))

    response = client.post("/v1/messages", json=payload)

    assert response.status_code == 201

    with sqlite3.connect(database_path) as connection:
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(messages)").fetchall()
        }
        row = connection.execute(
            """
            SELECT
                sender_device_id,
                recipient_device_id,
                ciphertext
            FROM messages
            """
        ).fetchone()

    assert columns == {
        "message_id",
        "version",
        "sender_device_id",
        "recipient_device_id",
        "ciphertext",
    }
    assert row == (
        payload["sender_device_id"],
        payload["recipient_device_id"],
        payload["ciphertext"],
    )


def test_sqlite_message_is_deleted_persistently(tmp_path: Path) -> None:
    database_path = tmp_path / "messages.sqlite3"
    settings = NodeSettings(database_path=database_path)
    first_client = TestClient(create_app(settings=settings))

    create_response = first_client.post("/v1/messages", json=create_payload())
    message_id = create_response.json()["message_id"]

    delete_response = first_client.delete(f"/v1/messages/{message_id}")

    assert delete_response.status_code == 204

    second_client = TestClient(create_app(settings=settings))
    receive_response = second_client.get("/v1/messages/device1:bob")

    assert receive_response.json() == []
