import base64
import time
from pathlib import Path

import pytest

from ghostlink.entity import GhostEntity
from ghostlink.relay_request_auth import (
    AUTH_CLOCK_SKEW_SECONDS,
    AUTH_DEVICE_ID_HEADER,
    AUTH_ISSUED_AT_HEADER,
    AUTH_REQUEST_ID_HEADER,
    AUTH_SIGNATURE_HEADER,
    AUTH_SIGNING_KEY_HEADER,
    InMemoryRelayRequestReplayStore,
    RelayRequestProofError,
    SQLiteRelayRequestReplayStore,
    authenticate_relay_request,
    create_relay_request_headers,
)


def _authenticate(
    headers: dict[str, str],
    *,
    expected_device_id: str,
    method: str,
    path: str,
    payload: dict[str, object] | None,
    now: int,
    replay_store,
) -> None:
    authenticate_relay_request(
        expected_device_id=expected_device_id,
        method=method,
        path=path,
        payload=payload,
        device_id=headers.get(AUTH_DEVICE_ID_HEADER),
        signing_public_key=headers.get(AUTH_SIGNING_KEY_HEADER),
        request_id=headers.get(AUTH_REQUEST_ID_HEADER),
        issued_at=headers.get(AUTH_ISSUED_AT_HEADER),
        signature=headers.get(AUTH_SIGNATURE_HEADER),
        now=now,
        replay_store=replay_store,
    )


def test_request_proof_accepts_valid_device_and_rejects_replay() -> None:
    device = GhostEntity.generate().enroll_device()
    now = int(time.time())
    payload = {"message": "ciphertext-only"}
    headers = create_relay_request_headers(
        device,
        method="POST",
        path="/v3/messages",
        payload=payload,
        issued_at=now,
        request_id="1" * 32,
    )
    replay_store = InMemoryRelayRequestReplayStore()

    _authenticate(
        headers,
        expected_device_id=device.device_id,
        method="POST",
        path="/v3/messages",
        payload=payload,
        now=now,
        replay_store=replay_store,
    )

    with pytest.raises(RelayRequestProofError):
        _authenticate(
            headers,
            expected_device_id=device.device_id,
            method="POST",
            path="/v3/messages",
            payload=payload,
            now=now,
            replay_store=replay_store,
        )


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [
        ("GET", "/v3/messages", {"message": "ciphertext-only"}),
        ("POST", "/v3/messages/other", {"message": "ciphertext-only"}),
        ("POST", "/v3/messages", {"message": "tampered"}),
    ],
)
def test_request_proof_binds_method_path_and_body(
    method: str,
    path: str,
    payload: dict[str, object],
) -> None:
    device = GhostEntity.generate().enroll_device()
    now = int(time.time())
    headers = create_relay_request_headers(
        device,
        method="POST",
        path="/v3/messages",
        payload={"message": "ciphertext-only"},
        issued_at=now,
        request_id="2" * 32,
    )

    with pytest.raises(RelayRequestProofError):
        _authenticate(
            headers,
            expected_device_id=device.device_id,
            method=method,
            path=path,
            payload=payload,
            now=now,
            replay_store=InMemoryRelayRequestReplayStore(),
        )


def test_request_proof_rejects_signature_and_device_substitution() -> None:
    alice = GhostEntity.generate().enroll_device()
    bob = GhostEntity.generate().enroll_device()
    now = int(time.time())
    headers = create_relay_request_headers(
        alice,
        method="GET",
        path=f"/v3/messages/{alice.device_id}",
        payload=None,
        issued_at=now,
        request_id="3" * 32,
    )

    signature = base64.b64decode(headers[AUTH_SIGNATURE_HEADER], validate=True)
    tampered = bytearray(signature)
    tampered[0] ^= 1
    bad_signature_headers = dict(headers)
    bad_signature_headers[AUTH_SIGNATURE_HEADER] = base64.b64encode(
        bytes(tampered)
    ).decode("ascii")

    with pytest.raises(RelayRequestProofError):
        _authenticate(
            bad_signature_headers,
            expected_device_id=alice.device_id,
            method="GET",
            path=f"/v3/messages/{alice.device_id}",
            payload=None,
            now=now,
            replay_store=InMemoryRelayRequestReplayStore(),
        )

    with pytest.raises(RelayRequestProofError):
        _authenticate(
            headers,
            expected_device_id=bob.device_id,
            method="GET",
            path=f"/v3/messages/{alice.device_id}",
            payload=None,
            now=now,
            replay_store=InMemoryRelayRequestReplayStore(),
        )


@pytest.mark.parametrize(
    "issued_at_delta",
    [
        -(AUTH_CLOCK_SKEW_SECONDS + 1),
        AUTH_CLOCK_SKEW_SECONDS + 1,
    ],
)
def test_request_proof_rejects_stale_and_future_timestamp(
    issued_at_delta: int,
) -> None:
    device = GhostEntity.generate().enroll_device()
    now = int(time.time())
    issued_at = now + issued_at_delta
    headers = create_relay_request_headers(
        device,
        method="GET",
        path=f"/v3/messages/{device.device_id}",
        payload=None,
        issued_at=issued_at,
        request_id="4" * 32,
    )

    with pytest.raises(RelayRequestProofError):
        _authenticate(
            headers,
            expected_device_id=device.device_id,
            method="GET",
            path=f"/v3/messages/{device.device_id}",
            payload=None,
            now=now,
            replay_store=InMemoryRelayRequestReplayStore(),
        )


def test_sqlite_replay_state_survives_store_restart(tmp_path: Path) -> None:
    device = GhostEntity.generate().enroll_device()
    now = int(time.time())
    path = f"/v3/messages/{device.device_id}"
    headers = create_relay_request_headers(
        device,
        method="GET",
        path=path,
        payload=None,
        issued_at=now,
        request_id="5" * 32,
    )
    database = tmp_path / "relay.sqlite3"

    first_store = SQLiteRelayRequestReplayStore(database)
    _authenticate(
        headers,
        expected_device_id=device.device_id,
        method="GET",
        path=path,
        payload=None,
        now=now,
        replay_store=first_store,
    )

    reopened_store = SQLiteRelayRequestReplayStore(database)
    with pytest.raises(RelayRequestProofError):
        _authenticate(
            headers,
            expected_device_id=device.device_id,
            method="GET",
            path=path,
            payload=None,
            now=now,
            replay_store=reopened_store,
        )


def test_expired_replay_entry_can_be_collected() -> None:
    device = GhostEntity.generate().enroll_device()
    store = InMemoryRelayRequestReplayStore()

    assert store.accept(
        device.device_id,
        "6" * 32,
        expires_at=100,
        now=50,
    )
    assert store.accept(
        device.device_id,
        "6" * 32,
        expires_at=300,
        now=101,
    )
