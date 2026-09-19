import time
import urllib.parse
from collections.abc import Callable
from typing import cast

import pytest
from fastapi.testclient import TestClient
from ghostlink.client.node_client import (
    GhostNodeClient,
    GhostNodeConnectionError,
    GhostNodeProtocolError,
    GhostNodeRequestError,
)
from ghostlink.device import EnrolledGhostDevice
from ghostlink.entity import GhostEntity
from ghostlink.node import create_app
from ghostlink.ratchet_binding import RatchetPreKeyMaterial
from ghostlink.ratchet_engine import RatchetEngineClient
from ghostlink.ratchet_publication import (
    create_ratchet_prekey_publication,
    export_ratchet_prekey_publication,
)
from ghostlink.ratchet_publish import publish_prekey_generation


def _material(
    *,
    pre_key_id: int | None,
    pre_key_byte: int,
    kyber_pre_key_id: int,
    kyber_byte: int,
) -> RatchetPreKeyMaterial:
    return RatchetPreKeyMaterial(
        registration_id=4_200,
        identity_key=bytes([1]) * 33,
        pre_key_id=pre_key_id,
        pre_key=None if pre_key_id is None else bytes([pre_key_byte]) * 33,
        signed_pre_key_id=2_001,
        signed_pre_key=bytes([3]) * 33,
        signed_pre_key_signature=bytes([4]) * 64,
        kyber_pre_key_id=kyber_pre_key_id,
        kyber_pre_key=bytes([kyber_byte]) * 1_184,
        kyber_pre_key_signature=bytes([6]) * 64,
    )


def _publication(
    device: EnrolledGhostDevice,
    *,
    sequence: int = 1,
    issued_at: int = 1_000,
    expires_at: int = 4_600,
) -> str:
    publication = create_ratchet_prekey_publication(
        device,
        publication_sequence=sequence,
        issued_at=issued_at,
        expires_at=expires_at,
        one_time_material=(
            _material(
                pre_key_id=1_001,
                pre_key_byte=2,
                kyber_pre_key_id=3_001,
                kyber_byte=5,
            ),
            _material(
                pre_key_id=1_002,
                pre_key_byte=7,
                kyber_pre_key_id=3_002,
                kyber_byte=8,
            ),
        ),
        fallback_material=_material(
            pre_key_id=None,
            pre_key_byte=9,
            kyber_pre_key_id=3_999,
            kyber_byte=10,
        ),
    )
    return export_ratchet_prekey_publication(publication)


class FakeEngine:
    def __init__(self, payload: str) -> None:
        self.payload = payload
        self.commits: list[tuple[int, int | None]] = []

    def prepare_prekey_publication(
        self,
        *,
        one_time_count: int = 100,
        issued_at: int | None = None,
        lifetime_seconds: int = 7 * 24 * 60 * 60,
    ) -> str:
        del one_time_count, issued_at, lifetime_seconds
        return self.payload

    def commit_prekey_publication(
        self,
        publication_sequence: int,
        *,
        published_at: int | None = None,
    ) -> None:
        self.commits.append((publication_sequence, published_at))


def _requester(
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
        return (
            response.status_code,
            response.json() if response.content else None,
        )

    return requester


def test_publication_orchestration_commits_only_after_valid_relay_receipt() -> None:
    entity = GhostEntity.generate()
    device = entity.enroll_device()
    now = int(time.time())
    payload = _publication(
        device,
        issued_at=now,
        expires_at=now + 3_600,
    )
    fake_engine = FakeEngine(payload)
    node = GhostNodeClient(
        "https://ghostnode.test",
        requester=_requester(TestClient(create_app())),
    )

    receipt = publish_prekey_generation(
        cast(RatchetEngineClient, fake_engine),
        node,
        device,
        acknowledged_at=now + 1,
    )

    assert receipt.device_id == device.device_id
    assert receipt.publication_sequence == 1
    assert receipt.expires_at == now + 3_600
    assert receipt.one_time_count == 2
    assert fake_engine.commits == [(1, now + 1)]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        (
            "device_id",
            "device1:" + ("a" * 52),
            "DeviceID does not match",
        ),
        ("publication_sequence", 2, "sequence does not match"),
        ("expires_at", 4_601, "expiration does not match"),
        ("one_time_count", 1, "count does not match"),
    ],
)
def test_publication_orchestration_rejects_mismatched_receipt_without_commit(
    field: str,
    value: object,
    message: str,
) -> None:
    entity = GhostEntity.generate()
    device = entity.enroll_device()
    payload = _publication(device)
    fake_engine = FakeEngine(payload)

    base_receipt: dict[str, object] = {
        "version": 1,
        "device_id": device.device_id,
        "publication_sequence": 1,
        "expires_at": 4_600,
        "one_time_count": 2,
    }
    base_receipt[field] = value

    def requester(
        method: str,
        url: str,
        request_payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        del method, url, request_payload, timeout, headers
        return 200, base_receipt

    node = GhostNodeClient("https://ghostnode.test", requester=requester)

    with pytest.raises(GhostNodeProtocolError, match=message):
        publish_prekey_generation(
            cast(RatchetEngineClient, fake_engine),
            node,
            device,
            acknowledged_at=1_100,
        )

    assert fake_engine.commits == []


def test_publication_orchestration_keeps_pending_after_lost_response_then_retries(
) -> None:
    entity = GhostEntity.generate()
    device = entity.enroll_device()
    payload = _publication(device)
    fake_engine = FakeEngine(payload)
    attempts = 0

    valid_receipt: dict[str, object] = {
        "version": 1,
        "device_id": device.device_id,
        "publication_sequence": 1,
        "expires_at": 4_600,
        "one_time_count": 2,
    }

    def requester(
        method: str,
        url: str,
        request_payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        del method, url, request_payload, timeout, headers
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise GhostNodeConnectionError("response lost")
        return 200, valid_receipt

    node = GhostNodeClient("https://ghostnode.test", requester=requester)

    with pytest.raises(GhostNodeConnectionError):
        publish_prekey_generation(
            cast(RatchetEngineClient, fake_engine),
            node,
            device,
            acknowledged_at=1_100,
        )
    assert fake_engine.commits == []

    receipt = publish_prekey_generation(
        cast(RatchetEngineClient, fake_engine),
        node,
        device,
        acknowledged_at=1_101,
    )
    assert receipt.publication_sequence == 1
    assert fake_engine.commits == [(1, 1_101)]


def test_node_client_rejects_invalid_prekey_receipt_shape() -> None:
    entity = GhostEntity.generate()
    device = entity.enroll_device()
    payload = _publication(device)

    def requester(
        method: str,
        url: str,
        request_payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        del method, url, request_payload, timeout, headers
        return 200, {
            "version": 1,
            "device_id": device.device_id,
            "publication_sequence": 1,
            "expires_at": 4_600,
            "one_time_count": 2,
            "unexpected": True,
        }

    node = GhostNodeClient("https://ghostnode.test", requester=requester)

    with pytest.raises(GhostNodeProtocolError, match="fields do not match"):
        node.publish_prekeys(
            device.device_id,
            bytes(device.device.signing_verify_key),
            payload,
        )


def test_node_client_rejects_signing_key_not_matching_target_device() -> None:
    entity = GhostEntity.generate()
    device = entity.enroll_device()
    other = GhostEntity.generate().enroll_device()
    payload = _publication(device)
    node = GhostNodeClient("https://ghostnode.test")

    with pytest.raises(ValueError, match="does not derive"):
        node.publish_prekeys(
            device.device_id,
            bytes(other.device.signing_verify_key),
            payload,
        )


def test_node_client_surfaces_prekey_publication_conflict() -> None:
    entity = GhostEntity.generate()
    device = entity.enroll_device()
    payload = _publication(device)

    def requester(
        method: str,
        url: str,
        request_payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        del method, url, request_payload, timeout, headers
        return 409, {"detail": "publication_sequence conflict"}

    node = GhostNodeClient("https://ghostnode.test", requester=requester)

    with pytest.raises(GhostNodeRequestError) as error:
        node.publish_prekeys(
            device.device_id,
            bytes(device.device.signing_verify_key),
            payload,
        )

    assert error.value.status_code == 409
