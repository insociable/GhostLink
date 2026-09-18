import base64
import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi.testclient import TestClient
from ghostlink.config import NodeSettings
from ghostlink.device import EnrolledGhostDevice
from ghostlink.entity import GhostEntity
from ghostlink.node import create_app
from ghostlink.prekey_fetch import create_prekey_fetch_request
from ghostlink.prekey_relay import (
    RelayPreKeyGeneration,
    SQLitePreKeyPublicationStore,
)
from ghostlink.ratchet_binding import (
    RatchetPreKeyMaterial,
    import_ratchet_prekey_binding,
)
from ghostlink.ratchet_publication import (
    create_ratchet_prekey_publication,
    export_ratchet_prekey_publication,
)


def material(
    *,
    seed: int,
    pre_key_id: int | None,
    signed_pre_key_id: int,
    kyber_pre_key_id: int,
) -> RatchetPreKeyMaterial:
    return RatchetPreKeyMaterial(
        registration_id=4_200,
        identity_key=bytes([1]) * 33,
        pre_key_id=pre_key_id,
        pre_key=None if pre_key_id is None else bytes([seed]) * 33,
        signed_pre_key_id=signed_pre_key_id,
        signed_pre_key=bytes([3]) * 33,
        signed_pre_key_signature=bytes([4]) * 64,
        kyber_pre_key_id=kyber_pre_key_id,
        kyber_pre_key=bytes([seed + 3]) * 1_184,
        kyber_pre_key_signature=bytes([seed + 4]) * 64,
    )


def publication_request(
    device: EnrolledGhostDevice,
    *,
    sequence: int,
    issued_at: int | None = None,
    lifetime_seconds: int = 3_600,
) -> dict[str, object]:
    now = int(time.time()) if issued_at is None else issued_at
    base = sequence * 100
    signed_pre_key_id = 2_000 + sequence

    publication = create_ratchet_prekey_publication(
        device,
        publication_sequence=sequence,
        issued_at=now,
        expires_at=now + lifetime_seconds,
        one_time_material=(
            material(
                seed=10,
                pre_key_id=1_000 + base + 1,
                signed_pre_key_id=signed_pre_key_id,
                kyber_pre_key_id=3_000 + base + 1,
            ),
            material(
                seed=20,
                pre_key_id=1_000 + base + 2,
                signed_pre_key_id=signed_pre_key_id,
                kyber_pre_key_id=3_000 + base + 2,
            ),
        ),
        fallback_material=material(
            seed=30,
            pre_key_id=None,
            signed_pre_key_id=signed_pre_key_id,
            kyber_pre_key_id=3_000 + base + 99,
        ),
    )
    return {
        "version": 1,
        "device_signing_public_key": base64.b64encode(
            bytes(device.device.signing_verify_key)
        ).decode("ascii"),
        "publication": export_ratchet_prekey_publication(publication),
    }


def test_prekey_publication_is_cryptographically_verified_and_acknowledged() -> None:

    entity = GhostEntity.generate()
    device = entity.enroll_device()
    request = publication_request(device, sequence=1)
    client = TestClient(create_app())

    response = client.put(f"/v2/prekeys/{device.device_id}", json=request)

    assert response.status_code == 200
    assert response.json()["device_id"] == device.device_id
    assert response.json()["publication_sequence"] == 1
    assert response.json()["one_time_count"] == 2


def test_prekey_publication_rejects_route_device_mismatch() -> None:

    entity = GhostEntity.generate()
    device = entity.enroll_device()
    request = publication_request(device, sequence=1)
    other_device_id = GhostEntity.generate().enroll_device().device_id

    response = TestClient(create_app()).put(
        f"/v2/prekeys/{other_device_id}",
        json=request,
    )

    assert response.status_code == 422
    assert response.json() == {
        "detail": "route DeviceID does not match device signing public key"
    }


def test_prekey_publication_rejects_structurally_valid_signature_tampering() -> None:

    entity = GhostEntity.generate()
    device = entity.enroll_device()
    request = publication_request(device, sequence=1)
    document = json.loads(str(request["publication"]))
    document["one_time"][0]["pre_key"] = base64.b64encode(
        bytes([0x99]) * 33
    ).decode("ascii")
    request["publication"] = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
    )

    response = TestClient(create_app()).put(
        f"/v2/prekeys/{device.device_id}",
        json=request,
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "device signature is invalid"}


def test_prekey_publication_sequence_is_strictly_monotonic_and_idempotent() -> None:

    entity = GhostEntity.generate()
    device = entity.enroll_device()
    client = TestClient(create_app())

    first = publication_request(device, sequence=1)
    assert client.put(f"/v2/prekeys/{device.device_id}", json=first).status_code == 200
    assert client.put(f"/v2/prekeys/{device.device_id}", json=first).status_code == 200

    conflicting = dict(first)
    conflict_document = json.loads(str(conflicting["publication"]))
    conflict_document["one_time"].reverse()
    conflicting["publication"] = json.dumps(
        conflict_document,
        sort_keys=True,
        separators=(",", ":"),
    )
    conflict = client.put(
        f"/v2/prekeys/{device.device_id}",
        json=conflicting,
    )
    assert conflict.status_code == 409
    assert conflict.json() == {
        "detail": "publication_sequence already exists with different payload"
    }

    skipped = publication_request(device, sequence=3)
    response = client.put(f"/v2/prekeys/{device.device_id}", json=skipped)
    assert response.status_code == 409
    assert response.json() == {
        "detail": "publication_sequence must advance by exactly one"
    }

    second = publication_request(device, sequence=2)
    accepted = client.put(f"/v2/prekeys/{device.device_id}", json=second)
    assert accepted.status_code == 200
    assert accepted.json()["publication_sequence"] == 2

    stale = client.put(f"/v2/prekeys/{device.device_id}", json=first)
    assert stale.status_code == 409


def test_prekey_publication_requires_shared_relay_bearer_when_enabled() -> None:

    token = "prekey-relay-secret"  # noqa: S105
    entity = GhostEntity.generate()
    device = entity.enroll_device()
    request = publication_request(device, sequence=1)
    client = TestClient(
        create_app(settings=NodeSettings(access_token=token))
    )

    missing = client.put(f"/v2/prekeys/{device.device_id}", json=request)
    accepted = client.put(
        f"/v2/prekeys/{device.device_id}",
        json=request,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert missing.status_code == 401
    assert accepted.status_code == 200


def test_prekey_publication_rejects_already_expired_generation() -> None:

    entity = GhostEntity.generate()
    device = entity.enroll_device()
    now = int(time.time())
    request = publication_request(
        device,
        sequence=1,
        issued_at=now - 100,
        lifetime_seconds=50,
    )

    response = TestClient(create_app()).put(
        f"/v2/prekeys/{device.device_id}",
        json=request,
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "publication is already expired"}


def test_prekey_publication_sqlite_replacement_survives_app_recreation(
    tmp_path: Path,
) -> None:

    database_path = tmp_path / "relay.sqlite3"
    settings = NodeSettings(database_path=database_path)
    entity = GhostEntity.generate()
    device = entity.enroll_device()

    first = publication_request(device, sequence=1)
    first_client = TestClient(create_app(settings=settings))
    assert (
        first_client.put(
            f"/v2/prekeys/{device.device_id}",
            json=first,
        ).status_code
        == 200
    )

    second_client = TestClient(create_app(settings=settings))
    retry = second_client.put(
        f"/v2/prekeys/{device.device_id}",
        json=first,
    )
    assert retry.status_code == 200
    assert retry.json()["publication_sequence"] == 1

    second = publication_request(device, sequence=2)
    replaced = second_client.put(
        f"/v2/prekeys/{device.device_id}",
        json=second,
    )
    assert replaced.status_code == 200
    assert replaced.json()["publication_sequence"] == 2



def fetch_request(
    requester: EnrolledGhostDevice,
    target_device_id: str,
    *,
    issued_at: int | None = None,
    request_id: str | None = None,
) -> dict[str, object]:
    request = create_prekey_fetch_request(
        requester,
        target_device_id,
        issued_at=int(time.time()) if issued_at is None else issued_at,
        request_id=request_id,
    )
    return request.model_dump()


def test_prekey_fetch_is_authenticated_idempotent_and_uses_fallback() -> None:
    target = GhostEntity.generate().enroll_device()
    requester_a = GhostEntity.generate().enroll_device()
    requester_b = GhostEntity.generate().enroll_device()
    requester_c = GhostEntity.generate().enroll_device()
    client = TestClient(create_app())

    publication = publication_request(target, sequence=1)
    assert (
        client.put(
            f"/v2/prekeys/{target.device_id}",
            json=publication,
        ).status_code
        == 200
    )

    first_request = fetch_request(requester_a, target.device_id)
    first = client.post(
        f"/v2/prekeys/{target.device_id}/fetch",
        json=first_request,
    )
    assert first.status_code == 200
    assert first.json()["bundle_kind"] == "one_time"
    assert first.json()["remaining_one_time_count"] == 1
    first_binding = import_ratchet_prekey_binding(first.json()["binding"])
    assert first_binding.binding.bundle_kind == "one_time"

    retry = client.post(
        f"/v2/prekeys/{target.device_id}/fetch",
        json=first_request,
    )
    assert retry.status_code == 200
    assert retry.json() == first.json()

    same_requester_new_nonce = client.post(
        f"/v2/prekeys/{target.device_id}/fetch",
        json=fetch_request(requester_a, target.device_id),
    )
    assert same_requester_new_nonce.status_code == 200
    assert same_requester_new_nonce.json() == first.json()

    second = client.post(
        f"/v2/prekeys/{target.device_id}/fetch",
        json=fetch_request(requester_b, target.device_id),
    )
    assert second.status_code == 200
    assert second.json()["bundle_kind"] == "one_time"
    assert second.json()["remaining_one_time_count"] == 0
    assert second.json()["binding"] != first.json()["binding"]

    fallback = client.post(
        f"/v2/prekeys/{target.device_id}/fetch",
        json=fetch_request(requester_c, target.device_id),
    )
    assert fallback.status_code == 200
    assert fallback.json()["bundle_kind"] == "fallback"
    assert fallback.json()["remaining_one_time_count"] == 0
    fallback_binding = import_ratchet_prekey_binding(fallback.json()["binding"])
    assert fallback_binding.binding.bundle_kind == "fallback"


def test_prekey_fetch_signature_is_bound_to_target_device() -> None:
    target = GhostEntity.generate().enroll_device()
    other_target = GhostEntity.generate().enroll_device()
    requester = GhostEntity.generate().enroll_device()
    client = TestClient(create_app())

    assert (
        client.put(
            f"/v2/prekeys/{other_target.device_id}",
            json=publication_request(other_target, sequence=1),
        ).status_code
        == 200
    )

    signed_for_target = fetch_request(requester, target.device_id)
    response = client.post(
        f"/v2/prekeys/{other_target.device_id}/fetch",
        json=signed_for_target,
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "requester signature is invalid"}


def test_prekey_fetch_rejects_stale_request_and_device_substitution() -> None:
    target = GhostEntity.generate().enroll_device()
    requester = GhostEntity.generate().enroll_device()
    impostor = GhostEntity.generate().enroll_device()
    client = TestClient(create_app())
    now = int(time.time())

    assert (
        client.put(
            f"/v2/prekeys/{target.device_id}",
            json=publication_request(target, sequence=1),
        ).status_code
        == 200
    )

    stale = client.post(
        f"/v2/prekeys/{target.device_id}/fetch",
        json=fetch_request(
            requester,
            target.device_id,
            issued_at=now - 301,
        ),
    )
    assert stale.status_code == 401
    assert stale.json() == {"detail": "fetch request is too old"}

    substituted = fetch_request(requester, target.device_id)
    substituted["requester_device_id"] = impostor.device_id
    mismatch = client.post(
        f"/v2/prekeys/{target.device_id}/fetch",
        json=substituted,
    )
    assert mismatch.status_code == 401
    assert mismatch.json() == {
        "detail": (
            "requester DeviceID does not match requester signing public key"
        )
    }


def test_prekey_fetch_requires_shared_bearer_when_enabled() -> None:
    token = "prekey-fetch-secret"  # noqa: S105
    target = GhostEntity.generate().enroll_device()
    requester = GhostEntity.generate().enroll_device()
    client = TestClient(create_app(settings=NodeSettings(access_token=token)))

    publication = publication_request(target, sequence=1)
    assert (
        client.put(
            f"/v2/prekeys/{target.device_id}",
            json=publication,
            headers={"Authorization": f"Bearer {token}"},
        ).status_code
        == 200
    )

    request = fetch_request(requester, target.device_id)
    missing = client.post(
        f"/v2/prekeys/{target.device_id}/fetch",
        json=request,
    )
    accepted = client.post(
        f"/v2/prekeys/{target.device_id}/fetch",
        json=request,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert missing.status_code == 401
    assert accepted.status_code == 200


def test_prekey_fetch_rate_limit_does_not_break_idempotent_retry() -> None:
    settings = NodeSettings(
        prekey_fetch_window_seconds=60,
        prekey_fetch_max_new_allocations=1,
    )
    target = GhostEntity.generate().enroll_device()
    requester_a = GhostEntity.generate().enroll_device()
    requester_b = GhostEntity.generate().enroll_device()
    client = TestClient(create_app(settings=settings))

    assert (
        client.put(
            f"/v2/prekeys/{target.device_id}",
            json=publication_request(target, sequence=1),
        ).status_code
        == 200
    )

    request_a = fetch_request(requester_a, target.device_id)
    first = client.post(
        f"/v2/prekeys/{target.device_id}/fetch",
        json=request_a,
    )
    blocked = client.post(
        f"/v2/prekeys/{target.device_id}/fetch",
        json=fetch_request(requester_b, target.device_id),
    )
    retry = client.post(
        f"/v2/prekeys/{target.device_id}/fetch",
        json=request_a,
    )

    assert first.status_code == 200
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) >= 1
    assert retry.status_code == 200
    assert retry.json() == first.json()


def test_prekey_fetch_unknown_target_is_not_found() -> None:
    target = GhostEntity.generate().enroll_device()
    requester = GhostEntity.generate().enroll_device()

    response = TestClient(create_app()).post(
        f"/v2/prekeys/{target.device_id}/fetch",
        json=fetch_request(requester, target.device_id),
    )

    assert response.status_code == 404
    assert response.json() == {
        "detail": "target has no active pre-key generation"
    }


def test_sqlite_publication_retry_after_pop_does_not_restore_pool(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "relay.sqlite3"
    settings = NodeSettings(database_path=database_path)
    target = GhostEntity.generate().enroll_device()
    requesters = [
        GhostEntity.generate().enroll_device()
        for _ in range(3)
    ]
    client = TestClient(create_app(settings=settings))
    publication = publication_request(target, sequence=1)

    assert (
        client.put(
            f"/v2/prekeys/{target.device_id}",
            json=publication,
        ).status_code
        == 200
    )
    first = client.post(
        f"/v2/prekeys/{target.device_id}/fetch",
        json=fetch_request(requesters[0], target.device_id),
    )
    assert first.status_code == 200
    assert first.json()["remaining_one_time_count"] == 1

    retry_publication = client.put(
        f"/v2/prekeys/{target.device_id}",
        json=publication,
    )
    assert retry_publication.status_code == 200

    second = client.post(
        f"/v2/prekeys/{target.device_id}/fetch",
        json=fetch_request(requesters[1], target.device_id),
    )
    third = client.post(
        f"/v2/prekeys/{target.device_id}/fetch",
        json=fetch_request(requesters[2], target.device_id),
    )

    assert second.status_code == 200
    assert second.json()["bundle_kind"] == "one_time"
    assert second.json()["remaining_one_time_count"] == 0
    assert third.status_code == 200
    assert third.json()["bundle_kind"] == "fallback"


def test_sqlite_fetch_allocation_survives_app_recreation(
    tmp_path: Path,
) -> None:
    settings = NodeSettings(database_path=tmp_path / "relay.sqlite3")
    target = GhostEntity.generate().enroll_device()
    requester = GhostEntity.generate().enroll_device()
    request = fetch_request(requester, target.device_id)

    first_client = TestClient(create_app(settings=settings))
    assert (
        first_client.put(
            f"/v2/prekeys/{target.device_id}",
            json=publication_request(target, sequence=1),
        ).status_code
        == 200
    )
    first = first_client.post(
        f"/v2/prekeys/{target.device_id}/fetch",
        json=request,
    )
    assert first.status_code == 200

    second_client = TestClient(create_app(settings=settings))
    retry = second_client.post(
        f"/v2/prekeys/{target.device_id}/fetch",
        json=request,
    )

    assert retry.status_code == 200
    assert retry.json() == first.json()


def test_sqlite_fetch_is_atomic_under_concurrent_requesters(
    tmp_path: Path,
) -> None:
    target = GhostEntity.generate().enroll_device()
    requesters = [
        GhostEntity.generate().enroll_device()
        for _ in range(3)
    ]
    store = SQLitePreKeyPublicationStore(
        tmp_path / "relay.sqlite3",
        fetch_max_new_allocations=10,
    )
    store.publish(
        RelayPreKeyGeneration(
            device_id=target.device_id,
            publication_sequence=1,
            expires_at=10_000,
            publication_payload='{"generation":1}',
            one_time_bindings=("one", "two"),
            fallback_binding="fallback",
        )
    )

    def allocate(index: int) -> tuple[str, str]:
        response = store.fetch(
            target.device_id,
            requesters[index].device_id,
            f"{index + 1:032x}",
            now=1_000,
        )
        return response.bundle_kind, response.binding

    with ThreadPoolExecutor(max_workers=3) as executor:
        results = list(executor.map(allocate, range(3)))

    one_time = [binding for kind, binding in results if kind == "one_time"]
    fallback = [binding for kind, binding in results if kind == "fallback"]

    assert sorted(one_time) == ["one", "two"]
    assert fallback == ["fallback"]


def test_sqlite_same_requester_concurrency_consumes_only_one_bundle(
    tmp_path: Path,
) -> None:
    target = GhostEntity.generate().enroll_device()
    requester = GhostEntity.generate().enroll_device()
    store = SQLitePreKeyPublicationStore(tmp_path / "relay.sqlite3")
    store.publish(
        RelayPreKeyGeneration(
            device_id=target.device_id,
            publication_sequence=1,
            expires_at=10_000,
            publication_payload='{"generation":1}',
            one_time_bindings=("one", "two"),
            fallback_binding="fallback",
        )
    )

    def allocate(index: int) -> tuple[str, int]:
        response = store.fetch(
            target.device_id,
            requester.device_id,
            f"{index + 1:032x}",
            now=1_000,
        )
        return response.binding, response.remaining_one_time_count

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(allocate, range(4)))

    assert set(results) == {("one", 1)}
