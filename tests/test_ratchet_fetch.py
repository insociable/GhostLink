import base64
import json
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
)
from ghostlink.contact import (
    ValidatedContact,
    export_contact_bundle,
    import_contact_bundle,
)
from ghostlink.device import EnrolledGhostDevice
from ghostlink.entity import GhostEntity
from ghostlink.node import create_app
from ghostlink.ratchet_binding import (
    RatchetBindingError,
    RatchetPreKeyMaterial,
    SignedRatchetPreKeyBinding,
    export_ratchet_prekey_binding,
)
from ghostlink.ratchet_engine import RatchetEngineClient
from ghostlink.ratchet_fetch import establish_session_from_relay
from ghostlink.ratchet_publication import (
    create_ratchet_prekey_publication,
    export_ratchet_prekey_publication,
    import_ratchet_prekey_publication,
)


def _material(
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


def _publication_request(
    device: EnrolledGhostDevice,
    *,
    issued_at: int,
) -> dict[str, object]:
    publication = create_ratchet_prekey_publication(
        device,
        publication_sequence=1,
        issued_at=issued_at,
        expires_at=issued_at + 3_600,
        one_time_material=(
            _material(
                seed=10,
                pre_key_id=1_001,
                signed_pre_key_id=2_001,
                kyber_pre_key_id=3_001,
            ),
            _material(
                seed=20,
                pre_key_id=1_002,
                signed_pre_key_id=2_001,
                kyber_pre_key_id=3_002,
            ),
        ),
        fallback_material=_material(
            seed=30,
            pre_key_id=None,
            signed_pre_key_id=2_001,
            kyber_pre_key_id=3_999,
        ),
    )
    return {
        "version": 1,
        "device_signing_public_key": base64.b64encode(
            bytes(device.device.signing_verify_key)
        ).decode("ascii"),
        "publication": export_ratchet_prekey_publication(publication),
    }


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


class FakeEngine:
    def __init__(self) -> None:
        self.established: list[
            tuple[SignedRatchetPreKeyBinding, ValidatedContact, int | None]
        ] = []

    def establish_session(
        self,
        signed_binding: SignedRatchetPreKeyBinding,
        contact: ValidatedContact,
        *,
        now: int | None = None,
    ) -> None:
        self.established.append((signed_binding, contact, now))


def _setup_relay(
) -> tuple[
    TestClient,
    GhostNodeClient,
    EnrolledGhostDevice,
    EnrolledGhostDevice,
    ValidatedContact,
    int,
]:
    alice = GhostEntity.generate()
    bob = GhostEntity.generate()
    alice_device = alice.enroll_device()
    bob_device = bob.enroll_device()
    bob_contact = import_contact_bundle(
        export_contact_bundle(bob, bob_device)
    )
    now = int(time.time())
    api_client = TestClient(create_app())
    published = api_client.put(
        f"/v2/prekeys/{bob_device.device_id}",
        json=_publication_request(bob_device, issued_at=now),
    )
    assert published.status_code == 200
    node = GhostNodeClient(
        "https://ghostnode.test",
        requester=_requester(api_client),
    )
    return api_client, node, alice_device, bob_device, bob_contact, now


def test_sender_fetch_verifies_contact_before_engine_session() -> None:
    (
        _api_client,
        node,
        alice_device,
        bob_device,
        bob_contact,
        now,
    ) = _setup_relay()
    fake_engine = FakeEngine()

    response = establish_session_from_relay(
        cast(RatchetEngineClient, fake_engine),
        node,
        alice_device,
        bob_contact,
        issued_at=now,
        verification_time=now,
    )

    assert response.target_device_id == bob_device.device_id
    assert response.requester_device_id == alice_device.device_id
    assert response.publication_sequence == 1
    assert response.bundle_kind == "one_time"
    assert len(fake_engine.established) == 1
    signed, contact, verified_at = fake_engine.established[0]
    assert signed.binding.device_id == bob_device.device_id
    assert signed.binding.publication_sequence == 1
    assert contact == bob_contact
    assert verified_at == now


@pytest.mark.parametrize(
    ("field", "mutate", "message"),
    [
        (
            "publication_sequence",
            lambda value: cast(int, value) + 1,
            "sequence does not match",
        ),
        (
            "expires_at",
            lambda value: cast(int, value) + 1,
            "expiration does not match",
        ),
        (
            "bundle_kind",
            lambda value: "fallback" if value == "one_time" else "one_time",
            "bundle kind does not match",
        ),
    ],
)
def test_sender_fetch_rejects_relay_metadata_mismatch_before_engine(
    field: str,
    mutate: Callable[[object], object],
    message: str,
) -> None:
    (
        api_client,
        _node,
        alice_device,
        _bob_device,
        bob_contact,
        now,
    ) = _setup_relay()
    fake_engine = FakeEngine()
    base_requester = _requester(api_client)

    def requester(
        method: str,
        url: str,
        payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        status_code, body = base_requester(
            method,
            url,
            payload,
            timeout,
            headers,
        )
        assert isinstance(body, dict)
        modified = dict(body)
        modified[field] = mutate(modified[field])
        return status_code, modified

    node = GhostNodeClient(
        "https://ghostnode.test",
        requester=requester,
    )

    with pytest.raises(GhostNodeProtocolError, match=message):
        establish_session_from_relay(
            cast(RatchetEngineClient, fake_engine),
            node,
            alice_device,
            bob_contact,
            issued_at=now,
            verification_time=now,
        )

    assert fake_engine.established == []


def test_sender_fetch_rejects_binding_from_unverified_device_before_engine() -> None:
    (
        api_client,
        _node,
        alice_device,
        _bob_device,
        bob_contact,
        now,
    ) = _setup_relay()
    mallory = GhostEntity.generate()
    mallory_device = mallory.enroll_device()
    mallory_publication = import_ratchet_prekey_publication(
        str(_publication_request(mallory_device, issued_at=now)["publication"])
    )
    foreign_binding = export_ratchet_prekey_binding(
        mallory_publication.one_time[0]
    )
    fake_engine = FakeEngine()
    base_requester = _requester(api_client)

    def requester(
        method: str,
        url: str,
        payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        status_code, body = base_requester(
            method,
            url,
            payload,
            timeout,
            headers,
        )
        assert isinstance(body, dict)
        modified = dict(body)
        modified["binding"] = foreign_binding
        return status_code, modified

    node = GhostNodeClient(
        "https://ghostnode.test",
        requester=requester,
    )

    with pytest.raises(
        RatchetBindingError,
        match="GhostID does not match verified contact",
    ):
        establish_session_from_relay(
            cast(RatchetEngineClient, fake_engine),
            node,
            alice_device,
            bob_contact,
            issued_at=now,
            verification_time=now,
        )

    assert fake_engine.established == []


def test_sender_fetch_rejects_noncanonical_binding_before_engine() -> None:
    (
        api_client,
        _node,
        alice_device,
        _bob_device,
        bob_contact,
        now,
    ) = _setup_relay()
    fake_engine = FakeEngine()
    base_requester = _requester(api_client)

    def requester(
        method: str,
        url: str,
        payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        status_code, body = base_requester(
            method,
            url,
            payload,
            timeout,
            headers,
        )
        assert isinstance(body, dict)
        modified = dict(body)
        parsed_binding = json.loads(cast(str, modified["binding"]))
        modified["binding"] = json.dumps(parsed_binding, indent=2)
        return status_code, modified

    node = GhostNodeClient(
        "https://ghostnode.test",
        requester=requester,
    )

    with pytest.raises(
        GhostNodeProtocolError,
        match="canonical serialization",
    ):
        establish_session_from_relay(
            cast(RatchetEngineClient, fake_engine),
            node,
            alice_device,
            bob_contact,
            issued_at=now,
            verification_time=now,
        )

    assert fake_engine.established == []


def test_node_client_fetch_retry_after_lost_response_reuses_allocation() -> None:
    (
        api_client,
        _node,
        alice_device,
        bob_device,
        _bob_contact,
        now,
    ) = _setup_relay()
    attempts = 0
    lost_body: dict[str, object] | None = None

    def requester(
        method: str,
        url: str,
        payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        nonlocal attempts, lost_body
        parsed = urllib.parse.urlparse(url)
        response = api_client.request(
            method,
            parsed.path,
            json=payload,
            headers=headers,
        )
        body = response.json() if response.content else None
        if method == "POST" and parsed.path.endswith("/fetch"):
            attempts += 1
            if attempts == 1:
                assert isinstance(body, dict)
                lost_body = dict(body)
                raise GhostNodeConnectionError("response lost after allocation")
        return response.status_code, body

    node = GhostNodeClient(
        "https://ghostnode.test",
        requester=requester,
    )

    with pytest.raises(GhostNodeConnectionError, match="response lost"):
        node.fetch_prekey(
            alice_device,
            bob_device.device_id,
            issued_at=now,
        )

    recovered = node.fetch_prekey(
        alice_device,
        bob_device.device_id,
        issued_at=now,
    )

    assert lost_body is not None
    assert recovered.binding == lost_body["binding"]
    assert (
        recovered.remaining_one_time_count
        == lost_body["remaining_one_time_count"]
    )


def test_node_client_rejects_unknown_prekey_fetch_response_fields() -> None:
    alice_device = GhostEntity.generate().enroll_device()
    bob_device = GhostEntity.generate().enroll_device()

    def requester(
        method: str,
        url: str,
        payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        del method, url, payload, timeout, headers
        return 200, {
            "version": 1,
            "target_device_id": bob_device.device_id,
            "requester_device_id": alice_device.device_id,
            "publication_sequence": 1,
            "expires_at": int(time.time()) + 3_600,
            "bundle_kind": "one_time",
            "binding": "{}",
            "remaining_one_time_count": 1,
            "unexpected": True,
        }

    node = GhostNodeClient(
        "https://ghostnode.test",
        requester=requester,
    )

    with pytest.raises(GhostNodeProtocolError, match="fields do not match"):
        node.fetch_prekey(
            alice_device,
            bob_device.device_id,
            issued_at=int(time.time()),
        )
