import base64
import json
from dataclasses import replace

import pytest
from ghostlink.device import EnrolledGhostDevice
from ghostlink.entity import GhostEntity
from ghostlink.ratchet_binding import RatchetBindingError, RatchetPreKeyMaterial
from ghostlink.ratchet_publication import (
    RatchetPreKeyPublication,
    create_ratchet_prekey_publication,
    export_ratchet_prekey_publication,
    import_ratchet_prekey_publication,
    verify_local_ratchet_prekey_publication,
)


def material(
    *,
    pre_key_id: int | None,
    pre_key_byte: int,
    kyber_pre_key_id: int,
    kyber_byte: int,
) -> RatchetPreKeyMaterial:
    return RatchetPreKeyMaterial(
        registration_id=4_200,
        identity_key=b"\x01" * 33,
        pre_key_id=pre_key_id,
        pre_key=None if pre_key_id is None else bytes([pre_key_byte]) * 33,
        signed_pre_key_id=2_001,
        signed_pre_key=b"\x03" * 33,
        signed_pre_key_signature=b"\x04" * 64,
        kyber_pre_key_id=kyber_pre_key_id,
        kyber_pre_key=bytes([kyber_byte]) * 1_184,
        kyber_pre_key_signature=b"\x06" * 64,
    )


def publication_fixture() -> tuple[
    GhostEntity,
    EnrolledGhostDevice,
    RatchetPreKeyPublication,
]:
    entity = GhostEntity.generate()
    device = entity.enroll_device()
    publication = create_ratchet_prekey_publication(
        device,
        publication_sequence=7,
        issued_at=1_000,
        expires_at=4_600,
        one_time_material=(
            material(
                pre_key_id=1_001,
                pre_key_byte=2,
                kyber_pre_key_id=3_001,
                kyber_byte=5,
            ),
            material(
                pre_key_id=1_002,
                pre_key_byte=7,
                kyber_pre_key_id=3_002,
                kyber_byte=8,
            ),
        ),
        fallback_material=material(
            pre_key_id=None,
            pre_key_byte=9,
            kyber_pre_key_id=3_999,
            kyber_byte=10,
        ),
    )
    return entity, device, publication


def test_publication_round_trip_is_deterministic_and_locally_verifiable() -> None:
    _, device, publication = publication_fixture()

    serialized = export_ratchet_prekey_publication(publication)
    imported = import_ratchet_prekey_publication(serialized)

    assert imported == publication
    assert export_ratchet_prekey_publication(imported) == serialized
    verify_local_ratchet_prekey_publication(imported, device)


def test_publication_rejects_duplicate_kyber_role() -> None:
    _, _, publication = publication_fixture()
    conflicting = replace(
        publication.one_time[0].binding,
        kyber_pre_key_id=publication.fallback.binding.kyber_pre_key_id,
    )

    with pytest.raises(RatchetBindingError, match="Kyber ID"):
        RatchetPreKeyPublication(
            publication_sequence=publication.publication_sequence,
            one_time=(
                replace(publication.one_time[0], binding=conflicting),
                publication.one_time[1],
            ),
            fallback=publication.fallback,
        )


def test_publication_rejects_generation_identity_mismatch() -> None:
    _, _, publication = publication_fixture()
    changed = replace(
        publication.one_time[0].binding,
        registration_id=4_201,
    )

    with pytest.raises(RatchetBindingError, match="generation identity"):
        RatchetPreKeyPublication(
            publication_sequence=publication.publication_sequence,
            one_time=(
                replace(publication.one_time[0], binding=changed),
                publication.one_time[1],
            ),
            fallback=publication.fallback,
        )


def test_publication_tampering_breaks_local_signature_verification() -> None:
    _, device, publication = publication_fixture()
    document = json.loads(export_ratchet_prekey_publication(publication))
    document["one_time"][0]["pre_key"] = base64.b64encode(b"\\x99" * 33).decode("ascii")

    imported = import_ratchet_prekey_publication(
        json.dumps(document, sort_keys=True, separators=(",", ":"))
    )

    with pytest.raises(RatchetBindingError, match="invalid device signature"):
        verify_local_ratchet_prekey_publication(
            imported,
            device,
        )
