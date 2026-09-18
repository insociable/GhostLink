import base64
import json
from dataclasses import replace

import pytest
from ghostlink.contact import export_contact_bundle, import_contact_bundle
from ghostlink.entity import GhostEntity
from ghostlink.ratchet_binding import (
    RatchetBindingError,
    RatchetPreKeyMaterial,
    create_ratchet_prekey_binding,
    export_ratchet_prekey_binding,
    import_ratchet_prekey_binding,
    sign_ratchet_prekey_binding,
    verify_ratchet_prekey_binding,
)


def ratchet_material(*, identity_byte: int = 1) -> RatchetPreKeyMaterial:
    return RatchetPreKeyMaterial(
        registration_id=4_200,
        identity_key=bytes([identity_byte]) * 33,
        pre_key_id=1001,
        pre_key=b"\x02" * 33,
        signed_pre_key_id=2001,
        signed_pre_key=b"\x03" * 33,
        signed_pre_key_signature=b"\x04" * 64,
        kyber_pre_key_id=3001,
        kyber_pre_key=b"\x05" * 1_184,
        kyber_pre_key_signature=b"\x06" * 64,
    )


def create_signed_fixture(*, issued_at: int = 1_000):
    bob = GhostEntity.generate()
    bob_device = bob.enroll_device()
    contact = import_contact_bundle(export_contact_bundle(bob, bob_device))
    binding = create_ratchet_prekey_binding(
        bob_device,
        ratchet_material(),
        publication_sequence=7,
        bundle_kind="one_time",
        issued_at=issued_at,
        lifetime_seconds=3_600,
        bundle_id=b"\xaa" * 16,
    )
    signed = sign_ratchet_prekey_binding(binding, bob_device)
    return bob, bob_device, contact, binding, signed


def test_signed_ratchet_binding_round_trip_verifies_against_contact() -> None:
    _, _, contact, binding, signed = create_signed_fixture()

    serialized = export_ratchet_prekey_binding(signed)
    imported = import_ratchet_prekey_binding(serialized)
    verified = verify_ratchet_prekey_binding(
        imported,
        contact,
        now=1_100,
    )

    assert verified == binding
    assert verified.signal_address_name == contact.device_id
    assert verified.signal_device_id == 1
    assert len(verified.bundle_id) == 16
    assert verified.publication_sequence == 7
    assert verified.bundle_kind == "one_time"


def test_exported_binding_contains_public_material_only() -> None:
    bob, bob_device, _, _, signed = create_signed_fixture()

    serialized = export_ratchet_prekey_binding(signed)

    assert base64.b64encode(bytes(bob.signing_key)).decode("ascii") not in serialized
    assert (
        base64.b64encode(bytes(bob_device.device.signing_key)).decode("ascii")
        not in serialized
    )
    assert (
        base64.b64encode(bytes(bob_device.device.encryption_key)).decode("ascii")
        not in serialized
    )


def test_modified_libsignal_identity_key_breaks_device_signature() -> None:
    _, _, contact, _, signed = create_signed_fixture()
    document = json.loads(export_ratchet_prekey_binding(signed))
    document["identity_key"] = base64.b64encode(b"\x99" * 33).decode("ascii")

    imported = import_ratchet_prekey_binding(json.dumps(document))

    with pytest.raises(RatchetBindingError, match="device signature is invalid"):
        verify_ratchet_prekey_binding(imported, contact, now=1_100)


def test_modified_prekey_breaks_device_signature() -> None:
    _, _, contact, _, signed = create_signed_fixture()
    document = json.loads(export_ratchet_prekey_binding(signed))
    document["pre_key"] = base64.b64encode(b"\x98" * 33).decode("ascii")

    imported = import_ratchet_prekey_binding(json.dumps(document))

    with pytest.raises(RatchetBindingError, match="device signature is invalid"):
        verify_ratchet_prekey_binding(imported, contact, now=1_100)


def test_binding_for_another_verified_device_is_rejected() -> None:
    _, _, _, _, signed = create_signed_fixture()
    mallory = GhostEntity.generate()
    mallory_device = mallory.enroll_device()
    mallory_contact = import_contact_bundle(
        export_contact_bundle(mallory, mallory_device)
    )

    with pytest.raises(
        RatchetBindingError,
        match="GhostID does not match verified contact",
    ):
        verify_ratchet_prekey_binding(signed, mallory_contact, now=1_100)


def test_expired_binding_is_rejected() -> None:
    _, _, contact, _, signed = create_signed_fixture(issued_at=1_000)

    with pytest.raises(RatchetBindingError, match="binding has expired"):
        verify_ratchet_prekey_binding(signed, contact, now=5_001)


def test_binding_issued_too_far_in_future_is_rejected() -> None:
    _, _, contact, _, signed = create_signed_fixture(issued_at=2_000)

    with pytest.raises(
        RatchetBindingError,
        match="issued too far in the future",
    ):
        verify_ratchet_prekey_binding(signed, contact, now=1_000)


def test_libsignal_address_must_equal_verified_device_id() -> None:
    _, bob_device, _, binding, _ = create_signed_fixture()

    with pytest.raises(
        RatchetBindingError,
        match="signal_address_name must equal",
    ):
        replace(binding, signal_address_name="device1:" + ("a" * 52))

    assert binding.signal_address_name == bob_device.device_id


def test_binding_rejects_partial_optional_prekey() -> None:
    material = replace(ratchet_material(), pre_key=None)
    bob = GhostEntity.generate()
    bob_device = bob.enroll_device()

    with pytest.raises(
        RatchetBindingError,
        match="pre_key_id and pre_key",
    ):
        create_ratchet_prekey_binding(
            bob_device,
            material,
            publication_sequence=1,
            bundle_kind="one_time",
            issued_at=1_000,
            bundle_id=b"\xbb" * 16,
        )


def test_binding_rejects_noncanonical_or_unknown_wire_data() -> None:
    _, _, _, _, signed = create_signed_fixture()
    document = json.loads(export_ratchet_prekey_binding(signed))
    document["unexpected"] = "field"

    with pytest.raises(
        RatchetBindingError,
        match="fields do not match",
    ):
        import_ratchet_prekey_binding(json.dumps(document))


def test_signing_binding_with_wrong_local_device_is_rejected() -> None:
    _, _, _, binding, _ = create_signed_fixture()
    other = GhostEntity.generate()
    other_device = other.enroll_device()

    with pytest.raises(
        RatchetBindingError,
        match="binding GhostID does not match local device",
    ):
        sign_ratchet_prekey_binding(binding, other_device)


def test_identity_replacement_changes_authenticated_binding_bytes() -> None:
    _, bob_device, _, binding, signed = create_signed_fixture()
    changed_material = ratchet_material(identity_byte=9)
    changed = create_ratchet_prekey_binding(
        bob_device,
        changed_material,
        publication_sequence=binding.publication_sequence,
        bundle_kind=binding.bundle_kind,
        issued_at=binding.issued_at,
        lifetime_seconds=binding.expires_at - binding.issued_at,
        bundle_id=binding.bundle_id,
    )
    changed_signed = sign_ratchet_prekey_binding(changed, bob_device)

    assert changed.identity_key != binding.identity_key
    assert changed.canonical_bytes() != binding.canonical_bytes()
    assert changed_signed.device_signature != signed.device_signature

def test_publication_sequence_is_authenticated() -> None:
    _, _, contact, _, signed = create_signed_fixture()
    document = json.loads(export_ratchet_prekey_binding(signed))
    document["publication_sequence"] += 1

    imported = import_ratchet_prekey_binding(json.dumps(document))

    with pytest.raises(RatchetBindingError, match="device signature is invalid"):
        verify_ratchet_prekey_binding(imported, contact, now=1_100)


def test_one_time_binding_requires_ec_one_time_prekey() -> None:
    bob = GhostEntity.generate()
    bob_device = bob.enroll_device()
    material = replace(ratchet_material(), pre_key_id=None, pre_key=None)

    with pytest.raises(
        RatchetBindingError,
        match="one_time binding requires",
    ):
        create_ratchet_prekey_binding(
            bob_device,
            material,
            publication_sequence=1,
            bundle_kind="one_time",
            issued_at=1_000,
        )


def test_fallback_binding_requires_absent_ec_one_time_prekey() -> None:
    bob = GhostEntity.generate()
    bob_device = bob.enroll_device()
    material = replace(ratchet_material(), pre_key_id=None, pre_key=None)

    binding = create_ratchet_prekey_binding(
        bob_device,
        material,
        publication_sequence=2,
        bundle_kind="fallback",
        issued_at=1_000,
    )
    signed = sign_ratchet_prekey_binding(binding, bob_device)
    contact = import_contact_bundle(export_contact_bundle(bob, bob_device))

    assert verify_ratchet_prekey_binding(signed, contact, now=1_100) == binding

    with pytest.raises(
        RatchetBindingError,
        match="fallback binding must not contain",
    ):
        create_ratchet_prekey_binding(
            bob_device,
            ratchet_material(),
            publication_sequence=2,
            bundle_kind="fallback",
            issued_at=1_000,
        )


@pytest.mark.parametrize("publication_sequence", [0, -1, 1 << 64])
def test_binding_rejects_invalid_publication_sequence(
    publication_sequence: int,
) -> None:
    bob = GhostEntity.generate()
    bob_device = bob.enroll_device()

    with pytest.raises(RatchetBindingError, match="publication_sequence"):
        create_ratchet_prekey_binding(
            bob_device,
            ratchet_material(),
            publication_sequence=publication_sequence,
            bundle_kind="one_time",
            issued_at=1_000,
        )


def test_binding_rejects_unknown_bundle_kind() -> None:
    bob = GhostEntity.generate()
    bob_device = bob.enroll_device()

    with pytest.raises(RatchetBindingError, match="bundle_kind"):
        create_ratchet_prekey_binding(
            bob_device,
            ratchet_material(),
            publication_sequence=1,
            bundle_kind="unexpected",
            issued_at=1_000,
        )
