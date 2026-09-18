import base64
import json

import pytest
from ghostlink.contact import (
    ContactBundleError,
    ValidatedContact,
    export_contact_bundle,
    export_contact_qr_payload,
    import_contact_bundle,
    import_contact_qr_payload,
)
from ghostlink.entity import GhostEntity
from ghostlink.identity import derive_identity_fingerprint


def test_contact_bundle_round_trip_returns_validated_public_device() -> None:
    alice = GhostEntity.generate()
    alice_device = alice.enroll_device()

    serialized = export_contact_bundle(alice, alice_device)
    contact = import_contact_bundle(serialized)

    assert contact.ghost_id == alice.ghost_id
    assert contact.device_id == alice_device.device_id
    assert bytes(contact.identity_verify_key) == bytes(alice.verify_key)
    assert bytes(contact.device.encryption_public_key) == bytes(
        alice_device.device.encryption_public_key
    )


def test_contact_bundle_does_not_export_private_keys() -> None:
    alice = GhostEntity.generate()
    alice_device = alice.enroll_device()

    serialized = export_contact_bundle(alice, alice_device)

    identity_private_key = base64.b64encode(bytes(alice.signing_key)).decode("ascii")
    device_signing_private_key = base64.b64encode(
        bytes(alice_device.device.signing_key)
    ).decode("ascii")
    device_encryption_private_key = base64.b64encode(
        bytes(alice_device.device.encryption_key)
    ).decode("ascii")

    assert identity_private_key not in serialized
    assert device_signing_private_key not in serialized
    assert device_encryption_private_key not in serialized


def test_contact_bundle_rejects_modified_certificate_signature() -> None:
    alice = GhostEntity.generate()
    alice_device = alice.enroll_device()
    document = json.loads(export_contact_bundle(alice, alice_device))
    document["device_certificate_signature"] = base64.b64encode(
        b"\x00" * 64
    ).decode("ascii")

    with pytest.raises(
        ContactBundleError,
        match="device certificate signature is invalid",
    ):
        import_contact_bundle(json.dumps(document))


def test_contact_bundle_rejects_wrong_identity_public_key() -> None:
    alice = GhostEntity.generate()
    alice_device = alice.enroll_device()
    mallory = GhostEntity.generate()
    document = json.loads(export_contact_bundle(alice, alice_device))
    document["identity_public_key"] = base64.b64encode(
        bytes(mallory.verify_key)
    ).decode("ascii")

    with pytest.raises(
        ContactBundleError,
        match="certificate GhostID does not match identity key",
    ):
        import_contact_bundle(json.dumps(document))


def test_contact_bundle_rejects_invalid_ghost_id_format() -> None:
    alice = GhostEntity.generate()
    alice_device = alice.enroll_device()
    document = json.loads(export_contact_bundle(alice, alice_device))
    document["ghost_id"] = "invalid"

    with pytest.raises(
        ContactBundleError,
        match="ghost_id must use the ghost1 format",
    ):
        import_contact_bundle(json.dumps(document))


def test_contact_bundle_rejects_unknown_version() -> None:
    alice = GhostEntity.generate()
    alice_device = alice.enroll_device()
    document = json.loads(export_contact_bundle(alice, alice_device))
    document["version"] = 99

    with pytest.raises(
        ContactBundleError,
        match="unsupported contact bundle version",
    ):
        import_contact_bundle(json.dumps(document))


def test_contact_bundle_rejects_unknown_fields() -> None:
    alice = GhostEntity.generate()
    alice_device = alice.enroll_device()
    document = json.loads(export_contact_bundle(alice, alice_device))
    document["unexpected"] = "value"

    with pytest.raises(ContactBundleError, match="unknown fields: unexpected"):
        import_contact_bundle(json.dumps(document))



def test_fingerprint_v2_is_identical_across_devices_for_same_identity() -> None:
    alice = GhostEntity.generate()
    first = import_contact_bundle(
        export_contact_bundle(alice, alice.enroll_device())
    )
    second = import_contact_bundle(
        export_contact_bundle(alice, alice.enroll_device())
    )

    assert first.device_id != second.device_id
    assert derive_identity_fingerprint(bytes(first.identity_verify_key)) == (
        derive_identity_fingerprint(bytes(second.identity_verify_key))
    )


def test_contact_qr_payload_round_trip_is_public_and_validated() -> None:
    alice = GhostEntity.generate()
    alice_device = alice.enroll_device()

    payload = export_contact_qr_payload(alice, alice_device)
    contact = import_contact_qr_payload(payload)

    assert payload.startswith("ghostlink:contact:1:")
    assert isinstance(contact, ValidatedContact)
    assert contact.ghost_id == alice.ghost_id
    assert contact.device_id == alice_device.device_id


def test_contact_qr_payload_contains_only_contact_bundle_public_fields() -> None:
    alice = GhostEntity.generate()
    alice_device = alice.enroll_device()

    payload = export_contact_qr_payload(alice, alice_device)
    encoded = payload.removeprefix("ghostlink:contact:1:")
    decoded = base64.urlsafe_b64decode(encoded + ("=" * (-len(encoded) % 4)))
    document = json.loads(decoded)

    assert set(document) == {
        "version",
        "ghost_id",
        "identity_public_key",
        "device_id",
        "device_signing_public_key",
        "device_encryption_public_key",
        "device_certificate_signature",
    }
    assert all("private" not in field for field in document)
    assert "trust_state" not in document


def test_contact_qr_payload_rejects_unsupported_version() -> None:
    with pytest.raises(
        ContactBundleError,
        match="unsupported GhostLink contact QR version",
    ):
        import_contact_qr_payload("ghostlink:contact:2:AAAA")


def test_contact_qr_payload_rejects_noncanonical_bundle_json() -> None:
    alice = GhostEntity.generate()
    alice_device = alice.enroll_device()
    document = json.loads(export_contact_bundle(alice, alice_device))
    noncanonical = json.dumps(document, indent=2).encode("utf-8")
    encoded = base64.urlsafe_b64encode(noncanonical).decode("ascii").rstrip("=")

    with pytest.raises(
        ContactBundleError,
        match="QR contact bundle must use canonical JSON",
    ):
        import_contact_qr_payload(f"ghostlink:contact:1:{encoded}")


def test_contact_qr_payload_cannot_import_trust_state() -> None:
    alice = GhostEntity.generate()
    alice_device = alice.enroll_device()
    document = json.loads(export_contact_bundle(alice, alice_device))
    document["trust_state"] = "verified"
    serialized = json.dumps(document, sort_keys=True, separators=(",", ":"))
    encoded = base64.urlsafe_b64encode(serialized.encode("utf-8")).decode(
        "ascii"
    ).rstrip("=")

    with pytest.raises(ContactBundleError, match="unknown fields: trust_state"):
        import_contact_qr_payload(f"ghostlink:contact:1:{encoded}")
