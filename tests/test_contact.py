import base64
import json

import pytest
from ghostlink.contact import (
    ContactBundleError,
    export_contact_bundle,
    import_contact_bundle,
)
from ghostlink.entity import GhostEntity


def test_contact_bundle_round_trip_returns_verified_public_device() -> None:
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
