"""Application orchestration for crash-safe ratchet pre-key publication."""

from __future__ import annotations

import time

from ghostlink.client.node_client import (
    GhostNodeClient,
    GhostNodeProtocolError,
    PreKeyPublicationReceipt,
)
from ghostlink.device import EnrolledGhostDevice
from ghostlink.ratchet_engine import RatchetEngineClient
from ghostlink.ratchet_publication import (
    import_ratchet_prekey_publication,
    verify_local_ratchet_prekey_publication,
)


def publish_prekey_generation(
    engine: RatchetEngineClient,
    node: GhostNodeClient,
    device: EnrolledGhostDevice,
    *,
    one_time_count: int = 100,
    issued_at: int | None = None,
    lifetime_seconds: int = 7 * 24 * 60 * 60,
    acknowledged_at: int | None = None,
) -> PreKeyPublicationReceipt:
    """Prepare, publish, validate the relay receipt, then commit locally.

    The local lifecycle remains pending unless every relay acknowledgement
    field matches the exact locally staged publication.
    """
    payload = engine.prepare_prekey_publication(
        one_time_count=one_time_count,
        issued_at=issued_at,
        lifetime_seconds=lifetime_seconds,
    )
    publication = import_ratchet_prekey_publication(payload)
    verify_local_ratchet_prekey_publication(publication, device)

    receipt = node.publish_prekeys(
        device.device_id,
        bytes(device.device.signing_verify_key),
        payload,
    )

    expected_sequence = publication.publication_sequence
    expected_expiration = publication.fallback.binding.expires_at
    expected_count = len(publication.one_time)

    if receipt.device_id != device.device_id:
        raise GhostNodeProtocolError(
            "pre-key receipt DeviceID does not match the local device"
        )
    if receipt.publication_sequence != expected_sequence:
        raise GhostNodeProtocolError(
            "pre-key receipt sequence does not match the staged publication"
        )
    if receipt.expires_at != expected_expiration:
        raise GhostNodeProtocolError(
            "pre-key receipt expiration does not match the staged publication"
        )
    if receipt.one_time_count != expected_count:
        raise GhostNodeProtocolError(
            "pre-key receipt count does not match the staged publication"
        )

    commit_time = (
        int(time.time()) if acknowledged_at is None else acknowledged_at
    )
    engine.commit_prekey_publication(
        expected_sequence,
        published_at=commit_time,
    )
    return receipt
