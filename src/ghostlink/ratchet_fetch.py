"""Sender-side orchestration from GhostNode pre-key fetch to libsignal session."""

from __future__ import annotations

import time

from ghostlink.client.node_client import (
    GhostNodeClient,
    GhostNodeProtocolError,
)
from ghostlink.contact import VerifiedContact
from ghostlink.device import EnrolledGhostDevice
from ghostlink.prekey_fetch import PreKeyFetchResponse
from ghostlink.ratchet_binding import (
    export_ratchet_prekey_binding,
    import_ratchet_prekey_binding,
    verify_ratchet_prekey_binding,
)
from ghostlink.ratchet_engine import RatchetEngineClient


def establish_session_from_relay(
    engine: RatchetEngineClient,
    node: GhostNodeClient,
    local_device: EnrolledGhostDevice,
    contact: VerifiedContact,
    *,
    issued_at: int | None = None,
    verification_time: int | None = None,
) -> PreKeyFetchResponse:
    """Fetch, verify and atomically establish one remote libsignal session.

    The relay response is treated as untrusted transport data. No ratchet state
    is mutated until the signed binding has been checked against VerifiedContact
    and all response metadata agrees with that binding.
    """
    request_time = int(time.time()) if issued_at is None else issued_at
    current_time = (
        request_time
        if verification_time is None
        else verification_time
    )

    response = node.fetch_prekey(
        local_device,
        contact.device_id,
        issued_at=request_time,
    )
    signed_binding = import_ratchet_prekey_binding(response.binding)

    if export_ratchet_prekey_binding(signed_binding) != response.binding:
        raise GhostNodeProtocolError(
            "pre-key fetch binding must use canonical serialization"
        )

    binding = verify_ratchet_prekey_binding(
        signed_binding,
        contact,
        now=current_time,
    )

    if response.target_device_id != binding.device_id:
        raise GhostNodeProtocolError(
            "pre-key fetch target DeviceID does not match the signed binding"
        )
    if response.publication_sequence != binding.publication_sequence:
        raise GhostNodeProtocolError(
            "pre-key fetch sequence does not match the signed binding"
        )
    if response.expires_at != binding.expires_at:
        raise GhostNodeProtocolError(
            "pre-key fetch expiration does not match the signed binding"
        )
    if response.bundle_kind != binding.bundle_kind:
        raise GhostNodeProtocolError(
            "pre-key fetch bundle kind does not match the signed binding"
        )

    engine.establish_session(
        signed_binding,
        contact,
        now=current_time,
    )
    return response
