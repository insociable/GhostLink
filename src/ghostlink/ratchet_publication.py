"""Signed production publication containing one complete ratchet pre-key generation."""

from __future__ import annotations

import json
from dataclasses import dataclass

from nacl.exceptions import BadSignatureError

from ghostlink.device import EnrolledGhostDevice
from ghostlink.ratchet_binding import (
    RatchetBindingError,
    RatchetPreKeyMaterial,
    SignedRatchetPreKeyBinding,
    create_ratchet_prekey_binding,
    export_ratchet_prekey_binding,
    import_ratchet_prekey_binding,
    sign_ratchet_prekey_binding,
)

_PUBLICATION_VERSION = 1
_MAX_PUBLICATION_SEQUENCE = (1 << 53) - 1
_MAX_ONE_TIME_BINDINGS = 256
_MAX_PUBLICATION_BYTES = 1024 * 1024
_PUBLICATION_FIELDS = {
    "version",
    "publication_sequence",
    "one_time",
    "fallback",
}


@dataclass(frozen=True, slots=True)
class RatchetPreKeyPublication:
    """One device-signed atomic pre-key generation ready for relay publication."""

    publication_sequence: int
    one_time: tuple[SignedRatchetPreKeyBinding, ...]
    fallback: SignedRatchetPreKeyBinding

    def __post_init__(self) -> None:
        if (
            not isinstance(self.publication_sequence, int)
            or isinstance(self.publication_sequence, bool)
            or self.publication_sequence <= 0
            or self.publication_sequence > _MAX_PUBLICATION_SEQUENCE
        ):
            raise RatchetBindingError(
                "publication_sequence is outside the supported range"
            )
        if not self.one_time or len(self.one_time) > _MAX_ONE_TIME_BINDINGS:
            raise RatchetBindingError(
                "publication must contain between 1 and 256 one-time bindings"
            )

        fallback = self.fallback.binding
        if fallback.bundle_kind != "fallback":
            raise RatchetBindingError(
                "publication fallback must use bundle_kind fallback"
            )
        if fallback.publication_sequence != self.publication_sequence:
            raise RatchetBindingError(
                "fallback publication_sequence does not match publication"
            )

        reference = (
            fallback.ghost_id,
            fallback.device_id,
            fallback.signal_address_name,
            fallback.signal_device_id,
            fallback.registration_id,
            fallback.issued_at,
            fallback.expires_at,
            fallback.identity_key,
            fallback.signed_pre_key_id,
            fallback.signed_pre_key,
            fallback.signed_pre_key_signature,
        )

        bundle_ids = {fallback.bundle_id}
        pre_key_ids: set[int] = set()
        kyber_ids = {fallback.kyber_pre_key_id}

        for signed in self.one_time:
            binding = signed.binding
            if binding.bundle_kind != "one_time":
                raise RatchetBindingError(
                    "one-time publication entry has the wrong bundle_kind"
                )
            if binding.publication_sequence != self.publication_sequence:
                raise RatchetBindingError(
                    "one-time publication_sequence does not match publication"
                )
            current = (
                binding.ghost_id,
                binding.device_id,
                binding.signal_address_name,
                binding.signal_device_id,
                binding.registration_id,
                binding.issued_at,
                binding.expires_at,
                binding.identity_key,
                binding.signed_pre_key_id,
                binding.signed_pre_key,
                binding.signed_pre_key_signature,
            )
            if current != reference:
                raise RatchetBindingError(
                    "publication bindings do not share one generation identity"
                )
            if binding.bundle_id in bundle_ids:
                raise RatchetBindingError("publication contains duplicate bundle_id")
            bundle_ids.add(binding.bundle_id)

            if binding.pre_key_id is None:
                raise RatchetBindingError(
                    "one-time publication entry is missing its EC pre-key"
                )
            if binding.pre_key_id in pre_key_ids:
                raise RatchetBindingError(
                    "publication contains duplicate EC one-time pre-key ID"
                )
            pre_key_ids.add(binding.pre_key_id)

            if binding.kyber_pre_key_id in kyber_ids:
                raise RatchetBindingError(
                    "publication contains duplicate or last-resort Kyber ID"
                )
            kyber_ids.add(binding.kyber_pre_key_id)


def create_ratchet_prekey_publication(
    device: EnrolledGhostDevice,
    *,
    publication_sequence: int,
    issued_at: int,
    expires_at: int,
    one_time_material: tuple[RatchetPreKeyMaterial, ...],
    fallback_material: RatchetPreKeyMaterial,
) -> RatchetPreKeyPublication:
    """Sign one complete prepared libsignal generation with the GhostLink device."""
    lifetime_seconds = expires_at - issued_at
    if lifetime_seconds <= 0:
        raise RatchetBindingError("publication expiration must follow issuance")

    one_time: list[SignedRatchetPreKeyBinding] = []
    for material in one_time_material:
        binding = create_ratchet_prekey_binding(
            device,
            material,
            publication_sequence=publication_sequence,
            bundle_kind="one_time",
            issued_at=issued_at,
            lifetime_seconds=lifetime_seconds,
        )
        one_time.append(sign_ratchet_prekey_binding(binding, device))

    fallback_binding = create_ratchet_prekey_binding(
        device,
        fallback_material,
        publication_sequence=publication_sequence,
        bundle_kind="fallback",
        issued_at=issued_at,
        lifetime_seconds=lifetime_seconds,
    )
    fallback = sign_ratchet_prekey_binding(fallback_binding, device)

    return RatchetPreKeyPublication(
        publication_sequence=publication_sequence,
        one_time=tuple(one_time),
        fallback=fallback,
    )


def export_ratchet_prekey_publication(
    publication: RatchetPreKeyPublication,
) -> str:
    """Return deterministic JSON bytes-as-text for exact retry publication."""
    document: dict[str, object] = {
        "version": _PUBLICATION_VERSION,
        "publication_sequence": publication.publication_sequence,
        "one_time": [
            json.loads(export_ratchet_prekey_binding(binding))
            for binding in publication.one_time
        ],
        "fallback": json.loads(
            export_ratchet_prekey_binding(publication.fallback)
        ),
    }
    serialized = json.dumps(document, sort_keys=True, separators=(",", ":"))
    if len(serialized.encode("utf-8")) > _MAX_PUBLICATION_BYTES:
        raise RatchetBindingError("pre-key publication exceeds the size limit")
    return serialized


def import_ratchet_prekey_publication(
    serialized: str,
) -> RatchetPreKeyPublication:
    """Parse a staged publication without trusting its signatures yet."""
    if len(serialized.encode("utf-8")) > _MAX_PUBLICATION_BYTES:
        raise RatchetBindingError("pre-key publication exceeds the size limit")
    try:
        parsed: object = json.loads(serialized)
    except json.JSONDecodeError as exc:
        raise RatchetBindingError(
            "pre-key publication must be valid JSON"
        ) from exc
    if not isinstance(parsed, dict):
        raise RatchetBindingError("pre-key publication must be a JSON object")

    document: dict[str, object] = {}
    for key, value in parsed.items():
        if not isinstance(key, str):
            raise RatchetBindingError(
                "pre-key publication field names must be text"
            )
        document[key] = value

    if set(document) != _PUBLICATION_FIELDS:
        raise RatchetBindingError(
            "pre-key publication fields do not match version 1"
        )
    if document["version"] != _PUBLICATION_VERSION:
        raise RatchetBindingError("unsupported pre-key publication version")

    sequence = document["publication_sequence"]
    if (
        not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence <= 0
        or sequence > _MAX_PUBLICATION_SEQUENCE
    ):
        raise RatchetBindingError(
            "publication_sequence is outside the supported range"
        )

    raw_one_time = document["one_time"]
    if (
        not isinstance(raw_one_time, list)
        or not raw_one_time
        or len(raw_one_time) > _MAX_ONE_TIME_BINDINGS
    ):
        raise RatchetBindingError(
            "publication one_time must contain between 1 and 256 entries"
        )

    one_time: list[SignedRatchetPreKeyBinding] = []
    for item in raw_one_time:
        if not isinstance(item, dict):
            raise RatchetBindingError(
                "publication one_time entries must be JSON objects"
            )
        one_time.append(
            import_ratchet_prekey_binding(
                json.dumps(item, sort_keys=True, separators=(",", ":"))
            )
        )

    raw_fallback = document["fallback"]
    if not isinstance(raw_fallback, dict):
        raise RatchetBindingError("publication fallback must be a JSON object")
    fallback = import_ratchet_prekey_binding(
        json.dumps(raw_fallback, sort_keys=True, separators=(",", ":"))
    )

    return RatchetPreKeyPublication(
        publication_sequence=sequence,
        one_time=tuple(one_time),
        fallback=fallback,
    )


def verify_local_ratchet_prekey_publication(
    publication: RatchetPreKeyPublication,
    device: EnrolledGhostDevice,
) -> None:
    """Verify every staged publication signature against the local enrolled device."""
    certificate = device.certificate.certificate
    if device.device_id != certificate.device_id:
        raise RatchetBindingError("enrolled device does not match its certificate")
    if bytes(device.device.signing_verify_key) != certificate.signing_public_key:
        raise RatchetBindingError(
            "device signing key does not match its certificate"
        )
    if (
        bytes(device.device.encryption_public_key)
        != certificate.encryption_public_key
    ):
        raise RatchetBindingError(
            "device encryption key does not match its certificate"
        )

    for signed in (*publication.one_time, publication.fallback):
        binding = signed.binding
        if binding.ghost_id != certificate.ghost_id:
            raise RatchetBindingError(
                "publication GhostID does not match local device"
            )
        if binding.device_id != certificate.device_id:
            raise RatchetBindingError(
                "publication DeviceID does not match local device"
            )
        try:
            device.device.signing_verify_key.verify(
                binding.canonical_bytes(),
                signed.device_signature,
            )
        except BadSignatureError as exc:
            raise RatchetBindingError(
                "publication contains an invalid device signature"
            ) from exc
