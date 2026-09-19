"""Local framed-RPC client for the GhostLink libsignal ratchet engine."""

from __future__ import annotations

import base64
import json
import math
import struct
import subprocess
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import IO, Self

from ghostlink.contact import ValidatedContact
from ghostlink.device import EnrolledGhostDevice
from ghostlink.ratchet_binding import (
    RatchetBindingError,
    RatchetPreKeyBinding,
    RatchetPreKeyMaterial,
    SignedRatchetPreKeyBinding,
    verify_ratchet_prekey_binding,
)
from ghostlink.ratchet_publication import (
    RatchetPreKeyPublication,
    create_ratchet_prekey_publication,
    export_ratchet_prekey_publication,
    import_ratchet_prekey_publication,
    verify_local_ratchet_prekey_publication,
)
from ghostlink.state_witness import (
    ComponentCheckpoint,
    MonotonicWitness,
    StateCheckpointError,
    StateWitnessError,
    WitnessRecord,
    derive_checkpoint,
    initialize_witness,
    reconcile_checkpoint,
)

_RPC_VERSION = 1
_MAX_FRAME_BYTES = 2 * 1024 * 1024
_DEFAULT_RPC_TIMEOUT_SECONDS = 10.0
_MAX_PAYLOAD_BYTES = 1024 * 1024
_SIGNAL_DEVICE_ID = 1
_MAX_REGISTRATION_ID = 16_380
_MAX_PREKEY_ID = 0x7FFF_FFFF
_EC_PUBLIC_KEY_BYTES = 33
_LIBSIGNAL_SIGNATURE_BYTES = 64
_MAX_KYBER_PUBLIC_KEY_BYTES = 4096
_MAX_PUBLICATION_SEQUENCE = (1 << 53) - 1
_MAX_ONE_TIME_PREKEYS = 256
_MAX_LIFETIME_SECONDS = 7 * 24 * 60 * 60
_MAX_PUBLICATION_BYTES = 1024 * 1024


class RatchetEngineError(RuntimeError):
    """Base class for local ratchet-engine failures."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


class RatchetEngineConnectionError(RatchetEngineError):
    """Raised when the local ratchet-engine process is unavailable."""


class RatchetEngineProtocolError(RatchetEngineError):
    """Raised when the local ratchet engine violates the RPC protocol."""


@dataclass(frozen=True, slots=True)
class RatchetCiphertext:
    """Opaque libsignal ciphertext returned by the local ratchet engine."""

    message_type: int
    ciphertext: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.message_type, int) or isinstance(
            self.message_type,
            bool,
        ):
            raise ValueError("message_type must be an integer")
        if self.message_type < 0:
            raise ValueError("message_type must be non-negative")
        if not self.ciphertext:
            raise ValueError("ciphertext must not be empty")
        if len(self.ciphertext) > _MAX_FRAME_BYTES:
            raise ValueError("ciphertext exceeds the RPC size limit")


@dataclass(frozen=True, slots=True)
class RatchetPreKeyGeneration:
    """Public material and lifecycle metadata for one prepared generation."""

    publication_sequence: int
    issued_at: int
    expires_at: int
    one_time: tuple[RatchetPreKeyMaterial, ...]
    fallback: RatchetPreKeyMaterial
    public_payload: str | None


@dataclass(frozen=True, slots=True)
class RatchetPreKeyGenerationStatus:
    """Non-secret lifecycle metadata for one pending or active generation."""

    publication_sequence: int
    issued_at: int
    expires_at: int
    published_at: int | None
    staged: bool


@dataclass(frozen=True, slots=True)
class RatchetPreKeyLifecycleStatus:
    """Non-secret ratchet pre-key lifecycle status used for maintenance."""

    publication_sequence: int
    pending: RatchetPreKeyGenerationStatus | None
    active: RatchetPreKeyGenerationStatus | None
    retired_count: int


@dataclass(frozen=True, slots=True)
class RatchetPreKeyGarbageCollectionResult:
    """Non-secret counts from one transactional retired pre-key GC pass."""

    retired_generations_removed: int
    pre_keys_removed: int
    signed_pre_keys_removed: int
    kyber_pre_keys_removed: int


def _require_mapping(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            f"{context} must be a JSON object",
        )

    document: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise RatchetEngineProtocolError(
                "PROTOCOL_ERROR",
                f"{context} contains a non-text field name",
            )
        document[key] = item
    return document


def _require_exact_fields(
    document: dict[str, object],
    expected: set[str],
    context: str,
) -> None:
    if set(document) != expected:
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            f"{context} fields do not match the RPC protocol",
        )


def _require_integer(
    document: dict[str, object],
    field: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    value = document.get(field)
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or (maximum is not None and value > maximum)
    ):
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            f"{field} is outside the supported integer range",
        )
    return value


def _decode_base64(
    value: object,
    field: str,
    *,
    exact_size: int | None = None,
    max_size: int | None = None,
    allow_empty: bool = False,
) -> bytes:
    if not isinstance(value, str):
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            f"{field} must be Base64 text",
        )
    if not allow_empty and not value:
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            f"{field} must not be empty",
        )

    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            f"{field} must be valid Base64",
        ) from exc

    if base64.b64encode(decoded).decode("ascii") != value:
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            f"{field} must use canonical Base64",
        )
    if exact_size is not None and len(decoded) != exact_size:
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            f"{field} has an invalid decoded length",
        )
    if max_size is not None and len(decoded) > max_size:
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            f"{field} exceeds the size limit",
        )
    return decoded


def _encode_base64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _require_lower_hex(
    value: object,
    field: str,
    *,
    byte_length: int,
) -> str:
    expected_length = byte_length * 2
    if (
        not isinstance(value, str)
        or len(value) != expected_length
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            f"{field} must be {byte_length}-byte lowercase hexadecimal",
        )
    return value


def _material_to_wire(binding: RatchetPreKeyBinding) -> dict[str, object]:
    return {
        "version": 1,
        "registration_id": binding.registration_id,
        "signal_device_id": binding.signal_device_id,
        "identity_key": _encode_base64(binding.identity_key),
        "pre_key_id": binding.pre_key_id,
        "pre_key": (
            None if binding.pre_key is None else _encode_base64(binding.pre_key)
        ),
        "signed_pre_key_id": binding.signed_pre_key_id,
        "signed_pre_key": _encode_base64(binding.signed_pre_key),
        "signed_pre_key_signature": _encode_base64(
            binding.signed_pre_key_signature,
        ),
        "kyber_pre_key_id": binding.kyber_pre_key_id,
        "kyber_pre_key": _encode_base64(binding.kyber_pre_key),
        "kyber_pre_key_signature": _encode_base64(
            binding.kyber_pre_key_signature,
        ),
    }


def _material_from_wire(value: object) -> RatchetPreKeyMaterial:
    document = _require_mapping(value, "pre-key material")
    expected = {
        "version",
        "registration_id",
        "signal_device_id",
        "identity_key",
        "pre_key_id",
        "pre_key",
        "signed_pre_key_id",
        "signed_pre_key",
        "signed_pre_key_signature",
        "kyber_pre_key_id",
        "kyber_pre_key",
        "kyber_pre_key_signature",
    }
    _require_exact_fields(document, expected, "pre-key material")

    if _require_integer(document, "version", minimum=1) != 1:
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            "unsupported pre-key material version",
        )
    if (
        _require_integer(document, "signal_device_id", minimum=1)
        != _SIGNAL_DEVICE_ID
    ):
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            "signal_device_id must equal 1",
        )

    registration_id = _require_integer(
        document,
        "registration_id",
        minimum=1,
        maximum=_MAX_REGISTRATION_ID,
    )

    raw_pre_key_id = document.get("pre_key_id")
    raw_pre_key = document.get("pre_key")
    if raw_pre_key_id is None and raw_pre_key is None:
        pre_key_id = None
        pre_key = None
    elif raw_pre_key_id is None or raw_pre_key is None:
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            "pre_key_id and pre_key must both be present or both be null",
        )
    else:
        if not isinstance(raw_pre_key_id, int) or isinstance(
            raw_pre_key_id,
            bool,
        ):
            raise RatchetEngineProtocolError(
                "PROTOCOL_ERROR",
                "pre_key_id must be an integer",
            )
        if raw_pre_key_id <= 0 or raw_pre_key_id > _MAX_PREKEY_ID:
            raise RatchetEngineProtocolError(
                "PROTOCOL_ERROR",
                "pre_key_id is outside the supported range",
            )
        pre_key_id = raw_pre_key_id
        pre_key = _decode_base64(
            raw_pre_key,
            "pre_key",
            exact_size=_EC_PUBLIC_KEY_BYTES,
        )

    return RatchetPreKeyMaterial(
        registration_id=registration_id,
        identity_key=_decode_base64(
            document["identity_key"],
            "identity_key",
            exact_size=_EC_PUBLIC_KEY_BYTES,
        ),
        pre_key_id=pre_key_id,
        pre_key=pre_key,
        signed_pre_key_id=_require_integer(
            document,
            "signed_pre_key_id",
            minimum=1,
            maximum=_MAX_PREKEY_ID,
        ),
        signed_pre_key=_decode_base64(
            document["signed_pre_key"],
            "signed_pre_key",
            exact_size=_EC_PUBLIC_KEY_BYTES,
        ),
        signed_pre_key_signature=_decode_base64(
            document["signed_pre_key_signature"],
            "signed_pre_key_signature",
            exact_size=_LIBSIGNAL_SIGNATURE_BYTES,
        ),
        kyber_pre_key_id=_require_integer(
            document,
            "kyber_pre_key_id",
            minimum=1,
            maximum=_MAX_PREKEY_ID,
        ),
        kyber_pre_key=_decode_base64(
            document["kyber_pre_key"],
            "kyber_pre_key",
            max_size=_MAX_KYBER_PUBLIC_KEY_BYTES,
        ),
        kyber_pre_key_signature=_decode_base64(
            document["kyber_pre_key_signature"],
            "kyber_pre_key_signature",
            exact_size=_LIBSIGNAL_SIGNATURE_BYTES,
        ),
    )


def _prekey_generation_from_wire(value: object) -> RatchetPreKeyGeneration:
    document = _require_mapping(value, "pre-key generation")
    _require_exact_fields(
        document,
        {
            "version",
            "publication_sequence",
            "issued_at",
            "expires_at",
            "one_time",
            "fallback",
            "public_payload",
        },
        "pre-key generation",
    )

    if _require_integer(document, "version", minimum=1) != 1:
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            "unsupported pre-key generation version",
        )

    sequence = _require_integer(
        document,
        "publication_sequence",
        minimum=1,
        maximum=_MAX_PUBLICATION_SEQUENCE,
    )
    issued_at = _require_integer(document, "issued_at", minimum=0)
    expires_at = _require_integer(document, "expires_at", minimum=0)
    if expires_at <= issued_at:
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            "pre-key generation expiration must follow issuance",
        )
    if expires_at - issued_at > _MAX_LIFETIME_SECONDS:
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            "pre-key generation lifetime exceeds seven days",
        )

    raw_one_time = document["one_time"]
    if (
        not isinstance(raw_one_time, list)
        or not raw_one_time
        or len(raw_one_time) > _MAX_ONE_TIME_PREKEYS
    ):
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            "one_time must contain between 1 and 256 entries",
        )
    one_time = tuple(_material_from_wire(item) for item in raw_one_time)
    fallback = _material_from_wire(document["fallback"])

    if fallback.pre_key_id is not None or fallback.pre_key is not None:
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            "fallback material must not contain an EC one-time pre-key",
        )

    reference = (
        fallback.registration_id,
        fallback.identity_key,
        fallback.signed_pre_key_id,
        fallback.signed_pre_key,
        fallback.signed_pre_key_signature,
    )
    pre_key_ids: set[int] = set()
    kyber_ids = {fallback.kyber_pre_key_id}

    for material in one_time:
        if material.pre_key_id is None or material.pre_key is None:
            raise RatchetEngineProtocolError(
                "PROTOCOL_ERROR",
                "one-time material is missing its EC pre-key",
            )
        current = (
            material.registration_id,
            material.identity_key,
            material.signed_pre_key_id,
            material.signed_pre_key,
            material.signed_pre_key_signature,
        )
        if current != reference:
            raise RatchetEngineProtocolError(
                "PROTOCOL_ERROR",
                "pre-key generation materials do not share signed identity data",
            )
        if material.pre_key_id in pre_key_ids:
            raise RatchetEngineProtocolError(
                "PROTOCOL_ERROR",
                "pre-key generation contains duplicate EC pre-key IDs",
            )
        if material.kyber_pre_key_id in kyber_ids:
            raise RatchetEngineProtocolError(
                "PROTOCOL_ERROR",
                "pre-key generation contains duplicate Kyber IDs",
            )
        pre_key_ids.add(material.pre_key_id)
        kyber_ids.add(material.kyber_pre_key_id)

    raw_payload = document["public_payload"]
    if raw_payload is not None:
        if (
            not isinstance(raw_payload, str)
            or not raw_payload
            or len(raw_payload.encode("utf-8")) > _MAX_PUBLICATION_BYTES
        ):
            raise RatchetEngineProtocolError(
                "PROTOCOL_ERROR",
                "public_payload is invalid or exceeds the size limit",
            )
        public_payload: str | None = raw_payload
    else:
        public_payload = None

    return RatchetPreKeyGeneration(
        publication_sequence=sequence,
        issued_at=issued_at,
        expires_at=expires_at,
        one_time=one_time,
        fallback=fallback,
        public_payload=public_payload,
    )


def _generation_status_from_wire(
    value: object,
    *,
    context: str,
    role: str,
) -> RatchetPreKeyGenerationStatus:
    document = _require_mapping(value, context)
    _require_exact_fields(
        document,
        {
            "publication_sequence",
            "issued_at",
            "expires_at",
            "published_at",
            "staged",
        },
        context,
    )
    sequence = _require_integer(
        document,
        "publication_sequence",
        minimum=1,
        maximum=_MAX_PUBLICATION_SEQUENCE,
    )
    issued_at = _require_integer(document, "issued_at", minimum=0)
    expires_at = _require_integer(document, "expires_at", minimum=0)
    if expires_at <= issued_at:
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            f"{context} expiration must follow issuance",
        )

    raw_published_at = document["published_at"]
    if raw_published_at is None:
        published_at: int | None = None
    else:
        if not isinstance(raw_published_at, int) or isinstance(
            raw_published_at,
            bool,
        ):
            raise RatchetEngineProtocolError(
                "PROTOCOL_ERROR",
                f"{context} published_at must be an integer or null",
            )
        if raw_published_at < 0:
            raise RatchetEngineProtocolError(
                "PROTOCOL_ERROR",
                f"{context} published_at is outside the supported range",
            )
        published_at = raw_published_at

    staged = document["staged"]
    if not isinstance(staged, bool):
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            f"{context} staged must be a boolean",
        )

    if role == "pending" and published_at is not None:
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            "pending pre-key lifecycle generation must not be published",
        )
    if role == "active":
        if published_at is None:
            raise RatchetEngineProtocolError(
                "PROTOCOL_ERROR",
                "active pre-key lifecycle generation must be published",
            )
        if not staged:
            raise RatchetEngineProtocolError(
                "PROTOCOL_ERROR",
                "active pre-key lifecycle generation must be staged",
            )

    return RatchetPreKeyGenerationStatus(
        publication_sequence=sequence,
        issued_at=issued_at,
        expires_at=expires_at,
        published_at=published_at,
        staged=staged,
    )


def _lifecycle_status_from_wire(value: object) -> RatchetPreKeyLifecycleStatus:
    document = _require_mapping(value, "pre-key lifecycle status")
    _require_exact_fields(
        document,
        {
            "version",
            "publication_sequence",
            "pending",
            "active",
            "retired_count",
        },
        "pre-key lifecycle status",
    )
    if _require_integer(document, "version", minimum=1) != 1:
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            "unsupported pre-key lifecycle status version",
        )
    publication_sequence = _require_integer(
        document,
        "publication_sequence",
        minimum=0,
        maximum=_MAX_PUBLICATION_SEQUENCE,
    )

    pending = (
        None
        if document["pending"] is None
        else _generation_status_from_wire(
            document["pending"],
            context="pending pre-key lifecycle generation",
            role="pending",
        )
    )
    active = (
        None
        if document["active"] is None
        else _generation_status_from_wire(
            document["active"],
            context="active pre-key lifecycle generation",
            role="active",
        )
    )
    retired_count = _require_integer(
        document,
        "retired_count",
        minimum=0,
        maximum=32,
    )

    if pending is not None and pending.publication_sequence != publication_sequence:
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            "pending sequence does not match lifecycle publication sequence",
        )
    if active is not None and active.publication_sequence > publication_sequence:
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            "active sequence exceeds lifecycle publication sequence",
        )
    if (
        pending is not None
        and active is not None
        and pending.publication_sequence <= active.publication_sequence
    ):
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            "pending sequence must be newer than active sequence",
        )

    return RatchetPreKeyLifecycleStatus(
        publication_sequence=publication_sequence,
        pending=pending,
        active=active,
        retired_count=retired_count,
    )


def _garbage_collection_result_from_wire(
    value: object,
) -> RatchetPreKeyGarbageCollectionResult:
    document = _require_mapping(value, "pre-key garbage collection result")
    _require_exact_fields(
        document,
        {
            "retired_generations_removed",
            "pre_keys_removed",
            "signed_pre_keys_removed",
            "kyber_pre_keys_removed",
        },
        "pre-key garbage collection result",
    )
    return RatchetPreKeyGarbageCollectionResult(
        retired_generations_removed=_require_integer(
            document,
            "retired_generations_removed",
            minimum=0,
            maximum=32,
        ),
        pre_keys_removed=_require_integer(
            document,
            "pre_keys_removed",
            minimum=0,
            maximum=32 * _MAX_ONE_TIME_PREKEYS,
        ),
        signed_pre_keys_removed=_require_integer(
            document,
            "signed_pre_keys_removed",
            minimum=0,
            maximum=32,
        ),
        kyber_pre_keys_removed=_require_integer(
            document,
            "kyber_pre_keys_removed",
            minimum=0,
            maximum=32 * (_MAX_ONE_TIME_PREKEYS + 1),
        ),
    )


def _binding_matches_material(
    binding: RatchetPreKeyBinding,
    material: RatchetPreKeyMaterial,
) -> bool:
    return (
        binding.registration_id == material.registration_id
        and binding.identity_key == material.identity_key
        and binding.pre_key_id == material.pre_key_id
        and binding.pre_key == material.pre_key
        and binding.signed_pre_key_id == material.signed_pre_key_id
        and binding.signed_pre_key == material.signed_pre_key
        and binding.signed_pre_key_signature
        == material.signed_pre_key_signature
        and binding.kyber_pre_key_id == material.kyber_pre_key_id
        and binding.kyber_pre_key == material.kyber_pre_key
        and binding.kyber_pre_key_signature
        == material.kyber_pre_key_signature
    )


def _verify_publication_matches_generation(
    publication: RatchetPreKeyPublication,
    generation: RatchetPreKeyGeneration,
) -> None:
    if publication.publication_sequence != generation.publication_sequence:
        raise RatchetBindingError(
            "staged publication sequence does not match pending generation"
        )
    if len(publication.one_time) != len(generation.one_time):
        raise RatchetBindingError(
            "staged publication one-time count does not match pending generation"
        )

    for signed, material in zip(
        publication.one_time,
        generation.one_time,
        strict=True,
    ):
        binding = signed.binding
        if (
            binding.issued_at != generation.issued_at
            or binding.expires_at != generation.expires_at
            or not _binding_matches_material(binding, material)
        ):
            raise RatchetBindingError(
                "staged one-time binding does not match pending generation"
            )

    fallback = publication.fallback.binding
    if (
        fallback.issued_at != generation.issued_at
        or fallback.expires_at != generation.expires_at
        or not _binding_matches_material(fallback, generation.fallback)
    ):
        raise RatchetBindingError(
            "staged fallback binding does not match pending generation"
        )


class RatchetEngineClient:
    """Own one local libsignal engine process for a GhostLink device."""

    def __init__(
        self,
        command: Sequence[str],
        local_device: EnrolledGhostDevice,
        vault_path: str | Path,
        master_key: bytes,
        *,
        state_id: str | None = None,
        coordination_key: bytes | None = None,
        witness: MonotonicWitness | None = None,
        allow_legacy_migration: bool = False,
        recovery_previous_checkpoint: WitnessRecord | None = None,
        rpc_timeout: float = _DEFAULT_RPC_TIMEOUT_SECONDS,
    ) -> None:
        if not command or any(not part for part in command):
            raise ValueError("command must contain non-empty arguments")
        if len(master_key) != 32:
            raise ValueError("master_key must contain exactly 32 bytes")
        if (
            not isinstance(rpc_timeout, int | float)
            or isinstance(rpc_timeout, bool)
            or not math.isfinite(rpc_timeout)
            or rpc_timeout <= 0
        ):
            raise ValueError("rpc_timeout must be a finite positive number")

        state_values = (state_id, coordination_key, witness)
        configured_count = sum(value is not None for value in state_values)
        if configured_count not in {0, 3}:
            raise ValueError(
                "state_id, coordination_key and witness must be configured together"
            )
        if state_id is not None:
            _require_lower_hex(state_id, "state_id", byte_length=16)
            if coordination_key is None or len(coordination_key) != 32:
                raise ValueError(
                    "coordination_key must contain exactly 32 bytes"
                )
        if allow_legacy_migration and state_id is None:
            raise ValueError(
                "legacy vault migration requires rollback-state coordination"
            )
        if recovery_previous_checkpoint is not None:
            if state_id is None or witness is None:
                raise ValueError(
                    "ratchet recovery requires rollback-state coordination"
                )
            if allow_legacy_migration:
                raise ValueError(
                    "ratchet recovery cannot be combined with legacy migration"
                )
            if recovery_previous_checkpoint.component != "ratchet":
                raise ValueError(
                    "ratchet recovery checkpoint must use component ratchet"
                )
            if recovery_previous_checkpoint.state_id != state_id:
                raise ValueError(
                    "ratchet recovery checkpoint belongs to another client state"
                )
            try:
                witnessed = witness.get("ratchet")
            except StateWitnessError as exc:
                raise RatchetEngineError(
                    "STATE_WITNESS",
                    f"unable to read ratchet witness: {exc}",
                ) from exc
            if (
                witnessed is None
                or witnessed.state_id != recovery_previous_checkpoint.state_id
                or witnessed.component != recovery_previous_checkpoint.component
                or witnessed.revision != recovery_previous_checkpoint.revision
                or witnessed.digest != recovery_previous_checkpoint.digest
            ):
                raise RatchetEngineError(
                    "STATE_WITNESS",
                    "ratchet recovery checkpoint is not the current witnessed state",
                )

        self._lock = threading.Lock()
        self._next_request_id = 1
        self._local_device = local_device
        self._closed = False
        self._vault_path = Path(vault_path)
        self._state_id = state_id
        self._coordination_key = coordination_key
        self._witness = witness
        self._vault_checkpoint: ComponentCheckpoint | None = None
        self._witness_pending = False
        self._rpc_timeout = float(rpc_timeout)

        if allow_legacy_migration and witness is not None:
            try:
                if witness.get("ratchet") is not None:
                    raise RatchetEngineError(
                        "STATE_WITNESS",
                        "ratchet witness already exists; legacy migration refused",
                    )
            except StateWitnessError as exc:
                raise RatchetEngineError(
                    "STATE_WITNESS",
                    f"unable to read ratchet witness: {exc}",
                ) from exc

        try:
            process = subprocess.Popen(  # noqa: S603
                list(command),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                bufsize=0,
                close_fds=True,
            )
        except OSError as exc:
            raise RatchetEngineConnectionError(
                "START_FAILED",
                "unable to start local ratchet engine",
            ) from exc

        if process.stdin is None or process.stdout is None:
            process.kill()
            raise RatchetEngineConnectionError(
                "START_FAILED",
                "ratchet engine pipes were not created",
            )

        self._process = process
        self._stdin: IO[bytes] = process.stdin
        self._stdout: IO[bytes] = process.stdout

        key_copy = bytearray(master_key)
        try:
            pong = self._request("ping", {})
            self._require_rpc_version(pong, "ping response")

            open_params: dict[str, object] = {
                "device_id": local_device.device_id,
                "vault_path": str(self._vault_path),
                "master_key": _encode_base64(bytes(key_copy)),
            }
            if state_id is not None:
                open_params["state_id"] = state_id
                open_params["allow_legacy_migration"] = allow_legacy_migration
                if recovery_previous_checkpoint is not None:
                    open_params["recovery_previous_revision"] = (
                        recovery_previous_checkpoint.revision
                    )
                    open_params["recovery_previous_digest"] = (
                        recovery_previous_checkpoint.digest
                    )

            opened = self._request("open", open_params)
            if state_id is None:
                self._require_rpc_version(opened, "open response")
            else:
                open_document = _require_mapping(opened, "open response")
                _require_exact_fields(
                    open_document,
                    {"rpc_version", "state_origin"},
                    "open response",
                )
                if (
                    _require_integer(
                        open_document,
                        "rpc_version",
                        minimum=1,
                    )
                    != _RPC_VERSION
                ):
                    raise RatchetEngineProtocolError(
                        "PROTOCOL_ERROR",
                        "unsupported ratchet RPC version",
                    )
                state_origin = open_document.get("state_origin")
                if state_origin not in {
                    "created",
                    "migrated",
                    "recovered",
                    "existing",
                }:
                    raise RatchetEngineProtocolError(
                        "PROTOCOL_ERROR",
                        "ratchet open response has invalid state_origin",
                    )
                self._sync_vault_witness(
                    allow_initialize=state_origin in {"created", "migrated"},
                )
        except Exception:
            self._terminate()
            raise
        finally:
            key_copy[:] = b"\x00" * len(key_copy)

    @property
    def local_device_id(self) -> str:
        """Return the DeviceID bound to this ratchet engine instance."""
        return self._local_device.device_id

    @property
    def process_id(self) -> int:
        """Return the child process ID for diagnostics/tests."""
        return self._process.pid

    def _require_rpc_version(self, value: object, context: str) -> None:
        document = _require_mapping(value, context)
        _require_exact_fields(document, {"rpc_version"}, context)
        if _require_integer(document, "rpc_version", minimum=1) != _RPC_VERSION:
            raise RatchetEngineProtocolError(
                "PROTOCOL_ERROR",
                "unsupported ratchet RPC version",
            )

    def _checkpoint_from_rpc(
        self,
        value: object,
    ) -> tuple[ComponentCheckpoint, bytes]:
        if self._state_id is None or self._coordination_key is None:
            raise RatchetEngineProtocolError(
                "PROTOCOL_ERROR",
                "ratchet state checkpoint is not configured",
            )

        document = _require_mapping(value, "state_checkpoint result")
        _require_exact_fields(
            document,
            {"state_id", "revision", "previous_digest"},
            "state_checkpoint result",
        )
        state_id = _require_lower_hex(
            document.get("state_id"),
            "state_id",
            byte_length=16,
        )
        if state_id != self._state_id:
            raise RatchetEngineProtocolError(
                "PROTOCOL_ERROR",
                "ratchet state checkpoint belongs to another client state",
            )
        revision = _require_integer(
            document,
            "revision",
            minimum=1,
            maximum=_MAX_PUBLICATION_SEQUENCE,
        )
        previous_value = document.get("previous_digest")
        if revision == 1:
            if previous_value is not None:
                raise RatchetEngineProtocolError(
                    "PROTOCOL_ERROR",
                    "initial ratchet checkpoint must not have a previous digest",
                )
            previous_digest = None
        else:
            previous_digest = _require_lower_hex(
                previous_value,
                "previous_digest",
                byte_length=32,
            )

        try:
            payload = self._vault_path.read_bytes()
        except OSError as exc:
            raise RatchetEngineError(
                "STATE_WITNESS",
                "unable to read ratchet vault for checkpoint verification",
            ) from exc

        try:
            checkpoint = derive_checkpoint(
                self._coordination_key,
                state_id=state_id,
                component="ratchet",
                revision=revision,
                previous_digest=previous_digest,
                payload=payload,
            )
        except StateCheckpointError as exc:
            raise RatchetEngineError(
                "STATE_WITNESS",
                f"unable to derive ratchet checkpoint: {exc}",
            ) from exc
        return checkpoint, payload

    def _sync_vault_witness(self, *, allow_initialize: bool) -> None:
        if self._state_id is None:
            return
        if self._coordination_key is None or self._witness is None:
            raise RatchetEngineError(
                "STATE_WITNESS",
                "ratchet witness coordination is incomplete",
            )

        checkpoint_value = self._request("state_checkpoint", {})
        checkpoint, payload = self._checkpoint_from_rpc(checkpoint_value)

        try:
            current = self._witness.get("ratchet")
            if current is None:
                if not allow_initialize:
                    raise RatchetEngineError(
                        "STATE_WITNESS",
                        "ratchet witness is missing for an existing rollback-aware vault",
                    )
                if checkpoint.revision != 1 or checkpoint.previous_digest is not None:
                    raise RatchetEngineError(
                        "STATE_WITNESS",
                        "ratchet witness initialization requires revision 1",
                    )
                initialize_witness(
                    self._witness,
                    checkpoint,
                    coordination_key=self._coordination_key,
                    payload=payload,
                )
            else:
                reconcile_checkpoint(
                    self._witness,
                    checkpoint,
                    coordination_key=self._coordination_key,
                    payload=payload,
                )
        except (StateCheckpointError, StateWitnessError) as exc:
            self._witness_pending = True
            raise RatchetEngineError(
                "STATE_WITNESS",
                f"ratchet rollback verification failed: {exc}",
            ) from exc

        acknowledged = _require_mapping(
            self._request(
                "acknowledge_checkpoint",
                {"digest": checkpoint.digest},
            ),
            "acknowledge_checkpoint result",
        )
        _require_exact_fields(
            acknowledged,
            {"acknowledged"},
            "acknowledge_checkpoint result",
        )
        if acknowledged.get("acknowledged") is not True:
            self._witness_pending = True
            raise RatchetEngineProtocolError(
                "PROTOCOL_ERROR",
                "ratchet checkpoint acknowledgement failed",
            )

        self._vault_checkpoint = checkpoint
        self._witness_pending = False

    def _mutating_request(self, method: str, params: object) -> object:
        if self._state_id is not None and self._witness_pending:
            raise RatchetEngineError(
                "STATE_WITNESS",
                "ratchet witness synchronization is pending; restart required",
            )

        result = self._request(method, params)
        if self._state_id is not None:
            try:
                self._sync_vault_witness(allow_initialize=False)
            except Exception:
                self._witness_pending = True
                raise
        return result

    def _read_exact(
        self,
        size: int,
        timed_out: threading.Event | None = None,
    ) -> bytes:
        chunks: list[bytes] = []
        remaining = size

        while remaining:
            chunk = self._stdout.read(remaining)
            if not chunk:
                if timed_out is not None and timed_out.is_set():
                    raise RatchetEngineConnectionError(
                        "ENGINE_TIMEOUT",
                        "ratchet engine RPC deadline expired",
                    )
                raise RatchetEngineConnectionError(
                    "ENGINE_CLOSED",
                    "ratchet engine closed its output unexpectedly",
                )
            chunks.append(chunk)
            remaining -= len(chunk)

        return b"".join(chunks)

    def _expire_rpc_request(self, timed_out: threading.Event) -> None:
        timed_out.set()
        try:
            if self._process.poll() is None:
                self._process.kill()
        except OSError:
            pass

    def _request(self, method: str, params: object) -> object:
        with self._lock:
            if self._closed:
                raise RatchetEngineConnectionError(
                    "ENGINE_CLOSED",
                    "ratchet engine client is closed",
                )
            if self._process.poll() is not None:
                raise RatchetEngineConnectionError(
                    "ENGINE_EXITED",
                    "ratchet engine process is not running",
                )

            request_id = self._next_request_id
            self._next_request_id += 1

            payload = json.dumps(
                {
                    "id": request_id,
                    "method": method,
                    "params": params,
                },
                separators=(",", ":"),
            ).encode("utf-8")

            if not payload or len(payload) > _MAX_FRAME_BYTES:
                raise RatchetEngineProtocolError(
                    "FRAME_TOO_LARGE",
                    "ratchet RPC request exceeds the frame limit",
                )

            timed_out = threading.Event()
            timer = threading.Timer(
                self._rpc_timeout,
                self._expire_rpc_request,
                args=(timed_out,),
            )
            timer.daemon = True
            timer.start()
            try:
                try:
                    self._stdin.write(struct.pack(">I", len(payload)))
                    self._stdin.write(payload)
                    self._stdin.flush()
                    length = struct.unpack(">I", self._read_exact(4, timed_out))[0]
                    if length == 0 or length > _MAX_FRAME_BYTES:
                        raise RatchetEngineProtocolError(
                            "PROTOCOL_ERROR",
                            "ratchet RPC response frame length is invalid",
                        )
                    raw_response = self._read_exact(length, timed_out)
                except (BrokenPipeError, OSError) as exc:
                    if timed_out.is_set():
                        raise RatchetEngineConnectionError(
                            "ENGINE_TIMEOUT",
                            "ratchet engine RPC deadline expired",
                        ) from exc
                    raise RatchetEngineConnectionError(
                        "ENGINE_IO",
                        "ratchet engine pipe failed",
                    ) from exc

                try:
                    parsed: object = json.loads(raw_response.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise RatchetEngineProtocolError(
                        "PROTOCOL_ERROR",
                        "ratchet RPC response is not valid UTF-8 JSON",
                    ) from exc

                response = _require_mapping(parsed, "RPC response")
                if response.get("id") != request_id:
                    raise RatchetEngineProtocolError(
                        "PROTOCOL_ERROR",
                        "ratchet RPC response id does not match request",
                    )

                ok = response.get("ok")
                if ok is True:
                    _require_exact_fields(
                        response,
                        {"id", "ok", "result"},
                        "successful RPC response",
                    )
                    return response["result"]

                if ok is False:
                    _require_exact_fields(
                        response,
                        {"id", "ok", "error"},
                        "failed RPC response",
                    )
                    error = _require_mapping(response["error"], "RPC error")
                    _require_exact_fields(error, {"code", "message"}, "RPC error")
                    code = error.get("code")
                    message = error.get("message")
                    if (
                        not isinstance(code, str)
                        or not code
                        or not isinstance(message, str)
                        or not message
                    ):
                        raise RatchetEngineProtocolError(
                            "PROTOCOL_ERROR",
                            "ratchet RPC error fields are invalid",
                        )
                    raise RatchetEngineError(code, message)

                raise RatchetEngineProtocolError(
                    "PROTOCOL_ERROR",
                    "ratchet RPC response has an invalid ok field",
                )
            finally:
                timer.cancel()
                timer.join()
                if timed_out.is_set():
                    self._terminate()
                    raise RatchetEngineConnectionError(
                        "ENGINE_TIMEOUT",
                        "ratchet engine RPC deadline expired",
                    )

    def create_prekey_material(self) -> RatchetPreKeyMaterial:
        """Generate and persist fresh public pre-key material."""
        return _material_from_wire(
            self._mutating_request("create_prekey_material", {}),
        )

    def prepare_prekey_generation(
        self,
        *,
        one_time_count: int = 100,
        issued_at: int | None = None,
        lifetime_seconds: int = _MAX_LIFETIME_SECONDS,
    ) -> RatchetPreKeyGeneration:
        """Atomically prepare and persist one pending pre-key generation."""
        now = int(time.time()) if issued_at is None else issued_at
        return _prekey_generation_from_wire(
            self._mutating_request(
                "prepare_prekey_generation",
                {
                    "one_time_count": one_time_count,
                    "issued_at": now,
                    "lifetime_seconds": lifetime_seconds,
                },
            )
        )

    def get_pending_prekey_generation(
        self,
    ) -> RatchetPreKeyGeneration | None:
        """Recover the pending generation and staged payload after restart."""
        result = self._request("get_pending_prekey_generation", {})
        if result is None:
            return None
        return _prekey_generation_from_wire(result)

    def get_prekey_lifecycle_status(
        self,
    ) -> RatchetPreKeyLifecycleStatus:
        """Return non-secret local lifecycle metadata for maintenance decisions."""
        return _lifecycle_status_from_wire(
            self._request("get_prekey_lifecycle_status", {})
        )

    def garbage_collect_prekeys(
        self,
        *,
        now: int | None = None,
    ) -> RatchetPreKeyGarbageCollectionResult:
        """Remove retired pre-key material only after the retention window."""
        current_time = int(time.time()) if now is None else now
        return _garbage_collection_result_from_wire(
            self._mutating_request(
                "garbage_collect_prekeys",
                {"now": current_time},
            )
        )

    def stage_prekey_publication(
        self,
        publication_sequence: int,
        public_payload: str,
    ) -> None:
        """Persist the exact signed public payload before any relay publication."""
        if not public_payload:
            raise ValueError("public_payload must not be empty")
        if len(public_payload.encode("utf-8")) > _MAX_PUBLICATION_BYTES:
            raise ValueError("public_payload exceeds the 1 MiB limit")
        self._mutating_request(
            "stage_prekey_publication",
            {
                "publication_sequence": publication_sequence,
                "public_payload": public_payload,
            },
        )

    def prepare_prekey_publication(
        self,
        *,
        one_time_count: int = 100,
        issued_at: int | None = None,
        lifetime_seconds: int = _MAX_LIFETIME_SECONDS,
    ) -> str:
        """Return one durable, locally verified signed publication payload."""
        generation = self.get_pending_prekey_generation()
        if generation is None:
            generation = self.prepare_prekey_generation(
                one_time_count=one_time_count,
                issued_at=issued_at,
                lifetime_seconds=lifetime_seconds,
            )

        if generation.public_payload is not None:
            publication = import_ratchet_prekey_publication(
                generation.public_payload
            )
            verify_local_ratchet_prekey_publication(
                publication,
                self._local_device,
            )
            _verify_publication_matches_generation(publication, generation)
            return generation.public_payload

        publication = create_ratchet_prekey_publication(
            self._local_device,
            publication_sequence=generation.publication_sequence,
            issued_at=generation.issued_at,
            expires_at=generation.expires_at,
            one_time_material=generation.one_time,
            fallback_material=generation.fallback,
        )
        payload = export_ratchet_prekey_publication(publication)
        self.stage_prekey_publication(
            generation.publication_sequence,
            payload,
        )
        return payload

    def commit_prekey_publication(
        self,
        publication_sequence: int,
        *,
        published_at: int | None = None,
    ) -> None:
        """Commit a relay-acknowledged pending generation as active."""
        acknowledged_at = int(time.time()) if published_at is None else published_at
        self._mutating_request(
            "commit_prekey_publication",
            {
                "publication_sequence": publication_sequence,
                "published_at": acknowledged_at,
            },
        )

    def has_session(self, contact: ValidatedContact) -> bool:
        """Return whether a persistent libsignal session already exists."""
        result = _require_mapping(
            self._request(
                "has_session",
                {"remote_device_id": contact.device_id},
            ),
            "has_session result",
        )
        _require_exact_fields(result, {"exists"}, "has_session result")
        exists = result.get("exists")
        if not isinstance(exists, bool):
            raise RatchetEngineProtocolError(
                "PROTOCOL_ERROR",
                "has_session exists must be a boolean",
            )
        return exists

    def invalidate_session(self, contact: ValidatedContact) -> bool:
        """Remove persisted ratchet state bound to a superseded remote DeviceID."""
        result = _require_mapping(
            self._mutating_request(
                "invalidate_session",
                {"remote_device_id": contact.device_id},
            ),
            "invalidate_session result",
        )
        _require_exact_fields(
            result,
            {"invalidated"},
            "invalidate_session result",
        )
        invalidated = result.get("invalidated")
        if not isinstance(invalidated, bool):
            raise RatchetEngineProtocolError(
                "PROTOCOL_ERROR",
                "invalidate_session invalidated must be a boolean",
            )
        return invalidated

    def establish_session(
        self,
        signed_binding: SignedRatchetPreKeyBinding,
        contact: ValidatedContact,
        *,
        now: int | None = None,
    ) -> None:
        """Verify a GhostLink binding before creating a libsignal session."""
        binding = verify_ratchet_prekey_binding(
            signed_binding,
            contact,
            now=now,
        )
        self._mutating_request(
            "establish_session",
            {
                "remote_device_id": contact.device_id,
                "publication_sequence": binding.publication_sequence,
                "material": _material_to_wire(binding),
            },
        )

    def encrypt(
        self,
        contact: ValidatedContact,
        plaintext: bytes,
    ) -> RatchetCiphertext:
        """Encrypt arbitrary bytes for one already verified contact device."""
        if len(plaintext) > _MAX_PAYLOAD_BYTES:
            raise ValueError("plaintext exceeds the 1 MiB engine limit")

        result = _require_mapping(
            self._mutating_request(
                "encrypt",
                {
                    "remote_device_id": contact.device_id,
                    "plaintext": _encode_base64(plaintext),
                },
            ),
            "encrypt result",
        )
        _require_exact_fields(
            result,
            {"message_type", "ciphertext"},
            "encrypt result",
        )
        return RatchetCiphertext(
            message_type=_require_integer(
                result,
                "message_type",
                minimum=0,
            ),
            ciphertext=_decode_base64(
                result["ciphertext"],
                "ciphertext",
                max_size=_MAX_FRAME_BYTES,
            ),
        )

    def decrypt(
        self,
        contact: ValidatedContact,
        message: RatchetCiphertext,
    ) -> bytes:
        """Decrypt one libsignal ciphertext from a verified contact device."""
        result = _require_mapping(
            self._mutating_request(
                "decrypt",
                {
                    "remote_device_id": contact.device_id,
                    "message_type": message.message_type,
                    "ciphertext": _encode_base64(message.ciphertext),
                },
            ),
            "decrypt result",
        )
        _require_exact_fields(result, {"plaintext"}, "decrypt result")
        return _decode_base64(
            result["plaintext"],
            "plaintext",
            max_size=_MAX_PAYLOAD_BYTES,
            allow_empty=True,
        )

    def decrypt_context_bound(
        self,
        contact: ValidatedContact,
        message: RatchetCiphertext,
        expected_context: bytes,
    ) -> bytes:
        """Decrypt only if the authenticated plaintext starts with expected_context."""
        if not expected_context:
            raise ValueError("expected_context must not be empty")
        if len(expected_context) > 4096:
            raise ValueError("expected_context exceeds the 4096-byte limit")

        result = _require_mapping(
            self._mutating_request(
                "decrypt_context_bound",
                {
                    "remote_device_id": contact.device_id,
                    "message_type": message.message_type,
                    "ciphertext": _encode_base64(message.ciphertext),
                    "expected_context": _encode_base64(expected_context),
                },
            ),
            "decrypt_context_bound result",
        )
        _require_exact_fields(
            result,
            {"plaintext"},
            "decrypt_context_bound result",
        )
        return _decode_base64(
            result["plaintext"],
            "plaintext",
            max_size=_MAX_PAYLOAD_BYTES,
            allow_empty=True,
        )

    def close(self) -> None:
        """Close the vault, erase the engine key buffer, and stop the child."""
        if self._closed:
            return

        try:
            if self._process.poll() is None:
                self._request("close", {})
        finally:
            self._closed = True
            try:
                self._stdin.close()
            except OSError:
                pass
            try:
                self._stdout.close()
            except OSError:
                pass
            if self._process.poll() is None:
                try:
                    self._process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    self._process.wait(timeout=5)

    def _terminate(self) -> None:
        self._closed = True
        try:
            self._stdin.close()
        except OSError:
            pass
        try:
            self._stdout.close()
        except OSError:
            pass
        if self._process.poll() is None:
            self._process.kill()
            self._process.wait(timeout=5)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
