"""Authenticated local persistence for human contact trust decisions."""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import os
import secrets
import tempfile
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from nacl.exceptions import CryptoError
from nacl.secret import SecretBox

from ghostlink.contact import (
    ContactBundleError,
    ValidatedContact,
    import_contact_bundle,
)
from ghostlink.identity import derive_identity_fingerprint
from ghostlink.state_witness import (
    ComponentCheckpoint,
    MonotonicWitness,
    StateCheckpointError,
    StateWitnessError,
    advance_checkpoint,
    create_initial_checkpoint,
    derive_checkpoint,
    initialize_witness,
    reconcile_checkpoint,
    witness_record,
)

_LEGACY_STORE_VERSION = 1
_STORE_VERSION = 2
_CIPHER_NAME = "secretbox"
_MAX_STORE_BYTES = 4 * 1024 * 1024
_MAX_RECORDS = 1_024
_MAX_LABEL_BYTES = 256
_RECORD_ID_BYTES = 16
_RECORD_ID_HEX_LENGTH = _RECORD_ID_BYTES * 2
_OUTER_FIELDS = {"version", "cipher", "ciphertext"}
_LEGACY_PAYLOAD_FIELDS = {"version", "records"}
_PAYLOAD_FIELDS = {
    "version",
    "state_id",
    "revision",
    "previous_digest",
    "records",
}
_RECORD_FIELDS = {
    "record_id",
    "label",
    "state",
    "current_bundle",
    "pinned_ghost_id",
    "candidate_bundle",
}


class ContactTrustError(ValueError):
    """Raised when local contact trust state cannot be used safely."""


def _require_monotonic_lifecycle_update(
    current: ValidatedContact,
    candidate: ValidatedContact,
    *,
    current_bundle: str,
    candidate_bundle: str,
) -> bool:
    """Reject lifecycle rollback/downgrade and report idempotent updates."""
    if current.ghost_id != candidate.ghost_id:
        return False
    current_epoch = current.lifecycle_epoch
    if current_epoch is None:
        return False
    candidate_epoch = candidate.lifecycle_epoch
    if candidate_epoch is None:
        raise ContactTrustError(
            "lifecycle-aware contact cannot downgrade to a legacy device bundle"
        )
    if candidate_epoch < current_epoch:
        raise ContactTrustError("contact device lifecycle rollback rejected")
    if candidate_epoch == current_epoch:
        if candidate_bundle != current_bundle:
            raise ContactTrustError("contact device lifecycle equivocation rejected")
        return True
    return False


class ContactTrustState(StrEnum):
    """Human trust state for one locally saved contact."""

    IMPORTED = "imported"
    VERIFIED = "verified"
    CHANGED = "changed"


@dataclass(frozen=True, slots=True)
class ContactTrustRecord:
    """One validated contact plus its local human-trust decision."""

    record_id: str
    label: str
    state: ContactTrustState
    current_bundle: str
    pinned_ghost_id: str | None
    candidate_bundle: str | None

    @property
    def current_contact(self) -> ValidatedContact:
        """Return the cryptographically validated current public contact."""
        return _validated_bundle(self.current_bundle)[1]

    @property
    def candidate_contact(self) -> ValidatedContact | None:
        """Return the staged replacement identity, when one exists."""
        if self.candidate_bundle is None:
            return None
        return _validated_bundle(self.candidate_bundle)[1]


@dataclass(slots=True)
class ContactTrustStore:
    """In-memory view of the authenticated local contact trust store."""

    records: dict[str, ContactTrustRecord] = field(default_factory=dict)
    state_id: str | None = None
    revision: int | None = None
    previous_digest: str | None = None
    checkpoint_digest: str | None = field(default=None, repr=False)

    def list_records(self) -> tuple[ContactTrustRecord, ...]:
        """Return records in a stable display order."""
        return tuple(
            sorted(
                self.records.values(),
                key=lambda record: (record.label.casefold(), record.record_id),
            )
        )

    def get(self, record_id: str) -> ContactTrustRecord:
        """Return one record or fail closed for an unknown local identifier."""
        try:
            return self.records[record_id]
        except KeyError as exc:
            raise ContactTrustError("unknown contact record") from exc

    def add_contact(
        self,
        label: str,
        bundle: str,
        *,
        record_id: str | None = None,
    ) -> ContactTrustRecord:
        """Save a cryptographically valid bundle as human-unverified."""
        validated_label = _validate_label(label)
        canonical_bundle, _contact = _validated_bundle(bundle)
        identifier = _new_record_id(self.records) if record_id is None else record_id
        _validate_record_id(identifier)
        if identifier in self.records:
            raise ContactTrustError("contact record already exists")

        record = ContactTrustRecord(
            record_id=identifier,
            label=validated_label,
            state=ContactTrustState.IMPORTED,
            current_bundle=canonical_bundle,
            pinned_ghost_id=None,
            candidate_bundle=None,
        )
        self.records[identifier] = record
        return record

    def update_contact_bundle(
        self,
        record_id: str,
        bundle: str,
    ) -> ContactTrustRecord:
        """Apply new valid public material without silently changing pinned identity."""
        record = self.get(record_id)
        canonical_bundle, contact = _validated_bundle(bundle)

        if record.state is ContactTrustState.CHANGED:
            raise ContactTrustError(
                "contact identity change requires explicit verification or rejection"
            )

        if record.state is ContactTrustState.IMPORTED:
            if _require_monotonic_lifecycle_update(
                record.current_contact,
                contact,
                current_bundle=record.current_bundle,
                candidate_bundle=canonical_bundle,
            ):
                return record
            updated = ContactTrustRecord(
                record_id=record.record_id,
                label=record.label,
                state=ContactTrustState.IMPORTED,
                current_bundle=canonical_bundle,
                pinned_ghost_id=None,
                candidate_bundle=None,
            )
            self.records[record_id] = updated
            return updated

        if record.pinned_ghost_id is None:
            raise ContactTrustError("verified contact is missing its pinned identity")

        if contact.ghost_id == record.pinned_ghost_id:
            if _require_monotonic_lifecycle_update(
                record.current_contact,
                contact,
                current_bundle=record.current_bundle,
                candidate_bundle=canonical_bundle,
            ):
                return record
            updated = ContactTrustRecord(
                record_id=record.record_id,
                label=record.label,
                state=ContactTrustState.VERIFIED,
                current_bundle=canonical_bundle,
                pinned_ghost_id=record.pinned_ghost_id,
                candidate_bundle=None,
            )
        else:
            updated = ContactTrustRecord(
                record_id=record.record_id,
                label=record.label,
                state=ContactTrustState.CHANGED,
                current_bundle=record.current_bundle,
                pinned_ghost_id=record.pinned_ghost_id,
                candidate_bundle=canonical_bundle,
            )

        self.records[record_id] = updated
        return updated

    def verify_identity(
        self,
        record_id: str,
        fingerprint: str,
    ) -> ContactTrustRecord:
        """Record explicit successful comparison of the complete Fingerprint v2."""
        record = self.get(record_id)

        if record.state is ContactTrustState.CHANGED:
            candidate = record.candidate_contact
            if candidate is None:
                raise ContactTrustError("changed contact is missing its candidate")
            target_contact = candidate
            target_bundle = record.candidate_bundle
        else:
            target_contact = record.current_contact
            target_bundle = record.current_bundle

        if target_bundle is None:
            raise ContactTrustError("contact verification target is unavailable")

        expected = derive_identity_fingerprint(bytes(target_contact.identity_verify_key))
        if not isinstance(fingerprint, str) or not hmac.compare_digest(
            fingerprint,
            expected,
        ):
            raise ContactTrustError("fingerprint does not match contact identity")

        updated = ContactTrustRecord(
            record_id=record.record_id,
            label=record.label,
            state=ContactTrustState.VERIFIED,
            current_bundle=target_bundle,
            pinned_ghost_id=target_contact.ghost_id,
            candidate_bundle=None,
        )
        self.records[record_id] = updated
        return updated

    def reject_identity_change(self, record_id: str) -> ContactTrustRecord:
        """Discard a staged replacement and restore the previously pinned identity."""
        record = self.get(record_id)
        if record.state is not ContactTrustState.CHANGED:
            raise ContactTrustError("contact has no identity change to reject")
        if record.pinned_ghost_id is None:
            raise ContactTrustError("changed contact is missing its pinned identity")

        updated = ContactTrustRecord(
            record_id=record.record_id,
            label=record.label,
            state=ContactTrustState.VERIFIED,
            current_bundle=record.current_bundle,
            pinned_ghost_id=record.pinned_ghost_id,
            candidate_bundle=None,
        )
        self.records[record_id] = updated
        return updated

    def require_verified_contact(self, record_id: str) -> ValidatedContact:
        """Return a contact only after a local human-verification decision."""
        record = self.get(record_id)
        if record.state is ContactTrustState.IMPORTED:
            raise ContactTrustError("contact identity has not been human-verified")
        if record.state is ContactTrustState.CHANGED:
            raise ContactTrustError("contact identity changed and requires re-verification")
        if record.pinned_ghost_id is None:
            raise ContactTrustError("verified contact is missing its pinned identity")

        contact = record.current_contact
        if contact.ghost_id != record.pinned_ghost_id:
            raise ContactTrustError("verified contact no longer matches pinned identity")
        return contact


def _validate_key(key: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) != SecretBox.KEY_SIZE:
        raise ContactTrustError("contact store key must contain exactly 32 bytes")
    return key


def _validate_record_id(record_id: str) -> str:
    if (
        not isinstance(record_id, str)
        or len(record_id) != _RECORD_ID_HEX_LENGTH
        or any(character not in "0123456789abcdef" for character in record_id)
    ):
        raise ContactTrustError("contact record ID must be 128-bit lowercase hex")
    return record_id


def _validate_label(label: str) -> str:
    if not isinstance(label, str) or not label or label != label.strip():
        raise ContactTrustError("contact label must be non-empty trimmed text")
    if len(label.encode("utf-8")) > _MAX_LABEL_BYTES:
        raise ContactTrustError("contact label is too large")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in label):
        raise ContactTrustError("contact label contains control characters")
    return label


def _new_record_id(records: dict[str, ContactTrustRecord]) -> str:
    while True:
        record_id = secrets.token_hex(_RECORD_ID_BYTES)
        if record_id not in records:
            return record_id


def _validated_bundle(serialized: str) -> tuple[str, ValidatedContact]:
    if not isinstance(serialized, str):
        raise ContactTrustError("contact bundle must be text")
    try:
        contact = import_contact_bundle(serialized)
    except ContactBundleError as exc:
        raise ContactTrustError("contact bundle is cryptographically invalid") from exc

    parsed: object = json.loads(serialized)
    canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
    return canonical, contact


def _require_mapping(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ContactTrustError(f"{context} must be a JSON object")
    document: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ContactTrustError(f"{context} field names must be text")
        document[key] = item
    return document


def _require_exact_fields(
    document: dict[str, object],
    expected: set[str],
    context: str,
) -> None:
    if set(document) != expected:
        raise ContactTrustError(f"{context} fields do not match the supported format")


def _require_text(
    document: dict[str, object],
    field_name: str,
    context: str,
) -> str:
    value = document.get(field_name)
    if not isinstance(value, str):
        raise ContactTrustError(f"{context} {field_name} must be text")
    return value


def _require_optional_text(
    document: dict[str, object],
    field_name: str,
    context: str,
) -> str | None:
    value = document.get(field_name)
    if value is not None and not isinstance(value, str):
        raise ContactTrustError(f"{context} {field_name} must be text or null")
    return value


def _record_from_document(value: object) -> ContactTrustRecord:
    document = _require_mapping(value, "contact record")
    _require_exact_fields(document, _RECORD_FIELDS, "contact record")

    record_id = _validate_record_id(
        _require_text(document, "record_id", "contact record")
    )
    label = _validate_label(_require_text(document, "label", "contact record"))
    raw_state = _require_text(document, "state", "contact record")
    try:
        state = ContactTrustState(raw_state)
    except ValueError as exc:
        raise ContactTrustError("contact record has unsupported trust state") from exc

    raw_current = _require_text(document, "current_bundle", "contact record")
    current_bundle, current_contact = _validated_bundle(raw_current)
    if current_bundle != raw_current:
        raise ContactTrustError("contact record current bundle is not canonical")

    pinned_ghost_id = _require_optional_text(
        document,
        "pinned_ghost_id",
        "contact record",
    )
    raw_candidate = _require_optional_text(
        document,
        "candidate_bundle",
        "contact record",
    )

    if state is ContactTrustState.IMPORTED:
        if pinned_ghost_id is not None or raw_candidate is not None:
            raise ContactTrustError("imported contact has invalid trust metadata")
        candidate_bundle = None
    elif state is ContactTrustState.VERIFIED:
        if pinned_ghost_id != current_contact.ghost_id or raw_candidate is not None:
            raise ContactTrustError("verified contact does not match pinned identity")
        candidate_bundle = None
    else:
        if pinned_ghost_id != current_contact.ghost_id or raw_candidate is None:
            raise ContactTrustError("changed contact has invalid pinned identity")
        candidate_bundle, candidate_contact = _validated_bundle(raw_candidate)
        if candidate_bundle != raw_candidate:
            raise ContactTrustError("contact record candidate bundle is not canonical")
        if candidate_contact.ghost_id == pinned_ghost_id:
            raise ContactTrustError("changed contact candidate matches pinned identity")

    return ContactTrustRecord(
        record_id=record_id,
        label=label,
        state=state,
        current_bundle=current_bundle,
        pinned_ghost_id=pinned_ghost_id,
        candidate_bundle=candidate_bundle,
    )


def _record_to_document(record: ContactTrustRecord) -> dict[str, object]:
    validated = _record_from_document(
        {
            "record_id": record.record_id,
            "label": record.label,
            "state": record.state.value,
            "current_bundle": record.current_bundle,
            "pinned_ghost_id": record.pinned_ghost_id,
            "candidate_bundle": record.candidate_bundle,
        }
    )
    return {
        "record_id": validated.record_id,
        "label": validated.label,
        "state": validated.state.value,
        "current_bundle": validated.current_bundle,
        "pinned_ghost_id": validated.pinned_ghost_id,
        "candidate_bundle": validated.candidate_bundle,
    }


def _validate_state_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 32
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ContactTrustError(
            "contact store state_id must be 128-bit lowercase hexadecimal"
        )
    return value


def _validate_revision(value: object) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
        or value > (1 << 53) - 1
    ):
        raise ContactTrustError(
            "contact store revision must be a positive JSON-safe integer"
        )
    return value


def _validate_previous_digest(value: object, *, revision: int) -> str | None:
    if revision == 1:
        if value is not None:
            raise ContactTrustError(
                "initial contact store must not have a previous digest"
            )
        return None
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ContactTrustError(
            "contact store previous_digest must be 32-byte lowercase hexadecimal"
        )
    return value


def _records_document(store: ContactTrustStore) -> list[dict[str, object]]:
    if len(store.records) > _MAX_RECORDS:
        raise ContactTrustError("contact store contains too many records")
    return [
        _record_to_document(store.records[record_id])
        for record_id in sorted(store.records)
    ]


def _serialize_contact_payload(store: ContactTrustStore) -> bytes:
    records = _records_document(store)
    if store.state_id is None and store.revision is None and store.previous_digest is None:
        payload: dict[str, object] = {
            "version": _LEGACY_STORE_VERSION,
            "records": records,
        }
    else:
        if store.state_id is None or store.revision is None:
            raise ContactTrustError(
                "contact store rollback metadata is only partially present"
            )
        state_id = _validate_state_id(store.state_id)
        revision = _validate_revision(store.revision)
        previous_digest = _validate_previous_digest(
            store.previous_digest,
            revision=revision,
        )
        payload = {
            "version": _STORE_VERSION,
            "state_id": state_id,
            "revision": revision,
            "previous_digest": previous_digest,
            "records": records,
        }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def encrypt_contact_store(store: ContactTrustStore, key: bytes) -> str:
    """Serialize and authenticate-encrypt local trust state."""
    _validate_key(key)
    payload = _serialize_contact_payload(store)
    payload_version = json.loads(payload.decode("utf-8"))["version"]
    ciphertext = bytes(SecretBox(key).encrypt(payload))
    document = json.dumps(
        {
            "version": payload_version,
            "cipher": _CIPHER_NAME,
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    if len(document.encode("utf-8")) > _MAX_STORE_BYTES:
        raise ContactTrustError("encrypted contact store is too large")
    return document


def decrypt_contact_store(serialized: str, key: bytes) -> ContactTrustStore:
    """Decrypt, authenticate, and strictly validate local trust state."""
    _validate_key(key)
    if not isinstance(serialized, str):
        raise ContactTrustError("contact store must be text")
    if len(serialized.encode("utf-8")) > _MAX_STORE_BYTES:
        raise ContactTrustError("encrypted contact store is too large")

    try:
        parsed: object = json.loads(serialized)
    except json.JSONDecodeError as exc:
        raise ContactTrustError("contact store must be valid JSON") from exc
    outer = _require_mapping(parsed, "contact store")
    _require_exact_fields(outer, _OUTER_FIELDS, "contact store")

    version = outer.get("version")
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version not in {_LEGACY_STORE_VERSION, _STORE_VERSION}
    ):
        raise ContactTrustError("unsupported contact store version")
    if outer.get("cipher") != _CIPHER_NAME:
        raise ContactTrustError("unsupported contact store cipher")

    encoded = outer.get("ciphertext")
    if not isinstance(encoded, str) or not encoded:
        raise ContactTrustError("contact store ciphertext must be Base64 text")
    try:
        ciphertext = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ContactTrustError("contact store ciphertext must be valid Base64") from exc

    try:
        plaintext = SecretBox(key).decrypt(ciphertext)
    except CryptoError as exc:
        raise ContactTrustError(
            "contact store key is incorrect or store data was modified"
        ) from exc

    try:
        payload_value: object = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContactTrustError("decrypted contact store must be valid UTF-8 JSON") from exc
    payload = _require_mapping(payload_value, "contact store payload")

    payload_version = payload.get("version")
    if payload_version != version:
        raise ContactTrustError("contact store outer/payload versions disagree")

    if version == _LEGACY_STORE_VERSION:
        _require_exact_fields(
            payload,
            _LEGACY_PAYLOAD_FIELDS,
            "contact store payload",
        )
        state_id = None
        revision = None
        previous_digest = None
    else:
        _require_exact_fields(payload, _PAYLOAD_FIELDS, "contact store payload")
        state_id = _validate_state_id(payload.get("state_id"))
        revision = _validate_revision(payload.get("revision"))
        previous_digest = _validate_previous_digest(
            payload.get("previous_digest"),
            revision=revision,
        )

    raw_records = payload.get("records")
    if not isinstance(raw_records, list):
        raise ContactTrustError("contact store records must be a list")
    if len(raw_records) > _MAX_RECORDS:
        raise ContactTrustError("contact store contains too many records")

    records: dict[str, ContactTrustRecord] = {}
    for raw_record in raw_records:
        record = _record_from_document(raw_record)
        if record.record_id in records:
            raise ContactTrustError("contact store contains duplicate record IDs")
        records[record.record_id] = record

    return ContactTrustStore(
        records=records,
        state_id=state_id,
        revision=revision,
        previous_digest=previous_digest,
    )


def load_contact_store(path: Path, key: bytes) -> ContactTrustStore:
    """Load an encrypted store without performing freshness verification."""
    _validate_key(key)
    if path.exists() and path.is_dir():
        raise ContactTrustError("contact store path must point to a file")
    if not path.exists():
        return ContactTrustStore()
    try:
        serialized = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ContactTrustError("unable to read contact store") from exc
    return decrypt_contact_store(serialized, key)


def _atomic_write_contact_store(path: Path, serialized: str) -> None:
    if path.exists() and path.is_dir():
        raise ContactTrustError("contact store path must point to a file")
    path.parent.mkdir(parents=True, exist_ok=True)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temporary, path)
        if os.name == "posix":
            path.chmod(0o600)
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def save_contact_store(
    path: Path,
    key: bytes,
    store: ContactTrustStore,
) -> None:
    """Atomically replace one authenticated encrypted contact store."""
    _atomic_write_contact_store(path, encrypt_contact_store(store, key))


def _wrap_witness_error(exc: Exception) -> ContactTrustError:
    return ContactTrustError(f"contact store rollback verification failed: {exc}")


def _current_checkpoint(
    store: ContactTrustStore,
    coordination_key: bytes,
) -> ComponentCheckpoint:
    if (
        store.state_id is None
        or store.revision is None
        or store.checkpoint_digest is None
    ):
        raise ContactTrustError(
            "contact store has no verified rollback checkpoint"
        )
    return ComponentCheckpoint(
        state_id=store.state_id,
        component="contacts",
        revision=store.revision,
        previous_digest=store.previous_digest,
        digest=store.checkpoint_digest,
    )


def new_witnessed_contact_store(state_id: str) -> ContactTrustStore:
    """Create an in-memory revision-1 store ready for first witnessed save."""
    return ContactTrustStore(
        state_id=_validate_state_id(state_id),
        revision=1,
        previous_digest=None,
    )


def load_contact_store_witnessed(
    path: Path,
    key: bytes,
    *,
    state_id: str,
    coordination_key: bytes,
    witness: MonotonicWitness,
) -> ContactTrustStore:
    """Load a current store and fail closed on rollback or divergence."""
    expected_state_id = _validate_state_id(state_id)
    if not path.exists():
        try:
            if witness.get("contacts") is not None:
                raise ContactTrustError(
                    "contact store is missing while its witness is initialized"
                )
        except StateWitnessError as exc:
            raise _wrap_witness_error(exc) from exc
        return new_witnessed_contact_store(expected_state_id)

    store = load_contact_store(path, key)
    if store.state_id is None or store.revision is None:
        raise ContactTrustError(
            "legacy contact store requires explicit rollback-state migration"
        )
    if store.state_id != expected_state_id:
        raise ContactTrustError(
            "contact store belongs to a different client state"
        )

    payload = _serialize_contact_payload(store)
    try:
        checkpoint = derive_checkpoint(
            coordination_key,
            state_id=store.state_id,
            component="contacts",
            revision=store.revision,
            previous_digest=store.previous_digest,
            payload=payload,
        )
        reconcile_checkpoint(
            witness,
            checkpoint,
            coordination_key=coordination_key,
            payload=payload,
        )
    except (StateCheckpointError, StateWitnessError) as exc:
        raise _wrap_witness_error(exc) from exc

    store.checkpoint_digest = checkpoint.digest
    return store


def save_contact_store_witnessed(
    path: Path,
    key: bytes,
    store: ContactTrustStore,
    *,
    state_id: str,
    coordination_key: bytes,
    witness: MonotonicWitness,
) -> None:
    """Durably save contact trust state then advance its monotonic witness."""
    expected_state_id = _validate_state_id(state_id)
    if store.state_id != expected_state_id or store.revision is None:
        raise ContactTrustError(
            "contact store rollback metadata does not match local profile"
        )

    if store.checkpoint_digest is None:
        if store.revision != 1 or store.previous_digest is not None:
            raise ContactTrustError(
                "unwitnessed contact store is not an initial revision"
            )
        payload = _serialize_contact_payload(store)
        try:
            checkpoint = create_initial_checkpoint(
                coordination_key,
                expected_state_id,
                "contacts",
                payload,
            )
            if witness.get("contacts") is not None:
                raise ContactTrustError(
                    "contact witness already exists for unwitnessed store"
                )
        except (StateCheckpointError, StateWitnessError) as exc:
            raise _wrap_witness_error(exc) from exc

        _atomic_write_contact_store(path, encrypt_contact_store(store, key))
        try:
            initialize_witness(
                witness,
                checkpoint,
                coordination_key=coordination_key,
                payload=payload,
            )
        except (StateCheckpointError, StateWitnessError) as exc:
            raise _wrap_witness_error(exc) from exc
        store.checkpoint_digest = checkpoint.digest
        return

    current = _current_checkpoint(store, coordination_key)
    next_store = ContactTrustStore(
        records=dict(store.records),
        state_id=expected_state_id,
        revision=current.revision + 1,
        previous_digest=current.digest,
    )
    next_payload = _serialize_contact_payload(next_store)
    try:
        next_checkpoint = advance_checkpoint(
            coordination_key,
            current,
            next_payload,
        )
    except StateCheckpointError as exc:
        raise _wrap_witness_error(exc) from exc

    _atomic_write_contact_store(
        path,
        encrypt_contact_store(next_store, key),
    )
    try:
        witness.compare_and_set(
            witness_record(current),
            witness_record(next_checkpoint),
        )
    except StateWitnessError as exc:
        raise _wrap_witness_error(exc) from exc

    store.state_id = next_store.state_id
    store.revision = next_store.revision
    store.previous_digest = next_store.previous_digest
    store.checkpoint_digest = next_checkpoint.digest


def migrate_contact_store_to_witness(
    path: Path,
    key: bytes,
    *,
    state_id: str,
    coordination_key: bytes,
    witness: MonotonicWitness,
) -> ContactTrustStore:
    """Explicitly enroll one legacy contact store into rollback coordination."""
    expected_state_id = _validate_state_id(state_id)
    if path.exists():
        legacy = load_contact_store(path, key)
        if legacy.state_id is not None:
            return load_contact_store_witnessed(
                path,
                key,
                state_id=expected_state_id,
                coordination_key=coordination_key,
                witness=witness,
            )
        store = ContactTrustStore(
            records=dict(legacy.records),
            state_id=expected_state_id,
            revision=1,
            previous_digest=None,
        )
    else:
        store = new_witnessed_contact_store(expected_state_id)

    save_contact_store_witnessed(
        path,
        key,
        store,
        state_id=expected_state_id,
        coordination_key=coordination_key,
        witness=witness,
    )
    return store
