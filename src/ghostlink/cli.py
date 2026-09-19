"""Command-line client for GhostLink's ratcheted protocol-v3 runtime."""

from __future__ import annotations

import argparse
import getpass
import os
import shutil
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path

from ghostlink.client import (
    GhostNodeClient,
    GhostNodeClientError,
    GhostNodeRequestError,
)
from ghostlink.config import load_access_token_from_file
from ghostlink.contact import (
    ContactBundleError,
    ValidatedContact,
    decode_contact_qr_payload,
    export_lifecycle_contact_bundle,
    export_lifecycle_contact_qr_payload,
    import_contact_bundle,
)
from ghostlink.contact_qr import render_contact_qr_svg
from ghostlink.contact_store import (
    ContactTrustRecord,
    ContactTrustState,
    ContactTrustStore,
    load_contact_store_witnessed,
    migrate_contact_store_to_witness,
    save_contact_store_witnessed,
)
from ghostlink.identity import derive_identity_fingerprint
from ghostlink.profile import (
    LocalProfile,
    ProfileError,
    create_local_profile,
    decrypt_local_profile,
    encrypt_local_profile,
    initialize_profile_witness,
    reconcile_profile_witness,
    rotate_local_profile_device,
    upgrade_local_profile,
)
from ghostlink.ratchet_engine import RatchetEngineClient, RatchetEngineError
from ghostlink.ratchet_fetch import establish_session_from_relay
from ghostlink.ratchet_maintenance import maintain_prekeys
from ghostlink.ratchet_message import (
    RatchetMessageError,
    RatchetMessageReplayError,
    decrypt_ratchet_message,
    encrypt_ratchet_message,
)
from ghostlink.replay import (
    ReplayCacheError,
    WitnessedSQLiteReplayCache,
    migrate_replay_cache_to_witness,
)
from ghostlink.state_witness import (
    ComponentCheckpoint,
    SQLiteMonotonicWitness,
    StateWitnessError,
    WitnessRecord,
)

PasswordReader = Callable[[str], str]
NodeClientFactory = Callable[[str], GhostNodeClient]
RatchetEngineFactory = Callable[[LocalProfile, Path], RatchetEngineClient]

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_RATCHET_ENGINE_PATH = (
    _PROJECT_ROOT / "ratchet-engine" / "dist" / "src" / "rpc-server.js"
)


def _default_node_client_factory(base_url: str) -> GhostNodeClient:
    return GhostNodeClient(
        base_url,
        access_token=load_access_token_from_file(),
    )


class CLIError(RuntimeError):
    """Raised for user-facing CLI failures."""


def _ratchet_vault_path(profile_path: Path) -> Path:
    return Path(f"{profile_path}.ratchet")


def _replay_state_path(profile_path: Path, explicit_path: str | None) -> Path:
    if explicit_path is not None:
        return Path(explicit_path)
    return Path(f"{profile_path}.state.sqlite3")


def _contact_store_path(profile_path: Path, explicit_path: str | None) -> Path:
    if explicit_path is not None:
        return Path(explicit_path)
    return Path(f"{profile_path}.contacts")


def _state_witness_path(profile_path: Path) -> Path:
    return Path(f"{profile_path}.witness.sqlite3")


def _device_recovery_pending_profile_path(profile_path: Path) -> Path:
    return Path(f"{profile_path}.device-recovery.pending")


def _device_recovery_ratchet_backup_path(profile_path: Path) -> Path:
    return Path(f"{profile_path}.ratchet.device-recovery-old")


def _require_state_coordination(profile: LocalProfile) -> tuple[str, bytes]:
    state_id = profile.client_state_id
    key = profile.state_coordination_key
    if state_id is None or key is None:
        raise CLIError(
            "profile has no rollback-state identity; run profile-upgrade first"
        )
    if len(state_id) != 32 or len(key) != 32:
        raise CLIError("profile rollback-state identity is invalid")
    return state_id, key


def _profile_witness(
    profile_path: Path,
    profile: LocalProfile,
) -> SQLiteMonotonicWitness:
    state_id, coordination_key = _require_state_coordination(profile)
    return SQLiteMonotonicWitness(
        _state_witness_path(profile_path),
        state_id,
        coordination_key,
    )


def _require_ratchet_key(profile: LocalProfile) -> bytes:
    key = profile.ratchet_master_key
    if key is None:
        raise CLIError(
            "legacy profile has no ratchet vault key; run profile-upgrade first"
        )
    if len(key) != 32:
        raise CLIError("profile ratchet vault key has an invalid length")
    return key


def _require_contact_store_key(profile: LocalProfile) -> bytes:
    key = profile.contact_store_key
    if key is None:
        raise CLIError(
            "legacy profile has no contact-store key; run profile-upgrade first"
        )
    if len(key) != 32:
        raise CLIError("profile contact-store key has an invalid length")
    return key


def _create_ratchet_engine(
    profile: LocalProfile,
    profile_path: Path,
    *,
    allow_legacy_migration: bool = False,
    recovery_previous_checkpoint: WitnessRecord | None = None,
) -> RatchetEngineClient:
    node = shutil.which("node")
    if node is None:
        raise CLIError("Node.js is required for the ratchet engine")
    if not _RATCHET_ENGINE_PATH.is_file():
        raise CLIError(
            "built ratchet-engine is unavailable; "
            "build ratchet-engine before using ratcheted CLI commands"
        )
    state_id, coordination_key = _require_state_coordination(profile)
    return RatchetEngineClient(
        [node, str(_RATCHET_ENGINE_PATH)],
        profile.device,
        _ratchet_vault_path(profile_path),
        _require_ratchet_key(profile),
        state_id=state_id,
        coordination_key=coordination_key,
        witness=_profile_witness(profile_path, profile),
        allow_legacy_migration=allow_legacy_migration,
        recovery_previous_checkpoint=recovery_previous_checkpoint,
    )


def _default_ratchet_engine_factory(
    profile: LocalProfile,
    profile_path: Path,
) -> RatchetEngineClient:
    return _create_ratchet_engine(profile, profile_path)


def _write_new_private_file(path: Path, content: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(content)


def _replace_private_file_atomic(path: Path, content: str) -> None:
    """Atomically replace one encrypted private file with mode 0600."""
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
            handle.write(content)
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


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    directory_fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _rename_file_atomic(source: Path, destination: Path) -> None:
    if destination.exists():
        raise CLIError(f"recovery artifact already exists: {destination}")
    os.replace(source, destination)
    _fsync_directory(destination.parent)


def _unlink_file_durable(path: Path) -> None:
    path.unlink(missing_ok=True)
    _fsync_directory(path.parent)


def _write_new_public_file(path: Path, content: str) -> None:
    with path.open("x", encoding="utf-8") as handle:
        handle.write(content)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _prompt_new_password(password_reader: PasswordReader) -> str:
    password = password_reader("New GhostLink profile password: ")
    confirmation = password_reader("Confirm profile password: ")

    if password != confirmation:
        raise CLIError("password confirmation does not match")
    if not password:
        raise CLIError("password must not be empty")

    return password


def _load_profile_with_password(
    path: Path,
    password_reader: PasswordReader,
) -> tuple[LocalProfile, str]:
    password = password_reader("GhostLink profile password: ")
    return decrypt_local_profile(_read_text(path), password), password


def _load_profile(path: Path, password_reader: PasswordReader) -> LocalProfile:
    profile, _password = _load_profile_with_password(path, password_reader)
    if profile.device_lifecycle is None:
        return profile
    try:
        reconcile_profile_witness(
            profile,
            _profile_witness(path, profile),
        )
    except ProfileError as exc:
        raise CLIError(str(exc)) from exc
    return profile


def _command_init(args: argparse.Namespace, password_reader: PasswordReader) -> int:
    path = Path(args.profile)
    password = _prompt_new_password(password_reader)
    profile = create_local_profile()
    serialized = encrypt_local_profile(profile, password)
    _write_new_private_file(path, serialized)
    initialize_profile_witness(
        profile,
        _profile_witness(path, profile),
    )

    print(f"Profile created: {path}")
    print(f"GhostID: {profile.entity.ghost_id}")
    print(f"Fingerprint v2: {derive_identity_fingerprint(bytes(profile.entity.verify_key))}")
    print(f"DeviceID: {profile.device.device_id}")
    return 0


def _command_profile_upgrade(
    args: argparse.Namespace,
    password_reader: PasswordReader,
) -> int:
    path = Path(args.profile)
    profile, password = _load_profile_with_password(path, password_reader)
    upgraded = upgrade_local_profile(profile)
    changed = upgraded is not profile
    if changed:
        serialized = encrypt_local_profile(upgraded, password)
        _replace_private_file_atomic(path, serialized)

    witness = _profile_witness(path, upgraded)
    try:
        witness_record = witness.get("profile")
    except StateWitnessError as exc:
        raise CLIError(f"unable to read profile rollback witness: {exc}") from exc

    if witness_record is None:
        initialize_profile_witness(upgraded, witness)
        witness_status = "Profile rollback witness initialized."
    else:
        reconcile_profile_witness(upgraded, witness)
        witness_status = "Profile rollback witness verified."

    if changed:
        print(f"Profile upgraded atomically: {path}")
    else:
        print("Profile already uses the current local secret format.")
    print(witness_status)
    print(
        "Ratcheted protocol-v3, contact-store, lifecycle and "
        "rollback-coordination secrets are available."
    )
    return 0




def _validate_recovery_candidate(
    current: LocalProfile,
    candidate: LocalProfile,
    current_checkpoint: ComponentCheckpoint,
) -> None:
    if candidate.entity.ghost_id != current.entity.ghost_id:
        raise CLIError("recovery candidate changed GhostID")
    if bytes(candidate.entity.verify_key) != bytes(current.entity.verify_key):
        raise CLIError("recovery candidate changed identity key")
    if candidate.client_state_id != current.client_state_id:
        raise CLIError("recovery candidate changed client state ID")
    if candidate.state_coordination_key != current.state_coordination_key:
        raise CLIError("recovery candidate changed state coordination key")
    if candidate.ratchet_master_key != current.ratchet_master_key:
        raise CLIError("recovery candidate changed ratchet master key")
    if candidate.contact_store_key != current.contact_store_key:
        raise CLIError("recovery candidate changed contact store key")
    if current.device_lifecycle is None or candidate.device_lifecycle is None:
        raise CLIError("device recovery requires lifecycle-aware profiles")
    if candidate.device.device_id == current.device.device_id:
        raise CLIError("recovery candidate did not rotate DeviceID")
    if (
        candidate.device_lifecycle.statement.epoch
        != current.device_lifecycle.statement.epoch + 1
    ):
        raise CLIError("recovery candidate lifecycle epoch is not exactly next")
    if candidate.state_revision != current_checkpoint.revision + 1:
        raise CLIError("recovery candidate profile revision is not exactly next")
    if candidate.state_previous_digest != current_checkpoint.digest:
        raise CLIError("recovery candidate profile lineage is invalid")


def _command_device_recover(
    args: argparse.Namespace,
    password_reader: PasswordReader,
    node_client_factory: NodeClientFactory,
) -> int:
    profile_path = Path(args.profile)
    active, password = _load_profile_with_password(profile_path, password_reader)
    if active.device_lifecycle is None:
        raise CLIError(
            "profile has no device lifecycle state; run profile-upgrade first"
        )

    witness = _profile_witness(profile_path, active)
    active_checkpoint = reconcile_profile_witness(active, witness)
    pending_path = _device_recovery_pending_profile_path(profile_path)
    vault_path = _ratchet_vault_path(profile_path)
    backup_path = _device_recovery_ratchet_backup_path(profile_path)
    client = node_client_factory(args.node)
    active_registered = False

    if pending_path.exists():
        candidate = decrypt_local_profile(_read_text(pending_path), password)
        _validate_recovery_candidate(active, candidate, active_checkpoint)
    elif backup_path.exists():
        if not vault_path.exists():
            raise CLIError(
                "device recovery is incomplete: replacement ratchet vault is missing"
            )
        _publish_profile_lifecycle(client, active)
        with _create_ratchet_engine(active, profile_path):
            pass
        _unlink_file_durable(backup_path)
        print("Device recovery finalized after interruption.")
        print(f"GhostID: {active.entity.ghost_id}")
        print(f"DeviceID: {active.device.device_id}")
        return 0
    else:
        _publish_profile_lifecycle(client, active)
        active_registered = True
        candidate = rotate_local_profile_device(active, active_checkpoint)
        _write_new_private_file(
            pending_path,
            encrypt_local_profile(candidate, password),
        )

    if pending_path.exists() and not active_registered:
        try:
            _publish_profile_lifecycle(client, active)
        except GhostNodeRequestError as exc:
            if exc.status_code != 409:
                raise
            relay = client.get_device_lifecycle(active.entity.ghost_id)
            if relay.lifecycle != candidate.device_lifecycle:
                raise CLIError(
                    "relay lifecycle conflicts with the pending recovery"
                ) from exc

    try:
        ratchet_record = witness.get("ratchet")
    except StateWitnessError as exc:
        raise CLIError(f"unable to read ratchet rollback witness: {exc}") from exc

    if backup_path.exists() and not vault_path.exists():
        if ratchet_record is None:
            raise CLIError(
                "device recovery archive exists without ratchet witness"
            )
        _rename_file_atomic(backup_path, vault_path)
        try:
            with _create_ratchet_engine(active, profile_path):
                pass
        except Exception:
            _rename_file_atomic(vault_path, backup_path)
            raise
        _rename_file_atomic(vault_path, backup_path)
        try:
            ratchet_record = witness.get("ratchet")
        except StateWitnessError as exc:
            raise CLIError(
                f"unable to read ratchet rollback witness: {exc}"
            ) from exc

    if backup_path.exists() and vault_path.exists():
        with _create_ratchet_engine(candidate, profile_path):
            pass
    elif not backup_path.exists():
        vault_exists = vault_path.exists()
        if vault_exists != (ratchet_record is not None):
            raise CLIError(
                "ratchet vault/witness mismatch; repair or migrate state before recovery"
            )
        if vault_exists:
            with _create_ratchet_engine(active, profile_path):
                pass
            ratchet_record = witness.get("ratchet")
            if ratchet_record is None:
                raise CLIError("ratchet witness disappeared during recovery")
            _rename_file_atomic(vault_path, backup_path)

    if backup_path.exists() and not vault_path.exists():
        if ratchet_record is None:
            raise CLIError("ratchet recovery requires the current witness record")
        with _create_ratchet_engine(
            candidate,
            profile_path,
            recovery_previous_checkpoint=ratchet_record,
        ):
            pass

    _publish_profile_lifecycle(client, candidate)

    os.replace(pending_path, profile_path)
    if os.name == "posix":
        profile_path.chmod(0o600)
    _fsync_directory(profile_path.parent)
    reconcile_profile_witness(candidate, witness)

    if backup_path.exists():
        _unlink_file_durable(backup_path)

    lifecycle = candidate.device_lifecycle
    if lifecycle is None:
        raise CLIError("device recovery produced no lifecycle state")

    print("Device recovery completed.")
    print(f"GhostID: {candidate.entity.ghost_id}")
    print(f"DeviceID: {candidate.device.device_id}")
    print(f"Lifecycle epoch: {lifecycle.statement.epoch}")
    return 0


def _command_contact_store_upgrade(
    args: argparse.Namespace,
    password_reader: PasswordReader,
) -> int:
    profile_path = Path(args.profile)
    profile = _load_profile(profile_path, password_reader)
    state_id, coordination_key = _require_state_coordination(profile)
    store = migrate_contact_store_to_witness(
        _contact_store_path(profile_path, args.contacts),
        _require_contact_store_key(profile),
        state_id=state_id,
        coordination_key=coordination_key,
        witness=_profile_witness(profile_path, profile),
    )
    print("Contact store enrolled in rollback-state witness.")
    print(f"Revision: {store.revision}")
    return 0


def _command_replay_state_upgrade(
    args: argparse.Namespace,
    password_reader: PasswordReader,
) -> int:
    profile_path = Path(args.profile)
    profile = _load_profile(profile_path, password_reader)
    state_id, coordination_key = _require_state_coordination(profile)
    migrate_replay_cache_to_witness(
        _replay_state_path(profile_path, args.state),
        state_id=state_id,
        coordination_key=coordination_key,
        witness=_profile_witness(profile_path, profile),
    )
    print("Replay state enrolled in rollback-state witness.")
    return 0


def _command_ratchet_vault_upgrade(
    args: argparse.Namespace,
    password_reader: PasswordReader,
) -> int:
    profile_path = Path(args.profile)
    profile = _load_profile(profile_path, password_reader)
    vault_path = _ratchet_vault_path(profile_path)
    if not vault_path.is_file():
        raise CLIError("legacy ratchet vault does not exist")
    with _create_ratchet_engine(
        profile,
        profile_path,
        allow_legacy_migration=True,
    ):
        pass
    print("Ratchet vault enrolled in rollback-state witness.")
    return 0


def _command_whoami(args: argparse.Namespace, password_reader: PasswordReader) -> int:
    profile = _load_profile(Path(args.profile), password_reader)
    print(f"GhostID: {profile.entity.ghost_id}")
    print(f"Fingerprint v2: {derive_identity_fingerprint(bytes(profile.entity.verify_key))}")
    print(f"DeviceID: {profile.device.device_id}")
    return 0


def _command_contact_export(
    args: argparse.Namespace,
    password_reader: PasswordReader,
) -> int:
    profile = _load_profile(Path(args.profile), password_reader)
    if profile.device_lifecycle is None:
        raise CLIError(
            "profile has no device lifecycle state; run profile-upgrade first"
        )
    bundle = export_lifecycle_contact_bundle(
        profile.entity,
        profile.device_lifecycle,
    )
    output = Path(args.output)
    _write_new_public_file(output, bundle)

    print(f"Contact bundle created: {output}")
    print(f"GhostID: {profile.entity.ghost_id}")
    print(f"DeviceID: {profile.device.device_id}")
    return 0


def _command_contact_export_qr(
    args: argparse.Namespace,
    password_reader: PasswordReader,
) -> int:
    profile = _load_profile(Path(args.profile), password_reader)
    if profile.device_lifecycle is None:
        raise CLIError(
            "profile has no device lifecycle state; run profile-upgrade first"
        )
    payload = export_lifecycle_contact_qr_payload(
        profile.entity,
        profile.device_lifecycle,
    )
    svg = render_contact_qr_svg(payload)
    output = Path(args.output)
    _write_new_public_file(output, svg)

    print(f"Public contact QR created: {output}")
    print(f"GhostID: {profile.entity.ghost_id}")
    print(
        f"Fingerprint v2: "
        f"{derive_identity_fingerprint(bytes(profile.entity.verify_key))}"
    )
    return 0


def _command_contact_verify(args: argparse.Namespace) -> int:
    contact = import_contact_bundle(_read_text(Path(args.bundle)))
    print("Contact bundle cryptographically valid")
    print(f"GhostID: {contact.ghost_id}")
    print(f"Fingerprint v2: {derive_identity_fingerprint(bytes(contact.identity_verify_key))}")
    print(f"DeviceID: {contact.device_id}")
    return 0


def _fingerprint_for_contact(contact: ValidatedContact) -> str:
    return derive_identity_fingerprint(bytes(contact.identity_verify_key))


def _print_contact_record(record: ContactTrustRecord) -> None:
    current = record.current_contact
    print(f"Contact ID: {record.record_id}")
    print(f"Label: {record.label}")
    print(f"Trust state: {record.state.value}")
    print(f"GhostID: {current.ghost_id}")
    print(f"Fingerprint v2: {_fingerprint_for_contact(current)}")
    print(f"DeviceID: {current.device_id}")
    candidate = record.candidate_contact
    if candidate is not None:
        print("IDENTITY CHANGE CANDIDATE:")
        print(f"Candidate GhostID: {candidate.ghost_id}")
        print(f"Candidate Fingerprint v2: {_fingerprint_for_contact(candidate)}")
        print(f"Candidate DeviceID: {candidate.device_id}")


def _load_profile_contact_store(
    profile_path: Path,
    profile: LocalProfile,
    explicit_path: str | None,
) -> ContactTrustStore:
    state_id, coordination_key = _require_state_coordination(profile)
    return load_contact_store_witnessed(
        _contact_store_path(profile_path, explicit_path),
        _require_contact_store_key(profile),
        state_id=state_id,
        coordination_key=coordination_key,
        witness=_profile_witness(profile_path, profile),
    )


def _save_profile_contact_store(
    profile_path: Path,
    profile: LocalProfile,
    explicit_path: str | None,
    store: ContactTrustStore,
) -> None:
    state_id, coordination_key = _require_state_coordination(profile)
    save_contact_store_witnessed(
        _contact_store_path(profile_path, explicit_path),
        _require_contact_store_key(profile),
        store,
        state_id=state_id,
        coordination_key=coordination_key,
        witness=_profile_witness(profile_path, profile),
    )


def _command_contact_import(
    args: argparse.Namespace,
    password_reader: PasswordReader,
) -> int:
    profile_path = Path(args.profile)
    profile = _load_profile(profile_path, password_reader)
    store = _load_profile_contact_store(profile_path, profile, args.contacts)
    record = store.add_contact(args.label, _read_text(Path(args.bundle)))
    _save_profile_contact_store(profile_path, profile, args.contacts, store)

    print("Contact bundle cryptographically valid; human verification pending.")
    _print_contact_record(record)
    return 0


def _command_contact_import_qr(
    args: argparse.Namespace,
    password_reader: PasswordReader,
) -> int:
    profile_path = Path(args.profile)
    profile = _load_profile(profile_path, password_reader)
    store = _load_profile_contact_store(profile_path, profile, args.contacts)
    bundle = decode_contact_qr_payload(args.payload)
    record = store.add_contact(args.label, bundle)
    _save_profile_contact_store(profile_path, profile, args.contacts, store)

    print("QR contact cryptographically valid; human verification pending.")
    _print_contact_record(record)
    return 0


def _command_contact_list(
    args: argparse.Namespace,
    password_reader: PasswordReader,
) -> int:
    profile_path = Path(args.profile)
    profile = _load_profile(profile_path, password_reader)
    store = _load_profile_contact_store(profile_path, profile, args.contacts)
    records = store.list_records()
    if not records:
        print("No saved contacts.")
        return 0

    for record in records:
        print(
            f"{record.record_id}  {record.state.value:<8}  "
            f"{record.label}  {record.current_contact.ghost_id}"
        )
    return 0


def _command_contact_show(
    args: argparse.Namespace,
    password_reader: PasswordReader,
) -> int:
    profile_path = Path(args.profile)
    profile = _load_profile(profile_path, password_reader)
    store = _load_profile_contact_store(profile_path, profile, args.contacts)
    _print_contact_record(store.get(args.contact_id))
    return 0


def _command_contact_trust(
    args: argparse.Namespace,
    password_reader: PasswordReader,
) -> int:
    profile_path = Path(args.profile)
    profile = _load_profile(profile_path, password_reader)
    store = _load_profile_contact_store(profile_path, profile, args.contacts)
    record = store.verify_identity(args.contact_id, args.fingerprint)
    _save_profile_contact_store(profile_path, profile, args.contacts, store)

    print("Human identity verification recorded.")
    _print_contact_record(record)
    return 0


def _print_contact_update_result(record: ContactTrustRecord) -> None:
    if record.state is ContactTrustState.CHANGED:
        print(
            "IDENTITY CHANGED: trusted messaging is blocked until the "
            "candidate fingerprint is verified or rejected.",
            file=sys.stderr,
        )
    _print_contact_record(record)


def _command_contact_update(
    args: argparse.Namespace,
    password_reader: PasswordReader,
) -> int:
    profile_path = Path(args.profile)
    profile = _load_profile(profile_path, password_reader)
    store = _load_profile_contact_store(profile_path, profile, args.contacts)
    record = store.update_contact_bundle(
        args.contact_id,
        _read_text(Path(args.bundle)),
    )
    _save_profile_contact_store(profile_path, profile, args.contacts, store)

    _print_contact_update_result(record)
    return 0


def _command_contact_update_qr(
    args: argparse.Namespace,
    password_reader: PasswordReader,
) -> int:
    profile_path = Path(args.profile)
    profile = _load_profile(profile_path, password_reader)
    store = _load_profile_contact_store(profile_path, profile, args.contacts)
    bundle = decode_contact_qr_payload(args.payload)
    record = store.update_contact_bundle(args.contact_id, bundle)
    _save_profile_contact_store(profile_path, profile, args.contacts, store)

    _print_contact_update_result(record)
    return 0


def _command_contact_reject_change(
    args: argparse.Namespace,
    password_reader: PasswordReader,
) -> int:
    profile_path = Path(args.profile)
    profile = _load_profile(profile_path, password_reader)
    store = _load_profile_contact_store(profile_path, profile, args.contacts)
    record = store.reject_identity_change(args.contact_id)
    _save_profile_contact_store(profile_path, profile, args.contacts, store)

    print("Candidate identity rejected; previous verified identity restored.")
    _print_contact_record(record)
    return 0


def _resolve_message_contact(
    args: argparse.Namespace,
    profile_path: Path,
    profile: LocalProfile,
) -> ValidatedContact:
    if args.contact_id is not None:
        store = _load_profile_contact_store(
            profile_path,
            profile,
            args.contacts,
        )
        return store.require_verified_contact(args.contact_id)

    if args.contact is None:
        raise CLIError("a contact ID or raw contact bundle is required")

    print(
        "Contact trust: raw bundle diagnostic path; "
        "human verification state is bypassed."
    )
    return import_contact_bundle(_read_text(Path(args.contact)))


def _publish_profile_lifecycle(
    client: GhostNodeClient,
    profile: LocalProfile,
) -> None:
    lifecycle = profile.device_lifecycle
    if lifecycle is None:
        raise CLIError(
            "profile has no device lifecycle state; run profile-upgrade first"
        )
    client.publish_device_lifecycle(
        bytes(profile.entity.verify_key),
        lifecycle,
    )


def _command_node_health(
    args: argparse.Namespace,
    node_client_factory: NodeClientFactory,
) -> int:
    client = node_client_factory(args.node)
    if not client.health():
        raise CLIError("GhostNode returned an unhealthy status")
    print("GhostNode healthy")
    return 0



def _command_prekey_sync(
    args: argparse.Namespace,
    password_reader: PasswordReader,
    node_client_factory: NodeClientFactory,
    ratchet_engine_factory: RatchetEngineFactory,
) -> int:
    profile_path = Path(args.profile)
    profile = _load_profile(profile_path, password_reader)
    _require_ratchet_key(profile)
    client = node_client_factory(args.node)
    _publish_profile_lifecycle(client, profile)

    with ratchet_engine_factory(profile, profile_path) as engine:
        result = maintain_prekeys(engine, client, profile.device)

    print(
        "Ratchet pre-keys synchronized: "
        f"{result.action}, sequence={result.publication_sequence}"
    )
    return 0


def _command_send(
    args: argparse.Namespace,
    password_reader: PasswordReader,
    node_client_factory: NodeClientFactory,
    ratchet_engine_factory: RatchetEngineFactory,
) -> int:
    profile_path = Path(args.profile)
    profile = _load_profile(profile_path, password_reader)
    _require_ratchet_key(profile)
    contact = _resolve_message_contact(args, profile_path, profile)
    plaintext = args.message.encode("utf-8")
    client = node_client_factory(args.node)
    _publish_profile_lifecycle(client, profile)

    with ratchet_engine_factory(profile, profile_path) as engine:
        maintain_prekeys(engine, client, profile.device)
        if not engine.has_session(contact):
            establish_session_from_relay(
                engine,
                client,
                profile.device,
                contact,
            )

        message = encrypt_ratchet_message(
            engine,
            contact,
            plaintext,
        )
        message_id = client.send_ratchet(profile.device, message)

    print(f"Ratcheted message queued: {message_id}")
    print(f"Recipient: {contact.ghost_id}")
    return 0


def _command_inbox(
    args: argparse.Namespace,
    password_reader: PasswordReader,
    node_client_factory: NodeClientFactory,
    ratchet_engine_factory: RatchetEngineFactory,
) -> int:
    profile_path = Path(args.profile)
    profile = _load_profile(profile_path, password_reader)
    _require_ratchet_key(profile)
    contact = _resolve_message_contact(args, profile_path, profile)
    client = node_client_factory(args.node)
    _publish_profile_lifecycle(client, profile)
    state_id, coordination_key = _require_state_coordination(profile)
    replay_cache = WitnessedSQLiteReplayCache(
        _replay_state_path(profile_path, args.state),
        state_id,
        coordination_key,
        _profile_witness(profile_path, profile),
    )

    delivered = 0
    skipped = 0
    replayed = 0

    with ratchet_engine_factory(profile, profile_path) as engine:
        maintain_prekeys(engine, client, profile.device)
        messages = client.receive_ratchet(profile.device)

        for message in messages:
            if message.sender_device_id != contact.device_id:
                skipped += 1
                continue

            if replay_cache.has_seen(contact.device_id, message.message_id):
                replayed += 1
                if not args.keep:
                    client.delete_ratchet(
                        profile.device,
                        message.message_id,
                    )
                continue

            try:
                plaintext = decrypt_ratchet_message(
                    engine,
                    contact,
                    message,
                    replay_cache,
                )
                text = plaintext.decode("utf-8")
            except RatchetMessageReplayError:
                replayed += 1
                if not args.keep:
                    client.delete_ratchet(
                        profile.device,
                        message.message_id,
                    )
                continue
            except (RatchetMessageError, RatchetEngineError, UnicodeDecodeError):
                skipped += 1
                continue

            print(f"{contact.ghost_id}: {text}")
            delivered += 1

            if not args.keep:
                client.delete_ratchet(
                    profile.device,
                    message.message_id,
                )

    if delivered == 0:
        print("No readable ratcheted messages.")

    if skipped:
        print(
            f"Skipped {skipped} ratcheted message(s) that could not be verified or decrypted.",
            file=sys.stderr,
        )
    if replayed:
        print(
            f"Suppressed {replayed} replayed ratcheted message(s).",
            file=sys.stderr,
        )

    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the GhostLink M5 command-line parser."""
    parser = argparse.ArgumentParser(
        prog="ghostlink",
        description="Experimental GhostLink ratcheted client",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser(
        "init",
        help="create an encrypted local profile",
    )
    init_parser.add_argument("--profile", required=True)

    upgrade_parser = subparsers.add_parser(
        "profile-upgrade",
        help="upgrade a legacy profile for the encrypted ratchet vault",
    )
    upgrade_parser.add_argument("--profile", required=True)

    recovery_parser = subparsers.add_parser(
        "device-recover",
        help="rotate DeviceID, publish relay lifecycle and reset ratchet state crash-safely",
    )
    recovery_parser.add_argument("--profile", required=True)
    recovery_parser.add_argument("--node", required=True)

    contact_store_upgrade_parser = subparsers.add_parser(
        "contact-store-upgrade",
        help="enroll a legacy contact store in rollback-state coordination",
    )
    contact_store_upgrade_parser.add_argument("--profile", required=True)
    contact_store_upgrade_parser.add_argument("--contacts")

    replay_upgrade_parser = subparsers.add_parser(
        "replay-state-upgrade",
        help="enroll a legacy replay cache in rollback-state coordination",
    )
    replay_upgrade_parser.add_argument("--profile", required=True)
    replay_upgrade_parser.add_argument("--state")

    ratchet_upgrade_parser = subparsers.add_parser(
        "ratchet-vault-upgrade",
        help="enroll a legacy ratchet vault in rollback-state coordination",
    )
    ratchet_upgrade_parser.add_argument("--profile", required=True)

    whoami_parser = subparsers.add_parser(
        "whoami",
        help="show the local GhostID and DeviceID",
    )
    whoami_parser.add_argument("--profile", required=True)

    export_parser = subparsers.add_parser(
        "contact-export",
        help="export a public contact bundle",
    )
    export_parser.add_argument("--profile", required=True)
    export_parser.add_argument("--output", required=True)

    export_qr_parser = subparsers.add_parser(
        "contact-export-qr",
        help="export the public contact as a standard SVG QR code",
    )
    export_qr_parser.add_argument("--profile", required=True)
    export_qr_parser.add_argument("--output", required=True)

    verify_parser = subparsers.add_parser(
        "contact-verify",
        help="cryptographically validate a public contact bundle",
    )
    verify_parser.add_argument("bundle")

    import_parser = subparsers.add_parser(
        "contact-import",
        help="save a cryptographically valid contact as human-unverified",
    )
    import_parser.add_argument("--profile", required=True)
    import_parser.add_argument("--contacts")
    import_parser.add_argument("--label", required=True)
    import_parser.add_argument("bundle")

    import_qr_parser = subparsers.add_parser(
        "contact-import-qr",
        help="save a scanned public QR payload as human-unverified",
    )
    import_qr_parser.add_argument("--profile", required=True)
    import_qr_parser.add_argument("--contacts")
    import_qr_parser.add_argument("--label", required=True)
    import_qr_parser.add_argument("--payload", required=True)

    list_parser = subparsers.add_parser(
        "contact-list",
        help="list persisted local contact trust states",
    )
    list_parser.add_argument("--profile", required=True)
    list_parser.add_argument("--contacts")

    show_parser = subparsers.add_parser(
        "contact-show",
        help="show fingerprints and trust state for one saved contact",
    )
    show_parser.add_argument("--profile", required=True)
    show_parser.add_argument("--contacts")
    show_parser.add_argument("contact_id")

    trust_parser = subparsers.add_parser(
        "contact-trust",
        help="record explicit human verification of a complete Fingerprint v2",
    )
    trust_parser.add_argument("--profile", required=True)
    trust_parser.add_argument("--contacts")
    trust_parser.add_argument("--fingerprint", required=True)
    trust_parser.add_argument("contact_id")

    update_parser = subparsers.add_parser(
        "contact-update",
        help="apply new valid public material to a saved contact",
    )
    update_parser.add_argument("--profile", required=True)
    update_parser.add_argument("--contacts")
    update_parser.add_argument("contact_id")
    update_parser.add_argument("bundle")

    update_qr_parser = subparsers.add_parser(
        "contact-update-qr",
        help="apply a scanned public QR payload to a saved contact",
    )
    update_qr_parser.add_argument("--profile", required=True)
    update_qr_parser.add_argument("--contacts")
    update_qr_parser.add_argument("contact_id")
    update_qr_parser.add_argument("--payload", required=True)

    reject_parser = subparsers.add_parser(
        "contact-reject-change",
        help="reject a staged identity replacement",
    )
    reject_parser.add_argument("--profile", required=True)
    reject_parser.add_argument("--contacts")
    reject_parser.add_argument("contact_id")

    health_parser = subparsers.add_parser(
        "node-health",
        help="check GhostNode health",
    )
    health_parser.add_argument("--node", required=True)

    sync_parser = subparsers.add_parser(
        "prekey-sync",
        help="publish or maintain this device's ratchet pre-keys",
    )
    sync_parser.add_argument("--profile", required=True)
    sync_parser.add_argument("--node", required=True)

    send_parser = subparsers.add_parser(
        "send",
        help="send one ratcheted protocol-v3 text message",
    )
    send_parser.add_argument("--profile", required=True)
    send_contact = send_parser.add_mutually_exclusive_group(required=True)
    send_contact.add_argument(
        "--contact-id",
        help="persisted human-verified contact record ID",
    )
    send_contact.add_argument(
        "--contact",
        help="raw bundle path; diagnostic only and bypasses human trust",
    )
    send_parser.add_argument("--contacts")
    send_parser.add_argument("--node", required=True)
    send_parser.add_argument("message")

    inbox_parser = subparsers.add_parser(
        "inbox",
        help="receive ratcheted protocol-v3 messages from one verified contact",
    )
    inbox_parser.add_argument("--profile", required=True)
    inbox_contact = inbox_parser.add_mutually_exclusive_group(required=True)
    inbox_contact.add_argument(
        "--contact-id",
        help="persisted human-verified contact record ID",
    )
    inbox_contact.add_argument(
        "--contact",
        help="raw bundle path; diagnostic only and bypasses human trust",
    )
    inbox_parser.add_argument("--contacts")
    inbox_parser.add_argument("--node", required=True)
    inbox_parser.add_argument(
        "--state",
        help="path to the persistent replay-cache database",
    )
    inbox_parser.add_argument(
        "--keep",
        action="store_true",
        help="leave successfully decrypted messages on the relay",
    )

    return parser


def run(
    argv: Sequence[str] | None = None,
    *,
    password_reader: PasswordReader = getpass.getpass,
    node_client_factory: NodeClientFactory = _default_node_client_factory,
    ratchet_engine_factory: RatchetEngineFactory | None = None,
) -> int:
    """Run one GhostLink CLI command and return its process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    engine_factory = ratchet_engine_factory or _default_ratchet_engine_factory

    try:
        if args.command == "init":
            return _command_init(args, password_reader)
        if args.command == "profile-upgrade":
            return _command_profile_upgrade(args, password_reader)
        if args.command == "device-recover":
            return _command_device_recover(
                args,
                password_reader,
                node_client_factory,
            )
        if args.command == "contact-store-upgrade":
            return _command_contact_store_upgrade(args, password_reader)
        if args.command == "replay-state-upgrade":
            return _command_replay_state_upgrade(args, password_reader)
        if args.command == "ratchet-vault-upgrade":
            return _command_ratchet_vault_upgrade(args, password_reader)
        if args.command == "whoami":
            return _command_whoami(args, password_reader)
        if args.command == "contact-export":
            return _command_contact_export(args, password_reader)
        if args.command == "contact-export-qr":
            return _command_contact_export_qr(args, password_reader)
        if args.command == "contact-verify":
            return _command_contact_verify(args)
        if args.command == "contact-import":
            return _command_contact_import(args, password_reader)
        if args.command == "contact-import-qr":
            return _command_contact_import_qr(args, password_reader)
        if args.command == "contact-list":
            return _command_contact_list(args, password_reader)
        if args.command == "contact-show":
            return _command_contact_show(args, password_reader)
        if args.command == "contact-trust":
            return _command_contact_trust(args, password_reader)
        if args.command == "contact-update":
            return _command_contact_update(args, password_reader)
        if args.command == "contact-update-qr":
            return _command_contact_update_qr(args, password_reader)
        if args.command == "contact-reject-change":
            return _command_contact_reject_change(args, password_reader)
        if args.command == "node-health":
            return _command_node_health(args, node_client_factory)
        if args.command == "prekey-sync":
            return _command_prekey_sync(
                args,
                password_reader,
                node_client_factory,
                engine_factory,
            )
        if args.command == "send":
            return _command_send(
                args,
                password_reader,
                node_client_factory,
                engine_factory,
            )
        if args.command == "inbox":
            return _command_inbox(
                args,
                password_reader,
                node_client_factory,
                engine_factory,
            )
    except (
        CLIError,
        ContactBundleError,
        FileExistsError,
        FileNotFoundError,
        GhostNodeClientError,
        OSError,
        ProfileError,
        RatchetEngineError,
        ReplayCacheError,
        ValueError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    parser.error("unknown command")
    return 2


def main() -> None:
    """Console-script entry point."""
    raise SystemExit(run())


if __name__ == "__main__":
    main()
