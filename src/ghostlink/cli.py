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

from ghostlink.client import GhostNodeClient, GhostNodeClientError
from ghostlink.config import NODE_TOKEN_ENV
from ghostlink.contact import (
    ContactBundleError,
    export_contact_bundle,
    import_contact_bundle,
)
from ghostlink.entity import GhostEntity
from ghostlink.identity import format_ghost_id_fingerprint
from ghostlink.message import decrypt_message, encrypt_message
from ghostlink.profile import (
    LocalProfile,
    ProfileError,
    create_local_profile,
    decrypt_local_profile,
    encrypt_local_profile,
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
from ghostlink.replay import ReplayCacheError, SQLiteReplayCache

PasswordReader = Callable[[str], str]
NodeClientFactory = Callable[[str], GhostNodeClient]
RatchetEngineFactory = Callable[[LocalProfile, Path], RatchetEngineClient]

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_RATCHET_ENGINE_PATH = (
    _PROJECT_ROOT / "ratchet-engine" / "dist" / "src" / "rpc-server.js"
)


def _default_node_client_factory(base_url: str) -> GhostNodeClient:
    token = os.environ.get(NODE_TOKEN_ENV)
    return GhostNodeClient(
        base_url,
        access_token=token if token and token.strip() else None,
    )


class CLIError(RuntimeError):
    """Raised for user-facing CLI failures."""


def _ratchet_vault_path(profile_path: Path) -> Path:
    return Path(f"{profile_path}.ratchet")


def _replay_state_path(profile_path: Path, explicit_path: str | None) -> Path:
    if explicit_path is not None:
        return Path(explicit_path)
    return Path(f"{profile_path}.state.sqlite3")


def _require_ratchet_key(profile: LocalProfile) -> bytes:
    key = profile.ratchet_master_key
    if key is None:
        raise CLIError(
            "legacy profile has no ratchet vault key; run profile-upgrade first"
        )
    if len(key) != 32:
        raise CLIError("profile ratchet vault key has an invalid length")
    return key


def _default_ratchet_engine_factory(
    profile: LocalProfile,
    profile_path: Path,
) -> RatchetEngineClient:
    node = shutil.which("node")
    if node is None:
        raise CLIError("Node.js is required for the ratchet engine")
    if not _RATCHET_ENGINE_PATH.is_file():
        raise CLIError(
            "built ratchet-engine is unavailable; "
            "build ratchet-engine before using ratcheted CLI commands"
        )
    return RatchetEngineClient(
        [node, str(_RATCHET_ENGINE_PATH)],
        profile.device,
        _ratchet_vault_path(profile_path),
        _require_ratchet_key(profile),
    )


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
    return profile


def _command_init(args: argparse.Namespace, password_reader: PasswordReader) -> int:
    path = Path(args.profile)
    password = _prompt_new_password(password_reader)
    profile = create_local_profile()
    serialized = encrypt_local_profile(profile, password)
    _write_new_private_file(path, serialized)

    print(f"Profile created: {path}")
    print(f"GhostID: {profile.entity.ghost_id}")
    print(f"Fingerprint: {format_ghost_id_fingerprint(profile.entity.ghost_id)}")
    print(f"DeviceID: {profile.device.device_id}")
    return 0


def _command_profile_upgrade(
    args: argparse.Namespace,
    password_reader: PasswordReader,
) -> int:
    path = Path(args.profile)
    profile, password = _load_profile_with_password(path, password_reader)
    if profile.ratchet_master_key is not None:
        print("Profile already supports the ratchet vault.")
        return 0

    upgraded = upgrade_local_profile(profile)
    serialized = encrypt_local_profile(upgraded, password)
    _replace_private_file_atomic(path, serialized)

    print(f"Profile upgraded atomically: {path}")
    print("Ratcheted protocol-v3 commands are now available.")
    return 0


def _command_whoami(args: argparse.Namespace, password_reader: PasswordReader) -> int:
    profile = _load_profile(Path(args.profile), password_reader)
    print(f"GhostID: {profile.entity.ghost_id}")
    print(f"Fingerprint: {format_ghost_id_fingerprint(profile.entity.ghost_id)}")
    print(f"DeviceID: {profile.device.device_id}")
    return 0


def _command_contact_export(
    args: argparse.Namespace,
    password_reader: PasswordReader,
) -> int:
    profile = _load_profile(Path(args.profile), password_reader)
    bundle = export_contact_bundle(profile.entity, profile.device)
    output = Path(args.output)
    _write_new_public_file(output, bundle)

    print(f"Contact bundle created: {output}")
    print(f"GhostID: {profile.entity.ghost_id}")
    print(f"DeviceID: {profile.device.device_id}")
    return 0


def _command_contact_verify(args: argparse.Namespace) -> int:
    contact = import_contact_bundle(_read_text(Path(args.bundle)))
    print("Contact bundle verified")
    print(f"GhostID: {contact.ghost_id}")
    print(f"Fingerprint: {format_ghost_id_fingerprint(contact.ghost_id)}")
    print(f"DeviceID: {contact.device_id}")
    return 0


def _command_node_health(
    args: argparse.Namespace,
    node_client_factory: NodeClientFactory,
) -> int:
    client = node_client_factory(args.node)
    if not client.health():
        raise CLIError("GhostNode returned an unhealthy status")
    print("GhostNode healthy")
    return 0


def _command_node_smoke(
    args: argparse.Namespace,
    node_client_factory: NodeClientFactory,
) -> int:
    """Run the retained ephemeral static protocol-v2 relay smoke."""
    client = node_client_factory(args.node)
    if not client.health():
        raise CLIError("GhostNode returned an unhealthy status")

    alice = GhostEntity.generate()
    bob = GhostEntity.generate()
    alice_device = alice.enroll_device()
    bob_device = bob.enroll_device()
    expected_plaintext = b"ghostlink-e2ee-smoke-v2"

    message = encrypt_message(
        sender=alice_device,
        recipient=bob_device.public_device(),
        plaintext=expected_plaintext,
    )
    client.send(message)

    try:
        received = next(
            (
                candidate
                for candidate in client.receive(bob_device.device_id)
                if candidate.message_id == message.message_id
            ),
            None,
        )
        if received is None:
            raise CLIError("smoke message was not returned by GhostNode")

        plaintext = decrypt_message(
            recipient=bob_device,
            sender=alice_device.public_device(),
            message=received,
        )
        if plaintext != expected_plaintext:
            raise CLIError("smoke message plaintext did not round-trip correctly")
    finally:
        client.delete(bob_device.device_id, message.message_id)

    print("GhostNode legacy static V2 smoke test passed")
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
    contact = import_contact_bundle(_read_text(Path(args.contact)))
    plaintext = args.message.encode("utf-8")
    client = node_client_factory(args.node)

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
    contact = import_contact_bundle(_read_text(Path(args.contact)))
    client = node_client_factory(args.node)
    replay_cache = SQLiteReplayCache(
        _replay_state_path(profile_path, args.state)
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

    verify_parser = subparsers.add_parser(
        "contact-verify",
        help="verify a public contact bundle",
    )
    verify_parser.add_argument("bundle")

    health_parser = subparsers.add_parser(
        "node-health",
        help="check GhostNode health",
    )
    health_parser.add_argument("--node", required=True)

    smoke_parser = subparsers.add_parser(
        "node-smoke",
        help="run the retained static-v2 relay smoke test",
    )
    smoke_parser.add_argument("--node", required=True)

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
    send_parser.add_argument("--contact", required=True)
    send_parser.add_argument("--node", required=True)
    send_parser.add_argument("message")

    inbox_parser = subparsers.add_parser(
        "inbox",
        help="receive ratcheted protocol-v3 messages from one verified contact",
    )
    inbox_parser.add_argument("--profile", required=True)
    inbox_parser.add_argument("--contact", required=True)
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
        if args.command == "whoami":
            return _command_whoami(args, password_reader)
        if args.command == "contact-export":
            return _command_contact_export(args, password_reader)
        if args.command == "contact-verify":
            return _command_contact_verify(args)
        if args.command == "node-health":
            return _command_node_health(args, node_client_factory)
        if args.command == "node-smoke":
            return _command_node_smoke(args, node_client_factory)
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
