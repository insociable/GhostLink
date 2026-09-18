"""Command-line client for the GhostLink M3 two-client demonstration."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from ghostlink.client import GhostNodeClient, GhostNodeClientError
from ghostlink.contact import (
    ContactBundleError,
    export_contact_bundle,
    import_contact_bundle,
)
from ghostlink.identity import format_ghost_id_fingerprint
from ghostlink.message import MessageDecryptionError, decrypt_message, encrypt_message
from ghostlink.profile import (
    LocalProfile,
    ProfileError,
    create_local_profile,
    decrypt_local_profile,
    encrypt_local_profile,
)

PasswordReader = Callable[[str], str]
NodeClientFactory = Callable[[str], GhostNodeClient]


class CLIError(RuntimeError):
    """Raised for user-facing CLI failures."""


def _write_new_private_file(path: Path, content: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(content)


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


def _load_profile(path: Path, password_reader: PasswordReader) -> LocalProfile:
    password = password_reader("GhostLink profile password: ")
    return decrypt_local_profile(_read_text(path), password)


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


def _command_send(
    args: argparse.Namespace,
    password_reader: PasswordReader,
    node_client_factory: NodeClientFactory,
) -> int:
    profile = _load_profile(Path(args.profile), password_reader)
    contact = import_contact_bundle(_read_text(Path(args.contact)))
    plaintext = args.message.encode("utf-8")

    message = encrypt_message(
        sender=profile.device,
        recipient=contact.device,
        plaintext=plaintext,
    )
    message_id = node_client_factory(args.node).send(message)

    print(f"Message queued: {message_id}")
    print(f"Recipient: {contact.ghost_id}")
    return 0


def _command_inbox(
    args: argparse.Namespace,
    password_reader: PasswordReader,
    node_client_factory: NodeClientFactory,
) -> int:
    profile = _load_profile(Path(args.profile), password_reader)
    contact = import_contact_bundle(_read_text(Path(args.contact)))
    client = node_client_factory(args.node)
    stored_messages = client.receive(profile.device.device_id)

    delivered = 0
    skipped = 0

    for stored in stored_messages:
        if stored.message.sender_device_id != contact.device_id:
            skipped += 1
            continue

        try:
            plaintext = decrypt_message(
                recipient=profile.device,
                sender=contact.device,
                message=stored.message,
            )
            text = plaintext.decode("utf-8")
        except (MessageDecryptionError, UnicodeDecodeError):
            skipped += 1
            continue

        print(f"{contact.ghost_id}: {text}")
        delivered += 1

        if not args.keep:
            client.delete(stored.message_id)

    if delivered == 0:
        print("No readable messages.")

    if skipped:
        print(
            f"Skipped {skipped} message(s) that could not be verified or decrypted.",
            file=sys.stderr,
        )

    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the GhostLink M3 command-line parser."""
    parser = argparse.ArgumentParser(
        prog="ghostlink",
        description="Experimental GhostLink M3 client",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="create an encrypted local profile")
    init_parser.add_argument("--profile", required=True)

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

    send_parser = subparsers.add_parser(
        "send",
        help="encrypt and send one text message",
    )
    send_parser.add_argument("--profile", required=True)
    send_parser.add_argument("--contact", required=True)
    send_parser.add_argument("--node", required=True)
    send_parser.add_argument("message")

    inbox_parser = subparsers.add_parser(
        "inbox",
        help="receive and decrypt messages from one verified contact",
    )
    inbox_parser.add_argument("--profile", required=True)
    inbox_parser.add_argument("--contact", required=True)
    inbox_parser.add_argument("--node", required=True)
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
    node_client_factory: NodeClientFactory = GhostNodeClient,
) -> int:
    """Run one GhostLink CLI command and return its process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "init":
            return _command_init(args, password_reader)
        if args.command == "whoami":
            return _command_whoami(args, password_reader)
        if args.command == "contact-export":
            return _command_contact_export(args, password_reader)
        if args.command == "contact-verify":
            return _command_contact_verify(args)
        if args.command == "node-health":
            return _command_node_health(args, node_client_factory)
        if args.command == "send":
            return _command_send(args, password_reader, node_client_factory)
        if args.command == "inbox":
            return _command_inbox(args, password_reader, node_client_factory)
    except (
        CLIError,
        ContactBundleError,
        FileExistsError,
        FileNotFoundError,
        GhostNodeClientError,
        OSError,
        ProfileError,
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
