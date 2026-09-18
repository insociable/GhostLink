from __future__ import annotations

import base64
import json
import urllib.parse
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import cast

from fastapi.testclient import TestClient
from nacl import utils
from nacl.pwhash import argon2id
from nacl.secret import SecretBox
import pytest

import ghostlink.cli as cli_module
from ghostlink.cli import run
from ghostlink.client import GhostNodeClient, GhostNodeRequestError
from ghostlink.node import create_app
from ghostlink.profile import (
    LocalProfile,
    decrypt_local_profile,
)
from ghostlink.ratchet_engine import RatchetEngineClient
from ghostlink.ratchet_message import (
    RatchetMessage,
    RatchetMessageReplayError,
)


def create_test_requester(
    api_client: TestClient,
) -> Callable[
    [str, str, dict[str, object] | None, float, dict[str, str]],
    tuple[int, object | None],
]:
    def requester(
        method: str,
        url: str,
        payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        assert timeout > 0
        path = urllib.parse.urlparse(url).path
        response = api_client.request(method, path, json=payload, headers=headers)
        return (
            response.status_code,
            response.json() if response.content else None,
        )

    return requester


class FakeRatchetEngine:
    def __init__(self, profile: LocalProfile, sessions: set[str]) -> None:
        self.local_device_id = profile.device.device_id
        self.sessions = sessions

    def __enter__(self) -> FakeRatchetEngine:
        return self

    def __exit__(self, *args: object) -> None:
        del args

    def has_session(self, contact) -> bool:
        return contact.device_id in self.sessions


def fake_engine_factory(
    session_state: dict[str, set[str]],
) -> Callable[[LocalProfile, Path], RatchetEngineClient]:
    def factory(profile: LocalProfile, profile_path: Path) -> RatchetEngineClient:
        sessions = session_state.setdefault(str(profile_path), set())
        return cast(
            RatchetEngineClient,
            FakeRatchetEngine(profile, sessions),
        )

    return factory


def install_fake_ratchet_operations(monkeypatch) -> None:
    def maintain(engine, node, device):
        del engine, node, device
        return SimpleNamespace(action="healthy", publication_sequence=1)

    def bootstrap(engine, node, local_device, contact):
        del node, local_device
        cast(FakeRatchetEngine, engine).sessions.add(contact.device_id)
        return None

    def encrypt(engine, contact, plaintext):
        return RatchetMessage(
            version=3,
            message_id="a" * 32,
            sender_device_id=cast(FakeRatchetEngine, engine).local_device_id,
            recipient_device_id=contact.device_id,
            created_at=1_000,
            expires_at=2_000,
            ciphertext_type=3,
            ciphertext=b"fake-libsignal-ciphertext",
        )

    def decrypt(engine, contact, message, replay_cache):
        del engine
        if not replay_cache.accept(
            contact.device_id,
            message.message_id,
            now=1_100,
        ):
            raise RatchetMessageReplayError("ratcheted message replay detected")
        return b"Hello Bob from the GhostLink CLI"

    monkeypatch.setattr(cli_module, "maintain_prekeys", maintain)
    monkeypatch.setattr(cli_module, "establish_session_from_relay", bootstrap)
    monkeypatch.setattr(cli_module, "encrypt_ratchet_message", encrypt)
    monkeypatch.setattr(cli_module, "decrypt_ratchet_message", decrypt)


def _legacy_v1_profile(serialized_v2: str, password: str) -> str:
    profile = decrypt_local_profile(serialized_v2, password)
    certificate = profile.device.certificate.certificate
    secret = {
        "identity_signing_seed": base64.b64encode(
            bytes(profile.entity.signing_key)
        ).decode("ascii"),
        "device_signing_seed": base64.b64encode(
            bytes(profile.device.device.signing_key)
        ).decode("ascii"),
        "device_encryption_private_key": base64.b64encode(
            bytes(profile.device.device.encryption_key)
        ).decode("ascii"),
        "ghost_id": certificate.ghost_id,
        "device_id": certificate.device_id,
        "device_signing_public_key": base64.b64encode(
            certificate.signing_public_key
        ).decode("ascii"),
        "device_encryption_public_key": base64.b64encode(
            certificate.encryption_public_key
        ).decode("ascii"),
        "device_certificate_signature": base64.b64encode(
            profile.device.certificate.signature
        ).decode("ascii"),
    }
    plaintext = json.dumps(
        secret,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    salt = utils.random(argon2id.SALTBYTES)
    key = argon2id.kdf(
        SecretBox.KEY_SIZE,
        password.encode("utf-8"),
        salt,
        opslimit=argon2id.OPSLIMIT_INTERACTIVE,
        memlimit=argon2id.MEMLIMIT_INTERACTIVE,
    )
    ciphertext = bytes(SecretBox(key).encrypt(plaintext))
    return json.dumps(
        {
            "version": 1,
            "kdf": {
                "name": "argon2id",
                "salt": base64.b64encode(salt).decode("ascii"),
                "opslimit": argon2id.OPSLIMIT_INTERACTIVE,
                "memlimit": argon2id.MEMLIMIT_INTERACTIVE,
            },
            "cipher": "secretbox",
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _create_profiles_and_contacts(
    tmp_path: Path,
    capsys,
    password_reader,
    node_client_factory,
) -> tuple[Path, Path, Path, Path]:
    alice_profile = tmp_path / "alice.ghost"
    bob_profile = tmp_path / "bob.ghost"
    alice_contact = tmp_path / "alice.contact"
    bob_contact = tmp_path / "bob.contact"

    for profile in (alice_profile, bob_profile):
        assert run(
            ["init", "--profile", str(profile)],
            password_reader=password_reader,
            node_client_factory=node_client_factory,
        ) == 0

    assert run(
        [
            "contact-export",
            "--profile",
            str(alice_profile),
            "--output",
            str(alice_contact),
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0
    assert run(
        [
            "contact-export",
            "--profile",
            str(bob_profile),
            "--output",
            str(bob_contact),
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0
    capsys.readouterr()
    return alice_profile, bob_profile, alice_contact, bob_contact


def test_cli_two_client_ratcheted_message_workflow(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    api_client = TestClient(create_app())
    requester = create_test_requester(api_client)
    session_state: dict[str, set[str]] = {}
    install_fake_ratchet_operations(monkeypatch)

    def node_client_factory(base_url: str) -> GhostNodeClient:
        return GhostNodeClient(base_url, requester=requester)

    def password_reader(prompt: str) -> str:
        del prompt
        return "test profile password"

    alice_profile, bob_profile, alice_contact, bob_contact = (
        _create_profiles_and_contacts(
            tmp_path,
            capsys,
            password_reader,
            node_client_factory,
        )
    )
    node_url = "http://ghostnode.test"
    engine_factory = fake_engine_factory(session_state)

    assert run(
        [
            "send",
            "--profile",
            str(alice_profile),
            "--contact",
            str(bob_contact),
            "--node",
            node_url,
            "Hello Bob from the GhostLink CLI",
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        ratchet_engine_factory=engine_factory,
    ) == 0

    sent = capsys.readouterr()
    assert "Ratcheted message queued:" in sent.out
    assert api_client.get("/v2/messages/" + decrypt_local_profile(
        bob_profile.read_text(),
        "test profile password",
    ).device.device_id).json() == []

    assert run(
        [
            "inbox",
            "--profile",
            str(bob_profile),
            "--contact",
            str(alice_contact),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        ratchet_engine_factory=engine_factory,
    ) == 0

    first_inbox = capsys.readouterr()
    assert "Hello Bob from the GhostLink CLI" in first_inbox.out
    assert first_inbox.err == ""

    assert run(
        [
            "inbox",
            "--profile",
            str(bob_profile),
            "--contact",
            str(alice_contact),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        ratchet_engine_factory=engine_factory,
    ) == 0
    second_inbox = capsys.readouterr()
    assert "No readable ratcheted messages." in second_inbox.out


def test_cli_prekey_sync_runs_ratchet_maintenance(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    api_client = TestClient(create_app())
    requester = create_test_requester(api_client)
    calls: list[str] = []

    def node_client_factory(base_url: str) -> GhostNodeClient:
        return GhostNodeClient(base_url, requester=requester)

    password_reader = lambda prompt: "sync password"  # noqa: E731
    profile_path = tmp_path / "sync.ghost"
    assert run(
        ["init", "--profile", str(profile_path)],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0
    capsys.readouterr()

    def maintain(engine, node, device):
        del engine, node
        calls.append(device.device_id)
        return SimpleNamespace(action="published_initial", publication_sequence=1)

    monkeypatch.setattr(cli_module, "maintain_prekeys", maintain)

    profile = decrypt_local_profile(
        profile_path.read_text(),
        "sync password",
    )
    exit_code = run(
        [
            "prekey-sync",
            "--profile",
            str(profile_path),
            "--node",
            "http://ghostnode.test",
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        ratchet_engine_factory=fake_engine_factory({}),
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert calls == [profile.device.device_id]
    assert "published_initial" in captured.out


def test_cli_does_not_fall_back_to_static_v2_when_bootstrap_fails(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    api_client = TestClient(create_app())
    requester = create_test_requester(api_client)
    session_state: dict[str, set[str]] = {}

    def node_client_factory(base_url: str) -> GhostNodeClient:
        return GhostNodeClient(base_url, requester=requester)

    password_reader = lambda prompt: "no fallback password"  # noqa: E731
    alice_profile, _bob_profile, _alice_contact, bob_contact = (
        _create_profiles_and_contacts(
            tmp_path,
            capsys,
            password_reader,
            node_client_factory,
        )
    )

    monkeypatch.setattr(
        cli_module,
        "maintain_prekeys",
        lambda engine, node, device: SimpleNamespace(
            action="healthy",
            publication_sequence=1,
        ),
    )

    def fail_bootstrap(*args, **kwargs):
        del args, kwargs
        raise GhostNodeRequestError(404, "target has no active pre-key generation")

    monkeypatch.setattr(
        cli_module,
        "establish_session_from_relay",
        fail_bootstrap,
    )

    exit_code = run(
        [
            "send",
            "--profile",
            str(alice_profile),
            "--contact",
            str(bob_contact),
            "--node",
            "http://ghostnode.test",
            "must not downgrade",
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        ratchet_engine_factory=fake_engine_factory(session_state),
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "target has no active pre-key generation" in captured.err

    bob = decrypt_local_profile(
        (tmp_path / "bob.ghost").read_text(),
        "no fallback password",
    )
    assert api_client.get(f"/v2/messages/{bob.device.device_id}").json() == []
    assert api_client.get(f"/v3/messages/{bob.device.device_id}").json() == []


def test_cli_suppresses_authenticated_v3_replay_before_second_decrypt(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    api_client = TestClient(create_app())
    requester = create_test_requester(api_client)
    session_state: dict[str, set[str]] = {}
    install_fake_ratchet_operations(monkeypatch)

    def node_client_factory(base_url: str) -> GhostNodeClient:
        return GhostNodeClient(base_url, requester=requester)

    password_reader = lambda prompt: "replay password"  # noqa: E731
    alice_profile, bob_profile, alice_contact, bob_contact = (
        _create_profiles_and_contacts(
            tmp_path,
            capsys,
            password_reader,
            node_client_factory,
        )
    )
    engine_factory = fake_engine_factory(session_state)
    node_url = "http://ghostnode.test"

    assert run(
        [
            "send",
            "--profile",
            str(alice_profile),
            "--contact",
            str(bob_contact),
            "--node",
            node_url,
            "display exactly once",
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        ratchet_engine_factory=engine_factory,
    ) == 0
    capsys.readouterr()

    assert run(
        [
            "inbox",
            "--profile",
            str(bob_profile),
            "--contact",
            str(alice_contact),
            "--node",
            node_url,
            "--keep",
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        ratchet_engine_factory=engine_factory,
    ) == 0
    first = capsys.readouterr()
    assert "Hello Bob from the GhostLink CLI" in first.out

    assert run(
        [
            "inbox",
            "--profile",
            str(bob_profile),
            "--contact",
            str(alice_contact),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        ratchet_engine_factory=engine_factory,
    ) == 0
    second = capsys.readouterr()
    assert "Hello Bob from the GhostLink CLI" not in second.out
    assert "Suppressed 1 replayed ratcheted message(s)." in second.err


def test_cli_profile_upgrade_atomically_migrates_v1(
    tmp_path: Path,
    capsys,
) -> None:
    unlock_phrase = "legacy migration password"
    profile_path = tmp_path / "legacy.ghost"

    assert run(
        ["init", "--profile", str(profile_path)],
        password_reader=lambda prompt: unlock_phrase,
    ) == 0
    capsys.readouterr()

    current = profile_path.read_text()
    profile_path.write_text(
        _legacy_v1_profile(current, unlock_phrase),
        encoding="utf-8",
    )
    before = decrypt_local_profile(profile_path.read_text(), unlock_phrase)
    assert before.ratchet_master_key is None

    assert run(
        ["profile-upgrade", "--profile", str(profile_path)],
        password_reader=lambda prompt: unlock_phrase,
    ) == 0

    captured = capsys.readouterr()
    upgraded = decrypt_local_profile(profile_path.read_text(), unlock_phrase)
    assert upgraded.entity.ghost_id == before.entity.ghost_id
    assert upgraded.device.device_id == before.device.device_id
    assert upgraded.ratchet_master_key is not None
    assert len(upgraded.ratchet_master_key) == 32
    assert "upgraded atomically" in captured.out


def test_cli_refuses_to_overwrite_existing_profile(tmp_path: Path, capsys) -> None:
    profile_path = tmp_path / "existing.ghost"
    profile_path.write_text("already here", encoding="utf-8")

    exit_code = run(
        ["init", "--profile", str(profile_path)],
        password_reader=lambda prompt: "test password",
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "error:" in captured.err


def test_cli_node_smoke_remains_explicit_legacy_v2(capsys) -> None:
    api_client = TestClient(create_app())
    requester = create_test_requester(api_client)

    def node_client_factory(base_url: str) -> GhostNodeClient:
        return GhostNodeClient(base_url, requester=requester)

    exit_code = run(
        ["node-smoke", "--node", "http://ghostnode.test"],
        node_client_factory=node_client_factory,
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "legacy static V2 smoke test passed" in captured.out
    assert captured.err == ""
