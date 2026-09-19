from __future__ import annotations

import base64
import json
import stat
import time
import urllib.parse
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import ghostlink.cli as cli_module
import pytest
from fastapi.testclient import TestClient
from ghostlink.cli import run
from ghostlink.client import GhostNodeClient, GhostNodeRequestError
from ghostlink.contact import (
    export_contact_bundle,
    export_contact_qr_payload,
    import_contact_bundle,
)
from ghostlink.contact_store import (
    ContactTrustError,
    ContactTrustState,
    ContactTrustStore,
    load_contact_store,
    save_contact_store,
)
from ghostlink.device_lifecycle import create_device_lifecycle_statement
from ghostlink.entity import GhostEntity
from ghostlink.identity import derive_identity_fingerprint
from ghostlink.node import create_app
from ghostlink.profile import LocalProfile, decrypt_local_profile
from ghostlink.ratchet_engine import RatchetEngineClient
from ghostlink.ratchet_message import (
    RatchetMessage,
    RatchetMessageReplayError,
)
from ghostlink.replay import SQLiteReplayCache
from nacl import utils
from nacl.pwhash import argon2id
from nacl.secret import SecretBox


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

    def invalidate_session(self, contact) -> bool:
        existed = contact.device_id in self.sessions
        self.sessions.discard(contact.device_id)
        return existed


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
        del plaintext
        now = int(time.time())
        return RatchetMessage(
            version=3,
            message_id="a" * 32,
            sender_device_id=cast(FakeRatchetEngine, engine).local_device_id,
            recipient_device_id=contact.device_id,
            created_at=now,
            expires_at=now + 3_600,
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


def _import_and_trust_contact(
    owner_profile: Path,
    contact_path: Path,
    *,
    label: str,
    password: str,
    password_reader,
    node_client_factory,
    capsys,
) -> str:
    assert run(
        [
            "contact-import",
            "--profile",
            str(owner_profile),
            "--label",
            label,
            str(contact_path),
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0
    capsys.readouterr()

    owner = decrypt_local_profile(owner_profile.read_text(), password)
    assert owner.contact_store_key is not None
    store = load_contact_store(
        Path(f"{owner_profile}.contacts"),
        owner.contact_store_key,
    )
    record = store.list_records()[0]
    contact = import_contact_bundle(contact_path.read_text())
    fingerprint = derive_identity_fingerprint(bytes(contact.identity_verify_key))
    assert run(
        [
            "contact-trust",
            "--profile",
            str(owner_profile),
            "--fingerprint",
            fingerprint,
            record.record_id,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0
    capsys.readouterr()
    return record.record_id


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
    node_url = "https://ghostnode.test"
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
    retired = api_client.get("/v2/messages/" + decrypt_local_profile(
        bob_profile.read_text(),
        "test profile password",
    ).device.device_id)
    assert retired.status_code == 404

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
            "https://ghostnode.test",
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        ratchet_engine_factory=fake_engine_factory({}),
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert calls == [profile.device.device_id]
    assert "published_initial" in captured.out

    lifecycle = node_client_factory(
        "https://ghostnode.test"
    ).get_device_lifecycle(profile.entity.ghost_id)
    assert lifecycle.active_device_id == profile.device.device_id
    assert profile.device_lifecycle is not None
    assert lifecycle.epoch == profile.device_lifecycle.statement.epoch


def test_device_recovery_does_not_promote_before_relay_revocation(
    tmp_path: Path,
    capsys,
) -> None:
    api_client = TestClient(create_app())
    real_requester = create_test_requester(api_client)
    lifecycle_puts = 0

    def failing_requester(
        method: str,
        url: str,
        payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        nonlocal lifecycle_puts
        path = urllib.parse.urlparse(url).path
        if method == "PUT" and path.startswith("/v3/device-lifecycle/"):
            lifecycle_puts += 1
            if lifecycle_puts == 2:
                return 503, {"detail": "injected lifecycle outage"}
        return real_requester(method, url, payload, timeout, headers)

    def failing_factory(base_url: str) -> GhostNodeClient:
        return GhostNodeClient(base_url, requester=failing_requester)

    def healthy_factory(base_url: str) -> GhostNodeClient:
        return GhostNodeClient(base_url, requester=real_requester)

    password_reader = lambda prompt: "recovery relay password"  # noqa: E731
    profile_path = tmp_path / "relay-recovery.ghost"
    node_url = "https://ghostnode.test"

    assert run(
        ["init", "--profile", str(profile_path)],
        password_reader=password_reader,
    ) == 0
    capsys.readouterr()

    before = decrypt_local_profile(
        profile_path.read_text(),
        "recovery relay password",
    )
    assert before.device_lifecycle is not None

    failed = run(
        [
            "device-recover",
            "--profile",
            str(profile_path),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=failing_factory,
    )
    failed_output = capsys.readouterr()
    assert failed == 1
    assert "injected lifecycle outage" in failed_output.err

    still_active = decrypt_local_profile(
        profile_path.read_text(),
        "recovery relay password",
    )
    assert still_active.device.device_id == before.device.device_id
    pending_path = Path(f"{profile_path}.device-recovery.pending")
    assert pending_path.exists()

    relay_before = healthy_factory(node_url).get_device_lifecycle(
        before.entity.ghost_id
    )
    assert relay_before.active_device_id == before.device.device_id
    assert relay_before.epoch == before.device_lifecycle.statement.epoch

    resumed = run(
        [
            "device-recover",
            "--profile",
            str(profile_path),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=healthy_factory,
    )
    assert resumed == 0
    capsys.readouterr()

    after = decrypt_local_profile(
        profile_path.read_text(),
        "recovery relay password",
    )
    assert after.device_lifecycle is not None
    assert after.device.device_id != before.device.device_id
    assert not pending_path.exists()

    relay_after = healthy_factory(node_url).get_device_lifecycle(
        after.entity.ghost_id
    )
    assert relay_after.active_device_id == after.device.device_id
    assert relay_after.epoch == after.device_lifecycle.statement.epoch

    with pytest.raises(GhostNodeRequestError) as revoked:
        healthy_factory(node_url).prekey_status(before.device)
    assert revoked.value.status_code == 401


def test_new_private_file_fsyncs_file_and_parent_directory(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / "durable-private.ghost"
    real_fsync = cli_module.os.fsync
    synced: list[str] = []

    def record_fsync(descriptor: int) -> None:
        mode = cli_module.os.fstat(descriptor).st_mode
        synced.append("directory" if stat.S_ISDIR(mode) else "file")
        real_fsync(descriptor)

    monkeypatch.setattr(cli_module.os, "fsync", record_fsync)
    cli_module._write_new_private_file(path, "encrypted-profile")

    assert path.read_text(encoding="utf-8") == "encrypted-profile"
    assert synced[0] == "file"
    if cli_module.os.name == "posix":
        assert synced[-1] == "directory"
    with pytest.raises(FileExistsError):
        cli_module._write_new_private_file(path, "replacement")
    assert path.read_text(encoding="utf-8") == "encrypted-profile"


def test_init_removes_profile_after_private_file_fsync_failure(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    password = "durable init password"  # noqa: S105
    password_reader = lambda prompt: password  # noqa: E731
    profile_path = tmp_path / "durable-init.ghost"
    real_fsync = cli_module.os.fsync

    def fail_regular_file_fsync(descriptor: int) -> None:
        if stat.S_ISREG(cli_module.os.fstat(descriptor).st_mode):
            raise OSError("injected private file fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(cli_module.os, "fsync", fail_regular_file_fsync)
    assert run(
        ["init", "--profile", str(profile_path)],
        password_reader=password_reader,
    ) == 1
    failed = capsys.readouterr()
    assert "injected private file fsync failure" in failed.err
    assert not profile_path.exists()

    monkeypatch.setattr(cli_module.os, "fsync", real_fsync)
    assert run(
        ["init", "--profile", str(profile_path)],
        password_reader=password_reader,
    ) == 0
    capsys.readouterr()
    assert profile_path.is_file()


def test_device_recovery_retries_after_initial_lifecycle_publication_failure(
    tmp_path: Path,
    capsys,
) -> None:
    api_client = TestClient(create_app())
    real_requester = create_test_requester(api_client)
    failed_once = False

    def failing_requester(
        method: str,
        url: str,
        payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        nonlocal failed_once
        path = urllib.parse.urlparse(url).path
        if (
            not failed_once
            and method == "PUT"
            and path.startswith("/v3/device-lifecycle/")
        ):
            failed_once = True
            return 503, {"detail": "injected initial lifecycle outage"}
        return real_requester(method, url, payload, timeout, headers)

    def failing_factory(base_url: str) -> GhostNodeClient:
        return GhostNodeClient(base_url, requester=failing_requester)

    def healthy_factory(base_url: str) -> GhostNodeClient:
        return GhostNodeClient(base_url, requester=real_requester)

    password = "initial lifecycle recovery password"  # noqa: S105
    password_reader = lambda prompt: password  # noqa: E731
    profile_path = tmp_path / "initial-lifecycle-recovery.ghost"
    pending_path = Path(f"{profile_path}.device-recovery.pending")
    node_url = "https://ghostnode.test"
    assert run(
        ["init", "--profile", str(profile_path)],
        password_reader=password_reader,
    ) == 0
    capsys.readouterr()

    before = decrypt_local_profile(profile_path.read_text(), password)
    assert before.device_lifecycle is not None
    assert run(
        [
            "device-recover",
            "--profile",
            str(profile_path),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=failing_factory,
    ) == 1
    failed = capsys.readouterr()
    assert "injected initial lifecycle outage" in failed.err
    assert not pending_path.exists()

    still_active = decrypt_local_profile(profile_path.read_text(), password)
    assert still_active.device.device_id == before.device.device_id
    with pytest.raises(GhostNodeRequestError) as missing:
        healthy_factory(node_url).get_device_lifecycle(before.entity.ghost_id)
    assert missing.value.status_code == 404

    assert run(
        [
            "device-recover",
            "--profile",
            str(profile_path),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=healthy_factory,
    ) == 0
    capsys.readouterr()

    recovered = decrypt_local_profile(profile_path.read_text(), password)
    assert recovered.device_lifecycle is not None
    assert (
        recovered.device_lifecycle.statement.epoch
        == before.device_lifecycle.statement.epoch + 1
    )


def test_device_recovery_retries_after_pending_profile_write_failure(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    api_client = TestClient(create_app())
    requester = create_test_requester(api_client)

    def node_client_factory(base_url: str) -> GhostNodeClient:
        return GhostNodeClient(base_url, requester=requester)

    password = "pending write recovery password"  # noqa: S105
    password_reader = lambda prompt: password  # noqa: E731
    profile_path = tmp_path / "pending-write-recovery.ghost"
    node_url = "https://ghostnode.test"
    assert run(
        ["init", "--profile", str(profile_path)],
        password_reader=password_reader,
    ) == 0
    capsys.readouterr()

    before = decrypt_local_profile(profile_path.read_text(), password)
    real_write = cli_module._write_new_private_file

    def fail_write(path: Path, content: str) -> None:
        del path, content
        raise OSError("injected pending profile write failure")

    monkeypatch.setattr(cli_module, "_write_new_private_file", fail_write)
    assert run(
        [
            "device-recover",
            "--profile",
            str(profile_path),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 1
    failed = capsys.readouterr()
    assert "injected pending profile write failure" in failed.err
    assert not Path(f"{profile_path}.device-recovery.pending").exists()

    still_active = decrypt_local_profile(profile_path.read_text(), password)
    assert still_active.device.device_id == before.device.device_id
    relay = node_client_factory(node_url).get_device_lifecycle(
        before.entity.ghost_id
    )
    assert relay.active_device_id == before.device.device_id

    monkeypatch.setattr(cli_module, "_write_new_private_file", real_write)
    assert run(
        [
            "device-recover",
            "--profile",
            str(profile_path),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0
    capsys.readouterr()

    recovered = decrypt_local_profile(profile_path.read_text(), password)
    assert recovered.device.device_id != before.device.device_id
    assert recovered.device_lifecycle is not None
    assert before.device_lifecycle is not None
    assert (
        recovered.device_lifecycle.statement.epoch
        == before.device_lifecycle.statement.epoch + 1
    )


def test_device_recovery_removes_pending_after_directory_fsync_failure(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    api_client = TestClient(create_app())
    requester = create_test_requester(api_client)

    def node_client_factory(base_url: str) -> GhostNodeClient:
        return GhostNodeClient(base_url, requester=requester)

    password = "pending fsync recovery password"  # noqa: S105
    password_reader = lambda prompt: password  # noqa: E731
    profile_path = tmp_path / "pending-fsync-recovery.ghost"
    pending_path = Path(f"{profile_path}.device-recovery.pending")
    node_url = "https://ghostnode.test"
    assert run(
        ["init", "--profile", str(profile_path)],
        password_reader=password_reader,
    ) == 0
    capsys.readouterr()

    before = decrypt_local_profile(profile_path.read_text(), password)
    real_fsync_directory = cli_module._fsync_directory

    def fail_directory_fsync(path: Path) -> None:
        del path
        raise OSError("injected pending directory fsync failure")

    monkeypatch.setattr(cli_module, "_fsync_directory", fail_directory_fsync)
    assert run(
        [
            "device-recover",
            "--profile",
            str(profile_path),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 1
    failed = capsys.readouterr()
    assert "injected pending directory fsync failure" in failed.err
    assert not pending_path.exists()

    unchanged = decrypt_local_profile(profile_path.read_text(), password)
    assert unchanged.device.device_id == before.device.device_id
    relay = node_client_factory(node_url).get_device_lifecycle(
        before.entity.ghost_id
    )
    assert relay.active_device_id == before.device.device_id

    monkeypatch.setattr(
        cli_module,
        "_fsync_directory",
        real_fsync_directory,
    )
    assert run(
        [
            "device-recover",
            "--profile",
            str(profile_path),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0
    capsys.readouterr()

    recovered = decrypt_local_profile(profile_path.read_text(), password)
    assert recovered.device.device_id != before.device.device_id


def test_device_recovery_resumes_same_candidate_after_profile_promotion_failure(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    api_client = TestClient(create_app())
    requester = create_test_requester(api_client)

    def node_client_factory(base_url: str) -> GhostNodeClient:
        return GhostNodeClient(base_url, requester=requester)

    password = "promotion failure recovery password"  # noqa: S105
    password_reader = lambda prompt: password  # noqa: E731
    profile_path = tmp_path / "promotion-failure-recovery.ghost"
    pending_path = Path(f"{profile_path}.device-recovery.pending")
    node_url = "https://ghostnode.test"
    assert run(
        ["init", "--profile", str(profile_path)],
        password_reader=password_reader,
    ) == 0
    capsys.readouterr()

    before = decrypt_local_profile(profile_path.read_text(), password)
    real_replace = cli_module.os.replace

    def fail_promotion(source, destination) -> None:
        if Path(source) == pending_path and Path(destination) == profile_path:
            raise OSError("injected profile promotion failure")
        real_replace(source, destination)

    monkeypatch.setattr(cli_module.os, "replace", fail_promotion)
    assert run(
        [
            "device-recover",
            "--profile",
            str(profile_path),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 1
    failed = capsys.readouterr()
    assert "injected profile promotion failure" in failed.err
    assert pending_path.exists()

    candidate = decrypt_local_profile(pending_path.read_text(), password)
    still_active = decrypt_local_profile(profile_path.read_text(), password)
    assert still_active.device.device_id == before.device.device_id
    relay = node_client_factory(node_url).get_device_lifecycle(
        before.entity.ghost_id
    )
    assert relay.active_device_id == candidate.device.device_id

    monkeypatch.setattr(cli_module.os, "replace", real_replace)
    assert run(
        [
            "device-recover",
            "--profile",
            str(profile_path),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0
    capsys.readouterr()

    recovered = decrypt_local_profile(profile_path.read_text(), password)
    assert recovered.device.device_id == candidate.device.device_id
    assert not pending_path.exists()


def test_device_recovery_retry_after_post_promotion_fsync_starts_fresh_rotation(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    api_client = TestClient(create_app())
    requester = create_test_requester(api_client)

    def node_client_factory(base_url: str) -> GhostNodeClient:
        return GhostNodeClient(base_url, requester=requester)

    password = "post promotion fsync password"  # noqa: S105
    password_reader = lambda prompt: password  # noqa: E731
    profile_path = tmp_path / "post-promotion-fsync.ghost"
    node_url = "https://ghostnode.test"
    assert run(
        ["init", "--profile", str(profile_path)],
        password_reader=password_reader,
    ) == 0
    capsys.readouterr()

    before = decrypt_local_profile(profile_path.read_text(), password)
    assert before.device_lifecycle is not None
    real_fsync = cli_module._fsync_directory
    fsync_calls = 0

    def fail_fsync(path: Path) -> None:
        nonlocal fsync_calls
        fsync_calls += 1
        if fsync_calls == 2:
            raise OSError("injected post-promotion fsync failure")
        real_fsync(path)

    monkeypatch.setattr(cli_module, "_fsync_directory", fail_fsync)
    assert run(
        [
            "device-recover",
            "--profile",
            str(profile_path),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 1
    failed = capsys.readouterr()
    assert "injected post-promotion fsync failure" in failed.err

    promoted = decrypt_local_profile(profile_path.read_text(), password)
    assert promoted.device.device_id != before.device.device_id
    assert promoted.device_lifecycle is not None
    assert (
        promoted.device_lifecycle.statement.epoch
        == before.device_lifecycle.statement.epoch + 1
    )
    assert not Path(f"{profile_path}.device-recovery.pending").exists()

    monkeypatch.setattr(cli_module, "_fsync_directory", real_fsync)
    assert run(
        [
            "device-recover",
            "--profile",
            str(profile_path),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0
    capsys.readouterr()

    recovered = decrypt_local_profile(profile_path.read_text(), password)
    assert recovered.device_lifecycle is not None
    assert recovered.device.device_id != promoted.device.device_id
    assert (
        recovered.device_lifecycle.statement.epoch
        == promoted.device_lifecycle.statement.epoch + 1
    )


def test_device_recovery_retry_after_profile_witness_failure_starts_fresh_rotation(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    api_client = TestClient(create_app())
    requester = create_test_requester(api_client)

    def node_client_factory(base_url: str) -> GhostNodeClient:
        return GhostNodeClient(base_url, requester=requester)

    password = "profile witness recovery password"  # noqa: S105
    password_reader = lambda prompt: password  # noqa: E731
    profile_path = tmp_path / "profile-witness-recovery.ghost"
    node_url = "https://ghostnode.test"
    assert run(
        ["init", "--profile", str(profile_path)],
        password_reader=password_reader,
    ) == 0
    capsys.readouterr()

    before = decrypt_local_profile(profile_path.read_text(), password)
    assert before.device_lifecycle is not None
    real_reconcile = cli_module.reconcile_profile_witness
    calls = 0

    def fail_second_reconcile(profile, witness):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise cli_module.CLIError("injected profile witness reconciliation failure")
        return real_reconcile(profile, witness)

    monkeypatch.setattr(
        cli_module,
        "reconcile_profile_witness",
        fail_second_reconcile,
    )
    assert run(
        [
            "device-recover",
            "--profile",
            str(profile_path),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 1
    failed = capsys.readouterr()
    assert "injected profile witness reconciliation failure" in failed.err

    promoted = decrypt_local_profile(profile_path.read_text(), password)
    assert promoted.device_lifecycle is not None
    assert promoted.device.device_id != before.device.device_id
    assert (
        promoted.device_lifecycle.statement.epoch
        == before.device_lifecycle.statement.epoch + 1
    )

    monkeypatch.setattr(
        cli_module,
        "reconcile_profile_witness",
        real_reconcile,
    )
    assert run(
        [
            "device-recover",
            "--profile",
            str(profile_path),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0
    capsys.readouterr()

    recovered = decrypt_local_profile(profile_path.read_text(), password)
    assert recovered.device_lifecycle is not None
    assert recovered.device.device_id != promoted.device.device_id
    assert (
        recovered.device_lifecycle.statement.epoch
        == promoted.device_lifecycle.statement.epoch + 1
    )


def test_device_recovery_rejects_cleanup_archive_without_replacement_vault(
    tmp_path: Path,
    capsys,
) -> None:
    api_client = TestClient(create_app())
    requester = create_test_requester(api_client)

    def node_client_factory(base_url: str) -> GhostNodeClient:
        return GhostNodeClient(base_url, requester=requester)

    password = "archive without witness password"  # noqa: S105
    password_reader = lambda prompt: password  # noqa: E731
    profile_path = tmp_path / "archive-without-witness.ghost"
    backup_path = Path(f"{profile_path}.ratchet.device-recovery-old")
    assert run(
        ["init", "--profile", str(profile_path)],
        password_reader=password_reader,
    ) == 0
    capsys.readouterr()

    backup_path.write_bytes(b"stale archive")
    assert run(
        [
            "device-recover",
            "--profile",
            str(profile_path),
            "--node",
            "https://ghostnode.test",
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 1
    failed = capsys.readouterr()
    assert "replacement ratchet vault is missing" in failed.err

    active = decrypt_local_profile(profile_path.read_text(), password)
    assert active.entity.ghost_id
    with pytest.raises(GhostNodeRequestError) as missing_lifecycle:
        node_client_factory("https://ghostnode.test").get_device_lifecycle(
            active.entity.ghost_id
        )
    assert missing_lifecycle.value.status_code == 404
    assert backup_path.exists()


def test_device_recovery_rejects_pending_archive_without_ratchet_witness(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    api_client = TestClient(create_app())
    requester = create_test_requester(api_client)

    def node_client_factory(base_url: str) -> GhostNodeClient:
        return GhostNodeClient(base_url, requester=requester)

    password = "pending archive witness password"  # noqa: S105
    password_reader = lambda prompt: password  # noqa: E731
    profile_path = tmp_path / "pending-archive-witness.ghost"
    pending_path = Path(f"{profile_path}.device-recovery.pending")
    backup_path = Path(f"{profile_path}.ratchet.device-recovery-old")
    node_url = "https://ghostnode.test"
    assert run(
        ["init", "--profile", str(profile_path)],
        password_reader=password_reader,
    ) == 0
    capsys.readouterr()

    before = decrypt_local_profile(profile_path.read_text(), password)
    real_replace = cli_module.os.replace

    def fail_promotion(source, destination) -> None:
        if Path(source) == pending_path and Path(destination) == profile_path:
            raise OSError("injected profile promotion failure")
        real_replace(source, destination)

    monkeypatch.setattr(cli_module.os, "replace", fail_promotion)
    assert run(
        [
            "device-recover",
            "--profile",
            str(profile_path),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 1
    capsys.readouterr()
    assert pending_path.exists()

    monkeypatch.setattr(cli_module.os, "replace", real_replace)
    backup_path.write_bytes(b"orphaned old ratchet archive")
    assert run(
        [
            "device-recover",
            "--profile",
            str(profile_path),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 1
    failed = capsys.readouterr()
    assert "device recovery archive exists without ratchet witness" in failed.err

    still_active = decrypt_local_profile(profile_path.read_text(), password)
    assert still_active.device.device_id == before.device.device_id
    assert pending_path.exists()
    assert backup_path.exists()


def test_device_recovery_rejects_vault_witness_existence_mismatch(
    tmp_path: Path,
    capsys,
) -> None:
    api_client = TestClient(create_app())
    requester = create_test_requester(api_client)

    def node_client_factory(base_url: str) -> GhostNodeClient:
        return GhostNodeClient(base_url, requester=requester)

    password = "vault witness mismatch password"  # noqa: S105
    password_reader = lambda prompt: password  # noqa: E731
    profile_path = tmp_path / "vault-witness-mismatch.ghost"
    vault_path = Path(f"{profile_path}.ratchet")
    pending_path = Path(f"{profile_path}.device-recovery.pending")
    assert run(
        ["init", "--profile", str(profile_path)],
        password_reader=password_reader,
    ) == 0
    capsys.readouterr()

    before = decrypt_local_profile(profile_path.read_text(), password)
    vault_path.write_bytes(b"unwitnessed ratchet vault")
    assert run(
        [
            "device-recover",
            "--profile",
            str(profile_path),
            "--node",
            "https://ghostnode.test",
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 1
    failed = capsys.readouterr()
    assert "ratchet vault/witness mismatch" in failed.err

    still_active = decrypt_local_profile(profile_path.read_text(), password)
    assert still_active.device.device_id == before.device.device_id
    assert pending_path.exists()
    assert vault_path.exists()


def test_device_recovery_retries_final_cleanup_without_rotating_again(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    api_client = TestClient(create_app())
    requester = create_test_requester(api_client)

    def node_client_factory(base_url: str) -> GhostNodeClient:
        return GhostNodeClient(base_url, requester=requester)

    password = "cleanup retry password"  # noqa: S105
    password_reader = lambda prompt: password  # noqa: E731
    profile_path = tmp_path / "cleanup-retry.ghost"
    vault_path = Path(f"{profile_path}.ratchet")
    backup_path = Path(f"{profile_path}.ratchet.device-recovery-old")
    node_url = "https://ghostnode.test"

    assert run(
        ["init", "--profile", str(profile_path)],
        password_reader=password_reader,
    ) == 0
    capsys.readouterr()
    assert run(
        [
            "device-recover",
            "--profile",
            str(profile_path),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0
    capsys.readouterr()

    active = decrypt_local_profile(profile_path.read_text(), password)
    assert active.device_lifecycle is not None
    active_epoch = active.device_lifecycle.statement.epoch
    vault_path.write_bytes(b"replacement vault placeholder")
    backup_path.write_bytes(b"old vault placeholder")

    class FakeEngine:
        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            del args

    monkeypatch.setattr(
        cli_module,
        "_create_ratchet_engine",
        lambda *args, **kwargs: FakeEngine(),
    )
    real_unlink = cli_module._unlink_file_durable

    def fail_cleanup(path: Path) -> None:
        if path == backup_path:
            raise OSError("injected recovery archive cleanup failure")
        real_unlink(path)

    monkeypatch.setattr(cli_module, "_unlink_file_durable", fail_cleanup)
    assert run(
        [
            "device-recover",
            "--profile",
            str(profile_path),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 1
    failed = capsys.readouterr()
    assert "injected recovery archive cleanup failure" in failed.err
    assert backup_path.exists()

    monkeypatch.setattr(cli_module, "_unlink_file_durable", real_unlink)
    assert run(
        [
            "device-recover",
            "--profile",
            str(profile_path),
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0
    capsys.readouterr()

    finalized = decrypt_local_profile(profile_path.read_text(), password)
    assert finalized.device.device_id == active.device.device_id
    assert finalized.device_lifecycle is not None
    assert finalized.device_lifecycle.statement.epoch == active_epoch
    assert not backup_path.exists()
    assert vault_path.exists()


def test_cli_send_refreshes_verified_contact_after_remote_device_rotation(
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

    password = "remote lifecycle refresh password"  # noqa: S105
    password_reader = lambda prompt: password  # noqa: E731
    alice_profile, bob_profile, _alice_contact, bob_contact = (
        _create_profiles_and_contacts(
            tmp_path,
            capsys,
            password_reader,
            node_client_factory,
        )
    )
    node_url = "https://ghostnode.test"

    assert run(
        [
            "contact-import",
            "--profile",
            str(alice_profile),
            "--label",
            "Bob",
            str(bob_contact),
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0
    capsys.readouterr()

    alice = decrypt_local_profile(alice_profile.read_text(), password)
    assert alice.contact_store_key is not None
    store_path = Path(f"{alice_profile}.contacts")
    store = load_contact_store(store_path, alice.contact_store_key)
    record = store.list_records()[0]
    bob_contact_value = import_contact_bundle(bob_contact.read_text())
    fingerprint = derive_identity_fingerprint(
        bytes(bob_contact_value.identity_verify_key)
    )
    assert run(
        [
            "contact-trust",
            "--profile",
            str(alice_profile),
            "--fingerprint",
            fingerprint,
            record.record_id,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0
    capsys.readouterr()

    bob = decrypt_local_profile(bob_profile.read_text(), password)
    assert bob.device_lifecycle is not None
    relay = node_client_factory(node_url)
    relay.publish_device_lifecycle(
        bytes(bob.entity.verify_key),
        bob.device_lifecycle,
    )

    engine_factory = fake_engine_factory(session_state)
    send_args = [
        "send",
        "--profile",
        str(alice_profile),
        "--contact-id",
        record.record_id,
        "--node",
        node_url,
        "before rotation",
    ]
    assert run(
        send_args,
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        ratchet_engine_factory=engine_factory,
    ) == 0
    capsys.readouterr()

    old_device_id = bob.device.device_id
    assert old_device_id in session_state[str(alice_profile)]

    replacement = bob.entity.enroll_device()
    replacement_lifecycle = create_device_lifecycle_statement(
        bob.entity,
        replacement,
        epoch=bob.device_lifecycle.statement.epoch + 1,
        issued_at=bob.device_lifecycle.statement.issued_at + 1,
    )
    relay.publish_device_lifecycle(
        bytes(bob.entity.verify_key),
        replacement_lifecycle,
    )

    send_args[-1] = "after rotation"
    assert run(
        send_args,
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        ratchet_engine_factory=engine_factory,
    ) == 0
    capsys.readouterr()

    restored = load_contact_store(store_path, alice.contact_store_key)
    refreshed = restored.require_verified_contact(record.record_id)
    assert refreshed.device_id == replacement.device_id
    assert refreshed.lifecycle_epoch == replacement_lifecycle.statement.epoch
    assert old_device_id not in session_state[str(alice_profile)]
    assert replacement.device_id in session_state[str(alice_profile)]


def test_contact_refresh_rejects_newer_epoch_with_regressed_issued_at(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    api_client = TestClient(create_app())
    requester = create_test_requester(api_client)
    install_fake_ratchet_operations(monkeypatch)

    def node_client_factory(base_url: str) -> GhostNodeClient:
        return GhostNodeClient(base_url, requester=requester)

    password = "regressed lifecycle refresh password"  # noqa: S105
    password_reader = lambda prompt: password  # noqa: E731
    alice_profile, bob_profile, _alice_contact, bob_contact = (
        _create_profiles_and_contacts(
            tmp_path,
            capsys,
            password_reader,
            node_client_factory,
        )
    )
    record_id = _import_and_trust_contact(
        alice_profile,
        bob_contact,
        label="Bob",
        password=password,
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        capsys=capsys,
    )

    alice = decrypt_local_profile(alice_profile.read_text(), password)
    bob = decrypt_local_profile(bob_profile.read_text(), password)
    assert alice.contact_store_key is not None
    assert bob.device_lifecycle is not None

    store_path = Path(f"{alice_profile}.contacts")
    store = load_contact_store(store_path, alice.contact_store_key)
    current = store.require_verified_contact(record_id)
    assert current.lifecycle_issued_at == bob.device_lifecycle.statement.issued_at

    replacement = bob.entity.enroll_device()
    regressed = create_device_lifecycle_statement(
        bob.entity,
        replacement,
        epoch=bob.device_lifecycle.statement.epoch + 1,
        issued_at=bob.device_lifecycle.statement.issued_at - 1,
    )
    relay_record = SimpleNamespace(
        identity_public_key=bytes(bob.entity.verify_key),
        lifecycle=regressed,
    )

    class MaliciousLifecycleClient:
        def get_device_lifecycle(self, ghost_id: str):
            assert ghost_id == bob.entity.ghost_id
            return relay_record

    sessions = {current.device_id}
    engine = FakeRatchetEngine(alice, sessions)
    args = SimpleNamespace(contact_id=record_id, contacts=None)

    with pytest.raises(ContactTrustError, match="issued_at rollback"):
        cli_module._refresh_message_contact_lifecycle(
            args,
            alice_profile,
            alice,
            cast(GhostNodeClient, MaliciousLifecycleClient()),
            cast(RatchetEngineClient, engine),
            current,
        )

    restored = load_contact_store(store_path, alice.contact_store_key)
    unchanged = restored.require_verified_contact(record_id)
    assert unchanged.device_id == current.device_id
    assert unchanged.lifecycle_epoch == current.lifecycle_epoch
    assert unchanged.lifecycle_issued_at == current.lifecycle_issued_at
    assert sessions == {current.device_id}


def test_verified_peer_stays_on_old_device_when_relay_only_knows_old_epoch(
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

    password = "stale relay password"  # noqa: S105
    password_reader = lambda prompt: password  # noqa: E731
    alice_profile, bob_profile, _alice_contact, bob_contact = (
        _create_profiles_and_contacts(
            tmp_path,
            capsys,
            password_reader,
            node_client_factory,
        )
    )
    record_id = _import_and_trust_contact(
        alice_profile,
        bob_contact,
        label="Bob",
        password=password,
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        capsys=capsys,
    )
    node_url = "https://ghostnode.test"
    relay = node_client_factory(node_url)
    bob = decrypt_local_profile(bob_profile.read_text(), password)
    assert bob.device_lifecycle is not None
    relay.publish_device_lifecycle(
        bytes(bob.entity.verify_key),
        bob.device_lifecycle,
    )

    replacement = bob.entity.enroll_device()
    replacement_lifecycle = create_device_lifecycle_statement(
        bob.entity,
        replacement,
        epoch=bob.device_lifecycle.statement.epoch + 1,
        issued_at=bob.device_lifecycle.statement.issued_at + 1,
    )
    assert replacement_lifecycle.statement.epoch == 2

    session_state[str(alice_profile)] = {bob.device.device_id}
    assert run(
        [
            "send",
            "--profile",
            str(alice_profile),
            "--contact-id",
            record_id,
            "--node",
            node_url,
            "relay still knows epoch N",
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        ratchet_engine_factory=fake_engine_factory(session_state),
    ) == 0
    capsys.readouterr()

    alice = decrypt_local_profile(alice_profile.read_text(), password)
    assert alice.contact_store_key is not None
    persisted = load_contact_store(
        Path(f"{alice_profile}.contacts"),
        alice.contact_store_key,
    ).require_verified_contact(record_id)
    assert persisted.device_id == bob.device.device_id
    assert persisted.lifecycle_epoch == bob.device_lifecycle.statement.epoch
    assert session_state[str(alice_profile)] == {bob.device.device_id}
    assert replacement.device_id not in session_state[str(alice_profile)]


def test_verified_peer_keeps_current_contact_when_relay_has_no_lifecycle(
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

    password = "missing relay lifecycle password"  # noqa: S105
    password_reader = lambda prompt: password  # noqa: E731
    alice_profile, bob_profile, _alice_contact, bob_contact = (
        _create_profiles_and_contacts(
            tmp_path,
            capsys,
            password_reader,
            node_client_factory,
        )
    )
    record_id = _import_and_trust_contact(
        alice_profile,
        bob_contact,
        label="Bob",
        password=password,
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        capsys=capsys,
    )
    bob = decrypt_local_profile(bob_profile.read_text(), password)
    session_state[str(alice_profile)] = {bob.device.device_id}
    node_url = "https://ghostnode.test"

    with pytest.raises(GhostNodeRequestError) as missing:
        node_client_factory(node_url).get_device_lifecycle(bob.entity.ghost_id)
    assert missing.value.status_code == 404

    assert run(
        [
            "send",
            "--profile",
            str(alice_profile),
            "--contact-id",
            record_id,
            "--node",
            node_url,
            "404 does not invent a rotation",
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        ratchet_engine_factory=fake_engine_factory(session_state),
    ) == 0
    capsys.readouterr()

    alice = decrypt_local_profile(alice_profile.read_text(), password)
    assert alice.contact_store_key is not None
    persisted = load_contact_store(
        Path(f"{alice_profile}.contacts"),
        alice.contact_store_key,
    ).require_verified_contact(record_id)
    assert persisted.device_id == bob.device.device_id
    assert session_state[str(alice_profile)] == {bob.device.device_id}


def test_remote_rotation_invalidation_failure_keeps_old_contact_and_session(
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

    password = "invalidation failure password"  # noqa: S105
    password_reader = lambda prompt: password  # noqa: E731
    alice_profile, bob_profile, _alice_contact, bob_contact = (
        _create_profiles_and_contacts(
            tmp_path,
            capsys,
            password_reader,
            node_client_factory,
        )
    )
    record_id = _import_and_trust_contact(
        alice_profile,
        bob_contact,
        label="Bob",
        password=password,
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        capsys=capsys,
    )
    bob = decrypt_local_profile(bob_profile.read_text(), password)
    assert bob.device_lifecycle is not None
    relay = node_client_factory("https://ghostnode.test")
    relay.publish_device_lifecycle(
        bytes(bob.entity.verify_key),
        bob.device_lifecycle,
    )
    replacement = bob.entity.enroll_device()
    replacement_lifecycle = create_device_lifecycle_statement(
        bob.entity,
        replacement,
        epoch=bob.device_lifecycle.statement.epoch + 1,
        issued_at=bob.device_lifecycle.statement.issued_at + 1,
    )
    relay.publish_device_lifecycle(
        bytes(bob.entity.verify_key),
        replacement_lifecycle,
    )

    old_device_id = bob.device.device_id
    session_state[str(alice_profile)] = {old_device_id}
    real_invalidate = FakeRatchetEngine.invalidate_session

    def fail_invalidation(self, contact) -> bool:
        del self, contact
        raise cli_module.CLIError("injected session invalidation failure")

    monkeypatch.setattr(
        FakeRatchetEngine,
        "invalidate_session",
        fail_invalidation,
    )
    send_args = [
        "send",
        "--profile",
        str(alice_profile),
        "--contact-id",
        record_id,
        "--node",
        "https://ghostnode.test",
        "must fail before contact persistence",
    ]
    assert run(
        send_args,
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        ratchet_engine_factory=fake_engine_factory(session_state),
    ) == 1
    failed = capsys.readouterr()
    assert "injected session invalidation failure" in failed.err

    alice = decrypt_local_profile(alice_profile.read_text(), password)
    assert alice.contact_store_key is not None
    persisted = load_contact_store(
        Path(f"{alice_profile}.contacts"),
        alice.contact_store_key,
    ).require_verified_contact(record_id)
    assert persisted.device_id == old_device_id
    assert session_state[str(alice_profile)] == {old_device_id}

    monkeypatch.setattr(
        FakeRatchetEngine,
        "invalidate_session",
        real_invalidate,
    )
    assert run(
        send_args,
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        ratchet_engine_factory=fake_engine_factory(session_state),
    ) == 0
    capsys.readouterr()

    refreshed = load_contact_store(
        Path(f"{alice_profile}.contacts"),
        alice.contact_store_key,
    ).require_verified_contact(record_id)
    assert refreshed.device_id == replacement.device_id
    assert old_device_id not in session_state[str(alice_profile)]
    assert replacement.device_id in session_state[str(alice_profile)]


def test_remote_rotation_contact_save_failure_is_resumable_after_invalidation(
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

    password = "contact save failure password"  # noqa: S105
    password_reader = lambda prompt: password  # noqa: E731
    alice_profile, bob_profile, _alice_contact, bob_contact = (
        _create_profiles_and_contacts(
            tmp_path,
            capsys,
            password_reader,
            node_client_factory,
        )
    )
    record_id = _import_and_trust_contact(
        alice_profile,
        bob_contact,
        label="Bob",
        password=password,
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        capsys=capsys,
    )
    bob = decrypt_local_profile(bob_profile.read_text(), password)
    assert bob.device_lifecycle is not None
    relay = node_client_factory("https://ghostnode.test")
    relay.publish_device_lifecycle(
        bytes(bob.entity.verify_key),
        bob.device_lifecycle,
    )
    replacement = bob.entity.enroll_device()
    replacement_lifecycle = create_device_lifecycle_statement(
        bob.entity,
        replacement,
        epoch=bob.device_lifecycle.statement.epoch + 1,
        issued_at=bob.device_lifecycle.statement.issued_at + 1,
    )
    relay.publish_device_lifecycle(
        bytes(bob.entity.verify_key),
        replacement_lifecycle,
    )

    old_device_id = bob.device.device_id
    session_state[str(alice_profile)] = {old_device_id}
    real_save = cli_module._save_profile_contact_store

    def fail_save(*args, **kwargs) -> None:
        del args, kwargs
        raise cli_module.CLIError("injected contact-store persistence failure")

    monkeypatch.setattr(cli_module, "_save_profile_contact_store", fail_save)
    send_args = [
        "send",
        "--profile",
        str(alice_profile),
        "--contact-id",
        record_id,
        "--node",
        "https://ghostnode.test",
        "retry after partial refresh",
    ]
    assert run(
        send_args,
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        ratchet_engine_factory=fake_engine_factory(session_state),
    ) == 1
    failed = capsys.readouterr()
    assert "injected contact-store persistence failure" in failed.err

    alice = decrypt_local_profile(alice_profile.read_text(), password)
    assert alice.contact_store_key is not None
    persisted = load_contact_store(
        Path(f"{alice_profile}.contacts"),
        alice.contact_store_key,
    ).require_verified_contact(record_id)
    assert persisted.device_id == old_device_id
    assert old_device_id not in session_state[str(alice_profile)]

    monkeypatch.setattr(cli_module, "_save_profile_contact_store", real_save)
    assert run(
        send_args,
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        ratchet_engine_factory=fake_engine_factory(session_state),
    ) == 0
    capsys.readouterr()

    refreshed = load_contact_store(
        Path(f"{alice_profile}.contacts"),
        alice.contact_store_key,
    ).require_verified_contact(record_id)
    assert refreshed.device_id == replacement.device_id
    assert old_device_id not in session_state[str(alice_profile)]
    assert replacement.device_id in session_state[str(alice_profile)]


def test_stale_queued_message_is_skipped_after_peer_learns_rotation(
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

    password = "stale queued message password"  # noqa: S105
    password_reader = lambda prompt: password  # noqa: E731
    alice_profile, bob_profile, alice_contact, bob_contact = (
        _create_profiles_and_contacts(
            tmp_path,
            capsys,
            password_reader,
            node_client_factory,
        )
    )
    alice_record_id = _import_and_trust_contact(
        bob_profile,
        alice_contact,
        label="Alice",
        password=password,
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        capsys=capsys,
    )
    node_url = "https://ghostnode.test"
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
            "queued before Alice rotates",
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        ratchet_engine_factory=engine_factory,
    ) == 0
    capsys.readouterr()

    alice = decrypt_local_profile(alice_profile.read_text(), password)
    bob = decrypt_local_profile(bob_profile.read_text(), password)
    assert alice.device_lifecycle is not None
    old_alice_device_id = alice.device.device_id
    session_state[str(bob_profile)] = {old_alice_device_id}

    replacement = alice.entity.enroll_device()
    replacement_lifecycle = create_device_lifecycle_statement(
        alice.entity,
        replacement,
        epoch=alice.device_lifecycle.statement.epoch + 1,
        issued_at=alice.device_lifecycle.statement.issued_at + 1,
    )
    relay = node_client_factory(node_url)
    relay.publish_device_lifecycle(
        bytes(alice.entity.verify_key),
        replacement_lifecycle,
    )

    assert run(
        [
            "inbox",
            "--profile",
            str(bob_profile),
            "--contact-id",
            alice_record_id,
            "--node",
            node_url,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        ratchet_engine_factory=engine_factory,
    ) == 0
    inbox = capsys.readouterr()
    assert "queued before Alice rotates" not in inbox.out
    assert "No readable ratcheted messages." in inbox.out
    assert "Skipped 1 ratcheted message" in inbox.err

    assert bob.contact_store_key is not None
    refreshed = load_contact_store(
        Path(f"{bob_profile}.contacts"),
        bob.contact_store_key,
    ).require_verified_contact(alice_record_id)
    assert refreshed.device_id == replacement.device_id
    assert old_alice_device_id not in session_state[str(bob_profile)]

    retained = relay.receive_ratchet(bob.device)
    assert len(retained) == 1
    assert retained[0].sender_device_id == old_alice_device_id


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
            "https://ghostnode.test",
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
    assert api_client.get(f"/v2/messages/{bob.device.device_id}").status_code == 404
    assert node_client_factory(
        "https://ghostnode.test"
    ).receive_ratchet(bob.device) == []


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
    node_url = "https://ghostnode.test"

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
    assert upgraded.contact_store_key is not None
    assert len(upgraded.contact_store_key) == 32
    assert upgraded.contact_store_key != upgraded.ratchet_master_key
    assert upgraded.client_state_id is not None
    assert len(upgraded.client_state_id) == 32
    assert upgraded.state_coordination_key is not None
    assert len(upgraded.state_coordination_key) == 32
    assert upgraded.state_coordination_key not in {
        upgraded.ratchet_master_key,
        upgraded.contact_store_key,
    }
    assert upgraded.state_revision == 1
    assert upgraded.state_previous_digest is None
    assert "upgraded atomically" in captured.out


def test_cli_requires_explicit_contact_store_rollback_migration(
    tmp_path: Path,
    capsys,
) -> None:
    password = "contact rollback migration password"  # noqa: S105
    profile_path = tmp_path / "alice.ghost"
    contacts_path = Path(f"{profile_path}.contacts")

    assert run(
        ["init", "--profile", str(profile_path)],
        password_reader=lambda prompt: password,
    ) == 0
    capsys.readouterr()

    profile = decrypt_local_profile(profile_path.read_text(), password)
    assert profile.contact_store_key is not None
    legacy_store = ContactTrustStore()
    peer = GhostEntity.generate()
    bundle = export_contact_bundle(peer, peer.enroll_device())
    legacy_store.add_contact("Peer", bundle)
    save_contact_store(
        contacts_path,
        profile.contact_store_key,
        legacy_store,
    )

    assert run(
        ["contact-list", "--profile", str(profile_path)],
        password_reader=lambda prompt: password,
    ) == 1
    refused = capsys.readouterr()
    assert "requires explicit rollback-state migration" in refused.err

    assert run(
        ["contact-store-upgrade", "--profile", str(profile_path)],
        password_reader=lambda prompt: password,
    ) == 0
    migrated = capsys.readouterr()
    assert "enrolled in rollback-state witness" in migrated.out

    assert run(
        ["contact-list", "--profile", str(profile_path)],
        password_reader=lambda prompt: password,
    ) == 0
    listed = capsys.readouterr()
    assert "Peer" in listed.out


def test_cli_requires_explicit_replay_state_rollback_migration(
    tmp_path: Path,
    capsys,
) -> None:
    password = "replay rollback migration password"  # noqa: S105
    profile_path = tmp_path / "alice.ghost"
    replay_path = Path(f"{profile_path}.state.sqlite3")

    assert run(
        ["init", "--profile", str(profile_path)],
        password_reader=lambda prompt: password,
    ) == 0
    capsys.readouterr()

    legacy = SQLiteReplayCache(replay_path)
    assert legacy.accept(
        "device1:" + ("a" * 52),
        "1" * 32,
        now=1_000_000,
    )

    assert run(
        ["replay-state-upgrade", "--profile", str(profile_path)],
        password_reader=lambda prompt: password,
    ) == 0
    migrated = capsys.readouterr()
    assert "Replay state enrolled in rollback-state witness." in migrated.out


def test_cli_ratchet_vault_upgrade_uses_explicit_migration_mode(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    password = "ratchet vault migration password"  # noqa: S105
    profile_path = tmp_path / "alice.ghost"
    vault_path = Path(f"{profile_path}.ratchet")

    assert run(
        ["init", "--profile", str(profile_path)],
        password_reader=lambda prompt: password,
    ) == 0
    capsys.readouterr()
    vault_path.write_bytes(b"legacy-vault-placeholder")

    calls: dict[str, object] = {}

    class MigrationEngine:
        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            del args

    def create_engine(
        profile: LocalProfile,
        path: Path,
        *,
        allow_legacy_migration: bool = False,
    ):
        calls["ghost_id"] = profile.entity.ghost_id
        calls["path"] = path
        calls["allow"] = allow_legacy_migration
        return MigrationEngine()

    monkeypatch.setattr(cli_module, "_create_ratchet_engine", create_engine)

    assert run(
        ["ratchet-vault-upgrade", "--profile", str(profile_path)],
        password_reader=lambda prompt: password,
    ) == 0

    output = capsys.readouterr()
    assert calls["path"] == profile_path
    assert calls["allow"] is True
    assert "Ratchet vault enrolled in rollback-state witness." in output.out


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


def test_cli_persists_imported_contact_and_records_human_verification(
    tmp_path: Path,
    capsys,
) -> None:
    password_reader = lambda prompt: "contact trust password"  # noqa: E731
    alice_profile = tmp_path / "alice.ghost"
    bob_profile = tmp_path / "bob.ghost"
    bob_contact = tmp_path / "bob.contact"

    assert run(
        ["init", "--profile", str(alice_profile)],
        password_reader=password_reader,
    ) == 0
    assert run(
        ["init", "--profile", str(bob_profile)],
        password_reader=password_reader,
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
    ) == 0
    capsys.readouterr()

    assert run(
        [
            "contact-import",
            "--profile",
            str(alice_profile),
            "--label",
            "Bob",
            str(bob_contact),
        ],
        password_reader=password_reader,
    ) == 0
    imported_output = capsys.readouterr()
    assert "human verification pending" in imported_output.out

    alice = decrypt_local_profile(
        alice_profile.read_text(),
        "contact trust password",
    )
    assert alice.contact_store_key is not None
    store_path = Path(f"{alice_profile}.contacts")
    store = load_contact_store(store_path, alice.contact_store_key)
    record = store.list_records()[0]
    assert record.state is ContactTrustState.IMPORTED

    bob = import_contact_bundle(bob_contact.read_text())
    fingerprint = derive_identity_fingerprint(bytes(bob.identity_verify_key))

    assert run(
        [
            "contact-show",
            "--profile",
            str(alice_profile),
            record.record_id,
        ],
        password_reader=password_reader,
    ) == 0
    shown = capsys.readouterr()
    assert fingerprint in shown.out
    assert "Trust state: imported" in shown.out

    assert run(
        [
            "contact-trust",
            "--profile",
            str(alice_profile),
            "--fingerprint",
            fingerprint,
            record.record_id,
        ],
        password_reader=password_reader,
    ) == 0
    trusted_output = capsys.readouterr()
    assert "Human identity verification recorded." in trusted_output.out

    restored = load_contact_store(store_path, alice.contact_store_key)
    verified = restored.get(record.record_id)
    assert verified.state is ContactTrustState.VERIFIED
    assert restored.require_verified_contact(record.record_id).ghost_id == bob.ghost_id


def test_cli_send_by_contact_id_requires_verified_state_and_blocks_changes(
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

    password_reader = lambda prompt: "trusted send password"  # noqa: E731
    alice_profile, _bob_profile, _alice_contact, bob_contact = (
        _create_profiles_and_contacts(
            tmp_path,
            capsys,
            password_reader,
            node_client_factory,
        )
    )

    assert run(
        [
            "contact-import",
            "--profile",
            str(alice_profile),
            "--label",
            "Bob",
            str(bob_contact),
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0
    capsys.readouterr()

    alice = decrypt_local_profile(
        alice_profile.read_text(),
        "trusted send password",
    )
    assert alice.contact_store_key is not None
    store_path = Path(f"{alice_profile}.contacts")
    store = load_contact_store(store_path, alice.contact_store_key)
    record = store.list_records()[0]

    blocked = run(
        [
            "send",
            "--profile",
            str(alice_profile),
            "--contact-id",
            record.record_id,
            "--node",
            "https://ghostnode.test",
            "not yet trusted",
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        ratchet_engine_factory=fake_engine_factory(session_state),
    )
    blocked_output = capsys.readouterr()
    assert blocked == 1
    assert "has not been human-verified" in blocked_output.err

    bob = import_contact_bundle(bob_contact.read_text())
    fingerprint = derive_identity_fingerprint(bytes(bob.identity_verify_key))
    assert run(
        [
            "contact-trust",
            "--profile",
            str(alice_profile),
            "--fingerprint",
            fingerprint,
            record.record_id,
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0
    capsys.readouterr()

    assert run(
        [
            "send",
            "--profile",
            str(alice_profile),
            "--contact-id",
            record.record_id,
            "--node",
            "https://ghostnode.test",
            "trusted message",
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        ratchet_engine_factory=fake_engine_factory(session_state),
    ) == 0
    sent = capsys.readouterr()
    assert "Ratcheted message queued:" in sent.out
    assert "human verification state is bypassed" not in sent.out

    replacement = GhostEntity.generate()
    replacement_bundle = tmp_path / "replacement.contact"
    replacement_bundle.write_text(
        export_contact_bundle(replacement, replacement.enroll_device()),
        encoding="utf-8",
    )

    assert run(
        [
            "contact-update",
            "--profile",
            str(alice_profile),
            record.record_id,
            str(replacement_bundle),
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0
    changed_output = capsys.readouterr()
    assert "IDENTITY CHANGED" in changed_output.err
    assert "Trust state: changed" in changed_output.out

    blocked_changed = run(
        [
            "send",
            "--profile",
            str(alice_profile),
            "--contact-id",
            record.record_id,
            "--node",
            "https://ghostnode.test",
            "must fail closed",
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
        ratchet_engine_factory=fake_engine_factory(session_state),
    )
    changed_send = capsys.readouterr()
    assert blocked_changed == 1
    assert "identity changed and requires re-verification" in changed_send.err


def test_cli_does_not_expose_retired_static_v2_smoke_command() -> None:
    assert "node-smoke" not in cli_module.build_parser().format_help()


def test_cli_contact_qr_export_and_import_remain_human_unverified(
    tmp_path: Path,
    capsys,
) -> None:
    unlock_phrase = "qr integration password"

    def password_reader(prompt: str) -> str:
        del prompt
        return unlock_phrase

    alice_path = tmp_path / "alice-qr.ghost"
    bob_path = tmp_path / "bob-qr.ghost"
    for profile_path in (alice_path, bob_path):
        assert run(
            ["init", "--profile", str(profile_path)],
            password_reader=password_reader,
        ) == 0
    capsys.readouterr()

    qr_path = tmp_path / "alice-contact.svg"
    assert run(
        [
            "contact-export-qr",
            "--profile",
            str(alice_path),
            "--output",
            str(qr_path),
        ],
        password_reader=password_reader,
    ) == 0
    exported = capsys.readouterr()
    assert "Public contact QR created:" in exported.out
    assert qr_path.read_text(encoding="utf-8").startswith("<svg")

    alice = decrypt_local_profile(alice_path.read_text(encoding="utf-8"), unlock_phrase)
    payload = export_contact_qr_payload(alice.entity, alice.device)

    assert run(
        [
            "contact-import-qr",
            "--profile",
            str(bob_path),
            "--label",
            "Alice QR",
            "--payload",
            payload,
        ],
        password_reader=password_reader,
    ) == 0
    imported = capsys.readouterr()
    assert "cryptographically valid; human verification pending" in imported.out
    assert "Trust state: imported" in imported.out

    bob = decrypt_local_profile(bob_path.read_text(encoding="utf-8"), unlock_phrase)
    assert bob.contact_store_key is not None
    store = load_contact_store(
        Path(f"{bob_path}.contacts"),
        bob.contact_store_key,
    )
    records = store.list_records()
    assert len(records) == 1
    assert records[0].state is ContactTrustState.IMPORTED
    assert records[0].pinned_ghost_id is None



def test_cli_contact_update_qr_quarantines_verified_identity_change(
    tmp_path: Path,
    capsys,
) -> None:
    unlock_phrase = "qr change password"

    def password_reader(prompt: str) -> str:
        del prompt
        return unlock_phrase

    local_profile = tmp_path / "local-qr-change.ghost"
    assert run(
        ["init", "--profile", str(local_profile)],
        password_reader=password_reader,
    ) == 0
    capsys.readouterr()

    alice = GhostEntity.generate()
    alice_device = alice.enroll_device()
    alice_payload = export_contact_qr_payload(alice, alice_device)

    assert run(
        [
            "contact-import-qr",
            "--profile",
            str(local_profile),
            "--label",
            "Alice",
            "--payload",
            alice_payload,
        ],
        password_reader=password_reader,
    ) == 0
    capsys.readouterr()

    local = decrypt_local_profile(
        local_profile.read_text(encoding="utf-8"),
        unlock_phrase,
    )
    assert local.contact_store_key is not None
    store_path = Path(f"{local_profile}.contacts")
    store = load_contact_store(store_path, local.contact_store_key)
    imported = store.list_records()[0]
    alice_fingerprint = derive_identity_fingerprint(bytes(alice.verify_key))

    assert run(
        [
            "contact-trust",
            "--profile",
            str(local_profile),
            "--fingerprint",
            alice_fingerprint,
            imported.record_id,
        ],
        password_reader=password_reader,
    ) == 0
    capsys.readouterr()

    replacement = GhostEntity.generate()
    replacement_payload = export_contact_qr_payload(
        replacement,
        replacement.enroll_device(),
    )
    replacement_fingerprint = derive_identity_fingerprint(
        bytes(replacement.verify_key)
    )

    assert run(
        [
            "contact-update-qr",
            "--profile",
            str(local_profile),
            imported.record_id,
            "--payload",
            replacement_payload,
        ],
        password_reader=password_reader,
    ) == 0
    changed_output = capsys.readouterr()
    assert "IDENTITY CHANGED" in changed_output.err
    assert "Trust state: changed" in changed_output.out
    assert f"Candidate Fingerprint v2: {replacement_fingerprint}" in changed_output.out

    restored = load_contact_store(store_path, local.contact_store_key)
    changed = restored.get(imported.record_id)
    assert changed.state is ContactTrustState.CHANGED
    assert changed.pinned_ghost_id == alice.ghost_id
    assert changed.candidate_contact is not None
    assert changed.candidate_contact.ghost_id == replacement.ghost_id


def test_cli_contact_export_uses_lifecycle_aware_bundle(
    tmp_path: Path,
    capsys,
) -> None:
    password = "lifecycle export password"  # noqa: S105
    profile_path = tmp_path / "alice-lifecycle.ghost"
    contact_path = tmp_path / "alice-lifecycle.contact"

    assert run(
        ["init", "--profile", str(profile_path)],
        password_reader=lambda prompt: password,
    ) == 0
    capsys.readouterr()

    assert run(
        [
            "contact-export",
            "--profile",
            str(profile_path),
            "--output",
            str(contact_path),
        ],
        password_reader=lambda prompt: password,
    ) == 0

    contact = import_contact_bundle(contact_path.read_text(encoding="utf-8"))
    assert contact.lifecycle_epoch == 1
    assert contact.lifecycle_statement is not None
