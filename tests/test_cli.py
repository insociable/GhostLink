import urllib.parse
from collections.abc import Callable
from pathlib import Path

from fastapi.testclient import TestClient
from ghostlink.cli import run
from ghostlink.client import GhostNodeClient
from ghostlink.node import create_app


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

        if response.content:
            body: object | None = response.json()
        else:
            body = None

        return response.status_code, body

    return requester


def test_cli_two_client_encrypted_message_workflow(
    tmp_path: Path,
    capsys,
) -> None:
    api_client = TestClient(create_app())
    requester = create_test_requester(api_client)

    def node_client_factory(base_url: str) -> GhostNodeClient:
        return GhostNodeClient(base_url, requester=requester)

    def password_reader(prompt: str) -> str:
        return "test profile password"

    alice_profile = tmp_path / "alice.ghost"
    bob_profile = tmp_path / "bob.ghost"
    alice_contact = tmp_path / "alice.contact"
    bob_contact = tmp_path / "bob.contact"
    node_url = "http://ghostnode.test"

    assert run(
        ["init", "--profile", str(alice_profile)],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
    ) == 0

    alice_init = capsys.readouterr()
    assert "GhostID:" in alice_init.out
    assert "Fingerprint:" in alice_init.out

    assert run(
        ["init", "--profile", str(bob_profile)],
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
        ],
        password_reader=password_reader,
        node_client_factory=node_client_factory,
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
    ) == 0

    second_inbox = capsys.readouterr()
    assert "No readable messages." in second_inbox.out


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
