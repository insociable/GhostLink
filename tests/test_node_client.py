import base64
import time
import urllib.parse
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest
from fastapi.testclient import TestClient
from ghostlink.client.node_client import (
    GhostNodeClient,
    GhostNodeProtocolError,
    GhostNodeRequestError,
)
from ghostlink.config import NodeSettings
from ghostlink.device_lifecycle import create_device_lifecycle_statement
from ghostlink.entity import GhostEntity
from ghostlink.node import create_app
from ghostlink.ratchet_message import RatchetMessage

ALICE_DEVICE_ID = "device1:" + ("a" * 52)
BOB_DEVICE_ID = "device1:" + ("b" * 52)


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

        parsed = urllib.parse.urlparse(url)
        response = api_client.request(
            method,
            parsed.path,
            json=payload,
            headers=headers,
        )

        body: object | None
        if response.content:
            body = response.json()
        else:
            body = None

        return response.status_code, body

    return requester


@pytest.mark.parametrize("status_code", [301, 302, 303, 307, 308])
def test_node_client_never_follows_http_redirects(status_code: int) -> None:
    target_requests: list[dict[str, str]] = []

    class TargetHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            target_requests.append(dict(self.headers))
            body = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
    target_thread = Thread(target=target.serve_forever, daemon=True)
    target_thread.start()
    target_url = f"http://127.0.0.1:{target.server_port}/captured"

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(status_code)
            self.send_header("Location", target_url)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            pass

    redirect = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    redirect_thread = Thread(target=redirect.serve_forever, daemon=True)
    redirect_thread.start()

    try:
        client = GhostNodeClient(
            f"http://127.0.0.1:{redirect.server_port}",
            access_token=base64.b64encode(b"redirect-token").decode("ascii"),
        )
        with pytest.raises(GhostNodeRequestError) as error:
            client.health()

        assert error.value.status_code == status_code
        assert target_requests == []
    finally:
        redirect.shutdown()
        redirect.server_close()
        target.shutdown()
        target.server_close()
        redirect_thread.join(timeout=2)
        target_thread.join(timeout=2)


def test_node_client_never_follows_relative_redirects() -> None:
    request_paths: list[str] = []

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            request_paths.append(self.path)
            if self.path == "/health":
                self.send_response(302)
                self.send_header("Location", "/redirected")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = GhostNodeClient(
            f"http://127.0.0.1:{server.server_port}",
            access_token=base64.b64encode(b"redirect-token").decode("ascii"),
        )
        with pytest.raises(GhostNodeRequestError) as error:
            client.health()

        assert error.value.status_code == 302
        assert request_paths == ["/health"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_node_client_reports_health() -> None:
    api_client = TestClient(create_app())
    client = GhostNodeClient(
        "https://ghostnode.test",
        requester=create_test_requester(api_client),
    )

    assert client.health()


def test_node_client_publishes_and_verifies_device_lifecycle() -> None:
    entity = GhostEntity.generate()
    device = entity.enroll_device()
    lifecycle = create_device_lifecycle_statement(
        entity,
        device,
        epoch=1,
        issued_at=123,
    )
    api_client = TestClient(create_app())
    client = GhostNodeClient(
        "https://ghostnode.test",
        requester=create_test_requester(api_client),
    )

    published = client.publish_device_lifecycle(
        bytes(entity.verify_key),
        lifecycle,
    )
    assert published.ghost_id == entity.ghost_id
    assert published.epoch == 1
    assert published.issued_at == 123
    assert published.active_device_id == device.device_id
    assert published.identity_public_key == bytes(entity.verify_key)
    assert published.lifecycle == lifecycle

    fetched = client.get_device_lifecycle(entity.ghost_id)
    assert fetched == published


def test_node_client_rejects_tampered_lifecycle_receipt() -> None:
    entity = GhostEntity.generate()
    device = entity.enroll_device()
    lifecycle = create_device_lifecycle_statement(
        entity,
        device,
        epoch=1,
        issued_at=123,
    )
    api_client = TestClient(create_app())
    real_requester = create_test_requester(api_client)
    other_device_id = GhostEntity.generate().enroll_device().device_id

    def requester(
        method: str,
        url: str,
        payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        status_code, body = real_requester(
            method,
            url,
            payload,
            timeout,
            headers,
        )
        if status_code == 200 and isinstance(body, dict):
            tampered = dict(body)
            tampered["active_device_id"] = other_device_id
            return status_code, tampered
        return status_code, body

    client = GhostNodeClient(
        "https://ghostnode.test",
        requester=requester,
    )
    with pytest.raises(
        GhostNodeProtocolError,
        match="DeviceID does not match",
    ):
        client.publish_device_lifecycle(
            bytes(entity.verify_key),
            lifecycle,
        )


def test_static_v2_transport_methods_are_retired() -> None:
    client = GhostNodeClient("https://ghostnode.test")

    assert not hasattr(client, "send")
    assert not hasattr(client, "receive")
    assert not hasattr(client, "delete")


def test_node_client_rejects_invalid_health_payload() -> None:
    def requester(
        method: str,
        url: str,
        payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        return 200, ["not", "an", "object"]

    client = GhostNodeClient(
        "https://ghostnode.test",
        requester=requester,
    )

    with pytest.raises(
        GhostNodeProtocolError,
        match="health response must be a JSON object",
    ):
        client.health()


@pytest.mark.parametrize(
    "base_url",
    [
        "ghostnode.test",
        "ftp://ghostnode.test",
        "http://user:password@ghostnode.test",
        "http://ghostnode.test",
        "http://192.168.1.20:8000",
    ],
)
def test_node_client_rejects_unsafe_or_invalid_base_urls(base_url: str) -> None:
    with pytest.raises(ValueError):
        GhostNodeClient(base_url)


@pytest.mark.parametrize(
    "base_url",
    [
        "http://127.0.0.1:8000",
        "http://[::1]:8000",
        "http://localhost:8000",
        "http://LOCALHOST.:8000",
        "https://ghostnode.test",
    ],
)
def test_node_client_accepts_https_or_loopback_http(base_url: str) -> None:
    client = GhostNodeClient(base_url)
    assert client.base_url == base_url


def test_node_client_sends_bearer_access_token() -> None:
    token = "test-relay-token"  # noqa: S105
    bob = GhostEntity.generate().enroll_device()
    api_client = TestClient(
        create_app(settings=NodeSettings(access_token=token))
    )
    client = GhostNodeClient(
        "https://ghostnode.test",
        access_token=token,
        requester=create_test_requester(api_client),
    )

    assert client.receive_ratchet(bob) == []


def test_node_client_sanitizes_untrusted_error_detail() -> None:
    raw_detail = "\x1b[31mrelay failure\n" + ("x" * 1_000)

    def requester(
        method: str,
        url: str,
        payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        return 503, {"detail": raw_detail}

    client = GhostNodeClient(
        "https://ghostnode.test",
        requester=requester,
    )

    with pytest.raises(GhostNodeRequestError) as error:
        client.health()

    assert error.value.status_code == 503
    assert "\x1b" not in error.value.detail
    assert "\n" not in error.value.detail
    assert len(error.value.detail) == 512


def test_node_client_without_required_token_is_rejected() -> None:
    token = "test-relay-token"  # noqa: S105
    bob = GhostEntity.generate().enroll_device()
    api_client = TestClient(
        create_app(settings=NodeSettings(access_token=token))
    )
    client = GhostNodeClient(
        "https://ghostnode.test",
        requester=create_test_requester(api_client),
    )

    with pytest.raises(GhostNodeRequestError) as error:
        client.receive_ratchet(bob)

    assert error.value.status_code == 401



def test_node_client_ratchet_v3_round_trip() -> None:
    alice = GhostEntity.generate().enroll_device()
    bob = GhostEntity.generate().enroll_device()
    api_client = TestClient(create_app())
    client = GhostNodeClient(
        "https://ghostnode.test",
        requester=create_test_requester(api_client),
    )
    now = int(time.time())
    message = RatchetMessage(
        version=3,
        message_id="3" * 32,
        sender_device_id=alice.device_id,
        recipient_device_id=bob.device_id,
        created_at=now,
        expires_at=now + 3_600,
        ciphertext_type=3,
        ciphertext=b"opaque-libsignal",
    )

    assert client.send_ratchet(alice, message) == message.message_id
    assert client.receive_ratchet(bob) == [message]
    client.delete_ratchet(bob, message.message_id)
    assert client.receive_ratchet(bob) == []


def test_node_client_rejects_unexpected_ratchet_v3_fields() -> None:
    bob = GhostEntity.generate().enroll_device()

    def requester(
        method: str,
        url: str,
        payload: dict[str, object] | None,
        timeout: float,
        headers: dict[str, str],
    ) -> tuple[int, object | None]:
        del method, url, payload, timeout, headers
        return 200, [
            {
                "version": 3,
                "message_id": "4" * 32,
                "sender_device_id": ALICE_DEVICE_ID,
                "recipient_device_id": BOB_DEVICE_ID,
                "created_at": 1,
                "expires_at": 2,
                "ciphertext_type": 3,
                "ciphertext": base64.b64encode(b"ciphertext").decode("ascii"),
                "unexpected": True,
            }
        ]

    client = GhostNodeClient(
        "https://ghostnode.test",
        requester=requester,
    )

    with pytest.raises(
        GhostNodeProtocolError,
        match="ratcheted message fields do not match",
    ):
        client.receive_ratchet(bob)
