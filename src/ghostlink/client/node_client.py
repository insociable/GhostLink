"""HTTP transport for exchanging encrypted messages with GhostNode."""

from __future__ import annotations

import base64
import binascii
import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

from ghostlink.message import GhostMessage

RequestFunction = Callable[
    [str, str, dict[str, object] | None, float],
    tuple[int, object | None],
]


class GhostNodeClientError(RuntimeError):
    """Base error for GhostNode client failures."""


class GhostNodeConnectionError(GhostNodeClientError):
    """Raised when the GhostNode cannot be reached."""


class GhostNodeProtocolError(GhostNodeClientError):
    """Raised when GhostNode returns an invalid or unexpected payload."""


class GhostNodeRequestError(GhostNodeClientError):
    """Raised when GhostNode rejects a request."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"GhostNode request failed ({status_code}): {detail}")


@dataclass(frozen=True, slots=True)
class StoredGhostMessage:
    """One encrypted GhostMessage stored by a GhostNode."""

    message_id: str
    message: GhostMessage


def _decode_response(raw: bytes) -> object | None:
    if not raw:
        return None

    try:
        decoded: object = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GhostNodeProtocolError("GhostNode returned invalid JSON") from exc

    return decoded


def _urllib_request(
    method: str,
    url: str,
    payload: dict[str, object] | None,
    timeout: float,
) -> tuple[int, object | None]:
    headers = {"Accept": "application/json"}
    body: bytes | None = None

    if payload is not None:
        body = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        headers["Content-Type"] = "application/json"

    # The caller validates that base_url is absolute HTTP(S) before building this URL.
    request = urllib.request.Request(  # noqa: S310
        url,
        data=body,
        headers=headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.status, _decode_response(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, _decode_response(exc.read())
    except urllib.error.URLError as exc:
        raise GhostNodeConnectionError(
            f"unable to reach GhostNode: {exc.reason}"
        ) from exc


def _require_mapping(value: object | None, context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise GhostNodeProtocolError(f"{context} must be a JSON object")

    document: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise GhostNodeProtocolError(f"{context} contains a non-text field name")
        document[key] = item

    return document


def _require_text(document: dict[str, object], field: str) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not value:
        raise GhostNodeProtocolError(f"{field} must be non-empty text")
    return value


def _require_version(document: dict[str, object]) -> int:
    value = document.get("version")
    if not isinstance(value, int) or isinstance(value, bool):
        raise GhostNodeProtocolError("version must be an integer")
    return value


def _decode_ciphertext(value: str) -> bytes:
    try:
        ciphertext = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise GhostNodeProtocolError("ciphertext must be valid Base64") from exc

    if not ciphertext:
        raise GhostNodeProtocolError("ciphertext must not be empty")

    return ciphertext


def _extract_error_detail(body: object | None) -> str:
    if isinstance(body, dict):
        detail = body.get("detail")
        if isinstance(detail, str) and detail:
            return detail
    return "unexpected GhostNode response"


def _parse_stored_message(value: object) -> StoredGhostMessage:
    document = _require_mapping(value, "stored message")
    message_id = _require_text(document, "message_id")
    sender_device_id = _require_text(document, "sender_device_id")
    recipient_device_id = _require_text(document, "recipient_device_id")
    ciphertext_text = _require_text(document, "ciphertext")
    version = _require_version(document)

    return StoredGhostMessage(
        message_id=message_id,
        message=GhostMessage(
            version=version,
            sender_device_id=sender_device_id,
            recipient_device_id=recipient_device_id,
            ciphertext=_decode_ciphertext(ciphertext_text),
        ),
    )


@dataclass(frozen=True, slots=True)
class GhostNodeClient:
    """Synchronous client for the minimal GhostNode relay API."""

    base_url: str
    timeout: float = 10.0
    requester: RequestFunction = _urllib_request

    def __post_init__(self) -> None:
        parsed = urllib.parse.urlparse(self.base_url)

        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("base_url must be an absolute HTTP(S) URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("base_url must not contain embedded credentials")
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than zero")

        object.__setattr__(self, "base_url", self.base_url.rstrip("/"))

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, object] | None = None,
    ) -> tuple[int, object | None]:
        return self.requester(
            method,
            f"{self.base_url}{path}",
            payload,
            self.timeout,
        )

    def health(self) -> bool:
        """Return whether GhostNode reports a healthy status."""
        status_code, body = self._request("GET", "/health")

        if status_code != 200:
            raise GhostNodeRequestError(
                status_code,
                _extract_error_detail(body),
            )

        document = _require_mapping(body, "health response")
        return document.get("status") == "ok"

    def send(self, message: GhostMessage) -> str:
        """Submit one already-encrypted GhostMessage and return its relay ID."""
        payload: dict[str, object] = {
            "version": message.version,
            "sender_device_id": message.sender_device_id,
            "recipient_device_id": message.recipient_device_id,
            "ciphertext": base64.b64encode(message.ciphertext).decode("ascii"),
        }

        status_code, body = self._request(
            "POST",
            "/v1/messages",
            payload,
        )

        if status_code != 201:
            raise GhostNodeRequestError(
                status_code,
                _extract_error_detail(body),
            )

        stored = _parse_stored_message(body)

        if stored.message != message:
            raise GhostNodeProtocolError(
                "GhostNode returned a message different from the submitted envelope"
            )

        return stored.message_id

    def receive(self, recipient_device_id: str) -> list[StoredGhostMessage]:
        """Retrieve encrypted envelopes addressed to one device."""
        if not recipient_device_id:
            raise ValueError("recipient_device_id must not be empty")

        encoded_device_id = urllib.parse.quote(
            recipient_device_id,
            safe=":",
        )
        status_code, body = self._request(
            "GET",
            f"/v1/messages/{encoded_device_id}",
        )

        if status_code != 200:
            raise GhostNodeRequestError(
                status_code,
                _extract_error_detail(body),
            )

        if not isinstance(body, list):
            raise GhostNodeProtocolError(
                "message list response must be a JSON array"
            )

        return [_parse_stored_message(item) for item in body]

    def delete(self, message_id: str) -> None:
        """Delete one relay message after successful local processing."""
        if not message_id:
            raise ValueError("message_id must not be empty")

        encoded_message_id = urllib.parse.quote(message_id, safe="")
        status_code, body = self._request(
            "DELETE",
            f"/v1/messages/{encoded_message_id}",
        )

        if status_code != 204:
            raise GhostNodeRequestError(
                status_code,
                _extract_error_detail(body),
            )
