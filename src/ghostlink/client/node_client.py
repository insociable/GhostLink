"""HTTP transport for exchanging encrypted messages with GhostNode."""

from __future__ import annotations

import base64
import binascii
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, cast

from ghostlink.device import EnrolledGhostDevice, derive_device_id
from ghostlink.message import MESSAGE_VERSION, GhostMessage
from ghostlink.prekey_fetch import (
    PreKeyFetchResponse,
    create_prekey_fetch_request,
)

_MAX_CIPHERTEXT_BYTES = 1_048_576
_DEVICE_ID_PREFIX = "device1:"
_DEVICE_ID_PAYLOAD_LENGTH = 52
_BASE32_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz234567")
_MESSAGE_ID_LENGTH = 32
_HEX_ALPHABET = frozenset("0123456789abcdef")
_PREKEY_PUBLICATION_VERSION = 1
_PREKEY_FETCH_VERSION = 1
_MAX_PREKEY_BINDING_BYTES = 32 * 1024
_MAX_PUBLICATION_SEQUENCE = (1 << 53) - 1
_MAX_ONE_TIME_PREKEYS = 256
_MAX_PREKEY_PUBLICATION_BYTES = 1_048_576
_EXPECTED_PREKEY_RECEIPT_FIELDS = {
    "version",
    "device_id",
    "publication_sequence",
    "expires_at",
    "one_time_count",
}
_EXPECTED_PREKEY_FETCH_FIELDS = {
    "version",
    "target_device_id",
    "requester_device_id",
    "publication_sequence",
    "expires_at",
    "bundle_kind",
    "binding",
    "remaining_one_time_count",
}
_EXPECTED_MESSAGE_FIELDS = {
    "version",
    "message_id",
    "sender_device_id",
    "recipient_device_id",
    "created_at",
    "expires_at",
    "ciphertext",
}

RequestFunction = Callable[
    [str, str, dict[str, object] | None, float, dict[str, str]],
    tuple[int, object | None],
]


@dataclass(frozen=True, slots=True)
class PreKeyPublicationReceipt:
    """Strictly validated GhostNode acknowledgement for one generation."""

    version: int
    device_id: str
    publication_sequence: int
    expires_at: int
    one_time_count: int


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
    extra_headers: dict[str, str],
) -> tuple[int, object | None]:
    headers = {"Accept": "application/json", **extra_headers}
    body: bytes | None = None

    if payload is not None:
        body = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        headers["Content-Type"] = "application/json"

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
    if value != MESSAGE_VERSION:
        raise GhostNodeProtocolError("unsupported message version")
    return value


def _require_timestamp(document: dict[str, object], field: str) -> int:
    value = document.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise GhostNodeProtocolError(f"{field} must be a non-negative integer")
    return value


def _validate_device_id(value: str, field: str) -> str:
    if not value.startswith(_DEVICE_ID_PREFIX):
        raise GhostNodeProtocolError(f"{field} must use the device1 format")

    payload = value[len(_DEVICE_ID_PREFIX) :]
    if len(payload) != _DEVICE_ID_PAYLOAD_LENGTH:
        raise GhostNodeProtocolError(f"{field} payload has an invalid length")
    if any(character not in _BASE32_ALPHABET for character in payload):
        raise GhostNodeProtocolError(
            f"{field} payload is not valid lowercase Base32"
        )
    return value


def _validate_message_id(value: str) -> str:
    if len(value) != _MESSAGE_ID_LENGTH:
        raise GhostNodeProtocolError("message_id has an invalid length")
    if value != value.lower() or any(character not in _HEX_ALPHABET for character in value):
        raise GhostNodeProtocolError("message_id must be lowercase hexadecimal")
    return value


def _decode_ciphertext(value: str) -> bytes:
    try:
        ciphertext = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise GhostNodeProtocolError("ciphertext must be valid Base64") from exc

    if not ciphertext:
        raise GhostNodeProtocolError("ciphertext must not be empty")
    if len(ciphertext) > _MAX_CIPHERTEXT_BYTES:
        raise GhostNodeProtocolError("ciphertext exceeds the 1 MiB relay limit")
    return ciphertext


def _extract_error_detail(body: object | None) -> str:
    if isinstance(body, dict):
        detail = body.get("detail")
        if isinstance(detail, str) and detail:
            return detail
    return "unexpected GhostNode response"


def _require_bounded_integer(
    document: dict[str, object],
    field: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    value = document.get(field)
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > maximum
    ):
        raise GhostNodeProtocolError(
            f"{field} is outside the supported integer range"
        )
    return value


def _parse_prekey_receipt(value: object | None) -> PreKeyPublicationReceipt:
    document = _require_mapping(value, "pre-key publication receipt")
    if set(document) != _EXPECTED_PREKEY_RECEIPT_FIELDS:
        raise GhostNodeProtocolError(
            "pre-key publication receipt fields do not match the protocol"
        )

    version = _require_bounded_integer(
        document,
        "version",
        minimum=_PREKEY_PUBLICATION_VERSION,
        maximum=_PREKEY_PUBLICATION_VERSION,
    )
    device_id = _validate_device_id(
        _require_text(document, "device_id"),
        "device_id",
    )
    publication_sequence = _require_bounded_integer(
        document,
        "publication_sequence",
        minimum=1,
        maximum=_MAX_PUBLICATION_SEQUENCE,
    )
    expires_at = _require_bounded_integer(
        document,
        "expires_at",
        minimum=1,
        maximum=(1 << 63) - 1,
    )
    one_time_count = _require_bounded_integer(
        document,
        "one_time_count",
        minimum=1,
        maximum=_MAX_ONE_TIME_PREKEYS,
    )
    return PreKeyPublicationReceipt(
        version=version,
        device_id=device_id,
        publication_sequence=publication_sequence,
        expires_at=expires_at,
        one_time_count=one_time_count,
    )


def _parse_prekey_fetch_response(
    value: object | None,
) -> PreKeyFetchResponse:
    document = _require_mapping(value, "pre-key fetch response")
    if set(document) != _EXPECTED_PREKEY_FETCH_FIELDS:
        raise GhostNodeProtocolError(
            "pre-key fetch response fields do not match the protocol"
        )

    version = _require_bounded_integer(
        document,
        "version",
        minimum=_PREKEY_FETCH_VERSION,
        maximum=_PREKEY_FETCH_VERSION,
    )
    target_device_id = _validate_device_id(
        _require_text(document, "target_device_id"),
        "target_device_id",
    )
    requester_device_id = _validate_device_id(
        _require_text(document, "requester_device_id"),
        "requester_device_id",
    )
    publication_sequence = _require_bounded_integer(
        document,
        "publication_sequence",
        minimum=1,
        maximum=_MAX_PUBLICATION_SEQUENCE,
    )
    expires_at = _require_bounded_integer(
        document,
        "expires_at",
        minimum=1,
        maximum=_MAX_PUBLICATION_SEQUENCE,
    )
    bundle_kind = _require_text(document, "bundle_kind")
    if bundle_kind not in {"one_time", "fallback"}:
        raise GhostNodeProtocolError(
            "bundle_kind is not a supported pre-key fetch role"
        )
    binding = _require_text(document, "binding")
    if len(binding.encode("utf-8")) > _MAX_PREKEY_BINDING_BYTES:
        raise GhostNodeProtocolError("binding exceeds the size limit")
    remaining_one_time_count = _require_bounded_integer(
        document,
        "remaining_one_time_count",
        minimum=0,
        maximum=_MAX_ONE_TIME_PREKEYS,
    )

    return PreKeyFetchResponse(
        version=version,
        target_device_id=target_device_id,
        requester_device_id=requester_device_id,
        publication_sequence=publication_sequence,
        expires_at=expires_at,
        bundle_kind=cast(Literal["one_time", "fallback"], bundle_kind),
        binding=binding,
        remaining_one_time_count=remaining_one_time_count,
    )


def _parse_message(value: object) -> GhostMessage:
    document = _require_mapping(value, "message")
    if set(document) != _EXPECTED_MESSAGE_FIELDS:
        raise GhostNodeProtocolError(
            "message fields do not match the protocol specification"
        )

    message_id = _validate_message_id(_require_text(document, "message_id"))
    sender_device_id = _validate_device_id(
        _require_text(document, "sender_device_id"),
        "sender_device_id",
    )
    recipient_device_id = _validate_device_id(
        _require_text(document, "recipient_device_id"),
        "recipient_device_id",
    )

    return GhostMessage(
        version=_require_version(document),
        message_id=message_id,
        sender_device_id=sender_device_id,
        recipient_device_id=recipient_device_id,
        created_at=_require_timestamp(document, "created_at"),
        expires_at=_require_timestamp(document, "expires_at"),
        ciphertext=_decode_ciphertext(_require_text(document, "ciphertext")),
    )


@dataclass(frozen=True, slots=True)
class GhostNodeClient:
    """Synchronous client for the canonical GhostNode protocol-v2 API."""

    base_url: str
    timeout: float = 10.0
    access_token: str | None = None
    requester: RequestFunction = _urllib_request

    def __post_init__(self) -> None:
        parsed = urllib.parse.urlparse(self.base_url)

        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("base_url must be an absolute HTTP(S) URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("base_url must not contain embedded credentials")
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        if self.access_token is not None and not self.access_token.strip():
            raise ValueError("access_token must not be empty")

        object.__setattr__(self, "base_url", self.base_url.rstrip("/"))

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, object] | None = None,
    ) -> tuple[int, object | None]:
        headers: dict[str, str] = {}
        if self.access_token is not None:
            headers["Authorization"] = f"Bearer {self.access_token}"

        return self.requester(
            method,
            f"{self.base_url}{path}",
            payload,
            self.timeout,
            headers,
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
        """Submit one encrypted protocol-v2 envelope."""
        payload: dict[str, object] = {
            "version": message.version,
            "message_id": message.message_id,
            "sender_device_id": message.sender_device_id,
            "recipient_device_id": message.recipient_device_id,
            "created_at": message.created_at,
            "expires_at": message.expires_at,
            "ciphertext": base64.b64encode(message.ciphertext).decode("ascii"),
        }

        status_code, body = self._request("POST", "/v2/messages", payload)
        if status_code != 201:
            raise GhostNodeRequestError(
                status_code,
                _extract_error_detail(body),
            )

        stored = _parse_message(body)
        if stored != message:
            raise GhostNodeProtocolError(
                "GhostNode returned an envelope different from the submission"
            )
        return stored.message_id

    def publish_prekeys(
        self,
        device_id: str,
        device_signing_public_key: bytes,
        publication: str,
    ) -> PreKeyPublicationReceipt:
        """Submit one exact signed ratchet pre-key generation."""
        try:
            _validate_device_id(device_id, "device_id")
        except GhostNodeProtocolError as exc:
            raise ValueError(str(exc)) from exc

        if len(device_signing_public_key) != 32:
            raise ValueError(
                "device_signing_public_key must contain exactly 32 bytes"
            )
        if derive_device_id(device_signing_public_key) != device_id:
            raise ValueError(
                "device_signing_public_key does not derive the target DeviceID"
            )

        publication_bytes = publication.encode("utf-8")
        if (
            not publication_bytes
            or len(publication_bytes) > _MAX_PREKEY_PUBLICATION_BYTES
        ):
            raise ValueError(
                "publication must be non-empty and no larger than 1 MiB"
            )

        encoded_device_id = urllib.parse.quote(device_id, safe=":")
        payload: dict[str, object] = {
            "version": _PREKEY_PUBLICATION_VERSION,
            "device_signing_public_key": base64.b64encode(
                device_signing_public_key
            ).decode("ascii"),
            "publication": publication,
        }
        status_code, body = self._request(
            "PUT",
            f"/v2/prekeys/{encoded_device_id}",
            payload,
        )
        if status_code != 200:
            raise GhostNodeRequestError(
                status_code,
                _extract_error_detail(body),
            )
        return _parse_prekey_receipt(body)

    def fetch_prekey(
        self,
        requester_device: EnrolledGhostDevice,
        target_device_id: str,
        *,
        issued_at: int | None = None,
        request_id: str | None = None,
    ) -> PreKeyFetchResponse:
        """Fetch one target-signed pre-key allocation using requester DeviceID proof."""
        try:
            _validate_device_id(target_device_id, "target_device_id")
        except GhostNodeProtocolError as exc:
            raise ValueError(str(exc)) from exc

        now = int(time.time()) if issued_at is None else issued_at
        fetch_request = create_prekey_fetch_request(
            requester_device,
            target_device_id,
            issued_at=now,
            request_id=request_id,
        )
        encoded_device_id = urllib.parse.quote(target_device_id, safe=":")
        status_code, body = self._request(
            "POST",
            f"/v2/prekeys/{encoded_device_id}/fetch",
            fetch_request.model_dump(),
        )
        if status_code != 200:
            raise GhostNodeRequestError(
                status_code,
                _extract_error_detail(body),
            )

        response = _parse_prekey_fetch_response(body)
        if response.target_device_id != target_device_id:
            raise GhostNodeProtocolError(
                "pre-key fetch target DeviceID does not match the request"
            )
        if response.requester_device_id != requester_device.device_id:
            raise GhostNodeProtocolError(
                "pre-key fetch requester DeviceID does not match the local device"
            )
        return response

    def receive(self, recipient_device_id: str) -> list[GhostMessage]:
        """Retrieve encrypted protocol-v2 envelopes for one device."""
        try:
            _validate_device_id(recipient_device_id, "recipient_device_id")
        except GhostNodeProtocolError as exc:
            raise ValueError(str(exc)) from exc

        encoded_device_id = urllib.parse.quote(recipient_device_id, safe=":")
        status_code, body = self._request(
            "GET",
            f"/v2/messages/{encoded_device_id}",
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

        return [_parse_message(item) for item in body]

    def delete(self, recipient_device_id: str, message_id: str) -> None:
        """Delete one delivered protocol-v2 envelope."""
        try:
            _validate_device_id(recipient_device_id, "recipient_device_id")
            _validate_message_id(message_id)
        except GhostNodeProtocolError as exc:
            raise ValueError(str(exc)) from exc

        encoded_device_id = urllib.parse.quote(recipient_device_id, safe=":")
        encoded_message_id = urllib.parse.quote(message_id, safe="")
        status_code, body = self._request(
            "DELETE",
            f"/v2/messages/{encoded_device_id}/{encoded_message_id}",
        )

        if status_code != 204:
            raise GhostNodeRequestError(
                status_code,
                _extract_error_detail(body),
            )