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

from nacl.signing import VerifyKey

from ghostlink.device import EnrolledGhostDevice, derive_device_id
from ghostlink.device_lifecycle import (
    DeviceLifecycleError,
    SignedDeviceLifecycleStatement,
    export_device_lifecycle_statement,
    import_device_lifecycle_statement,
    verify_device_lifecycle_statement,
)
from ghostlink.prekey_fetch import (
    PreKeyFetchResponse,
    create_prekey_fetch_request,
)
from ghostlink.prekey_status import (
    PreKeyStatusResponse,
    create_prekey_status_request,
)
from ghostlink.ratchet_message import RATCHET_MESSAGE_VERSION, RatchetMessage
from ghostlink.relay_request_auth import create_relay_request_headers

_MAX_CIPHERTEXT_BYTES = 1_048_576
_DEVICE_ID_PREFIX = "device1:"
_DEVICE_ID_PAYLOAD_LENGTH = 52
_BASE32_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz234567")
_MESSAGE_ID_LENGTH = 32
_HEX_ALPHABET = frozenset("0123456789abcdef")
_PREKEY_PUBLICATION_VERSION = 1
_PREKEY_FETCH_VERSION = 1
_PREKEY_STATUS_VERSION = 1
_DEVICE_LIFECYCLE_RELAY_VERSION = 1
_MAX_DEVICE_LIFECYCLE_BYTES = 16_384
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
_EXPECTED_PREKEY_STATUS_FIELDS = {
    "version",
    "device_id",
    "publication_sequence",
    "expires_at",
    "remaining_one_time_count",
}
_EXPECTED_DEVICE_LIFECYCLE_FIELDS = {
    "version",
    "ghost_id",
    "epoch",
    "issued_at",
    "active_device_id",
    "identity_public_key",
    "statement",
}
_EXPECTED_RATCHET_MESSAGE_FIELDS = {
    "version",
    "message_id",
    "sender_device_id",
    "recipient_device_id",
    "created_at",
    "expires_at",
    "ciphertext_type",
    "ciphertext",
}

RequestFunction = Callable[
    [str, str, dict[str, object] | None, float, dict[str, str]],
    tuple[int, object | None],
]


@dataclass(frozen=True, slots=True)
class DeviceLifecycleRelayRecord:
    """Strictly verified relay view of one identity lifecycle head."""

    version: int
    ghost_id: str
    epoch: int
    issued_at: int
    active_device_id: str
    identity_public_key: bytes
    lifecycle: SignedDeviceLifecycleStatement


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


def _parse_device_lifecycle_record(
    value: object | None,
) -> DeviceLifecycleRelayRecord:
    document = _require_mapping(value, "device lifecycle response")
    if set(document) != _EXPECTED_DEVICE_LIFECYCLE_FIELDS:
        raise GhostNodeProtocolError(
            "device lifecycle response fields do not match the protocol"
        )

    version = _require_bounded_integer(
        document,
        "version",
        minimum=_DEVICE_LIFECYCLE_RELAY_VERSION,
        maximum=_DEVICE_LIFECYCLE_RELAY_VERSION,
    )
    identity_public_key_text = _require_text(
        document,
        "identity_public_key",
    )
    try:
        identity_public_key = base64.b64decode(
            identity_public_key_text,
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise GhostNodeProtocolError(
            "identity_public_key must be valid Base64"
        ) from exc
    if len(identity_public_key) != 32:
        raise GhostNodeProtocolError(
            "identity_public_key must decode to exactly 32 bytes"
        )
    if (
        base64.b64encode(identity_public_key).decode("ascii")
        != identity_public_key_text
    ):
        raise GhostNodeProtocolError(
            "identity_public_key must use canonical Base64"
        )

    serialized = _require_text(document, "statement")
    if len(serialized.encode("utf-8")) > _MAX_DEVICE_LIFECYCLE_BYTES:
        raise GhostNodeProtocolError(
            "device lifecycle statement exceeds the size limit"
        )

    try:
        lifecycle = import_device_lifecycle_statement(serialized)
        active_device = verify_device_lifecycle_statement(
            lifecycle,
            VerifyKey(identity_public_key),
        )
    except (DeviceLifecycleError, ValueError) as exc:
        raise GhostNodeProtocolError(
            f"device lifecycle response is not authentic: {exc}"
        ) from exc
    if export_device_lifecycle_statement(lifecycle) != serialized:
        raise GhostNodeProtocolError(
            "device lifecycle statement must use canonical JSON"
        )

    ghost_id = _require_text(document, "ghost_id")
    epoch = _require_bounded_integer(
        document,
        "epoch",
        minimum=1,
        maximum=_MAX_PUBLICATION_SEQUENCE,
    )
    issued_at = _require_timestamp(document, "issued_at")
    active_device_id = _validate_device_id(
        _require_text(document, "active_device_id"),
        "active_device_id",
    )
    if lifecycle.statement.ghost_id != ghost_id:
        raise GhostNodeProtocolError(
            "device lifecycle response GhostID does not match its statement"
        )
    if lifecycle.statement.epoch != epoch:
        raise GhostNodeProtocolError(
            "device lifecycle response epoch does not match its statement"
        )
    if lifecycle.statement.issued_at != issued_at:
        raise GhostNodeProtocolError(
            "device lifecycle response timestamp does not match its statement"
        )
    if active_device.device_id != active_device_id:
        raise GhostNodeProtocolError(
            "device lifecycle response DeviceID does not match its statement"
        )

    return DeviceLifecycleRelayRecord(
        version=version,
        ghost_id=ghost_id,
        epoch=epoch,
        issued_at=issued_at,
        active_device_id=active_device_id,
        identity_public_key=identity_public_key,
        lifecycle=lifecycle,
    )


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


def _parse_prekey_status_response(
    value: object | None,
) -> PreKeyStatusResponse:
    document = _require_mapping(value, "pre-key status response")
    if set(document) != _EXPECTED_PREKEY_STATUS_FIELDS:
        raise GhostNodeProtocolError(
            "pre-key status response fields do not match the protocol"
        )

    version = _require_bounded_integer(
        document,
        "version",
        minimum=_PREKEY_STATUS_VERSION,
        maximum=_PREKEY_STATUS_VERSION,
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
        maximum=_MAX_PUBLICATION_SEQUENCE,
    )
    remaining_one_time_count = _require_bounded_integer(
        document,
        "remaining_one_time_count",
        minimum=0,
        maximum=_MAX_ONE_TIME_PREKEYS,
    )
    return PreKeyStatusResponse(
        version=version,
        device_id=device_id,
        publication_sequence=publication_sequence,
        expires_at=expires_at,
        remaining_one_time_count=remaining_one_time_count,
    )


def _parse_ratchet_message(value: object) -> RatchetMessage:
    document = _require_mapping(value, "ratcheted message")
    if set(document) != _EXPECTED_RATCHET_MESSAGE_FIELDS:
        raise GhostNodeProtocolError(
            "ratcheted message fields do not match the protocol specification"
        )

    ciphertext_text = _require_text(document, "ciphertext")
    ciphertext = _decode_ciphertext(ciphertext_text)
    if base64.b64encode(ciphertext).decode("ascii") != ciphertext_text:
        raise GhostNodeProtocolError("ciphertext must use canonical Base64")

    return RatchetMessage(
        version=_require_bounded_integer(
            document,
            "version",
            minimum=RATCHET_MESSAGE_VERSION,
            maximum=RATCHET_MESSAGE_VERSION,
        ),
        message_id=_validate_message_id(_require_text(document, "message_id")),
        sender_device_id=_validate_device_id(
            _require_text(document, "sender_device_id"),
            "sender_device_id",
        ),
        recipient_device_id=_validate_device_id(
            _require_text(document, "recipient_device_id"),
            "recipient_device_id",
        ),
        created_at=_require_timestamp(document, "created_at"),
        expires_at=_require_timestamp(document, "expires_at"),
        ciphertext_type=_require_bounded_integer(
            document,
            "ciphertext_type",
            minimum=0,
            maximum=255,
        ),
        ciphertext=ciphertext,
    )



@dataclass(frozen=True, slots=True)
class GhostNodeClient:
    """Synchronous client for GhostNode ratcheted messaging and pre-key APIs."""

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
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[int, object | None]:
        headers: dict[str, str] = {}
        if self.access_token is not None:
            headers["Authorization"] = f"Bearer {self.access_token}"
        if extra_headers is not None:
            headers.update(extra_headers)

        return self.requester(
            method,
            f"{self.base_url}{path}",
            payload,
            self.timeout,
            headers,
        )

    def publish_device_lifecycle(
        self,
        identity_public_key: bytes,
        lifecycle: SignedDeviceLifecycleStatement,
    ) -> DeviceLifecycleRelayRecord:
        """Publish one exact identity-signed lifecycle head."""
        if len(identity_public_key) != 32:
            raise ValueError(
                "identity_public_key must contain exactly 32 bytes"
            )
        try:
            active_device = verify_device_lifecycle_statement(
                lifecycle,
                VerifyKey(identity_public_key),
            )
            serialized = export_device_lifecycle_statement(lifecycle)
        except (DeviceLifecycleError, ValueError) as exc:
            raise ValueError(str(exc)) from exc

        statement = lifecycle.statement
        if active_device.device_id != statement.device_id:
            raise ValueError(
                "device lifecycle active DeviceID does not match its certificate"
            )

        encoded_ghost_id = urllib.parse.quote(statement.ghost_id, safe=":")
        payload: dict[str, object] = {
            "version": _DEVICE_LIFECYCLE_RELAY_VERSION,
            "identity_public_key": base64.b64encode(
                identity_public_key
            ).decode("ascii"),
            "statement": serialized,
        }
        status_code, body = self._request(
            "PUT",
            f"/v3/device-lifecycle/{encoded_ghost_id}",
            payload,
        )
        if status_code != 200:
            raise GhostNodeRequestError(
                status_code,
                _extract_error_detail(body),
            )

        record = _parse_device_lifecycle_record(body)
        if record.ghost_id != statement.ghost_id:
            raise GhostNodeProtocolError(
                "device lifecycle receipt GhostID does not match the request"
            )
        if record.identity_public_key != identity_public_key:
            raise GhostNodeProtocolError(
                "device lifecycle receipt identity key does not match the request"
            )
        if record.lifecycle != lifecycle:
            raise GhostNodeProtocolError(
                "device lifecycle receipt differs from the submitted statement"
            )
        return record

    def get_device_lifecycle(
        self,
        ghost_id: str,
    ) -> DeviceLifecycleRelayRecord:
        """Fetch and cryptographically verify one relay lifecycle head."""
        if not ghost_id.startswith("ghost1:"):
            raise ValueError("ghost_id must use the ghost1 format")
        encoded_ghost_id = urllib.parse.quote(ghost_id, safe=":")
        status_code, body = self._request(
            "GET",
            f"/v3/device-lifecycle/{encoded_ghost_id}",
        )
        if status_code != 200:
            raise GhostNodeRequestError(
                status_code,
                _extract_error_detail(body),
            )
        record = _parse_device_lifecycle_record(body)
        if record.ghost_id != ghost_id:
            raise GhostNodeProtocolError(
                "device lifecycle response GhostID does not match the request"
            )
        return record

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

    def send_ratchet(
        self,
        sender_device: EnrolledGhostDevice,
        message: RatchetMessage,
        *,
        issued_at: int | None = None,
        request_id: str | None = None,
    ) -> str:
        """Submit one device-authenticated protocol-v3 envelope."""
        if sender_device.device_id != message.sender_device_id:
            raise ValueError(
                "sender device does not match the ratcheted message sender"
            )

        payload: dict[str, object] = {
            "version": message.version,
            "message_id": message.message_id,
            "sender_device_id": message.sender_device_id,
            "recipient_device_id": message.recipient_device_id,
            "created_at": message.created_at,
            "expires_at": message.expires_at,
            "ciphertext_type": message.ciphertext_type,
            "ciphertext": base64.b64encode(message.ciphertext).decode("ascii"),
        }
        path = "/v3/messages"
        headers = create_relay_request_headers(
            sender_device,
            method="POST",
            path=path,
            payload=payload,
            issued_at=int(time.time()) if issued_at is None else issued_at,
            request_id=request_id,
        )
        status_code, body = self._request(
            "POST",
            path,
            payload,
            extra_headers=headers,
        )
        if status_code != 201:
            raise GhostNodeRequestError(
                status_code,
                _extract_error_detail(body),
            )
        stored = _parse_ratchet_message(body)
        if stored != message:
            raise GhostNodeProtocolError(
                "GhostNode returned a ratcheted envelope different from the submission"
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

    def prekey_status(
        self,
        device: EnrolledGhostDevice,
        *,
        issued_at: int | None = None,
        request_id: str | None = None,
    ) -> PreKeyStatusResponse:
        """Return the owning device's active relay pre-key pool status."""
        now = int(time.time()) if issued_at is None else issued_at
        request = create_prekey_status_request(
            device,
            issued_at=now,
            request_id=request_id,
        )
        encoded_device_id = urllib.parse.quote(device.device_id, safe=":")
        status_code, body = self._request(
            "POST",
            f"/v2/prekeys/{encoded_device_id}/status",
            request.model_dump(),
        )
        if status_code != 200:
            raise GhostNodeRequestError(
                status_code,
                _extract_error_detail(body),
            )

        response = _parse_prekey_status_response(body)
        if response.device_id != device.device_id:
            raise GhostNodeProtocolError(
                "pre-key status DeviceID does not match the local device"
            )
        return response

    def receive_ratchet(
        self,
        recipient_device: EnrolledGhostDevice,
        *,
        issued_at: int | None = None,
        request_id: str | None = None,
    ) -> list[RatchetMessage]:
        """Retrieve one device's protocol-v3 mailbox with owner proof."""
        recipient_device_id = recipient_device.device_id
        encoded_device_id = urllib.parse.quote(recipient_device_id, safe=":")
        path = f"/v3/messages/{encoded_device_id}"
        headers = create_relay_request_headers(
            recipient_device,
            method="GET",
            path=path,
            payload=None,
            issued_at=int(time.time()) if issued_at is None else issued_at,
            request_id=request_id,
        )
        status_code, body = self._request(
            "GET",
            path,
            extra_headers=headers,
        )
        if status_code != 200:
            raise GhostNodeRequestError(
                status_code,
                _extract_error_detail(body),
            )
        if not isinstance(body, list):
            raise GhostNodeProtocolError(
                "ratcheted message list response must be a JSON array"
            )
        return [_parse_ratchet_message(item) for item in body]

    def delete_ratchet(
        self,
        recipient_device: EnrolledGhostDevice,
        message_id: str,
        *,
        issued_at: int | None = None,
        request_id: str | None = None,
    ) -> None:
        """Delete one delivered protocol-v3 envelope with owner proof."""
        try:
            _validate_message_id(message_id)
        except GhostNodeProtocolError as exc:
            raise ValueError(str(exc)) from exc

        recipient_device_id = recipient_device.device_id
        encoded_device_id = urllib.parse.quote(recipient_device_id, safe=":")
        encoded_message_id = urllib.parse.quote(message_id, safe="")
        path = f"/v3/messages/{encoded_device_id}/{encoded_message_id}"
        headers = create_relay_request_headers(
            recipient_device,
            method="DELETE",
            path=path,
            payload=None,
            issued_at=int(time.time()) if issued_at is None else issued_at,
            request_id=request_id,
        )
        status_code, body = self._request(
            "DELETE",
            path,
            extra_headers=headers,
        )
        if status_code != 204:
            raise GhostNodeRequestError(
                status_code,
                _extract_error_detail(body),
            )
