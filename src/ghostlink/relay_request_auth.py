"""Device-authenticated request proofs for ratcheted GhostNode message routes."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
import sqlite3
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from ghostlink.config import NodeSettings
from ghostlink.device import EnrolledGhostDevice, derive_device_id
from ghostlink.relay_state import RelayStateCoordinator

AUTH_VERSION = 1
AUTH_CLOCK_SKEW_SECONDS = 5 * 60
AUTH_DEVICE_ID_HEADER = "X-GhostLink-Device-ID"
AUTH_SIGNING_KEY_HEADER = "X-GhostLink-Signing-Key"
AUTH_REQUEST_ID_HEADER = "X-GhostLink-Request-ID"
AUTH_ISSUED_AT_HEADER = "X-GhostLink-Issued-At"
AUTH_SIGNATURE_HEADER = "X-GhostLink-Signature"

_DOMAIN = b"ghostlink-relay-request-v1\x00"
_DEVICE_ID_PREFIX = "device1:"
_DEVICE_ID_PAYLOAD_LENGTH = 52
_BASE32_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz234567")
_REQUEST_ID_BYTES = 16
_DEVICE_SIGNING_PUBLIC_KEY_BYTES = 32
_SIGNATURE_BYTES = 64
_MAX_SAFE_INTEGER = (1 << 53) - 1


class RelayRequestProofError(ValueError):
    """Raised when a relay request proof is malformed or unauthentic."""


class RelayRequestReplayStore(Protocol):
    """Short-lived replay state for authenticated relay requests."""

    def accept(
        self,
        device_id: str,
        request_id: str,
        *,
        expires_at: int,
        now: int,
    ) -> bool:
        """Atomically accept one unseen request ID."""

    def is_healthy(self) -> bool:
        """Return whether replay storage is available."""


def _is_device_id(value: str) -> bool:
    if not value.startswith(_DEVICE_ID_PREFIX):
        return False
    payload = value[len(_DEVICE_ID_PREFIX) :]
    return (
        len(payload) == _DEVICE_ID_PAYLOAD_LENGTH
        and all(character in _BASE32_ALPHABET for character in payload)
    )


def _validate_request_id(value: str) -> str:
    if len(value) != _REQUEST_ID_BYTES * 2:
        raise RelayRequestProofError(
            "request_id must be 128-bit lowercase hexadecimal"
        )
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise RelayRequestProofError(
            "request_id must be 128-bit lowercase hexadecimal"
        ) from exc
    if decoded.hex() != value:
        raise RelayRequestProofError("request_id must use lowercase hexadecimal")
    return value


def _decode_canonical_base64(
    value: str,
    *,
    field_name: str,
    exact_size: int,
) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RelayRequestProofError(
            f"{field_name} must be valid Base64"
        ) from exc
    if len(decoded) != exact_size:
        raise RelayRequestProofError(f"{field_name} has an invalid decoded length")
    if base64.b64encode(decoded).decode("ascii") != value:
        raise RelayRequestProofError(f"{field_name} must use canonical Base64")
    return decoded


def _canonical_body_bytes(payload: dict[str, object] | None) -> bytes:
    if payload is None:
        return b""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _canonical_request_bytes(
    *,
    method: str,
    path: str,
    payload: dict[str, object] | None,
    device_id: str,
    request_id: str,
    issued_at: int,
) -> bytes:
    if method not in {"GET", "POST", "DELETE"}:
        raise RelayRequestProofError("unsupported authenticated relay method")
    if not path.startswith("/") or "?" in path or "#" in path:
        raise RelayRequestProofError("authenticated relay path is not canonical")
    if not _is_device_id(device_id):
        raise RelayRequestProofError("DeviceID is not canonical")
    _validate_request_id(request_id)
    if (
        not isinstance(issued_at, int)
        or isinstance(issued_at, bool)
        or issued_at < 0
        or issued_at > _MAX_SAFE_INTEGER
    ):
        raise RelayRequestProofError("issued_at is outside the supported range")

    document = {
        "version": AUTH_VERSION,
        "method": method,
        "path": path,
        "device_id": device_id,
        "request_id": request_id,
        "issued_at": issued_at,
        "body_sha256": hashlib.sha256(_canonical_body_bytes(payload)).hexdigest(),
    }
    return _DOMAIN + json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def create_relay_request_headers(
    device: EnrolledGhostDevice,
    *,
    method: str,
    path: str,
    payload: dict[str, object] | None,
    issued_at: int,
    request_id: str | None = None,
) -> dict[str, str]:
    """Create one method/path/body-bound DeviceID proof."""
    certificate = device.certificate.certificate
    if device.device_id != certificate.device_id:
        raise RelayRequestProofError("enrolled device does not match its certificate")

    signing_public_key = bytes(device.device.signing_verify_key)
    if signing_public_key != certificate.signing_public_key:
        raise RelayRequestProofError(
            "device signing key does not match its certificate"
        )

    resolved_request_id = (
        secrets.token_hex(_REQUEST_ID_BYTES)
        if request_id is None
        else _validate_request_id(request_id)
    )
    canonical = _canonical_request_bytes(
        method=method,
        path=path,
        payload=payload,
        device_id=device.device_id,
        request_id=resolved_request_id,
        issued_at=issued_at,
    )
    signature = device.device.signing_key.sign(canonical).signature
    return {
        AUTH_DEVICE_ID_HEADER: device.device_id,
        AUTH_SIGNING_KEY_HEADER: base64.b64encode(signing_public_key).decode(
            "ascii"
        ),
        AUTH_REQUEST_ID_HEADER: resolved_request_id,
        AUTH_ISSUED_AT_HEADER: str(issued_at),
        AUTH_SIGNATURE_HEADER: base64.b64encode(signature).decode("ascii"),
    }


def authenticate_relay_request(
    *,
    expected_device_id: str,
    method: str,
    path: str,
    payload: dict[str, object] | None,
    device_id: str | None,
    signing_public_key: str | None,
    request_id: str | None,
    issued_at: str | None,
    signature: str | None,
    now: int,
    replay_store: RelayRequestReplayStore,
) -> None:
    """Verify one DeviceID proof and atomically reject request-ID replay."""
    if (
        device_id is None
        or signing_public_key is None
        or request_id is None
        or issued_at is None
        or signature is None
    ):
        raise RelayRequestProofError("missing authenticated relay request header")
    if not _is_device_id(expected_device_id):
        raise RelayRequestProofError("expected DeviceID is not canonical")
    if device_id != expected_device_id or not _is_device_id(device_id):
        raise RelayRequestProofError("authenticated DeviceID is not authorized")

    try:
        parsed_issued_at = int(issued_at)
    except ValueError as exc:
        raise RelayRequestProofError("issued_at is not canonical") from exc
    if str(parsed_issued_at) != issued_at:
        raise RelayRequestProofError("issued_at is not canonical")
    if parsed_issued_at < 0 or parsed_issued_at > _MAX_SAFE_INTEGER:
        raise RelayRequestProofError("issued_at is outside the supported range")
    if parsed_issued_at > now + AUTH_CLOCK_SKEW_SECONDS:
        raise RelayRequestProofError("request proof was issued too far in the future")
    if parsed_issued_at < now - AUTH_CLOCK_SKEW_SECONDS:
        raise RelayRequestProofError("request proof is too old")

    resolved_request_id = _validate_request_id(request_id)
    public_key = _decode_canonical_base64(
        signing_public_key,
        field_name="signing public key",
        exact_size=_DEVICE_SIGNING_PUBLIC_KEY_BYTES,
    )
    if derive_device_id(public_key) != device_id:
        raise RelayRequestProofError(
            "DeviceID does not match the signing public key"
        )

    canonical = _canonical_request_bytes(
        method=method,
        path=path,
        payload=payload,
        device_id=device_id,
        request_id=resolved_request_id,
        issued_at=parsed_issued_at,
    )
    decoded_signature = _decode_canonical_base64(
        signature,
        field_name="signature",
        exact_size=_SIGNATURE_BYTES,
    )
    try:
        VerifyKey(public_key).verify(canonical, decoded_signature)
    except BadSignatureError as exc:
        raise RelayRequestProofError("request signature is invalid") from exc

    if not replay_store.accept(
        device_id,
        resolved_request_id,
        expires_at=parsed_issued_at + AUTH_CLOCK_SKEW_SECONDS,
        now=now,
    ):
        raise RelayRequestProofError("request proof was already used")


@dataclass(slots=True)
class InMemoryRelayRequestReplayStore:
    """Process-local replay state for development/tests."""

    _entries: dict[tuple[str, str], int] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def accept(
        self,
        device_id: str,
        request_id: str,
        *,
        expires_at: int,
        now: int,
    ) -> bool:
        with self._lock:
            expired = [
                key
                for key, entry_expires_at in self._entries.items()
                if entry_expires_at < now
            ]
            for key in expired:
                self._entries.pop(key, None)

            key = (device_id, request_id)
            if key in self._entries:
                return False
            self._entries[key] = expires_at
            return True

    def is_healthy(self) -> bool:
        return True


@dataclass(slots=True)
class SQLiteRelayRequestReplayStore:
    """Persistent replay state colocated with the GhostNode SQLite database."""

    path: Path
    coordinator: RelayStateCoordinator | None = None

    def __post_init__(self) -> None:
        if (
            self.coordinator is not None
            and self.coordinator.path.resolve() != self.path.resolve()
        ):
            raise ValueError(
                "relay state coordinator path does not match request replay store"
            )
        if self.path.exists() and self.path.is_dir():
            raise ValueError("node.database_path must point to a file")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS relay_request_replay_v1 (
                    device_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    PRIMARY KEY (device_id, request_id)
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_relay_request_replay_v1_expiry
                ON relay_request_replay_v1 (expires_at)
                """
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5.0)

    def _accept(
        self,
        connection: sqlite3.Connection,
        device_id: str,
        request_id: str,
        *,
        expires_at: int,
        now: int,
    ) -> bool:
        connection.execute(
            "DELETE FROM relay_request_replay_v1 WHERE expires_at < ?",
            (now,),
        )
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO relay_request_replay_v1 (
                device_id,
                request_id,
                expires_at
            ) VALUES (?, ?, ?)
            """,
            (device_id, request_id, expires_at),
        )
        return cursor.rowcount == 1

    def accept(
        self,
        device_id: str,
        request_id: str,
        *,
        expires_at: int,
        now: int,
    ) -> bool:
        if self.coordinator is not None:
            return self.coordinator.mutate(
                lambda connection: self._accept(
                    connection,
                    device_id,
                    request_id,
                    expires_at=expires_at,
                    now=now,
                )
            )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            return self._accept(
                connection,
                device_id,
                request_id,
                expires_at=expires_at,
                now=now,
            )

    def is_healthy(self) -> bool:
        if self.coordinator is not None and not self.coordinator.is_healthy():
            return False
        try:
            with self._connect() as connection:
                connection.execute("SELECT 1").fetchone()
        except sqlite3.Error:
            return False
        return True


def create_relay_request_replay_store(
    settings: NodeSettings,
    coordinator: RelayStateCoordinator | None = None,
) -> RelayRequestReplayStore:
    """Create replay storage matching GhostNode persistence mode."""
    if settings.database_path is None:
        return InMemoryRelayRequestReplayStore()
    return SQLiteRelayRequestReplayStore(
        settings.database_path,
        coordinator=coordinator,
    )
